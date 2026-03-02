"""CSV parsing and analytics computation for both data sources."""

import os
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

BASE_DIR = Path(__file__).parent.parent
LOG_CSV = BASE_DIR / "hids_exec_log.csv"
RESULTS_CSV = BASE_DIR / "hids_final_results.csv"

# Severity mapping used by monitor.py
EVENT_SEVERITY = {
    "execve": "HIGH", "fork/clone": "MED", "ptrace": "HIGH",
    "open_sensitive": "HIGH", "connect": "MED", "setuid": "HIGH",
    "chmod": "MED", "mmap_rwx": "HIGH", "unlink": "MED",
    "rename": "MED", "bind": "MED", "process_vm_writev": "HIGH",
}


def _read_log() -> pd.DataFrame:
    """Load and normalise hids_exec_log.csv; returns empty DataFrame on missing file."""
    if not LOG_CSV.exists():
        return pd.DataFrame()
    df = pd.read_csv(LOG_CSV)
    if df.empty:
        return df
    df["timestamp"] = pd.to_datetime(df["timestamp"], unit="s", utc=True)
    df["detail"] = df["detail"].fillna("").astype(str)
    return df


def get_summary() -> dict:
    df = _read_log()
    if df.empty:
        return {
            "total_events": 0, "high_severity_count": 0, "med_severity_count": 0,
            "unique_pids": 0, "unique_processes": 0, "monitoring_span_seconds": 0.0,
            "last_updated": datetime.now(timezone.utc).isoformat(),
        }
    span = (df["timestamp"].max() - df["timestamp"].min()).total_seconds()
    return {
        "total_events": len(df),
        "high_severity_count": int((df["severity"] == "HIGH").sum()),
        "med_severity_count": int((df["severity"] == "MED").sum()),
        "unique_pids": int(df["pid"].nunique()),
        "unique_processes": int(df["process_name"].nunique()),
        "monitoring_span_seconds": round(span, 1),
        "last_updated": datetime.now(timezone.utc).isoformat(),
    }


def get_timeline(bucket_seconds: int = 5) -> dict:
    df = _read_log()
    if df.empty:
        return {"buckets": []}

    df["bucket"] = df["timestamp"].dt.floor(f"{bucket_seconds}s")
    grouped = df.groupby(["bucket", "severity"]).size().unstack(fill_value=0).reset_index()
    # Ensure both severity columns exist
    for col in ("HIGH", "MED"):
        if col not in grouped.columns:
            grouped[col] = 0

    buckets = [
        {
            "time": row["bucket"].isoformat(),
            "HIGH": int(row["HIGH"]),
            "MED": int(row["MED"]),
        }
        for _, row in grouped.iterrows()
    ]
    return {"buckets": buckets}


def get_event_distribution() -> dict:
    df = _read_log()
    if df.empty:
        return {"distribution": []}

    counts = df.groupby(["event_name", "severity"]).size().reset_index(name="count")
    distribution = [
        {"event_name": row["event_name"], "count": int(row["count"]), "severity": row["severity"]}
        for _, row in counts.sort_values("count", ascending=False).iterrows()
    ]
    return {"distribution": distribution}


def get_top_processes(n: int = 15) -> dict:
    df = _read_log()
    if df.empty:
        return {"processes": []}

    agg = (
        df.groupby("process_name")
        .agg(
            pid_count=("pid", "nunique"),
            event_count=("pid", "count"),
            high_count=("severity", lambda s: (s == "HIGH").sum()),
            med_count=("severity", lambda s: (s == "MED").sum()),
        )
        .reset_index()
        .sort_values("event_count", ascending=False)
        .head(n)
    )
    # Collect unique event types per process
    event_types_map = df.groupby("process_name")["event_name"].apply(lambda s: list(s.unique()))

    processes = []
    for _, row in agg.iterrows():
        processes.append({
            "process_name": row["process_name"],
            "pid_count": int(row["pid_count"]),
            "event_count": int(row["event_count"]),
            "high_count": int(row["high_count"]),
            "med_count": int(row["med_count"]),
            "event_types": event_types_map.get(row["process_name"], []),
        })
    return {"processes": processes}


def get_rwx_events() -> dict:
    df = _read_log()
    if df.empty:
        return {"rwx_events": [], "total": 0}

    rwx = df[df["event_name"] == "mmap_rwx"].sort_values("timestamp")
    events = [
        {
            "timestamp": row["timestamp"].isoformat(),
            "pid": int(row["pid"]),
            "ppid": int(row["ppid"]),
            "process_name": row["process_name"],
            "detail": row["detail"],
        }
        for _, row in rwx.iterrows()
    ]
    return {"rwx_events": events, "total": len(events)}


def get_process_tree() -> dict:
    df = _read_log()
    if df.empty:
        return {"trees": []}

    # Per-PID stats — event count and whether any HIGH severity occurred
    pid_stats = df.groupby("pid").agg(
        process_name=("process_name", "first"),
        event_count=("pid", "count"),
        has_high=("severity", lambda s: (s == "HIGH").any()),
        ppid=("ppid", "first"),
    ).reset_index()
    pid_map = {row["pid"]: row for _, row in pid_stats.iterrows()}
    all_pids = set(pid_map.keys())

    def build_node(pid, visited: set):
        """Recursively build a tree node; `visited` guards against cyclic ppid chains."""
        row = pid_map[pid]
        children_pids = [
            p for p, r in pid_map.items()
            if r["ppid"] == pid and p != pid and p not in visited
        ]
        return {
            "pid": int(pid),
            "process_name": row["process_name"],
            "event_count": int(row["event_count"]),
            "has_high": bool(row["has_high"]),
            "children": [build_node(c, visited | {c}) for c in children_pids],
        }

    # Root nodes: PIDs whose PPID doesn't appear in the log
    root_pids = [p for p, r in pid_map.items() if r["ppid"] not in all_pids]
    trees = [build_node(p, {p}) for p in root_pids]
    # Sort roots by event count descending
    trees.sort(key=lambda n: n["event_count"], reverse=True)
    return {"trees": trees}


def get_model_results() -> dict:
    if not RESULTS_CSV.exists():
        return {"available": False}

    df = pd.read_csv(RESULTS_CSV)
    if df.empty:
        return {"available": False}

    total = len(df)
    correct = df["correct"].sum()
    accuracy = correct / total * 100 if total else 0

    is_threat = df["risk_level"].isin(["High", "Critical"])
    detected = df["rl_action"].isin(["Alert", "Block"])
    tp = (is_threat & detected).sum()
    fp = (~is_threat & detected).sum()
    fn = (is_threat & ~detected).sum()

    precision = tp / (tp + fp) * 100 if (tp + fp) else 0
    recall = tp / (tp + fn) * 100 if (tp + fn) else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0

    risk_dist = df["risk_level"].value_counts().to_dict()
    action_dist = df["rl_action"].value_counts().to_dict()

    per_pid = df.to_dict(orient="records")
    # Normalise boolean column which pandas may read as 0/1
    for row in per_pid:
        row["correct"] = bool(row["correct"])
        row["fuzzy_score"] = int(row["fuzzy_score"])
        row["confidence"] = float(row["confidence"])

    return {
        "available": True,
        "accuracy": round(accuracy, 1),
        "precision": round(precision, 1),
        "recall": round(recall, 1),
        "f1": round(f1, 1),
        "risk_distribution": {k: int(v) for k, v in risk_dist.items()},
        "action_distribution": {k: int(v) for k, v in action_dist.items()},
        "per_pid": per_pid,
    }


def get_event_feed() -> dict:
    df = _read_log()
    if df.empty:
        return {"events": []}

    recent = df.sort_values("timestamp", ascending=False).head(50)
    events = [
        {
            "timestamp": row["timestamp"].isoformat(),
            "pid": int(row["pid"]),
            "process_name": row["process_name"],
            "event_name": row["event_name"],
            "severity": row["severity"],
            "detail": row["detail"],
        }
        for _, row in recent.iterrows()
    ]
    return {"events": events}
