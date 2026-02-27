from bcc import BPF
import csv
import time
import os
import json
from collections import defaultdict
from datetime import datetime

# eBPF program
program = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct data_t {
    u32 pid;
    u32 ppid;
    u64 timestamp_ns;
    char comm[TASK_COMM_LEN];
    char syscall[16];
};

BPF_PERF_OUTPUT(events);

// Generic helper — called by each tracepoint wrapper
static inline int submit_event(struct pt_regs *ctx, const char *syscall_name, int len) {
    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.timestamp_ns = bpf_ktime_get_ns();
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    data.ppid = task->real_parent->tgid;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    __builtin_memcpy(&data.syscall, syscall_name, len);
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int trace_open(struct pt_regs *ctx) {
    return submit_event(ctx, "open", 5);
}

int trace_read(struct pt_regs *ctx) {
    return submit_event(ctx, "read", 5);
}

int trace_write(struct pt_regs *ctx) {
    return submit_event(ctx, "write", 6);
}

int trace_fork(struct pt_regs *ctx) {
    return submit_event(ctx, "fork", 5);
}

int trace_clone(struct pt_regs *ctx) {
    return submit_event(ctx, "clone", 6);
}

int trace_ptrace(struct pt_regs *ctx) {
    return submit_event(ctx, "ptrace", 7);
}
"""

# ---------------------------------------------------------------------------
# PID-tree aggregator
# ---------------------------------------------------------------------------
class PIDTreeAggregator:
    """Tracks process trees and aggregates syscall counts per PID lineage."""

    def __init__(self):
        # pid -> { ppid, comm, syscalls: {name: count}, first_seen, last_seen }
        self.processes: dict[int, dict] = {}
        # ppid -> set of child pids
        self.children: dict[int, set] = defaultdict(set)

    def record(self, pid: int, ppid: int, comm: str, syscall: str, ts: float):
        if pid not in self.processes:
            self.processes[pid] = {
                "ppid": ppid,
                "comm": comm,
                "syscalls": defaultdict(int),
                "first_seen": ts,
                "last_seen": ts,
            }
            self.children[ppid].add(pid)

        entry = self.processes[pid]
        entry["syscalls"][syscall] += 1
        entry["last_seen"] = ts
        # comm can change (exec), keep latest
        entry["comm"] = comm

    def get_ancestors(self, pid: int) -> list[int]:
        """Walk up the tree and return the ancestor chain."""
        chain = []
        visited = set()
        current = pid
        while current in self.processes and current not in visited:
            visited.add(current)
            chain.append(current)
            current = self.processes[current]["ppid"]
        return chain

    def get_tree(self, root_pid: int, depth: int = 0, max_depth: int = 10) -> dict:
        """Recursively build a tree dict starting from root_pid."""
        if depth > max_depth or root_pid not in self.processes:
            return {}
        info = self.processes[root_pid]
        return {
            "pid": root_pid,
            "comm": info["comm"],
            "syscalls": dict(info["syscalls"]),
            "children": [
                self.get_tree(c, depth + 1, max_depth)
                for c in sorted(self.children.get(root_pid, []))
            ],
        }

    def dump_summary(self, path: str = "pid_tree_summary.json"):
        """Write a JSON summary of all tracked trees."""
        # Find root pids (ppid not in our tracked set)
        roots = set()
        for pid, info in self.processes.items():
            if info["ppid"] not in self.processes:
                roots.add(pid)
        trees = [self.get_tree(r) for r in sorted(roots)]
        with open(path, "w") as fp:
            json.dump(trees, fp, indent=2, default=str)

    def print_stats(self):
        """Print a quick per-PID syscall summary to stdout."""
        print("\n===== PID-Tree Syscall Summary =====")
        # Sort by total syscall count descending
        ranked = sorted(
            self.processes.items(),
            key=lambda kv: sum(kv[1]["syscalls"].values()),
            reverse=True,
        )
        for pid, info in ranked[:30]:  # top 30
            total = sum(info["syscalls"].values())
            calls = ", ".join(f"{k}:{v}" for k, v in sorted(info["syscalls"].items()))
            ancestors = " -> ".join(str(a) for a in reversed(self.get_ancestors(pid)))
            print(f"  PID {pid:>7} ({info['comm']:<16}) total={total:>6}  [{calls}]  tree: {ancestors}")
        print("====================================\n")


# ---------------------------------------------------------------------------
# Attach probes
# ---------------------------------------------------------------------------
b = BPF(text=program)

# Syscall probes — try the __x64_sys_ prefix first, fall back to ksys / do_ variants
PROBES = {
    "__x64_sys_openat":  "trace_open",   # modern kernels use openat not open
    "__x64_sys_open":    "trace_open",
    "__x64_sys_read":    "trace_read",
    "__x64_sys_write":   "trace_write",
    "__x64_sys_fork":    "trace_fork",
    "__x64_sys_clone":   "trace_clone",
    "__x64_sys_ptrace":  "trace_ptrace",
}

attached = []
for event, fn in PROBES.items():
    try:
        b.attach_kprobe(event=event, fn_name=fn)
        attached.append(event)
    except Exception:
        pass  # kernel may not expose every variant

if not attached:
    print("ERROR: Could not attach to any kprobe. Are you running as root?")
    exit(1)

print(f"Attached to: {', '.join(attached)}")

# ---------------------------------------------------------------------------
# CSV log + aggregation loop
# ---------------------------------------------------------------------------
log_file = "hids_exec_log.csv"
file_exists = os.path.isfile(log_file)
aggregator = PIDTreeAggregator()

SUMMARY_INTERVAL = 30  # seconds between automatic summary dumps
last_summary = time.time()

with open(log_file, "w", newline="") as f:
    writer = csv.writer(f)

    if not file_exists:
        writer.writerow(["timestamp", "pid", "ppid", "process_name", "syscall"])

    def print_event(cpu, data, size):
        global last_summary

        event = b["events"].event(data)
        ts = time.time()
        comm = event.comm.decode("utf-8", "replace")
        syscall = event.syscall.decode("utf-8", "replace")

        # CSV row
        writer.writerow([ts, event.pid, event.ppid, comm, syscall])
        f.flush()

        # Aggregate
        aggregator.record(event.pid, event.ppid, comm, syscall, ts)

        print(
            f"[{datetime.fromtimestamp(ts).strftime('%H:%M:%S.%f')}] "
            f"PID={event.pid:<7} PPID={event.ppid:<7} COMM={comm:<16} SYSCALL={syscall}"
        )

        # Periodic summary
        if ts - last_summary > SUMMARY_INTERVAL:
            last_summary = ts
            aggregator.print_stats()
            aggregator.dump_summary()

    b["events"].open_perf_buffer(print_event, page_cnt=64)

    print("HIDS syscall monitor running... Ctrl+C to stop.")
    print(f"Logging to {log_file}  |  Tree summary every {SUMMARY_INTERVAL}s -> pid_tree_summary.json\n")

    while True:
        try:
            b.perf_buffer_poll(timeout=100)
        except KeyboardInterrupt:
            print("\nFinal summary:")
            aggregator.print_stats()
            aggregator.dump_summary("pid_tree_summary.json")
            print("Stopping monitor.")
            break