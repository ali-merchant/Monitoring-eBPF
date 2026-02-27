from bcc import BPF
import csv
import time
import os
import json
import signal
import sys
from collections import defaultdict
from datetime import datetime

#VSCODE has a noise problem

program = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>

#define EVT_EXEC       1
#define EVT_FORK       2
#define EVT_PTRACE     3
#define EVT_OPEN_SENS  4
#define EVT_CONNECT    5
#define EVT_SETUID     6
#define EVT_CHMOD      7
#define EVT_MMAP_RWX   8
#define EVT_UNLINK     9
#define EVT_RENAME     10
#define EVT_BIND       11
#define EVT_PROCESS_VM 12

struct data_t {
    u32  pid;
    u32  ppid;
    u64  timestamp_ns;
    u8   event_type;
    u32  extra_u32;        // target_pid for ptrace, prot flags for mmap, uid for setuid
    char comm[TASK_COMM_LEN];
    char detail[128];
};

BPF_PERF_OUTPUT(events);

BPF_HASH(rate_count, u32, u64);
BPF_HASH(rate_ts,    u32, u64);
#define RATE_LIMIT 20

static inline int rate_limited(u32 pid) {
    u64 now = bpf_ktime_get_ns();
    u64 *ts  = rate_ts.lookup(&pid);
    u64 *cnt = rate_count.lookup(&pid);
    if (!ts || (now - *ts) > 1000000000ULL) {
        rate_ts.update(&pid, &now);
        u64 one = 1;
        rate_count.update(&pid, &one);
        return 0;
    }
    if (!cnt) return 0;
    if (*cnt >= RATE_LIMIT) return 1;
    (*cnt)++;
    rate_count.update(&pid, cnt);
    return 0;
}

static inline void fill_base(struct data_t *d, u8 etype) {
    d->pid          = bpf_get_current_pid_tgid() >> 32;
    d->timestamp_ns = bpf_ktime_get_ns();
    d->event_type   = etype;
    d->extra_u32    = 0;
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    d->ppid = t->real_parent->tgid;
    bpf_get_current_comm(&d->comm, sizeof(d->comm));
}

TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    struct data_t data = {};
    fill_base(&data, EVT_EXEC);
    bpf_probe_read_user_str(&data.detail, sizeof(data.detail), args->filename);
    events.perf_submit(args, &data, sizeof(data));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_clone) {
    struct data_t data = {};
    fill_base(&data, EVT_FORK);
    data.extra_u32 = (u32)args->clone_flags;  // clone flags tell us if it's a thread or process
    events.perf_submit(args, &data, sizeof(data));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_ptrace) {
    struct data_t data = {};
    fill_base(&data, EVT_PTRACE);
    data.extra_u32 = (u32)args->pid;   // target pid — decoded in Python, no memcpy needed
    events.perf_submit(args, &data, sizeof(data));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    char path[64];
    bpf_probe_read_user_str(path, sizeof(path), args->filename);

    if (
        (path[0]=='/' && path[1]=='e' && path[2]=='t' && path[3]=='c' && path[4]=='/') ||
        (path[0]=='/' && path[1]=='r' && path[2]=='o' && path[3]=='o' && path[4]=='t') ||
        (path[0]=='.' && path[1]=='s' && path[2]=='s' && path[3]=='h')
    ) {
        struct data_t data = {};
        fill_base(&data, EVT_OPEN_SENS);
        bpf_probe_read_user_str(&data.detail, sizeof(data.detail), args->filename);
        events.perf_submit(args, &data, sizeof(data));
    }

    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_connect) {
    struct data_t data = {};
    fill_base(&data, EVT_CONNECT);
    if (rate_limited(data.pid)) return 0;
    events.perf_submit(args, &data, sizeof(data));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_bind) {
    struct data_t data = {};
    fill_base(&data, EVT_BIND);
    events.perf_submit(args, &data, sizeof(data));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_setuid) {
    struct data_t data = {};
    fill_base(&data, EVT_SETUID);
    data.extra_u32 = (u32)args->uid;   // which uid they're trying to become
    events.perf_submit(args, &data, sizeof(data));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_fchmodat) {
    struct data_t data = {};
    fill_base(&data, EVT_CHMOD);
    data.extra_u32 = (u32)args->mode;  // the mode bits being set
    bpf_probe_read_user_str(&data.detail, sizeof(data.detail), args->filename);
    events.perf_submit(args, &data, sizeof(data));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_unlinkat) {
    struct data_t data = {};
    fill_base(&data, EVT_UNLINK);
    bpf_probe_read_user_str(&data.detail, sizeof(data.detail), args->pathname);
    events.perf_submit(args, &data, sizeof(data));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_renameat2) {
    struct data_t data = {};
    fill_base(&data, EVT_RENAME);
    bpf_probe_read_user_str(&data.detail, sizeof(data.detail), args->oldname);
    events.perf_submit(args, &data, sizeof(data));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_mmap) {
    if ((args->prot & 7) == 7) {
        struct data_t data = {};
        fill_base(&data, EVT_MMAP_RWX);
        data.extra_u32 = (u32)args->prot;  // full prot flags for analysis
        events.perf_submit(args, &data, sizeof(data));
    }
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_process_vm_writev) {
    struct data_t data = {};
    fill_base(&data, EVT_PROCESS_VM);
    data.extra_u32 = (u32)args->pid;   // target process being written to
    events.perf_submit(args, &data, sizeof(data));
    return 0;
}
"""

# ---------------------------------------------------------------------------
# Event metadata
# ---------------------------------------------------------------------------
EVENT_NAMES = {
    1:  "execve",         2:  "fork/clone",    3:  "ptrace",
    4:  "open_sensitive", 5:  "connect",        6:  "setuid",
    7:  "chmod",          8:  "mmap_rwx",       9:  "unlink",
    10: "rename",         11: "bind",           12: "process_vm_writev",
}

EVENT_SEVERITY = {
    1: "HIGH", 2: "MED",  3: "HIGH", 4: "HIGH",
    5: "MED",  6: "HIGH", 7: "MED",  8: "HIGH",
    9: "MED",  10: "MED", 11: "MED", 12: "HIGH",
}

def build_detail(event) -> str:
    """
    Build a human-readable detail string in Python instead of kernel space.
    Uses extra_u32 which holds event-specific integer data.
    """
    etype = event.event_type
    raw   = event.detail.decode("utf-8", "replace").rstrip("\x00")
    extra = event.extra_u32

    if etype == 3:    # ptrace  — extra_u32 = target pid
        return f"target_pid={extra}"
    elif etype == 2:  # clone   — extra_u32 = clone_flags
        thread = bool(extra & 0x00010000)  # CLONE_THREAD flag
        return f"clone_flags=0x{extra:08x} ({'thread' if thread else 'process'})"
    elif etype == 6:  # setuid  — extra_u32 = target uid
        return f"target_uid={extra}"
    elif etype == 7:  # chmod   — extra_u32 = mode, raw = path
        return f"{raw} mode=0o{extra:04o}"
    elif etype == 8:  # mmap    — extra_u32 = prot flags
        flags = []
        if extra & 1: flags.append("READ")
        if extra & 2: flags.append("WRITE")
        if extra & 4: flags.append("EXEC")
        return f"prot={'|'.join(flags)}"
    elif etype == 12: # process_vm_writev — extra_u32 = target pid
        return f"target_pid={extra}"
    else:
        return raw  # execve path, open path, etc.

# ---------------------------------------------------------------------------
# PID-tree aggregator
# ---------------------------------------------------------------------------
class PIDTreeAggregator:
    def __init__(self):
        self.processes: dict[int, dict] = {}
        self.children:  dict[int, set]  = defaultdict(set)
        self.alerts:    list[dict]       = []

    def record(self, pid: int, ppid: int, comm: str, event_type: int,
               detail: str, ts: float):
        name = EVENT_NAMES.get(event_type, "unknown")
        if pid not in self.processes:
            self.processes[pid] = {
                "ppid": ppid, "comm": comm,
                "events": defaultdict(int),
                "first_seen": ts, "last_seen": ts,
            }
            self.children[ppid].add(pid)
        entry = self.processes[pid]
        entry["events"][name] += 1
        entry["last_seen"]     = ts
        entry["comm"]          = comm

        alert = None
        if event_type == 3 and comm not in ("gdb", "strace", "ltrace", "perf"):
            alert = f"SUSPICIOUS_PTRACE: {comm} (pid={pid}) ptracing {detail}"
        elif event_type == 8:
            alert = f"RWX_MMAP: {comm} (pid={pid}) mapped RWX memory — possible shellcode"
        elif event_type == 12:
            alert = f"PROCESS_VM_WRITE: {comm} (pid={pid}) writing to {detail}"
        elif event_type == 6 and comm not in ("sudo", "su", "login", "sshd", "passwd"):
            alert = f"UNEXPECTED_SETUID: {comm} (pid={pid}) → {detail}"
        elif event_type == 4 and "shadow" in detail:
            alert = f"SHADOW_READ: {comm} (pid={pid}) opened {detail}"

        if alert:
            self.alerts.append({"ts": ts, "alert": alert, "pid": pid, "comm": comm})
            print(f"\n  ⚠️  ALERT: {alert}\n")

    def get_ancestors(self, pid: int) -> list[int]:
        chain, visited, current = [], set(), pid
        while current in self.processes and current not in visited:
            visited.add(current)
            chain.append(current)
            current = self.processes[current]["ppid"]
        return chain

    def get_tree(self, root_pid: int, depth: int = 0, max_depth: int = 10) -> dict:
        if depth > max_depth or root_pid not in self.processes:
            return {}
        info = self.processes[root_pid]
        return {
            "pid": root_pid, "comm": info["comm"],
            "events": dict(info["events"]),
            "children": [
                self.get_tree(c, depth + 1, max_depth)
                for c in sorted(self.children.get(root_pid, []))
            ],
        }

    def dump_summary(self, path: str = "pid_tree_summary.json"):
        roots = {pid for pid, info in self.processes.items()
                 if info["ppid"] not in self.processes}
        output = {
            "generated_at": datetime.now().isoformat(),
            "alerts":       self.alerts,
            "trees":        [self.get_tree(r) for r in sorted(roots)],
        }
        with open(path, "w") as fp:
            json.dump(output, fp, indent=2, default=str)

    def print_stats(self):
        print("\n===== PID-Tree Event Summary =====")
        ranked = sorted(self.processes.items(),
                        key=lambda kv: sum(kv[1]["events"].values()), reverse=True)
        for pid, info in ranked[:20]:
            total = sum(info["events"].values())
            evts  = ", ".join(f"{k}:{v}" for k, v in sorted(info["events"].items()))
            anc   = " -> ".join(str(a) for a in reversed(self.get_ancestors(pid)))
            print(f"  PID {pid:>7} ({info['comm']:<16}) total={total:>5}  [{evts}]  tree: {anc}")
        if self.alerts:
            print(f"\n  🚨 {len(self.alerts)} alert(s) fired — see pid_tree_summary.json")
        print("==================================\n")

# ---------------------------------------------------------------------------
# Compile & attach
# ---------------------------------------------------------------------------
b = BPF(text=program)
print("eBPF program loaded.")

# ---------------------------------------------------------------------------
# Dedup cache
# ---------------------------------------------------------------------------
DEDUP_WINDOW = 5.0
_dedup_cache: dict[tuple, float] = {}

def is_duplicate(pid: int, etype: int, detail: str, ts: float) -> bool:
    key  = (pid, etype, detail[:32])
    last = _dedup_cache.get(key)
    if last and (ts - last) < DEDUP_WINDOW:
        return True
    _dedup_cache[key] = ts
    if len(_dedup_cache) > 10_000:
        cutoff = ts - DEDUP_WINDOW
        for k in [k for k, v in _dedup_cache.items() if v < cutoff]:
            del _dedup_cache[k]
    return False

# ---------------------------------------------------------------------------
# CSV + aggregator setup
# ---------------------------------------------------------------------------
log_file         = "hids_exec_log.csv"
aggregator       = PIDTreeAggregator()
SUMMARY_INTERVAL = 30
last_summary     = time.time()

log_f  = open(log_file, "w", newline="")
writer = csv.writer(log_f)
writer.writerow(["timestamp", "pid", "ppid", "process_name",
                 "event_type", "event_name", "severity", "detail"])

# ---------------------------------------------------------------------------
# Clean shutdown handler — fixes the Ctrl+C problem
# ---------------------------------------------------------------------------
def shutdown(signum, frame):
    print("\nShutting down — writing final summary...")
    aggregator.print_stats()
    aggregator.dump_summary()
    log_f.flush()
    log_f.close()
    print(f"Log saved → {log_file}")
    sys.exit(0)

signal.signal(signal.SIGINT,  shutdown)
signal.signal(signal.SIGTERM, shutdown)

# ---------------------------------------------------------------------------
# Event callback
# ---------------------------------------------------------------------------
def print_event(cpu, data, size):
    global last_summary

    event  = b["events"].event(data)
    ts     = time.time()
    comm   = event.comm.decode("utf-8", "replace").rstrip("\x00")
    etype  = event.event_type
    ename  = EVENT_NAMES.get(etype, "unknown")
    sev    = EVENT_SEVERITY.get(etype, "MED")
    detail = build_detail(event)

    # Deduplicate MED noise
    if sev == "MED" and is_duplicate(event.pid, etype, detail, ts):
        return

    # CSV logging
    writer.writerow([
        ts,
        event.pid,
        event.ppid,
        comm,
        etype,
        ename,
        sev,
        detail
    ])
    log_f.flush()

    # Aggregation
    aggregator.record(event.pid, event.ppid, comm, etype, detail, ts)

    # Clean console output (NO emojis)
    print(
        f"[{datetime.fromtimestamp(ts).strftime('%H:%M:%S')}] "
        f"SEVERITY={sev:<6} "
        f"PID={event.pid:<7} "
        f"PPID={event.ppid:<7} "
        f"COMM={comm:<16} "
        f"EVENT={ename:<20} "
        f"{detail[:60]}"
    )

    if ts - last_summary > SUMMARY_INTERVAL:
        last_summary = ts
        aggregator.print_stats()
        aggregator.dump_summary()
# ---------------------------------------------------------------------------
# Main loop — no try/except needed, signal handler owns shutdown
# ---------------------------------------------------------------------------
b["events"].open_perf_buffer(print_event, page_cnt=256)

print("HIDS monitor running... Ctrl+C to stop.")
print(f"Logging → {log_file}  |  Summary every {SUMMARY_INTERVAL}s\n")

while True:
    b.perf_buffer_poll(timeout=100)