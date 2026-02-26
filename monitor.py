from bcc import BPF
import csv
import time
import os

# eBPF program

"""
example entries execsnoop

sed              26965   26963     0 /usr/bin/sed -e s/\\/\\x5x/g -e s/;/\\x3b/g
ls               26966   26696     0 /usr/bin/ls --color=auto
sed              26970   26968     0 /usr/bin/sed -e s/\\/\\x5x/g -e s/;/\\x3b/g
sed              26976   26974     0 /usr/bin/sed -e s/\\/\\x5x/g -e s/;/\\x3b/g
    
"""
program = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct data_t {
    u32 pid;
    u32 ppid;
    char comm[TASK_COMM_LEN];
};

BPF_PERF_OUTPUT(events);

int trace_exec(struct pt_regs *ctx) { //runs when execve called
    struct data_t data = {};
    
    u64 pid_tgid = bpf_get_current_pid_tgid();
    data.pid = pid_tgid >> 32;
    
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task(); // get PPID
    data.ppid = task->real_parent->tgid;
    
    bpf_get_current_comm(&data.comm, sizeof(data.comm)); //process name
    
    events.perf_submit(ctx, &data, sizeof(data));//send struct to python
    return 0;
}
"""

b = BPF(text=program)
b.attach_kprobe(event="__x64_sys_execve", fn_name="trace_exec")

# Create log file
log_file = "hids_exec_log.csv"
file_exists = os.path.isfile(log_file)

with open(log_file, "a", newline="") as f:
    writer = csv.writer(f)

    if not file_exists:
        writer.writerow(["timestamp", "pid", "ppid", "process_name"])

    def print_event(cpu, data, size):
        event = b["events"].event(data)
        timestamp = time.time()
        process_name = event.comm.decode("utf-8", "replace")

        writer.writerow([timestamp, event.pid, event.ppid, process_name])
        f.flush()

        print(f"[{timestamp}] PID={event.pid} PPID={event.ppid} COMM={process_name}")

    b["events"].open_perf_buffer(print_event)

    print("HIDS execve monitor running... Ctrl+C to stop.")

    while True:
        try:
            b.perf_buffer_poll()
        except KeyboardInterrupt:
            print("Stopping monitor.")
            break