#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events SEC(".maps");

typedef enum {
    UNDEFINED = 0,
    PROCESS_EXEC = 1,
    PROCESS_EXIT = 2,
} process_event_type_t;

typedef struct process_event {
    u32 type;
    u32 pid;
} process_event_t;

char __license[] SEC("license") = "Dual MIT/GPL";

SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint__syscalls__sys_enter_execve(struct syscall_trace_enter* ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = pid_tgid >> 32;

    process_event_t event = {
        .type = PROCESS_EXEC,
        .pid = tgid,
    };

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int tracepoint__sched__sched_process_exit(struct trace_event_raw_sched_process_exec* ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = (u32)(pid_tgid >> 32);
    u32 pid =  (u32)(pid_tgid & 0xFFFFFFFF);

    if (tgid != pid) {
        // Only if the thread group ID matched with the PID the process itself exits. If they don't
        // match only a thread of the process stopped and we do not need to report this PID to
        // userspace for further processing.
        return 0;
    }

    process_event_t event = {
        .type = PROCESS_EXIT,
        .pid = tgid,
    };

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    return 0;
}