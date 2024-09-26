#include "common.h"
#include "bpf_helpers.h"

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events SEC(".maps");

char __license[] SEC("license") = "Dual MIT/GPL";

SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint__syscalls__sys_enter_execve(void *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = pid_tgid >> 32;
    bpf_printk("Hello, execve! %d\n", tgid);

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &tgid, sizeof(tgid));
    return 0;
}