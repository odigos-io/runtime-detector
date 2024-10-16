#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"

char __license[] SEC("license") = "Dual MIT/GPL";

// we use this env var prefix to filter out processes we are not interested in
const char odigos_env_prefix[] =  "ODIGOS_POD";
#define ODIGOS_PREFIX_LEN         (10)

#define MAX_ENV_VARS              (128)
#define MAX_NS_FOR_PID            (8)

// This max is only for processes we track.
// Those which are filtered out are not counted in this limit.
#define MAX_CONCURRENT_PIDS       (16384) // 2^14

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);   // the pid as return from bpf_get_current_pid_tgid()
	__type(value, u32); // the pid in the configured namespace (user space is aware of)
	__uint(max_entries, MAX_CONCURRENT_PIDS);
} tracked_pids_to_ns_pids SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);   // the pid in the configured namespace (user space is aware of)
	__type(value, u32); // the pid in the last level namespace (the container pid)
	__uint(max_entries, MAX_CONCURRENT_PIDS);
} user_pid_to_container_pid SEC(".maps");

typedef enum {
    UNDEFINED = 0,
    PROCESS_EXEC = 1,
    PROCESS_EXIT = 2,
} process_event_type_t;

typedef struct process_event {
    u32 type;
    u32 pid;
} process_event_t;

// This is the inode number of the PID namespace we are interested in.
// It is set by the userspace code.
volatile const u32 pid_ns_inode = 0;

static __always_inline bool is_odigos_env_prefix(char *env) {
    // don't compare the null terminator
    for (int i=0; i < ODIGOS_PREFIX_LEN; i++) {
        if (env[i] != odigos_env_prefix[i]) {
            return false;
        }
    }
    return true;
}

typedef struct pids_in_ns {
    // the pid in the configured namespace (user space is aware of)
    u32 configured_ns_pid;
    // the pid in the last level namespace (the container pid)
    u32 last_level_pid;
} pids_in_ns_t;

static __always_inline long get_pid_for_configured_ns(struct task_struct *task, pids_in_ns_t *pids) {
    struct upid upid =     {0};
    u32 inum =              0;
    u32 selected_pid =      0;
    unsigned int level =    BPF_CORE_READ(task, thread_pid, level);
    unsigned int num_pids = level + 1;

    if (num_pids > MAX_NS_FOR_PID) {
        bpf_printk("Number of PIDs is greater than supported: %d", num_pids);
        num_pids = MAX_NS_FOR_PID;
    }

    for (int i = 0; i < num_pids && i < MAX_NS_FOR_PID; i++) {
        upid = BPF_CORE_READ(task, thread_pid, numbers[i]);
        inum = BPF_CORE_READ(upid.ns, ns.inum);
        if (inum == pid_ns_inode) {
            pids->configured_ns_pid = upid.nr;
            break;
        }
    }

    upid = BPF_CORE_READ(task, thread_pid, numbers[level]);
    pids->last_level_pid = upid.nr;

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint__syscalls__sys_enter_execve(struct syscall_trace_enter* ctx) {
    /*
    The format of the tracepoint args is:
    args:
        field:const char * filename;	offset:16;	size:8;	signed:0;
        field:const char *const * argv;	offset:24;	size:8;	signed:0;
        field:const char *const * envp;	offset:32;	size:8;	signed:0;
    */
    const char **args = (const char **)(ctx->args[2]);
    const char *argp;
    // save space for a terminating null byte
    char buf[ODIGOS_PREFIX_LEN + 1] = {0};
    long ret;
    bool found_relevant = false;

    #pragma unroll
	for (int i = 1; i < MAX_ENV_VARS; i++) {
		ret = bpf_probe_read_user(&argp, sizeof(argp), &args[i]);
		if (ret < 0) {
			return 0;
        }

		ret = bpf_probe_read_user_str(&buf[0], sizeof(buf), argp);
		if (ret < 0) {
			return 0;
        }

        if (is_odigos_env_prefix(&buf[0])) {
            found_relevant = true;
            break;
        }
	}

    if (!found_relevant) {
        return 0;
    }

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    pids_in_ns_t pids = {0};
    ret = get_pid_for_configured_ns(task, &pids);
    if (ret < 0) {
        bpf_printk("Could not find PID for task: 0x%llx", bpf_get_current_pid_tgid());
        return 0;
    }

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid =  (u32)(pid_tgid & 0xFFFFFFFF);
    ret = bpf_map_update_elem(&tracked_pids_to_ns_pids, &pid, &pids.configured_ns_pid, BPF_ANY);
    if (ret != 0) {
        bpf_printk("Failed to update PID to NS PID map: %d", ret);
        return 0;
    }

    ret = bpf_map_update_elem(&user_pid_to_container_pid, &pids.configured_ns_pid, &pids.last_level_pid, BPF_ANY);
    if (ret != 0) {
        bpf_printk("Failed to update user PID to container PID map: %d", ret);
        return 0;
    }

    process_event_t event = {
        .type = PROCESS_EXEC,
        .pid = pids.configured_ns_pid,
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

    // look this pid in the map, avoid sending exit event for PIDs we didn't send exec event for.
    u32 *selected_pid = bpf_map_lookup_elem(&tracked_pids_to_ns_pids, &pid);
    if (selected_pid == NULL) {
        return 0;
    }

    process_event_t event = {
        .type = PROCESS_EXIT,
        .pid = *selected_pid,
    };

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    bpf_map_delete_elem(&tracked_pids_to_ns_pids, &pid);
    bpf_map_delete_elem(&user_pid_to_container_pid, selected_pid);
    return 0;
}