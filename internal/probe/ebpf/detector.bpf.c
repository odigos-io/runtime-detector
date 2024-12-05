#include "vmlinux.h"
#include "bpf_helpers.h"

#ifndef NO_BTF
#include "bpf_core_read.h"
#include "bpf_tracing.h"
#endif

char __license[] SEC("license") = "Dual MIT/GPL";

#define MAX_ENV_VARS              (128)
#define MAX_NS_FOR_PID            (8)

// This max is only for processes we track.
// Those which are filtered out are not counted in this limit.
#define MAX_CONCURRENT_PIDS       (16384) // 2^14

// The maximum length of the prefix we are looking for in the environment variables.
#define MAX_ENV_PREFIX_LEN        (128)
#define MAX_ENV_PREFIX_MASK       ((MAX_ENV_PREFIX_LEN) - 1)

typedef struct env_prefix {
    u64 len;
    u8 prefix[MAX_ENV_PREFIX_LEN];
} env_prefix_t;

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, u32);
    __type(value, env_prefix_t);
    __uint(max_entries, 1);
} env_prefix SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);   // the pid as return from bpf_get_current_pid_tgid()
	__type(value, u32); // the pid in the configured namespace (user space is aware of)
	__uint(max_entries, MAX_CONCURRENT_PIDS);
} tracked_pids_to_ns_pids SEC(".maps");

// The following map is used to store the mapping between the PID in the configured namespace
// (which the user is aware of) and the PID in the last level namespace (the container PID).
// It can be read from user-space.
// user space can also write to this function in the initialization phase
// to let the probes know about relevant process which are already running.
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
volatile const u32 configured_pid_ns_inode = 0;

// return the configured env prefix for filtering, or NULL if invalid
static __always_inline env_prefix_t *get_env_prefix() {
    u32 key = 0;
    char prefix[MAX_ENV_PREFIX_LEN] = {0};
    env_prefix_t *configured_prefix = bpf_map_lookup_elem(&env_prefix, &key);

    if (!configured_prefix) {
        bpf_printk("Env prefix not configured\n");
        return NULL;
    }

    // the user space code should validate that the prefix is not longer than MAX_ENV_PREFIX_LEN as well.
    u64 len = configured_prefix->len;
    if (len > MAX_ENV_PREFIX_LEN) {
        bpf_printk("Env prefix is too long: %lld\n", len);
        return NULL;
    }

    return configured_prefix;
}

static __always_inline bool is_env_prefix_match(char *env, env_prefix_t *configured_prefix) {
    u64 len = configured_prefix->len;
    for (int i = 0; i < (len & MAX_ENV_PREFIX_MASK); i++) {
        if (env[i] != configured_prefix->prefix[i]) {
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

#ifndef NO_BTF
static __always_inline long get_pid_for_configured_ns(struct task_struct *task, pids_in_ns_t *pids) {
    struct upid upid =     {0};
    u32 inum =              0;
    u32 selected_pid =      0;
    unsigned int level =    BPF_CORE_READ(task, thread_pid, level);
    unsigned int num_pids = level + 1;
    bool found =            false;

    if (num_pids > MAX_NS_FOR_PID) {
        bpf_printk("Number of PIDs is greater than supported: %d", num_pids);
        num_pids = MAX_NS_FOR_PID;
    }

    for (int i = 0; i < num_pids && i < MAX_NS_FOR_PID; i++) {
        upid = BPF_CORE_READ(task, thread_pid, numbers[i]);
        inum = BPF_CORE_READ(upid.ns, ns.inum);
        if (inum == configured_pid_ns_inode) {
            pids->configured_ns_pid = upid.nr;
            found = true;
            break;
        }
    }

    if (!found) {
        return -1;
    }

    upid = BPF_CORE_READ(task, thread_pid, numbers[level]);
    pids->last_level_pid = upid.nr;

    return 0;
}
#endif

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
    char buf[MAX_ENV_PREFIX_LEN + 1] = {0};
    long ret;
    bool found_relevant = false;
    env_prefix_t *configured_prefix = get_env_prefix();
    if (!configured_prefix) {
        return 0;
    }

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

        if (is_env_prefix_match(&buf[0], configured_prefix)) {
            found_relevant = true;
            break;
        }
	}

    if (!found_relevant) {
        return 0;
    }

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid =  (u32)(pid_tgid & 0xFFFFFFFF);
    pids_in_ns_t pids = {0};

#ifdef NO_BTF
    pids.configured_ns_pid = pid;
    pids.last_level_pid = 0;
#else
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    ret = get_pid_for_configured_ns(task, &pids);
    if (ret < 0) {
        bpf_printk("Could not find PID for task: 0x%llx", bpf_get_current_pid_tgid());
        return 0;
    }
#endif

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

/*
sched_process_fork is located inside the kernel_clone function in the kernel.
it is common to the syscalls: fork, vfork, clone, and clone3.
*/
#ifndef NO_BTF
SEC("raw_tp/sched_process_fork")
int BPF_PROG(tracepoint_btf__sched__sched_process_fork, struct task_struct *parent, struct task_struct *child) {
    long ret_code = 0; 

    u32 parent_pid = (u32)BPF_CORE_READ(parent, pid);
    u32 child_pid = (u32)BPF_CORE_READ(child, pid);

    // filter only relevant pids based on the parent
    // check if that this clone/fork is called from a process we are tracking (went through execve)
    void *found = bpf_map_lookup_elem(&tracked_pids_to_ns_pids, &parent_pid);
    if (found == NULL) {
        return 0;
    }

    pids_in_ns_t pids = {0};

    ret_code = get_pid_for_configured_ns(child, &pids);
    if (ret_code < 0) {
        bpf_printk("Could not find PID for task: 0x%llx", child_pid);
        return 0;
    }

    // track this child pid
    ret_code = bpf_map_update_elem(&tracked_pids_to_ns_pids, &child_pid, &pids.configured_ns_pid, BPF_ANY);
    if (ret_code != 0) {
        bpf_printk("Failed to update PID to NS PID map: %d", ret_code);
        return 0;
    }

    // populate the map with the container pid, so that user space can read it
    ret_code = bpf_map_update_elem(&user_pid_to_container_pid, &pids.configured_ns_pid, &pids.last_level_pid, BPF_ANY);
    if (ret_code != 0) {
        bpf_printk("Failed to update user PID to container PID map: %d", ret_code);
        return 0;
    }

    process_event_t event = {
        .type = PROCESS_EXEC,
        .pid = pids.configured_ns_pid,
    };

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    return 0;
}
#else
SEC("tracepoint/sched/sched_process_fork")
int tracepoint__sched__sched_process_fork(struct trace_event_raw_sched_process_fork* ctx) {
    long ret_code = 0;
    u32 parent_pid = (u32)ctx->parent_pid;
    u32 child_pid = (u32)ctx->child_pid;

    // check if that this clone/fork is called from a process we are tracking (went through execve)
    void *found = bpf_map_lookup_elem(&tracked_pids_to_ns_pids, &parent_pid);
    if (found == NULL) {
        return 0;
    }

    u32 unknown_pid = 0;
    ret_code = bpf_map_update_elem(&tracked_pids_to_ns_pids, &child_pid, &child_pid, BPF_ANY);
    if (ret_code != 0) {
        bpf_printk("Failed to update PID to NS PID map: %d", ret_code);
        return 0;
    }

    // populate the map with the container pid, so that user space can read it
    // since we don't have BTF here, we can't get the last level pid
    ret_code = bpf_map_update_elem(&user_pid_to_container_pid, &child_pid, &unknown_pid, BPF_ANY);
    if (ret_code != 0) {
        bpf_printk("Failed to update user PID to container PID map: %d", ret_code);
        return 0;
    }

    process_event_t event = {
        .type = PROCESS_EXEC,
        .pid = child_pid,
    };

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    return 0;
}
#endif

SEC("tracepoint/sched/sched_process_exit")
int tracepoint__sched__sched_process_exit(struct trace_event_raw_sched_process_exec* ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = (u32)(pid_tgid >> 32);
    u32 pid =  (u32)(pid_tgid & 0xFFFFFFFF);
    long ret = 0;

    if (tgid != pid) {
        // Only if the thread group ID matched with the PID the process itself exits. If they don't
        // match only a thread of the process stopped and we do not need to report this PID to
        // userspace for further processing.
        return 0;
    }

    process_event_t event = { .type = PROCESS_EXIT};

    // look this pid in the map, we will find an entry if this process was found relevant in the exec/fork probes
    u32 *selected_pid = bpf_map_lookup_elem(&tracked_pids_to_ns_pids, &pid);
    if (selected_pid == NULL) {
        // get the pid in the configured namespace
        pids_in_ns_t pids = {0};
#ifdef NO_BTF
        pids.configured_ns_pid = pid;
        pids.last_level_pid = 0;
#else
        struct task_struct *task = (struct task_struct *)bpf_get_current_task();
        ret = get_pid_for_configured_ns(task, &pids);
        if (ret < 0) {
            bpf_printk("process exit: Could not find PID for task return code: %ld", ret);
            return 0;
        }
#endif
        // find out if this exit event is for a process we are interested in
        // this can happen if this map was written to by the user space
        void *found = bpf_map_lookup_elem(&user_pid_to_container_pid, &pids.configured_ns_pid);
        if (found == NULL) {
            return 0;
        }
        event.pid = pids.configured_ns_pid;
    } else {
        event.pid = *selected_pid;
    }

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    bpf_map_delete_elem(&user_pid_to_container_pid,  &event.pid);
    bpf_map_delete_elem(&tracked_pids_to_ns_pids, &pid);
    return 0;
}