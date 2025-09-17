#include "vmlinux.h"
#include "bpf_helpers.h"
#include "utils.h"

#ifndef NO_BTF
#include "bpf_core_read.h"
#include "bpf_tracing.h"
#endif

char __license[] SEC("license") = "Dual MIT/GPL";

#define MAX_NS_FOR_PID            (8)

// This max is only for processes we track.
// Those which are filtered out are not counted in this limit.
#define MAX_CONCURRENT_PIDS       (16384) // 2^14

// The maximum length of the prefix we are looking for in the environment variables.
#define MAX_ENV_PREFIX_LEN        (16)
#define MAX_ENV_PREFIX_MASK       ((MAX_ENV_PREFIX_LEN) - 1)
#ifndef SMALL_PROGRAM
#define MAX_ENV_VARS              (1536)
#else
#define MAX_ENV_VARS              (128)
#endif

// The maximum length of the executable pathname to filter out.
#define MAX_EXEC_PATHNAME_LEN     (64)
#define MAX_EXEC_PATHNAME_MASK    ((MAX_EXEC_PATHNAME_LEN) - 1)
#define MAX_EXEC_PATHS_TO_FILTER  (32)

// The maximum length of the path we are looking for in the openat syscall
#define MAX_OPEN_PATHNAME_LEN     (128)
#define MAX_OPEN_PATHNAME_MASK    ((MAX_OPEN_PATHNAME_LEN) - 1)
#define MAX_OPEN_PATHS_TO_TRACK   (8)

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

typedef struct {
    u64 len;
    u8  buf[MAX_OPEN_PATHNAME_LEN];
} open_filename_t;

typedef struct {
    u64 len;
    u8  buf[MAX_EXEC_PATHNAME_LEN];
} exec_filename_t;

typedef struct {
    // This is the inode number of the PID namespace we are interested in.
    // It is set by the userspace code.
    // It may be 0, in that case we will report PIDs as seen by the root ns.
    u32 configured_pid_ns_inode;
    u8 padding[4];

    // injected by the user space code, indicating how many paths are configured to track in the open probe,
    // must be less than or equal to MAX_OPEN_PATHS_TO_TRACK
    u8 num_open_paths_to_track;
    // injected by the user space code, indicating how many paths are configured
    // to be filtered out in the exec probe, must be less than or equal to MAX_EXEC_PATHS_TO_FILTER
    u8 num_exec_paths_to_filter;
    u8 padding2[6];
} detector_config_t;

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, u32);
    __type(value, detector_config_t);
    __uint(max_entries, 1);
} detector_config SEC(".maps");

// Used to store the paths configured to be tracked for relevant processes when open occurs.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, u32);
    __type(value, open_filename_t);
    __uint(max_entries, MAX_OPEN_PATHS_TO_TRACK);
} files_open_to_track SEC(".maps");

// Used to store the executable paths configured to be ignored in the exec probe.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, u32);
    __type(value, exec_filename_t);
    __uint(max_entries, MAX_EXEC_PATHS_TO_FILTER);
} exec_files_to_filter SEC(".maps");

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
    PROCESS_FORK = 3,
    PROCESS_FILE_OPEN = 4,
} process_event_type_t;

typedef struct process_event {
    u32 type;
    u32 pid;
} process_event_t;

// return the configured env prefix for filtering, or NULL if invalid
static __always_inline env_prefix_t *get_env_prefix() {
    u32 key = 0;
    char prefix[MAX_ENV_PREFIX_LEN] = {0};
    env_prefix_t *configured_prefix = bpf_map_lookup_elem(&env_prefix, &key);

    if (!configured_prefix) {
        return NULL;
    }

    // the user space code should validate that the prefix is not longer than MAX_ENV_PREFIX_LEN as well.
    u64 len = configured_prefix->len;
    if (len > MAX_ENV_PREFIX_LEN) {
        return NULL;
    }

    return configured_prefix;
}

static __always_inline bool is_env_prefix_match(char *env, env_prefix_t *configured_prefix) {
    return __bpf_memcmp(env, configured_prefix->prefix, MAX_ENV_PREFIX_LEN);
}

static __always_inline bool compare_open_filenames(open_filename_t *opened_filename, open_filename_t *configured_filename) {
    if (opened_filename->len != configured_filename->len) {
        return false;
    }

    u64 len = configured_filename->len;
    if (len == 0) {
        return false;
    }

    return __bpf_memcmp(opened_filename->buf, configured_filename->buf, MAX_OPEN_PATHNAME_LEN);
}

static __always_inline bool compare_exec_filenames(exec_filename_t *executed_filename, exec_filename_t *configured_filename) {
    if (executed_filename->len != configured_filename->len) {
        return false;
    }

    u64 len = configured_filename->len;
    if (len == 0) {
        return false;
    }

    return __bpf_memcmp(executed_filename->buf, configured_filename->buf, MAX_EXEC_PATHNAME_LEN);
}

typedef struct pids_in_ns {
    // the pid in the configured namespace (user space is aware of)
    u32 configured_ns_pid;
    // the pid in the last level namespace (the container pid)
    u32 last_level_pid;
} pids_in_ns_t;

#ifndef NO_BTF
static __always_inline long get_pid_for_configured_ns(struct task_struct *task, pids_in_ns_t *pids, u32 host_pid) {
    struct upid upid =         {0};
    u32 inum =                  0;
    u32 selected_pid =          0;
    unsigned int level =        BPF_CORE_READ(task, thread_pid, level);
    unsigned int num_pids =     level + 1;
    bool found =                false;
    detector_config_t *config = NULL;
    u32 zero_key =              0;

    if (num_pids > MAX_NS_FOR_PID) {
        num_pids = MAX_NS_FOR_PID;
    }

    config = bpf_map_lookup_elem(&detector_config, &zero_key);
    if (config == NULL) {
        return -1;
    }

    u32 configured_pid_ns_inode = config->configured_pid_ns_inode;
    if (configured_pid_ns_inode == 0) {
        pids->configured_ns_pid = host_pid;
        goto done;
    }

#pragma unroll(MAX_NS_FOR_PID)
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

done:
    upid = BPF_CORE_READ(task, thread_pid, numbers[level]);
    pids->last_level_pid = upid.nr;

    return 0;
}
#endif

static __always_inline bool is_executable_ignored(const char *filename) {
    exec_filename_t executed_filename = {0};
    long bytes_read = bpf_probe_read_user_str(&executed_filename.buf[0], sizeof(executed_filename.buf), filename);
    if (bytes_read <= 0) {
        // we might fail to read the filename if the user memory for that string is not paged in yet.
        // see https://mozillazg.com/2024/03/ebpf-tracepoint-syscalls-sys-enter-execve-can-not-get-filename-argv-values-case-en.html for more details.
        // pass the event to user space, to avoid missing the execve event of a possible relevant process.
        return false;
    }

    // bytes read includes the null terminator
    executed_filename.len = bytes_read - 1;
    exec_filename_t *configured_filename = NULL;

    u32 zero_key = 0;
    detector_config_t *config = bpf_map_lookup_elem(&detector_config, &zero_key);
    if (config == NULL) {
        return false;
    }

    u32 num_paths = config->num_exec_paths_to_filter;
    u32 idx = 0;
    for (u32 i = 0; i < num_paths; i++) {
        idx = i;
        configured_filename = bpf_map_lookup_elem(&exec_files_to_filter, &idx);
        if (configured_filename == NULL) {
            break;
        }
        if (compare_exec_filenames(&executed_filename, configured_filename)) {
            // this is an executable we should ignore
            return true;
        }
    }

    return false;
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
    u64 pid_tgid = 0;
    u32 pid = 0;
    pids_in_ns_t pids = {0};
    struct task_struct *task = NULL;
    const char **envp = (const char **)(ctx->args[2]);
    const char *argp;
    // save space for a terminating null byte
    char buf[MAX_ENV_PREFIX_LEN + 1] = {0};
    long ret;
    env_prefix_t *configured_prefix = get_env_prefix();
    if (!configured_prefix) {
        return 0;
    }

    // only read up to the configured prefix length
    // if the configured prefix is shorter than MAX_ENV_PREFIX_LEN,
    // the buffer will have the contents [<max prefix length bytes>, 0, 0 ,...0]
    // this allows us to always use a constant-size compare function
    // (comparing MAX_ENV_PREFIX_LEN bytes) in an optimized way
    // and a verifier-friendly way.
    u32 size_to_read = configured_prefix->len;
    if (size_to_read > MAX_ENV_PREFIX_LEN) {
        // user space should validate the env prefix passed, this should not happen if user space verifies the prefix length
        return 0;
    }

    int i = 0;
#pragma unroll
    for (; i < MAX_ENV_VARS; i++) {
        ret = bpf_probe_read_user(&argp, sizeof(argp), &envp[i]);
        if (ret < 0) {
            return 0;
        }

        if (!argp) {
            // envp[i] is NULL, we reached the end of the environment variables vector
            // and did not find a relevant one.
            return 0;
        }

        ret = bpf_probe_read_user(&buf[0], size_to_read, argp);
        if (ret < 0) {
            // we tried to read a **non** NULL pointer, but failed.
            // this can happen if the user memory for that string is not paged in yet.
            break;
        }

        if (is_env_prefix_match(&buf[0], configured_prefix)) {
            break;
        }
    }

    // from this point - there are 3 possibilities:
    // 1. Found a relevant environment variable, and the process is relevant.
    // 2. We failed to read one of the environment variables, and are not certain whether the process is relevant or not.
    // 3. Scanned the first MAX_ENV_VARS environment variables and did not find a relevant one - no certainty that the process is relevant or not.

#ifndef SMALL_PROGRAM
    // check if the executed file is in the list of files to ignore
    const char *filename = (const char *)(ctx->args[0]);
    if (is_executable_ignored(filename)) {
        return 0;
    }
#endif

    pid_tgid = bpf_get_current_pid_tgid();
    pid =  (u32)(pid_tgid & 0xFFFFFFFF);

#ifdef NO_BTF
    pids.configured_ns_pid = pid;
    pids.last_level_pid = 0;
#else
    task = (struct task_struct *)bpf_get_current_task();
    ret = get_pid_for_configured_ns(task, &pids, pid);
    if (ret < 0) {
        return 0;
    }
#endif

    ret = bpf_map_update_elem(&tracked_pids_to_ns_pids, &pid, &pids.configured_ns_pid, BPF_ANY);
    if (ret != 0) {
        return 0;
    }

    ret = bpf_map_update_elem(&user_pid_to_container_pid, &pids.configured_ns_pid, &pids.last_level_pid, BPF_ANY);
    if (ret != 0) {
        return 0;
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_execve")
int tracepoint__syscalls__sys_exit_execve(struct syscall_trace_exit* ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid =  (u32)(pid_tgid & 0xFFFFFFFF);

    u32 *user_pid = bpf_map_lookup_elem(&tracked_pids_to_ns_pids, &pid);
    if (user_pid == NULL) {
        return 0;
    }

    process_event_t event = {
        .type = PROCESS_EXEC,
        .pid = *user_pid,
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

    u32 parent_tgid = (u32)BPF_CORE_READ(parent, tgid);
    u32 child_tgid = (u32)BPF_CORE_READ(child, tgid);

    if (parent_tgid == child_tgid) {
        // this is a thread, not a process
        return 0;
    }

    u32 parent_pid = (u32)BPF_CORE_READ(parent, pid);
    u32 child_pid = (u32)BPF_CORE_READ(child, pid);

    // filter only relevant pids based on the parent
    // check if that this clone/fork is called from a process we are tracking
    void *found = bpf_map_lookup_elem(&tracked_pids_to_ns_pids, &parent_pid);
    if (found == NULL) {
        return 0;
    }

    pids_in_ns_t pids = {0};

    ret_code = get_pid_for_configured_ns(child, &pids, child_pid);
    if (ret_code < 0) {
        return 0;
    }

    // track this child pid
    ret_code = bpf_map_update_elem(&tracked_pids_to_ns_pids, &child_pid, &pids.configured_ns_pid, BPF_ANY);
    if (ret_code != 0) {
        return 0;
    }

    // populate the map with the container pid, so that user space can read it
    ret_code = bpf_map_update_elem(&user_pid_to_container_pid, &pids.configured_ns_pid, &pids.last_level_pid, BPF_ANY);
    if (ret_code != 0) {
        return 0;
    }

    process_event_t event = {
        .type = PROCESS_FORK,
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

    // we can't make sure here that the child pid is a new process, and not a thread.
    // this will be verified in user space (only when BTF is not available)

    u32 unknown_pid = 0;
    ret_code = bpf_map_update_elem(&tracked_pids_to_ns_pids, &child_pid, &child_pid, BPF_ANY);
    if (ret_code != 0) {
        return 0;
    }

    // populate the map with the container pid, so that user space can read it
    // since we don't have BTF here, we can't get the last level pid
    ret_code = bpf_map_update_elem(&user_pid_to_container_pid, &child_pid, &unknown_pid, BPF_ANY);
    if (ret_code != 0) {
        return 0;
    }

    process_event_t event = {
        .type = PROCESS_FORK,
        .pid = child_pid,
    };

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    return 0;
}
#endif

SEC("tracepoint/syscalls/sys_enter_openat")
int tracepoint__syscalls__sys_enter_openat(struct syscall_trace_enter* ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = (u32)(pid_tgid >> 32);

    // the open can be called on a different thread than the main one,
    // hence we use the tgid to find the main pid we are tracking
    u32 *userspace_pid = bpf_map_lookup_elem(&tracked_pids_to_ns_pids, &tgid);
    if (userspace_pid == NULL) {
        return 0;
    }

    /*
    The format of the tracepoint args is:
        field:int dfd;	offset:16;	size:8;	signed:0;
        field:const char * filename;	offset:24;	size:8;	signed:0;
        field:int flags;	offset:32;	size:8;	signed:0;
        field:umode_t mode;	offset:40;	size:8;	signed:0;
    */

    const char *filename = (const char *)(ctx->args[1]);
    open_filename_t opened_filename = {0};

    long bytes_read = bpf_probe_read_user_str(&opened_filename.buf[0], sizeof(opened_filename.buf), filename);
    if (bytes_read <= 0) {
        return 0;
    }

    // bytes read includes the null terminator
    opened_filename.len = bytes_read - 1;
    open_filename_t *configured_filename = NULL;

    u32 zero_key = 0;
    detector_config_t *config = bpf_map_lookup_elem(&detector_config, &zero_key);
    if (config == NULL) {
        return 0;
    }

    u32 num_paths = config->num_open_paths_to_track;

    // go over the configured relevant paths and check if the opened file matches any of them
#pragma unroll(MAX_OPEN_PATHS_TO_TRACK)
    for (u32 i = 0; i < MAX_OPEN_PATHS_TO_TRACK; i++) {
        if (i >= num_paths) {
            break;
        }

        u32 idx = i;
        configured_filename = bpf_map_lookup_elem(&files_open_to_track, &idx);
        if (configured_filename == NULL) {
            break;
        }

        if (compare_open_filenames(&opened_filename, configured_filename)) {
            process_event_t event = {
                .type = PROCESS_FILE_OPEN,
                .pid = *userspace_pid,
            };
            bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
            return 0;
        }
    }

    return 0;
}

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
#ifdef NO_BTF
        // we don't have BTF, hence we might have added the PID to the maps in the fork probe
        bpf_map_delete_elem(&user_pid_to_container_pid,  &pid);
        bpf_map_delete_elem(&tracked_pids_to_ns_pids, &pid);
#endif
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
        ret = get_pid_for_configured_ns(task, &pids, pid);
        if (ret < 0) {
            // this might happen for processes we are not tracking, and that are not in the configured namespace
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