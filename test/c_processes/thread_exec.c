/*
 * thread_exec - a minimal test program where a non-leader thread calls execve.
 *
 * Mode 1 (default, no args):
 *   The main thread creates a second thread. The second thread sleeps briefly
 *   and then calls execve on itself with the "--child" flag.
 *   Because a non-leader thread calls execve, the kernel performs de_thread():
 *   it kills the original leader and changes the calling thread's pid to tgid.
 *
 * Mode 2 (--child):
 *   Just sleep and exit. This is the target of the non-leader thread's exec.
 *
 * Expected detector events (with zero duration filter):
 *   ProcessExecEvent  (initial exec of this binary)
 *   ProcessExitEvent  (leader is killed by the kernel after the non-leader thread's execve)
 *   ProcessExecEvent  (non-leader thread's exec succeeds — this binary in --child mode)
 *   ProcessExitEvent  (process exits after sleep)
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

extern char **environ;

static void *thread_func(void *arg) {
    char *self_path = (char *)arg;

    /* Small delay so the initial exec event is processed first. */
    usleep(200000); /* 200 ms */

    char *new_argv[] = {self_path, "--child", NULL};
    execve(self_path, new_argv, environ);

    /* Should not reach here. */
    perror("execve");
    _exit(1);
    return NULL;
}

int main(int argc, char *argv[]) {
    /* Mode 2: --child — just sleep and exit. */
    if (argc >= 2 && strcmp(argv[1], "--child") == 0) {
        sleep(1);
        return 0;
    }

    /* Mode 1: create a non-leader thread that will exec. */
    pthread_t thread;
    int ret = pthread_create(&thread, NULL, thread_func, argv[0]);
    if (ret != 0) {
        fprintf(stderr, "pthread_create failed: %d\n", ret);
        return 1;
    }

    pthread_join(thread, NULL);
    return 0;
}
