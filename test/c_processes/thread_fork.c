/*
 * thread_fork - a minimal test program where a non-leader thread calls fork().
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/wait.h>

static void *thread_func(void *arg) {
    /* Small delay so the initial exec event is processed first. */
    usleep(200000); /* 200 ms */

    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return NULL;
    }

    if (pid == 0) {
        /* Child process — sleep briefly and exit. */
        sleep(1);
        _exit(0);
    }

    /* Parent thread — wait for the child to exit. */
    waitpid(pid, NULL, 0);
    return NULL;
}

int main(int argc, char *argv[]) {
    pthread_t thread;
    int ret = pthread_create(&thread, NULL, thread_func, NULL);
    if (ret != 0) {
        fprintf(stderr, "pthread_create failed: %d\n", ret);
        return 1;
    }

    pthread_join(thread, NULL);
    return 0;
}
