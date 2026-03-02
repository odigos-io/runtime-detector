/*
 * signal_fork - a process that forks in response to SIGUSR1.
 * Exits cleanly on SIGTERM.
 */
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>

static volatile sig_atomic_t got_term = 0;
static volatile sig_atomic_t got_usr1 = 0;

static void handle_usr1(int sig) {
    got_usr1 = 1;
}

static void handle_term(int sig) {
    got_term = 1;
}

int main(void) {
    struct sigaction sa1 = { .sa_handler = handle_usr1 };
    struct sigaction sa_term = { .sa_handler = handle_term };
    sigaction(SIGUSR1, &sa1, NULL);
    sigaction(SIGTERM, &sa_term, NULL);

    /* Signal readiness by writing to stdout. */
    printf("ready\n");
    fflush(stdout);

    while (!got_term) {
        // pause() causes the calling process (or thread) to sleep until a
        // signal is delivered that either terminates the process or causes
        // the invocation of a signal-catching function
        pause();

        if (got_usr1) {
            got_usr1 = 0;
            pid_t pid = fork();
            if (pid == 0) {
                /* Child: sleep briefly so the detector can observe it. */
                sleep(1);
                _exit(0);
            }
            /* Parent: reap the child. */
            if (pid > 0)
                waitpid(pid, NULL, 0);
        }
    }

    return 0;
}
