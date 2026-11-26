/*
 * environ_rewrite - overwrites its environment memory as soon as it starts, the way processes setting
 * their title do (e.g. PHP-FPM, Ruby), then forks a child.
 */
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

int main(void) {
    /* The environment strings are contiguous, this is the memory /proc/<pid>/environ reads. */
    if (environ[0] != NULL) {
        char *end = environ[0];
        for (char **e = environ; *e != NULL; e++) {
            end = *e + strlen(*e) + 1;
        }
        memset(environ[0], 0, end - environ[0]);
    }

    pid_t pid = fork();
    if (pid == 0) {
        usleep(300 * 1000);
        _exit(0);
    }
    if (pid > 0)
        waitpid(pid, NULL, 0);

    return 0;
}
