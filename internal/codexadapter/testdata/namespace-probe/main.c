/* Fixed offline runtime diagnostic, never a product entrypoint. No mounts,
 * commands, network operations or operator-selected syscall flags. */
#define _GNU_SOURCE
#include <errno.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static void probe(const char *name, int clone_call, unsigned long flags) {
    pid_t worker = fork();
    if (worker < 0) _exit(2);
    if (worker == 0) {
        errno = 0;
        long result = clone_call ? syscall(SYS_clone, flags | SIGCHLD, 0, 0, 0, 0)
                                 : syscall(SYS_unshare, flags);
        int error = result < 0 ? errno : 0;
        if (clone_call && result == 0) _exit(0);
        if (clone_call && result > 0) {
            int status;
            if (waitpid((pid_t)result, &status, 0) != result ||
                !WIFEXITED(status) || WEXITSTATUS(status) != 0) _exit(2);
        }
        dprintf(STDOUT_FILENO, "{\"case\":\"%s\",\"flags\":%lu,\"errno\":%d}\n",
                name, flags, error);
        _exit(0);
    }
    int status;
    if (waitpid(worker, &status, 0) != worker ||
        !WIFEXITED(status) || WEXITSTATUS(status) != 0) _exit(2);
}

int main(int argc, char **argv) {
    (void)argv;
    if (argc != 1 || getpid() != 1 || prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1) return 2;
    alarm(25);
    puts("hsg-namespace-probe/v1 ready"); fflush(stdout);
    char permit[4];
    if (read(STDIN_FILENO, permit, sizeof permit) != 3 ||
        permit[0] != 'g' || permit[1] != 'o' || permit[2] != '\n') return 2;
    probe("clone-control", 1, 0);
    probe("unshare-control", 0, 0);
    probe("clone-user", 1, CLONE_NEWUSER);
    probe("clone-user-mount", 1, CLONE_NEWUSER | CLONE_NEWNS);
    probe("clone-invalid-user-fs", 1, CLONE_NEWUSER | CLONE_NEWNS | CLONE_FS);
    probe("unshare-user", 0, CLONE_NEWUSER);
    probe("unshare-user-mount", 0, CLONE_NEWUSER | CLONE_NEWNS);
    return 0;
}
