/* Fixed offline diagnostic. Map only this process's own UID/GID in one new
 * child namespace, then exit. No mounts, commands, credentials or network. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/capability.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static int write_map(const char *path, const char *text) {
    int fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd < 0) return errno;
    size_t len = strlen(text);
    ssize_t n = write(fd, text, len);
    int error = n < 0 ? errno : (n == (ssize_t)len ? 0 : EIO);
    if (close(fd) != 0 && error == 0) error = errno;
    return error;
}

int main(int argc, char **argv) {
    (void)argv;
    struct __user_cap_header_struct header = {_LINUX_CAPABILITY_VERSION_3, 0};
    struct __user_cap_data_struct caps[2] = {{0}};
    if (argc != 1 || getpid() != 1 || prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1 ||
        syscall(SYS_capget, &header, caps) != 0) return 2;
    for (int i = 0; i < 2; i++) {
        if (caps[i].effective || caps[i].permitted || caps[i].inheritable) return 2;
    }
    alarm(25);
    unsigned int uid = geteuid(), gid = getegid();
    if (!((uid == 0 && gid == 0) || (uid == 1000 && gid == 1000))) return 2;
    puts("hsg-uid-map-probe/v1 ready"); fflush(stdout);
    char permit[4];
    if (read(STDIN_FILENO, permit, sizeof permit) != 3 ||
        memcmp(permit, "go\n", 3) != 0) return 2;
    long child = syscall(SYS_clone, CLONE_NEWUSER | CLONE_NEWNS | SIGCHLD, 0, 0, 0, 0);
    if (child < 0) {
        dprintf(STDOUT_FILENO, "{\"uid\":%u,\"stage\":\"clone\",\"errno\":%d}\n", uid, errno);
        return 0;
    }
    if (child == 0) {
        alarm(10);
        char mapping[64];
        snprintf(mapping, sizeof mapping, "0 %u 1\n", uid);
        int error = write_map("/proc/self/uid_map", mapping);
        dprintf(STDOUT_FILENO, "{\"uid\":%u,\"stage\":\"uid_map\",\"errno\":%d}\n", uid, error);
        if (error) _exit(0);
        error = write_map("/proc/self/setgroups", "deny\n");
        dprintf(STDOUT_FILENO, "{\"uid\":%u,\"stage\":\"setgroups\",\"errno\":%d}\n", uid, error);
        if (error) _exit(0);
        snprintf(mapping, sizeof mapping, "0 %u 1\n", gid);
        error = write_map("/proc/self/gid_map", mapping);
        dprintf(STDOUT_FILENO, "{\"uid\":%u,\"stage\":\"gid_map\",\"errno\":%d}\n", uid, error);
        if (error) _exit(0);
        dprintf(STDOUT_FILENO, "{\"uid\":%u,\"stage\":\"mapped\",\"child_uid\":%u,\"child_gid\":%u}\n",
                uid, (unsigned int)geteuid(), (unsigned int)getegid());
        _exit(0);
    }
    int status;
    if (waitpid((pid_t)child, &status, 0) != child ||
        !WIFEXITED(status) || WEXITSTATUS(status) != 0) return 2;
    return 0;
}
