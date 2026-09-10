/* Offline composition fixture only, not an approved product entrypoint.
 * Normalize container UID/GID 0 to 1000 in a fresh user namespace while
 * preserving the underlying host identity. Drop all capabilities before
 * execing the fixed, separately verified bootstrap. No task input is read. */
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
#include <unistd.h>

static _Noreturn void deny(void) {
    const char message[] = "hsg-uid-setup: denied\n";
    if (write(STDERR_FILENO, message, sizeof message - 1) != (ssize_t)(sizeof message - 1)) _exit(125);
    _exit(125);
}

static void write_map(const char *path, const char *text) {
    int fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd < 0) deny();
    size_t length = strlen(text);
    if (write(fd, text, length) != (ssize_t)length || close(fd) != 0) deny();
}

static void check_ids(uid_t uid, gid_t gid) {
    uid_t real_uid, effective_uid, saved_uid;
    gid_t real_gid, effective_gid, saved_gid;
    if (getresuid(&real_uid, &effective_uid, &saved_uid) != 0 ||
        getresgid(&real_gid, &effective_gid, &saved_gid) != 0 ||
        real_uid != uid || effective_uid != uid || saved_uid != uid ||
        real_gid != gid || effective_gid != gid || saved_gid != gid) deny();
}

static void check_caps(unsigned int expected) {
    struct __user_cap_header_struct header = {_LINUX_CAPABILITY_VERSION_3, 0};
    struct __user_cap_data_struct caps[2] = {{0}};
    if (syscall(SYS_capget, &header, caps) != 0 ||
        caps[0].effective != expected || caps[0].permitted != expected ||
        caps[0].inheritable || caps[1].effective || caps[1].permitted || caps[1].inheritable) deny();
    for (int cap = 0; cap < 64; cap++) {
        errno = 0;
        int bit = prctl(PR_CAPBSET_READ, cap, 0, 0, 0);
        if (bit < 0) {
            if (errno == EINVAL && cap > CAP_SETFCAP) return;
            deny();
        }
        if (bit != ((expected != 0 && cap == CAP_SETFCAP) ? 1 : 0) ||
            prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET, cap, 0, 0) != 0) deny();
    }
    deny(); /* Unknown capability width must not pass silently. */
}

int main(int argc, char **argv) {
    (void)argv;
    if (argc != 1 || getpid() != 1 || prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1) deny();
    alarm(5);
    check_ids(0, 0);
    check_caps(1U << CAP_SETFCAP);
    if (unshare(CLONE_NEWUSER) != 0) deny();
    write_map("/proc/self/uid_map", "1000 0 1\n");
    write_map("/proc/self/setgroups", "deny\n");
    write_map("/proc/self/gid_map", "1000 0 1\n");
    check_ids(1000, 1000);
    for (int cap = 0; cap < 64; cap++) {
        errno = 0;
        if (prctl(PR_CAPBSET_READ, cap, 0, 0, 0) < 0) {
            if (errno != EINVAL || cap <= CAP_SETFCAP) deny();
            break;
        }
        if (prctl(PR_CAPBSET_DROP, cap, 0, 0, 0) != 0) deny();
        if (cap == 63) deny();
    }
    if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) != 0) deny();
    struct __user_cap_header_struct header = {_LINUX_CAPABILITY_VERSION_3, 0};
    struct __user_cap_data_struct caps[2] = {{0}};
    if (syscall(SYS_capset, &header, caps) != 0) deny();
    check_caps(0);
    if (prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1) deny();
    alarm(0);
    char *const fixed_argv[] = {"/hsg-next", NULL};
    char *const fixed_env[] = {"HOME=/nonexistent", "PATH=/usr/local/bin:/usr/bin:/bin",
                              "LANG=C.UTF-8", "LC_ALL=C.UTF-8", NULL};
    execve(fixed_argv[0], fixed_argv, fixed_env);
    deny();
}
