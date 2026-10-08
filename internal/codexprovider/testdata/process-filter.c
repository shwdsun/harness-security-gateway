#define _GNU_SOURCE
#include "../native_launcher/process_filter.h"
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

static void *thread(void *p) { return p; }

/* Evaluate the exact installed instructions for architectures we cannot safely
 * execute in this test process. Actual syscall negatives below use the kernel. */
static unsigned int verdict(unsigned int arch, unsigned int nr, unsigned int flags) {
    unsigned int a = 0;
    for (unsigned int pc = 0; pc < sizeof(hgw_process_filter) / sizeof(hgw_process_filter[0]); pc++) {
        const struct sock_filter *i = &hgw_process_filter[pc];
        switch (i->code) {
        case BPF_LD | BPF_W | BPF_ABS:
            if (i->k == offsetof(struct seccomp_data, arch)) a = arch;
            else if (i->k == offsetof(struct seccomp_data, nr)) a = nr;
            else if (i->k == offsetof(struct seccomp_data, args[0])) a = flags;
            else return 0;
            break;
        case BPF_JMP | BPF_JEQ | BPF_K: pc += a == i->k ? i->jt : i->jf; break;
        case BPF_JMP | BPF_JSET | BPF_K: pc += (a & i->k) != 0 ? i->jt : i->jf; break;
        case BPF_RET | BPF_K: return i->k;
        default: return 0;
        }
    }
    return 0;
}

int main(void) {
    if (verdict(AUDIT_ARCH_I386, SYS_getpid, 0) != SECCOMP_RET_KILL_PROCESS ||
        verdict(AUDIT_ARCH_X86_64, 0x40000000U | SYS_clone, CLONE_THREAD) != (SECCOMP_RET_ERRNO | EPERM) ||
        verdict(AUDIT_ARCH_X86_64, SYS_clone, CLONE_THREAD) != SECCOMP_RET_ALLOW) return 1;
#ifndef HGW_FILTER_ALREADY_INSTALLED
    if (hgw_restrict_processes() != 0) return 1;
#else
    /* Refer to the function for -Werror, but deliberately do not call it: this
     * positive control must fail if the launcher omits installation. */
    (void)hgw_restrict_processes;
#endif
    pthread_t t;
    void *returned = NULL;
    if (pthread_create(&t, NULL, thread, (void *)(uintptr_t)42) != 0 ||
        pthread_join(t, &returned) != 0 || returned != (void *)(uintptr_t)42) return 2;
    errno = 0;
    if (syscall(SYS_fork) != -1 || errno != EPERM) return 3;
    errno = 0;
    if (syscall(SYS_vfork) != -1 || errno != EPERM) return 4;
    errno = 0;
    if (syscall(SYS_clone, SIGCHLD, NULL, NULL, NULL, 0) != -1 || errno != EPERM) return 5;
    errno = 0;
    if (syscall(SYS_clone3, NULL, 0) != -1 || errno != ENOSYS) return 6;
    errno = 0;
    if (syscall(0x40000000U | SYS_getpid) != -1 || errno != EPERM) return 7;
    puts("threads allowed; new TGIDs denied; clone3 fallback; ABI closed");
    return 0;
}
