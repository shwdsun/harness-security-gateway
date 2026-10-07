#define _GNU_SOURCE
#include "process_filter.h"
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

extern char **environ;

/* FD 3 is the already opened and digest-verified fixed native ELF. There is no
 * command/path/argument selector. The trusted owner supplies a closed env and
 * a fresh private working directory. Keep this launcher single-threaded. */
int main(int argc, char **argv) {
    (void)argv;
    struct stat st;
    if (argc != 1 || geteuid() == 0 || getuid() != geteuid() || getgid() != getegid() ||
        fstat(3, &st) != 0 || !S_ISREG(st.st_mode) || st.st_nlink != 1 ||
        (st.st_mode & (0022 | S_ISUID | S_ISGID)) != 0 || (st.st_mode & 0111) == 0 ||
        fcntl(3, F_SETFD, FD_CLOEXEC) != 0 ||
        syscall(SYS_close_range, 4U, ~0U, 0) != 0 || hgw_restrict_processes() != 0) {
        return 125; /* No raw diagnostics or native execution on rejection. */
    }
    char *const fixed[] = {
        "codex", "--config", "cli_auth_credentials_store=\"file\"",
        "--config", "forced_login_method=\"chatgpt\"",
        "--config", "features.code_mode.enabled=false",
        "--config", "features.code_mode_host=false",
        "--config", "features.plugins=false", "--config", "features.apps=false",
        "--config", "check_for_update_on_startup=false",
        "app-server", "--listen", "stdio://", NULL,
    };
    fexecve(3, fixed, environ);
    return 125;
}
