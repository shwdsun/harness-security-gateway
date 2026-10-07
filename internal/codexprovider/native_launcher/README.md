# Fixed native account launcher (V4 candidate)

Build on Linux/amd64 with `cc -std=c11 -O2 -Wall -Wextra -Werror main.c -o codex-auth-launcher`.
The isolated V4 profile pins the resulting executable and verifies the launcher
and native artifact before constructing its Owner consumer. V4 is wired as a
candidate; its remaining acceptance and activation gates are recorded in
[the V4 contract](../../../docs/codex-profile-v4.md). The old exposed profile does
not include or select it. No system policy install
is required: the launcher restricts itself and the native program it execs.

The owner must verify the launcher and native artifact, inherit only the verified
native ELF on FD 3, and provide the closed auth-only environment and temporary
home. The executable rejects arguments; its app-server argv is fixed. It creates
no threads before installing the inherited filter. A direct-child Wait plus pipe
and refresh callback joins can therefore establish that this helper has stopped
writing. This relies on the fixed trusted native executable and RPC surface;
it does not make native code an untrusted sandbox.

The startup/recovery gate is separate: a replacement owner must establish that
the fixed, nondelegated service cgroup has no old member before durable recovery.
Neither a process-group signal nor an absent in-memory provider proves that.
