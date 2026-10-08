# Codex native network canary

This opt-in Linux check tests one prerequisite for the blocked Codex profiles:
whether the pinned CLI's sandbox helper can deny new IPv4/IPv6 TCP/UDP sockets
while still executing a child process. It grants no runtime authority and does
not resolve `codex.provider-control-v1`.

## Run and interpret

Place the standalone binary matching both the version and SHA256 in
`internal/codexprofile/contract.go` on `PATH`, then run from this repository:

```sh
HSG_CODEX_NETWORK_CANARY=1 go test -v -count=1 \
  -run '^TestCodexNetworkCanary$' ./internal/codexadapter
```

The canary starts with empty disposable Codex/SQLite homes and an explicit
environment. A fixture-owned `TMPDIR` contains the CLI's synthetic mount
registry. The child only creates and immediately closes unconnected sockets;
there are no listeners, connections, DNS queries, model requests, credential
reads, Docker operations, or host configuration changes.

Both controls use the same local helper and test command. The named permission
profile's network toggle is the only invocation difference:

| Case | Required result |
| --- | --- |
| Network enabled | All four socket creations succeed |
| Network disabled | All four return `EPERM` or `EACCES` |

An enabled canary fails if the binary differs, a child cannot start, a positive
control fails, or the complete expected denial results are absent. It does not
silently skip an unsupported execution environment. Ordinary tests skip the
native check unless explicitly enabled. Namespace startup failures under an
outer sandbox are environment evidence, not an isolation pass or product
failure. Do not relax host or product containment settings to obtain a pass.

## Version and evidence boundary

The local 0.151.0 CLI help exposes `codex sandbox --permission-profile NAME --
COMMAND`, with an explicit profile required when active sandbox state is absent.
The [official helper example](https://learn.chatgpt.com/docs/agent-approvals-security)
checked on 2026-09-08 instead uses a platform subcommand. Use the pinned binary's
observed interface for this canary; documentation from another version is not
execution evidence.

The canary uses a test-only named permission profile. The production adapter
uses `exec --sandbox workspace-write` and legacy network settings. Passing the
helper check does not establish their equivalence, every tool's launch path,
inherited socket handling, Unix socket isolation, image compatibility, or
complete configuration/context closure.

The [command network proxy](https://learn.chatgpt.com/docs/agent-approvals-security)
does not mediate the Codex client's model/authentication requests. HSG still
requires a separate, content-bound provider control policy. The next integration
witness must exercise the actual `exec` path against a local synthetic upstream:
client control traffic succeeds while a tool cannot reach that same endpoint.
It must also account for the selected runtime's Unix socket and inherited-FD
surfaces. A host allowlist or this primitive test cannot substitute for permitted
operation/credential mediation. Real provider use remains blocked by the gates
in [Codex Profile v1](codex-profile-v1.md).
