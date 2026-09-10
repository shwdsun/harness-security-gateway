# Codex Profile v3: fixed native tool package

Status: **implemented candidate configuration, execution blocked**.
Observed on **2026-09-09 UTC**. No approved image, real-provider target or
production deployment is supplied by this profile.

V3 keeps CLI **0.151.0**, `gpt-5.6-sol`, `medium`, the fixed messaging
instructions and the existing credential/network/lifecycle requirements. It
adds the matching local Code Mode host and an explicit package layout. The
gateway still owns no agent loop or tool dispatcher; native tool execution
remains inside Codex.

## One versioned unit

| Item | Fixed value |
| --- | --- |
| Profile | `codex.chatgpt-personal-messaging-tools-v3` |
| Adapter | `0.3.0-new-only` |
| Policy projection | `codex.locked-tools-v3` |
| Candidate entrypoint | `cmd/codex-tools-runner`; absent from `make build` |
| Package root inside a future image | `/opt/hsg/codex` |
| CLI entrypoint | `/opt/hsg/codex/bin/codex` |
| Contract SHA-256 | `8bbae8b91929e32c4eca53270716c35e03999ec03d535f7011a088472b80ce50` |

The [closed contract](../internal/codexprofile/tools_v3.go) binds all the
artifacts below. V1/v2 contract bytes, fingerprints, adapter identities and
invocations remain unchanged. V3 adds a zero-omitted contract member and a
separate fingerprint domain. Its candidate cannot mix V2's adapter or policy.
A future executable image and TargetRevision must bind this new identity.

Paths are relative to the package root:

| File | SHA-256 |
| --- | --- |
| `bin/codex` | `9739cbc928b9c573be83256acd46668f5dd4f119d2d09e05246895ca2aaf0c9a` |
| `bin/codex-code-mode-host` | `a9adcea47799d8caaec5fbf073966fef2869f754bc7b463e30783880dfb12913` |
| `codex-package.json` | `ed8beb433be66cf74a75af94f4b2e2df35ef25325620ddad1a377bba8f1ffeea` |
| `codex-path/rg` | `e62198eb19b136b88c330af83647b5a962cb99b6b1f066758568f12de1974849` |
| `codex-resources/bwrap` | `7df960565a0dece99240ea4b9d0e011307817f9f3b73176c7b71fda44fe84765` |
| `codex-resources/zsh/bin/zsh` | `67faaaa89242c4a332e16e508a1977cffc24bf7fca31d4411cdfd101f3831ef3` |

These are measured cached artifacts, not authenticated release provenance.
The companion's `--help` reports default `stdio`; it does **not** implement
`--version`. Identify it by the package version/platform plus its exact hash.
The full distribution supplies native discovery paths and bundled helpers;
do not copy only the CLI or mix in the user's current installation.
The future base image still owns OS libraries, its shell and sandbox
prerequisites; these six files are not a complete Runner image.

## Configuration ownership and defaults

[MessagingToolsConfig](../internal/codexadapter/adapter.go) is the executable
template. These fixed overrides are added to the existing V2 restrictions:

```toml
features.code_mode.enabled = false
features.code_mode_host = { enabled = true, disable_in_process_fallback = true }
features.shell_tool = true
features.unified_exec = true
features.multi_agent = false
features.multi_agent_v2 = { enabled = false, max_concurrent_threads_per_session = 1, usage_hint_enabled = false }
agents.max_threads = 1
features.skip_host_skill_discovery = true
analytics.enabled = false
features.runtime_metrics = false
```

This is a description of the compiled overrides, **not** a workspace or user
`config.toml` to load. The adapter uses the existing ignore/strict flags, empty
explicit child environment, per-Run homes and tool-network denial. There is
no new option map, remote host URL, download, updater, listener or daemon.

The bundled model already requires `code_mode_only`; its native host works
without enabling the experimental forcing switch. Native tracing observed
Codex lazily launching the matching sibling host without arguments, through
inherited process pipes. In-process fallback is explicitly disabled.

`multi_agent=false` and `multi_agent_v2=false` do not remove this CLI's
Code Mode collaboration definitions. The enforced capacity is therefore one
slot **including the root agent**, with the legacy limit also set to one.
A synthetic native spawn call was rejected at capacity, without a child
inference. Do not interpret a feature-list boolean or absent UI as enforcement.

The CLI still supplies its embedded instructions and system-skill descriptions.
V3 names that context as `pinned-cli-builtins-only`; it does not claim an empty
native instruction set. Host skill discovery is disabled. Complete context
closure and authenticated provider catalog behavior remain acceptance gates.
The current [official configuration reference](https://learn.chatgpt.com/docs/config-file/config-reference)
documents Code Mode and unified-exec settings; exact hidden settings and
defaults here are supported by the pinned native observations, not by assuming
current documentation describes this old binary.

## Reusable preparation

Use the [V3 candidate example](../config/codex-tools-candidate.example.json)
for new configuration work. Only operator-owned workspace/credential mappings,
the future approved image digest and new revision are deployment inputs.
Do not expose them to messages or copy credentials into the package.

```sh
./bin/hgwctl codex check -config config/codex-tools-candidate.example.json
```

Expected result: exit **3**, configuration `valid`, execution `blocked`.
The eight blockers remain; this command never launches or verifies a CLI.
The older example is retained for V2 compatibility.

For a trusted build, stage only the six files from an independently acquired,
version-pinned cache. The following recipe creates a new local directory; the
illustrative paths must be replaced with operator-owned build paths:

```sh
(
  set -eu
  umask 077
  codex_release=/private/cache/codex-0.151.0
  codex_stage=/private/build/codex-package
  mkdir -m 0755 -- "$codex_stage"
  for part in bin codex-path codex-resources codex-resources/zsh codex-resources/zsh/bin; do
    mkdir -m 0755 -- "$codex_stage/$part"
  done
  for part in bin/codex bin/codex-code-mode-host codex-path/rg codex-resources/bwrap codex-resources/zsh/bin/zsh; do
    install -m 0555 -- "$codex_release/$part" "$codex_stage/$part"
  done
  install -m 0444 -- "$codex_release/codex-package.json" "$codex_stage/codex-package.json"
)
```

No install hook or system security change belongs in this recipe. Retain the
source/build receipt and verify all six hashes. A future image must place that
tree at `/opt/hsg/codex`, owned by its trusted image owner and on the immutable
root filesystem; its non-root Runner needs read/execute access. The isolated
candidate entrypoint can be built explicitly with the fixed model:

```sh
go build -trimpath -buildvcs=false \
  -ldflags '-X main.codexModel=gpt-5.6-sol' \
  -o /private/build/codex-tools-runner ./cmd/codex-tools-runner
```

Before emitting HRP readiness, the [startup guard](../internal/codexadapter/tools_package.go)
requires the exact six-file tree, directory safety, ordinary single-link files,
sizes, execute bits and hashes. Missing, changed, extra, symlinked, hardlinked,
group/other-writable or special files are rejected. The entire package must be
outside writable workspace/state paths. An early staging attempt with inherited
group-write directory permissions was correctly rejected before any CLI call.

This check hashes about 347 MB once per Run. It has no persistent validation
cache. It detects packaging mistakes; only the future read-only image and
mount boundary can prevent replacement after the check. It is not an atomic
file-to-exec handoff, image provenance or production approval.

## Focused verification and remaining gate

[TestCodexToolsConfiguration](../internal/codexadapter/tools_canary_linux_test.go)
uses the actual V3 adapter, launcher, pinned bundle and bundled model catalog.
It requires an externally established PID-1 namespace with only active
loopback, an owned writable scratch directory and `HSG_CODEX_TOOLS_CANARY=1`.
Its fake provider and nonce bearer exist only in that namespace. Completion
cases permit exactly two synthetic requests; running-tool cancellation permits
exactly one. No synthetic catalog override is used.

| Case | Required evidence | Observed scope |
| --- | --- | --- |
| `host` | Namespaced native definitions, nonce returned by real V8 execution, V3 terminal result, descendant quiescence | Native host execution observed |
| `agent-capacity` | A spawn attempt rejected at the root's occupied one-slot limit; no extra inference; quiescence | Native rejection observed |
| `file-write` | Real nested `apply_patch` writes exact nonce bytes in the owned workspace | Passed in a separate offline guest on 2026-09-09 with a temporary guest compatibility profile and a read-only package owned by the mapped test UID; workstation AppArmor failure retained |
| `command-exec` | Native `exec_command` returns the fixed probe's exit 17 and stdout/stderr proof; independent file receipt, CWD, UID, privilege state and quiescence | Passed in a fresh offline guest on 2026-09-09 using the same temporary compatibility profile and mapped read-only package |
| `network-allow-control` / `network-deny` | Native tool reaches the same listener used by client inference only in the control; four IP socket kinds succeed in the control and return `EPERM` in the denied case | Both passed in one fresh offline guest on 2026-09-09; independent nonce file, two requests and quiescence per case |
| `command-cancel` | Exact nonce receipt plus independently contended original file lock before cancellation; sole V3 cancelled terminal, reaped leader, no descendants and same lock available within 5 seconds before namespace teardown | Passed in a fresh offline guest on 2026-09-09; one synthetic request, observed cancellation and cleanup 5 ms |

Compile the opt-in test artifact with
`CGO_ENABLED=0 go test -c -tags=codexintegration -trimpath -buildvcs=false ./internal/codexadapter`.
Within the owned namespace, the full acceptance selector is
`-test.run='^TestCodexToolsConfiguration$'`; component-only diagnosis may select
`-test.run='^TestCodexToolsConfiguration$/^(host|agent-capacity)$'`.
Passing that smaller selector does not pass file writing, command execution
or network isolation, or approve an image.

On **2026-09-09 04:23 UTC**, the separate guest selected only
`-test.run='^TestCodexToolsConfiguration$/^file-write$'`. Exact file contents,
two synthetic requests, V3 completion and descendant quiescence passed.
Native test, guest wrapper, guest policy cleanup, domain teardown and evidence
collection were checked separately and passed. Earlier startup/ownership
precondition failures remain retained; neither entered the file-write subcase.

On **2026-09-09 05:00 UTC**, a fresh guest selected only
`-test.run='^TestCodexToolsConfiguration$/^command-exec$'`. The native Code Mode
host called `exec_command` with a fixed probe from the same test binary. It
verified the exact working directory, UID 1001, `NoNewPrivs=1`, zero effective
capabilities and absence of the synthetic provider environment key. It wrote
an exclusive nonce-bearing file, emitted distinct stdout/stderr proofs and
deliberately exited **17**. The tool result preserved that exit code with no
live session; the parent independently verified the file, and the surrounding
V3 Run completed after exactly two synthetic requests. Descendant quiescence
and all five result axes passed. This verifies one command completion path;
the intentional nonzero command exit is tool data, not a failed gateway Run.
It does not establish cancellation, network isolation or credential closure
for this package. No file-write or older direct-catalog case was rerun.

On **2026-09-09 05:28 UTC**, another fresh guest selected only
`-test.run='^TestCodexToolsConfiguration$/^network-(allow-control|deny)$'`.
The pair reused the existing HTTP and socket probes inside native Code Mode
`exec_command`, with the bundled catalog and no older direct-mode fixture.
The control changed exactly one test invocation argument from
`sandbox_workspace_write.network_access=false` to `true`; the guest and outer
namespace remained offline. Its tool reached the same live listener used by
the client exactly once. With the product's deny argument unchanged, the tool
reported kernel `EPERM` and the listener recorded zero probe hits, while both
client inference requests succeeded. New IPv4/IPv6 TCP/UDP sockets all opened
in the control and all returned `EPERM` in the denied case. Both commands
returned exit 0 with complete output proofs and independently checked nonce
files; each V3 Run completed and its descendants were quiescent. All five
result axes passed. Other native cases were not rerun.

This network witness covers new IP sockets and the local IPv4 HTTP path. It
does not establish Unix socket or inherited-FD isolation, provider operation
and credential mediation, cancellation or complete runtime acceptance.

On **2026-09-09 05:55 UTC**, a fresh guest selected only
`-test.run='^TestCodexToolsConfiguration$/^command-cancel$'`. The native Code
Mode host called `exec_command` with the existing fixed held-lock helper.
Before cancelling, the parent required the exact nonce-bearing `held` receipt
and independently observed `EWOULDBLOCK` on its original lock file. This
rejects an unstarted or already-exited tool as cancellation evidence. Exactly
one synthetic request occurred. The adapter returned the sole `RunCancelled`
terminal at sequence 2; its leader was reaped, namespace descendants were gone,
and the same lock was available before workspace and namespace teardown.
Observed cancellation through cleanup was **5 ms**, within the 5-second bound;
this single observation is not a latency guarantee. No `auth.json` was created,
and the helper required the synthetic provider key to be absent. The selected
case and all five result axes passed; no prior native case was rerun.

The canary observes quiescence after the adapter returns. It does not establish
the production rule that the outer runtime completes cleanup before publishing
a terminal result. Timeout variants, detached-descendant failure injection and
the approved image's lifecycle still require acceptance.

This lab package was owned by test UID 1001 under an outer read-only mount;
the fixture verified namespace ownership and an `EROFS` refusal to change its
manifest permissions. A guest root-owned control appeared as unmapped UID 65534,
which the unchanged strict package guard rejects. The temporary named
`unconfined` bwrap profile was removed afterward; workstation and server-host
policy were unchanged. This proves a component path in that fixture, not the
ownership/mount composition of a future root-owned production image.

The older fixture inspected only the top-level `tools` array. Responses Lite
can instead carry definitions in `input` items of type `additional_tools`.
An empty top-level array does **not** prove there are no tools. The old
host-disabled diagnostic is retained; the broad tool-absence claim is corrected.

Next: complete the remaining network surfaces (including Unix sockets and
inherited FDs), resource, context, credential and lifecycle acceptance,
including timeout/detached-descendant behavior and outer cleanup before terminal
publication, for this new package in an approved test environment. Do not rerun the old
five direct-catalog cases as a substitute, change a workstation policy to hide
the failed composition, or infer production readiness from the host canary.
