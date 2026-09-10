# Codex exec integration fixture

Status on **2026-09-08 23:21 UTC**: all five native integration cases passed
in an offline disposable guest with an explicit, temporary bwrap compatibility
profile. The guest wrapper separately reported an error; its result is retained
below. This fixture does not enable a Codex target or satisfy the production
provider/image gates.

The opt-in Linux test consumes the actual `Run`, `ExecLauncher` and pinned
Codex 0.151.0 binary. A deterministic local HTTP/SSE service supplies model
responses. No real model, login, provider credential, Discord connector,
container daemon or deployment is involved.

## Run

Put the standalone binary matching `codexprofile.CLIBinarySHA256V1` on `PATH`.
The host must supply `/usr/bin/bwrap` and support the outer disposable
user/network/PID/mount namespaces **and the native CLI's nested sandbox**.

```sh
go test -tags=codexintegration -v -count=1 \
  -run '^TestCodexExecIntegration$' ./internal/codexadapter
```

Ordinary builds exclude this fixture. An explicitly requested run fails on a
startup failure, missing probe, failed positive control or incomplete result;
it never treats an unsupported environment as a pass. Do not relax host or
product security policy to make it pass.

The outer namespace has only a private loopback interface. Its filesystem is
read-only except for the owned fixture and a private `/tmp` scratch mount,
needed by the CLI's native sandbox registry. The test copies its own executable
into the fixture so it remains accessible when `/tmp` is replaced. The outer
90-second supervisor and PID-1 exit contain failed-fixture descendants. That
safety cleanup does not count as successful adapter or production cleanup.

This is a fixed trusted simulator, not an adversarial host-filesystem sandbox.
The read-only host filesystem remains visible; arbitrary Unix socket access,
inherited descriptors and hostile tools are outside its claim.

## Explicit simulation differences

The adapter's production arguments are retained, with these test-only changes:

- owned local binary/workspace/home/output paths and temporary directories;
- `--skip-git-repo-check` for the nonrepository fixture;
- a custom Responses provider on private loopback, a synthetic nonce bearer,
  and disabled websocket/retry behavior;
- for tool scenarios, one synthetic model catalog with the same model slug,
  explicit direct tool mode and minimal synthetic model instructions;
- for the network-enabled positive control only, replacement of exactly one
  `sandbox_workspace_write.network_access=false` value with `true`.

The synthetic bearer correlates fixture requests. It proves no production
credential isolation or ChatGPT subscription behavior. The tool helper also
rejects accidental inheritance of the synthetic provider environment variable.
These additions exist only in the tagged test, not in HRP or product config.

## Cases and current evidence

| Case | Required witness | Observation on 2026-09-08 |
| --- | --- | --- |
| No-catalog baseline | Native request preserves model, effort, fixed developer instructions and user input; final file reaches HRP completion | Passed locally and in the 23:21 UTC guest run; top-level tools array empty and Code Mode unavailable diagnostic observed; complete tool absence was not established |
| Cancel during provider request | Native request is active before cancellation; sole terminal is sequence 2 `run.cancelled`; provider connection closes and leader/namespace descendants are gone before outer teardown | Passed locally and in the guest; active request disconnected |
| Tool network denied | Real `exec_command` runs the owned probe; nonce-bound tool output reports kernel `EPERM`; same provider listener records zero probe hits; HRP completes | Passed in the guest; two inference requests, zero probe hits, verified `EPERM` tool output |
| Network-enabled control | Same tool reaches that listener once, returns its nonce and completes | Passed in the guest; two inference requests, exactly one probe hit and verified output |
| Cancellation | Probe demonstrably holds an owned file lock before cancellation; sole terminal is sequence 2 `run.cancelled`; leader is reaped, lock available and namespace descendants gone before outer teardown | Passed in the guest; held lock, sole cancelled terminal and quiescence checks passed |

Independent native observations showed that the synthetic direct-mode catalog
exposes top-level `exec_command`, whereas the no-catalog baseline's top-level
array was empty. A later
**2026-09-08** check localized the bundled-catalog conflict: the exact pinned
binary's `codex debug models --bundled` reports `gpt-5.6-sol` with
`tool_mode: code_mode_only` and `shell_type: unified_exec`. V1/V2 adapter
invocations disable Code Mode host. This explains the Code Mode diagnostic;
the shell type alone does not
establish that shell tools will be offered.

**Correction, 2026-09-09:** Responses Lite can carry namespaced definitions
inside `input.additional_tools`. The older fixture did not adjudicate those
items, so its empty array does not prove there are no tools. The new
[V3 native package canary](codex-profile-v3.md) checks those definitions and
actual tool results. Earlier completed synthetic cases and diagnostic logs
remain dated evidence, not a V3 or production acceptance result.

The bundled command skips catalog refresh and used an empty owned home. It
agrees with the relevant fields extracted from the exact binary; it does not
observe an authenticated provider's potentially different catalog. Current
[official configuration documentation](https://learn.chatgpt.com/docs/config-file/config-reference)
describes a `model_catalog_json` override, but does not establish that changing
tool mode or model instructions preserves provider compatibility.

The offline candidate report therefore explicitly lists
`model_tool_compatibility`. An accepted tool execution configuration must bind
its native executable dependencies, effective model metadata and existing
context/network boundaries to a versioned profile. The synthetic direct-mode
catalog remains a test delta; it cannot enable Code Mode host, amend either
sealed contract, or establish real-model tool support. The completed five-case
run is preserved without repeating it for this metadata diagnosis.

The earlier workstation network failure was localized in stages: the native sandbox first needed
private writable `/tmp`; after that fixture correction, nested namespace
creation was denied. A separate nested-bwrap `/bin/true` control also failed.
The initial run did not establish the policy cause. Later on 2026-09-08,
read-only policy and kernel-journal inspection plus a fresh minimal control
identified an enforcing AppArmor `unpriv_bwrap` capability denial for
`sys_admin`. The outer child carried the stacked `bwrap//&unpriv_bwrap` label;
the minimal control had no seccomp filter. This is an observed host-policy
restriction, not evidence that Linux user namespaces are globally disabled or
that the native tool reached the probe. Host settings were not changed.

A later **2026-09-08 19:41 UTC** attempt used a fresh offline Ubuntu 24.04.4
guest, kernel `6.8.0-138-generic`, and the verified Noble bubblewrap 0.9.0
executable. The frozen payload and dependencies passed their checks, and the
bootstrap invoked the preflight as an unprivileged user. The outer preflight
failed configuring private loopback with `RTM_NEWADDR: Operation not permitted`,
before the native test or Codex ran. Retained guest kernel logs show the
`unconfined` to `unprivileged_userns` transition, then `setpcap` and `net_admin`
denials. This guest failure is distinct from the workstation's nested
`unpriv_bwrap` / `sys_admin` denial. The two checked bwrap-specific AppArmor
policy paths were absent in that image; copying a verified executable and
checking library dependencies did not supply a working sandbox policy.

That VM powered off after the failure; its transient domain disappeared and
the prior guests' definitions/states and disk metadata were preserved. No
policy was relaxed and no native case gained a pass from this attempt. A
compatible test runtime must specify its namespace policy as well as its
binary and kernel inputs. The later run established that startup prerequisite
before executing the full fixture.

At **23:21 UTC**, an operator-authorized continuation on the same pinned
guest kernel and binary inputs added a temporary, exact-path bwrap profile
with `flags=(unconfined)` and `userns`. This is a guest compatibility exception,
not a least-privilege production policy. The original denial reproduced before
loading it; an identical executable at a different path remained restricted.
Outer namespace, nested bwrap and native Codex sandbox startup controls passed.
An earlier attempt had stopped because its unprofiled copy was under `/run`,
which the later mount diagnostics confirmed was `noexec`. Moving that copy
to a dedicated executable directory preserved the mount and policy settings.

The unchanged static Go 1.26.7 fixture then passed all five cases in 15.92
seconds; its preceding preflight also exited 0. The native test exited 0; retained integration
log SHA-256 is
`8a79ac71ea21c5712fe28096bd17f056cc7583526e2420948b949ee8ee9f9c6f`.
This was not a race-instrumented guest binary. No host security configuration,
real provider, credential or product contract changed.

The outer guest wrapper separately recorded `stage=native-fixture rc=1
cleanup_rc=1`; it did not deliver its final summary to the serial console.
Read-only extraction from the stopped guest recovered the complete native
results. Kernel removal events and identical before/after profile lists prove
the temporary profile was removed; the generic policy file hash was unchanged,
the transient VM disappeared and prior state was preserved. The failed wrapper
receipt remains a separate failure, not a whole-experiment pass. A local
output-fault replay with the guest's exact GNU checksum utility reproduced
the false wrapper/cleanup errors caused by a failed output sink. Serial
descriptor invalidation is consistent with the retained getty configuration,
but was not directly captured. A durable-log correction passed local fault
checks; it has not been rerun in the guest, and final live sysctl values were
not retained independently. No second native run was used to overwrite this
evidence.

Earlier standalone
[socket canary](codex-network-canary.md) evidence does not prove that these
composed namespaces or legacy exec network settings work.

Cancellation during an active provider request does not require a tool sandbox
and was observed separately before the earlier blocked tool cases. The later
guest run also observed the distinct held-tool lock and descendant case.

Observed descendant cleanup belongs to the combined CLI and fixture path.
`ExecLauncher` alone does not guarantee detached descendant death. The strict
`EPERM` probe remains a mechanism-specific witness; other connection failures
need separate attribution and are not silently accepted as network denial.

## Launcher correction and remaining gates

The design review prompted a concrete regression: a detached descendant can
hold stdout/stderr pipes after the CLI leader exits, leaving `exec.Cmd.Wait`
blocked. `ExecLauncher` now sets a two-second `WaitDelay`; the regression failed
before this change and passed after it. A pipe-drain timeout returns an error.
It does not prove descendant death or bound an arbitrary blocking `io.Writer`.
Cancellation can consume both the separate two-second TERM grace and the
two-second pipe-drain grace; an outer deadline must account for both.

The final review also exposed an empty-environment edge: Go treats a nil
`Cmd.Env` as parent-environment inheritance. The launcher now preserves an
explicitly empty environment for both nil and zero-length invocation inputs.
A synthetic parent-key regression reproduced the leak before the fix. The
adapter already supplies its fixed environment; this closes the launcher's
latent edge without adding any ambient configuration or credential source.

Production still requires an approved image, versioned executable authority,
provider operation/credential mediation, context closure, real authentication
and refresh behavior, and outer-runtime quiescence before terminal publication.
See [Codex Profile v1](codex-profile-v1.md) and
[Codex Profile v2](codex-profile-v2.md). This experiment changes none of their
sealed values or readiness decisions.
