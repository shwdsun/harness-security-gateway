# Implementation status

Last verified: 2026-09-06

Release posture: **research prototype / pre-alpha**

The control plane, durable authorization path, sandbox lifecycle, mock Runner,
and offline security witness are implemented. Two sealed but blocked
`new_only` Codex behavior contracts are present: unchanged v1 has no added
model context, while v2 maps one fixed private-messaging behavior profile to
Codex's developer-instruction layer. A non-executable candidate manifest and
offline preflight are present; no approved Codex image or executable target is
shipped and the default build omits its entrypoint. There is no public Discord
Connector, provider-authenticated target, or production deployment. The
project therefore does not yet demonstrate a secure Discord-to-Codex path.

This document is the public source of truth for what is implemented, what is
only represented in code, and what remains work in progress.

## Status at a glance

| Capability | State | Evidence boundary |
| --- | --- | --- |
| Strict Connector and execution protocols | Implemented | Bounded JSON, closed enums, unknown-field rejection, protocol tests |
| Exact Binding authorization | Implemented | Exact Connector/actor/conversation tuple selects one immutable target revision |
| Durable Run, replay, dispatch, and outbox state | Implemented | SQLite schema v7, migration/reopen/failure-injection tests |
| Sandbox target and runtime lifecycle | Implemented for the mock path | Immutable manifests, rootless-runtime attestation logic, create-intent reconciliation, and lifecycle tests; the live rootless-Docker observation is local evidence, not public CI |
| Post-cleanup terminal publication | Implemented and fault-tested for the mock path | Sandbox schema v8 stages outcomes privately; cleanup precedes atomic terminal/session publication and unlock; real-image descendant quiescence remains unproved |
| Runner-state v2 local mock path | Implemented and locally tested | Explicit `sandboxd/v3`, immutable version-aware target carrier, sandbox schema v9, conditional state mounts, real mock-process and fake-runtime recovery tests; no live Docker/provider claim |
| Scoped opaque-session lifecycle | Implemented for the mock path | One-use references, age/turn bounds, exact-scope fences, reset and migration tests |
| Offline security witness | Implemented | Production decoder/policy/service/Core store with synthetic input; no network or credentials |
| Codex HRP/1 adapter | Implemented and unit-tested for the first `new_only` cut; not shipped as a target | Translation and failure-redaction tests; no image or accepted runtime profile |
| Codex Profile v1 contract | Sealed but blocked; not accepted by the runtime | Exact CLI/model/auth/state/network/context/teardown semantics and stable contract fingerprint; live gates remain failed closed |
| Codex Profile v2 contract | Sealed but blocked; not accepted by the runtime | Fixed content-hashed private-messaging behavior at the developer layer; distinct adapter identity; no additional authority |
| Offline Codex candidate check | Implemented, always execution-blocked | Total profile/target matching, closed local binding, non-authorizing digest, opt-in metadata inspection and subprocess tests; no secret reads, leases or resolved runtime policy |
| Real Codex target | Not implemented | No approved image/auth/network/context profile or provider canary evidence |
| Discord Connector | Not implemented | Protocol boundary exists; no Discord token, client, cursor, or delivery loop |
| Production security | Not claimed | Deployment identities, credentials, egress, cancellation, and live-path evidence remain open |

## Implemented control plane

### Ingress and admission

- `connectorwire` defines the small, versioned Connector contract. V1 admits
  text input and a closed action vocabulary; recognized control actions remain
  unsupported rather than being interpreted as arbitrary commands.
- `agentpolicy` compiles an operator-authored, exact Binding from one Connector,
  actor, and conversation to one immutable target revision.
- `agentservice` validates the event, applies the Binding, and linearizes an
  accepted request into a durable Run. Event replay is content-bound:
  byte-equivalent replay returns the original receipt, while a conflicting
  payload under the same retained event ID is rejected.
- Core persists the Binding and policy fingerprints used at admission. Later
  dispatch cannot silently substitute a target or broaden authority.

### Run and delivery lifecycle

- Core SQLite state owns durable Runs, dispatch leases, exact session scope,
  and Connector-scoped outbound delivery.
- `agentdispatch` recovers queued work, freezes the sandbox start request, and
  advances only through compare-protected transitions.
- Outbound recipients derive from the accepted Run. Runner output supplies
  content but cannot choose a Connector or conversation.
- A nonterminal-Run fence serializes each exact authorization/session scope.

### Sandbox and runtime boundary

- `sandboxd` accepts a closed execution request over a private Unix socket and
  verifies the peer UID at connection time.
- Target manifests fix the runner family, adapter version, protocol, image
  digest, workspace, session policy, limits, and profiles. The execution wire
  cannot override those values.
- The separate `harness-target/v2` data contract expresses no persistent Runner
  state or one logical persistent state ref. It has an independent hash domain
  and exact field-name validation; historical v1 bytes remain pinned. Explicit
  `sandboxd/v3` admits the locked-down mock through one version-aware execution
  path; `sandboxd/v2` still rejects v2. Schema v9 durably distinguishes no state
  from missing ownership, and only persistent state receives a mount. A fixed
  new-only mock artifact is tested as a real child process. See
  [Target manifests](target-manifest.md).
- The Docker runtime adapter emits fixed `argv`, uses rootless-runtime
  attestation, and never exposes the runtime socket to the Runner.
- A durable create intent precedes the external create. If the result is
  uncertain, reconciliation uses immutable labels and identity; it does not
  issue a speculative second create.
- Every controller terminal outcome is staged privately in sandbox schema v8.
  Public status and events remain nonterminal until trusted cleanup succeeds.
  One sandbox transaction then publishes the outcome and successor session,
  clears the runtime reference, and releases the writer lock. Core observes
  that result and commits its own terminal/outbox transaction separately.
  Fault tests cover cleanup failure, lost staging responses, late publication
  rollback, database reopen, and preservation of the original outcome without
  re-executing the harness. These are controller/store tests with a fake
  runtime, not proof of actual detached-descendant containment.
  A two-store integration test additionally verifies that Core creates no
  session or delivery before sandbox publication and exactly one delivery
  when it subsequently observes that publication, even after a deadline.
- The sandbox session mechanism stores synthetic mock session tokens only in
  sandbox state. Core sees opaque, exact-scope, one-use references with
  target-authored age and turn limits. A real provider-token boundary remains
  unproved.

## Security witness

`make demo-security` uses the production strict decoder, compiled policy,
`agentservice`, and Core SQLite store. It verifies:

1. request-supplied target fields and arbitrary actions are rejected;
2. a recognized but unsupported target-selection action creates no Run;
3. a non-exact actor/conversation tuple creates no Run;
4. an accepted queued Run and its immutable Binding evidence survive exact
   child-process `SIGKILL` and database reopen; and
5. exact replay deduplicates while conflicting replay is rejected without a
   replacement Run.

The child receives an empty environment. The witness does not start Docker,
open a network listener, contact Discord or a model provider, or read provider
credentials. It is intentionally not evidence for container isolation,
credential safety, whole-system crash recovery, or formal verification.

## Codex adapter and profile: present but not wired into a target

`internal/codexadapter` and `cmd/codex-runner` implement the first closed
`new_only` HRP/1 translation cut. The adapter:

- requires the sealed `gpt-5.6-sol` model alias and `medium` reasoning effort;
- constructs a fixed Codex invocation rather than accepting message-selected
  options;
- accepts only the closed terminal event needed by the outer protocol;
- bounds and redacts provider output and failures; and
- rejects resume, non-text input, and unsupported profiles.

`internal/codexprofile` seals the candidate CLI 0.151.0 artifact digest,
model/effort, profile-ref projection, single-file ChatGPT credential mechanism,
disposable state, mediated-control-only network claim, empty customization
allow-set, and post-quiescence output rule. The concrete local credential slot
is deliberately unresolved and excluded. Its contract fingerprint is pinned in
code and every contract field is fingerprint-relevant. This is configuration
evidence, not runtime evidence: the current Docker profile gate still rejects
the expressible Codex projection before any CLI call. See
`codex-profile-v1.md`.

The separate v2 contract preserves that authority envelope and adds one exact,
content-hashed private-messaging behavior profile. `codexadapter.MessagingConfig`
maps it to the documented `developer_instructions` config key, while the
untrusted user message remains byte-exact stdin and absent from argv/env. It
reports adapter `0.2.0-new-only`, so a future manifest cannot confuse it with
the context-free v1 behavior. Unit tests pin both contract fingerprints, the
fixed instruction bytes, the native role mapping, and pre-readiness rejection
of unknown profiles. An opt-in exact-CLI canary additionally checks byte-exact
developer/user role placement and absence of three hostile workspace-file
sentinels under an empty home. The debug subcommand cannot accept two
exec-only ignore flags, so that canary is decoding/placement evidence rather
than complete exec or provider-context closure. See `codex-profile-v2.md`.
This is model-behavior configuration, not prompt-injection protection or an
authorization boundary.

The repository ships no Codex Runner image or executable Codex target, and
`make build` does not produce `cmd/codex-runner`. Enabling a real path therefore
requires an explicit, reviewable image and target addition; configuration in the
shipped examples cannot select it. The profile also requires no persistent
Runner `/state`, which no valid v1 manifest can express. The v3 local mock
path now integrates TargetManifest v2, explicit ownership kind and conditional
mounts, but it deliberately rejects Codex. The complete provider-profile
resolver and credential/network runtime remain unimplemented.
Context, credential, network, cancellation, and teardown gates remain open,
including proof that repository-level, system, or managed customization cannot
enter the harness unexpectedly.

`codexprofile.Contract.MatchTarget` and `internal/codexcandidate` now implement
the offline subset: full sealed-profile matching against TargetManifest v2,
one closed local workspace/credential binding, a prefixed configuration digest
and optional metadata-only inspection. `hgwctl codex check` always reports
`blocked` and exits 3 for valid configuration; it does not load sandboxd's
config, register authority, open Core state or invoke a runtime. The public
candidate example has a placeholder image digest. Matching metadata cannot
validate auth, prevent races or supply executable mediation content. See
[the preflight contract and usage](codex-candidate-preflight.md).

## Open gates

### Deployment identities and local IPC

- provision separate Connector, Core, and sandbox service identities;
- verify private path ownership, setgid group traversal, socket `0660` modes,
  connect-time UID checks, restart behavior, and log redaction on the target
  host; and
- demonstrate that neither the Connector nor Runner can reach Core data,
  sandbox state, provider session state, or the rootless runtime socket.

### Real Codex target

- materialize and attest the sealed CLI artifact in a digest-pinned runner
  image;
- build on the locally verified v3/v2 mock state path without weakening its
  explicit profile gate or changing legacy TargetManifest/revision fingerprints;
- resolve immutable policy, auth, network, context, resource, and teardown
  authority plus the local credential slot/generation/source identity into a
  new target-revision security fingerprint;
- validate overlapping workspace/credential confidentiality domains before any
  egress-enabled target is selectable;
- close repository/system customization injection;
- validate the implemented generic terminal-publication mechanism against the
  exact runtime image's cleanup and descendant-quiescence behavior;
- run credential reach, refresh, revocation, output-redaction, provider-egress,
  tool-egress, cancellation, detached-descendant, and quiescence canaries; and
- exercise fake ingress against the real target before introducing any
  platform credential.

### Discord Connector

- normalize Discord's stable actor, channel, message, and event identities;
- keep bot credentials and gateway cursors inside the Connector domain;
- implement bounded durable ingress spool, reconnect/catch-up, replay, self-
  event rejection, and outbound completion semantics; and
- pass the isolated private-Discord adversarial cases before expanding to
  another platform.

## Deliberately deferred

- Claude Code and additional harness implementations;
- WhatsApp and other messaging platforms;
- attachments, rich interactions, remote provisioning, and remote approvals;
- dynamic skills, plugins, MCP servers, mounts, images, credentials, or network
  policy;
- workflow orchestration, multi-agent scheduling, Kubernetes, multi-host
  operation, and high availability; and
- ACP adoption, unless a real Runner conformance experiment demonstrates that
  it reduces adapter maintenance without replacing the HSG security envelope.

## Verification commands

The release checks require Go 1.26.7 or newer and are:

```bash
test -z "$(gofmt -l cmd demo internal)"
make build
go test -count=1 ./...
go test -race -count=1 ./...
go vet ./...
make demo-security
make config-check
make bakeoff-check
```

Passing these commands supports only the scopes named above. A green unit test
suite is not evidence that the disabled live integration is safe.
