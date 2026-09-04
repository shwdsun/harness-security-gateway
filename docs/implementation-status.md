# Implementation status

Last verified: 2026-09-04

Release posture: **research prototype / pre-alpha**

The control plane, durable authorization path, sandbox lifecycle, mock Runner,
and offline security witness are implemented. Two sealed but blocked
`new_only` Codex behavior contracts are present: unchanged v1 has no added
model context, while v2 maps one fixed private-messaging behavior profile to
Codex's developer-instruction layer. No Codex image or TargetManifest is
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
| Scoped opaque-session lifecycle | Implemented for the mock path | One-use references, age/turn bounds, exact-scope fences, reset and migration tests |
| Offline security witness | Implemented | Production decoder/policy/service/Core store with synthetic input; no network or credentials |
| Codex HRP/1 adapter | Implemented and unit-tested for the first `new_only` cut; not shipped as a target | Translation and failure-redaction tests; no image, TargetManifest, or accepted runtime profile |
| Codex Profile v1 contract | Sealed but blocked; not accepted by the runtime | Exact CLI/model/auth/state/network/context/teardown semantics and stable contract fingerprint; live gates remain failed closed |
| Codex Profile v2 contract | Sealed but blocked; not accepted by the runtime | Fixed content-hashed private-messaging behavior at the developer layer; distinct adapter identity; no additional authority |
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
- The Docker runtime adapter emits fixed `argv`, uses rootless-runtime
  attestation, and never exposes the runtime socket to the Runner.
- A durable create intent precedes the external create. If the result is
  uncertain, reconciliation uses immutable labels and identity; it does not
  issue a speculative second create.
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

The repository ships no Codex Runner image or Codex TargetManifest, and
`make build` does not produce `cmd/codex-runner`. Enabling a real path therefore
requires an explicit, reviewable image and target addition; configuration in the
shipped examples cannot select it. The profile also requires no persistent
Runner `/state`, while TargetManifest v1 and the current runtime always resolve
and mount one. No valid v1 manifest therefore conforms to the whole profile.
Context, credential, network, cancellation, and teardown gates remain open,
including proof that repository-level, system, or managed customization cannot
enter the harness unexpectedly.

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
- add a versioned, closed `none` versus `persistent(ref)` Runner-state schema
  without changing TargetManifest v1 or its fingerprint;
- resolve immutable policy, auth, network, context, resource, and teardown
  authority plus the local credential slot/generation/source identity into a
  new target-revision security fingerprint;
- validate overlapping workspace/credential confidentiality domains before any
  egress-enabled target is selectable;
- close repository/system customization injection;
- implement a generic durable provisional-terminal mechanism that publishes
  output only after cleanup/quiescence proof and atomically releases locks;
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
