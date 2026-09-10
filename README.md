# Harness Security Gateway

[![CI](https://github.com/shwdsun/harness-security-gateway/actions/workflows/ci.yml/badge.svg)](https://github.com/shwdsun/harness-security-gateway/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Harness Security Gateway (HSG) is a small, single-user gateway between a
messaging platform and an agent *harness*: a coding-agent environment that can
read files, run tools, use credentials, and reach networks. It turns
authenticated messaging events into durable Runs against operator-approved,
immutable harness targets without implementing another agent loop or
orchestrator.

> **Status as of 2026-09-10: research prototype / pre-alpha.** The control plane,
> mock path, credential lifecycle and opt-in V3/native provider canary are
> implemented within their documented scopes. Three real-provider Runs failed;
> authenticated completion remains unverified. Normal daemon configuration is
> mock-only. No public Discord Connector, approved production Codex target or
> production deployment is available.

Start with `make demo-security` or the [local mock runbook](docs/runbook.md).
The [2026-09-10 checkpoint](docs/checkpoint-2026-09-10.md) records local Go/race/vet
results, scoped native experiments, failed real Runs and the next work package.
Those dated observations are separate from the CI badge and release status.

> Messages may invoke an operator-preauthorized execution envelope; they may
> never select or widen that envelope.

## Why this exists

The goal is a practical personal gateway: request coding work from a private
conversation, run it within an operator-approved environment, and receive the
result in that conversation. The first intended path is private Discord to one
immutable Codex target.

Messaging-to-agent connectivity is easy to demonstrate; authority is the
harder problem. A message is untrusted intent entering a powerful execution
environment. HSG is structured to keep transport identity, admission,
execution authority, and harness reasoning in separate trust domains.

It does not try to prove that a model will obey hostile text. It is designed to
constrain what the resulting execution can reach. OS-level identity separation,
image and profile pinning, credential reach, egress, cancellation, and teardown
remain explicit release blockers rather than completed claims.

## Architecture

```text
platform -> Connector -> agentd -> sandboxd -> ephemeral Runner -> harness
            identity     Binding    target/runtime   HRP/1 adapter
                         + Run
```

- A **Connector** owns one platform protocol and credential. It reports
  authenticated platform facts but cannot choose execution resources.
- **`agentd`** owns exact Bindings, admission, durable Runs, replay, and the
  outbound reply scope.
- **`sandboxd`** owns immutable target revisions, workspaces, private session
  state, and the rootless runtime boundary.
- A **Runner** translates the language-neutral HRP/1 stream to one harness. It
  receives one bounded Run and never receives a control-plane or container
  runtime socket.

An `ExecutionTarget` is immutable configuration, not a permanent model
process. A container belongs to one Run; workspace and provider-session state
have separate, sandbox-owned lifetimes.

## Current implementation

This is a real control plane exercised end to end with a deterministic mock
Runner; it is not yet a real platform-to-provider integration.

| Area | Status |
| --- | --- |
| Core admission, replay, Runs, and outbox | Implemented and deterministically tested |
| Sandbox lifecycle and uncertain-create reconciliation | Implemented and deterministically tested with a fake runtime; the digest-pinned mock Runner was exercised locally on rootless Docker, outside public CI |
| Exact scoped session lifecycle | Implemented and tested with one-use references, age/turn bounds, and one live Run per exact scope |
| Offline security witness | Implemented; uses production decoding, policy, service, and Core SQLite code |
| Credential lifecycle | Immutable source/proof/generation binding, held-source handoff and ordered cleanup/release implemented; normal daemon enrollment remains unavailable |
| Codex adapter and V3 package | V1/V2 contracts retained; opt-in V3 adds a pinned native tool package, bootstrap and scoped native witnesses. No approved production Runner image is shipped |
| Controlled provider canary | Separate opt-in local owner and retained-history continuation; three real Runs failed on 2026-09-10 with cleanup independently checked. The third found empty/missing Content-Type and blocked later dispatch; [bounded response diagnostics](docs/codex-provider-canary.md#response-contract-investigation--2026-09-10) prepare the remaining compatibility investigation |
| Recovery verification | Opt-in formal model with explicit assumptions and sampled implementation conformance; ordinary tests and native witnesses retain their separate scopes |
| Production Codex target | Blocked on complete authority, artifact, context, provider and deployment acceptance |
| Discord Connector | Not implemented |
| Production deployment | Not ready |

The detailed and authoritative status is in
[docs/implementation-status.md](docs/implementation-status.md).

## Run the security witness

Requires Go 1.26.7 or newer within the Go 1 compatibility promise. The patch
floor includes standard-library security fixes used by this codebase.

```bash
go test ./...
go vet ./...
make demo-security
```

The demo checks five narrow, deterministic properties: closed target/control
input, exact actor/conversation admission, durable acceptance across a killed
process, exact replay deduplication, and conflicting-replay rejection. It is
not a container, credential, Discord, Codex, or whole-system security proof.

The advanced rootless-Docker mock flow requires a repository-digest workflow
(and, on engines that do not assign local RepoDigests, an operator-controlled
registry) and is described in the
[local runbook](docs/runbook.md).

## Deployment model

There is deliberately no production installer or `docker compose up` path yet.
Today this repository supports two bounded uses: the offline security witness
above, and the advanced mock flow in the local runbook. The latter runs the
control services on the host and creates one digest-pinned mock Runner
container per Run; it is not a Discord or Codex deployment.

The [provider canary](docs/codex-provider-canary.md) is a separate, opt-in
experiment requiring explicit artifacts, local prerequisites and authorization
for its external effects. Its entrypoint is omitted from the default build;
it is not an installer or a supported production target.

The intended real topology keeps long-lived control services separate from
ephemeral harness execution. A Connector may be packaged as one long-running
service or container per platform credential. `agentd` owns durable admission,
and `sandboxd` alone owns the exact local rootless-runtime socket. Each Run is
executed in one container created from a preloaded, digest-pinned harness
Runner image containing its thin HRP adapter and pinned harness executable.
Secrets and deployment-local bindings are provisioned into their own trust
domains; they are never baked into images or selected by a message.

Dependency and image acquisition is an operator-controlled build/provision
operation, not a message-time feature. A deployment may fetch reviewed,
version-pinned inputs or use a controlled offline cache while producing and
recording immutable artifacts. Before a Run can execute, its target's exact
image digest must already exist in the selected rootless image store. Run
creation uses `--pull=never`, and the closed target/runtime contract provides
no message-time package, harness-update, or dynamic skill/plugin mechanism.

See [Deployment and artifact lifecycle](docs/deployment.md) for the current
paths, intended placement, dependency policy, and the gates that intentionally
block a turnkey real-platform deployment.

## Security model

- An exact `(Connector, actor, conversation)` Binding selects one immutable
  `TargetRevision`.
- Inbound wire data cannot name a host path, image, command, argument,
  environment variable, mount, network rule, credential, plugin, skill bundle,
  MCP server, or runtime option.
- Admission creates a durable Run before execution; duplicate delivery and
  recovery reconcile the same authorization decision.
- The outbound destination is derived from the accepted Run. Runner output
  cannot redirect a reply.
- An ambiguous container create is reconciled by immutable identity and is
  never retried as a second create.
- The mock session path keeps synthetic provider-session tokens in sandbox
  state. Core sees exact-scope, one-use opaque references, which never authorize
  a new Run. This does not establish secrecy of a real provider credential.

The V3/provider-canary contract is explicitly `credential-exposed-personal`:
native tools can read its dedicated credential file, and allowed provider
requests can disclose data they can read. The runtime-owned operation endpoint
constrains requests; it does not hide the credential from those tools. See the
[canary's credential boundary](docs/codex-provider-canary.md).

Code, deterministic tests, runtime evidence, and explicitly scoped experiments
outrank prose or model review. See [architecture.md](docs/architecture.md) and
[access-control.md](docs/access-control.md) for the trust and authorization
model.

## Work in progress and release blockers

The following gates remain open; the repository makes no claim that they have
passed:

- deploy distinct service UIDs and verify private path ownership, setgid
  directory traversal, and `0660` socket access;
- build and digest-pin the Codex image, then bind resolved auth, network,
  context, and runtime profiles into the target revision;
- close repository/system skill and customization injection, then test
  credential reach, refresh, revocation, and provider-versus-tool egress;
- prove cancellation, detached-descendant cleanup, and container quiescence;
- exercise fake ingress against the real target before adding a platform
  credential;
- implement a Discord Connector with stable-ID admission and Connector-owned
  durable cursor, spool, reconnect, and catch-up behavior;
- complete the deny audit and isolated private-Discord adversarial experiments.

Some internal identifiers retain the original prototype namespace (`HG_`,
`hgw`, and `harness-gateway`) because they participate in persisted hashes,
labels, or local paths. They are compatibility identifiers, not the current
product name. This pre-alpha repository otherwise makes no compatibility
guarantee.

## Repository map

| Path | Responsibility |
| --- | --- |
| `cmd/` | Control services, local utilities, mock Runner and experimental Codex/bootstrap/canary entry points |
| `internal/` | Closed protocols, policy, durable stores, dispatch, runtime, and adapter packages |
| `demo/security/` | Credential-free deterministic security witness |
| `runners/mock/` | Digest-pinnable mock Runner image |
| `config/` | Example daemon configuration; never message-selectable |
| `bakeoff/` | Candidate-neutral adversarial cases and result schema |
| `formal/recovery/` | Opt-in recovery model, checked-in trace corpus and explicit proof assumptions |
| `docs/` | Architecture, protocols, evidence limits, status, and runbook |

## Non-goals

HSG is not a generic bot framework, model router, memory service, planner,
workflow DSL, or multi-agent orchestrator. Dynamic message-selected plugins,
images, mounts, credentials, tools, or network rules are outside the boundary.
Multi-host scheduling, Kubernetes, high availability, and a broad platform
matrix are deliberately deferred.

## Documentation

- [Current implementation status](docs/implementation-status.md)
- [2026-09-10 checkpoint and reflection](docs/checkpoint-2026-09-10.md)
- [Content evolution and verification scope](docs/content-evolution-and-verification.md)
- [Controlled provider canary and evidence limits](docs/codex-provider-canary.md)
- [Design principles](docs/design-principles.md)
- [Architecture](docs/architecture.md)
- [Access-control model](docs/access-control.md)
- [Connector protocol](docs/connector-protocol.md)
- [Harness Runner Protocol](docs/runner-protocol.md)
- [Deployment and artifact lifecycle](docs/deployment.md)
- [Product scope](docs/positioning.md)
- [Competitive security bake-off](docs/competitive-bakeoff.md)
- [Local mock runbook](docs/runbook.md)

## Security and license

HSG is developed independently with AI assistance; its implementation and
verification records are also available as a reference for other projects.

Please report vulnerabilities through
[GitHub private vulnerability reporting](https://github.com/shwdsun/harness-security-gateway/security/advisories/new),
with the metadata-only fallback in [SECURITY.md](SECURITY.md) if that form is
unavailable.

Licensed under the [Apache License 2.0](LICENSE). Third-party dependency notices
are recorded in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
