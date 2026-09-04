# Harness Security Gateway

[![CI](https://github.com/shwdsun/harness-security-gateway/actions/workflows/ci.yml/badge.svg)](https://github.com/shwdsun/harness-security-gateway/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Harness Security Gateway (HSG) is a small, single-user gateway between a
messaging platform and an agent *harness*: a coding-agent environment that can
read files, run tools, use credentials, and reach networks. It turns
authenticated messaging events into durable Runs against operator-approved,
immutable harness targets without implementing another agent loop or
orchestrator.

> **Status: research prototype / pre-alpha.** The control-plane walking
> skeleton and offline security witness are implemented. Two sealed `new_only`
> Codex adapter behavior profiles exist in code, but no Codex Runner image or
> TargetManifest is shipped and the default build omits its entrypoint. No
> provider-authenticated Codex target or Discord Connector exists yet. Do not
> deploy this repository as a production gateway or treat it as evidence of a
> secure Discord-to-Codex path.

What runs today: the Go control plane passes its ordinary and race tests, and
`make demo-security` checks five offline properties. The end-to-end platform
path uses a deterministic mock Runner, not Discord or a model provider.

> Messages may invoke an operator-preauthorized execution envelope; they may
> never select or widen that envelope.

## Why this exists

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
| Codex adapter | Context-free v1 and fixed private-messaging v2 `new_only` cuts implemented and unit-tested; neither is wired into a shipped target |
| Real Codex target | Not implemented; blocked on image, context, auth, egress, cancellation, and teardown gates |
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
- The sandbox session design keeps provider tokens private. Current evidence
  uses synthetic mock tokens only; a real provider credential boundary remains
  an open gate. Public session references are exact-scope, one-use capabilities
  and never authorize a new Run.

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
| `cmd/` | `agentd`, `sandboxd`, `hgwctl`, fake Connector, mock Runner, and disabled Codex adapter entry points |
| `internal/` | Closed protocols, policy, durable stores, dispatch, runtime, and adapter packages |
| `demo/security/` | Credential-free deterministic security witness |
| `runners/mock/` | Digest-pinnable mock Runner image |
| `config/` | Example daemon configuration; never message-selectable |
| `bakeoff/` | Candidate-neutral adversarial cases and result schema |
| `docs/` | Architecture, protocols, evidence limits, status, and runbook |

## Non-goals

HSG is not a generic bot framework, model router, memory service, planner,
workflow DSL, or multi-agent orchestrator. Dynamic message-selected plugins,
images, mounts, credentials, tools, or network rules are outside the boundary.
Multi-host scheduling, Kubernetes, high availability, and a broad platform
matrix are deliberately deferred.

## Documentation

- [Design principles](docs/design-principles.md)
- [Architecture](docs/architecture.md)
- [Access-control model](docs/access-control.md)
- [Connector protocol](docs/connector-protocol.md)
- [Harness Runner Protocol](docs/runner-protocol.md)
- [Implementation status](docs/implementation-status.md)
- [Product scope](docs/positioning.md)
- [Competitive security bake-off](docs/competitive-bakeoff.md)
- [Local mock runbook](docs/runbook.md)

## Security and license

Please report vulnerabilities through
[GitHub private vulnerability reporting](https://github.com/shwdsun/harness-security-gateway/security/advisories/new),
with the metadata-only fallback in [SECURITY.md](SECURITY.md) if that form is
unavailable.

Licensed under the [Apache License 2.0](LICENSE). Third-party dependency notices
are recorded in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
