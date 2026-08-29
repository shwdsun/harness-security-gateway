# Product position and scope

Status: research prototype / pre-alpha.

## Category

Harness Security Gateway is a **Messaging-to-Harness Security Gateway**:

> A small, self-hosted policy and isolation gateway from authenticated
> messaging identities to pre-approved coding-harness targets.

The project does not claim that forwarding a Discord or WhatsApp message to a
coding agent is novel. Connectivity is a feature already supplied by vendor
products and community bridges. The claim to test is narrower: an untrusted
messaging entry point can trigger useful work without gaining authority over
the workspace, model credentials, execution runtime, or target configuration.

The intended authority chain is:

```text
Connector observes a platform event
  -> gateway control plane authorizes an immutable TargetRevision
  -> sandbox executor materializes that approved target
  -> a fresh Runner performs exactly one Run
```

Neither the message, model, Connector, nor Runner may select an arbitrary host
path, image, mount, command, environment, network policy, credential, runtime,
plugin, skill, or MCP server.

## Current phase

The mock walking skeleton, authorization mechanisms, and offline security
witness are implemented and unit-tested; deployment hardening remains open. A
first credential-free, `new_only` Codex adapter exists in code, but no Codex
image or TargetManifest is shipped and the default build omits its entrypoint.
Its context, authentication, network, cancellation, and teardown gates remain
open. Feature expansion stays frozen during competitive and adversarial
validation.

The only production path admitted in the next implementation phase is:

```text
private Discord -> Discord Connector -> gateway control plane
                -> sandbox executor -> immutable Codex target -> text reply
```

V1 remains single-host, single-operator, and text-only. Execution is limited to
one live Run per exact authorization/session scope.

## Frozen non-goals

Until the Discord-and-Codex path passes its security gates, do not add:

- Claude Code or WhatsApp production integrations;
- attachments, buttons, remote approvals, or rich message schemas;
- dynamic skills, plugins, MCP servers, mounts, images, or network rules;
- schedulers, memory systems, agent orchestration, or workflow DSLs;
- Kubernetes, multi-host operation, high availability, or service registries.

## What can be claimed now

The repository demonstrates strict local protocols, exact admission, durable
message and Run state, a digest-pinned mock Runner, rootless-runtime
attestation, fail-closed crash reconciliation, and a credential-free security
witness. The Codex adapter is a disabled code cut, not a live integration. The
repository does not yet demonstrate a secure Discord-to-Codex deployment,
cross-UID deployment, credential isolation, or constrained provider egress.

## Competitive gate

Claude Code Channels, OpenClaw, and NanoClaw are evaluated against the same
functional, isolation, replay, credential, egress, and crash cases in
`competitive-bakeoff.md`. The project continues only if it can provide a
material and repeatable security property that the simpler alternatives do not.

If an existing system satisfies the required threat model with lower operating
cost, this project should pivot to a small security test suite or stop. A broad
feature race is explicitly not a success condition.

## ACP and MCP

ACP v2 is a non-blocking Runner-internal compatibility candidate. It cannot
replace Connector admission, immutable target selection, Run lifecycle,
container reconciliation, or HRP's outer security envelope. No ACP code is on
the current critical path; adoption requires a conformance experiment with a
real Harness.

MCP is not enabled in any shipped target. A future MCP server is executable
authority and must be pinned and reviewed as part of an immutable target, never
selected by chat content or discovered from an untrusted repository.
