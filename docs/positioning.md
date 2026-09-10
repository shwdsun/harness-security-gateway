# Product position and scope

Status as of **2026-09-10**: an independently developed, AI-assisted experiment
and reference project; research prototype / pre-alpha.

The project provides a concrete implementation, verification approach and
record of failed as well as successful experiments for others to study. AI
assists design, implementation and review; the human maintainer owns scope and
release decisions. Neither generated code nor model agreement establishes a
security guarantee. Claims follow the evidence boundaries in
[implementation status](implementation-status.md).

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

The mock path, authorization mechanisms, credential lifecycle and offline
security witness are implemented. V1/V2 Codex contracts are retained, while
opt-in V3 fixtures and the runtime-owned provider canary exercise native tool,
credential handoff and cleanup boundaries. Two real-provider Runs on 2026-09-10
failed without the completion marker; cleanup was independently observed.
Authenticated-provider acceptance remains open. Normal daemon configuration
remains mock-only, and no approved production Codex image/target or public
Discord Connector is shipped. See the [checkpoint](checkpoint-2026-09-10.md)
for the completed scope, failed experiments and next work package.

The intended first product path remains:

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
witness. The opt-in Codex experiments add scoped native/transport and cleanup
evidence, with failed real-provider attempts explicitly retained. They do not
establish a secure Discord-to-Codex deployment, production service-identity
isolation or authenticated model completion. V3 remains
`credential-exposed-personal`; its operation endpoint does not hide the
dedicated credential from native tools. The formal recovery pilot proves only
its stated abstract invariant and does not replace native or provider evidence.

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
