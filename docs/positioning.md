# Product position and scope

Status as of **2026-10-08**: research prototype / pre-alpha. The historical
private Discord-to-Codex path has scoped live witnesses, including two sequential
text Runs on September 16. That profile exposes reusable provider auth to its
Runner. The separate V4 candidate still needs real compatibility, refresh and
Discord acceptance; source integration does not close those product gates.

The goal is a usable personal gateway for requesting coding work from private
messaging, executing it within a pre-approved environment and receiving the
result in the same conversation. Security, a small scope and clear behavior
serve that practical use. Current capabilities and remaining gates are recorded
in [implementation status](implementation-status.md).

The project is developed independently with AI assistance. Its implementation
and verification records can also serve as a reference for others. The
[engineering case study](engineering-case-study.md) makes the decisions,
evidence and open research questions inspectable without changing the practical
product goal.

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

The mock path, exact authorization, durable lifecycle and private Discord
Connector are implemented. V1–V3 contracts and their dated witnesses remain
separate from the opt-in V4 owner-isolated credential candidate. Its synthetic
native and fault evidence does not establish real-provider compatibility. The
October 7 real campaign stopped after enrollment, before serving or a task;
cleanup was verified and the failed campaign remains retained.

Default daemon builds remain mock-only and no approved production Codex target
is shipped. See [implementation status](implementation-status.md) for current
evidence and the [checkpoint](checkpoint-2026-09-10.md) for the earlier scope.

The first product path:

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
evidence, with failed real-provider attempts explicitly retained. Historical
Discord-to-Codex Runs under separate system identities, including a two-message
repeat, have recorded end state. They do not establish general reliability,
complete adversarial coverage, current V4 compatibility or production readiness.
V3 remains
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
