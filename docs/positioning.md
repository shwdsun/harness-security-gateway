# Product position and scope

Status as of **2026-10-19**: early development (pre-alpha). The local simulation
and offline demonstration are runnable. One fixed isolated Discord-to-Codex
deployment passed [bounded real-service acceptance](real-service-acceptance-2026-10-19.md),
including a task, actual reply, cleanup and evidence supporting natural credential
renewal. A supported real installation and personal pilot are not ready.
See [current capabilities](implementation-status.md) and [core concepts](concepts.md).

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
platform connector observes a message
  -> gateway checks the exact local authorization rule
  -> execution service resolves the approved environment
  -> a per-task Runner invokes the coding harness
```

Neither the message, model, Connector, nor Runner may select an arbitrary host
path, image, mount, command, environment, network policy, credential, runtime,
plugin, skill, or MCP server.

## Current phase

The simulated-agent path, exact authorization, durable task lifecycle and
private Discord connector are implemented. Earlier real experiments used an
execution profile whose reusable authentication was readable by task tools.
The isolated-authentication profile now has a bounded October 19 real-service
result alongside the separately scoped executable and failure tests. Its
credential-isolated messaging milestone was accepted only for the named profile,
exact artifacts and tested deployment. Earlier failures, including the October 7
credential-setup failure before a task, remain retained.

Default daemon builds remain mock-only and no approved production Codex target
is shipped. See [implementation status](implementation-status.md) for current
evidence and the [checkpoint](checkpoint-2026-09-10.md) for the earlier scope.

The first product path:

```text
private Discord -> Discord Connector -> gateway control plane
                -> sandbox executor -> immutable Codex target -> text reply
```

The initial product scope is single-host, single-operator and text-only.
Execution is limited to one live task per exact authorization/session scope.

## Frozen non-goals

The bounded acceptance does not authorize expansion. The following remain
outside the current product scope:

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
evidence, with failed real-provider attempts explicitly retained. The October 19
result adds real compatibility and qualified renewal evidence for fixed isolated
artifacts. Historical Discord-to-Codex Runs under earlier profiles, including a
two-message repeat, retain their separate scope. These observations do not
establish general reliability, complete adversarial coverage or production
readiness.
The earlier Codex execution profile remains classified as
`credential-exposed-personal`: its operation endpoint does not hide the
dedicated credential from task tools. The formal recovery pilot proves only
its stated abstract invariant and does not replace native or provider evidence.

## Competitive gate

Claude Code Channels, OpenClaw, and NanoClaw are evaluated against the same
functional, isolation, replay, credential, egress, and crash cases in
`competitive-bakeoff.md`. The project continues only if it can provide a
material and repeatable security property that the simpler alternatives do not.

If an existing system satisfies the required threat model with lower operating
cost, this project should pivot to a small security test suite or stop. A broad
feature race is explicitly not a success condition.

## Future integration boundary

Other harnesses and tool-server integrations remain future work. Any adopted
compatibility protocol would sit inside the per-task adapter; it would not
replace message authorization, task lifecycle or container reconciliation.
Executable integrations must be fixed and reviewed with their target, never
selected by chat content or discovered from an untrusted repository.

Earlier exploratory protocol labels are retained in the
[planning history](milestone-history.md#earlier-exploratory-compatibility-note),
rather than presented as dependencies of the current product.
