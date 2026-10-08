# Documentation guide

Start with the [product overview](../README.md). This index organizes purpose,
operation, technical contracts and dated evidence. The [core concepts](concepts.md)
define names before specialist details use them.

## Understand the product

| Document | Question it answers |
| --- | --- |
| [Product scope](positioning.md) | Who is this for, what is the first workflow, and what is outside scope? |
| [Core concepts](concepts.md) | What are a task, rule, target, Runner and harness? What do technical IDs mean? |
| [Current implementation status](implementation-status.md) | What can I run, what is implemented, and what needs acceptance? |
| [Delivery roadmap](milestones.md) | What outcomes are needed before a useful personal release? |
| [Engineering case study](engineering-case-study.md) | How do decisions map to code, verification and AI-assisted practice? |

## Run the local examples

| Document | Scope |
| --- | --- |
| [Deployment paths and artifacts](deployment.md) | Supported examples, experimental paths, placement and acquisition rules |
| [Local mock runbook](runbook.md) | Advanced container-based simulation with explicit prerequisites |
| [Discord connector](discord-connector.md) | Implemented platform behavior and configuration contract; not a turnkey deployment guide |

`make demo-security` is the smaller offline starting point. Experiments requiring
real credentials or external services have separate prerequisites and
authorization; their documentation does not enable them.

## Review the technical contracts

| Topic | Documents |
| --- | --- |
| Design rationale | [Design principles](design-principles.md), [first principles](first-principles.md), [decision-to-code traceability](drift-ledger.md) |
| Ownership and authorization | [Architecture](architecture.md), [access control](access-control.md) |
| Messages and execution | [Connector protocol](connector-protocol.md), [Runner protocol](runner-protocol.md), [target manifest](target-manifest.md) |
| Credentials | [Isolation plan](credential-isolation-plan.md), [source lifecycle](credential-source-lifecycle.md), [enrollment](credential-source-enrollment.md) |
| Change and verification | [Content evolution and verification scope](content-evolution-and-verification.md), [comparison test protocol](competitive-bakeoff.md), [formal recovery pilot](../formal/recovery/README.md) |

Code/configuration names are exact in these documents. Test-case IDs and planning
labels are reference keys, explained in [concepts](concepts.md#planning-test-and-design-identifiers).

## Experimental Codex integration

These profiles are experimental execution-contract revisions, not product
releases. Read the [current credential boundary](implementation-status.md#credential-isolation)
before selecting an earlier profile or a technical experiment.

- [Isolated-authentication candidate](codex-profile-v4.md): current experimental
  direction, with real-service acceptance still open.
- [Earlier execution contracts](codex-profile-v1.md), [messaging behavior](codex-profile-v2.md)
  and [native tool package](codex-profile-v3.md): earlier revisions and their limits.
- [Fixed daemon startup](codex-daemon-startup.md), [provider experiment](codex-provider-canary.md)
  and [candidate preflight](codex-candidate-preflight.md): bounded procedures and dated results.
- [Provider operations](codex-provider-operations.md), [transport](codex-provider-transport.md)
  and [control boundary](codex-control-boundary.md): technical subcontracts.
- [Native execution](codex-exec-integration.md), [network experiment](codex-network-canary.md)
  and [live-path plan](codex-live-path-plan.md): earlier integration records.

## Historical evidence and decisions

Use these for provenance, not as instructions or current capability summaries:

- [Implementation history](implementation-history.md): retained dated results,
  failed attempts and the scope of earlier observations.
- [Planning history](milestone-history.md): earlier delivery decisions and
  progress notes, including subsequently superseded scheduling choices.
- [September 10 checkpoint](checkpoint-2026-09-10.md): an earlier reflection.

Current readiness belongs in [implementation status](implementation-status.md).
Historical dates and artifact scope remain attached to their observations.
