# Core concepts and reference identifiers

This page defines HSG's documentation vocabulary. Start with the
[product overview](../README.md) for purpose and current support. Technical
names below correspond to code or configuration; they do not add capabilities.

## From message to reply

1. A platform **connector** observes a message and reports its sender,
   conversation and content to the gateway.
2. The gateway matches those platform facts against a locally configured
   **authorization rule**. An unmatched request is refused.
3. Acceptance creates a durable **task record** before execution starts.
4. The execution service resolves the rule's approved **execution target**.
   A fresh **Runner** handles that task within the target's configured limits.
5. The gateway records the outcome and delivers a reply to the accepted
   conversation. Cleanup and reply delivery have their own recorded progress.

Message content describes the requested work. It cannot configure these rules,
choose an execution environment or grant another task's authority.

## Components and records

| Public term | Technical name | Meaning |
| --- | --- | --- |
| Local operator | operator / maintainer | The person who configures authorization, environments, credentials and deployment; the current product is for one operator |
| Coding harness | harness, such as Codex | The existing agent program that manages model interaction, files and tools |
| Platform connector | Connector | The adapter for one messaging account; it owns that platform credential and observes platform identity |
| Gateway service | `agentd` / Core | The service that authorizes messages and owns durable task, duplicate-event and reply records |
| Execution service | `sandboxd` / sandbox owner | The service that owns target configuration, workspaces, runtime lifecycle and private harness state |
| Per-task adapter | Runner | A disposable program in the task's container that translates the task into the harness contract; distinct from the harness itself |
| Authorization rule | `Binding` | One exact relation from connector, sender, conversation and action to one target revision; independent sender/conversation allowlists are insufficient |
| Accepted task record | `Run` | The durable identity and lifecycle of one accepted request, including recovery; a container or reply alone is not the whole task |
| Execution target | `ExecutionTarget`, described by `TargetManifest` | Locally approved workspace, Runner image, policies, state and limits |
| Target revision | `TargetRevision` | An immutable identity for a target definition and resolved authority; changed settings require a new revision |
| Pending reply store | outbox | Durable output awaiting delivery, whose destination comes from the accepted task |

Names such as `run_id`, `target_revision` and `binding_fingerprint` remain exact
API/configuration names in reference documents and examples. Overview text uses
task, target revision and authorization rule where the identifier is unnecessary.

## Lifetimes and credentials

A **conversation** is the messaging platform's channel or direct-message
thread. A **workspace** contains task files and can outlive a task. A
**container** belongs to one task. A **harness session** carries the coding
agent's continuity between tasks, where the target supports it.
These lifetimes are distinct.

The **execution boundary** or **execution envelope** is the maximum authority
allowed by the target's filesystem, credential, network and resource policy.
It is separate from instructions about what the model should do. **Rootless
Docker** runs under an unprivileged operating-system account; that property
alone does not prove that task tools cannot read a credential or reach a resource.

The current experimental Codex target starts a fresh harness session for each
task (`new_only`). The mock path can also exercise bounded continuity
(`opaque_resume`): Core stores an opaque one-use reference, while the execution
service retains private session state. That reference neither authorizes a
new task nor changes its target.

A **platform credential** lets the connector use Discord. A **provider
credential** authenticates to the model service. Reusable access and refresh
tokens are sensitive even if a file has restrictive modes. The
**credential-isolation requirement** is that task-controlled code, including
workspace tools, cannot recover those reusable provider credentials.
Network restrictions alone do not hide a readable credential.

In the isolated Codex design, the **authentication owner** is trusted software
outside the Runner that holds real provider authentication and mediates narrowly
allowed requests. It is a technical component, not another human account. The
Runner receives a disposable local representation and a task-scoped channel.
Integrated real-service acceptance of this design remains open.

## Capability and evidence language

| Wording | Meaning in this project |
| --- | --- |
| Implemented and automatically tested | Cited code and tests establish the named behavior within their scope |
| Observed in a dated experiment | Measured for the named artifact, environment and date; not evidence of current general support |
| Awaiting integrated validation | A necessary complete workflow or boundary has not passed its acceptance checks |
| Supported workflow | A runnable path with documented prerequisites and limits; currently the offline demonstration and advanced mock workflow |
| Early development / pre-alpha | Source is available, but a supported real Discord-to-Codex installation is not ready |

A **mock** or **synthetic fixture** substitutes controlled data or behavior for
a real component. **Native** tests exercise an actual executable or operating
system mechanism; that word alone does not imply real model-service traffic.
A **witness** is a recorded, scoped demonstration of a property. A **canary**
is a deliberately bounded experimental run. Neither means whole-system approval.
A formal proof applies to its stated model and assumptions.

## Versions name different things

| Versioned item | What its version identifies |
| --- | --- |
| Runner protocol, `HRP/1` | Version 1 of the Harness Runner Protocol, the JSON Lines contract between execution service and Runner |
| Connector protocol v1 | The local HTTP contract between connector and gateway |
| `agentd/v3`, `sandboxd/v3` or another configuration schema | The accepted shape of one local configuration document |
| Core, sandbox or Connector database schema | One store's persistence/migration format; each store versions independently |
| Codex Profile v1–v4 | Experimental Codex execution-contract revisions, not HSG product releases; the latest candidate isolates reusable authentication from the Runner |
| Target revision or image digest | Exact approved configuration or artifact identity, rather than a general compatibility promise |

Specialist documents qualify a version by its subject. In a dated record,
unqualified `V1`/`V4` must be read in that record's protocol/profile context;
they are not global versions of the system.

## Planning, test and design identifiers

These labels exist for traceability in technical references and historical
records. Readers do not need them to use the local demonstrations.

| Identifier | Meaning |
| --- | --- |
| `M0` | Roadmap label for the functional private-messaging workflow |
| `M1` | Delivery milestone for the same workflow with provider credentials isolated from task tools |
| `M2` | Roadmap label for an installable, maintainable personal pilot |
| `M3` | Roadmap label for deciding product direction from comparative security benefit and operating cost |
| `CRED-01` | One test-case ID in [`bakeoff/cases.json`](../bakeoff/cases.json): can task tools recover reusable provider credentials? It is neither a component nor a milestone |
| `FUNC-`, `ID-`, `AUTH-`, `ISO-`, `REPO-`, `NET-` and similar IDs | Cases in that same comparison suite; each has its own description and acceptance criteria |
| `P0`, `P1`, `P2` | Requirement priorities in plans: mandatory for the relevant release, conditional before specified expansion, or later demand-driven work; not measured readiness |
| `A0`… / `F1`… | Assumptions and derived constraints in [first principles](first-principles.md), tracing decisions to rationale |
| `GO` / `BLOCKED` in a review or experiment | A decision for the named scope, or an unmet prerequisite; neither is a general security certification |

The relationship previously abbreviated `M1/CRED-01` is:

```text
delivery goal: useful messaging with isolated provider credentials (M1)
    includes the credential-recovery test requirement (CRED-01)
    plus real-service compatibility, renewal, reply and cleanup acceptance
```

Passing one test or merging source does not complete that delivery goal.
The [roadmap](milestones.md#delivery-goals) states the whole outcome;
the [credential-isolation plan](credential-isolation-plan.md) is its detailed
technical work package.

Legacy strings such as `HG_`, `hgw` and `harness-gateway` remain in persisted
hashes, labels and example paths for compatibility. They are not additional
products. This pre-alpha repository otherwise makes no compatibility guarantee.
