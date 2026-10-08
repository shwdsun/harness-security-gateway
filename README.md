# Harness Security Gateway

[![CI](https://github.com/shwdsun/harness-security-gateway/actions/workflows/ci.yml/badge.svg)](https://github.com/shwdsun/harness-security-gateway/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Harness Security Gateway (HSG) is a small, self-hosted gateway for requesting
coding work through private messaging. Its intended first workflow is to send
a task in Discord, run it with Codex inside a locally approved environment,
and receive the result in the same conversation.

The gateway checks who may request work and records each accepted task. It
keeps execution settings under the local operator's control: a message cannot
choose a host path, container image, credential or network policy. Codex
remains responsible for reasoning and tools; HSG supplies the surrounding
authorization and execution boundary.

> **Current status — 2026-10-08: early development (pre-alpha).** You can run
> an offline security demonstration and an advanced local workflow using a
> simulated coding agent. The Discord connector and experimental Codex
> integration are implemented, but a supported Discord-to-Codex deployment
> is still awaiting integrated credential-isolation and real-service testing.
> See [current capabilities and limits](docs/implementation-status.md).

## Try the offline demonstration

Requires Go 1.26.7 or newer within the Go 1 compatibility promise. The patch
floor includes standard-library security fixes used by this codebase.

```bash
go test ./...
go vet ./...
make demo-security
```

The demonstration uses the actual authorization and SQLite storage code with
test messages. It checks five specific properties: rejecting execution settings
in message input, authorizing the exact sender/conversation pair, preserving
acceptance after a process crash, recognizing a duplicate event, and rejecting
changed content under the same event identity. It requires no Docker, Discord
account or model-provider credential.

For a container-based simulation, follow the [local mock runbook](docs/runbook.md).
It requires a separately prepared rootless Docker environment. A **mock** is a
deterministic test substitute; that workflow does not contact a coding model.

## How it works

```text
private message -> platform connector -> authorization and task record
                -> approved execution environment -> coding harness -> reply
```

A **harness** is the coding-agent program around a model, such as Codex: it
manages the model conversation, files and tools. HSG runs that program rather
than adding another agent loop.

| Component | Responsibility | Code name |
| --- | --- | --- |
| Platform connector | Observe messages and send replies through one platform account | Discord Connector |
| Gateway service | Check local authorization rules and store accepted tasks and replies | `agentd`, also called Core |
| Execution service | Resolve the approved environment, manage containers and reconcile cleanup | `sandboxd` |
| Per-task adapter | Translate one accepted task to the harness and report its outcome | Runner |

An **authorization rule** (`Binding`) connects one connector, sender and
conversation to one approved execution target. A **task record** (`Run`)
stores an accepted request and its lifecycle. An **execution target** describes
the locally configured workspace, image, policies and limits; its
`TargetRevision` identifies an immutable version of those settings.
The [core concepts](docs/concepts.md) explain these terms and their lifetimes.

## What is implemented

| Capability | Current evidence and limit |
| --- | --- |
| Exact authorization and duplicate-event handling | Implemented and automatically tested against production decoding, policy and storage code |
| Durable task and reply lifecycle | Implemented, with restart and failure tests; platform delivery still has a send/receipt uncertainty window |
| Container lifecycle and cleanup reconciliation | Implemented and automatically tested; dated local container experiments have separate environmental limits |
| Discord message ingestion and reply delivery | Implemented; historical real-message experiments exist, but the current isolated-credential workflow needs integrated real-service validation |
| Codex execution and credential isolation | Experimental integration with automated and controlled native tests; real-provider compatibility and credential renewal remain unverified for the isolated candidate |
| Recovery model | An optional formal-methods experiment checks a stated abstract invariant; implementation and deployment require their own evidence |

Default builds use the simulated agent. Experimental Codex execution requires
an explicit build option and separately provisioned artifacts and credentials.
There is no supported production installer or approved production Codex image.
The [deployment guide](docs/deployment.md) explains prerequisites;
[implementation status](docs/implementation-status.md) separates current
capabilities from dated experiments.

## Security boundary

- Local policy authorizes an exact connector, sender and conversation together.
- Message input cannot specify images, commands, host paths, mounts, environment
  settings, credentials, plugins or runtime options.
- Acceptance is stored before execution. Duplicate events and recovery refer
  to the same recorded decision; an uncertain container creation is reconciled
  rather than retried as another creation.
- A reply destination comes from the accepted task. Model output cannot choose
  another recipient.
- Credentials, storage, runtime access and workspaces have separate owners.
  The current isolated-credential candidate needs real-service acceptance
  before that stronger deployment claim can be made.

The earlier real Codex experiments allowed workspace tools to read reusable
provider authentication. Their dated successes do not establish the newer
credential-isolation design. See the [current credential boundary](docs/implementation-status.md#credential-isolation).

Authorization and containment are enforced by code and operating-system
boundaries. Model compliance with instructions is not the security mechanism.
The [architecture](docs/architecture.md) and [access-control contract](docs/access-control.md)
give the precise assumptions and remaining limits.

## Next delivery goals

1. Validate useful Discord-to-Codex work while reusable provider credentials
   remain inaccessible to task tools, including credential renewal.
2. Complete the applicable isolation, cancellation, crash and cleanup cases
   for that exact deployment.
3. Provide a documented installation, update and recovery workflow with
   predictable operator effort before a personal pilot release.
4. Measure security benefit and operating cost against simpler alternatives
   before expanding the product.

The [delivery roadmap](docs/milestones.md) defines completion criteria.
The first workflow remains one operator, one private Discord entry, one fixed
Codex target and text tasks. Additional platforms, attachments, dynamic
plugins, memory services and multi-host scheduling are outside the current scope.

## Read the documentation

| Reader goal | Start here |
| --- | --- |
| Understand the product and terminology | [Product scope](docs/positioning.md), then [core concepts](docs/concepts.md) |
| Run the supported local examples | [Deployment paths](docs/deployment.md) and [mock runbook](docs/runbook.md) |
| Review implementation and security contracts | [Design principles](docs/design-principles.md), [architecture](docs/architecture.md) and [access control](docs/access-control.md) |
| Assess the engineering and research work | [Engineering case study](docs/engineering-case-study.md), linking code, counterexamples and July–October 2026 research |

The [documentation index](docs/README.md) organizes technical references,
experimental profiles and historical records. Internal planning and test IDs
are reference keys, explained in the concepts page.

Product code lives in `cmd/` and `internal/`; `config/` contains local examples,
`runners/mock/` contains test images, and `formal/recovery/` contains the recovery
model and its assumptions. HSG is developed independently with AI assistance,
with human ownership of scope, acceptance and release decisions.

## Security and license

Please report vulnerabilities through
[GitHub private vulnerability reporting](https://github.com/shwdsun/harness-security-gateway/security/advisories/new),
with the metadata-only fallback in [SECURITY.md](SECURITY.md) if that form is
unavailable.

Licensed under the [Apache License 2.0](LICENSE). Third-party dependency notices
are recorded in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
