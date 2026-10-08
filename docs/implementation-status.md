# Current implementation status

Snapshot: **2026-10-08**. HSG is in early development. The source implements a
personal messaging gateway, but a supported real Discord-to-Codex installation
is not ready. [Core concepts](concepts.md) define the names and evidence language
used here; [deployment paths](deployment.md) give prerequisites.

## What you can run

| Workflow | Prerequisites | What it demonstrates |
| --- | --- | --- |
| Offline security demonstration, `make demo-security` | Go; no Docker or platform/provider credentials | Five specific authorization, crash-persistence and duplicate-event properties using actual gateway code |
| [Local mock workflow](runbook.md) | Go, `jq`, a directly owned rootless Docker daemon and a prepared image with a repository digest | Gateway-to-container execution with a simulated harness, durable task state and cleanup |

The **mock** harness returns controlled test output rather than asking a model
to perform work. These are development examples with stated limits.

The Discord connector and Codex integration have code and experimental evidence.
Real execution is available only through explicit experimental build and
provisioning paths. No supported production installer or approved production
Codex image is supplied.

## Implemented capabilities

| Area | Implemented behavior | Limit of the claim |
| --- | --- | --- |
| Authorization | Exact connector/sender/conversation/action rules; strict message decoding; immutable target reference on acceptance | A compromised connector can assert facts within its configured rules; trusted deployment identities still matter |
| Durable task state | Atomic acceptance, event deduplication, dispatch and recorded outcomes | Duplicate suppression depends on receipt retention and the same non-rolled-back database lineage |
| Reply delivery | Destination derived from the task; durable delivery state and acknowledged chunk progress across restart | A crash or lost response between platform acceptance and local receipt storage may duplicate an unrecorded chunk |
| Execution lifecycle | One-task containers, workspace ownership, cancellation and reconciliation of uncertain creation or cleanup | Automatic tests use controlled runtimes; native observations apply only to their named environment and artifacts |
| Harness continuity | Bounded one-use private session references for targets supporting continuity | Current experimental Codex targets use a fresh harness session for each task |
| Credential lifecycle | Explicit enrollment, generation binding, source verification, retirement and occupancy tracking | Lifecycle bookkeeping alone does not hide readable authentication from task tools |
| Discord connector | Exact platform identity normalization, durable polling cursor, reply splitting and rate-limit pacing | Historical live text experiments do not establish the current credential-isolated deployment |
| Experimental Codex isolation | Trusted authentication owner, task-scoped provider mediation and disposable local client representation | Integrated real-provider compatibility, renewal and private-Discord acceptance remain open |

See [architecture](architecture.md), [access control](access-control.md) and the
[Discord contract](discord-connector.md) for precise mechanisms. Changed images
or deployment inputs require renewed validation of affected boundaries.

## Credential isolation

The requirement is that task-controlled tools cannot recover reusable model-
provider credentials from files, environment, process state, protocol traffic,
logs or retained sessions.

Earlier real Codex experiments mounted authentication that tools could read.
They demonstrated useful execution under that weaker arrangement. They do not
satisfy credential isolation.

The current [isolated-authentication candidate](codex-profile-v4.md), technically
called **Codex Profile v4**, keeps real authentication in trusted software
outside the Runner. Automated tests and scoped experiments exercise its native
client, authentication substitution, renewal, cancellation and owner recovery
with controlled provider data. Those observations do not establish compatibility
and renewal against the real model service.

The next integrated acceptance must establish:

1. Useful Codex work and replies through the intended private Discord path.
2. Reusable credentials remaining inaccessible to task-controlled tools.
3. Required credential renewal and persistence through the trusted owner.
4. Correct cancellation, crash recovery and final cleanup for the accepted
   artifacts and deployment.

These criteria define the [credential-isolated messaging delivery goal](milestones.md#credential-isolated-messaging).
Historical references call that goal `M1`; its credential-recovery test is
`CRED-01`. [Identifier meanings](concepts.md#planning-test-and-design-identifiers)
explain their distinct roles.

## Dated evidence

| Date | Observation | Scope |
| --- | --- | --- |
| 2026-09-10 | A controlled real-provider task completed with a tool-written marker, local delivery and independent cleanup checks | [Provider experiment](codex-provider-canary.md#fifth-real-run--2026-09-10); earlier failures retained; reusable credentials exposed to the Runner |
| 2026-09-11 | One task through ordinary services completed using simulated message ingress | [Fixed startup experiment](codex-daemon-startup.md#first-ordinary-service-run--2026-09-11); separate from a real Discord deployment |
| 2026-09-16 | Two sequential private Discord text tasks completed with replies and sequential container cleanup | Earlier credential-exposed profile, one host and bounded tasks; earlier failed repeat retained |
| 2026-10-07 | The isolated-profile real campaign stopped at credential-setup completion verification, before a task or serving started; cleanup was verified | Operations failure retained; no real task/provider/renewal acceptance for the isolated candidate |
| 2026-10-08 | Source review repaired redirect credential exposure, partial-reply completion, Unicode splitting, and outbound pacing/counting defects; automated checks passed | [Regression tests](../internal/discordconnector/delivery_progress_test.go) and [response-boundary tests](../internal/discordconnector/response_boundaries_test.go); no new live-platform result |

The reviewed source baseline was merged as
[`0dadcfb`](https://github.com/shwdsun/harness-security-gateway/commit/0dadcfb716e8c17fdd5e59b670148dbcfa9d276e).
[CI for that commit](https://github.com/shwdsun/harness-security-gateway/actions/runs/37707842453)
passed normal and experimental component checks, mock-image builds and reachable
Go vulnerability checks. Skipped or excluded native/provider tests retain their
stated scope. Source integration does not complete real-service acceptance or
activate a deployment.

## Remaining delivery work

- Finish the integrated credential-isolation acceptance described above.
- Attest the exact deployed images, service identities, credential/filesystem
  reach and provider-versus-tool network access.
- Complete applicable adversarial, cancellation, crash and cleanup scenarios.
- Establish supported installation, update and recovery with predictable
  operator effort before a personal pilot release.
- Measure benefit and operating cost against simpler alternatives before
  expanding the product.

These outcomes are specified in the [delivery roadmap](milestones.md).
Image and file attachments, additional platforms and general agent orchestration
remain outside the current product scope.

## Historical record

The [implementation history](implementation-history.md) preserves previous
dated entries and their failures, artifact scope and old readiness statements.
Use that page for provenance and the technical record. This page is the
current capability summary.
