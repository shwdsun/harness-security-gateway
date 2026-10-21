# Current implementation status

Snapshot: **2026-10-21**. HSG is in early development. The source implements a
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
| Discord connector | Exact platform identity normalization, durable polling cursor, reply splitting and rate-limit pacing | One new real task and independent reply passed with patched Go artifacts on October 21; general deployment support remains open |
| Experimental Codex isolation | Trusted authentication owner, task-scoped provider mediation and disposable local client representation | October 21 renewed artifact/compatibility and finite token observations; qualified natural-renewal evidence remains dated October 19; not universal secrecy or production approval |

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
with controlled provider data. A [bounded real-service acceptance](real-service-acceptance-2026-10-19.md)
passed on October 19 for fixed artifacts in one private experimental deployment.
It completed one authorized task, verified the actual Discord reply, observed
containment and cleanup, and supported accepted natural renewal through an
in-place access-token change. Renewal is a qualified inference, not a captured
upstream authentication exchange.

[October 21 verification](real-service-verification-2026-10-21.md) rebuilt seven
project Go executables with Go 1.26.9, checked their installed hashes and sampled
the actual service executables, then completed one new task and independent
reply with containment and cleanup. The finite token witness passed, but source
content and access-token values did not change: this is no new refresh result.
The old binaries' acceptance was not automatically transferred to the rebuild.

The real-token witness found no exact matches in its bounded live and retained
surfaces. It did not intercept active protocol streams or scan every raw tool
argument, response or discarded diagnostic. Earlier synthetic mechanism and
failure-path results retain their dates and assumptions; the linked result
explains which unchanged source and artifacts support their reuse.

The integrated acceptance criteria remain:

1. Useful Codex work and replies through the intended private Discord path.
2. Reusable credentials remaining inaccessible to task-controlled tools.
3. Required credential renewal and persistence through the trusted owner.
4. Correct cancellation, crash recovery and final cleanup for the accepted
   artifacts and deployment.

These criteria define the [credential-isolated messaging delivery goal](milestones.md#credential-isolated-messaging).
Historical references call that goal `M1`; its test of whether task tools can
extract reusable provider credentials is
`CRED-01`. [Identifier meanings](concepts.md#planning-test-and-design-identifiers)
explain their distinct roles. On October 19, the combined real-path, mechanism
and failure-path evidence was accepted for that goal and test **only for the
named profile, exact artifacts and tested deployment**, under their stated trust
assumptions. This does not approve a new deployment or establish universal secrecy.

## Dated evidence

| Date | Observation | Scope |
| --- | --- | --- |
| 2026-09-10 | A controlled real-provider task completed with a tool-written marker, local delivery and independent cleanup checks | [Provider experiment](codex-provider-canary.md#fifth-real-run--2026-09-10); earlier failures retained; reusable credentials exposed to the Runner |
| 2026-09-11 | One task through ordinary services completed using simulated message ingress | [Fixed startup experiment](codex-daemon-startup.md#first-ordinary-service-run--2026-09-11); separate from a real Discord deployment |
| 2026-09-16 | Two sequential private Discord text tasks completed with replies and sequential container cleanup | Earlier credential-exposed profile, one host and bounded tasks; earlier failed repeat retained |
| 2026-10-07 | The isolated-profile real campaign stopped at credential-setup completion verification, before a task or serving started; cleanup was verified | Operations failure retained; no real task/provider/renewal acceptance for the isolated candidate |
| 2026-10-08 | Source review repaired redirect credential exposure, partial-reply completion, Unicode splitting, and outbound pacing/counting defects; automated checks passed | [Regression tests](../internal/discordconnector/delivery_progress_test.go) and [response-boundary tests](../internal/discordconnector/response_boundaries_test.go); no new live-platform result |
| 2026-10-19 | One isolated-profile Discord-to-Codex task, exact file/output state, independently checked platform reply and owned cleanup passed | [Fixed-deployment acceptance](real-service-acceptance-2026-10-19.md); natural-renewal inference and bounded real-token scans, with earlier failures preserved |
| 2026-10-21 | Seven project Go artifacts rebuilt with Go 1.26.9; installed/live identity checks, one new task, independent reply, containment, finite token observations and cleanup passed | [Patched-artifact verification](real-service-verification-2026-10-21.md); no new refresh observed, unchanged third-party/C/image pins and prior native fault evidence retain their own scope |

The reviewed source baseline was merged as
[`0dadcfb`](https://github.com/shwdsun/harness-security-gateway/commit/0dadcfb716e8c17fdd5e59b670148dbcfa9d276e).
[CI for that commit](https://github.com/shwdsun/harness-security-gateway/actions/runs/37707842453)
passed normal and experimental component checks, mock-image builds and reachable
Go vulnerability checks. Skipped or excluded native/provider tests retain their
stated scope. That source merge did not establish real-service acceptance; the
October 19 result supplies its own bounded evidence. Neither activates a
production deployment.

## Remaining delivery work

- Establish supported installation, update and recovery with predictable
  operator effort before a personal pilot release.
- Renew artifact, identity, filesystem and network observations when the
  accepted deployment inputs change; retain unchanged mechanism evidence
  with its original date and assumptions.
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
