# Delivery roadmap

Current planning summary: **2026-10-08**. The first product path remains one
operator, one private Discord entry, one fixed Codex target and text tasks.
[Implementation status](implementation-status.md) reports evidence;
[core concepts](concepts.md) define technical terms and reference labels.

## Delivery goals

| Goal | Completion criteria | Current position |
| --- | --- | --- |
| Functional private messaging | Authorized text work reaches Codex, replies to the accepted conversation and cleans up | Observed in bounded September experiments under an earlier credential-exposed profile |
| Credential-isolated messaging | The same useful work, with reusable provider credentials inaccessible to task tools; real-service compatibility and renewal verified | Implemented candidate with scoped automated/native results; integrated real-service acceptance remains open |
| Usable personal pilot | Install, update, operate and recover a bounded deployment with predictable operator effort; applicable security requirements satisfied | Planned; supported real deployment is not ready |
| Product direction decision | Compare repeatable security benefit and operating cost with simpler alternatives | Comparison protocol exists; no completed comparative verdict |

The historical labels for these rows are respectively `M0`, `M1`, `M2` and
`M3`. They are planning references, not product versions. Public status should
name the outcome before the label. See [identifier meanings](concepts.md#planning-test-and-design-identifiers).

Do not combine functional progress and security acceptance into a single
percentage. A successful task can still run under a credential boundary that
does not satisfy the next delivery goal.

## Credential-isolated messaging

This goal preserves the useful private-message workflow while keeping reusable
provider authentication outside the entire task-controlled environment.

The [credential-isolation plan](credential-isolation-plan.md) defines the
implementation details. Completion requires the following, for one named
profile, exact artifacts and deployment:

1. **Client compatibility.** Establish that the fixed Codex client supports the
   isolated authentication path, including expired/rejected authentication and
   required renewal. Controlled fixtures provide component evidence; real-service
   compatibility must be observed.
2. **Credential boundary.** Keep real access, refresh and ID tokens in the
   trusted authentication owner. Task tools must not recover them through
   files, environment, processes, protocol traffic, logs or retained state.
   The disposable client representation must not grant authority outside its
   exact live task channel.
3. **Complete useful workflow.** Verify authorized Discord task admission,
   Codex work, expected file/output state, reply to the original conversation,
   and independently observed cleanup.
4. **Failure behavior.** Verify applicable hostile input, cancellation, crash,
   credential rejection/renewal and cleanup cases without speculative execution
   retries or releasing uncertain ownership.
5. **Consolidation.** Resolve defects in the changed boundary, attest affected
   artifacts and update contracts, tests, documentation and review evidence.

The credential-recovery requirement is test case `CRED-01` in
[`bakeoff/cases.json`](../bakeoff/cases.json). It is one necessary condition
inside this delivery milestone (`M1`), not another name for the entire milestone.
Two synthetic successes or passing source CI are insufficient.

An unresolved compatibility result remains an unmet acceptance condition. If
isolation would require widening authority or adding a disproportionate subsystem,
record the alternative and tradeoff before extending implementation.

## Usable personal pilot

The pilot requires the accepted security profile plus documented installation,
artifact acquisition, updates, long-running behavior and failure recovery.
Every applicable mandatory requirement must have evidence or an explicit
unmet condition. Operational usability includes manual substeps, waiting,
rework and recovery burden, rather than only counting successful tasks.

No new platform, attachment protocol, planner or general credential service is
needed to finish the current credential-isolated messaging goal. Expansion
follows actual demand and the [comparison gate](competitive-bakeoff.md#hard-gates).

## Source integration and deployment

Reviewed source can be integrated independently of real-service acceptance.
Source merge, an installable pilot, a published release and production activation
are distinct events. The October 8 reviewed source merge does not establish
credential isolation in a real deployment or grant deployment authority.

<a id="source-integration-decision--2026-10-08"></a>

### Source integration decision — 2026-10-08

The maintainer requested a reviewed pre-alpha development baseline and an
inspectable engineering/research case study. This supersedes the earlier
scheduling choice that held source integration until credential-isolated
messaging acceptance. Default builds remain simulated-agent-only; experimental
native execution still needs an explicit build option. Acceptance criteria
above are retained.

<a id="m1-what-completion-means"></a>

### Historical milestone reference

Older links to "M1: what completion means" refer to the
[credential-isolated messaging criteria](#credential-isolated-messaging) above.
The [planning history](milestone-history.md) preserves earlier decisions and
dated progress without treating them as current readiness.

## Engineering workflow

Prepare implementation, relevant tests, candidate artifacts, diagnostics and
recovery before a necessary operator handoff. Batch unavoidable external steps
within existing authorization, count manual work across the objective, and
redesign a workflow that repeatedly returns unfinished agent work to its operator.

Use [change impact](content-evolution-and-verification.md) to select checks:
retain unchanged mechanism evidence with its date and assumptions, and renew
affected artifact/runtime/provider evidence. Formal recovery proofs do not
establish real credential secrecy or provider compatibility. Keep recoverable
commits and reviewable changes; a delivery milestone does not require one giant
commit or repeating completed research.
