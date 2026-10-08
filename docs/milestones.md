# Milestones for the first usable private gateway

Planning baseline: **2026-09-17**. This is a bounded delivery proposal, not a
deployment authorization or a claim that the acceptance gates have passed.
Mechanisms remain defined by the existing architecture and access-control
contracts; evidence remains in [implementation status](implementation-status.md).

## Source integration decision — 2026-10-08

The maintainer has explicitly requested reviewed pre-alpha source integration
for practical development and an inspectable engineering/research case study.
This changes the earlier scheduling decision that coupled main integration to
M1 completion. Main may contain the reviewed candidate after code fixes and
required local/CI checks; default builds remain mock-only and native execution
remains opt-in. Integration does not close CRED-01/M1, approve the real V4
profile, publish a release or activate services. The real compatibility,
required refresh and private-Discord acceptance requirements below are retained.
Earlier dated merge-gate notes describe their original decision and evidence.

## Current position

The first path is implemented and has scoped live evidence: one private Discord
entry, exact operator Binding, durable Run, fixed Codex target, bounded execution,
reply to the admitted conversation and container cleanup. The 2026-09-16 23:43
UTC repeat continuation recorded two distinct completed Runs and first-attempt
deliveries, with sequential container lifecycles and clean service stops. This
closes the missing two-message witness for that deployment, not all reliability
or security claims. The earlier failed repeat is retained.

| Area | State and limit |
| --- | --- |
| Authority and durable lifecycle | Implemented, with deterministic and scoped native fault evidence; no claim of exhaustive deployment acceptance |
| Private Discord-to-Codex text work | Implemented and repeatedly observed on one host; fixed target and new-only execution |
| Separate service identities and runtime ownership | Deployed and exercised in dated witnesses; not a portable installation guarantee |
| Rotation and permanently refused ingress | Refusal/re-enrollment and cursor recovery observed; credential secrecy is a separate property |
| Repository and egress resistance | Structural tests and limited live cases exist; the small hostile-repository and reported-egress witnesses do not cover the complete adversarial matrix |
| CRED-01 | Known unmet requirement in the historical profile: reusable auth is readable inside its Runner. The separate V4 owner-only runtime has accepted scoped synthetic containment/native fault witnesses and pushed-commit CI. Its October7 real campaign stopped after enrollment, before a task; real-provider/refresh/private-Discord acceptance remains |
| Operations and release | Reproducible acquisition, full accepted-profile coverage, long-running usability and activation policy still need closure |
| Comparative bake-off | Protocol and laboratory preparation exist; no completed comparison verdict |

Do not express overall progress as a percentage: functional integration and
security acceptance have different denominators. The project is past its first
functional slice and is hardening the credential boundary of that slice.

## Delivery milestones

| Milestone | Outcome | Exit and integration decision |
| --- | --- | --- |
| M0 — functional private path | Authorized text work reaches Codex, returns a reply and cleans up | Scoped baseline achieved; retain historical evidence and residuals |
| M1 — credential-isolated private path | Same useful workflow, reusable provider auth stays outside the Runner | Close CRED-01 for the named profile, renew affected real-path evidence and complete review/CI/docs; earlier source integration does not discharge this milestone |
| M2 — usable personal pilot | A bounded, documented deployment can be installed, maintained and recovered with predictable operator effort | Account for every applicable P0 requirement on the accepted profile; close operational/release blockers and document supported behavior before a pilot release |
| M3 — product direction decision | Measured benefit and operating cost against simpler alternatives | Complete the comparative gate; decide CONTINUE, PIVOT or STOP before expanding the product |

These are acceptance boundaries, not four architecture projects. Keep text,
single operator, one private Discord entry, one fixed Codex target and new-only
execution through M1. No new platform, harness, attachment protocol, orchestration
layer or general secret-management service enters M1. Later feature selection
follows actual demand and [existing expansion gates](competitive-bakeoff.md#hard-gates).
Competitor subscription unavailability is BLOCKED, never a comparison pass or an
authorization to purchase access or substitute another profile.

## M1: what completion means

Follow the [credential isolation work package](credential-isolation-plan.md).
Its internal steps belong to one delivery, not separate approval ceremonies:

1. **Resolve compatibility.** Use synthetic credentials to test the actual fixed
   native launch path, local credential substitution, stale/rejected auth and
   trusted refresh persistence. Freeze the result and its limits. Do not infer
   runtime coverage from the names of host binaries or an isolated helper test.
2. **Implement the bounded mechanism.** Owner-held secrets, Run-scoped channel,
   fixed upstream auth, non-secret downstream refresh representation, serialized
   refresh and fail-closed persistence/recovery. Preserve Core/Connector authority
   contracts; no new remote configuration surface.
3. **Verify the changed boundary.** Deterministic adversarial and lifecycle tests,
   native tool positive/negative controls, artifact provenance and a bounded
   authorized real-path campaign. Real provider compatibility and required real
   refresh evidence must be observed or explicitly remain BLOCKED. Two synthetic
   successes alone do not close CRED-01 for the deployed profile.
4. **Consolidate and integrate.** Update current summaries, resolve touched
   packaging/trust-boundary ambiguities, audit the final diff and run normal
   tests/race/vet plus applicable CI. No unresolved defect in the M1 claim or
   changed security boundary may be hidden in a follow-up. Merge after review and
   authorization; label broader pilot/release gates separately.

The first stop point is the offline compatibility result. If the pinned
subscription path cannot support isolation without widening authority or a
disproportionate subsystem, write a concrete alternative/tradeoff decision before
more implementation. Do not silently change billing/auth mode or keep extending
the milestone. A blocked compatibility result is not M1 completion; revising the
merge milestone requires an explicit scope decision with the operator.

No reliable calendar estimate precedes that result. After it, estimate the
remaining implementation and campaign from the actual changed components. The
original default merge point was M1 completion. The October 8 source
integration decision above supersedes that scheduling choice while keeping
M1 acceptance and later pilot/operations gates separate.

**2026-09-17 progress:** the client-side fresh/stale/persistent-401 substitution
probe passed with synthetic owner secrets and native tool work; see the
[scoped result](credential-isolation-plan.md#offline-client-compatibility-result--2026-09-17).
The trusted real refresh/write-back mechanism is still unresolved. M1 is not
complete and no merge/release gate has been discharged by the simulation alone.
The accompanying broader race run also exposed an unresolved uncertain-Create
recovery assertion in the existing controller. Resolve that gate with bounded
fault diagnosis before integrating new production credential lifecycle behavior;
three passing isolated reruns do not erase the original failure.

**Later 2026-09-17 update:** deterministic diagnosis identified a pre-dispatch
proof-loss defect. It and the reviewed re-offer boundary are fixed; full local
test/race/vet, focused fault checks, security demo and existing formalpilot Go
tests pass. The prior failure remains historical evidence, and the documented
post-dispatch same-boot availability limit remains. The next work package is
trusted credential refresh/write-back; this does not close CRED-01 or M1.

**2026-09-19 progress:** the bounded trusted native-refresh gate now has fresh,
stale, write-back failure, refusal and timeout evidence. The fixed native facility
is a viable implementation candidate; unconditional forced refresh after stale
startup would perform an extra rotation. Proceed to the production credential
consumer, owner-auth substitution and affected lifecycle tests. The fixture is
not that implementation and does not close real-path acceptance or authorize a
merge; see the [result and contract](credential-isolation-plan.md#offline-trusted-native-refresh-result--2026-09-19).

**Later 2026-09-19 update:** reviewed owner storage and managed-auth parsing are
implemented, still unwired. This closes the local read/write component of step 2,
not the whole trusted consumer. The next bounded package must establish native
refresh-result evidence and helper cleanup after owner loss before provider and
isolated-profile integration. A saved valid file is not refresh proof, and an
absent in-memory endpoint cannot establish that an external helper stopped.
Acceptance and consolidation in steps 3–4 remain; M1 has not reached its merge
gate. Existing compatibility witnesses are reused rather than repeated.

## Engineering and operator workload

**October7 real-campaign outcome:** exact development-commit CI passed, but the
real campaign stopped at the private service-completion witness after successful
credential enrollment. Serving and the Discord task were not reached. Cleanup
was independently verified; enrollment migration persists. The campaign's
uncertain action is closed and cannot be replayed through its installed
authority. Record the operations coverage failure and preserve M1/main as
incomplete, rather than replacing real-provider/required-refresh acceptance with
offline tests or CI. Historical notes below retain their original scope.

**October7 consolidation:** the accumulated V4 code was independently reviewed
and passed local normal/tagged tests, race, vet, builds and deterministic
witness/configuration checks. CI coverage includes the opt-in components and
development checkpoint pushes. The original accepted native fault scopes are
reused; no historical failed wrapper has been converted into a pass. Current
approved-device real compatibility, required natural refresh and private Discord
acceptance still precede M1 completion and main integration. Actual pushed-commit
CI must pass separately. M2 release/activation is a later milestone.

**October6 Owner crash/restart acceptance:** the original09:53 fault and same-DB
original serve recovery passed startup retirement before known cleanup, no
credential/provider/newRun reopening, interrupted durable publication and final
global cleanup. Complete independent review accepted that scope. The whole
wrapper remains failed at a private analysis name collision; the complete raw
report was verified locally after an alias-only correction, with no native/VM
replay. The planned synthetic fault matrix now has separate accepted witnesses.
Next current approved-device real compatibility/required refresh/private Discord,
then final docs/diff/tests/CI/review and local commit preparation. Protected current
deployment inspection needs one local sudo authentication step; no additional
offline setup is needed. CRED-01/M1 and merge remain open.

**October6 helperloss acceptance:** the original08:40 first-helper loss passed
safe refusal, zero actual container dispatch, source-held retirement and ordered
joins/release/publication. Complete independent evidence review accepted that
component. The whole batch remains failed before intended Owner crash; restart
and global cleanup were not accepted. Repair only the private status observer,
then execute only crash/original same-DB recovery. Real compatibility/required
refresh/private Discord and consolidation/current tests/docs/CI/review still
precede M1 merge readiness; no additional offline operator setup is needed.

**October6 functional-pair acceptance:** the original04:57–04:58 offline execution
passed Catalog401 recovery and true Controller cancellation during authenticated
native refresh. A reviewed collector-only recovery obtained its raw evidence;
the original wrapper's pre-collection XML failure remains failed. Complete
independent review accepted the two native gates, including late-body rejection,
source/retirement, durable terminal and ordered cleanup. Helper loss and same-DB
Owner restart are now the only remaining synthetic faults; do not replay accepted
cases. Then observe approved-device real compatibility/required refresh/private
Discord and consolidate current tests/docs/diff/CI/review. No CRED-01/M1 or merge
completion follows yet; no additional operator configuration is needed for the
offline pair.

**October6 01:30 UTC actual acceptance:** a new offline VM completed native
inference401 recovery with the production8/16s bounds, two natural helper exits,
full candidate validation/Commit and actual tool/readback. Source, isolation,
secrecy, durable completion and cleanup evidence passed; complete independent
review accepted this narrow scope. Do not replay unrelated accepted campaigns.
Next batch the four remaining synthetic faults, with bounded functional
Catalog401/cancel and structural helper-loss/Owner-restart executions. Then
observe real compatibility/required refresh/private Discord, consolidate and
review current artifacts/diff/CI/docs. CRED-01/M1 and merge remain open.

**October6 local correction:** the fixed helper measurement found natural EOF
about4.98s with full matched candidate and no signal upgrade. A bounded8s normal
grace,16s cleanup and promptly interruptible cancellation are implemented without
changing ordinary5/12s error cleanup, original Commit guards or45/60s request
budgets. Three meaningful regressions and full Go test/race/vet/security checks
pass; new canonical Runner/Owner and actual52-source closure are rebuilt. Review
and actual affected inference401 composition precede recovery acceptance; the
remaining fault/real-path/consolidation gates and M1 merge are still open.

**October6 diagnostic, 00:00–00:04 UTC:** full refresh response/receipt and native
account/read passed; the original five-second EOF wait entered forced shutdown
and `cleanExit` refused. All joins and failed-generation retirement passed;
recovery stayed failed. Measure only fixed helper EOF/signal/candidate behavior
with synthetic inputs before choosing a production correction. Private measurement
budgets cannot approve new production waiting or bypass Commit guards. Existing
fresh/Ready/Seed/kernel evidence is reused. The recovery/fault/real acceptance and
consolidation gates below still precede M1 merge.

**October5 actual batch, 22:57–23:01 UTC:** fresh canonical native tool/readback,
same-object live provider positive control and native tool connect EPERM, bounded
secrecy/source health and ordered cleanup passed. The whole campaign remains
failed: inference401 reached actual refresh dispatch but did not recover; joined
closure and durable generation retirement passed. First diagnose that native
boundary with redacted stage evidence, then run only the isolated recovery case.
Do not replay completed fresh/Ready/Seed/kernel gates. Catalog401 and the bounded
cancel/helper-loss/Owner-restart matrix, real compatibility/required refresh and
consolidation/review/CI still precede M1 merge. Current phase authorization covers
necessary work until push/merge preparation; actual push/merge remain separate.

**October5 actual batch, 19:51–19:54 UTC:** native Seed4, readonly package kernel7
and canonical service/receiver/permit/Runner Ready passed. Independent review
accepts those bounded component gates; the original wrapper/remote result remains
failed at a oneshot exit-status observation, and final global inventory was not
executed. Exact cleanup/source release, joins, natural VM stop and old full
metadata preservation passed. Reuse these completed gates; the next campaign
adds full native RunStart/tool/401/recovery/secrecy with retained service status
and independent inventory, then bounded real compatibility/required refresh.
Consolidation, review and current CI still precede M1 merge. No operator setup,
global policy change or new Claude call is required for that offline work.

**October5 actual batch, 09:51–09:54 UTC:** the newly authorized detached-mode
batch passed both native source proofs and paused containment, then failed in
RootlessKit network setup before daemon-peer attestation. Effective controls and
Ready remain open. Failed state and complete bounded receipts are retained;
service/VM stop and old metadata preservation passed. A namespace-holder race
is a code-grounded hypothesis, not a traced attribution or a new AppArmor denial.
Next resolve this private runtime prerequisite before another Ready batch;
reuse product and native evidence instead of expanding the architecture or
repeating completed campaigns. No operator setup or global policy change is
indicated. Tools/401/recovery/secrecy, bounded real acceptance and consolidation/
review/current CI still precede CRED-01/M1 completion and merge.

**October5 actual batch, 09:12–09:15 UTC:** immutable image naming now has runtime
acceptance. Both native source proofs passed, but the resource container could
not start because the fixture's rootless mode reached an unsupported default
AppArmor-profile query. Owner/effective controls/Ready remain open. Failed state
and the known-created object are preserved; service/VM stop and old metadata
checks are separate from container removal. A reviewed one-line private guest
mode candidate is unexecuted and needs actual namespace/routes/label/resource
observations in a newly frozen bounded package. No operator setup is needed.
Unchanged product/Go evidence is reused; tools/401/recovery/secrecy, real acceptance
and consolidation/review/CI remain after Ready. M1 and merge are not complete.

**October5 next preparation, 08:50 UTC:** a fresh Ready-only batch is frozen with
the wrapper-only image-name correction and unchanged code/test/native artifacts.
Affected bounded transfer/resource-observation/attachment checks pass, input
provenance and final effects have independent review, and dated read-only lab
checks pass. No new VM/runtime/Ready result or execution authority follows.
Native/tool/401/recovery/secrecy and bounded real acceptance remain after Ready,
then consolidation/review/CI before M1 merge. No operator setup is required;
one concrete batch decision is the remaining operator involvement at this gate.

**October5 actual batch, 07:50–07:53 UTC:** the renewed Ready-only VM passed both
unprivileged source proofs and reached rootless daemon peer/cgroup2 capability
checks. Exact image content imported, but immutable named-reference lookup failed;
owner, effective container resources/isolation and Ready did not run. Failed
evidence is retained; service stops and exact VM absence/old metadata preservation
passed. An offline wrapper-only image-name candidate passes selected-platform
closure checks but has no native import result. Default container AppArmor profile
loading was also denied. Review these two packaging prerequisites together before
a fresh bounded batch; do not restart earlier successful stages or infer effective
containment from daemon capabilities. No operator configuration is currently
needed. Native tools/recovery/secrecy, real acceptance and consolidation remain
after Ready; CRED-01/M1 and merge are still open.

**October3 corrected preparation, 14:58 UTC:** a fresh Ready-only batch is frozen,
with the reviewed private fixture fix, signed-base-derived collector and exact
unchanged input reuse. Affected checks and independent preparation review pass;
actual read-only lab source/old-state/collision/capacity checks pass with their
date. New VM effects await one exact authorization; no operator setup is needed.
No runtime/Ready acceptance or M1 merge gate has passed in this preparation.
Reusing unchanged coverage by artifact hashes/function equality keeps the next
step bounded; full native/recovery/secrecy, real acceptance and consolidation
remain after that gate.

**October 3 execution, 13:22 UTC:** the authorized offline VM passed its initial
containment/guest closure checks but stopped before runtime/owner admission:
private fixture umask077 masked root parent0755 to0700, and native Hold correctly
refused traversal. Ready was not reached. The stopped-disk collector's partition
type mismatch was diagnosed and recovered without another VM; original failures
and old lab state are preserved. A private permission/cleanup correction passes
local checks and independent review, still not a new frozen executable batch.
Freeze only the corrected Ready package next, re-use unchanged inputs and renew
affected checks; this does not close step 2, CRED-01/M1 or the merge gate.

**2026-10-03 progress:** actual V4 constructor metadata/artifacts/pin and actual
ext4 seed Prepare/proof/handoff/finalization have positive evidence. Test-only
additions preserve all October 1 production sources. Two exact outer fixture
containers (one missing-CLI failure, one corrected pass) were cleaned up; no host
root installation was needed. Actual service startup and bootstrap receiver,
distinct owner/Runner native tools/recovery/secrecy, then bounded real-path
acceptance remain. Keep fixture transport and probe authority limits explicit;
these positives do not close M1 or authorize deployment.

**Later October 3 preparation:** the canonical Ready-only composition test and
frozen artifacts/config/unit are prepared, with affected static/race checks.
The offline runtime inputs and bounded VM provision/stop/evidence batch are now
prepared, with native proof and effective-resource preflights and reviewed-plan
archive binding. Actual service/receiver execution awaits its exact operation
authority; no composition result is claimed. Keep one coherent environment for that
boundary and the separately pinned synthetic tools/recovery/secrecy case, then
bounded real acceptance and consolidation. No operator setup is currently needed.

**2026-10-01 progress:** the separate V4 isolation candidate now wires original
owner borrowing, disposable local auth mounts, readiness before Create, fast
bootstrap admission, two-phase resource cleanup and the startup gate. It keeps
old profile authority unchanged. Next is one affected complete native runtime /
receiver / HRP / tool / secrecy campaign, then bounded real-path acceptance and
consolidation. No deployment or merge approval follows from local wiring; see
[V4 boundaries](codex-profile-v4.md).

**2026-09-27 progress:** provider auth substitution and owner-only recovery are
implemented privately, with one native client/consumer/provider composition
passing offline. Only a verified upstream 401 can force real refresh; client
Refresh is local and never grants it. The actual Endpoint budget, concurrent
recovery and cleanup boundaries have focused tests and internal review. Next
complete one coherent runtime/profile package: owner borrow handoff, local-file
mount verification, immutable launcher/profile provenance and startup-gate
placement. Then renew the combined secrecy/lifecycle/HRP/native-tool acceptance
and perform bounded real acceptance. This advances step 2; M1 is not ready to
merge and the old deployed classification has not changed.

**2026-09-20 progress:** the private native consumer now binds actual refresh
responses to candidate storage and joins its restricted helper, output readers
and relay before committing. Fixed native fresh/stale compatibility passes after
an observed notification-metadata mismatch was reproduced and corrected. These
components are unwired. Finish the provider substitution and isolated profile,
including startup-gate placement and immutable launcher provenance, before the
composed secrecy/lifecycle campaign and real acceptance. Steps 3–4 and the M1
merge gate remain open; compatibility success is not profile reclassification.

Retain coherent commits and recoverable checkpoints during M1. A milestone
merge does not require one giant commit or delaying review until the end.
Prepare reviewable diffs as work matures; PR creation/publication is a distinct
external action. The existing accumulated history need not be rewritten into
invented historical milestones. Once a PR exists, run CI during development so
the merge gate is not the first full check.

Reuse evidence by dependency, following the [verification contract](content-evolution-and-verification.md).
Preserve unchanged admission/replay/identity tests and dated observations; renew
credential, endpoint, runtime artifact and affected cleanup evidence. Native
compatibility and secret reachability need concrete tests; the recovery formal
model cannot establish those claims. No blanket rerun or new formal-methods
research is required merely to finish M1.

Prepare local code, fixtures, scripts, candidate artifacts and failure diagnostics
before involving the operator. Batch the real campaign into one reviewed plan
with explicit effects, limits and stop conditions. Authentication or actual
Discord input may still require the operator; do not promise zero involvement.
No live effects, activation, security-policy changes or Claude calls are granted
by this plan. Do not retry failed live work before diagnosing retained evidence.

## Design assessment and bounded cleanup

Keep the main separation: transport identity, exact admission, durable execution,
runtime containment and harness reasoning have different owners. CRED-01 fits
the existing runtime/provider boundary; it does not require a new planner or a
rewrite of the control plane.

Two documentation issues require attention during M1 consolidation:

- Artifact reachability includes copied native executables as well as newly
  compiled host binaries. Label fixtures by their actual consumer; do not delete
  a component merely because it is absent from a host binary dependency list.
- The kernel enforces process/filesystem/channel isolation, while trusted HSG
  code evaluates Bindings and provider policy. Wording that only the kernel is
  trusted must not erase those code obligations. Clarify the trusted computing
  base and its failure assumptions; do not substitute prompt obedience for it.

Correct stale current summaries (for example, “Discord unimplemented” or an
already-fixed permanent-refusal wedge). Preserve dated failed observations and
their original scope. Broad store refactoring, deleting historical test support
and generalized packaging redesign are not M1 prerequisites unless the new
credential boundary actually depends on them.

## Runtime prerequisites passed; preAttach binding defect found — 2026-10-05, 18:22–18:25 UTC

A fresh offline batch using the measured RootlessKit source with a minimal
none-driver repair passed actual namespace/loopback, exact image and container
NNP/seccomp/capability/cgroup checks. Owner startup/enrollment and one Create/Attach
reached; Ready did not. Code review identified that preAttach used the original
owner Binding to validate the separate disposable seed, which must be rejected.
The minimal shared validation repair preserves both independent capabilities.
Current source checks/build/review and a new Ready batch follow; this failed result
is retained. Exact owner-container cleanup/order/joins and VM/service stops passed,
and stopped-copy hash verified unchanged source; final global inventory was not
observed. The inherited guest AppArmor label is unconfined, not an extra confinement
claim. Full native tools/recovery/secrecy, real acceptance and consolidation remain;
CRED-01/M1/V4 activation and merge stay blocked.
