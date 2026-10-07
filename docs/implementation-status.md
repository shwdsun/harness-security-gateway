# Implementation status

## Real campaign stopped at enrollment witness; M1 remains open — 2026-10-07

The development candidate `a168ee306ad839634e4143334209ff21f178068f` was
pushed and [GitHub CI completed successfully](https://github.com/shwdsun/harness-security-gateway/actions/runs/37683057049)
at20:51 UTC. All three jobs and their steps passed, including normal and opt-in
tests/race/vet, both mock images and reachable vulnerability checking. This
establishes the pushed-commit CI result, not real-provider or release acceptance.

The bounded real campaign completed credential retirement and enrollment, but
the private driver timed out on its service-completion witness. Independent
service-journal evidence records successful enrollment; the retained campaign
still has an uncertain enrollment action and is closed after cleanup. Per-poll
values were not retained, so the cause of the missed completion witness remains
unresolved. No task was
posted, and Owner serving, Core and Connector starts were not reached. This
is an operations witness failure, not an observed failed model Run.

Cleanup and subsequent independent observation verified stopped HSG services,
removed temporary overrides, idle durable obligations and zero containers.
Credential migration persists; cleanup did not restore the retired enrollment.
Original local configurations were preserved, not activated with stale authority.

The accepted synthetic fault scopes and local/code-review results retain their
original limits. Approved-device real-provider compatibility, required natural
refresh and private Discord task/reply completion remain unobserved for V4.
CRED-01/M1 and main integration are incomplete; no production activation follows.
Retain the failure without reopening its closed authority, replaying enrollment
or reducing the
[M1 acceptance boundary](milestones.md#m1-what-completion-means).

## V4 consolidation reviewed; real acceptance remains open — 2026-10-07

The accumulated owner-only V4 implementation has received an independent,
code-grounded review of controller certainty, source ownership, native refresh,
runtime separation, provider substitution and explicit official-bot admission.
No concrete authority escape, speculative create replay or cleanup-release
regression was found in that review. Review is advisory, not an acceptance proof.

Local checks passed with Go1.26.7: command builds, module verification, normal
tests and race, full opt-in tests excluding the exact legacy native CLI experiment,
focused opt-in runtime/provider race, normal/tagged vet, security witness and
configuration/bake-off checks. Initial restricted-environment cache/socket errors
are environment limitations; the subsequent ordinary-host checks passed. No
accepted native fault campaign was rerun to change a historical failed wrapper.

CI now runs those opt-in component tests and vet, focused opt-in race and
development checkpoint pushes. This entry records the local result and CI
configuration; GitHub CI execution must be observed on the actual pushed commit.
Deployment documentation now distinguishes the existing V3 development bundle
from V4's separate Runner, Owner helper and root-controlled immutable artifacts.

Approved-device real-provider compatibility, required natural refresh and private
Discord completion remain unobserved for V4. CRED-01/M1 and the main integration
gate remain open. The deployed V3 profile remains credential-exposed; neither
offline Root workflow tests nor synthetic native witnesses approve production.
Earlier dated entries retain their original scope.

## Synthetic Owner crash and same-DB recovery accepted — 2026-10-06, 09:53 UTC

Complete independent raw-evidence review and primary adjudication accepted the
original bounded Owner SIGKILL, new-process original serve on the same database,
startup credential retirement, terminal publication and final cleanup. Exact
protected process identity remained stable while mutable RSS/scheduling fields
changed. The authenticated Owner signal preceded the original callback deadline;
old Owner/helper/cgroup absence was observed before the second explicit start.

The new process retired the generation before removing the known container,
without reopening credentials/provider/native execution or creating a new Run.
The physical source lock had already released on process death; durable
occupancy/workspace/ref remained until cleanup. Closed SQLite recorded one
interrupted Run, refNULL/intent0/outputNULL, revocation1 and zero occupancy/locks/
staged terminals. Enrolled fingerprint and unchanged source/proof were verified.
Original joins and the specific expected listener-close error passed. Empty
global inventory preceded five final owned stops and four inactive/PID0 units.

The original whole batch remains failed/remote1: its stopped-report analyzer had
a Python module/local-variable name collision. The complete original report was
already collected; an alias-only local correction reproduced the failure and
validated the same raw evidence with negative controls, without VM/disk/native
replay or rewriting the failed result. Old metadata preservation is qualified by
one recorded access-time-only difference; no old-byte or actor claim follows.

The remaining planned synthetic fault scopes are now accepted separately. Do
not rerun them merely to obtain a green wrapper. Approved-device real
compatibility, required refresh/private Discord and final consolidated review/
tests/docs/CI still precede CRED-01/M1 and merge readiness. V4 remains a candidate;
the deployed profile remains `credential-exposed-personal`. Earlier dated
entries below retain their historical scope.

## First native helper loss accepted; Owner restart pending — 2026-10-06

The original offline helperloss phase at08:40 UTC passed its narrow safe-failure
boundary. One authenticated helper pidfd SIGKILL preceded successful native
account/candidate promotion; actual external Create/Attach and Commit remained
zero. Native/provider joins, source-held credential retirement, resource close
and source unlock before publication passed. Closed SQLite recorded one failed
Run, refNULL/intent0, revocation1 and zero occupancy/workspace locks. Complete
independent raw-evidence review and primary adjudication accepted this scope.

The whole batch remains failed. The private supervisor refused before the Owner
crash signal; restart never ran. It compared complete mutable process status,
which can reject legitimate diagnostic changes. The actual failing operand was
not recorded and remains unknown. Later global inventory was nonempty and final
four-unit verification failed; VM absence and old metadata preservation passed
separately. All original results and volumes remain retained.

Next repair only that private observer, retaining raw diagnostics and exact
security/process/signal guards, then test only Owner crash and original same-DB
recovery. Do not replay accepted helperloss or other native campaigns. Approved-
device real compatibility/required refresh/private Discord and consolidation/
review/CI remain before CRED-01/M1; V4 stays a candidate and the deployed profile
remains `credential-exposed-personal`.

## Synthetic Catalog401 recovery and native-refresh cancellation accepted — 2026-10-06

The original offline VM executed Catalog401 recovery and authenticated native
Controller cancellation at04:57–04:58 UTC. Complete raw-evidence review accepted
both scopes. Catalog1/Inference2/Refresh1, two natural native exits/full candidates/
Commits, actual canonical Runner tool/readback, healthy updated Owner source and
contained tool socket denial passed. Cancellation consumed and closed a complete
late200 refresh response, then rejected it on the original cancelled context:
initialCommit1/recoveryCommit0, no candidate/replay and unchanged source.

Exact cleanup, source-held retirement before release/publication, closed SQLite
terminal/refNULL/intent0/zero occupancy and workspace locks, bounded secrecy and
ordered empty global inventory/owned stops passed. Cancellation retirement follows
runtime cleanup; startup retirement before cleanup remains a separate gate.

The original wrapper remains failed at literal old-volume XML comparison before
collection. One reviewed stopped-new-disk collection at05:25–05:26 UTC recovered
the original guest evidence without replay. Dated old-volume differences were
limited to exact access-time fields; no old-content digest or actor attribution
is claimed. Earlier failures and retained volumes remain unchanged.

Helper loss and same-database Owner crash/restart are the two remaining synthetic
faults. Real compatibility/required refresh/private Discord and final consolidated
tests/docs/review/CI remain before CRED-01/M1 and merge readiness. Reuse accepted
fresh/Ready/Seed/kernel/inference401 evidence within its original artifact scope.
V4 remains a candidate; deployment remains `credential-exposed-personal`.

## Synthetic native inference401 recovery accepted — 2026-10-06, 01:26–01:30 UTC

One new no-NIC VM completed the fixed native CLI's inference401 recovery with
the production eight-second natural shutdown and sixteen-second cleanup bounds.
Both helper calls exited normally without forced shutdown, validated full
candidates and committed; the second refreshed. Actual Catalog2/Inference3/
Refresh1, canonical Runner tool execution and independent readback passed.
Source health, same-object live socket control/tool connect denial, bounded
secrecy, source-held exact removal, release before publication and all joins
passed. Closed SQLite recorded completed/refNULL/intent0 and zero revocations,
credential occupancy and workspace locks; final global inventory was empty.
Owned service stops, natural VM absence and the pinned old-metadata preservation
gate passed. Complete independent review accepted this exact synthetic scope.

The new canonical Runner's initial preparation also passed; the full fresh
scenario was not rerun. Earlier fresh/Ready/Seed/kernel evidence retains its
original version and scope. Earlier failed reports remain failed. This result
does not establish a general helper exit bound or real-provider compatibility.
Catalog401, recovery cancellation, helper loss, Owner crash/restart and bounded
real-provider/Discord acceptance remain before CRED-01/M1 and merge readiness.
The deployed profile remains `credential-exposed-personal`; V4 is a candidate.

## Bounded normal helper shutdown implemented; composed recovery pending — 2026-10-06

The V4 candidate now permits eight seconds of natural EOF shutdown after a
successful account/read. Live cancellation or cleanup expiry interrupts that
wait; TERM/KILL and reader joins use a separate sixteen-second cleanup budget.
Ordinary error cleanup retains its five-second grace and twelve-second resolve
cleanup. Forced exits still refuse authorization. Original joins, full candidate
validation, cancellation/Owner-close checks and Commit conditions remain;
the60-second invocation and45-second endpoint idle limits are unchanged.

A synthetic helper exiting six seconds after actual EOF passed; cancellation
and Owner.close at the same post-account EOF barrier promptly refused Commit
and joined. These three regressions passed race execution. Full local Go test,
race and vet plus security demo passed. The canonical Runner and Owner were
rebuilt; the actual52-file Runner closure changed exactly the two helper source
files. Older artifact claims retain their original hashes and scope.

Independent implementation review found no blocker in this exact correction.
A new native inference401 composition with these production budgets remains
before recovery acceptance. The earlier failed
VM case is unchanged. This local correction does not close CRED-01/M1, activate
a production target or approve publication; the deployed profile remains
`credential-exposed-personal`.

## Fixed helper exits naturally near the original cutoff — 2026-10-06, 00:36 UTC

One network-none helper-only measurement reused the fixed native ELF/launcher
and exact synthetic rotating-token inputs. Both serialized consumer calls
accepted, with one refresh and complete candidate validation/Commit. The refreshed
helper exited normally/status0 without TERM/KILL about4.98 seconds after stdin
EOF; all process/readers/relay joins and owned container removal passed. The
measurement used private40/48-second observation bounds while retaining all
original exit/cancellation/Commit predicates and the60-second invocation limit.

This is a local helper compatibility result. It does not establish a general
native exit bound, identify an internal upstream cause or pass the original
failed VM inference401 composition. Production still uses its original five-
second EOF cutoff. The next proposed fix gives successful account/read a bounded
normal shutdown allowance while preserving prompt cancellation, shorter error
cleanup and rejection of every forced exit. It requires regression checks, new
compiled artifact hashes and affected composition acceptance before any M1 or
activation claim. Previously accepted fresh/Ready/Seed/kernel facts are reused
within their original scope; CRED-01/M1 and real-path gates remain open.

## Native recovery refusal localized; shutdown measurement pending — 2026-10-06, 00:00–00:04 UTC

One isolated inference401 diagnostic reused the unchanged native artifacts and
synthetic rotating-token inputs. Its bounded stages prove an accepted refresh
request, complete200 response/receipt and successful native account/read. Process,
readers and relay joined, but `cleanExit` refused the invocation because the
five-second EOF wait entered forced shutdown. The recorded other exit conditions
passed. Signal delivery, natural exit latency and the private candidate file
were not measured; candidate validation and source Commit were never reached.
The original recovery case and whole campaign remain **failed**.

Independent review checked the report, indexed bytes, all368 current sources,
the unchanged52-file canonical Runner closure and reversible private diagnostic
overlays. Failed generation retirement, zero occupancy/locks, all provider joins,
empty global container inventory and owned cleanup passed. These establish safe
failure, not successful recovery. Report SHA256
`261e9fc08cc5d3e4e18ed9f8a3219a03c63e692b15982a9bdaf8c1b146c2c44e`
contains1,710,080B/574 regular members/164 index records.

The next narrow measurement observes the fixed helper's EOF, signal syscall,
terminal state and candidate boundaries in a network-none container with synthetic
storage. Experimental waiting budgets do not change production acceptance.
Reuse the earlier complete fresh/Ready/Seed/kernel evidence. Recovery/fault/real
acceptance, consolidation and CRED-01/M1 remain open; deployment stays
`credential-exposed-personal`. No production service, credential, policy or
publication changes follow from this diagnostic.

## Fresh native isolation passed; inference401 recovery failed — 2026-10-05, 22:57–23:01 UTC

One fresh offline VM completed the canonical Runner's native tool call and
independent file readback. The fresh subtest passed without SKIP. Root observed
a live Owner and distinct Runner, exact executable/mount/UID identities, and
an owner-secret-free local seed. The same probe connected to the live Owner
socket as an unprivileged positive control; native tools attempted that same
socket object at the fixed mounted path and received EPERM, closing the FD.
AF_UNIX socket creation itself succeeded and remains diagnostic; actual channel
connection is the security measurement. INET4/6 creation was denied. Bounded
Runner secrecy scan, unchanged original source/health, source-held exact removal,
unlock before publication and all recorded cleanup joins passed.

The **whole campaign failed** in inference401. Actual Catalog2/Inference1 and
one Owner refresh dispatch were observed, followed by unavailable local auth;
successful native candidate/persistence and resumed inference were not observed.
The Run failed, its generation was revoked, and closed read-only SQLite showed
no runtime ref, credential occupancy or workspace lock. All provider joins
completed. Zero-valued result counters assigned only after the completion
assertion are unobserved, not evidence of no earlier Create/Attach. Diagnose the
native account/join/candidate boundary before a revised, isolated recovery case;
reuse the complete fresh witness and earlier Ready/Seed/kernel evidence.

Immutable report SHA256
`091f25805651f3cd7ee4c25acdd0ab03655e92cadaac6e3167d2c62fc52039a8`
has2,088,960B/637 unique regular members/186 index records. A separate failure
audit checked all368 public sources, frozen inputs and report/index bytes before
correction. Global inventory was empty and five owned stops succeeded; Owner
failed/PID0, so four inactive units did not pass. Natural VM shutdown, owned-domain
absence and old full metadata preservation passed. Earlier false reports remain
unchanged. Current exact rotating-input parser/candidate controls pass locally,
but cannot explain the unmeasured native failure. No production credentials,
Discord activation or global security policy changed. Catalog401/cancel/helper
loss/Owner restart, real compatibility/required refresh, consolidation/review/CI
and CRED-01/M1 remain open; deployed classification stays
`credential-exposed-personal`.

## Canonical Ready and readonly package controls passed — 2026-10-05, 19:51–19:54 UTC

A fresh offline VM passed four actual native Seed lifecycle cases and seven
actual kernel package controls without SKIP. The V4-only repair verifies the
fixed hash-pinned package's directory/open-file readonly properties in the
Runner's namespace, where host-root artifact UIDs need not appear as root.
Host installation/ancestor guards, exact mount admission, closed layout, hashes,
hardlink rejection and legacy ownership rules remain intact. Nested writable
mounts, chmod0555 on a writable mount, corruption and extra files were refused.

The canonical Runner reached Ready through configured startup/enrollment,
controller, Owner, Docker attach, receiver and permit. Its intentional stop
before RunStart produced a clean interrupted result, exactly one Create/Attach,
source-locked exact deletion, release before publication, unchanged original
source and joined controller/artifact/process-lock cleanup. Go/systemd journals
independently confirm successful test completion. All364 source and frozen input
hashes match after execution; old full metadata and natural VM absence passed.

The original outer batch remains **failed**: its oneshot exit-status guard saw
code0 after service deactivation, instead of the required code1. State unloading
is an inference, not a traced cause. Independent review accepts the narrower
component/Ready gate; final global container inventory was not reached and is
not claimed. The next distinct full Run campaign must retain service status and
collect that inventory independently, without replaying Ready solely for a
wrapper receipt. Native tools/401/recovery/secrecy, real compatibility/refresh
and consolidation/review/current CI remain; CRED-01/M1/activation/merge are open.
The deployed profile remains `credential-exposed-personal`.

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

## Ready blocked at dependency network setup — 2026-10-05, 09:51–09:54 UTC

One newly authorized offline batch restored the vendor's detached-mode default
while retaining NET=none and all product pins. Paused containment and both native
ext4 source proofs passed, but RootlessKit's network setup failed with an nsenter
Invalid argument before daemon-peer attestation. Namespace/image/resource/owner/
Ready observations were not reached. This failure does not establish another
AppArmor denial. The original false result and all failed state are retained.
Collected hashes/sizes, five service stops, final MainPID0/socket absence, natural
VM shutdown, owned-domain absence and full old metadata preservation were checked.
No actual container inventory was observed. All361 product sources remain unchanged.

The private dependency code suggests an asynchronous namespace-holder race;
this is a source-based hypothesis, not a traced syscall attribution. Resolve that
narrow startup prerequisite before another Ready batch, reusing existing evidence.
No product guard or global security policy changed and no operator setup is
indicated. CRED-01/M1/merge and V4 activation remain blocked; deployed classification
stays `credential-exposed-personal`. Earlier dated records below are preserved.

## Image naming accepted, Ready blocked by fixture runtime mode — 2026-10-05

The authorized offline batch at09:12–09:15 UTC passed paused containment, both
native ext4 source proofs and the original immutable named image lookup with
Id/RepoDigest/amd64 checks. Resource creation succeeded, but start failed at
Docker's default AppArmor profile visibility check. Owner, effective resource
controls and Ready did not run. The false result and failed disks are retained.
Service stops/MainPID0/natural shutdown, exact VM absence and full old metadata
preservation passed. Container removal or empty inventory was not established.
Independent review checked the collected evidence and these claim limits.

Measured vendor code identifies the fixture's explicit detached-network-mode
override. A private one-line guest-unit candidate restores the vendor default,
retaining NET=none and product pins; it remains unexecuted. Its daemon/guest
loopback boundary and actual namespaces/routes/labels/resources must be measured
before Ready. No product source or security policy changed. Source-proof/image
positives do not close CRED-01/M1, activate V4 or authorize merge; native/tool/
recovery/secrecy, real acceptance and consolidation remain. Deployed
classification stays `credential-exposed-personal`.

## Image-name correction and next Ready batch prepared — 2026-10-05

A fresh bounded offline batch now freezes the wrapper-only image-name candidate
and the unchanged Ready/native/probe/unit artifacts. All361 product source hashes
and module manifests/sums still match their original build provenance; no broad
Go stage was repeated. Affected streamed-transfer, resource-observation and new
attachment refusal checks pass; independent review verified final input lineage,
pins and operation scope. Resource observations bind the requested sleep
container's PID/starttime, NNP, default seccomp, capabilities and effective cgroups,
recording AppArmor without adding policy. They are not native secrecy evidence.

Dated read-only lab inspection at08:50 UTC verifies original reusable inputs,
retained failed-state metadata, no proposed collision and capacity. The fresh
VM/stage/volumes are **not authorized or executed**. Exact image lookup, resource
and Ready acceptance remain absent; the prior image-name failure is retained below.
Full native/tool/401/recovery/secrecy/real acceptance and final consolidation still
precede CRED-01/M1 and merge. Deployed classification remains unchanged.

## Ready attempt reached source proof, blocked at image naming — 2026-10-05

The expired October3 preparation was renewed with three test-only date literals;
production sources and native/probe/unit artifacts remain unchanged. Affected
race/vet and packaging checks pass. One authorized offline VM then passed both
unprivileged native ext4 source proofs and reached rootless daemon peer/cgroup2
capability checks. Image content import succeeded, but lookup by the immutable
image reference failed because the exported wrapper carries no image name.
Runtime startup failed; owner, effective container resource checks and Ready
were **not reached**. Its original failed result and evidence remain retained.
Service stops, MainPID0, natural shutdown, exact VM absence and complete old-state
metadata preservation were checked in the dated run.

A separate offline candidate changes only the outer image-name annotation,
preserving all content-addressed bytes and product pins. Selected-platform
descriptor closure and affected refusal checks pass; native named-import remains
unverified. The daemon also reported denial loading its default AppArmor profile
and did not advertise AppArmor in SecurityOptions. Container confinement is
therefore an open prerequisite, not a verified consequence of daemon startup.
Review these two packaging prerequisites before another bounded batch. No
product guard or host-global policy changed; no automatic retry is authorized.
CRED-01/M1, full native/recovery/secrecy/real-path acceptance and merge remain open.
The deployed classification remains `credential-exposed-personal`; the dated
preparations and failures below remain historical evidence.

## Corrected Ready-only batch prepared — 2026-10-03, 14:58 UTC

A fresh private batch now freezes the reviewed permission/cleanup correction and
signed-base-derived collector guard. Unchanged product sources and measured
owner/probe/unit artifacts are reused by exact pins; affected archive, staging
and attachment rejection checks pass. Independent review found no preparation
blocker. Dated read-only lab inspection confirms reusable input identity/hashes,
old-state preservation, no proposed collision and resource availability.
The new VM/stage/volumes are **not authorized or executed**. This preparation
does not prove native source proof, runtime, receiver or Ready. The prior failed
attempt is retained below; full native/recovery/secrecy/real-path acceptance,
CRED-01/M1 and merge remain open. Deployed profile classification is unchanged.

## Ready VM attempt stopped before admission — 2026-10-03, 13:22 UTC

The authorized bounded offline VM passed its paused containment, signed-image
kernel/dependency and guest provisioning checks, then failed before runtime/owner
start. Its native source Hold rejected a fixture parent directory: process
umask077 had changed the requested root-owned0755 parents to0700, preventing the
unprivileged owner from traversing them. The credential0700/auth0600 modes were
correct; product guards are unchanged. CaptureProof, runtime/receiver and Ready
were **not reached**. The VM stopped naturally, final units had MainPID0, and its
absence and older lab metadata preservation were independently checked.

The first collector also assumed a generic root partition type. Evidence was
recovered offline from the same stopped disk with signed-base-derived GPT/ext4
identity and logical source comparisons; both original failures stay retained.
A separate private fixture correction passes local permission checks under the
actual umask and bounded independent review. It is not a newly frozen VM plan or
a guest acceptance result. The next step is a fresh corrected Ready-only batch;
full native/tool/401/recovery/secrecy and real-path gates, CRED-01/M1 and merge
remain open. No product source or deployed profile classification changed.

## Affected V4 composition evidence — 2026-10-03

A further opt-in Ready-only test and its frozen artifact/config/service-unit
preparation now use the actual isolated constructor, global startup ownership,
native enrollment and controller. Its observer validates Runner Ready and stops
before RunStart, requiring an intentional interrupted result and ordered exact
cleanup. This composition has **not run**. The offline systemd VM/runtime inputs
and bounded single-VM batch are now prepared: signed clean guest image and
uidmap closure, measured static Docker bundle, exact cached image archive,
native source-proof and effective-resource preflights, finite stop and independent
post-stop evidence collection. Execution requires its exact operation authority.
Tagged compile-only, affected vet, freshness-boundary
race checks and disabled opt-in behavior pass; these are preparation checks.
Production sources remain unchanged. Full native tools/recovery/secrecy and
bounded real-path acceptance remain open.

The production code is unchanged from October 1. Two opt-in tests add positive
evidence at the remaining composition seams. Actual `isolatedRun.Prepare` now has
native ext4 HeldSource/CaptureProof/Handoff evidence, original owner Claim,
separate owner/seed bindings and mount arguments, registration before readiness,
and two-phase finalization under success, readiness failure, cancellation and
failed join. The original lock and healthy source survive borrowed-capability
cleanup. Readiness/transport is a private fake with simplified local auth bytes;
this does not establish native auth compatibility, persistence or admission.

One frozen rootless network-none probe passed the actual `NewConfiguredCodex`
V4 constructor with root-mapped read-only static artifacts, service-owned tmpfs
mutable roots, exact hashes/profile and owner FD Close. Its process pin names
the probe binary, not a deployed sandboxd. It never activates the owner gate,
creates a Run/container, reads enrolled auth or calls a provider. The previous
probe failed because the cached image lacked the CLI executable required by
config inspection; the corrected fixture supplies its frozen real CLI read-only,
without executing it. Both temporary outer containers were removed by exact ID
with absence verified. No host installation or service/policy change occurred.

The native seed test and three race repetitions pass on private ext4 temporary
fixtures; tagged full compilation (53 package entries) and affected vet pass.
All 358 prior internal/cmd source hashes are unchanged; two new test files bring
that inventory to 360. October 1 broad test/race/vet evidence retains its date.
Checkout ancestry, initial test fixture/constant and tool temporary-write failures
remain recorded; no product predicate was relaxed to admit them. Internal review
checked the two tests and their narrower evidence boundaries.

Actual root-controlled service startup, kernel bootstrap receiver, independent
owner/Runner native HRP/tool/recovery/secrecy composition and bounded real-path
acceptance remain open. See [V4 remaining acceptance](codex-profile-v4.md#remaining-acceptance).
CRED-01/M1 remain blocked; no merge or activation follows from these positives.

## Isolated runtime/profile wiring candidate — 2026-10-01

The opt-in [V4 candidate](codex-profile-v4.md) now connects the controller's
original HeldSource owner borrow to the provider/native consumer. Exact one-use
Claim is shared by copies; there is no mount fallback. Provider ownership is
registered before native preparation, which completes before external Create.
The unchanged ten-second inert-bootstrap phase verifies a separate disposable
seed object/content and both scope bindings, then opens already prepared
admission. The real enrolled auth is absent from this candidate's bind arguments.

Provider/helper/preparation join precedes container removal; seed handles and the
borrow finalize after verified absence or certain non-dispatch. The controller
retains original-source health across resource deletion and retires invalid
generations before held-source and durable occupancy release. Tests cover joined
taint, failed join, revoke failure/lost response, same-inode seed mutation and
independent static/mutable ownership. A separate schema/profile/adapter/pin keeps
old authority unchanged and retains native tools/developer instructions.

Startup now obtains the helper-absence gate after the global process lock and
before any store/recovery, in isolated serve and enrollment. Inert `-check`
does not activate it. Root-controlled static files/parent chains and pinned
launcher/native FDs prevent service-owned executable mutation; outstanding Run
borrows prevent premature FD Close. Independent review found a conflicting
ToolPackage-owner predicate in the first wiring and verified its correction;
mutable roots still require service ownership.

Focused offline tests, ordinary full tests, normal/tagged vet and the security
demo pass. Full tagged race completed at **08:31 UTC**, with all 48 ordinary
package entries and five opt-in entries; all final checks match the same 358
internal/cmd source files. Tool-sandbox failures and the first test fixture error
are retained. The old `TestCodexExecIntegration` campaign is
explicitly excluded from tagged runtime regression, without changing its test;
native compatibility evidence keeps its date. No new container/provider/model,
credential enrollment, deployment or remote CI observation occurred.

Complete production-constructor metadata, actual wrapper Prepare/CaptureProof,
bootstrap receiver and service-gate/native HRP/tool/secrecy composition are still
open. The September 27 shared-domain/test-storage witness does not cover them.
Next prepare that affected acceptance, then bounded real acceptance and final
review/CI. V4 remains a blocked candidate; CRED-01/M1 and merge are not complete.

## Per-Run provider authentication candidate — 2026-09-27

The private [isolated provider adapter](credential-isolation-plan.md#per-run-provider-authentication--2026-09-27)
now combines Endpoint admission with the native owner consumer. It generates
fresh, fictional per-Run auth for the client, replaces accepted inference/catalog
auth with owner-selected values, and handles client Refresh entirely locally.
Only a valid upstream 401 can trigger one forced owner recovery. Concurrent and
late 401s cannot repeat it or revoke a newer local representation; the adapter
never replays inference. Existing connection/operation budgets remain unchanged.

Independent review exposed a real HTTP budget mismatch: a rejected Refresh had
already spent the Endpoint's slot even though no local auth was issued. The
counterexample failed before the adapter checked the actual admission counter.
Focused tests now cover that fix, a valid HTTP Refresh waiting for recovery,
cross-Run/old/real-token rejection, cancellation, unjoined cleanup, auth failures,
and local-vs-upstream diagnostics. Tainted auth remains on the original held
source; successful resource cleanup cannot erase the controller's retirement
obligation. That shared-object contract still needs runtime integration.

One affected network-none witness used fixed CLI 0.151.0, the actual new provider
and native consumer, and synthetic upstream/storage. It observed exactly one
upstream 401, one native owner refresh, one local 401, one local Refresh, and a
successful new inference. Owner token strings stayed unchanged; cached readiness
and refresh each reached one accepted test-storage commit. Client files/output
and diagnostics contained no raw dynamic owner canary. All processes, readers,
endpoint and relay joined; the single container was removed by exact identity
and absence verified without rescue. No real model/provider/credential was used.

Full ordinary tests, normal/tagged vet and the security demo pass. Race coverage
completed at 19:25 UTC across all 48 ordinary package entries: the first run
completed 42 before its driver's total timeout; a bounded continuation passed
the remaining six against identical source digests. The original incomplete run
is retained as a timeout, not a pass.
The candidate remains unselected by every executable/profile. The witness shares
client/owner PID and mount domains and is not final Runner containment, actual
HeldSource enrollment, host startup-gate, HRP/tool or Catalog-401 acceptance.
Next wire the isolated immutable profile, artifacts, startup check and shared
credential lifecycle; then run the affected combined acceptance and bounded real
path. CRED-01/M1 and merge remain open. Existing profiles retain their exposed
classification; deployment and remote CI were not re-observed in this work.

## Trusted native consumer candidate — 2026-09-20

The [owner native consumer](credential-isolation-plan.md#trusted-native-consumer-candidate--2026-09-20)
is implemented, still private and unwired. It binds a native candidate to the
complete observed refresh response, permits unchanged token strings, separates
cached readiness from refresh, and persists only after process/readers/relay
join. The fixed launcher denies new processes while allowing threads. Unknown
Wait results and incomplete joins retain cleanup obligations; failed auth never
replays a refresh or restores old credentials. A startup cgroup gate exists as
a candidate, but its placement and actual service observation remain unwired.

Independent review closed inherited-filter test coverage, relay nuisance-request
handling, uncertain-Wait cleanup and extra-response acceptance gaps. Kernel
filter tests and synthetic process/storage/protocol/cancellation faults pass.
The affected fixed Codex 0.151.0 witness then exposed a real mock gap: native
notifications include `emittedAtMs`. A synthetic reproduction failed before the
exact-key, typed notification-metadata fix. The timestamp is discarded and cannot
authorize or prove refresh. The corrected canonical consumer/launcher passes
fresh and stale native auth in a network-none container, one synthetic refresh
and one test-storage commit each, including unchanged token strings. Failed
preflight/compatibility evidence is retained and all five experiment containers
were removed without rescue. No real credentials, OAuth, model or deployment
operation occurred. This witness does not compose the actual HeldSource storage
or the host service gate with the final Runner.

Final ordinary tests, full race (05:00 UTC), and normal/tagged vet pass after
the metadata correction. The security demo passed at 00:20 UTC before that
notification-only correction. The next work is provider auth substitution,
isolated Runner/profile and artifact wiring, then affected lifecycle/secrecy and
bounded real-path acceptance. CRED-01 and M1 remain open, the deployed path is
still `credential-exposed-personal`, and this is not a merge/release gate pass.

## Owner credential storage — 2026-09-19

The next CRED-01 component is implemented locally: a scope/proof-bound owner
borrow, exclusive of the legacy credential mount; bounded reads of the pinned
source; and compare/write/truncate/fsync/readback without replacing the enrolled
inode. Persistence failures invalidate that held source and retain its locks;
they never restore an older token group. Managed-auth parsing checks the fixed
file shape, account/subject consistency and timestamp ordering. It does not
verify OAuth or establish credential freshness. See the
[storage result and remaining integration](credential-isolation-plan.md#owner-storage-implementation--2026-09-19).

Independent internal review found and verified fixes for diagnostic formatting
leaks and a direct mount-observer bypass of the source mode. Temporary-file
tests exercise real I/O and locks with synthetic content, including partial
writes, failed sync/readback/close, stale content, replaced objects and races.
The first full race run exposed a controller regression outside the new storage
component: a certain Create failure could lose its no-dispatch proof across
cleanup failures, and online reconciliation could act on a snapshot read before
the worker completed. Six injected persistence schedules and a stale-snapshot
control failed before correction and pass after it. The controller now retains
the existing proof for a runtime-certified non-dispatch failure and re-reads
after claiming reconciliation ownership. Uncertain Create and restart fences
retain their previous semantics. The original failure cannot be uniquely
attributed to one of these two paths and remains preserved. After correction,
ordinary full tests, full race (completed at 23:16 UTC), normal/tagged vet and the
security demo pass. The local regression gate is green; this is not remote CI
or real-path acceptance.

No executable selects these new APIs. The native helper still needs a verified
refresh-result and process/recovery contract; then the provider boundary and
isolated Runner profile must be connected and accepted. This preserves the
existing control-plane design and requires no new daemon or schema. CRED-01 and
M1 remain open, and the deployed classification remains
`credential-exposed-personal`. No real credentials or deployed state changed.

## Trusted native-refresh compatibility — 2026-09-19

The [bounded native-auth probe](credential-isolation-plan.md#offline-trusted-native-refresh-result--2026-09-19)
resolved the next CRED-01 compatibility gate using fixed CLI 0.151.0 and synthetic
credentials only. Fresh and stale state refreshed, persisted and reloaded across
processes. Independent checks rejected read-only write-back, provider refusal and
a withheld response. RPC success alone was insufficient. A failed first stale
case revealed two rotations from stale startup plus forced refresh; the bounded
continuation separated those purposes without raising the request budget.

Six experiment containers were removed, including the failed case; no real
credentials, model requests or deployment changes occurred. Build/vet and internal
independent review covered the fixture; the September 17 full product regression
result retains its date and was not rerun for this testdata-only addition.

Next implement the trusted credential consumer and persistence/lifecycle contract,
then integrate owner-auth substitution and the isolated runtime profile. No
production authentication code changed in this step. CRED-01, M1, real acceptance
and the merge gate remain open; the deployed classification is still
`credential-exposed-personal`.

## Pre-dispatch recovery correction — 2026-09-17

A deterministic fault schedule reproduced a lost proof: Begin committed, but
the next read failed before any Create call; after storage recovered, the old
controller still treated the Run as uncertain. The controller now retains a
process-local proof of non-dispatch, revalidates immutable Run identity and boot,
and retries clear/stage/close/publication without Create or Lookup. Re-offered
requests first finish an existing terminal plan, preventing a lost clear response
from allowing another Create under an old proof. Unknown/foreign boots, a bound
ref, identity conflicts and process restart cannot borrow this shortcut.

Ordinary full tests, full race tests, vet, focused fault/re-offer regressions,
the security demo and existing formalpilot implementation tests passed. Internal
independent review identified and then verified closure of the re-offer issue.
The prior race failure remains retained; its exact original path was not uniquely
attributed. The current regression gate is green. No deployed state changed.

Post-dispatch removal followed by failed intent persistence still conservatively
retains its same-boot fence, as already documented by the recovery model. That
availability limit and process-loss behavior are preserved; no Store/schema or
formal-model change was introduced. Next is trusted credential refresh/write-back;
CRED-01 and M1 remain open.

## Credential substitution compatibility — 2026-09-17

The [bounded offline client probe](credential-isolation-plan.md#offline-client-compatibility-result--2026-09-17)
passed fresh, stale and persistent-401 cases through the actual fixed
ProviderCanaryLauncher/CLI. Local representations supported native tool work;
refresh updated local auth without disclosing the separately generated synthetic
owner secrets into the scanned client files/output. A first inadequate one-401
fixture failed and is retained. All four experiment containers were removed.
The owner-side upstream/refresh/persistence mechanism was simulated. No real
credentials, provider requests or deployment changes occurred, and CRED-01
remains open. Trusted refresh/write-back is the next implementation gate.

The same work package's ordinary tests and vet passed, including the tagged
fixture race check. The broader race run exposed an unresolved existing
`sandboxcontroller` uncertain-Create lifecycle assertion: cleanup remained
pending with its workspace lock retained. The isolated unchanged subtest passed
three times; that does not supersede the full-package failure. Diagnose the
pre-dispatch proof and post-cleanup persistence failure paths before extending
the production credential lifecycle. At that point the full regression gate was
not green; the later correction and verification above supersede that status,
while the broader M1 merge requirements remain open.

## Current planning baseline — 2026-09-17

The functional private Discord-to-Codex path has scoped repeat evidence: the
2026-09-16 23:43 UTC continuation completed two distinct Runs with independent
first-attempt replies, sequential containers and clean service stops. The earlier
failed repeat remains retained. This does not close credential isolation,
complete adversarial coverage, long-running operation or production acceptance.

The proposed next merge milestone is **M1: credential-isolated private path**,
including the affected native/real-path acceptance, final review and CI; see
[milestones](milestones.md) and the [CRED-01 candidate](credential-isolation-plan.md).
No isolation implementation or profile reclassification has occurred. The dated
observations and older capability summaries below retain their original scopes;
statements that the Discord Connector is absent, that only one message has ever
completed, or that the permanent-refusal wedge is still unfixed are superseded by
the later evidence above and the September 16 entries below. Other release gates
remain open. This planning update does not rerun tests or observe new host state.

Last verified: 2026-09-16 (the ingress wedge fixed, installed and witnessed on the live channel; credential rotation witnessed live: a byte-identical replacement of the enrolled object was refused and retired, and authority returned only through an explicit enrollment on a new TargetRevision; live-channel cases: two refusal classes witnessed with real platform payloads and the one-live-Run fence witnessed under real timing, after one real Discord message reached the fixed Codex target and its reply returned to the same conversation, on one host; after unattended pacing and bounded counters on the Connector's ingress path, and review-only deployment templates for a separate Discord Connector identity, after the log-redaction audit over the deployed services and restart, crash and reboot recovery under the separate service identities; repeatability, live-channel adversarial cases, real-traffic quota behaviour, credential rotation and boot activation remain open)

At **03:57–04:04 UTC on 2026-09-15**, one real message posted by the operator's
own Discord account in one private allowlisted channel produced one Run on the
fixed native Codex target and returned its reply to that same channel. The
Connector, Core and the sandbox owner ran as three separate locked system
identities from the reviewed unit templates. Core admitted exactly one Run
against the Discord binding's own immutable TargetRevision; the target wrote the
exact requested workspace marker and returned the exact expected reply; the
Connector posted one platform message, recorded its message ID and advanced its
cursor for the allowlisted channel only; the container was created and
destroyed; the credential generation was neither retired nor replaced and its
occupancy was released; earlier Run, delivery and credential history was
unchanged; and all three services stopped cleanly. This is **one message, on one
host, once.** It does not establish repeatability, resistance on a live channel,
quota behaviour under real traffic, credential rotation, concurrent or
multi-message behaviour, or production readiness, and nothing is enabled at
boot.

On **2026-09-16** credential rotation was witnessed. The enrolled auth object
was replaced at its own path by a byte-identical copy, so the credential
material was unchanged and only the kernel object differed. The next Run was
admitted and then refused at credential acquisition, and that attempt retired
its generation; no container was created, and the operator was told the request
had failed rather than left in silence. Enrolling again produced a **different
source digest** where generations 1 to 8 had all shared one, so the recorded
identity follows the object and not the bytes. Authority returned only after an
explicit operator enrollment, and only on a new TargetRevision: a revision is
permanently bound to one credential generation, so the rotated object required
advancing the revision as well. Two later Runs completed normally on the rotated
credential.

Running that witness exposed a defect in the Connector. It holds its ingress
cursor still whenever Core refuses an event, which is correct for a transient
refusal — the fence witness below shows a refused message is retried rather than
lost — and wrong for a permanent one. A message older than Core's accept window
is refused with `event_expired` forever, so it wedges the cursor and every later
message behind it. An outage longer than the accept window therefore leaves an
unattended Connector unable to admit anything until an operator intervenes. The
operator step exists and is recorded. The Connector fix now exists in code: the
two refusals that are about the event itself advance the cursor under their own
closed skip label, every other code still holds it, and the transient case keeps
a regression test because the fence witness depends on it. The same change makes
every reported counter a running total and moves the check receipt to stdout.

It was installed and witnessed on **2026-09-16**. A message was posted and left
to age past the accept window with the services stopped; on start the Connector
refused it under its own closed label, advanced past it, logged no retry at all,
created no container and admitted nothing. That witness read the Connector's own
cumulative `admitted=0`, which the previous binary could not have shown, and
which a stored Run count cannot answer either: Core compacts a terminal Run once
its inbound receipt ages past the receipt window, so the count is bounded by that
window rather than monotonic and fell from two to zero during a stage that
admitted nothing.

At **19:25 UTC on 2026-09-15**, live cases followed. Two messages were posted
seconds apart; Core refused the second with `run_in_progress` while the first
Run was live, three times at the Connector's configured backoff, and admitted it
once the first Run finished. The cursor never advanced past the refused message,
so it was re-presented rather than lost. The two containers were strictly
sequential — no second create before the first destroy — and both deliveries
succeeded on their first attempt, with both replies posted to the channel
40 seconds after the first message. Separately, a sticker and a pin system
message were each refused under their own closed label with the platform's real
payloads, admitting nothing and creating no container.

The conversation is a direct message between the operator's account and the bot.
Discord provides webhooks only on guild channels and a direct message is closed
to two accounts, so a foreign automated author and an unlisted author of any
kind are **structurally unreachable in this deployment** and keep offline
evidence only; oversize content is likewise unreachable because the platform's
own 2000-character limit binds before the protocol's 32 KiB. Multi-member
channel author filtering therefore has no live witness.

Reaching that target from Discord required its own authorization: a Discord
binding is a different six-field session scope, so the target's revision
advanced and a higher credential generation was enrolled under the new scope
from the same physical source, with the previous generation retired first. An
earlier attempt at that change failed because two configuration entries shared
one target ID: a target ID identifies one target and its revision is that
target's current immutable content, so revisions do not coexist. The local test
Connector's binding still expects the previous revision and therefore now fails
closed at revision resolution; it is a development fixture, not a standing
channel.

At **22:46–22:47 UTC on 2026-09-11**, one fake ingress event completed through three
separate locked system identities — a local test Connector, Core and the sandbox
owner — started from the reviewed `.service` templates instead of a developer
shell. The sandbox owner used its own rootless Docker runtime and private storage,
after the retained credential source was relinked into that identity's slot and
enrolled as a higher generation at its new locator, with the previous generation
retired. Core admitted one Run; the fixed native Codex target returned the exact
expected reply and wrote its exact workspace marker; one delivery completed; the
container was created and destroyed; and both services stopped cleanly. Independent
checks recorded unchanged earlier Run, delivery and credential history, no cleanup
obligations, an empty runtime inventory and the same credential object. Earlier
undelivered results stayed unclaimable by the new Connector, which can only claim
its own Runs' deliveries. This is one local witness of the documented
separate-identity path on one host. At that point boot activation, restart and
recovery under these identities, log-redaction review, the full adversarial
matrix, real refresh and Discord acceptance were all open; the recovery evidence
below followed on 2026-09-12, and nothing is enabled at boot.

On **2026-09-12**, a host reboot exercised recovery under those identities. The
tmpfiles entry recreated the setgid IPC directories and lingering restored the
sandbox user manager, while the rootless runtime stayed stopped because it is
deliberately not enabled; its pinned image survived. Both services then started
and stopped cleanly, an idle `SIGKILL` of the sandbox owner was recorded as a
signal failure whose next start retired no credential generation, and with the
runtime stopped the owner refused to serve: it exited non-zero at rootless
attestation and left no socket behind. Each check ran with no Run admitted, so
the enrolled generation, Run history and delivery history were unchanged
throughout. An earlier attempt at the last case restored the runtime about a
second after stopping it, so the owner raced past the gap; that attempt is
retained as an invalid test rather than a pass. Boot activation remains a
deliberate non-goal for now.

A recurring [log audit](../internal/logaudit/doc.go) then pinned what those
services may write. The deployed commands' entire diagnostic surface is six
reviewed strings; denied message text reaches neither an error, nor the line a
Connector would log, nor Core's retained input; and the Connector's bot token
and the platform's own error prose stay inside it, including when a token file
is rejected. Mutation checks confirm the audit fails when a new log line
appears or when both redaction layers are broken, and that
`connectorhttp.ServiceError` never serializing its cause is the load-bearing
boundary. Operator-facing fatal errors still name configuration paths and
internal failure points by design, and journald retention and permissions
remain host policy.

The [private Discord Connector](discord-connector.md) is now implemented as
code: one platform account, one allowlisted channel, no listening port, a
durable ingress cursor with bounded catch-up, self/bot/webhook filtering and
closed delivery-failure classification. It polls the platform's REST API rather
than the Gateway, so the Connector-owned cursor is the durable ingress and no
WebSocket dependency enters the module. Offline tests cover configuration
rejection, snowflake identity normalization, the skip matrix, cursor
monotonicity, advance only behind Core's acknowledgement, duplicate-send
suppression, mention suppression, token file handling and platform error
mapping, using a fake platform and Core. Its cycle also paces itself for
unattended operation: failures back off geometrically, a `429` extends the
pause to the platform's own `Retry-After` under a clamp that keeps an untrusted
header from parking the Connector, and bounded closed-label counters are
reported on change so that a Connector admitting nothing — the shape of a
platform application without the message-content intent — is visible. The complete default suite, the race
suite, vet and the security demo passed on **2026-09-11 at 23:20–23:26 UTC**.
No bot token, live channel, Connector deployment identity or real platform
request is part of that evidence, and the adversarial private-Discord cases,
the deny audit and the bake-off remain open.

The [native identity witness](../internal/localhttp/testdata/identity-witness/README.md)
passed at **04:29 UTC on 2026-09-11**. Distinct kernel UIDs inside one offline
rootless container exercised the production Unix listener/client: both intended
edges succeeded, wrong-edge groups were denied, and an outsider with both IPC
groups was disconnected byte-silently with no HTTP handler entry. Peers could
not replace sockets or access foreign private data. Each service could read its
own operator config but could not modify it; foreign config reads were denied.
All children exited and both listeners removed their sockets. Exact container
absence and empty product-managed inventory were independently verified at
**04:30 UTC**.

This increment adds only an opt-in testdata executable and documentation;
production Go code is unchanged. Focused race checks passed at **04:21 UTC**;
the final fixture build, vet, static-ELF check and host-invocation refusal passed
at **04:24 UTC**. No credential access, provider Run, host account provisioning
or security policy change occurred. This closes the isolated Linux identity
layout witness, not host service provisioning, runtime ownership, credential
transition or activation.

The [offline deployment preparation](../deploy/codex/README.md) adds fixed-input
assembly, a source/artifact manifest and inactive service identity/configuration
templates. Both daemon startup paths now support pre-provisioned `02710` socket
parents for a distinct configured peer UID; private storage remains `0700`.
No host account, service activation, credential transition or new provider Run
was part of that assembly increment. Host deployment and production acceptance
remain open; assembly is not authenticated native artifact provenance.

On **2026-09-11**, the complete default Go suite passed at **01:32 UTC**, race
and vet at **01:40 UTC**, and tagged affected-package race/vet at **01:43 UTC**.
Five Python boundary checks passed, including a new `umask 0002` case that fails
the original recipe's intermediate-directory creation and passes the corrected
explicit `0700` creation. No Go code changed after those Go checks.

At **01:44 UTC**, the final recipe produced byte-identical **422,758,400-byte**
archives from two independent source directories. Their SHA-256 was
`3b37e15456080ae8bc26002fa8aad1f6f20f6ad8b0fb46d3fec0f0e16483cc61`.
At **01:46 UTC**, independent archive/file checks and static-ELF inspection
passed. The packaged daemon's `-check` passed with no auth file, DB or socket and
unchanged fixture metadata. That fixture substituted the current test user's
runtime endpoint; it does not establish the template's separate OS identities.
Sysusers/tmpfiles dry-runs left their disposable roots unchanged, and the final
service templates passed syntax checking with only executable paths substituted
to the staged binaries. No template was installed or activated. These are local
observations, separate from CI and the earlier real-Run evidence below.

The [first ordinary-service Run](codex-daemon-startup.md#first-ordinary-service-run--2026-09-11)
passed at **00:47 UTC on 2026-09-11**. One fake event traversed ordinary `agentd`
and opt-in `sandboxd`, completed native Codex execution with a tool marker and
produced one local delivery. At **00:48 UTC**, independent observation confirmed
exact container absence, normal service exit, zero durable cleanup fences and
unchanged previous history and credential metadata. The original device-login
source and both databases were retained; generation 6 was explicitly enrolled
for the new scope after approved retirement of 5. This consumes one separately
authorized Run, not ongoing service activation. Provider HTTP details were not
exported; no real refresh, Discord or production acceptance is inferred.

The [fifth real canary](codex-provider-canary.md#fifth-real-run--2026-09-10)
passed on **2026-09-10 at 21:52–21:53 UTC** using the original dedicated device-login source
and the fixed inference media adjustment. This is one scoped real-provider
completion through the local owner. The four earlier failures below retain
their original evidence.

The subsequent [fixed Codex startup wiring](codex-daemon-startup.md) adds an
explicit `sandboxd/codex-v1` configuration behind the existing Linux/amd64
`codexintegration` build switch. The same daemon/controller now resolves one
fixed artifact/owner-bound target, supports explicit exact source enrollment,
and retains the existing idle/interrupted restart rules. `hgwctl session scope`
exports the compiled configuration scope without Core DB access. Default builds
remain mock-only. That implementation stage on **2026-09-10** executed no real
enrollment, container, provider Run, daemon deployment or Discord action; the
separately approved ordinary-service result above followed on September 11.

The final ordinary suite passed on **2026-09-10 at 22:47 UTC**. Complete default race and
tagged affected-package race suites, normal/tagged vet and the security demo
passed on the same product code. The first ordinary suite exposed a pre-existing
test wait that observed durable staging before asynchronous intent lookup; its
original safety assertions were retained and the wait corrected. Only that test
changed after the broad race runs; a 30-repeat tagged race check passed afterward.
At **22:40 UTC**, the new binary's `-check` passed with empty credential
directories, no auth file/database and unchanged fixture metadata. These are
local results, not a new CI or deployment observation.

The [2026-09-10 checkpoint assessment](checkpoint-2026-09-10.md) summarizes the
completed local work, verification limits, design/practice review and next work
package. The dated observations below remain supporting evidence.

The [runtime-owned provider canary](codex-provider-canary.md) now implements the
closed Unix/TLS operation endpoint, fixed upstream dialer, mounted socket/CA
bootstrap, joined cleanup before credential release/publication, and a separate
owner/artifact-bound opt-in pin. Offline Core/native completion with replay and
removal failure passed at **00:37–00:39 UTC**, cancellation at **00:45–00:47 UTC**,
and owner SIGKILL/recovery at **00:49–00:52 UTC** on 2026-09-10. The first armed
canary attempt at **02:13 UTC** failed the local Connector-directory policy
before any database, enrollment, runtime or provider operation. Its placeholder
socket now has a separate directory, and preflight compiles the same Core
configuration before reporting readiness. The focused regression failed before
the fix and passed afterward with race checks and vet. The continuation at
**02:30–02:31 UTC** enrolled one dedicated real source, admitted one Run and
started its native runtime, but ended in `runner_failed` without the marker.
Exact container absence and zero credential/workspace/result fences were
independently verified. The failed local delivery remains pending for evidence.
Provider operation/status details were not retained, so authenticated catalog,
inference and tool completion were not established by that Run. Both attempts are retained.
Subsequent offline checks on **2026-09-10** verify bounded operation/stage/status
snapshots in the private canary result and fixed native/relay failure separation.
These observations do not change cleanup authority or explain the earlier Run;
no further real Run was executed during that diagnostic implementation stage.
See the canary's diagnostic evidence limits.

The tagged local owner now supports an explicitly approved continuation in the
retained state root: it pins predecessor history and database objects, preserves
the enrolled source, uses the next local generation and isolates the new test's
delivery. Synthetic interruption/recovery and admission tests, tagged race/vet and
the security demo passed on **2026-09-10**. No real generation transition or second
Run was executed during this preparation; this does not enable a normal daemon
or public messaging path. See [continuation boundaries](codex-provider-canary.md#explicit-continuation-preparation--2026-09-10).

A separately approved continuation at **04:51–04:52 UTC** then retired the first
local generation, enrolled the next generation for the same source/proof and
admitted one new Run. It failed with `Codex native process failed`, without a
marker. Bounded diagnostics recorded two completed catalog exchanges with HTTP
200, one local settings response and thirteen inference exchanges with upstream
HTTP 200 rejected at `upstream_policy`. The exact response predicate is unknown;
neither authentication nor inference completion is established by these statuses.
At **04:53–04:54 UTC**, exact container absence, process exit and zero durable
cleanup fences were independently verified. Both failed Runs and pending results
remain retained. The consumed plan now rejects another execution. See the
[second Run's scope](codex-provider-canary.md#second-real-run--2026-09-10).
At that 04:53–04:54 observation, daemon configuration was mock-only; public Discord and production
deployment remain disabled.

The subsequent [response-rejection work package](codex-provider-canary.md#actionable-rejection-and-bounded-failure-handling--2026-09-10)
now implements closed predicate/media diagnostics and operation-scoped blocking
at upstream dispatch authorization. That work package preserved response acceptance,
other operations, transient/status behavior and joined cleanup. Its implementation
and read-only preparation did not explain the earlier response predicate or
execute another Run.

The third separately authorized Run at **07:08 UTC** then failed without a
marker. One authorized inference received HTTP 200 with an empty/missing
Content-Type (`content_type_missing`); twelve later inference requests were
denied locally without new upstream authorization. Two catalog exchanges
completed with JSON media and HTTP 200, and settings stayed local. At
**07:11–07:12 UTC**, independent observations confirmed exact container absence,
process exit, zero durable cleanup fences and the same source/proof across
generations 1–3. All three failed Runs and pending deliveries remain retained.
The consumed plan rejects reuse. This demonstrates bounded rejection handling,
not inference acceptance or a diagnosis of the earlier Runs. See
[the third Run's evidence and limits](codex-provider-canary.md#third-real-run--2026-09-10).

The subsequent [response-contract investigation](codex-provider-canary.md#response-contract-investigation--2026-09-10)
verifies complete synthetic Lite request forwarding through both HTTP/TLS hops.
Existing fixed-native SSE evidence does not support inferring incompatibility
from the Lite name. The endpoint now distinguishes closed response-field and
framing metadata and samples a rejected HTTP-200 MIME response only after
blocking further operation dispatch, within 512 bytes and one second. No raw
body is retained and that investigation did not relax response policy. The
third Run lacks these observations; its upstream cause remains unknown.

The [fourth separately authorized Run](codex-provider-canary.md#fourth-real-run--2026-09-10)
at **08:37–08:38 UTC** used the same dedicated device-code-login source and
failed without its marker. One inference returned HTTP/1.1 200 with an absent
Content-Type field and chunked framing. Its bounded probe read 512 decoded
bytes with an `event_stream_like` prefix, then ended at the byte limit. This
establishes a nonempty response with an SSE-like prefix, not a valid complete
event stream or model success. Twelve later inference requests were denied
locally without new dispatch grants. At **08:39–08:40 UTC**, independent checks
confirmed exact cleanup, unchanged credential metadata and equal source/proof
across generations 1–4. All four failed Runs and pending deliveries remain
retained; the consumed plan rejects reuse. That Run made no compatibility
change and did not explain the earlier Runs' narrower observations.

The subsequent [local compatibility decision](codex-provider-canary.md#absent-inference-media-compatibility--2026-09-10)
now supplies SSE media only for HTTP 200 on the fixed inference route when the
Content-Type field is genuinely absent. Explicit empty/invalid/wrong types,
catalog/refresh JSON requirements and other transport/authority limits retain
their behavior. Observed field-presence metadata remains separate from the
effective media class; no body-prefix hint grants acceptance. Raw TLS tests
cover byte preservation, framing, budgets and cancellation. At **09:10 UTC**, a
single offline native container completed valid SSE and rejected plain JSON
and incomplete SSE before its deadlines, with one inference per case and joined
cleanup. A new continuation passed default read-only preflight at **09:14 UTC**
with unchanged retained state and original device-login credential metadata.
That preparation executed no fifth Run; the separately authorized result follows.

At **21:52:38–21:53:08 UTC**, the fifth Run completed in 30.014 seconds, with
owner exit 0, the expected native reply and independently verified tool marker.
Two catalog responses completed with JSON; two inference responses returned
HTTP 200 with absent Content-Type and chunked framing, mapped to effective SSE.
Their final transport stages were `complete` and `response_write`; the latter's
write-ending reason is unrecorded. No refresh or MIME rejection was observed.
At **21:53–21:57 UTC**, exact container absence, process exit, zero durable
cleanup fences and one completed local delivery were independently checked.
All five generations share the same source/complete proof; credential metadata
was unchanged. The four earlier Runs/deliveries remain intact, and the consumed
fifth plan rejects reuse. This does not enable public messaging or production.

Credential identity/proof storage, enrolled-target pin composition, authoritative
Run re-open, ordered held-lock release and controller startup retirement are
implemented with synthetic tests. A tagged offline V3 fixture now connects
native enrollment, the actual service/controller, Docker handoff/bootstrap,
HRP and ordered cleanup/publication; its local 2026-09-09 10:24 UTC case passed.
Subsequent same-UID Core/Connector fixtures passed focused native faults at
10:53–10:56 UTC and two separate-owner SIGKILL/restart cases at 11:32–11:35 UTC.
Fixed resistant-descendant cleanup passed at 19:54 UTC and native held-tool
deadline at 20:12 UTC, with two earlier deadline-fixture failures retained.
Permanent credential admission feedback passed the service/HTTP/Core path at
20:28 UTC: fixed policy denial after exact Run absence, without waiting for its
deadline; existing/uncertain Runs retain their observation path.
The opt-in canary supplies a local enrollment caller and fixed candidate
resolution. The canaries above exercised an initial real-source enrollment,
same-source generation transitions and runtime handoffs; complete production
acceptance remains open. The subsequent fixed daemon configuration is now wired;
offline checks alone
confer no authority for real credential use.
Earlier live observations retain their own dates and evidence limits.

Release posture: **research prototype / pre-alpha**

The control plane, durable authorization path, sandbox lifecycle, mock Runner,
and offline security witness are implemented. Three sealed but blocked
`new_only` Codex behavior contracts are present: unchanged v1 has no added
model context, while v2 maps one fixed private-messaging behavior profile to
Codex's developer-instruction layer. V3 preserves that messaging behavior and
adds a pinned native tool package, fixed configuration and startup checks.
A non-executable candidate manifest and
offline preflight are present; no approved Codex image or executable target is
shipped and the default build omits its entrypoint. There is no public Discord
Connector, approved production Codex target, or production deployment. The
project therefore does not yet demonstrate a secure Discord-to-Codex path.

This document is the public source of truth for what is implemented, what is
only represented in code, and what remains work in progress.

## Status at a glance

| Capability | State | Evidence boundary |
| --- | --- | --- |
| Strict Connector and execution protocols | Implemented | Bounded JSON, closed enums, unknown-field rejection, protocol tests |
| Exact Binding authorization | Implemented | Exact Connector/actor/conversation tuple selects one immutable target revision |
| Durable Run, replay, dispatch, and outbox state | Implemented | SQLite schema v7, migration/reopen/failure-injection tests |
| Sandbox target and runtime lifecycle | Mock path and opt-in fixed Codex startup implemented | Immutable manifests, rootless-runtime attestation logic, create-intent reconciliation, and lifecycle tests; the live rootless-Docker observation is local evidence, not public CI |
| Post-cleanup terminal publication | Implemented and fault-tested; focused native and adversarial container witnesses | Sandbox schema v8 stages outcomes privately; exact cleanup precedes publication/unlock. On 2026-09-09, a fixed TERM-resistant/`setsid` Runner passed at 19:54 UTC and native deadline at 20:12 UTC; full native-launcher descendant matrix remains open; [scope](codex-control-boundary.md#deadline-and-resistant-descendant-witnesses) |
| Runner-state v2 local mock path | Implemented and locally tested | Explicit `sandboxd/v3`, immutable version-aware target carrier, sandbox schema v9, conditional state mounts, real mock-process and fake-runtime recovery tests; no live Docker/provider claim |
| Credential generation and occupancy | Implemented; explicit enrollment exercised through the opt-in fixed Codex executable | Sandbox schema v10, immutable records, one-way revocation, atomic admission/release and recovery tests; real-source canary transitions on 2026-09-10 and one explicitly maintained transition followed by ordinary enrollment/Run on 2026-09-11; no generic rotation CLI |
| Atomic credential proof registration | Implemented and tested; dedicated-source enrollment observed | Sandbox schema v11, immutable atomic proof, exact replay, no backfill/downgrade and store failure/concurrency tests; canaries on 2026-09-10 and ordinary enrollment/Run on 2026-09-11 used the same dedicated source, not production enrollment/rotation acceptance |
| Enrolled credential target pin | Integrated into sandboxservice; canary and ordinary-service bindings observed | Database-derived generation/proof, independently approved exact scope and atomic whole-batch registration; the 2026-09-11 daemon witness leaves complete production authority acceptance open |
| Trusted target resolution | One frozen resolver per entry; default mocks and explicit fixed Codex factory | Compiled-policy scope export, manifest/scope consistency, unchanged legacy mock pins and distinct owner/artifact-bound daemon authority; configuration/restart tests and one scoped ordinary-service real Run on 2026-09-11 |
| Credential startup recovery | Integrated with synthetic authority; two native owner-restart cases passed on 2026-09-09 at 11:32–11:35 UTC | SIGKILL with bound running runtime or existing unbound Create, retirement before failed inspection, retained occupancy/staged result, exact healthy cleanup and one Core interruption; no execution-source reopen/recreate. Same-boot tagged fixture, not host reboot or delayed absent Create; [scope](codex-control-boundary.md#native-owner-crash-and-recovery-witnesses) |
| Credential Run re-open/release | Integrated through the opt-in fixed startup and existing controller option | Run-derived proof/scope, acquisition-once and retained authority on failure; tagged native controller fixture observes the physical lock through removal and its release before publication |
| Local held credential file | Linux primitive with controller and opaque runtime consumers | Descriptor pinning, advisory locks, replacement rejection and one-Create copy-safe handoff; one dedicated real-source handoff observed in the failed 2026-09-10 canary; no generic path/FD accessor |
| Credential identity/proof | Linux/amd64 native-ext4 adapter with Run comparison integration | Canonical UUID/export-handle digests and root/slot/locator pins; synthetic witnesses and one real-source enrollment in the failed 2026-09-10 canary; production enrollment/rotation acceptance remains open |
| Credential mounted-object bootstrap | Implemented component and controller-owned Docker consumer | Six local component cases plus the 10:24 UTC integrated witness on 2026-09-09; local peer/PID view, applied policy, UID/GID/capability and mounted-object verification before permit; [scope](codex-control-boundary.md#controller-owned-synthetic-v3-witness) |
| Bounded synthetic provider consumer | Implemented and locally tested on 2026-09-09 | One-use HTTP/1.1 consumer, request/stream budgets and cancellation/cleanup fault tests; composed with the controller's V3 fixture, no real upstream or production transport separation |
| Built-in ChatGPT operation inventory | Offline fresh/refresh native `exec` passed on 2026-09-09 21:04–21:05 UTC | Synthetic file auth and refresh persistence; default paths, WebSocket attempts and zstd HTTP fallback observed; no real provider or production allowlist; see [inventory and next decision](codex-provider-operations.md) |
| Fixed subscription HTTPS/SSE candidate | Offline fresh/refresh native `exec` passed on 2026-09-09 21:24 UTC | Separate custom-provider overlay, uncompressed JSON and zero observed upgrades; refreshed token persisted and used; header differences and real-server/tool compatibility remain gates; V3 unchanged |
| HTTPS consumer/native-tool composition | Offline pass on 2026-09-09 22:05 UTC | One refresh and two real strict-consumer dispatches, native Code Mode command and independent result, positive controls, connection/FD/owner-procfs checks and cleanup; child PID and ancestor procfs views explicitly distinguished. Temporary synthetic auth, tagged runtime restrictions; production binding remains blocked; [scope and next integration](codex-provider-operations.md#offline-integrated-boundary) |
| HTTPS through Core/controller lifecycle | Three offline cases passed on 2026-09-09 22:49–22:54 UTC | Exact mounted synthetic file refreshed in place through the existing held-source/bootstrap; completion/replay/removal failure, held-tool cancellation and owner recovery each ended in one scoped Core delivery after cleanup. Recovery reopened no credentials and created/attached no runtime. Tagged fixtures only; [scope, failures and next contract decision](codex-provider-operations.md#offline-controller-lifecycle) |
| Fixed provider byte relay | Linux component and local HTTPS/owner-loss composition implemented on 2026-09-09 | Pinned Unix socket object, concrete peer UID, loopback-only ingress, byte/connection/deadline bounds and joined cleanup. Endpoint/TLS ownership stays in the existing runtime-owner design. The tagged canary and fixed daemon factory supply controller lifetime hooks, a fixed upstream dialer and distinct authority pins; [design and scope](codex-provider-canary.md) |
| Fixed channel in native container | Two offline cases passed on 2026-09-09 23:58–23:59 UTC | Read-only socket identity and peer UID mapping, fake refresh/tool completion, TCP/Unix denial and protected-object non-inheritance; owner loss yields harness failure before deadline and a joined failed relay. Standalone driver, with exact cleanup; this standalone witness did not establish controller/held-credential integration; the dated canary above covers that subsequent work. Scoped procfs/control limits and retained startup failures: [native acceptance](codex-provider-transport.md#offline-native-channel-acceptance) |
| Synthetic V3 controller composition | One scoped local pass on 2026-09-09 at 10:24 UTC | Actual service/controller/Docker/HRP, one Create/Attach despite receipt replay, native command/readback, exact removal while locked and close before publication. Tagged fixture only; no Core/Connector path or approved production image; [scope](codex-control-boundary.md#controller-owned-synthetic-v3-witness) |
| Core ingress through synthetic V3 | Three focused local cases passed on 2026-09-09 at 10:53–10:56 UTC | Real Connector/execution HTTP over peer-authenticated Unix sockets, compiled exact Binding, Core dispatch/outbox and native controller consumer; source replacement denied before Create, lost Start reply recovered without duplicate Create, removal failure withheld output, held-tool cancellation cleaned up before delivery. Same-UID tagged fixture with an offline responder; [scope and remaining matrix](codex-control-boundary.md#core-ingress-and-focused-native-fault-witnesses) |
| Scoped opaque-session lifecycle | Implemented for the mock path | One-use references, age/turn bounds, exact-scope fences, reset and migration tests |
| Offline security witness | Implemented | Production decoder/policy/service/Core store with synthetic input; no network or credentials |
| Codex HRP/1 adapter | Implemented and unit-tested for the first `new_only` cut; not shipped as a target | Translation and failure-redaction tests; no image or accepted runtime profile |
| Codex native tool-network prerequisite | Opt-in canary implemented; local primitive witness only | Pinned CLI helper, positive control and IPv4/IPv6 TCP/UDP socket denial; this primitive alone does not prove full tool `exec` or production image/provider mediation; see [canary scope](codex-network-canary.md) |
| Codex synthetic exec integration | All five native cases passed in an offline guest on 2026-09-08; separate wrapper error retained | Exact adapter/launcher/CLI completion, network denial and positive control, provider-wait and held-tool cancellation; temporary guest compatibility profile, no-catalog tool gap and production gates remain; see [integration scope](codex-exec-integration.md) |
| Codex Profile v1 contract | Sealed but blocked; not accepted by the runtime | Exact CLI/model/auth/state/network/context/teardown semantics and stable contract fingerprint; live gates remain failed closed |
| Codex Profile v2 contract | Sealed but blocked; not accepted by the runtime | Fixed content-hashed private-messaging behavior at the developer layer; distinct adapter identity; no additional authority |
| Codex Profile v3 tool package | Template/startup guard and opt-in fixed daemon configuration implemented | Exact six-file package, host/one-agent capacity evidence, offline-guest file-write/command-exec, native IP network pair and running-tool cancellation passes; earlier failures retained, production image/ownership gates open; see [V3 scope](codex-profile-v3.md) |
| Offline Codex candidate check | Implemented, always execution-blocked | Total profile/target matching, closed local binding, non-authorizing digest, explicit model/tool compatibility blocker, opt-in metadata inspection and subprocess tests; no secret reads, leases or resolved runtime policy |
| Real Codex target | No approved production target; canary, ordinary-service, separate-identity and one live-message witness passed | The fifth canary passed on 2026-09-10, one ordinary-service Run with fake ingress on 2026-09-11 at 00:47 UTC, one Run through three separate service identities at 22:46 UTC the same day, and one Run from a real Discord message on 2026-09-15 at 03:57–04:04 UTC; native reply/tool marker/delivery and independent cleanup verified each time. Four earlier failures retained; repeatability, production image/auth/network/context gates remain open |
| Discord Connector | Deployed under its own identity; one real message delivered end to end | REST-polling ingress with a durable per-channel cursor, stable-ID allowlist, self/bot/webhook filtering, bounded catch-up, mention-suppressed replies, duplicate-send suppression, closed failure classes and rate-limit-aware pacing, with no listening port. Live Runs on one host on 2026-09-15 and 2026-09-16, including the one-live-Run fence, two refusal classes under real platform payloads and a credential rotation refused and re-enrolled; multi-member channel filtering has no live witness, real-traffic quota calibration remains open, and a permanently refused event wedges the ingress cursor |
| Production security | Not claimed | Deployment identities, credentials, egress, cancellation, and live-path evidence remain open |

## Implemented control plane

### Ingress and admission

- `connectorwire` defines the small, versioned Connector contract. V1 admits
  text input and a closed action vocabulary; recognized control actions remain
  unsupported rather than being interpreted as arbitrary commands.
- `agentpolicy` compiles an operator-authored, exact Binding from one Connector,
  actor, and conversation to one immutable target revision.
- `agentservice` validates the event, applies the Binding, and linearizes an
  accepted request into a durable Run. Event replay is content-bound:
  byte-equivalent replay returns the original receipt, while a conflicting
  payload under the same retained event ID is rejected.
- Core persists the Binding and policy fingerprints used at admission. Later
  dispatch cannot silently substitute a target or broaden authority.

### Run and delivery lifecycle

- Core SQLite state owns durable Runs, dispatch leases, exact session scope,
  and Connector-scoped outbound delivery.
- `agentdispatch` recovers queued work, freezes the sandbox start request, and
  advances only through compare-protected transitions.
- Outbound recipients derive from the accepted Run. Runner output supplies
  content but cannot choose a Connector or conversation.
- A nonterminal-Run fence serializes each exact authorization/session scope.

### Sandbox and runtime boundary

- `sandboxd` accepts a closed execution request over a private Unix socket and
  verifies the peer UID at connection time.
- Target manifests fix the runner family, adapter version, protocol, image
  digest, workspace, session policy, limits, and profiles. The execution wire
  cannot override those values.
- The separate `harness-target/v2` data contract expresses no persistent Runner
  state or one logical persistent state ref. It has an independent hash domain
  and exact field-name validation; historical v1 bytes remain pinned. Explicit
  `sandboxd/v3` admits the locked-down mock through one version-aware execution
  path; `sandboxd/v2` still rejects v2. Schema v9 durably distinguishes no state
  from missing ownership, and only persistent state receives a mount. A fixed
  new-only mock artifact is tested as a real child process. See
  [Target manifests](target-manifest.md).
- The Docker runtime adapter emits fixed `argv`, uses rootless-runtime
  attestation, and never exposes the runtime socket to the Runner.
- A durable create intent precedes the external create. If the result is
  uncertain, reconciliation uses immutable labels and identity; it does not
  issue a speculative second create.
- Every controller terminal outcome is staged privately in sandbox schema v8.
  Public status and events remain nonterminal until trusted cleanup succeeds.
  One sandbox transaction then publishes the outcome and successor session,
  clears the runtime reference, and releases the writer lock. Core observes
  that result and commits its own terminal/outbox transaction separately.
  Fault tests cover cleanup failure, lost staging responses, late publication
  rollback, database reopen, and preservation of the original outcome without
  re-executing the harness. These are controller/store tests with a fake
  runtime, not proof of actual detached-descendant containment.
  A two-store integration test additionally verifies that Core creates no
  session or delivery before sandbox publication and exactly one delivery
  when it subsequently observes that publication, even after a deadline.
- Sandbox schema v10 adds durable credential generation, revocation and Run
  occupancy to that same transaction boundary. Synthetic tests exercise these
  transactions; the 2026-09-10 canary separately enrolled one dedicated real
  source. Historical targets remain credential-free; candidate checking,
  executable configuration and the Docker profile gate gain no new authority.
  See [credential source lifecycle](credential-source-lifecycle.md) for the
  implemented ordering and remaining physical-source/refresh requirements.
- Schema v11 stores proof in the immutable generation row. Source ownership,
  generation and proof register in one transaction; read-back and replay retain
  the exact pair even after revocation. Proofless synthetic history remains
  explicit and cannot acquire proof in place. Schema guards and reopen checks
  reject malformed/partial proofs. The failed 2026-09-10 canary exercised one
  real held-source enrollment; production enrollment remains unavailable.
- Strict enrolled-target registration reads that immutable generation/proof,
  compares independently approved workspace/auth/disclosure scope and composes
  all credential authority into a new durable target pin in the same transaction.
  Replay, rotation and mixed-batch rollback are tested; credential-free pins and
  legacy synthetic registration remain unchanged. sandboxservice now uses this
  strict path for every registry. Its single startup resolver supplies the base
  pin, explicit state ownership and optional independently approved credential
  scope; the service derives workspace/auth from the matching manifest. The
  compiled ingress policy can project the exact six-field scope without taking
  a request digest or reading enrollment. Default sandboxd uses the unified mock
  resolver, which rejects unsupported profiles before registration, including v1.
  The opt-in fixed daemon path separately verifies artifact/owner/provider
  authority and binds the configured enrolled scope. The canary has exercised
  a real-source binding; the new daemon has deterministic startup/recovery tests
  and one scoped real Run with fake ingress on 2026-09-11.
  Complete production acceptance remains open; a composed hash alone cannot
  establish it.
- Under the daemon's existing exclusive process lock, controller startup revokes
  generations referenced by retained credential occupancy in one transaction.
  Failure blocks startup before runtime recovery or new work. Old accepted
  credential Runs become cleanup-only; staged outcomes and uncertain intent
  authority are retained until exact cleanup and atomic publication/release.
  Store opens, background reconciliation, shutdown and idle generations do not
  trigger blanket retirement. Constructor/store fault tests use synthetic
  authority and fake runtimes, without new schema or real credential access.
  Two tagged native restart cases also exercise this order with an actual
  killed controller-owner process. Its physical source lock disappears on death;
  durable occupancy and retirement retain the cleanup fence until exact removal.
- The Linux held-file primitive provides process-local pinning and revalidation.
  Its controller consumer now reads the admitted Run's unrevoked generation and
  proof in one transaction, compares frozen scope/binding values, then holds and
  verifies the native source. Duplicate offers cannot acquire again. Validation
  runs before Create/AttachStart and after cleanup; failures retire only that
  Run's occupied generation. Reconciliation retains handles until revocation,
  runtime cleanup and physical close precede durable publication/release.
  Close failure stays latched until process restart recovery. Publication failure
  or response loss cannot reopen the credential or leave a stale volatile fence.
  Fault tests use constructed proof and a private handle seam. A separate tagged
  native fixture uses real Hold/proof, service admission, Docker and HRP, and
  observes physical lock ordering. The opt-in fixed daemon now supplies the
  same bindings; one ordinary-service Run with the dedicated real source passed
  on 2026-09-11. It adds a completion/cleanup witness, not the entire physical
  fault matrix. Earlier real-source observations retain their limited scope.
- The [credential enrollment contract](credential-source-enrollment.md) selects
  native-ext4 UUID/export-handle identity, immutable object/locator proof and
  conservative retirement after interrupted credential Runs. The isolated
  CaptureProof/VerifyProof adapter now implements digest collection/comparison,
  with synthetic held-file tests and a local native-ext4 backend test.
  Controller Run re-open and held-lock release now consume this boundary, but
  observations alone grant no runtime mount or complete target authority.
- The sandbox session mechanism stores synthetic mock session tokens only in
  sandbox state. Core sees opaque, exact-scope, one-use references with
  target-authored age and turn limits. A real provider-token boundary remains
  unproved.

## Security witness

`make demo-security` uses the production strict decoder, compiled policy,
`agentservice`, and Core SQLite store. It verifies:

1. request-supplied target fields and arbitrary actions are rejected;
2. a recognized but unsupported target-selection action creates no Run;
3. a non-exact actor/conversation tuple creates no Run;
4. an accepted queued Run and its immutable Binding evidence survive exact
   child-process `SIGKILL` and database reopen; and
5. exact replay deduplicates while conflicting replay is rejected without a
   replacement Run.

The child receives an empty environment. The witness does not start Docker,
open a network listener, contact Discord or a model provider, or read provider
credentials. It is intentionally not evidence for container isolation,
credential safety, whole-system crash recovery, or formal verification.

## Codex adapter and profile: present but not wired into a target

`internal/codexadapter` and `cmd/codex-runner` implement the first closed
`new_only` HRP/1 translation cut. The adapter:

- requires the sealed `gpt-5.6-sol` model alias and `medium` reasoning effort;
- constructs a fixed Codex invocation rather than accepting message-selected
  options;
- accepts only the closed terminal event needed by the outer protocol;
- bounds and redacts provider output and failures; and
- rejects resume, non-text input, and unsupported profiles.

`internal/codexprofile` seals the candidate CLI 0.151.0 artifact digest,
model/effort, profile-ref projection, single-file ChatGPT credential mechanism,
disposable state, mediated-control-only network claim, empty customization
allow-set, and post-quiescence output rule. The concrete local credential slot
is deliberately unresolved and excluded. Its contract fingerprint is pinned in
code and every contract field is fingerprint-relevant. This is configuration
evidence, not runtime evidence: the current Docker profile gate still rejects
the expressible Codex projection before any CLI call. See
`codex-profile-v1.md`.

The separate v2 contract preserves that authority envelope and adds one exact,
content-hashed private-messaging behavior profile. `codexadapter.MessagingConfig`
maps it to the documented `developer_instructions` config key, while the
untrusted user message remains byte-exact stdin and absent from argv/env. It
reports adapter `0.2.0-new-only`, so a future manifest cannot confuse it with
the context-free v1 behavior. Unit tests pin both contract fingerprints, the
fixed instruction bytes, the native role mapping, and pre-readiness rejection
of unknown profiles. An opt-in exact-CLI canary additionally checks byte-exact
developer/user role placement and absence of three hostile workspace-file
sentinels under an empty home. The debug subcommand cannot accept two
exec-only ignore flags, so that canary is decoding/placement evidence rather
than complete exec or provider-context closure. See `codex-profile-v2.md`.
This is model-behavior configuration, not prompt-injection protection or an
authorization boundary.

The tagged [synthetic exec fixture](codex-exec-integration.md) observed the full
local text path on 2026-09-08, including native request role placement and
precreated final-file consumption. Its no-catalog baseline had an empty
top-level tools array; that alone did not establish complete tool absence.
The explicit synthetic direct-mode catalog is only a lab delta. A same-day
exact-binary `debug models --bundled` check identified `code_mode_only` for
`gpt-5.6-sol`, conflicting with V1/V2's disabled Code Mode host. The
offline candidate reports `model_tool_compatibility`. V1/V2 remain unchanged;
the separate [V3 template](codex-profile-v3.md), added on 2026-09-09, pins and
configures the native host and checks package integrity before readiness.
Its canary reads native `input.additional_tools` and exercises actual results.
Host execution and one-agent capacity have component evidence. File writing
failed at the workstation's nested AppArmor boundary; a separate offline guest
passed the file-write subcase on 2026-09-09 04:23 UTC with a temporary guest
compatibility profile and a read-only package owned by the mapped test UID. Exact nonce
contents, two synthetic requests, V3 completion and quiescence passed; wrapper,
policy cleanup, domain teardown and evidence collection also passed separately.
On **2026-09-09 05:00 UTC**, a fresh guest passed only the native `command-exec`
subcase using the same offline recipe. A fixed probe's stdout/stderr, deliberate
exit 17, independent nonce file, CWD, UID 1001, `NoNewPrivs=1`, zero effective
capabilities and absent synthetic provider environment key were checked. The
outer V3 Run completed after two synthetic requests with no remaining
descendants; wrapper, policy cleanup, domain teardown and collection passed.
This adds command completion evidence, not new-package network, cancellation,
real-credential or production acceptance. Neither file-write nor the older
five direct-catalog cases was rerun for that check.
On **2026-09-09 05:28 UTC**, a separate fresh guest passed only the V3 network
allow/deny pair. In the control, a native tool reached the same listener used
by client inference once; in the denied case it returned `EPERM` with zero
probe hits while client inference still worked. IPv4/IPv6 TCP/UDP socket
creation succeeded in the control and returned `EPERM` under the unchanged
deny configuration. Each case had two synthetic requests, an independently
checked nonce file, V3 completion and descendant quiescence; all five result
axes passed. The control changed one test invocation network bit inside the
offline guest. Unix sockets, inherited FDs, provider mediation and cancellation
remain outside this witness; it does not enable a runtime target.
On **2026-09-09 05:55 UTC**, another fresh guest passed only V3 `command-cancel`.
The actual Code Mode tool held a parent-created lock and wrote an exact nonce
receipt; independent lock contention preceded cancellation. One synthetic
request and the sole V3 cancelled terminal at sequence 2 were observed. The
leader was reaped, all namespace descendants were gone and the original lock
was available before workspace/namespace teardown, in 5 ms on this run. All
five result axes passed. This is one running-tool cancellation witness;
timeout variants, detached descendants and exact-image cleanup before terminal
publication remain open. No earlier native case was rerun.
Earlier precondition failures remain retained. Workstation/server-host policy
and the product ownership guard were unchanged; production image composition
is still unverified. Bundled metadata does not establish the authenticated provider's
catalog, and V3 does not enable a runtime target. The earlier complete
tool/positive-control/held-lock cancellation fixture initially failed at nested
sandbox startup. A later same-day
minimal control and kernel journal identified the observed host's enforcing
AppArmor child capability restriction; no host policy was relaxed.
A subsequent fresh offline Ubuntu guest also failed the outer startup
preflight before any native case: retained logs show `unprivileged_userns`
denying `setpcap` and `net_admin`. That guest was shut down and its transient
domain removed. Binary/dependency checks alone did not establish a compatible
test-runtime namespace policy.
At 23:21 UTC, an authorized offline guest run reproduced the original refusal,
loaded a temporary exact-path bwrap compatibility exception and passed the
unprofiled refusal and nested/native startup controls. The unchanged static
fixture passed all five cases, including strict tool `EPERM`, the same-endpoint
positive control and held-lock cancellation. This is not a guest race result
or a production policy approval; no host security configuration changed.
The separate guest wrapper reported an error and lost its final serial summary.
Read-only disk extraction recovered the native exit 0 and complete results;
profile snapshots/kernel events verify profile removal, the generic policy hash
is unchanged and the transient VM is absent. The failed wrapper receipt remains
explicit. A local durable-log correction passed output-fault checks but has
not been executed in a guest; final live sysctl values were not independently
retained. See the integration scope for that limitation and dated evidence.
Cancellation during an active provider request did return the sole cancelled
terminal, close the connection and leave no namespace descendants before
outer teardown.
`ExecLauncher` now preserves empty invocation environments and bounds
inherited-pipe drain after leader exit; this does not prove descendant
quiescence or replace the outer runtime's release rule.

The repository ships no approved production Codex Runner image/target, and
`make build` does not produce `cmd/codex-runner`. Enabling a real path therefore
requires explicit reviewed artifacts and target authority; placeholder examples
cannot activate it. The profile also requires no persistent
Runner `/state`, which no valid v1 manifest can express. The v3 local mock
path now integrates TargetManifest v2, explicit ownership kind and conditional
mounts, but its mock schemas reject Codex. The separate opt-in fixed daemon
schema now supplies checked runtime construction; complete production
provider-profile acceptance remains open.
The separate tagged canary now supplies fixed credential/network runtime
construction and local enrollment, with one scoped real-provider completion
on 2026-09-10; it is not the production resolver.
Context, credential, network, cancellation, and teardown gates remain open,
including proof that repository-level, system, or managed customization cannot
enter the harness unexpectedly.

`codexprofile.Contract.MatchTarget` and `internal/codexcandidate` now implement
the offline subset: full sealed-profile matching against TargetManifest v2,
one closed local workspace/credential binding, a prefixed configuration digest
and optional metadata-only inspection. `hgwctl codex check` always reports
`blocked` and exits 3 for valid configuration; it does not load sandboxd's
config, register authority, open Core state or invoke a runtime. The public
candidate example has a placeholder image digest. Matching metadata cannot
validate auth, prevent races or supply executable mediation content. See
[the preflight contract and usage](codex-candidate-preflight.md).

## Open gates

The [content evolution and verification contract](content-evolution-and-verification.md)
was adopted on 2026-09-09. It defines typed-content extension boundaries and
change-specific evidence reuse; current protocols remain text-only and no media
implementation or real-target gate is completed by that decision.

The [live-path delivery plan](codex-live-path-plan.md), first reviewed on
2026-09-09 and updated on 2026-09-10, maps the eight candidate blockers to code
and evidence. Its synthetic delivery unit now connects provider control,
enrolled credential handoff and the fixed V3 runtime under fake ingress, with
the scoped evidence below. The subsequent
[response rejection and bounded failure handling](codex-provider-canary.md#actionable-rejection-and-bounded-failure-handling--2026-09-10)
package now has a real-Run witness for precise rejection and suppression of
later same-operation dispatch; response-contract compatibility remains an open
gate.
The [provider-control/credential-delivery decision](codex-control-boundary.md)
defines a bounded synthetic Responses consumer and a pre-execution mounted-object
gate. The verifier/bootstrap component has six passing local rootless cases
with synthetic files and a fixed synthetic successor. The bounded Responses
handler now has in-memory HTTP and lifetime/cleanup-fault evidence. The
[first combined rootless case](codex-control-boundary.md#first-composed-case-namespace-creation-rejected)
at **2026-09-09 08:16 UTC** passed mounted-source verification and dispatched two
native Responses requests, but failed native command execution at nested
namespace creation. Exact container removal and subsequent source unlock passed.
The [scoped compatibility follow-up](codex-control-boundary.md#runtime-diagnosis-and-passing-scoped-compatibility-case)
at **09:04 UTC** passed using a container-local seccomp profile and fixed UID
setup that preserved source ownership and cleared all capabilities before the
existing bootstrap gate. Native command/readback, quiescence and ordered cleanup
passed. This fixture does not approve the startup template for production.
The [controller-owned follow-up](codex-control-boundary.md#controller-owned-synthetic-v3-witness)
at **10:24 UTC** bound the fixture artifacts/policy into synthetic authority and
passed native enrollment, service/controller/Docker handoff, HRP and ordered
cleanup/publication. At **10:53–10:56 UTC**, the
[Core ingress follow-up](codex-control-boundary.md#core-ingress-and-focused-native-fault-witnesses)
passed source replacement denial, lost-reply/repeated-cleanup-failure recovery
and cancellation of a live native tool, through the real local HTTP interfaces
to one scoped outbox delivery. At **11:32–11:35 UTC**,
[native owner recovery](codex-control-boundary.md#native-owner-crash-and-recovery-witnesses)
passed SIGKILL with a bound runtime and with an existing unbound Create, retained
ownership through unavailable startup inspection, and healthy cleanup without
re-execution. At **19:54 / 20:12 UTC**, the
[termination follow-up](codex-control-boundary.md#deadline-and-resistant-descendant-witnesses)
passed a fixed resistant/`setsid` Runner and native held-tool deadline through
exact cleanup and one delivery. Still-absent delayed Create, native descendant
variants and production transport/context obligations remain open. At **20:28 UTC**,
[permanent admission feedback](codex-control-boundary.md#permanent-credential-admission-feedback)
passed revoked-generation/wrong-scope denial through the real service/HTTP/Core
path, producing one fixed failure after exact Run absence; transient failures
and existing Runs retain their prior behavior. At **21:04–21:05 UTC**, the
[built-in operation inventory](codex-provider-operations.md) passed fresh and
refreshed synthetic native file auth, including persistence. It narrows the
transport decision. The **21:24 UTC** fixed custom-provider candidate passed
uncompressed HTTPS/SSE and refreshed-token use; its header differences remain
explicit. The **22:05 UTC** offline composition covered operation enforcement
and scoped native-tool separation; the **22:49–22:54 UTC**
[controller lifecycle composition](codex-provider-operations.md#offline-controller-lifecycle)
added mounted-file refresh, cleanup/publication and cancellation/recovery.
The [bounded provider relay and transport decision](codex-provider-transport.md)
select an owner-hosted Unix/TLS operation endpoint and a network-none client
domain. The dated standalone native witness and subsequent
[runtime-owned canary](codex-provider-canary.md) now cover mount/UID/tool and
cleanup/publication integration within their experimental scope, with a distinct
opt-in pin. Fixed executable configuration is now integrated under a separate
daemon pin; production enrollment/rotation, complete production authority and
deployment isolation remain unresolved.
Four real Runs failed before the fifth controlled Run completed with its tool
marker, local delivery and cleanup. The new startup path has deterministic
configuration/enrollment/restart tests and a read-only binary/artifact check.
A separately approved fake-ingress Run through ordinary services then passed on
2026-09-11 at 00:47 UTC, with independent cleanup/source/history checks at
00:48 UTC. The next bounded deployment package is reproducible fixed-target
artifacts and separate service-identity configuration, checked before host
activation. Reuse the completed witness and existing tests; changed artifacts
and unresolved boundaries require their own evidence. Discord acceptance remains
later work; the production target is blocked.

### Deployment identities and local IPC

- provision separate Connector, Core, and sandbox service identities;
- verify private path ownership, setgid group traversal, socket `0660` modes,
  connect-time UID checks, restart behavior, and log redaction on the target
  host; and
- demonstrate that neither the Connector nor Runner can reach Core data,
  sandbox state, provider session state, or the rootless runtime socket.

The first two items were exercised once on one host on 2026-09-11 at 22:46 UTC:
three provisioned identities, pre-provisioned `02710` socket parents, connect-time
peer UID checks, private `0700` storage and one complete Run through the installed
unit templates, with both services stopping cleanly. A host reboot on
**2026-09-12** then exercised restart and recovery under those identities: the
tmpfiles entry recreated the setgid IPC directories, lingering restored the
sandbox user manager, the rootless runtime stayed stopped because it is not
enabled, and its pinned image survived. Both services restarted and stopped
cleanly; an idle `SIGKILL` of the sandbox owner was recorded as a signal failure
and the next start retired no credential generation; and with the runtime
stopped the owner refused to serve, exiting non-zero at rootless attestation
without leaving a socket behind. The third item's adversarial demonstration
remains open; the log-redaction audit is recorded above. The offline
[native identity witness](../internal/localhttp/testdata/identity-witness/README.md)
covers only its own synthetic container.

### Real Codex target

- materialize and attest the sealed CLI artifact in a digest-pinned runner
  image;
- build on the locally verified v3/v2 mock state path without weakening its
  explicit profile gate or changing legacy TargetManifest/revision fingerprints;
- resolve immutable policy, auth, network, context, resource, and teardown
  authority plus the local credential slot/generation/source identity into a
  new target-revision security fingerprint;
- validate overlapping workspace/credential confidentiality domains before any
  egress-enabled target is selectable;
- close repository/system customization injection;
- validate the implemented generic terminal-publication mechanism against the
  exact runtime image's cleanup and descendant-quiescence behavior;
- complete the unresolved credential reach, refresh, revocation, output-redaction,
  provider-egress, tool-egress, cancellation, detached-descendant and quiescence
  cases for the exact release artifact, preserving existing scoped witnesses.

The first controlled fake-ingress Run through ordinary services passed on
2026-09-11. It closes that local integration step; it does not authorize adding
a platform credential before the remaining target/deployment checks.

### Discord Connector

- normalize Discord's stable actor, channel, message, and event identities;
- keep bot credentials and gateway cursors inside the Connector domain;
- implement bounded durable ingress spool, reconnect/catch-up, replay, self-
  event rejection, and outbound completion semantics; and
- pass the isolated private-Discord adversarial cases before expanding to
  another platform.

The first three items are implemented and offline-tested in
[the Connector](discord-connector.md): snowflake-derived refs with stable event
IDs, a bot token held only in its own domain, a private cursor advanced only
behind Core's durable acknowledgement, bounded catch-up, self/bot/webhook
filtering, and lease completion including duplicate-send suppression. The
fourth item is partly covered: a deterministic adversarial suite drives the real
compiled policy, admission service and Core store with only the platform faked.
It exercises spoofed channels, unlisted, bot, webhook and self authors,
malformed and oversize content, hostile text that cannot select authority or
rewrite its own identity, exact replay, tampered replay under a retained event
ID, and the one-live-Run fence. Its deny audit asserts that every refusal used a
closed reason code, that no unauthorized Run was created and that denied message
text was not retained. Review-only templates now describe a separate Connector
identity with its own IPC group, its own agentd socket directory, `0700` private
storage, a bot token file outside that mutable state and no install target, and
tests pin those properties; nothing is provisioned or installed from them. The
isolated cases against a live private channel remain open, as do the provisioned
identity itself, a new TargetRevision and enrolled credential generation for the
Discord scope, and calibration of the Core quotas against real traffic.

## Deliberately deferred

- Claude Code and additional harness implementations;
- WhatsApp and other messaging platforms;
- attachments, rich interactions, remote provisioning, and remote approvals;
- dynamic skills, plugins, MCP servers, mounts, images, credentials, or network
  policy;
- workflow orchestration, multi-agent scheduling, Kubernetes, multi-host
  operation, and high availability; and
- ACP adoption, unless a real Runner conformance experiment demonstrates that
  it reduces adapter maintenance without replacing the HSG security envelope.

## Verification commands

The release checks require Go 1.26.7 or newer and are:

```bash
test -z "$(gofmt -l cmd demo internal)"
make build
go test -count=1 ./...
go test -race -count=1 ./...
go vet ./...
make demo-security
make config-check
make bakeoff-check
```

Passing these commands supports only the scopes named above. A green unit test
suite is not evidence that the disabled live integration is safe.
