# Codex Profile v4: owner-only authentication candidate

Status, **2026-10-07**: implemented opt-in wiring; synthetic native inference401,
Catalog401 recovery, authenticated refresh cancellation and first-helper-loss
safe failure and original same-DB Owner crash/restart accepted in separate
synthetic scopes. Consolidated local tests/race/vet and code review passed;
[pushed-commit CI passed](https://github.com/shwdsun/harness-security-gateway/actions/runs/37683057049).
The bounded real campaign stopped at its private enrollment-completion witness
before a task; cleanup was verified. Real-provider/refresh/Discord acceptance
and main integration remain open.
This is the next CRED-01 candidate,
with classification `credential-isolated-candidate`; older revisions remain
`credential-exposed-personal`. See [current evidence](implementation-status.md).

## Immutable authority

| Field | Fixed value |
| --- | --- |
| Profile | `codex.chatgpt-personal-messaging-isolated-v4` |
| Adapter | `codex` / `0.4.0-new-only` / `hrp/1`, no optional features |
| Policy / auth | `codex.locked-tools-isolated-v4` / `codex.owner-auth-v1` |
| Local config schema | `sandboxd/codex-isolated-v2` |
| Contract SHA-256 | `8edb914c08502d5b19682bdbdf661414e76301cf8ea61c91561b707d17219edc` |
| Owner launcher SHA-256 | `94427818c0c718c5e9791807cfc803751229c93f825948a220bece2293733ed7` |

[V4](../internal/codexprofile/isolated_v4.go) inherits the exact V3 six-file
native tool package, fixed CLI 0.151.0/model/effort, developer instructions,
300-second rw workspace, 2,000-byte output limit, network policy and disposable
new-only Runner state. It changes auth placement and lifecycle, with a separate
profile fingerprint and runtime/daemon pin domains. A distinct Runner executable
selects V4 at build time. Messages, HRP input and repository files cannot select
a profile, auth source, artifact, launcher, command or provider.

The [example](../config/sandboxd.codex-isolated.example.json) contains deliberately
unresolved artifact/authority hashes. It grants no enrollment or activation.
Only the Linux/amd64 `codexintegration` build accepts native execution. A changed
contract/pin requires a new TargetRevision and independently approved Binding
scope; existing immutable enrollment is not silently migrated.

## Credential and launch path

The controller acquires its usual exact enrolled HeldSource and retains original
health, locks and durable occupancy. It selects one owner-only borrow from the
sealed auth profile. A shared, exact Run/fingerprint/binding Claim consumes one
Create attempt; copies, retries and Close cannot restore that authority. The
controller's metadata handle has no credential-reading method.

After durable intent, the runtime constructs and registers the provider before
credential/native work. It creates only a new random local representation in a
separate private `client-seed/local/auth.json`. The real enrolled source is never
used as a Runner bind. The local seed gets its own transient HeldSource/object
proof/Handoff; that proof is neither an enrollment nor the original owner proof.
Native readiness and accepted persistence complete before container Create.

The inert bootstrap verifies the exact container policy, provider socket/CA,
mapped UID/capabilities/PID/cgroup/bootstrap executable, local seed object and
initial content digest, then revalidates both the original owner capability and
the separate seed handoff. Only then does it Open the prepared provider and
release the existing ten-second permit. Open performs no native readiness work.

The native client may update its disposable local auth file. Inference/catalog
must match the current local access/account pair before the provider substitutes
owner-chosen real auth. Client Refresh is entirely local. Only a valid actual
upstream 401 can authorize one native owner recovery; there is no inference
replay or extra refresh/connection budget. Recovery uncertainty taints the
original shared HeldSource. [The provider contract](credential-isolation-plan.md#per-run-provider-authentication--2026-09-27)
defines the concurrent/late-response and error rules.

## Startup, artifacts and cleanup

All V4 static artifacts and their parent chains are root-controlled, without
symlinks or group/other write authority. Launcher/native executable FDs are
hashed and pinned; sandboxd cannot modify the installed inodes. Tool package
ownership therefore differs from mutable workspace/credential/provider roots,
which retain the dedicated service's ownership and private-directory rules.
No constructor downloads, installs, enrolls or changes permissions.

Inside the Runner's user namespace, host-root file UIDs may be unmapped. V4's
adapter therefore checks actual kernel readonly properties on each package
directory and opened file descriptor, alongside the same fixed path, closed
layout, hashes, modes and hardlink guards. This does not replace the host's
root-controlled installation or exact readonly mount admission. Legacy profiles
keep their original owner predicate. Seven actual readonly/writable/submount/
content kernel controls and canonical Ready passed on October5; those witnesses
do not establish the remaining native tool or real-provider gates.

The owner service borrows those FDs per Run. Startup requires the existing
root-controlled, non-delegated `hgw-sandboxd.service` cgroup, empty capabilities,
NoNewPrivs and exactly the current process, after the global process lock and
before stores or recovery. Serve and explicit enrollment share that ordering.
`-check` verifies inert configuration/artifacts and closes FDs without invoking
the service gate or reading credentials. These checks do not configure a host.

On teardown, provider admission closes and helper, callbacks, preparation and
readers join before container removal. Exact absence, or certain non-dispatch,
permits finalization of seed handles and the owner borrow. A failed join or
finalization keeps its resource entry. Controller then checks the original held
health, durably retires any invalid generation, closes the held source and
releases occupancy/publication last. Lost retirement responses remain retryable;
resource-map deletion cannot erase credential taint. Owner loss requires startup
helper absence and the existing durable retirement/recovery, never auth replay.

## Remaining acceptance

**October7 real campaign:** credential enrollment succeeded according to the
service journal, but the private driver's completion condition timed out and
the campaign closed with that action uncertain. No task, serving startup,
provider compatibility or natural refresh was observed. Cleanup passed without
undoing credential migration. Current CI passed for the exact pushed development
candidate; it does not replace this missing real-path acceptance. CRED-01/M1
remain open. See the [current outcome](implementation-status.md).

**October6 09:53 actual acceptance:** authenticated Owner SIGKILL and a new
process's original serve on the same DB passed with no credential/provider/native
reopening or new Run. Startup retirement precedes known container cleanup;
physical source flock releases on death while durable occupancy/workspace/ref
remain until cleanup/publication. Exact source/enrollment, interrupted closed SQL,
original joins, empty inventory and final owned stops passed. Complete independent
review accepted this narrow original scope. The original wrapper remains failed
at a private Python analysis name collision; alias-only local analysis validated
the complete original report without replay or rewriting it. Remaining planned
synthetic faults are accepted separately. Approved-device real compatibility/
required refresh/private Discord and final consolidation/review/current CI remain;
V4 activation and CRED-01/M1 are still open. Earlier entries are historical.

**October6 helperloss acceptance:** the original08:40 phase proved authenticated
helper loss before promotion, no actual external Create/Attach, source-held
retirement, native/provider joins and resource release before publication. The
whole batch remains failed at private pre-crash supervision; original restart
and global cleanup did not pass. Repair the bounded observer and run only the
remaining crash/restart gate. This component result does not activate V4 or
establish real-provider compatibility.

**October6 actual acceptance:** production8/16-second inference401 recovery passed
at01:26–01:30 UTC; Catalog401 and native-refresh cancellation passed in the
original04:57–04:58 guest execution. The original functional wrapper remains
failed at pre-collection XML equality; one reviewed stopped-new-disk recovery
collected the guest evidence without replay. Raw native stages, original late200
body/context rejection, real tool/readback where applicable, source/durable
retirement and ordered cleanup were independently accepted. Cancellation retires
after runtime cleanup and before source release/publication. Helper loss and
same-DB Owner restart, approved-device real compatibility/required refresh/private
Discord and final consolidation/review/current CI remain. Earlier dated failures
below retain their original scope; V4 remains blocked for activation.

**October6 local shutdown correction:** successful account/read now uses a
fixed eight-second natural EOF grace with sixteen-second independent cleanup.
Live cancellation interrupts natural waiting; ordinary error cleanup stays5/12s.
Forced/nonzero/incomplete exits and all original candidate/Commit conditions
still refuse. Invocation60s and endpoint45s idle limits remain. Six-second natural
EOF and post-EOF Cancel/Owner-close regressions, full Go test/race/vet and security
demo pass locally; new Runner/Owner artifacts have a fresh52-source closure with
exactly two changed helper files. Implementation review and actual new-budget
inference401 composition are still required; previous false reports stay false.

**Current, October6 00:04 UTC:** configured startup/enrollment/controller and
Owner/receiver/permit reached a complete fresh canonical native tool/readback
Run in a no-NIC VM. Actual tool connect EPERM is paired with a same-object live
Owner positive control; bounded secrecy/source health and ordered cleanup pass.
The full campaign remains failed. The isolated inference401 diagnostic proves a
complete refresh response/receipt and successful account/read, then refusal at
`cleanExit` because the five-second EOF wait entered forced shutdown. Signal
delivery, natural exit latency and candidate persistence remain unmeasured;
successful source Commit and recovery remain unobserved. Joined closure,
generation retirement and independent empty global inventory were observed.
Measure only the fixed helper's shutdown/candidate boundary before designing the
affected recovery fix, retaining original false reports and Commit guards.
Catalog401/cancel/helper loss/Owner restart, bounded real compatibility/
required refresh and consolidation/review/current CI remain. Earlier Ready/Seed/
kernel positives are reused; V4 stays a blocked candidate.

Local tests exercise scope/copy consumption, pre-Create resource registration,
Prepare/Open separation, same-inode seed content mutation, retained preparation
joins, seed finalization order, shared health, revoke failure/lost response,
fixed native tool invocation and schema/profile separation. Independent review
found and corrected conflicting ToolPackage ownership predicates.

On **October 3**, actual wrapper Prepare/CaptureProof/Handoff and original owner
Claim passed with native ext4 sources, separate bindings, retained locks and
two-phase cleanup. Only endpoint readiness/transport is a fake, using simplified
fixed local bytes and a profile digest as opaque scope; this does not exercise
full TargetManifest admission/Create, native readiness or receiver.

The actual production V4 constructor also passed in a frozen rootless
network-none outer probe: static artifacts appeared root-owned and read-only in
that view; mutable roots belonged to UID 1000. Exact artifact/profile/pin wiring
and inert FD Close were checked. The pin names the probe executable. The first
fixture lacked its required CLI file and failed; a frozen read-only CLI corrected
only that fixture. Both outer containers have verified exact-ID cleanup. This
avoids a host installation for that constructor observation; it does not prove
the actual host service gate, ext4 mounted seed or native execution.

The September 27 native witness used synthetic storage and shared PID/mount
domains. It does not verify bootstrap receiver, service gate or final Runner
secrecy. The October 3 positives do not compose those remaining boundaries.

At the October3 preparation, the next Ready-only test was prepared with actual constructor/startup/enrollment
helpers and a controller observer that sends no RunStart. It requires a fresh
offline dedicated systemd VM; the measured inputs and bounded execution/evidence
batch are prepared, but it has not executed the service/receiver boundary.
Its test-executable pin and invalid synthetic source do not identify deployed
sandboxd or prove real-provider compatibility. Preparation checks do not change
this profile's blocked classification.

The later authorized October 3 VM attempt stopped before that composition test:
native Hold rejected root-owned parent directories incorrectly masked to0700 by
the private fixture's umask. Private credential modes were correct; no product
proof or admission guard was relaxed. Signed-base-bound offline collection
recovered the failure without restarting the guest, with exact absence/old-state
checks. A local fixture correction is reviewed, but a fresh frozen batch and
actual proof/runtime/Ready acceptance remain. This is not receiver/native evidence.

At14:58 UTC October3, a fresh corrected private batch is frozen and independently
reviewed, with affected rejection checks and dated read-only source/old-state/
collision/resource inspection. Unchanged artifacts and source evidence are reused
by pins/function equality. The new VM effects await exact authority; no new
proof/runtime/receiver/Ready pass or profile activation is claimed.

On **October5**, that expired preparation was renewed with only three test date
literals and executed once. Both unprivileged native ext4 source proofs passed;
rootless peer/cgroup2 capability checks reached the image gate. Exact content
import succeeded but immutable named-reference lookup failed. Owner and Ready
were not reached, nor were effective container resource/isolation checks. The
failed result remains retained; service stops, MainPID0, natural VM shutdown,
exact absence and complete old metadata preservation passed in that dated run.
An offline outer-wrapper naming candidate preserves every CAS blob/root digest
and product pin; its native import remains unexecuted. Default AppArmor profile
loading was also denied, and daemon SecurityOptions did not report AppArmor.
Resolve those packaging prerequisites before repeating the composed gate, without
weakening product or confinement checks. None of this activates V4 or closes M1.

Later October5, a fresh bounded batch freezes that image-name candidate, preserves
all product/source/artifact pins and adds actual sleep-resource PID/starttime,
NNP/seccomp/cap/cgroup observations. Affected local checks and independent final
review pass; dated read-only lab inputs/old-state/collision/capacity checks pass.
No new guest/runtime/Ready execution is claimed or authorized. The actual label
observation stays separate from both default AppArmor warnings and the native
Codex filter/secrecy gate; no policy exception or product guard changes.

At09:12–09:15 UTC October5, that exact authorized batch passed both native source
proofs and the original immutable named-image Id/RepoDigest/amd64 lookup. Resource
creation succeeded, but start failed at Docker's loaded AppArmor-profile query;
owner, actual effective controls and Ready remained unreached. The false result
and failed disks are retained. Service/VM stop and complete old-state preservation
passed; exact container deletion and empty inventory were not established.
Independent review verified the report and scope. A private guest-only mode
candidate addresses the measured vendor/fixture compatibility branch, without
changing product pins or policy; it is not executed. Actual namespace, loopback,
route, label and effective-control observations remain before the Ready gate.
No container AppArmor, native secrecy, profile activation or M1 pass follows.

At09:51–09:54 UTC October5, the newly authorized detached-mode batch passed both
native source proofs and paused containment, then failed during RootlessKit's
none-network setup with nsenter Invalid argument. Daemon-peer attestation and
actual namespace/image/resource/owner/Ready observations were not reached.
The failed result/state and complete bounded receipts are retained; service/VM
stop and full old metadata preservation passed. Dependency source suggests an
asynchronous holder race but the particular syscall/PID is not traced. This is
neither another demonstrated AppArmor denial nor V4 activation. Product pins,
guards and global security policy remain unchanged; operator setup is unnecessary.
Resolve the private runtime startup prerequisite before repeating Ready.

Next finish the Ready service/receiver gate, then compose pinned native HRP/tool work, owner
canary scans, cancellation/owner loss and Catalog-401 behavior. Then run bounded
real-path acceptance before claiming CRED-01/M1 or merge readiness.

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
