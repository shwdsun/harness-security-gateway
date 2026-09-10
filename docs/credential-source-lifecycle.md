# Credential source lifecycle

Status, 2026-09-09: **durable occupancy, held-file/proof primitives, atomic
registration, Run re-open/release and startup retirement implemented with
synthetic tests and two local native owner-restart witnesses; real source
enrollment and credential use remain blocked**.

This is a sandbox-store lifecycle extension, not a credential manager, new
daemon or message protocol. The existing executable configuration cannot enroll
a credential or bind one to a target. No file contents, token bytes, host paths
or provider responses enter these new database records. The offline candidate
check remains diagnostic and always execution-blocked.

## Implemented boundary

Sandbox schema v10 adds five small relations in the existing database:

| Record | Meaning |
| --- | --- |
| Source ownership | A supplied canonical source digest permanently belongs to one logical slot within this database lineage |
| Generation | Immutable slot, positive generation, source digest, workspace, auth profile and exact disclosure/session scope |
| Revocation | One-way retirement of one generation; exact registration replay cannot reactivate it |
| Target binding | A new immutable TargetRevision selects one enrolled generation; historical targets are explicitly credential-free |
| Occupancy | At most one Run per canonical source and slot, and one source per Run |

Schema v11 adds four proof columns to the existing immutable generation row,
without changing migration 1–10 bytes. `RegisterCredentialEnrollment` commits
generation and proof together with source ownership; exact replay compares
both. Four NULLs preserve proofless history. `RegisterCredentialGeneration`
retains this synthetic form and cannot downgrade a proof-bearing record; the
proof-aware entrypoint cannot upgrade an existing proofless generation in place.
The same generation update/delete/replacement guards protect the proof.

These APIs accept a **trusted local enrollment result**; only synthetic tests
supply it today. Equality of source digests remains a resolver
assumption, not proof that paths, hard links or bind aliases denote the same
resource. The store rejects reassignment of the same supplied source identity
to another slot. It cannot detect two different identities invented for the
same physical source. Token hashing and path hashing alone are not acceptable
enrollment mechanisms. `GetCredentialEnrollment` reads the immutable pair even
if revoked, rejects absent proof and grants no current authority. Store reopen
rejects malformed generation/proof shapes; it does not infer missing proof.

Generations increase strictly within a slot. A new generation requires explicit
revocation of the previous generation and no remaining occupant. Changing
source, workspace, auth profile or exact scope requires a new generation and a
new target revision. Refreshing token bytes does not itself change a generation.
These guarantees assume a trusted host and a retained, non-rolled-back database
lineage. Deleting the database or restoring an older backup defeats its history.

`RegisterStart` acquires occupancy in the transaction that inserts the Run,
consumes any opaque session and acquires any workspace writer lock. Credential
occupancy also serializes read-only workspaces; it does not depend on writer
locking. A conflict rolls back the entire admission. Exact Run replay returns
the existing result even after revocation, without granting a new Create.

`BeginRuntimeIntent` requires matching, unrevoked occupancy before committing
Create authority. Revocation prevents later admission and new Create intents;
it does **not** invalidate provider tokens, erase a completed refresh, stop an
existing container, or retract an intent that committed first. A runtime result
may still bind to that granted intent after revocation so it can be cleaned up.
Provider revocation and cancellation require their own operational mechanisms.

Staging retains occupancy. Clearing an uncertain Create intent does not release
it. Process death or loss of an OS file lock is not proof that a runtime stopped.
Only the trusted `ConfirmRuntimeStopped` boundary releases occupancy, in the
same transaction as terminal/session publication, runtime-reference clearing,
writer unlock and candidate retirement. Direct legacy terminal publication is
rejected for credential-bound targets. Existing credential-free history keeps
its compatibility behavior. Database reopen checks for missing or mismatched
occupancy, and reconciliation includes any retained occupant. An accepted Run's
own pre-Create occupancy does not deadlock the global execution lane.

Under exclusive sandbox mutation ownership, `Controller.New` first calls
`RetireOccupiedCredentialGenerations`. One transaction revokes all generations
referenced by retained occupancy, preserving every Run and its cleanup authority.
An error prevents runtime reconciliation, inventory and worker startup. An old
accepted credential Run without a Create intent is staged as interrupted and
cleaned up; it cannot be reoffered as new work. Existing staged outcomes and
uncertain-Create boot fencing survive retirement. Cleanup uses only durable Run
and runtime identity; it never reopens a credential. Idle generations are not
retired. `Store.Open`, background reconciliation and shutdown do not perform
this startup transaction or interrupt fresh current-process acceptance.

For a fresh admitted Run, the controller now reads only its unrevoked, occupied
generation/proof through `GetRunCredentialEnrollment`. It checks the frozen
Run/manifest workspace, auth profile, exact scope and copied local binding before
native Hold/VerifyProof. Only its execution owner may acquire; duplicate offers
do not reacquire. `RevokeRunCredential` derives retirement from the Run's retained
ownership, so rejected contenders cannot retire another Run's source. Before
Create/AttachStart and after runtime cleanup the controller revalidates the held
source. Observed failures retire the generation and retain occupancy through
cleanup. A failed revocation or staging write also keeps the volatile handle
fencing the execution lane.

After cleanup, the controller closes the held source before its centralized
ConfirmRuntimeStopped call. A close error stays latched and retains occupancy
until process restart recovery. A successful close removes the volatile entry;
the durable candidate/occupancy then cover publication failure or response loss
without reacquisition. Fault tests use synthetic handles/fake runtimes. The
[controller-owned native fixture](codex-control-boundary.md#controller-owned-synthetic-v3-witness)
also observes this ordering with actual Docker and a synthetic enrolled file.
Normal executable configuration and real credential use remain blocked.

The close ordering above assumes a live owner. SIGKILL releases its physical
lock before runtime cleanup. Recovery therefore depends on retained database
occupancy and one-way startup retirement, not on an OS lock surviving death.
The [2026-09-09 native restart witnesses](codex-control-boundary.md#native-owner-crash-and-recovery-witnesses)
observe physical lock loss, unchanged durable ownership, failed recovery without
publication, then exact cleanup and release by a healthy replacement. Recovery
opens no execution credential handle and never resumes or recreates that work.

## Local held-file boundary

`internal/credentialsource.Hold(root, directory)` now opens one existing local
`root/directory/auth.json` and retains its root, slot and file descriptors. It
offers `Validate`, `Close`, `CaptureProof`, `VerifyProof` and an opaque `Handoff`; no credential bytes,
raw filesystem identity, file descriptor or mount path is returned. The proof
adapter returns digests only. The handoff borrows the source for one Run/Create
and one independently attributed receiver observation; revoking it cannot
unlock the held source. The controller and tagged Docker consumer use this
boundary. Normal executable configuration and trusted real enrollment remain
unwired.

The Linux primitive requires an unprivileged current-UID operator, root and
slot directories at exactly `0700`, and a regular `0600` single-link file.
Configured path components cannot be symlinks. Ancestors must belong to root
or the operator and cannot be group/other writable, except root-owned sticky
directories. Below the dedicated root, `openat2` forbids mount crossings,
including bind mounts. Unknown mechanisms or unsupported filesystems fail
closed. The allowed local filesystem families are ext-family, XFS, Btrfs,
tmpfs and overlay; overlay additionally assumes trusted local backing storage.

Choose an operator-owned state location whose entire ancestry meets those
rules, separate from collaboratively writable source trees and Run workspaces.
A private leaf directory does not repair a group-writable ancestor. Diagnose
such a rejection before enrollment; do not recursively change an existing
project's permissions or relax Hold. Root-owned sticky temporary directories
can host fresh private offline fixtures, but are not a persistent credential
deployment recommendation. The operator must provision a durable protected
root before real enrollment; normal executable enrollment remains unwired.

An `O_PATH` open checks the file type before the pinned regular object is
reopened through trusted procfs. No auth content is read, parsed or hashed.
Nonblocking advisory locks cover both the slot directory and the auth file.
The slot lock prevents another cooperating holder from simply locking a new
auth inode after file replacement. These locks do not stop an uncooperative
host writer or the provider CLI, and disappear on process death.

`Validate` compares newly resolved paths against the held device/inode/mount
identities, checks both views' metadata, and requires exactly one slot entry,
`auth.json`. In-place byte changes are allowed. An observed replacement,
metadata violation or extra entry permanently invalidates that handle;
restoring the old object cannot revive it. Invalidation retains the locks until
explicit `Close`. Validation, proof observation and Close are serialized within
a handle.

The separate proof adapter uses native-ext4 UUID/export handles from the held
objects, initially on Linux/amd64 only. It returns a source digest and immutable
root/slot/locator proof, or compares fresh observations against expected pins.
It rejects missing/unknown proof and unsupported mechanisms without fallback;
collection failure or mismatch latches invalidation while retaining locks.
Digest equality is an observation within the documented filesystem/host trust
assumptions, not enrollment, scope authorization or a runtime permit. See the
[enrollment contract](credential-source-enrollment.md) for the exact encoding.

These are observation and cooperative-exclusion guarantees under a trusted
host and stable mount namespace. They do not prevent root/slot replacement,
observe a change restored between checks, or close a future path-based mount's
check/use gap. Close is not runtime cleanup evidence and cannot release durable
Run occupancy. The descriptor identities are only live comparison keys: inode
and mount-ID reuse prevents treating their hash as a permanent SourceDigest.
No cross-restart enrollment, mount handoff or token-persistence attestation is
implemented by this primitive.

## What is still required

The closed binding DTO now belongs to `internal/credentialsource`; the candidate
uses that single definition with its original field order and diagnostic hash.
The held-file primitive is not yet a durable source resolver or enrollment path.
The [enrollment and re-open contract](credential-source-enrollment.md) now
specifies the implemented native-ext4 identity/comparison adapter with separate
root, slot and locator pins, plus atomic registration storage. Startup retirement
and cleanup-only controller recovery are now integrated with synthetic authority.
Authoritative Run re-open and held-lock release before durable occupancy release
now have controller integration. The trusted local enrollment caller and its
executable configuration remain unimplemented. This design
does not turn the existing device/inode/mount tuple into permanent authority.
The strict enrolled-target registration now compares the independently supplied
auth profile, workspace and disclosure scope with the immutable enrollment and
hashes its source/generation/proof into a new durable revision-pin domain. This
read and whole-batch registration are atomic. The production resolver must still
derive that exact scope from frozen policy and bind resolved context, network
and other non-credential authority into the base pin. The service now freezes
one resolver result per target and consumes strict registration; the compiled
ingress policy can independently project the approved scope. Public configuration
resolves only credential-free mocks. The real-provider content resolver is absent;
neither a candidate digest nor a composed hash establishes its completeness.

Before wiring a real target, define and verify the dedicated source's canonical
identity, alias rejection, held object, substitution protection, and attestation
at resolution, mount, start, refresh and recovery. Inode stability alone cannot
serve as both permanent generation identity and a correct refresh contract.
The metadata-only inspector neither closes these races nor grants a lease.

For the sealed Codex single-file mechanism, the pinned CLI's synthetic refresh
witness below narrows the storage question. A real canary still needs dedicated
credentials and the intended disposable execution runtime. Observe startup,
an actually triggered ChatGPT token refresh, teardown and credential-home
residue. Distinguish in-place write, temporary-file rename, source-side
replacement and any additional credential files. An API-key login or a run with
no observed refresh is not refresh evidence. Failure or inconclusive evidence
leaves execution blocked; it does not authorize mounting the normal user's home
or changing the sealed mechanism silently.

## Evidence

On 2026-09-07, a local synthetic witness in an existing rootless container
observed that in-place writes through a single-file bind reached its host
source, while same-parent rename over the mounted file returned `EBUSY`.
Replacing the host source changed its inode but left the existing mount on the
old object; another write through that mount did not update the new source.
The fixed helper exited and its exact container and synthetic files were removed.
This is a local mechanics observation, not public CI or a Codex refresh canary.
It reinforces the need to distinguish the current path from the object a Run
actually holds; re-statting a path alone cannot attest an existing mount.

On the same date, a second local witness ran the exact pinned Codex 0.151.0
executable with fresh synthetic managed-ChatGPT credentials and an isolated
loopback refresh endpoint. No model turn or real provider contact occurred.
The app-server account-read path issued one verified synthetic refresh per case.
With a read-write single-file bind, the new synthetic refresh token reached the
host source, preserving the original device/inode, mode 0600 and single link.
With the source bound read-only, account-read still returned a managed account
without an RPC error, but the host retained the old synthetic refresh token.
**Account-read success is therefore insufficient evidence of persistence.**

Both exact containers and their synthetic source directories were removed.
The disposable credential home also contained installation_id and skills entry
names; their contents were not classified, and no exhaustive residue audit was
performed. A clean app-server exit was not observed in either case. This uses
app-server rather than the sealed exec path and proves neither real OAuth
rotation nor graceful shutdown, crash durability, mount-race resistance or
the product runtime's cleanup guarantees. It supports the dedicated writable
file mechanism only within the observed synthetic refresh case.

Store tests cover generation/revocation history, source ownership, immutable
bindings, simultaneous read-only admissions, scope mismatch, SQL guards,
SIGKILL/reopen, missing occupancy and late-publication rollback. A controller
test retains the occupant through fake-runtime cleanup failure and store reopen,
then verifies original-result publication and release without a new Create.
Startup tests also cover selective multi-generation retirement, late SQL rollback,
commit-response loss and retry, retirement before runtime lookup, interrupted
pre-Create Runs, same-boot pending intent with a late runtime, retained staged
results, and unaffected idle/fresh and credential-free acceptance.
Run execution tests additionally cover exact ownership/proof reads, unadmitted
and mismatched-occupancy revocation rejection, duplicate acquisition suppression,
scope/generation checks, mid-Create replacement, failed cleanup/revocation/staging,
sticky close failure and both sides of a publication commit. Successful runs
close exactly once before publication; recovery does not reopen the source.
Migration tests retain historical mock targets as credential-free. Existing
candidate digest and blocked-execution checks remain in place.

At **2026-09-09 11:32–11:35 UTC**, two local rootless cases additionally passed
with the host race detector: SIGKILL after actual Create but before binding its
reference, and SIGKILL during independently witnessed native tool work. Each
replacement first retired the occupied generation; unavailable inspection
retained cleanup responsibility, and a healthy replacement removed the same
container before publishing one scoped Core interruption. A fresh request using
that retired generation remained denied. These were same-boot process restarts
with already existing objects and empty synthetic auth, not delayed absent
Create, host reboot, real refresh or resistant-descendant evidence.

Held-file tests exercise synthetic symlink/hardlink rejection, unsafe owners
and modes, FIFO rejection, file/root/slot substitution, extra entries, stable
in-place updates, retained locks after invalidation, failure cleanup, concurrent
holders, cross-process contention and lock loss after SIGKILL. A read-only check
of an existing procfs mount exercises the no-cross-mount resolution flag; no
bind mount was created for this test. The kernel's treatment of bind crossings
is specified by [openat2](https://man7.org/linux/man-pages/man2/openat2.2.html).

Store tests use synthetic authority and fake runtimes; held-file tests use
synthetic local files. Proof tests additionally pin digest encoding, compare all
pins, retain locks on mismatch, and exercise the native ext4 backend on owned
synthetic descriptors. See the enrollment contract for the native-test scope
and its distinction from full Hold validation on an approved credential root.
Schema v11 tests additionally cover atomic pair registration/reopen, exact
replay, proofless-history preservation, SQL guards and rollback under a late
write failure. These tests do not establish actual source enrollment or storage
continuity across reboot, uncooperative-writer exclusion, real OAuth refresh,
provider token revocation, runtime mount race resistance or actual descendant
quiescence.
