# Credential source enrollment and re-open contract

**2026-09-10 update:** the dated sections below retain the 2026-09-08 contract
and implementation state. The [controlled canaries](codex-provider-canary.md)
subsequently exercised native held-source enrollment and handoff. The new
[fixed daemon startup](codex-daemon-startup.md) adds explicit local enrollment
and already-enrolled startup behind a build switch, with deterministic tests.
Default mock builds and production acceptance remain unchanged; this wiring
has not executed another real enrollment or provider Run.

Status, 2026-09-08: **identity/proof storage, Run re-open/release and startup
recovery integrated with synthetic tests; real enrollment and runtime use
remain blocked**.
Schema v11 adds proof to the existing immutable generation row.
Real Codex execution stays blocked. This document specifies the next boundaries
of [credential source lifecycle](credential-source-lifecycle.md).

## Identity and supported storage

The first enrollment profile is `linux-ext4-source/v1`. It requires native
ext4, its nonzero 16-byte external filesystem UUID, and bounded opaque export
file handles obtained from already-held root, slot and auth-file descriptors.
Read the UUID using `FS_IOC_GETFSUUID` on the held regular file. Obtain each
handle using `name_to_handle_at(AT_EMPTY_PATH)`, without `AT_HANDLE_FID`,
`AT_HANDLE_CONNECTABLE` or a later path lookup. The root, slot and file must
still satisfy Hold/Validate and be on the same mount beneath the root.

The mount's filesystem type must be attested as ext4 against the held mount in
the trusted sandbox owner's namespace; magic `0xef53` alone also covers ext2
and ext3. The first profile accepts the observed ext4 handle form: positive
type 1 and exactly 8 opaque bytes. Treat those bytes as opaque; never reconstruct
a handle from stat inode numbers. Other forms require a separately reviewed
profile, not an automatic change in encoding.

The broader local-filesystem allow-list in Hold does not confer enrollment
support. In particular, tmpfs, overlay, network filesystems, missing UUIDs,
unsupported ioctls/handles and unidentified mount views fail closed here. Do
not add capabilities, invoke `open_by_handle_at`, inspect a block device or
fall back to pathname/stat hashing to make this profile work.

The current native adapter implements the Linux/amd64 syscall ABI only. Other
Linux architectures return unavailable. It checks the held mount ID and device
against one ext4 record in `/proc/self/mountinfo`, bounds that input to 2 MiB,
and rejects an absent, malformed or duplicate matching record. The host's
procfs and mount namespace remain trusted inputs.

Within this profile, the physical object key is `(filesystem UUID, handle type,
opaque handle bytes)`. It is independent of a locator, logical slot, generation,
workspace, provider account and token contents. Aliases of the same supported
object must produce the same source key. A different file containing identical
token bytes is a different physical source; provider-account duplication and
confidentiality-domain checks remain separate gates.

Trust assumptions: native ext4's UUID/export-handle semantics, a trusted host
and mount namespace, and a retained storage/database lineage. This is not a
cryptographic defense against a host forging storage metadata or cloning a
filesystem UUID and handle namespace. Importing/cloning a volume, restoring
snapshots, changing UUIDs or migrating the host requires a separate explicit
storage/enrollment operation. Never automatically accept that as continuity.
Reboot/remount and filesystem-generation reuse have no local canary evidence
in this slice. Deployment attestation must address them before real enablement.

The [Linux handle API](https://man7.org/linux/man-pages/man2/open_by_handle_at.2.html)
supports comparing opaque handles obtained at different paths/times, and
explicitly excludes mount IDs as persistent filesystem identity. Those kernel
semantics support this design; they are not an HSG deployment proof.

## Canonical digests and immutable proof

`ObjectDigest` is lowercase hex SHA-256 of this byte sequence:

```text
ASCII("harness-security-gateway.credential-object/ext4-v1") || 0x00
|| filesystem_uuid[16]
|| uint32_be(handle_type)
|| uint32_be(handle_length)
|| opaque_handle_bytes[handle_length]
```

For the auth file, this value is the existing `SourceDigest`. Root and slot
objects use the same function for separate `RootObjectDigest` and
`SlotObjectDigest` pins. Do not salt SourceDigest with generation, slot ref,
path or scope: that would let the same object evade source-wide ownership and
occupancy under multiple digests. Do not include mount ID, device number, size,
mtime, ctime, token bytes or a randomly assigned enrollment ID.

The locator is a separate binding constraint. `LocatorDigest` is lowercase hex
SHA-256 of:

```text
ASCII("harness-security-gateway.credential-locator/v1") || 0x00
|| uint32_be(len(root_utf8)) || root_utf8
|| uint32_be(len(directory_ascii)) || directory_ascii
```

The root must be valid UTF-8 and the same canonical absolute, non-root path
accepted by the held-file boundary. The directory is one accepted canonical
ASCII component; the filename is fixed as `auth.json`. This path digest detects
a changed operator mapping; it is never physical source identity.

One new immutable proof per existing `(slot_ref, generation)` is sufficient:
`scheme`, `RootObjectDigest`, `SlotObjectDigest`, `LocatorDigest`. SourceDigest,
workspace, auth profile and disclosure/session scope already belong to the
generation record. No raw paths, UUIDs, file handles or token bytes need to
enter these database records. Do not add a second registry or daemon.

The proof and generation must be committed together under the sandbox's
exclusive mutation ownership. The existing RegisterCredentialGeneration call
cannot be followed by a separate proof insert and called atomic. Existing
synthetic generations without proof remain useful in tests and cannot become
real authority through implicit backfill. Replaying an enrollment requires
exact equality of both generation and proof; it never removes revocation.

The implemented credential TargetRevision composition includes scheme, all
four object/locator digests, slot ref/generation and existing exact scope. Its
base pin must cover the already-required resolved policy, auth, network and
context content. That real-provider resolver remains unimplemented; hashing a
manifest or sealed contract alone does not supply it. The candidate digest and
legacy fingerprint domains stay unchanged.

Synthetic encoding vectors, not host metadata:

| Input | Expected digest |
| --- | --- |
| UUID `00112233445566778899aabbccddeeff`, type `1`, opaque bytes `0100000002000000` | `f6e232218556022c5847877cd416ba6bce40fc7b570ebaf1e6752f4d8e658897` |
| Root `/srv/hsg/credentials`, directory `slot-one` | `af323ee479712026f4bc77da21261a122bffb4e9e2cd4eae00a984c5f7003978` |

## Implemented proof adapter

`HeldSource.CaptureProof` collects native identities from held descriptors and
returns SourceDigest plus a `Proof` containing the scheme and three remaining
pins. `HeldSource.VerifyProof` freshly collects and compares all four digests
with the trusted expected data. Both validate held/path metadata before and
after collection, serialize with Validate/Close, and read no auth contents.
Neither returns raw UUIDs, handles, paths or descriptors.

Missing, unknown or noncanonical expected data is rejected before observation.
`Proof.Validate` checks shape only and grants no authority. Collection failures
and mismatches latch handle invalidation and retain its locks until Close;
restoring the old path or expected data cannot revive it. Errors are fixed
package values and contain no source metadata. This package does not register
or revoke a generation, release durable occupancy, or grant a mount/Create.
The controller now consumes this adapter for an admitted Run as described below.
Trusted initial enrollment and exact-object runtime handoff remain unwired.

## Implemented atomic registration storage

Sandbox schema v11 stores the scheme and three proof digests as four nullable
columns on the generation row. All four NULLs explicitly retain proofless
synthetic history. Otherwise all values must satisfy the closed proof form;
checks include byte lengths and lowercase hexadecimal digests. The existing
generation update/delete/replacement guards cover these columns. Migrations
1–10 are unchanged; migration neither invents proof nor changes revocation or
Run occupancy. No separate proof table or backfill is needed.

`RegisterCredentialEnrollment(ctx, generation, proof)` inserts source ownership,
generation and proof in one transaction, with generation/proof in one INSERT.
It retains the existing retired-history, occupancy and permanent source-owner
checks. Replay requires exact generation and proof equality, including proof
presence. `RegisterCredentialGeneration` retains its proofless synthetic form;
neither entrypoint can replay an existing record as the other form. A higher
generation after explicit retirement and cleanup remains the rotation path.

`GetCredentialEnrollment` returns one immutable generation/proof pair, including
revoked history, so an uncertain registration result can be checked against the
exact intended record. Missing proof is an error. The read is not an unrevoked
authority check or fresh physical-source observation. Reads and store reopen
validate generation/proof shapes; malformed or partially present proof is
rejected. A revocation can occur after a read, so later admission/Create checks
remain mandatory.

All current callers supply constructed synthetic data in tests. This storage
API does not acquire exclusive daemon mutation ownership, resolve an actual
held file, validate operator scope against policy, or expose an enrollment CLI.
Those remain obligations of the future trusted local caller. A constructed
proof or successful registration alone grants no real execution capability.

## Implemented credential TargetRevision composition

`RegisterEnrolledTargetAuthorities` accepts one whole target batch and the
independently approved workspace, auth profile and exact disclosure/session
scope for each credential-bearing target. It loads generation and proof using
that target's own `(slot_ref, generation)`, checks all three scope values, and
composes the credential authority into the supplied non-credential revision
pin. The read, comparison, final pin and existing immutable target/credential/
Runner-state-owner registration share one transaction. A later entry failure
rolls back the whole batch. The caller supplies no separate proof or source
digest that could describe a different enrolled generation.

The new SHA-256 domain is
`harness-security-gateway.sandboxstore.credential-target/v1`. It frames these
strings in order, each preceded by its uint64 big-endian UTF-8 byte length:

1. domain and non-credential authority pin;
2. slot ref and positive canonical decimal generation;
3. proof scheme, SourceDigest, RootObjectDigest, SlotObjectDigest, LocatorDigest;
4. workspace ref, auth profile ref and exact scope digest.

Changing any input changes the pin, subject to the SHA-256 collision-resistance
assumption. Existing generation/proof records are immutable; a rotation requires
an explicitly enrolled higher generation and a new TargetRevision. Reusing an
existing revision with a changed composed pin fails. Revocation and token bytes
are excluded: exact historical replay after revocation remains idempotent, while
new bindings and admission against the revoked generation remain denied. Missing,
unknown or malformed proof, missing scope and scope mismatches fail closed.

Credential-free batch entries must carry no scope and retain the exact supplied
pin. The original `RegisterTargetAuthorities` path preserves mock and synthetic
history; it does not verify credential proof/scope coverage. Future real credential
consumers must use the strict enrolled entrypoint. Existing synthetic target pins
cannot be upgraded in place by switching entrypoints. No schema migration or
rewrite of stored history is performed.

Tests cover the independent encoding vector, every input field, exact reopen/
replay, scope rejection, rotation, legacy preservation and mixed-batch rollback.
The enrolled Run/controller fixtures and sandboxservice now consume this
entrypoint. Executable configuration supplies only credential-free mock targets;
credential-bearing callers remain synthetic. The trusted caller still has to
resolve and bind actual policy, auth, network, context, resources and teardown into the base
pin; hash-shape validation cannot establish that this resolution happened.
The current mock resolver and diagnostic candidate cannot satisfy that real-
provider obligation. Trusted enrollment and exact-object handoff also remain
required before credential use.

## Trusted resolution and service registration

`agentpolicy.Endpoint.SessionScope(actor, conversation)` projects a successful
exact authorization from the already compiled policy. Connector identity comes
from the endpoint; binding fingerprint and target identity/revision come from
the decision. All six fields retain the existing session-scope encoding. Denied
or self-originating pairs produce no scope. Config or returned-value mutation
cannot change the compiled decision. Unrelated policy revision changes do not
become scope changes.

`sandboxservice.WithAuthorityResolver` resolves each immutable registry entry
once during construction. Its trusted local result contains a non-credential
revision pin, explicit Runner-state ownership, and optional credential ref plus
independently approved scope. The service validates the manifest fingerprint,
scope target/revision and scope shape; derives workspace/auth from that manifest;
copies the ref and scope values; and sends the whole registry to strict enrolled
registration. This validates against the database's immutable proof/scope, rather
than deriving the expected scope from enrollment. A resolver error, unknown
profile, invalid scope or registration failure returns no usable service.
Later Run admission and exact replay never re-evaluate the resolver.

The legacy revision-pin and state callbacks remain credential-free compatibility
inputs, using the same strict registration path. They cannot be combined with
the unified resolver. No fallback chooses a different hook, target or digest
after failure. No new configuration schema or wire field is introduced.

`sandboxconfig.ResolveTargetAuthority`, now used by sandboxd, accepts only the
exact configured locked-down mock target, with family `mock`, adapter `0.1.0`,
policy `builtin.locked-down-v1` and three `builtin.none` refs. It returns the
unchanged v1/v2 mock fingerprint and explicit state ownership, with no credential.
This new resolver applies the closed profile matcher to both manifest versions;
legacy standalone hash helpers retain their historical v1 semantics. Reusing a
revision after a resolved workspace mapping changes is still rejected.

The Go credential result is a trusted construction input, not a remote authority
format or a certificate that policy enforcement exists. Only constructed tests
currently supply it. Real Codex network/context/teardown contracts still lack
their executable resolution. Their descriptive identifiers or candidate hashes
cannot produce an executable authority through the public mock resolver.

## Enrollment and authorized re-open

Initial enrollment is an explicit trusted local operator operation. It uses
the exact frozen scope, holds the dedicated source, captures and checks all
pins, validates again, and atomically registers generation plus proof. A
failed or uncertain commit grants no execution authority. Recover by querying
the exact intended immutable record; do not invent another ID/generation or
adopt the current path to make a retry succeed. Enrollment alone launches no
runtime, so releasing its temporary handle is not a Run cleanup decision.

An authoritative re-open is tied to one admitted Run. Do not scan credentials
at startup and turn a successful scan into cached readiness. The order is:

1. Resolve the exact immutable target/generation/proof and scope under trusted
   local policy. Missing or unknown proof blocks real use.
2. Commit the existing RegisterStart transaction, including source/slot Run
   occupancy, before trying to acquire/revalidate the real file. A normal
   admission conflict rejects that Run without retiring another Run's source.
3. Hold the exact frozen locator, query kernel identities from its held objects,
   and compare all pins. Revalidate the held source. File acquisition or identity
   failure for this admitted attempt retires the generation through the existing
   one-way revocation operation; keep Run occupancy through cleanup.
4. Only a successful exact match can proceed to the existing pre-Create intent
   transaction, which must again check unrevoked generation and occupancy.
   This is necessary but not sufficient: the complete target and exact-object
   runtime handoff gates remain mandatory and unimplemented.

Exact request replay retains the existing receipt semantics, including after
revocation. A duplicate delivery never authorizes another Hold, enrollment or
Create. The existing Run's single controller owner drives its lifecycle; the
sequence above is not repeated just because the request was delivered again.

The store/controller portion of this sequence is implemented.
`GetRunCredentialEnrollment(run_id)` joins an accepted Run, its exact retained
occupancy, target and unrevoked generation in one transaction. Unlike the
historical enrollment read, it rejects absent proof, pending Create, runtime
references and staged/terminal outcomes. `RevokeRunCredential(run_id)` derives
the generation from that same retained ownership; an unadmitted contender or
released Run cannot retire another occupant's source.

`WithCredentialBindings` copies trusted local slot bindings into the controller;
no executable configuration or wire request supplies them yet. After admission,
the sole execution worker compares generation, workspace, auth profile and
Run-derived scope, then uses the fixed native Hold/VerifyProof implementation
at the frozen locator. It revalidates before Create, before AttachStart and
after cleanup. The existing intent transaction still checks current revocation
and occupancy. These observations neither close a future mount check/use race
nor attest an actual refresh or runtime's access to the same held object.

Acquisition/comparison failures latch a failed attempt and retire its generation.
Retained handles also fence the execution lane when staging or revocation fails;
reconciliation retries cleanup/revocation without another acquisition. Public
failures use fixed messages and expose no source path or raw diagnostic. Current
integration tests construct proof and replace only the private handle seam.
The native opener's rejection path is exercised on a missing synthetic source;
there is no full native enrolled-source execution canary.

Revocation does not invalidate a previously committed Create intent, retract a
refresh or revoke a provider token. An uncertain or late runtime result must
still attach to the original intent so the exact runtime can be removed.
Failure to persist retirement blocks further authority; it is not a reason to
drop occupancy or replace the source. The restart rule below covers a process
crash between observing failure and committing retirement.

In-place token updates leave identity and generation unchanged. An observed
identity, locator or metadata failure cannot be repaired by automatically
accepting the current path. After cleanup, the operator may explicitly retire
and enroll a higher generation and a new TargetRevision. Existing source
ownership still forbids moving the same SourceDigest to a different slot.

## Restart and release rules

On acquiring exclusive sandbox mutation ownership after process restart,
**retire every generation referenced by retained credential Run occupancy before
authorizing any new credential Create**. Keep the occupancy and runtime intent
or reference for cleanup. This includes an accepted Run that crashed before
Create; the recovery path may not restart it as new work. This uses existing
revocation and occupancy records, not a new recovery service or state machine.

The store transaction and `Controller.New` integration are implemented with
synthetic authority and fake-runtime tests. The caller holds exclusive sandbox
mutation ownership; `sandboxd` already retains its process lock across startup
and shutdown. Retirement precedes Run recovery, the managed-runtime sweep and
worker startup. Any retirement error prevents controller startup, including a
lost response after commit; repeating the transaction is idempotent.
`Store.Open` and ordinary reconciliation do not retire generations. Fresh
accepted Runs in the current process and credential-free mock reoffers retain
their existing behavior. Real enrollment and credential execution remain blocked.

Recover interrupted credential Runs only to discover/stop/remove their exact
runtime and publish the original staged result, or a failure for a never-started
Run. Cleanup must not require re-opening the credential file, a new model call,
new Create or removal of revocation. An already staged result retains the
existing publication semantics after verified cleanup.

Generations with no retained occupancy need no blanket retirement at restart.
Their next admitted Run still performs a fresh exact-pin comparison. Thus an
idle restart does not force re-enrollment; an interrupted credential Run does.
The operator may re-enroll that same physical source at a higher generation
only after verified cleanup and removal of occupancy. This conservative cost
avoids reconstructing authority from a lost file lock or an unrecorded failed
validation. No filesystem observation by an offline diagnostic grants readiness.

When an active Run ends, first establish exact runtime stop/removal and required
descendant quiescence. Then close its held descriptors/locks while durable
occupancy still fences a new Run. Only then call ConfirmRuntimeStopped to
publish/release occupancy atomically. A close error or uncertain cleanup retains
occupancy. Releasing occupancy before closing its old file/slot locks could
cause a successor to acquire the database slot but fail against the old flock.

The controller now applies this order at its central publication boundary. A
close error is latched, retires the generation and prevents publication/release
until process restart recovery; repeating Close cannot turn that error into
readiness. After a successful physical close, the volatile handle entry is
removed before attempting database publication. The durable candidate and
occupancy retain the fence if publication fails, while a committed but lost
response cannot leave a stale volatile handle blocking subsequent work. Cleanup
preserves an already staged outcome even when its generation is retired.

## Required rejection matrix

| Situation | Required behavior |
| --- | --- |
| Fresh process, no retained occupant, all proof/scope values match | Next admitted Run may acquire; all remaining runtime gates still apply |
| Same object, in-place byte update | Same source/generation; this says nothing about refresh persistence or validity |
| Hardlink/symlink or mount crossing below the dedicated root | Hold rejects; the kernel key cannot override unsafe topology |
| Same path and bytes, different auth object | Reject and retire the admitted attempt's generation |
| Same auth object, changed root/slot object or locator | Reject old binding; require explicit higher generation/new target |
| Proof missing, malformed or unknown scheme | No real authority; no implicit upgrade of synthetic enrollment |
| Unsupported filesystem/UUID/handle or query denied | Reject; no stat/path-hash fallback or capability grant |
| Reopen/acquisition fails after Run occupancy commits | Retire generation; preserve occupancy until cleanup |
| Crash before retirement commit or while Create is uncertain | Startup retires the retained occupant's generation; cleanup only |
| Crash after physical locks close but before publication | Retained occupancy triggers the same conservative restart rule |
| Registration replay of a revoked generation | Still revoked |
| Exact Run request replay after revocation or completion | Return its existing receipt; no new acquisition or Create |
| New generation requested before old cleanup finishes | Existing store occupancy rejects it |
| Storage clone/rollback/host migration not explicitly reconciled | Block automatic continuity; storage-lineage authority must be re-established |

## Evidence and implementation boundary

On 2026-09-07 a private synthetic witness on the locally observed ext4 mount,
under the unprivileged operator, obtained a 16-byte filesystem UUID and 8-byte
opaque handle. Fresh Python processes saw identical identity after re-open and
in-place writes. A hardlink and rename retained identity. Same-path, same-byte
replacement produced a different identity, including after prior descriptors
closed. An old retained descriptor continued identifying its original object.
Only owned synthetic files were changed and their directory was removed.

That witness bypassed Hold's trusted-ancestor check and is not an acceptable
credential-root or full-resolver test. It did not implement enrollment, exercise
root/slot proof persistence, restart sandboxd, reboot/remount, force inode reuse,
clone storage, or run actual OAuth. Its result supports the selected syscall
mechanism within one observed filesystem lifetime.

A separate narrow observation on 2026-09-08 confirmed type 1 / 8-byte handles
for synthetic root and slot directories held with O_PATH and for the read-only
auth-file descriptor. Its own fixture was removed. This closed the local handle
shape question; that observation alone did not implement proof comparison,
enrollment or runtime integration.

On 2026-09-08 the Go adapter tests pin the encoding vectors, reject invalid
proofs and unsupported identity forms, and compare every digest independently.
Synthetic held-file tests cover in-place updates, replacement before/during
collection, latched failures, retained locks and concurrent capture/verify/close.
Their private identity reader isolates comparison from filesystem support;
public methods always use the native reader. A tmpfs fixture verifies that the
public CaptureProof API rejects unsupported enrollment storage.

A separate Go test exercised the actual native backend on an owned synthetic
ext4 fixture: root/slot/file handles, UUID collection, stable in-place identity,
an old descriptor retained through path replacement, and a distinct replacement
source digest. It passed locally without a skip, and its fixture was removed.
It bypasses Hold's ancestor check, as did the earlier syscall witness; this is
not a full native CaptureProof test on an approved deployment credential root.
Full Go tests, package race tests and vet passed; no real credential was used.

Schema v11 tests cover exact pair read-back/replay after reopen and revocation,
every digest/scope mismatch, all partial proof-presence combinations, NUL and
other malformed encodings, late transaction rollback, competing registrations,
SQL mutation rejection and corrupted-proof refusal. A v10 migration fixture
retains a revoked proofless generation and its admitted Run occupancy; it cannot
be upgraded in place. These are temporary synthetic databases, not deployed
source enrollment or sandboxd restart evidence.

Startup recovery tests now cover atomic multi-generation retirement, a late SQL
failure with full rollback, reopen/retry, commit-response loss, retirement before
runtime lookup, rejection of old accepted Run reoffers, same-boot uncertain
Create, late runtime cleanup and preservation of an existing staged result.
Idle generations and current-process acceptance remain usable in synthetic
tests. This is constructor/store integration, not a live credential restart canary.

Run integration tests now cover one acquisition under duplicate offers, strict
scope/generation/proof rejection, revocation between the read and intent grant,
replacement during Create, retained handles through cleanup/revocation/staging
failure, sticky close failure, and publication failure before/after commit.
Recovery of an already staged result uses no new Hold or Create. These remain
synthetic controller/store observations, not real credential mount evidence.

The next integration gate is the complete target security fingerprint and its
trusted local resolution, including the enrolled source/proof and exact scope.
Trusted enrollment wiring and exact-object runtime handoff also remain required
before any real credential use.
Do not enable a real target between those steps or repeat the completed generic
bind and synthetic-refresh experiments as unfinished architecture research.
