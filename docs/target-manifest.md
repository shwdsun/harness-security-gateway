# Target manifests and Runner state

A TargetManifest is local operator-authored data, never a remote request.
Accepting its syntax is not permission to execute it. Local `sandboxd/v2`
configuration accepts only `harness-target/v1`. Explicit `sandboxd/v3`
configuration also accepts v2 through the same registry, ownership store,
controller, HRP bridge and Docker runtime. V2 execution is restricted to the
built-in credential/network-free mock envelope; real providers remain disabled.

## Closed v2 state contract

V1 always requires a logical `state_ref`. V2 replaces that field with exactly
one required `runner_state` object:

```json
{"kind":"none"}
```

or:

```json
{"kind":"persistent","ref":"project-state"}
```

`none` means no persistent Runner-state resource. It does not mean no workspace,
an ephemeral workspace, no credential slot, or a guarantee of erasure. Workspace
persistence and access remain separate decisions. `persistent` names one logical
reference, not a host path; the local sandbox resolver must approve, resolve and
ownership-bind it. The manifest parser does none of those operations.

| Runner state | Session mode | Contract result |
| --- | --- | --- |
| `none` | `new_only` | Allowed, with zero session age/turn limits |
| `none` | `opaque_resume` | Rejected; no local persistent session resource |
| `persistent(ref)` | `new_only` | Allowed; storage persistence does not imply resume |
| `persistent(ref)` | `opaque_resume` | Allowed with `session.resume` and positive bounded age/turn limits |

The restriction on `none` is the initial local-resume contract, not a claim
that every possible harness needs a local directory to resume. Remote native
continuity would need its own reviewed contract, not a hidden fallback.

For the state object, omission, `null`, non-objects, missing/unknown kinds,
extra keys, or any `ref` key on `none` (including empty/null) are invalid.
`persistent` requires a nonempty valid logical ref. V2 rejects `state_ref` in
every form, including empty/null. All v2 field names are exact and case-sensitive,
including nested Runner and limits fields; case aliases cannot overwrite an
earlier field. Duplicate keys, trailing values, invalid UTF-8, documents over
64 KiB and nesting over eight levels are rejected. V1 JSON acceptance is not
changed by this stricter v2 boundary. Embedded targets now also pass through
their standalone 64 KiB/eight-level decoder, within the outer configuration's
1 MiB/fourteen-level limit. Oversized legacy embedded targets may therefore be
rejected earlier; legacy semantic hashes and canonical bytes do not change.

## Go API and fingerprints

`targetmanifest.Manifest`, `Decode`, `Validate` and `Fingerprint` remain v1.
`ManifestV2` and `DecodeV2` remain separate wire APIs.
V2's JSON unmarshaler also uses the strict boundary when embedded in another
document. `RunnerState` has private fields and constructors `NoRunnerState()`
and `PersistentRunnerState(ref)`. The zero value and invalid persistent refs
fail validation; constructors do not approve resources. `PersistentRef()` returns
`(ref, true)` only for the persistent kind, never a synthetic ref for `none`.
Failed decoding leaves an existing value unchanged.

`Definition` is the immutable version-aware carrier. `FromV1`, `FromV2` and
`DecodeDefinition` retain exactly one original validated wire struct, with
private copies of slice data. Validation, serialization and fingerprints use
that original, never a reconstructed cross-version manifest. `Common()` returns
a disposable read view; modifying it cannot change authority. There is no
v2-to-v1 conversion. Legacy `targetregistry.New` delegates to the same
`NewDefinitions` implementation, not a second execution path.

Both fingerprints validate first, exclude only `revision`, copy-sort required
features without mutating the caller, and hash canonical JSON. The field order
of each explicit Go wire struct is part of that canonical form. V2 includes
state kind/ref and uses `harness-gateway.target-manifest/v2` followed by a NUL
byte as its SHA-256 domain. V1 retains its exact v1 domain and canonical bytes.
Domain separation prevents cross-version input ambiguity; digest identity still
relies on SHA-256 collision resistance. The shared normalization retains the
legacy empty-feature-array-to-`null` canonical form for hashing; valid input
documents still require a feature array.

Compatibility and mutation coverage are in
`internal/targetmanifest/v1_compatibility_test.go`, `fixture_test.go`,
`manifest_v2_test.go`, `v2_boundary_test.go` and `definition_test.go`.
Config tests enforce the explicit version gate, including resolver helper APIs.

## Local configuration and durable ownership

V3 requires an explicit `runner_states` array, which may be empty. All storage
roots retain their path/ownership checks. A `none` target performs no state-ref
lookup or per-target state-path stat, creates no state leaf, owns no
`runner_state_owners` row and receives no `/state` mount. The common private
state namespace root may exist. Dormant catalog entries do not request leaf
creation or runtime inspection. Persistent targets retain approved mapping,
private-directory checks and exclusive historical ref/path ownership.

Sandbox schema v9 records an immutable `runner_state_kind` on each
TargetRevision. Absence of an owner row never means `none` implicitly.
Eligible historical v1–v8 migration strings and checksums remain unchanged;
v6–v8 revisions must prove complete existing ownership before v9 DDL. Older
refusal gates still apply. Reopen rejects contradictory kind/owner/session
evidence. Batch registration is atomic, including mixed versions/kinds.
Changing schema, kind, fingerprint, or historical state owner requires a new
revision and, for persistent state, an unclaimed namespace; editing the old
revision or deleting history is not migration.

The v1 resolved revision fingerprint retains its exact domain and byte framing.
V2 uses `harness-gateway.sandboxconfig.revision-security/v2`, length-framing
manifest fingerprint, workspace path, state kind, persistent ref/path only when
present, and runtime kind/endpoint/socket/CLI. This binds the built-in mock's
resolved authority, not unimplemented credential or profile content. Enabling
such authority requires a separately reviewed resolver/fingerprint domain.

The strict [enrolled-target registration](credential-source-enrollment.md#implemented-credential-targetrevision-composition)
now combines a caller-supplied non-credential authority pin with the stored
credential source/generation/proof and independently approved exact scope under
`harness-security-gateway.sandboxstore.credential-target/v1`. It preserves
credential-free pins and performs the read and registration in one transaction.
It does not turn the mock fingerprint or diagnostic candidate into complete
real-provider authority; that provider content resolver remains absent.

Default sandboxd obtains each mock entry's base pin and state ownership from
`sandboxconfig.ResolveTargetAuthority`, then sandboxservice registers the whole
batch through that strict entrypoint. Resolution accepts only the exact configured
locked-down mock projection in both v1 and v2; credentials are absent. The
historical standalone v1 hash helper is unchanged, but cannot be substituted for
the stricter executable resolver. A trusted credential resolver must also
supply the independently approved six-field scope, matching the target/revision;
the service derives workspace/auth from the manifest and hashes the exact scope
before transactional enrollment comparison. Resolver failure never falls back
to a legacy hook or diagnostic candidate.

The explicit [fixed Codex daemon](codex-daemon-startup.md) uses
`sandboxd/codex-v1` and a separate checked owner/artifact/provider factory. It
supplies one no-state V3 target, its frozen credential binding and independent
approved scope to the same registry/service/controller. Normal mock schemas
cannot select it; no legacy fingerprint encoding or execution wire changes.

## Mock artifact and evidence boundary

Within the mock configuration, v2 matches only family `mock`, adapter `0.1.0`, policy
`builtin.locked-down-v1` and three `builtin.none` refs. Image digests, resource
limits, workspace and session policy remain explicitly pinned. Unsupported
provider profiles fail before a Docker CLI call; configuration alone cannot
enable them.

The existing mock image always returns a synthetic session token and is for
`opaque_resume`. The Dockerfile's `new-only` build target fixes a token-free
profile into the executable; it advertises no resume feature and takes no
runtime profile option. Pair `none` / `new_only` with that artifact, not the
legacy image. Wrong pairings fail closed at the HRP boundary. See the
[runbook](runbook.md#optional-v3-no-state-mock) for local configuration.

Tests cover both mount shapes using a fake CLI, a real compiled new-only mock
process through the production bridge, and v3 config-to-controller/store
recovery under failed runtime cleanup. None still holds the workspace writer
lock and withholds terminal output until cleanup is confirmed. These are local
test results, not live Docker or provider-containment evidence. Connector,
Core and HRP wire shapes are unchanged. Real image, credential, network,
context and teardown gates remain in [Codex Profile v1](codex-profile-v1.md).
