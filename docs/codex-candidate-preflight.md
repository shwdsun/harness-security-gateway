# Offline Codex candidate preflight

Status: **implemented, local-only, always blocked for execution**.

This is a configuration diagnostic, not another deployment control plane.
`hgwctl codex check` checks one proposed Target and credential binding without
registering it, opening a daemon database, acquiring a runtime lock, invoking
Codex/Docker, or contacting a provider. No message, Connector or Core protocol
accepts this document or its report. The private experimental shim does not
consume it either.

## Use

After `make build`, copy the [V3 tools example](../config/codex-tools-candidate.example.json)
to an operator-owned regular file, mode `0600` (a non-group/other-writable
`0644` file is also accepted). Keep local paths and slot names private. For
example, once a private operator directory already exists:

```sh
install -m 0600 config/codex-tools-candidate.example.json /private/operator/codex-candidate.json
./bin/hgwctl codex check -config /private/operator/codex-candidate.json
```

Replace the illustrative destination with your actual private directory.
The shipped image digest and paths are placeholders, not a runnable target.
The [older V2 example](../config/codex-candidate.example.json) remains unchanged
for compatibility. V3's fixed package and native settings are documented in
[the tool-package template](codex-profile-v3.md).
Default checking reads only this configuration, so nonexistent workspace and
credential paths do not prevent structural validation. It emits one JSON
report with `configuration: valid`, `local_metadata: not_checked` and
`status: blocked`.

Explicitly opt in to read-only local metadata observations with:

```sh
./bin/hgwctl codex check -config /private/operator/codex-candidate.json -inspect
```

Exit codes: **3** = structurally valid but execution blocked (inspect findings
may still reject the local layout); **1** = invalid/unreadable configuration or
I/O failure; **2** = invalid command arguments. This command never returns
success/ready. Scripts must inspect the exit code and JSON instead of treating
any report as admission. `go run` wraps a child exit of 3 in its own exit of 1;
use the built binary when checking exit codes. Existing `hgwctl session`
commands retain their prior success/error behavior.

## Closed configuration ownership

`codex-candidate/v1` has exactly five top-level fields:

| Field | Owner and meaning |
| --- | --- |
| `schema` | Exact candidate document version, not `sandboxd/v3` |
| `profile_id` | Local selection of one sealed Codex v1/v2/v3 contract |
| `target` | Complete original TargetManifest v2 with explicit non-null fields |
| `workspace` | One logical `ref` and canonical absolute local `path` |
| `credential` | Exact workspace/auth scope, opaque `slot_ref`, positive signed-64-bit-range `generation`, dedicated `root`, and one canonical `directory` component |

The only credential filename is `auth.json`, resolved as
`credential.root/credential.directory/auth.json`. Refs are never paths. The
workspace and auth refs must exactly match the target and sealed contract.
Roots cannot be `/`, relative, unclean or lexically overlapping. Slot directory
names use lowercase ASCII letters, digits, `_`, `-`, `.`; no leading dot,
separator, `.`/`..`, or `auth.json` directory is accepted. Duplicate, unknown,
case-aliased, missing and null fields fail. There are no token, command, argv,
environment, mount, network-options, evidence, fingerprint-input or ready
fields.

The matcher requires exact runner family/adapter/protocol/features, profile
refs, `new_only` and `runner_state: {kind: none}`. V1 manifests remain
persistent and cannot match either Codex contract. As a conservative product
envelope, messaging profiles v2/v3 additionally require `rw`, 300 seconds and a
2,000-byte output limit. The effective deadline may be shorter due to Core's
deadline and startup time. Other validated manifest limits remain explicit
operator choices and are fingerprinted. V1's sealed values are unchanged.

The slot DTO exists once in `internal/credentialsource` and is reused by the
candidate with unchanged JSON order and diagnostic digest. That package also
contains an isolated Linux held-file primitive; this diagnostic never calls it.
The sandbox store separately implements durable generation/occupancy records
with synthetic authority. This diagnostic neither enrolls nor consults them;
see [credential lifecycle](credential-source-lifecycle.md). No generic credential
catalog or new daemon is introduced.

## What inspection proves—and does not

`-inspect` uses only path metadata and directory-entry names. It never opens,
reads, parses or hashes the configured auth file's content, creates/chmods
paths, logs path/UID values, or tests subscription authentication.

The workspace, credential root and slot must be current-UID `0700` directories;
the file must be current-UID regular `0600`, single-link and non-symlink. Every
observed prefix must be a non-symlink directory owned by root or the current
UID, without group/other write access except root-owned sticky ancestors such
as `/tmp`. A slot may contain only `auth.json`. Root-operator inspection is
reported `inconclusive`. Unknown/remapped ancestor ownership is not trusted.

These are **non-atomic observations**, not a source lease, live revalidation,
mount attestation or proof against races. They do not detect every bind-mount
alias or cross-actor shared domain; do not establish that this is a dedicated
identity or a valid/revoked login; and do not prove refresh or residue behavior.
Normal-home detection does not rely on ambient `HOME`/`CODEX_HOME` heuristics.
Never use the normal user's Codex home as a deployment source. A future
resolver must attest and hold the exact dedicated source under exclusive
ownership, with refresh and revocation semantics, before mounting anything.

## Diagnostic fingerprint, not revision authority

The report prefixes its digest with `codex-candidate/v1:` so it cannot
accidentally satisfy the existing 64-hex revision-pin validators. This is an
accidental-misuse guard, not protection against a trusted programmer stripping
the prefix or forging a new report.

The digest is SHA-256 of `harness-security-gateway.codex-candidate/v1`, NUL,
then the canonical closed Go JSON tuple, in this order: schema, profile ID,
complete sealed profile fingerprint, authoritative manifest fingerprint,
explicit revision, workspace mapping, complete credential binding. Revision
is explicit because the manifest fingerprint excludes it. Whitespace and
object ordering do not change the digest. V1/v2 mock execution-pin algorithms
are untouched.

No token bytes or file size/mtime/inode are hashed. Refresh, including replacing
an inode, does not itself change the configuration identity. Generation is
only an operator label here: the check does not consult historical monotonicity,
revocation or slot-ownership records. Changing scope, generation or path changes
the candidate digest but does not revoke or update any actual runtime authority.

The executable content behind policy/auth/network refs is still unresolved.
The report always lists image provenance, model/tool compatibility, network
mediation, context closure, credential lifecycle, confidentiality domains,
revision-security binding and real-runtime canaries as blockers. Desired
contract strings and matching filesystem permissions cannot substitute for
those mechanisms or evidence.

`model_tool_compatibility` identifies an unresolved candidate configuration,
not a live CLI or provider inspection. On 2026-09-08, the exact pinned CLI's
`debug models --bundled` reports `gpt-5.6-sol` as `code_mode_only`, while both
V1/V2 adapters disable Code Mode host. The old fixture observed an empty
top-level tools array and a host-disabled diagnostic. On 2026-09-09 the V3
investigation found namespaced tool definitions in `input.additional_tools`;
that old array check alone does not prove complete tool absence.

V3 now configures and pins the native host, and has bounded component evidence.
It still lacks accepted image/provider/tool execution evidence, so this offline
check retains the blocker for all profiles. It neither verifies the package nor
inspects a provider catalog. The synthetic direct-mode catalog is not promoted
into V3. See [V3's current gates](codex-profile-v3.md) and
[the earlier integration evidence](codex-exec-integration.md).
