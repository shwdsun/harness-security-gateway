# Codex Profile v1

Status: **sealed contract; blocked and not selectable**

This document freezes the first Codex-specific runtime contract without
enabling a Codex target. The contract belongs behind `sandboxd`; it is not a
Connector field, HRP feature, message option, generic mount API, or statement
that a production security boundary exists.

The code source of truth is `internal/codexprofile`. Its complete semantic
fingerprint is:

```text
96ca4f1845f5ee673d7302fb938e698d1344435d62280b8174e31200738f143d
```

Changing any contract field requires a new versioned profile and a new target
revision. Credential bytes are deliberately absent: normal token refresh must
not rewrite target authority, and secret digests must not enter public or
durable control-plane evidence.

This v1 value remains unchanged and injects no operator instruction profile.
The separate blocked `codex-profile-v2.md` candidate owns the fixed private-
messaging behavior and a distinct adapter/TargetRevision identity.

## Manifest projection, not a conforming manifest

The existing TargetManifest continues to carry only closed logical refs. The
following fields are the part of the candidate contract that TargetManifest v1
can express:

| Field | V1 value |
| --- | --- |
| runner family / adapter / protocol | `codex` / `0.1.0-new-only` / `hrp/1` |
| HRP features / session | none / `new_only` |
| policy | `codex.locked-v1` |
| auth | `codex.chatgpt-file-personal-v1` |
| skills | `builtin.none` |
| network | `codex.provider-control-v1` |
| persistent runner state | none; not expressible by TargetManifest v1 |

The contract ID `codex.chatgpt-personal-v1` names the candidate combination; it
does not add another remotely selectable Target field. This table is not a
successful Manifest matcher: every valid TargetManifest v1 has a nonempty
`state_ref`, while this profile forbids persistent Runner `/state`. A future
versioned target schema must represent that difference before a total profile
matcher or resolver exists. The current runtime still accepts only
`builtin.locked-down-v1` plus three `builtin.none` refs for the mock path and
explicitly rejects the Codex runner identity and four profile-ref projection
before any Docker call.

## CLI and model

| Field | V1 value |
| --- | --- |
| Codex CLI | `0.151.0` |
| artifact platform | `x86_64-unknown-linux-musl` |
| image path | `/usr/local/bin/codex` |
| candidate binary SHA-256 | `9739cbc928b9c573be83256acd46668f5dd4f119d2d09e05246895ca2aaf0c9a` |
| model | `gpt-5.6-sol` |
| reasoning effort | `medium` |
| model identity claim | provider alias; server-side behavior may drift |

The digest identifies the selected candidate binary bytes. It is not image
provenance or proof that the future image contains those bytes. A digest-pinned
OCI image, fixed entrypoint, build receipt, and in-image canary remain required.
The adapter now rejects any other model or reasoning effort before emitting
`runner.ready`; image construction must still supply the exact model build
value.

Official OpenAI documentation lists `gpt-5.6-sol` for Codex CLI and documents
`model_reasoning_effort`. It also states that file credential storage uses
`CODEX_HOME/auth.json`, that the file contains access tokens, and that ChatGPT
sessions can refresh during use. Those interface facts motivate this contract;
they do not establish the isolation claims below.

## Credential and mutable state

The credential classification is always `credential-exposed-personal` until a
stronger claim is supported by adversarial evidence.

```text
local credential slot:  unresolved; not part of this reusable contract
scope rule:              exact-workspace-auth-profile-v1
scope key:               (workspace_ref, auth_profile_ref)
login/store:             chatgpt / file
container credential:   /tmp/hgw-codex-home/auth.json
mount shape:             one dedicated RW file bind

CODEX_HOME:              /tmp/hgw-codex-home, per-Run disposable tmpfs
CODEX_SQLITE_HOME:       /tmp/hgw-codex-runner, per-Run disposable tmpfs
persistent harness data: auth.json only
```

The future local authority must resolve the exact scope key to an opaque
credential slot under a dedicated root and attest a regular, owner-only `0600`,
single-link file with no symlinked path component. The slot ref, generation,
and resolved local source identity are deployment authority and deliberately
absent from this reusable contract. Every TargetRevision that uses the binding
must include those values in a new revision-security fingerprint; token bytes
must not. The resolver must never mount the user's normal Codex home, its
parent, a persistent whole `CODEX_HOME`, or credentials through `/state`.

The scope rule does not assert that a Target, Binding, Cell, or future Instance
is a confidentiality boundary. Before any egress-enabled target is selectable,
deployment validation must reject overlapping resolved workspace, state, or
credential domains across actors unless the operator explicitly declares the
domain shared. No such shared-domain mechanism exists in this slice.

Codex Profile v1 intentionally has no persistent Runner `/state`. The current
TargetManifest requires a state ref and the current Docker runtime always
mounts it RW, so the profile is not yet representable. That conflict must be
resolved explicitly in the next schema/runtime slice rather than silently
allowing mutable state.

The auth slot also needs an exclusive writer lock. A failed, cancelled, or
crashed Run may already have refreshed the file; refresh is not transactional.
A real container canary must determine whether Codex refresh uses an in-place
write or rename replacement. Failure of a single-file bind must not be worked
around by mounting the whole directory.

## Network, context, and release

- Codex control traffic requires a versioned, content-bound mediation policy.
  Model-generated tools receive no network authority; loopback, private/LAN,
  link-local, metadata, arbitrary DNS, and other destinations remain denied.
  A domain allowlist alone is not a mediation proof, and an allowed provider
  channel can still carry arbitrary data.
- Project instructions, user or managed customization, and dynamic extensions
  such as skills, hooks, plugins, MCP, apps, memories, goals, multi-agent, and
  remote discovery have an empty allow-set. Workspace content remains readable
  untrusted data; the profile does not claim that repository files are absent.
- One ephemeral container owns one Run. A Runner terminal result is provisional
  until `sandboxd` proves the exact container is stopped and removed and no
  detached descendant remains. Only then may output become `completed` and the
  workspace and credential locks be released.

## Readiness gates

The local derived lifecycle is `disabled -> blocked -> ready -> retired`; it is
not remotely writable and is not a new orchestration state machine. V1 remains
`blocked` until all of the following have evidence for the exact contract
digest and image digest:

1. a reproducible, digest-pinned image contains the selected CLI bytes and
   fixed adapter entrypoint;
2. a versioned target schema adds a closed `none` versus `persistent(ref)`
   Runner-state union without changing TargetManifest v1 or its fingerprint;
3. a new local resolver performs total target/profile matching and binds the
   contract digest, resolved policy/auth/network content, any nontrivial skill
   content, and credential slot ref/generation/source identity into a new
   revision-security fingerprint while preserving the legacy
   locked-down/three-none fingerprint;
4. deployment confidentiality-domain validation passes, and the runtime safely
   resolves and exclusively locks the exact auth file while proving refresh and
   residue behavior;
5. provider control traffic succeeds while tool and private-network egress fail;
6. hostile workspace, system and managed customization canaries show that no
   unapproved context or extension is loaded; the latest recorded CLI 0.148
   system-skill canary failed, and the selected 0.151 candidate has no exact
   image PASS evidence;
7. a generic durable mechanism stages terminal output without disclosure,
   proves stop/removal and descendant quiescence, then atomically publishes the
   terminal state and releases locks; cancellation, deadline, TERM resistance,
   leader-exits-first and `setsid` descendant tests all pass, with no
   Codex-specific controller branch; and
8. subscription login, refresh, revocation, loss, cross-domain isolation and
   output/log redaction pass with a disposable dedicated identity.

Configuration/unit tests prove only the sealed value, adapter invocation shape,
fingerprint coverage, and fail-closed runtime rejection. They are not evidence
for any of these live gates.

## Explicit non-goals for this slice

- no sandboxd v3 profile registry or auth host path;
- no image, TargetManifest, Docker network, proxy, credential, login, or model
  request;
- no generic environment, mount, network, provider-options, or credential API;
- no resume, remote `auth.begin`, Discord Connector, dynamic skills, or new
  harness abstraction; and
- no change to Connector, agentd, execution wire, or HRP/1.

Official references: [Codex authentication](https://learn.chatgpt.com/docs/auth),
[Codex models](https://learn.chatgpt.com/docs/models), and
[Codex configuration reference](https://learn.chatgpt.com/docs/config-file/config-reference).
