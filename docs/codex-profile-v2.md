# Codex Profile v2: private messaging behavior

Status: **sealed candidate contract; blocked and not production-selectable**

Codex Profile v2 adds one fixed, non-secret behavior profile for a private,
asynchronous messaging Target. It does not add authority. Connector, Core,
execution-wire, HRP/1, workspace, credential, network, tool, session, and
teardown semantics remain unchanged from the blocked v1 candidate.

The code sources of truth are `internal/codexprofile` and
`internal/codexadapter`. The sealed identifiers are:

```text
messaging instruction raw text bytes:    1508
messaging instruction raw text SHA-256:  d25b789221c619f3b879f6f5718d07ef1ac466ed6f712ebe20c22d9958f9c9c6
messaging instruction profile SHA-256:   1e4af42e7e6778a46cca4637eedf6cccb7f1b90556c867ecaf478db908720369
Codex Profile v1 SHA-256 (unchanged):     96ca4f1845f5ee673d7302fb938e698d1344435d62280b8174e31200738f143d
Codex Profile v2 SHA-256:                 d8ee4889edd0bac79fd8ee6278bf10c06a29b0dcdc743433ecad17a5cee0aa68
```

The profile fingerprints hash the domain string, one NUL byte, and Go's JSON
encoding of the complete comparable struct. Their domains are respectively:

```text
harness-security-gateway.messaging-instruction/v1
harness-security-gateway.codex-profile/v1
harness-security-gateway.codex-profile/v2
```

These fingerprints are audit and change identifiers. They detect accidental or
reviewed semantic drift; they are not an integrity guarantee against a
compromised build or host. Any instruction text or contract-field change
requires new fingerprints, a new adapter identity, and a new TargetRevision.
V1's encoded value and fingerprint remain unchanged.

## Ownership and injection

The instruction profile is Target/Runner-owned immutable context. It is not a
Connector wrapper, message prefix, conversation transcript, workspace file,
skill, or remotely selectable option. For Codex CLI 0.151.0, the adapter JSON
encodes the exact compiled text as a TOML-compatible string value and supplies
exactly one fixed argument pair:

```text
--config developer_instructions=<JSON-quoted exact text>
```

The validated `RunStart.input.text` bytes pass unchanged to stdin at the final
`-` argument and are never concatenated with the developer instructions. The
exact-CLI canary separately verifies their placement in a user-role part. V2
reports this distinct runner identity:

```text
family:   codex
adapter:  0.2.0-new-only
protocol: hrp/1
features: []
```

Profile selection is closed local configuration. The private experiment fixes
`MessagingConfig` and `project-codex-r2`; Connector messages and HRP frames
cannot provide a profile ID, instruction text, CLI argument, environment
variable, or runtime option. Unknown or empty local profile IDs fail before
`runner.ready` and before process launch.

An adapter for another harness may support equivalent behavior only by mapping
a reviewed, content-bound profile to that harness's native higher-priority
instruction channel. If it cannot keep operator context separate from user
input, it must reject the profile instead of concatenating a prompt.

## Embedded interaction envelope

The exact instruction text defines these UX facts for this revision:

- one message starts one independent `new_only` Run;
- the workspace persists, but prior chat context does not;
- the Run has about five minutes and should leave a bounded, verified result;
- one self-contained final answer is returned in the user's language;
- the model is asked to stay below 1,500 UTF-8 bytes because this experiment's
  Connector conservatively rejects a result above 2,000 UTF-8 bytes;
- a longer deliverable may be stored in the workspace and referenced by a
  workspace-relative path.

Changing any of these model-visible facts requires a new instruction profile
and TargetRevision. The current path has no progress stream, remote file
retrieval, session resume, or deterministic output splitting. Those are
separate protocol/product changes, not prompt edits.

## Intended behavior, not a security boundary

The profile asks the harness to answer, investigate, or change according to the
request; do and verify requested work when possible; preserve unrelated state;
and report only the useful result and honest blockers. It also tells the model
that messages and workspace content are untrusted task data.

None of that authorizes tools or prevents prompt injection. Binding,
TargetRevision, sandbox, mounts, credential policy, network mediation, and
lifecycle enforcement remain the security boundary. The 1,500-byte request is
probabilistic UX guidance. A Connector must enforce the platform limit; the
current public repository still has no Discord Connector.

The adapter fixes `project_doc_max_bytes=0`, an untrusted-project declaration,
and the exec-only `--ignore-user-config --ignore-rules` controls to suppress
project-level context discovery. In the bounded debug canary, the three named
workspace sentinels were absent. That observation does not prove complete exec
context closure or make workspace content harmless: tools may still read that
content as untrusted task data, and it may influence the result.

## Exact CLI canaries and their limit

Unit tests pin the complete exec argv/environment and prove that hostile user
text is byte-exact stdin, never argv or environment. The opt-in
`TestCodexPromptInputCanary` additionally runs the exact Codex CLI 0.151.0
against an empty owner-only `CODEX_HOME` and hostile `AGENTS.md`, `codex.md`,
and `.codex/config.toml` fixtures. It proves that the exact instruction text
appears once in a developer-role part, the hostile message appears once in a
user-role part, and those workspace sentinels are not auto-promoted.

The debug subcommand does not accept the exec-only
`--ignore-user-config --ignore-rules` flags. Consequently this canary proves
configuration decoding and role placement under its empty-home fixture, not
complete equivalence with `codex exec` or complete model-context closure. A
sealed image still needs a provider-facing or equivalent full exec canary.

## Experimental and release boundary

The private vertical slice uses `project-codex/project-codex-r2`. That
experiment has no target-registry row or revision-security fingerprint. Its
substitute evidence is the shim's compiled exact revision, the matching
operator-owned agentd binding configuration, and recorded source/config/binary
digests. These identify the experiment but do not satisfy the production
resolver gate.

A future target schema/resolver must bind the resolved instruction fingerprint,
adapter and image digest, all authority-bearing profiles, and the local
credential binding before V2 can become production-selectable. All v1 readiness
gates still apply, including credential/egress containment and terminal release
only after outer-runtime quiescence.

Official interface reference: [Codex configuration
reference](https://learn.chatgpt.com/docs/config-file/config-reference).
