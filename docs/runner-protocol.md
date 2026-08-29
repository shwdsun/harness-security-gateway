# Harness Runner Protocol v1 (HRP/1)

HRP/1 is the adapter contract intended to let `sandboxd` run different
harnesses without knowing vendor CLI flags or event formats. The shipped target
uses a deterministic mock Runner; a disabled Codex conformance cut exists in
code, while no Claude Code adapter exists. A future deployable provider target
would package one harness and a thin fixed-entrypoint adapter in a reviewed OCI
image.

The protocol is an adapter contract, not a permission negotiation mechanism.
All image, mount, network, auth, resource, and sandbox decisions come from the
operator-approved TargetManifest before the container starts.

## Transport and lifecycle

- One ephemeral container handles one Run.
- UTF-8 JSON Lines are exchanged over stdin/stdout.
- stdout is protocol-only; the adapter captures and translates harness output.
- stderr is bounded local diagnostics and is never forwarded verbatim.
- The runner has no listening port and receives no control-plane/runtime socket.
- Duplicate JSON keys, unknown fields, invalid UTF-8, excessive depth, excessive
  line length, and events beyond configured limits are protocol violations.
- Exactly one terminal event is accepted.

The container rootfs and entrypoint are fixed by an image digest. The semantic
mount contract is:

```text
/workspace          the one target workspace, ro or rw by approved policy
/state              harness state for this target revision, rw
/tmp                bounded tmpfs
```

Those are the only V1 filesystem surfaces. Static harness-adapter configuration
is baked into the reviewed, digest-pinned image; V1 does not mount
`/config/config.json` or accept a dynamic config path.

There is deliberately no generic auth mount. Credential delivery is part of a
harness-specific reviewed policy and must pass a tool-read canary.

## Current Codex adapter cut (disabled)

`internal/codexadapter` and `cmd/codex-runner` implement the first
credential-free conformance cut. Its exact HRP identity is family `codex`,
version `0.1.0-new-only`, with no advertised optional features. A syntactically
valid `run.start` is accepted into the lifecycle before policy or launch work,
so every outcome is a valid `run.started` sequence 1 followed by exactly one
completed, failed, or cancelled sequence 2. Resume input is denied and success
never emits a session token.

The adapter builds one closed `codex exec` invocation. The Run contributes only
the prompt bytes, passed on child stdin; it cannot contribute a model, path,
flag, environment value, auth choice, sandbox mode, feature, or output target.
The selected model name is supplied at runner build time and an empty value
fails before readiness. That removes an ambient model default but does not make
a provider alias an immutable server-side model revision.

The current fixed process contract includes:

- digest-pinned image path `/usr/local/bin/codex`, workspace `/workspace`,
  inner `workspace-write` sandbox, no approvals, no tool network, no login
  shell, untrusted-project mode, and zero project-instruction bytes;
- `--json`, `--ephemeral`, strict config, ignored user config/rules, disabled
  web/apps/browser/computer/image tools, hooks, plugins, multi-agent, memories,
  goals, remote plugin discovery, skill search/dependency install, and bundled
  workspace dependencies;
- ChatGPT-only login with file-only credential storage;
- a writable but disposable `/tmp/hgw-codex-home`, created or attested before
  launch as an owner-only `0700` non-symlink directory containing either
  nothing or only one owner-only, single-link regular `0600` `auth.json`, with
  `CODEX_SQLITE_HOME=/tmp/hgw-codex-runner`; neither variable enters the model
  tool environment;
- prompt-free argv, bounded and non-forwarded JSONL/stderr diagnostics, and
  active child cancellation on the first diagnostic-limit violation;
- a pre-created owner-only final-output inode. Success requires the path still
  names that same regular single-link inode, exact mode, bounded nonblank UTF-8
  without NUL, zero child error, and no pinned Codex final-write failure marker.

No Codex target is shipped or selectable from the example configuration. The
current Docker runtime accepts only `builtin.none` auth/network profiles and
`--network none`; there is no image, TargetManifest, auth-file bind, or provider
egress profile for this adapter. Before enablement, the runtime profile must keep the whole
`CODEX_HOME` disposable and bind only a dedicated refreshable `auth.json` file.
The image must also prove, rather than infer, that repository config, managed or
system skills, hooks, plugins, MCP, and other extension sources do not enter the
model context. No public provider canary currently proves that closure, so the
gate remains failed closed.

The launcher signals the original process group with TERM then KILL. A detached
descendant can leave that group; therefore the adapter result is not sufficient
quiescence evidence. Container-level tests must prove teardown before release
of a successful result, including leader-exits-first and `setsid` descendants.
The digest-pinned image must also canary the CLI's retained-inode write behavior,
credential refresh/lifetime, exact residual writes, and model-control versus
tool-egress separation.

## Startup handshake

The first runner frame is:

```json
{"protocol":"hrp/1","type":"runner.ready","adapter":{"family":"codex","version":"0.1.0-new-only"},"features":[]}
```

Features describe protocol behavior; they never grant filesystem, network, or
credential authority. `sandboxd` checks the frame against the pinned manifest.

It then sends exactly one start frame:

```json
{"protocol":"hrp/1","type":"run.start","run_id":"01JEXAMPLE","target_revision":"project-codex-r1","input":{"media_type":"text/plain","text":"Inspect the project"},"session":{"mode":"new"},"deadline_unix_ms":1786900000000}
```

For a future adapter revision that advertises resume, a resume request is
resolved by `sandboxd`, never supplied by chat. The current Codex adapter does
not advertise this feature and rejects resume mode:

```json
{"session":{"mode":"resume","token":"vendor-token-known-only-inside-the-sandbox-domain"}}
```

The vendor token never leaves the sandbox domain. `sandboxd` maps it to a random
opaque `SessionRef` bound to the exact target revision and to the
domain-separated digest of the complete Core authorization scope. `agentd`
stores only that opaque reference under its six-field scope. The digest is a
control-plane invariant between `agentd` and `sandboxd`; it is never emitted in
HRP/1 and is not exposed to the runner.

## Events

Every Run event has the same `run_id` and a contiguous `seq` beginning at one.

```json
{"protocol":"hrp/1","type":"run.started","run_id":"01JEXAMPLE","seq":1}
```

Sanitized progress is optional:

```json
{"protocol":"hrp/1","type":"run.progress","run_id":"01JEXAMPLE","seq":2,"kind":"status","text":"Inspecting the project"}
```

V1 progress kinds are only `status` and `output_delta`. The runner cannot choose
who sees progress; `agentd` owns presentation policy.

Success contains bounded plain text. A `new_only` target must omit the vendor
session token; every successful `opaque_resume` Run (both initial and resumed)
must return a non-empty successor token:

```json
{"protocol":"hrp/1","type":"run.completed","run_id":"01JEXAMPLE","seq":3,"output":{"media_type":"text/plain","text":"Inspection complete"},"session_token":"opaque-vendor-token"}
```

`sandboxd` replaces that private token with a freshly generated one-use public
`SessionRef` in the durable execution result. Empty, missing, or mode-inconsistent
tokens are rejected before a successful terminal event is committed.

Failure uses a closed error-code set:

```json
{"protocol":"hrp/1","type":"run.failed","run_id":"01JEXAMPLE","seq":3,"error":{"code":"harness_error","message":"Sanitized bounded message"}}
```

V1 runner error codes are `input_rejected`, `invalid_session`, `policy_denied`,
`harness_error`, and `runner_internal`. Container exits, timeouts, output-limit
violations, and malformed protocol are classified independently by `sandboxd`;
runner claims are not trusted.

Typed artifacts are intentionally deferred until text-only Codex and Claude
conformance proves the common contract. Workspace patches can initially be
computed and bounded by `sandboxd`, rather than accepting a runner-supplied host
path.

## Cancellation and deadlines

`sandboxd` is the enforcement authority. On cancel or deadline it signals the
container, waits a short fixed grace period, then kills the container through
the runtime. The adapter may translate `SIGTERM` into harness-native graceful
cancellation and emit `run.cancelled`, but correctness never depends on it.

An interrupted writable Run is not automatically retried. In particular, an
uncertain container create is never followed by a second create. On the same
host boot, one absent intent lookup does not release the workspace lock; only
cleanup of the exact verified container, or an absent lookup after a host boot
change for a non-legacy boot-tagged intent, can do so. Legacy pending intents
without a boot ID require explicit operator recovery. Supported automatic
migration never creates that state: a non-empty pre-v3 sandbox database is
rejected unchanged and requires reviewed cold migration.

## Forbidden fields

Neither HRP/1 nor `agentd -> sandboxd` may contain user-selected image, argv,
entrypoint, shell command, host/container path, environment map, mount, network
mode, proxy credential, API key, Linux capability, device, UID/GID, runtime
socket, sandbox bypass, vendor flags, raw platform payload, raw stderr, or an
open-ended `options`/`metadata` object.

## Evolution

- Unknown fields are rejected within HRP/1.
- Incompatible changes use a new protocol name such as `hrp/2`.
- A new optional feature gets a closed schema understood by `sandboxd` and the
  adapter before a target may require it.
- `sandboxd` never transparently forwards an extension it does not understand.
- A new harness should require only a new conforming image and TargetManifest;
  vendor branches in `agentd` are a design failure.
