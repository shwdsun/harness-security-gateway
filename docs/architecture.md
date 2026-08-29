# Architecture

## Product boundary

The intended Harness Security Gateway boundary owns transport, identity,
durable routing, Run lifecycle, and containment. A selected harness would own
reasoning, tools, harness-specific skills, and any internal subagents. The
shipped path currently uses only the deterministic mock Runner; no Codex,
Claude Code, or messaging-platform target is enabled.

`live` means the entrypoint and state are persistent. Harness processes are
created for a Run and are not permanent agents.

## Trust domains

| Component | Owns | Must not own |
| --- | --- | --- |
| Connector instance | one platform credential and platform protocol | Core DB, workspaces, model credentials, runtime socket |
| `agentd` | exact bindings, inbox/outbox, Runs, opaque session refs | workspaces, model credentials, container runtime |
| local `hgwctl` | offline status and compare-protected reset for one configured Binding | raw scope selection, sandbox DB, vendor token, runtime or remote control |
| `sandboxd` | target manifests, workspace locks, harness state, runner runtime | platform credentials, Core DB |
| Runner container | one workspace and one bounded Run capability | platform credentials, Core DB, runtime socket, other targets |
| Auth proxy, when enabled | provider credentials and narrow model egress | workspace, platform credentials, runtime socket |

Connector and runner containers are both adapters, but they are deliberately
asymmetric:

| | Connector | Harness runner |
| --- | --- | --- |
| Lifetime | long-running per platform account | ephemeral per Run |
| External authority | asserts facts observed on one platform | none; all output is untrusted |
| Sensitive access | one platform token | one workspace and bounded execution |
| Control transport | dedicated `agentd` Unix socket | stdin/stdout pipes only |
| Runtime socket | never | never |

The walking skeleton runs the fake Connector, `agentd`, and `sandboxd` under
the same host UID and uses `0600` sockets. Both accepting daemons still enforce
the configured connect-time Linux UID before HTTP, but equal UIDs validate only
the mechanism and protocols, not cross-identity isolation. Production still
requires dedicated identities and reviewed `2710` path-prefix/`0660` socket
provisioning for both hops. Broadening a socket mode or sharing one bearer
credential is not an acceptable shortcut.

## User-facing model

```text
endpoint-bound Connector + actor + conversation
  -> exact run.create binding
  -> TargetRevision
  -> Run -> Reply
         -> Workspace
         -> RunnerImage
         -> Policy/Profile refs
```

V1 has no message-selected alias or route layer. The operator-authored exact
binding resolves directly to one target ID plus expected revision. A message
can never define a host path, image, command, environment, mount, network
policy, credential, vendor flag, or runtime option. Future config tooling may
offer labels without placing alias selection in the wire or authority model.

An `ExecutionTarget` is an immutable combination of a runner image, workspace
reference, harness-specific state reference, skill bundle, auth/network policy,
and limits. The authoritative manifest exists only in the sandbox domain.
`agentd` stores the target ID and expected revision, not a copy of its policy.

The intended packaging contains harness differences inside digest-pinned Runner
images:

```text
runner-codex image  -> thin HRP adapter -> Codex CLI/SDK
runner-claude image -> thin HRP adapter -> Claude Code CLI/SDK
runner-other image  -> thin HRP adapter -> another harness
```

Adding a harness means adding a reviewed image and target manifest. It does not
add a daemon, change Connector semantics, or create a dynamic plugin registry.

## Possible target evolution (not implemented)

The following long-term target model is a design candidate, separate from the
V1 code and wire contracts above:

```text
exact Subject -> Binding -> Cell -> 0..1 current Instance -> sequential Runs
```

The `Binding`, not the Cell, is the authority edge. Future remote control is an
explicit closed action grant on one exact
`(Connector, actor, conversation) -> Cell` Binding. A message never supplies a
Cell ID, target/revision, provider, path, image, command, credential, setup kind,
or options. Core resolves the exact Binding and fixed Cell, then intersects the
grant with current durable state and any action-specific operator policy.

The accepted future remote candidates are deliberately narrow:

- `cell.pause` stops new admission only. It does not cancel an active Run,
  destroy bytes, or authorize remote resume;
- `instance.provision` has zero remote parameters and may consume only an
  immutable Cell-scoped `ProvisionPolicy` naming one exact approved
  TargetRevision plus fixed quota/cooldown bounds. It requires a short-lived,
  one-use confirmation consumed atomically with the lifecycle mutation;
- `auth.begin` has zero remote parameters and may start only the Cell's fixed,
  manifest-named setup kind. For a browser/device-login flow, provider-side
  human approval remains the credential-grant step. At most one SetupSession is
  active per Instance, with bounded expiry and cooldown.

These actions are absent from V1 and require a new reviewed schema after Cell,
Operation, and Instance exist. Remote Instance destroy, Cell resume, grant
mutation, revision selection, mounts, packages, credentials, configuration, and
shell/root access remain outside the accepted remote surface.

No general control-menu entity is required. `/status` or an equivalent typed
read may return a small derived set of currently applicable inline actions, but
the presentation, buttons, and action IDs grant nothing. Every selected action
is re-authorized from the exact Binding and durable state. The one-use provision
confirmation prevents accidents, replay, and stale UI; it is not a second trust
factor against a compromised Connector or platform account.

Normal maintenance remains operator-owned configuration, controlled restart,
new image/TargetRevision, and reviewed offline procedure. A future
`MaintenanceSession` is reserved only as a disabled-by-default, local-only
break-glass boundary with exact Instance generation, exclusive writer lane,
durable audit, and persistent `operator_modified` taint. It never appears in
the message UI and never implies safe host-root access.

## Persistence and concurrency

`agentd` is the only online business SQLite owner. Its Core store contains the
inbox, outbox, exact-binding-authorized Runs, dispatch leases, and opaque
session references. A persistent database-derived process lock fences agentd
for its full lifetime. The local `hgwctl` may acquire that same lock only while
agentd is stopped, opens only an existing current-schema database without
migration, and can inspect or compare-delete the session for one configured
Binding ID. It cannot accept a database path or raw scope tuple independently
of the trusted agentd config. A Core session is keyed by the complete immutable
authorization scope `(binding_fingerprint, connector_id, actor_ref,
conversation_ref, target_id, target_revision)`.

The Core process lock is derived from the configured database pathname, so its
identity claim depends on trusted provisioning: agentd and `hgwctl` must use
the same operator-owned config and exact path on one stable private mount. A
hard link, single-file bind alias, rename, unlink, replacement, or remount of
the database while either process may run is unsupported. The opener rejects
a database observed with more than one hard link as a low-cost misprovisioning
guard, but that check is not proof against bind aliases or a malicious same-UID
operator. A future hostile-local-user claim would require a service-global or
operator-authored lock identity, not path canonicalization by inference.

`sandboxd` owns a separate reconciliation store containing workspace locks,
runtime references, events, target revision pins, permanent runner-state
namespace owners, and the private mapping from opaque session references to
vendor tokens. That mapping additionally binds a domain-separated digest of
the complete Core session scope; the digest crosses the execution boundary,
while the Core tuple and vendor token do not. Neither daemon reads the other's
database.

The Core outbox stores no Connector, conversation, or reply destination. Each
text delivery has exactly one mandatory immutable `run_id`; all destination
fields are derived from the parent Run by join for idempotency, quota, claim,
lease, and completion flows. `FinishRun` is the sole delivery-creation path, so
the terminal Run transition, optional session update, and reply creation share
one immediate transaction. A v4 database with any unparented, dangling, or
scope-divergent legacy delivery refuses schema-v5 migration without rewriting
that evidence.

The persistent workspace is a sandbox-owned clone or volume. It is not the
user's live checkout and must not share that checkout's `.git` directory.

`Workspace` is a first-class sandbox resource. The single-writer lock is keyed
by workspace ID, not target ID: Codex and Claude targets may reference the same
project, and must not write it concurrently. Sessions never resume across
harnesses or revisions. Sandbox schema v6 permanently binds each canonical
runner-state ref and a domain-separated digest of its clean absolute configured
path to one exact `(target_id, target_revision)`. Startup registers the whole
current Target batch before creating a new state leaf. Exact replay is
idempotent; changing or reassigning either namespace fails closed, and removing
a Target does not release its historical owner. An existing path without that
exact durable owner is never adopted from current configuration.

A target-bearing schema-v1–v5 sandbox database cannot reconstruct this history
and refuses migration before v6 DDL; it requires a reviewed cold/offline
procedure. The ownership claim is one canonical lexical namespace within a
stable, operator-provisioned mount and one non-rolled-back database lineage,
not permanent inode identity or detection of bind/remount substitution by the
trusted host. Deleting a database or state directory is not a migration.

Core schema v7 permits only one `queued`, `dispatching`, or `running` Run for
one exact six-field session scope. Sandbox schema v7 independently permits only
one `accepted`, `running`, or `cancelling` Run for the matching target revision
and scope digest. For an `opaque_resume` target, its manifest freezes positive
limits of at most 30 days and 1024 turns. The first successful Run is turn one;
the lineage's resume-admission horizon is the half-open boundary
`now >= lineage_start + max_age`, and admission rejects once the previous turn
equals the maximum.

Each sandbox `session_ref` is a one-use resume capability. A new Run consumes
the exact ref atomically with durable Run admission; an exact retry of the same
`run_id` returns that Run without consuming it again. Successful completion of
every opaque-resume Run must atomically bind a newly generated successor ref to
the returned vendor token. Failure, cancellation, interruption, or a crash
before that commit produces no successor and never makes the parent reusable.
Unknown, wrong-scope, used, expired, over-turn, and clock-regressed references
all return the same `invalid_session` class.

Atomic admission is the authorization linearization point: consuming the
one-use ref transfers authority to that exact durable Run. Queue delay or
restart does not re-age the already admitted Run; its frozen deadline and the
Target timeout bound execution. Consequently a Run admitted just before the
session horizon may execute after it, but any successor still inherits the old
absolute expiry and cannot authorize another Run. The rollback checks compare
against durable parent/Run creation floors; they are not a global wall-clock
high-water guarantee. In particular, a host-clock step-back after an
unobserved idle interval can extend the lineage's real elapsed lifetime; V1
would need a trusted external time or host-epoch authority to rule that out.
Within an observed lineage, however, a successor cannot lower the durable
creation floor established by the Run that consumed its parent.

Core never converts such a failure into a fresh session and never deletes the
current pointer automatically. A nil `StartRun.session_ref` means Core had no
current pointer—either the scope never completed a resumable Run or the local
operator explicitly reset it. This invariant relies on agentd and its 0600
Core database remaining the trusted authority; HRP and sandboxd do not attempt
to distinguish an operator reset from corruption or out-of-band deletion of
that trusted state. Reset deletes only Core's current pointer. Immutable
sandbox token lineage remains for audit and is unreachable through normal
admission.

V1 permits exactly one `sandboxd` for an OS user, even if two instances would
use different configuration, database, or workspace paths. It holds the
persistent global lock file
`/run/user/<uid>/harness-gateway-sandboxd.lock` for its entire lifetime. The
file remains after a clean exit; releasing the OS lock, not deleting the file,
ends ownership. As usual for `/run/user`, the runtime directory itself may be
recreated by a host reboot.

## Reliability

- inbound events are at-least-once and deduplicated by connector instance plus
  source event ID;
- outbound deliveries are leased and may rarely duplicate at the platform
  boundary;
- `StartRun` is idempotent by `run_id` and payload fingerprint;
- an uncertain Run is marked interrupted and is not automatically restarted;
- an inbound normalized event returns its original Run only while its allow
  receipt is inside the operator-selected `W_receipt`; after the monotone
  Connector horizon evicts it, the event returns `EVENT_EXPIRED`;
- the inbound at-most-once claim applies only to the same non-rolled-back Core
  SQLite persistence lineage; restoring an older DB/VM snapshot can repeat work
  performed after that snapshot;
- runner-state ownership likewise applies only to one non-rolled-back sandbox
  persistence lineage. If its DB loses an owner while the state path survives,
  startup fails closed as existing-unowned; correlated rollback/removal of both
  database evidence and filesystem state is outside the claim;
- every newly admitted Run stores the exact binding fingerprint and
  authorization-policy revision atomically with its receipt. Those fields are
  immutable; pre-EBA terminal history remains explicitly legacy, while a
  pre-EBA non-terminal Run refuses the Core schema-v4 upgrade;
- every outbound text delivery stores only its immutable parent Run and text;
  Core schema v5 removes the former destination copy, freezes both sides of the
  delivery→Run join, and refuses unsafe legacy delivery history before DDL;
- Core schema v6 freezes every Run/session scope field and replaces the old
  session key with the complete six-field authorization scope. It refuses any
  legacy session-bearing database or non-terminal/result-session-bearing Run
  before DDL because the missing binding/actor scope cannot be reconstructed;
- Core schema v7 enforces one nonterminal Run per exact session scope in both
  admission code and a partial unique index. Its pre-DDL gate refuses a v6
  lineage already containing duplicate live scopes;
- sandbox schema v5 binds every new Run and private session row to the Core
  scope digest, freezes the Run and session authority fields, and forbids
  session deletion or replacement. It refuses legacy live/session-bearing
  state before DDL and retains only terminal no-session history for audit;
- sandbox schema v6 makes TargetRevision and runner-state ownership append-only,
  requires an exact owner join before `StartRun`, and grants a first owner only
  after the trusted local startup layer observed the exact path absent. The
  owner commits before the new private state directory is created;
- sandbox schema v7 freezes target-authored session age/turn policy on each new
  Run, records immutable lineage origin/expiry/turn metadata, consumes every
  parent ref once, requires a successor on opaque-resume completion, and adds a
  second one-live-Run fence. Existing sessions or nonterminal pre-v7 Runs block
  migration before DDL because their lifecycle authority cannot be inferred;
- one writable Run is allowed per workspace in the MVP;
- changing harness or target revision starts a new harness session;
- `agentd` reconciles durable running Runs before claiming newer queued work;
- `sandboxd` has one global execution lane. A terminal result may become
  visible before container cleanup finishes, but any durable runtime reference,
  pending intent, running/cancelling row, or reconciliation-store read failure
  closes that lane before the next Create/Attach. It reopens only after cleanup
  crosses the durable proof boundary;
- before its one allowed container-create call, `sandboxd` durably records a
  pending runtime intent together with the current host boot ID;
- a successful create stores the exact runtime reference. A definitely
  pre-create failure may clear the intent and then preserve an exact
  cancellation/deadline result. If the intent is still pending at terminal
  persistence, `interrupted` is the only legal class regardless of the
  secondary cancellation/deadline trigger, and the intent/workspace lock remain
  until reconciliation proves cleanup;
- after an uncertain create, reconciliation is read-only: it calls
  `LookupIntent` and never issues a second create. On the same host boot, an
  absent lookup is not proof and cannot release the workspace;
- for a schema-v3 pending record with a non-null boot ID, an exact verified
  container is cleaned before the intent and lock are cleared. If lookup is
  absent, clearing is allowed only after the host boot ID has changed, because
  the old daemon request can no longer still execute;
- a non-empty pre-v3 sandbox database is never upgraded in place. Older schemas
  did not record enough evidence to distinguish a completed Create from one
  still executing, even when a row contains a runtime reference. Startup leaves
  such a database unchanged and requires reviewed cold migration;
- schema v4 rejects a v3 database containing `completed`, `failed`, or
  `cancelled` rows with a pending intent; it never silently relabels historical
  terminal evidence;
- a pending record without a boot ID is therefore unsupported legacy/manual
  state, not something the automatic migration creates. As a defensive rule it
  is never cleared automatically, regardless of the lookup result;
- startup first reconciles durable database records, then inventories and
  cleans identity-verified managed containers not accounted for by that state.

These rules deliberately forbid a second create and forbid treating one absent
lookup as an unlock fence. They avoid the name-reuse race in which the original
create could complete after a recovery create was removed.

## Protocol boundaries

Connector to `agentd` uses strict, versioned JSON over HTTP/1.1 on a dedicated
Unix socket. Connector identity comes from the listener/socket, never from a
JSON field. V1 operations are inbound event, outbound claim, and outbound
completion.

`agentd` to `sandboxd` also uses bounded, strict HTTP/1.1 JSON over one Unix
socket and accepts only:

```text
StartRun(run_id, target_id, expected_revision, session_scope_digest,
         session_ref?, input, deadline)
CancelRun(run_id)
GetRun(run_id)
```

It never accepts image, path, command, argv, environment, mount, network, auth,
or runtime fields. `session_scope_digest` is mandatory even for a new session,
is derived by `agentd` only from the durable parent Run, and is part of the
idempotency fingerprint. It is an invariant check, not permission delegated to
the runner. `StartRun` is idempotent by payload fingerprint. A non-null
`session_ref` is always a resume attempt and is never retried as `new`; absence
means the trusted Core scope currently has no ref. No wire field carries the
target-authored age/turn policy: sandboxd resolves it from the immutable target
revision before admission.

`sandboxd` to a runner container uses HRP/1 over pipes. The runner never receives
a control-plane socket and cannot request additional authority. See
`runner-protocol.md`.

## Container and credential policy

Runner images and base images are pinned by digest, have fixed entrypoints, and
are created only from local operator-approved target manifests. A restrictive
rootless runtime profile is the starting point, but one hardening profile cannot
be assumed to fit every harness: different inner sandboxes may require different
outer seccomp, AppArmor, or capability settings. Each versioned profile must
pass its own isolation canaries, and every exception is target-specific and
reviewable.

The Docker endpoint is not a general configuration surface in V1. It must be
exactly `unix:///run/user/<effective-uid>/docker.sock`; proxy, forwarded,
rootful, remote, and other Unix endpoints are rejected. Ambient Docker context
and environment are not trusted by `sandboxd`. Before creation and lifecycle
inspection, the runtime queries that socket and requires Docker's rootless
security fact. Container adoption and cleanup additionally verify the complete
container ID, deterministic name, exact image reference, and immutable target
labels.

A container does not by itself protect a credential from model-controlled tools
inside that container. Long-lived Codex/Claude login state is never treated as a
normal `/state` mount. The secure/default profile still prefers an external,
narrowly scoped auth/egress proxy.

V1's runtime accepts only the built-in locked-down policy and `none` for auth,
skill, and network profiles. The current Target fingerprint covers those exact
reference names, but a future non-trivial profile cannot remain only a mutable
string lookup. Before such a profile is supported, its resolved operator-owned
content or content digest must be bound into the revision security fingerprint.
Otherwise an unchanged TargetRevision could acquire changed authority behind
an unchanged reference.

An egress allowlist is also a capability grant, not proof against exfiltration.
Even a required provider domain can expose multiple operations or carry
arbitrary content. A future auth/egress proxy must therefore mediate the
permitted operation and credential, not merely compare destination names; its
canaries and claim must still acknowledge any unavoidable provider data path.

The first planned Codex target is an explicit exception: it will use ChatGPT
subscription login and must be labelled `credential-exposed personal` unless a
canary proves model-controlled tools cannot read reusable login state. OpenAI's
Codex authentication documentation says ChatGPT sign-in provides subscription
access, uses a browser flow, and caches reusable credentials locally in either
`auth.json` or the OS credential store. Therefore the login state must be
dedicated to the exact sandbox Instance/profile, kept out of Core, Connector,
Workspace, messages, logs, and the user's general home directory, and never
shared across Cells. Exact storage, refresh, revocation, and SetupSession
handling remain release gates; read-only mounting alone is not a confidentiality
claim. See <https://developers.openai.com/codex/auth>.

The first candidate storage shape is now narrower than a persistent auth
directory. `CODEX_HOME` is writable but disposable per Run because the pinned
CLI writes helper aliases, bundled skills, locks, and other mutable runtime
state there even for an ephemeral execution. Only the dedicated profile's
`auth.json` may be a refreshable file bind inside that temporary directory;
the user's normal Codex home and the directory containing it are never mounted.
`CODEX_SQLITE_HOME` points to separate private Run tmpfs so state/log/goals/
memory/queue databases do not persist with the credential. The inner tool
environment does not inherit either path. The credential-free adapter now
creates or attests the home as an owner-only `0700` non-symlink directory and
allows no entry other than an owner-only, single-link regular `0600`
`auth.json`; it cannot prove that the file is the reviewed bind rather than
ambient state. This is a reviewed candidate contract, not implemented
authority: mount-type enforcement, file-bind refresh, exact write residue,
credential reachability, system-skill injection, revocation, and teardown must
all pass against the digest-pinned image before the profile can enter a
TargetRevision. Persisting the whole `CODEX_HOME` is explicitly rejected.

## Explicit non-goals

- generic messaging framework;
- dynamic plugin, connector, or runner registry;
- automatic harness selection or fallback;
- a `harnessd` service or harness-to-harness message bus;
- scheduler or event bus;
- vector memory;
- orchestration of agents or subagents;
- using remote text to grant or approve arbitrary command-level authority; this
  does not prohibit the separately pre-authorized closed Cell actions above;
- V1 attachments, deploy, push, or host workspace writes. A future reviewed
  closed media union may carry bounded digest-verified opaque blobs, never paths
  or message-selected fetch authority.
