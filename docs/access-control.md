# Harness Security Gateway Access Control v1

Status: **exact EBA, peer-credential, Run-derived disclosure, bounded session lifecycle, and historical runner-state ownership code gates implemented; deployment, canary/experiment, and deny-audit gates remain open**

Date: 2026-08-28

Model name: **Exact Binding Authorization (EBA)**

> **Implemented boundary:** Exact replay of the original Run is
> guaranteed only while its allow receipt remains inside `W_receipt`. After the
> durable eviction horizon passes it, ingest returns `EVENT_EXPIRED` rather than
> the old Run. At-most-once applies only within the same non-rolled-back Core
> persistence lineage. The code implements this boundary. Exact `agentd/v3`
> bindings, pure evaluation, stable fingerprints/revision, and immutable allow
> evidence on new Runs are also implemented. Linux peer credentials are
> enforced before HTTP decode, but dedicated identities and socket-directory
> provisioning are still deployment gates. Run-derived disclosure and exact
> two-plane session scope, bounded one-use session lifecycle, and sandbox
> historical runner-state ownership are implemented. Production deployment
> evidence, real-provider canaries, and the complete deny audit remain release
> blockers.

## 1. Decision

V1 does not use Cedar, OPA, Zanzibar-style ReBAC, general RBAC, or a cryptographic
`RunGrant`. Its authorization policy is a small, closed relation authored by the
local operator:

```text
(connector identity, actor ref, conversation ref, action) -> one exact target revision
```

For V1, the only implemented ingress action is `run.create`, and every binding
resolves to exactly one target. There are no wildcards, roles, deny overrides,
dynamic attributes, user-selected target aliases, or permission metadata bags.

This is not an informal allowlist. It is a deliberately small authorization
model with a total decision function, a closed reason-code set, immutable
admission evidence, and deterministic falsification tests.

The security claim is narrow:

> A normalized platform event can create a Run only when its authenticated
> Connector, actor, conversation, and action exactly match one operator-authored
> binding. The Run can use only the binding's exact target revision, resume only
> its own session scope, and disclose output only to its frozen ingress
> destination.

The system does **not** claim that a model will obey hostile natural language.
Prompt injection is assumed possible; the enforceable boundary is the target,
runtime, storage, network, session, and disclosure envelope around the model.

## 2. Formal model

Let:

```text
C = authenticated Connector identities
A = canonical actor references
V = canonical conversation references
X = the closed action set
T = immutable (target_id, target_revision) pairs

Binding B ⊆ C × A × V × X × T
```

For V1:

```text
Ximplemented = {run.create}

Authorize(c, a, v, x):
    if x not in Ximplemented:
        DENY(ACTION_NOT_IMPLEMENTED)
    if there is not exactly one t such that (c, a, v, x, t) is in B:
        DENY(NO_BINDING)
    otherwise:
        ALLOW(binding_fingerprint, policy_revision, t)
```

Configuration loading rejects duplicate `(connector, actor, conversation,
action)` bindings, so an authorization lookup can never merge two grants or
choose between ambiguous targets.

### Possible future Cell-scoped delegation boundary — not V1

A future revision may consider remote `cell.pause`, zero-parameter
`instance.provision`, and `auth.begin`, but only for exact Bindings explicitly
configured for those actions and their fixed Cell. This design candidate does
not add those actions to `Ximplemented`, `agentd/v3`, the current Binding
fingerprint, or Connector v1.

The Cell is not a principal and is never merely "trusted." A future request is
authorized only when its endpoint Connector, actor, conversation, and closed
action exactly match one operator-authored Binding. The request carries no Cell
ID, target/profile/revision, provider, credential, setup kind, path, command, or
options. Core resolves the Cell and then requires:

- for `cell.pause`, an explicit action grant and compatible current state;
- for `instance.provision`, an explicit action grant, one immutable
  Cell-scoped `ProvisionPolicy`, lifecycle/quota/cooldown checks, and a
  short-lived one-use confirmation consumed atomically with the mutation;
- for `auth.begin`, an explicit action grant, an Instance that needs auth, one
  fixed manifest setup kind, one-active-session exclusion, expiry/cooldown, and
  writer exclusion. No remote `auth.complete` or credential input exists.

The same-channel provision confirmation prevents accidents, retained-event
replay, and stale UI; it is not a second trust factor against a compromised
Connector or authorized platform account. The subscription/device-login
`auth.begin` path need not add another confirmation while provider-side human
approval is still required; a future setup kind with material begin-time
effects or no external approval must require a one-use confirmation or local
arming permit.

A menu is optional presentation, not policy. A future status response may show
only currently applicable inline actions, but every click is a new typed event
and is fully re-authorized. A compromised Connector can forge every granted
action for all of its Bindings and read their replies; strict per-Connector
identity, small grants, audit receipts, quotas, cooldowns, and expiry bound but
do not erase that residual.

`binding_id` is only a human-readable label. Authority and session identity use:

```text
binding_fingerprint = SHA-256(
  "hgw.binding/v1\0" || canonical_json({
    connector_id, actor_ref, conversation_ref, action,
    target_id, target_revision
  })
)
```

Therefore, deleting a binding and later reusing its label cannot resurrect its
old session. Changing the exact target revision also produces a different
binding fingerprint. Operational labels and the global policy revision are not
part of the fingerprint because neither changes the binding's authority.

`policy_revision` is a domain-separated hash of the complete canonical
authorization relation: Connector identities, their configured peer UIDs and
self actors, the closed
`run.create` action, and every authority-bearing binding field. Ordering,
human binding labels, socket paths, timeout/lease values, and capacity limits
do not change it because they do not change this authorization relation. It
identifies agentd's authorization policy only. sandboxd
independently and durably pins the target revision's security semantics; the two
authorities are correlated by `run_id`, `target_id`, and `target_revision`, not
collapsed into one misleading shared hash.

## 3. Trust and compromise boundaries

| Principal | Trusted responsibility | If compromised |
|---|---|---|
| Local operator / host administrator | Own deployment, config, service identities, target definitions, and emergency stop | Entire local policy and data plane are lost; this is the V1 trust root |
| Platform Connector | Authenticate to its SNS platform, normalize platform facts, deliver replies | Can forge/drop/reorder events for bindings assigned to that Connector and read all replies assigned to it; cannot choose a target or directly mount Core DB/workspace/runtime, but can ask every allowed target to return any data that target can read |
| agentd | Authenticate local Connector peers, evaluate exact bindings, persist Runs and outbox, dispatch exact targets | Can schedule any target known to sandboxd and disclose Core data; cannot redefine a target revision or directly control the rootless runtime socket |
| sandboxd | Pin target semantics, own runtime lifecycle, resolve private sessions, enforce workspace serialization | Its configured workspaces, credentials, and rootless runtime authority are lost; it still should not imply host root |
| Runner / harness | Translate HRP/1 to Codex, Claude Code, or another harness | Fully untrusted after input; confined to the immutable target envelope |
| SNS user / message content | Nothing | Always untrusted input |

Important residual fact: a Connector is a disclosure trust domain. If one
Discord Connector multiplexes ten conversations, compromise of that Connector
can read the ten conversations' claimed outputs after agentd releases them. EBA
prevents it from creating Runs outside its configured tuples or choosing their
targets; it cannot make a compromised delivery component forget data it was
legitimately given. Stronger tenant isolation requires separate Connector
instances and OS identities.

## 4. OS identities and Unix sockets

Production claims require separate service identities:

```text
hgw-agentd
hgw-sandboxd
hgw-connector-discord-personal
hgw-connector-<next-instance>
```

The current same-UID development layout exercises the mandatory credential
check but is not a cross-identity production security boundary.

For every accepted Unix connection:

1. The listener selects the logical peer identity; `connector_id` is never read
   from JSON.
2. Before HTTP or JSON body parsing, the server reads Linux `SO_PEERCRED`.
3. It compares the exact configured UID. GID controls filesystem reachability
   only and is not an authentication factor; PID is not authorization evidence.
4. A mismatch closes the connection without reading or writing application
   bytes and without reaching an HTTP handler. A failure of the credential
   mechanism closes that connection and terminates the supervised listener
   fail-closed and loud. Non-Linux builds refuse to construct the listener.

Each Connector has a separate socket directory. A workable deployment layout is
an agentd-owned, Connector-group directory mode `2710` and an agentd-created
socket mode `0660`. The code derives `0660` for a distinct configured peer UID
and `0600` for the same-UID development profile. Group execute permits
traversal to the known socket; the
Connector cannot list, create, rename, or replace directory entries. sandboxd's
socket follows the same pattern and admits only the agentd identity.

Config files are operator-owned regular files, readable but not writable by the
service. Core DB is private to agentd; sandbox DB and rootless runtime state are
private to sandboxd. A Connector receives only its own socket mount if it runs
in a container.

## 5. V1 configuration shape

The implemented agentd schema replaces independent actor and conversation
allowlists with exact bindings. A condensed JSON document is:

```json
{
  "schema": "agentd/v3",
  "database": "/var/lib/hgw-agentd/core.sqlite3",
  "sandbox_socket": "/run/hgw/sandboxd.sock",
  "run_timeout_seconds": 900,
  "delivery_lease_seconds": 30,
  "run_dispatch_lease_seconds": 30,
  "connectors": [
    {
      "id": "discord-personal",
      "socket": "/run/hgw/connectors/discord-personal/agentd.sock",
      "peer_uid": 21003,
      "self_actor_ref": "discord:user:111111111111111111"
    }
  ],
  "bindings": [
    {
      "id": "operator-private-dm",
      "connector_id": "discord-personal",
      "actor_ref": "discord:user:222222222222222222",
      "conversation_ref": "discord:dm:333333333333333333",
      "target": {
        "id": "home-codex-review",
        "revision": "r1"
      }
    }
  ]
}
```

The implemented `agentd/v3` requires one `peer_uid` on every Connector.
`sandboxd/v2` similarly requires its sole accepted agentd UID at top level.
Missing, zero, `65534`, `(uid_t)-1`, non-integer, and out-of-range values are
rejected. These files are startup-only authority: no message or protocol field
can mutate a peer UID.

`ExecutionTarget` is already the stable, harness-neutral abstraction between
platform authorization and harness deployment. A second `route` indirection has
no V1 behavior to justify it. If repeated target references later become an
operator usability problem, config tooling may support anchors or a typed target
catalog without changing authorization semantics. Aliases and action arrays are
also absent because V1 has no implemented selection path and no second action. A
field that appears to grant an unreachable permission would misrepresent the
enforced authority model.

Load-time validation is fail-closed and occurs before any socket is bound:

- all IDs and refs pass the same canonical byte-level validators used on wire
  events; agentd never silently normalizes a ref;
- Connector IDs, binding IDs, and socket paths are unique;
- every binding references an existing Connector;
- `(connector_id, actor_ref, conversation_ref)` is unique in V1;
- a binding cannot name its Connector's `self_actor_ref`;
- every binding resolves to one non-empty exact target ID and revision;
- config/database/socket paths do not overlap unsafe authority domains;
- Connector self actors and peer UIDs are explicit; the old `agentd/v2` schema
  is rejected rather than upgraded implicitly.

JSON is the versioned serialization, not the policy model. Strict decoding
rejects duplicate keys and unknown fields. Extensibility happens by a new schema
version and typed fields, never by a free-form `metadata`, `permissions`, or
`options` object.

## 6. Ingress, decision, and replay sequence

```text
Unix peer
  -> endpoint-bound Connector identity
  -> SO_PEERCRED check
  -> bounded strict decode
  -> canonical ref validation and self-event rejection
  -> full normalized event hash
  -> durable replay lookup
  -> pure Authorize()
  -> atomic admission decision + Run snapshot
  -> asynchronous dispatch
```

The event hash covers every semantic field plus the endpoint-derived Connector:

```text
SHA-256("hgw.inbound-event/v2\0" || canonical_json({
  connector_id, event_id, actor_ref, conversation_ref, message_ref,
  occurred_at_unix_ms, content_type, text, action_type, target_alias
}))
```

For `(connector_id, event_id)`:

- while the allow receipt is retained, the same hash returns the original Run
  without re-authorization, quota evaluation, Run-ID allocation, or dispatch;
- while the receipt is retained, a different hash returns
  `EVENT_ID_CONFLICT` and creates no row;
- after the receipt's event time crosses the durable per-Connector eviction
  horizon, the original normalized event returns `EVENT_EXPIRED`;
- after eviction, the same event ID with a fresh timestamp and different full
  hash is a new normalized event and is evaluated under current policy.

The mandatory operator parameters are:

```text
W_accept   maximum age for a first presentation
W_receipt  allow-receipt retention by stable event time
S          maximum accepted future skew

0 < W_accept < W_receipt
minimum replay grace = W_receipt - W_accept
```

`occurred_at_unix_ms` must be a stable platform event time that does not change
on retry and is covered by the full event hash. That is a Connector correctness
obligation, not authentication against a compromised Connector.

The serialized ingest transaction obtains SQLite `BEGIN IMMEDIATE` writer
authority, samples the clock once, advances the monotone Connector horizon,
evicts expired allow receipts, performs retained receipt lookup, applies time
checks for a new key, authorizes, checks capacity, and atomically inserts the
Run plus receipt. Rejected policy and quota decisions do not get per-key
receipts. V1 uses inline eviction and terminal-Run compaction; there is no
background compactor.

Dedupe is a correctness property, not authentication. A compromised Connector
can mint new event IDs, so per-Connector queue and storage quotas are a P0
availability boundary even for the first live deployment. At minimum, agentd
must cap queued/non-terminal Runs per Connector, pending deliveries, retained
input/audit bytes, and total SQLite pages; quota failure occurs atomically before
a new Run is inserted.

The closed V1 decision reasons are:

```text
ALLOW
PEER_UNAUTHENTICATED
MALFORMED_EVENT
SELF_EVENT
NO_BINDING
ACTION_NOT_IMPLEMENTED
EVENT_ID_CONFLICT
POLICY_UNAVAILABLE
QUOTA_EXCEEDED
EVENT_EXPIRED
```

Transport or parse failures that occur before a normalized event exists retain
only a bounded counter and request digest. Rejected message text is never stored
as audit content. Allow and deny retention pools must be independent so deny
flooding cannot evict accepted history.

## 7. Frozen Run and disclosure authorization

An allowed admission atomically freezes at least:

```text
run_id
connector_id
event_id and event_hash
actor_ref
conversation_ref
message_ref
binding_fingerprint
policy_revision
target_id and target_revision
input
created_at
```

Those fields are immutable. Future `run.read` or `run.cancel` actions, if added,
must compare their exact requesting binding fingerprint with the frozen creator
scope. Conversation-local lookup alone is insufficient.

Output destination is a security resource. In V1, every outbound delivery must
belong to exactly one Run, and its destination is derived from that Run's frozen
`connector_id`, `conversation_ref`, and `message_ref`.

Core schema v5 implements the authority-free delivery row:

```text
text_deliveries(delivery_id, run_id NOT NULL UNIQUE, text, lease state, ...)
```

Claim queries join `text_deliveries` to `runs`, filter on the endpoint-bound
Connector identity, and return the Run's conversation and reply reference. No
caller, handler, Runner result, or `INSERT` argument can supply another
destination. If a future non-Run operational notification is required, it gets
a separate operator-only path rather than making `run_id` nullable.

`FinishRun` is the only delivery-creation path and accepts only delivery ID and
text. SQLite pins both sides of the join: a trigger freezes the Run's Connector,
conversation, and message refs; another freezes the delivery's `run_id`.
`run_id` is `NOT NULL UNIQUE` with `ON DELETE RESTRICT`, while every admitted
Run also has a mandatory receipt child that prevents replacement/deletion of
the Run. Claim, lease, completion, idempotency, and pending-delivery quota
queries all derive Connector scope through the parent Run.

Migration 5 refuses before DDL if any v4 delivery is unparented, dangling, or
has a stored destination different from its Run. It does not infer, quarantine,
delete, or silently rewrite such history. The narrow code claim excludes a
fabricated whole Run inserted by direct maintenance SQL, deliberate
multi-statement dismantling of receipt/delivery/Run history,
`INSERT OR REPLACE INTO text_deliveries`, schema tampering, and a compromised
agentd. A recurring source test forbids replacement writes and authority-table
upserts in shipped Core Go/SQL; direct database maintenance remains a trusted
operator action outside ordinary product APIs.

Connectors send plain text with provider side effects disabled where available
(for example, no automatic mention expansion). Outbound text is never parsed as
a new control action. The platform Connector also filters messages authored by
the bot, while agentd independently rejects `self_actor_ref`.

## 8. Session authorization

A harness session is a persistent security resource, not merely a convenience
token. The Core session scope is:

```text
(binding_fingerprint, connector_id, actor_ref, conversation_ref,
 target_id, target_revision)
```

Some fields are redundant with the fingerprint but remain explicit for audit
and invariant checks. `session_ref` is opaque and is never accepted from an SNS
message.

sandboxd stores its private vendor token with:

```text
(session_ref, target_id, target_revision, session_scope_digest)
```

where `session_scope_digest` is a domain-separated digest of the complete Core
scope. It is mandatory on every `StartRun`, including a new session, and is
part of the request fingerprint. On resume, any missing reference or scope
mismatch returns the same closed invalid-session class so it does not disclose
which component matched. This is defense against agentd implementation mistakes;
it is not claimed to resist a compromised agentd, which is sandboxd's only
authorized caller.

Core schema v6 implements the six-field key and freezes every Run/session scope
column. Its pre-DDL gate refuses legacy session rows, any non-terminal Run, and
any Run with a start/result session reference. Sandbox schema v5 binds the
private token row to the digest, freezes Run/session authority, enables
recursive trigger enforcement, and forbids deletion or replacement of a
session row. Its pre-DDL gate likewise refuses legacy session/live/runtime
state; only terminal no-session history can remain for audit, and execution
loaders reject such legacy rows because they have no digest.

The lifecycle gate is now implemented in code:

- each `opaque_resume` TargetRevision must author positive limits of at most
  30 days and 1024 turns; these values enter the semantic target fingerprint,
  are frozen on every sandbox Run, and are checked again by Store and SQLite;
- the first successful session-producing Run is turn one. Every successor
  inherits the original lineage start and absolute resume-admission horizon.
  Admission requires `now < expires_at`, rejects clock rollback before the
  current ref's creation, and rejects when the parent turn is already the
  configured maximum. Atomic consumption transfers authority to that exact
  durable Run, so later queue/restart delay does not re-age it; its frozen Run
  deadline and Target timeout apply, while any post-horizon successor remains
  expired for future admission. These are wall-clock checks, not a trusted
  elapsed-time oracle: a host-clock step-back after an unobserved idle interval
  can extend real elapsed lifetime. Preventing that requires an external
  trusted time or host-epoch authority. Within an observed lineage, the
  successor creation floor prevents a later turn from lowering the last Run's
  durable admission time;
- Core schema v7 permits one nonterminal Run for the exact six-field scope.
  Sandbox schema v7 independently applies the same fence to the target,
  revision, and scope digest;
- a public sandbox `session_ref` is a one-use resume capability. Its use is
  inserted atomically with the durable new Run. Exact retry of that same
  `run_id` remains idempotent, but no different Run may consume it again;
- every successful opaque-resume completion must atomically publish a fresh
  public ref and bind the runner's non-empty successor vendor token. A failed,
  cancelled, interrupted, or crashed resume has no successor and never
  recharges the consumed parent;
- unknown, wrong-scope, used, expired, over-turn, and clock-regressed refs all
  collapse to `invalid_session`. agentd preserves the current Core pointer and
  never retries the request as a fresh harness session;
- local `hgwctl session status/reset` resolves only an operator-configured
  Binding ID. It shares agentd's database-derived process lock, refuses while
  agentd is running, opens only an existing exact-ledger database without
  migration, blocks reset while the exact scope has a nonterminal Run, and
  compare-deletes only the expected current ref. It never accesses sandboxd or
  deletes the immutable private token lineage.

There is deliberately no chat `session.reset`. A nil `StartRun.session_ref`
means trusted Core has no current pointer, either because this scope never had
one or because the local operator explicitly reset it. A non-null ref is always
a resume and never falls back to `new`. This is not a claim that sandboxd can
detect corruption or out-of-band deletion of the trusted Core database; doing
so would require a distinct wire intent or cross-store generation protocol and
is outside the accepted agentd-trusted threat model.

Sandbox schema v6 separately binds each canonical runner-state ref and path
digest to its exact historical TargetRevision. Sandbox schema v7's pre-DDL gate
refuses any older session row or nonterminal Run because one-use provenance and
frozen limits cannot be reconstructed. Core v7 likewise refuses a v6 lineage
that already contains duplicate live scopes. No migration guesses, rewrites,
or deletes this evidence.

The mock Target exercises `opaque_resume`, but the first real Discord + Codex
TargetRevision remains `new_only` until dedicated-identity/path provisioning,
real lifecycle-limit/reset evidence, provider-auth/runtime canaries, bounded
deny audit, and the isolated-host plus private-Discord experiments are complete.
Provider authentication belongs to the separate auth profile; changing a
target revision starts a new harness session.

## 9. Target authority, time, and lifecycle

The message never selects workspace access, credentials, skills, network,
runtime, image, resource limits, or harness options. It reaches one exact target
revision. sandboxd owns and freezes that target's manifest, including:

```text
runner image digest and adapter
workspace ref and ro/rw mode
state ref
policy/auth/skill/network profile refs
session mode
time, memory, CPU, PID, input, output, stderr, and event limits
```

Profiles are closed executable registries. An opaque profile name that is
accepted but not enforced is a configuration error.

sandboxd already computes a semantic target fingerprint and durably refuses a
reused `(target_id, revision)` with changed manifest or local runtime/storage
authority. Therefore a `DescribeTargets`/`manifest_epoch` protocol is not a P0
authorization dependency. A startup `ValidateTargets` endpoint may be added as
an operational fail-fast check, but sandboxd's own revision pin remains the
security authority.

The effective Run deadline is already structurally bounded by both sides:

```text
min(agentd frozen run deadline, target manifest timeout)
```

Connector input cannot set it. Both configured limits are capped at 24 hours.
The effective terminal outcome should be made visible in audit, but a new
deadline authorization mechanism is not required.

The V1 Core lifecycle remains:

```text
queued -> dispatching -> running -> completed | failed | cancelled | interrupted
```

`interrupted` is the honest terminal class for an outcome that cannot safely be
classified after runtime uncertainty. An uncertain runtime Create is never
repeated. Runtime/workspace authority remains fenced until reconciliation proves
quiescence. Renaming this state to `indeterminate` adds no security property.

The former uncertain-Create classification P0 is closed: while a runtime intent
is pending, Core, controller, and SQLite accept only `interrupted` as the
terminal class. Cancellation or deadline may be the secondary trigger, but
cannot become a claim that execution did not occur. Dirty pre-invariant history
blocks automatic schema upgrade.

V1 policy is a startup snapshot and does not claim hot revocation. Stopping the
Connector is the ingress emergency stop; stopping agentd prevents new dispatch;
stopping sandboxd/rootless runtime is the execution stop. Existing admitted
Runs do not silently become `revoked` merely because a config file changed.
Dynamic revocation requires an explicit future state machine and output-discard
semantics.

## 10. Workspace confidentiality domains

Any bindings that can reach overlapping resolved workspace or state paths share
a confidentiality and persistence domain, even if one target is read-only and
even if their target revisions differ. A writable Run can plant content that a
later read-only Run consumes.

For the single-user, one-target V1 path, that sharing is explicit and accepted.
Before adding a second actor or any egress-enabled target, deployment validation
must examine resolved mounts and reject cross-actor overlap unless the operator
explicitly declares the domain shared. Target revision is not a confidentiality
boundary; concrete reachable data is.

## 11. Why not a general policy engine now

NIST's ABAC model evaluates subject, object, operation, and sometimes environment
attributes against policy. Cedar and OPA provide valuable policy separation and
more expressive evaluation; Zanzibar addresses globally distributed relationship
authorization at enormous scale. Those are established designs, but V1 needs a
finite exact relation with one author and one implemented action.

The complete V1 decision space is small enough to enumerate. A general engine
would add a schema/entity translation layer, another configuration language,
another runtime, and new fail-open/fail-closed behavior without removing the
application-level enforcement obligations around Run rows, sessions, outbox,
sockets, or runtime mounts.

Reconsider Cedar/OPA/ReBAC when at least one real requirement appears:

- dynamic groups or platform roles become trusted authorization facts;
- several independent policy authors must compose policy;
- multi-tenancy, delegation, conditional/time-based grants, or resource sharing
  cannot be represented as a small exact table;
- policy must hot-reload with defined revocation semantics;
- the binding relation is no longer practically exhaustible in tests.

## 12. Why not a cryptographic RunGrant now

agentd is the only local caller authorized to reach sandboxd. A token signed by
agentd cannot constrain a compromised agentd, while a Connector or Runner cannot
reach the socket to present one. StartRun replay is already handled by durable
`run_id` plus a full immutable request fingerprint.

Use authenticated channels rather than adding bearer tokens if the boundary
changes.
Reconsider mTLS/channel-bound grants only when sandboxd or a Runner becomes
remote, a broker stores and forwards requests, multiple issuers exist, or a
delegate must prove authority it cannot mint itself. `decision_id`,
`policy_revision`, and `binding_fingerprint` may cross the execution protocol as
audit evidence, but sandboxd must not treat unverified evidence as permission.

## 13. Evidence discipline

Architecture and code reviews are advisory inputs, not authorization or proof.
A finding enters this design only after it is adjudicated against the stated
invariant, the implementation, and a reproducible test or explicitly scoped
runtime observation. A reviewer verdict never widens a release claim.

The most important recurring review outcomes are pinned in code and tests:

- exact actor/conversation Bindings instead of independent allowlists;
- Run-derived outbound destination rather than caller-authored routing;
- connect-time UID checks before request decoding;
- one-use, exact-scope session references with bounded lineages;
- fail-closed schema migration and revision reuse; and
- durable uncertain-create reconciliation without a second Create.

## 14. Falsification experiments and release gates

Security acceptance uses deterministic invariants first. Passing a stochastic
prompt suite is never substituted for an enforcement test.

### P0 authorization and persistence

1. **Exhaustive tuple matrix:** enumerate every configured and adversarial
   Connector/actor/conversation/action combination. Exactly the configured
   tuples allow; cross-pairs such as `(A,C2)` and `(B,C1)` never do.
2. **Evaluator totality:** every input returns one closed reason code; panics,
   implicit fallthrough, and unknown actions never allow.
3. **Config fail-closed:** duplicate bindings, missing refs, self bindings,
   unsafe socket paths, and invalid/reserved peer UIDs cause non-zero startup
   before any listener exists. Duplicate peer UIDs remain valid for the
   explicitly non-isolating same-UID development profile.
4. **Peer identity:** processes under wrong UIDs are disconnected before body
   parsing and produce no Run or normalized admission record. GID is tested as
   socket reachability, never as application authentication.
5. **Replay:** inside `W_receipt`, the same event/hash repeated N times produces
   one Run, one runtime Create, and the same receipt without re-authorization;
   a changed hash conflicts. After the horizon passes the receipt, the original
   event returns `EVENT_EXPIRED`. Clock regression never moves the durable
   horizon backward.
6. **Hash coverage:** mutate each semantic field independently, including the
   endpoint Connector; every mutation changes the event hash.
7. **Disclosure binding:** neither public store APIs nor direct SQL fixtures can
   enqueue a Run output to a destination other than the parent Run; claimed
   batches never cross Connector identity.
8. **Session isolation:** another actor, conversation, binding revision, target,
   or target revision cannot resume the session. Expired/over-turn sessions
   fail closed.
9. **Crash injection:** kill agentd around send/ack and sandboxd around runtime
   Create. Runtime Create count is never greater than one; uncertain outcomes
   never become fabricated success/failure.
10. **Self-loop:** bot-authored outbound events cannot create a new Run even if
    replayed by the platform.
11. **Persistent backpressure:** flood unique valid events until every configured
    queue/storage cap is reached. SQLite growth remains within its hard bound,
    existing Runs remain recoverable, and new admissions fail atomically with
    `QUOTA_EXCEEDED`.

The gate is zero unauthorized Runs, deliveries, session resumes, or duplicate
runtime Creates. Percentages are not used.

### P0 runtime envelope

For each released target revision, use a deterministic malicious Runner/canary:

- network probes fail under `network: none`;
- root filesystem and read-only workspace writes fail;
- runtime socket, host namespaces, credentials, and unrelated state are absent;
- image digest, capabilities, `NoNewPrivileges`, resource limits, and mounts
  exactly match the target's resolved runtime plan;
- output, stderr, event, time, memory, CPU, and PID limits terminate the Run,
  not a daemon;
- one target cannot see another target's private state.

### Prompt-injection bake-off

Codex/Claude Code prompt-injection cases are retained as attack search inputs.
A hit is evidence of a broken deterministic boundary. A miss is reported only
as “no boundary violation observed for model/version/corpus,” never as a
security percentage or proof that the harness obeys instructions.

## 15. Current implementation delta

| Area | Current state | Required change |
|---|---|---|
| Strict versioned wire DTOs | Implemented | Keep; remove or reject unimplemented action semantics centrally |
| Actor/conversation authorization | Implemented as one exact `(Connector, actor, conversation) -> TargetRevision` binding and pure evaluator; exhaustive cross-product tests deny every unbound pair | Keep target selection and generic action arrays absent |
| Event hashing/replay | Endpoint Connector is in the v2 digest; bounded allow receipts, inline eviction, monotone horizons, and `EVENT_EXPIRED` are implemented; Core schema v3 version-tags legacy receipt comparison, schema v4 adds immutable EBA evidence, and schema v5 derives delivery scope without minting new v1 receipts | Add only a bounded deny counter/ring after its evidence schema is agreed; denies remain transient and have no per-key receipt |
| Target revision authority | Implemented: semantic and local authority revision pin | Keep; add only operational startup validation if useful |
| Deadline bounds | Implemented on agentd and target execution contexts | Expose effective outcome in audit; no new permission mechanism |
| Uncertain Create recovery | Implemented with persistent intent and no second Create | Keep `interrupted`; extend experiments |
| Uncertain terminal classification | Implemented across classifier, centralized terminal commit, Store typed guard, and SQLite v4 trigger; dirty v3 rows are refused | Run crash-injection experiments; do not weaken the invariant |
| Local peer authentication | Linux pre-decode exact-UID gate implemented for Connector→agentd and agentd→sandboxd; mismatches are byte-silent and credential-mechanism failure is daemon-fatal | Provision dedicated UIDs/groups and validate `2710` path prefixes plus inherited `0660` group ownership before claiming cross-identity isolation |
| Outbound disclosure | Implemented: destination exists only on the immutable parent Run; delivery creation is atomic with `FinishRun`; every outbox authorization/read path joins the Run | Keep replacement-SQL source guard and fail-closed legacy gate; operational notifications require a separate operator-only design |
| Core session scope | Immutable six-field key plus schema-v7 one-nonterminal-Run fence and offline lock-fenced Binding reset; lifecycle code gate complete | Keep the real target `new_only` until identity/path deployment, lifecycle-limit/reset, provider-auth/runtime canary, deny-audit, and isolated-host/private-Discord experiment evidence pass |
| sandbox session scope | Exact ref/target/revision/digest binding plus schema-v7 one-use, age/turn, successor, and one-live enforcement | Keep the digest control-plane-only and retain non-enumerating mismatch behavior |
| Historical runner-state ownership | Implemented in sandbox schema v6: whole-registry atomic registration, immutable ref/path-digest/TargetRevision owners, existing-unowned-path refusal, owner-required Run admission, and fail-closed target-bearing legacy migration | Record deployment evidence and a reviewed cold-migration procedure |
| Persistent disk/queue bounds | Operator-required receipt, queued/nonterminal Run, pending-delivery, retained-input, and SQLite page bounds are implemented | Calibrate values/page headroom with Discord experiments and add bounded deny audit |
| Policy decision audit | Accepted Runs immutably store binding fingerprint and policy revision; legacy terminal Runs remain explicitly without EBA evidence and legacy non-terminal state blocks Core schema v4 upgrade | Add closed-reason bounded deny ledger; do not retain denied message text |

## 16. Implementation order

No new SNS platform or harness is added before these gates pass.

1. **Implemented:** `agentd/v3`, direct exact bindings, canonical
   policy/fingerprint code, exhaustive `Authorize()` tests, and immutable Run
   allow evidence.
2. **Code implemented:** mandatory Linux `SO_PEERCRED` authentication and
   `agentd/v3`/`sandboxd/v2` peer UID configuration. **Deployment pending:**
   dedicated service identities, validate-only directory provisioning, and
   path-prefix/socket ownership evidence.
3. **Implemented:** Core admission/Run evidence, hard persistent quotas, and
   Run-derived outbox destination authority with a fail-closed v4→v5 migration.
4. **Implemented in code:** uncertain-create terminal precedence and sandbox
   schema-v6 durable historical runner-state ownership. Target-bearing pre-v6
   stores require a reviewed cold migration.
5. **Session lifecycle code complete:**
   target-authored age/turn limits, one-live-Run-per-scope on both stores,
   one-use refs, mandatory successors, invalid/expired fail-closed behavior,
   offline Binding-scoped reset, and deterministic multi-turn/queue-horizon
   evidence. Keep the real Discord + Codex target `new_only` until identity/path
   deployment, lifecycle-limit/reset, provider-auth/runtime canary, deny-audit,
   and isolated-host/private-Discord experiment evidence are complete.
6. Run deterministic authorization, persistence, crash, and runtime gates on the
   isolated test VM.
7. Only after a clean report, run the Discord + Codex adversarial bake-off.

P1, before a second actor or any egress profile: confidentiality-domain
validation, richer audit retention, explicit revocation design, safe outbound
mention policy, and operational target startup validation.

P2, only upon real demand: remote/chat reset for an exact Binding, trusted
dynamic groups, a general policy engine, or ACP-backed harness
session/permission adapters.
Message-supplied or message-selected targets, execution credentials, and runtime
options remain outside the boundary. A pre-authorized zero-parameter
`auth.begin` may trigger only a fixed sandbox-owned SetupSession; it is not
remote credential authority. ACP may reduce Runner adapter work; it does not
replace ingress authorization, Run lifecycle, or disclosure enforcement.

## 17. References

- NIST SP 800-162, ABAC definition and considerations:
  <https://www.nist.gov/publications/guide-attribute-based-access-control-abac-definition-and-considerations-0>
- Zanzibar paper, USENIX ATC 2019:
  <https://www.usenix.org/system/files/atc19-pang.pdf>
- Cedar policy language reference: <https://docs.cedarpolicy.com/>
- Open Policy Agent philosophy and enforcement model:
  <https://www.openpolicyagent.org/docs/philosophy>
