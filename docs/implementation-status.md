# Implementation status

Last verified: 2026-09-10 (three admitted real-canary Runs failed; authenticated-provider acceptance and deployment gates remain open)

The [2026-09-10 checkpoint assessment](checkpoint-2026-09-10.md) summarizes the
completed local work, verification limits, design/practice review and next work
package. The dated observations below remain supporting evidence.

The [runtime-owned provider canary](codex-provider-canary.md) now implements the
closed Unix/TLS operation endpoint, fixed upstream dialer, mounted socket/CA
bootstrap, joined cleanup before credential release/publication, and a separate
owner/artifact-bound opt-in pin. Offline Core/native completion with replay and
removal failure passed at **00:37–00:39 UTC**, cancellation at **00:45–00:47 UTC**,
and owner SIGKILL/recovery at **00:49–00:52 UTC** on 2026-09-10. The first armed
canary attempt at **02:13 UTC** failed the local Connector-directory policy
before any database, enrollment, runtime or provider operation. Its placeholder
socket now has a separate directory, and preflight compiles the same Core
configuration before reporting readiness. The focused regression failed before
the fix and passed afterward with race checks and vet. The continuation at
**02:30–02:31 UTC** enrolled one dedicated real source, admitted one Run and
started its native runtime, but ended in `runner_failed` without the marker.
Exact container absence and zero credential/workspace/result fences were
independently verified. The failed local delivery remains pending for evidence.
Provider operation/status details were not retained, so authenticated catalog,
inference and tool completion have not been established. Both attempts are retained.
Subsequent offline checks on **2026-09-10** verify bounded operation/stage/status
snapshots in the private canary result and fixed native/relay failure separation.
These observations do not change cleanup authority or explain the earlier Run;
no further real Run was executed during that diagnostic implementation stage.
See the canary's diagnostic evidence limits.

The tagged local owner now supports an explicitly approved continuation in the
retained state root: it pins predecessor history and database objects, preserves
the enrolled source, uses the next local generation and isolates the new test's
delivery. Synthetic interruption/recovery and admission tests, tagged race/vet and
the security demo passed on **2026-09-10**. No real generation transition or second
Run was executed during this preparation; this does not enable a normal daemon
or public messaging path. See [continuation boundaries](codex-provider-canary.md#explicit-continuation-preparation--2026-09-10).

A separately approved continuation at **04:51–04:52 UTC** then retired the first
local generation, enrolled the next generation for the same source/proof and
admitted one new Run. It failed with `Codex native process failed`, without a
marker. Bounded diagnostics recorded two completed catalog exchanges with HTTP
200, one local settings response and thirteen inference exchanges with upstream
HTTP 200 rejected at `upstream_policy`. The exact response predicate is unknown;
neither authentication nor inference completion is established by these statuses.
At **04:53–04:54 UTC**, exact container absence, process exit and zero durable
cleanup fences were independently verified. Both failed Runs and pending results
remain retained. The consumed plan now rejects another execution. See the
[second Run's scope](codex-provider-canary.md#second-real-run--2026-09-10).
Normal daemon configuration remains mock-only; public Discord and production
deployment remain disabled.

The subsequent [response-rejection work package](codex-provider-canary.md#actionable-rejection-and-bounded-failure-handling--2026-09-10)
now implements closed predicate/media diagnostics and operation-scoped blocking
at upstream dispatch authorization. It preserves the response acceptance rules,
other operations, transient/status behavior and joined cleanup. Its implementation
and read-only preparation did not explain the earlier response predicate or
execute another Run.

The third separately authorized Run at **07:08 UTC** then failed without a
marker. One authorized inference received HTTP 200 with an empty/missing
Content-Type (`content_type_missing`); twelve later inference requests were
denied locally without new upstream authorization. Two catalog exchanges
completed with JSON media and HTTP 200, and settings stayed local. At
**07:11–07:12 UTC**, independent observations confirmed exact container absence,
process exit, zero durable cleanup fences and the same source/proof across
generations 1–3. All three failed Runs and pending deliveries remain retained.
The consumed plan rejects reuse. This demonstrates bounded rejection handling,
not inference acceptance or a diagnosis of the earlier Runs. See
[the third Run's evidence and limits](codex-provider-canary.md#third-real-run--2026-09-10).

The subsequent [response-contract investigation](codex-provider-canary.md#response-contract-investigation--2026-09-10)
verifies complete synthetic Lite request forwarding through both HTTP/TLS hops.
Existing fixed-native SSE evidence does not support inferring incompatibility
from the Lite name. The endpoint now distinguishes closed response-field and
framing metadata and samples a rejected HTTP-200 MIME response only after
blocking further operation dispatch, within 512 bytes and one second. No raw
body is retained and no response policy is relaxed. The third Run lacks these
observations, so the upstream cause remains unknown; collecting the missing
evidence requires a separately authorized, newly pinned real Run.

Credential identity/proof storage, enrolled-target pin composition, authoritative
Run re-open, ordered held-lock release and controller startup retirement are
implemented with synthetic tests. A tagged offline V3 fixture now connects
native enrollment, the actual service/controller, Docker handoff/bootstrap,
HRP and ordered cleanup/publication; its local 2026-09-09 10:24 UTC case passed.
Subsequent same-UID Core/Connector fixtures passed focused native faults at
10:53–10:56 UTC and two separate-owner SIGKILL/restart cases at 11:32–11:35 UTC.
Fixed resistant-descendant cleanup passed at 19:54 UTC and native held-tool
deadline at 20:12 UTC, with two earlier deadline-fixture failures retained.
Permanent credential admission feedback passed the service/HTTP/Core path at
20:28 UTC: fixed policy denial after exact Run absence, without waiting for its
deadline; existing/uncertain Runs retain their observation path.
The opt-in canary supplies a local enrollment caller and fixed candidate
resolution. The failed canaries above exercised an initial real-source enrollment,
a same-source generation transition and runtime handoffs; complete production resolution and
normal executable configuration remain unimplemented. Offline checks alone
confer no authority for real credential use.
Earlier live observations retain their own dates and evidence limits.

Release posture: **research prototype / pre-alpha**

The control plane, durable authorization path, sandbox lifecycle, mock Runner,
and offline security witness are implemented. Three sealed but blocked
`new_only` Codex behavior contracts are present: unchanged v1 has no added
model context, while v2 maps one fixed private-messaging behavior profile to
Codex's developer-instruction layer. V3 preserves that messaging behavior and
adds a pinned native tool package, fixed configuration and startup checks.
A non-executable candidate manifest and
offline preflight are present; no approved Codex image or executable target is
shipped and the default build omits its entrypoint. There is no public Discord
Connector, provider-authenticated target, or production deployment. The
project therefore does not yet demonstrate a secure Discord-to-Codex path.

This document is the public source of truth for what is implemented, what is
only represented in code, and what remains work in progress.

## Status at a glance

| Capability | State | Evidence boundary |
| --- | --- | --- |
| Strict Connector and execution protocols | Implemented | Bounded JSON, closed enums, unknown-field rejection, protocol tests |
| Exact Binding authorization | Implemented | Exact Connector/actor/conversation tuple selects one immutable target revision |
| Durable Run, replay, dispatch, and outbox state | Implemented | SQLite schema v7, migration/reopen/failure-injection tests |
| Sandbox target and runtime lifecycle | Implemented for the mock path | Immutable manifests, rootless-runtime attestation logic, create-intent reconciliation, and lifecycle tests; the live rootless-Docker observation is local evidence, not public CI |
| Post-cleanup terminal publication | Implemented and fault-tested; focused native and adversarial container witnesses | Sandbox schema v8 stages outcomes privately; exact cleanup precedes publication/unlock. On 2026-09-09, a fixed TERM-resistant/`setsid` Runner passed at 19:54 UTC and native deadline at 20:12 UTC; full native-launcher descendant matrix remains open; [scope](codex-control-boundary.md#deadline-and-resistant-descendant-witnesses) |
| Runner-state v2 local mock path | Implemented and locally tested | Explicit `sandboxd/v3`, immutable version-aware target carrier, sandbox schema v9, conditional state mounts, real mock-process and fake-runtime recovery tests; no live Docker/provider claim |
| Credential generation and occupancy | Implemented; normal executable configuration remains mock-only | Sandbox schema v10, immutable source/generation/target records, one-way revocation, atomic admission/release, SIGKILL and fake-runtime recovery tests; initial real-source enrollment and one same-source generation transition were observed only through the opt-in canary on 2026-09-10 |
| Atomic credential proof registration | Implemented and tested; one real-source canary enrollment observed | Sandbox schema v11, immutable atomic proof, exact replay, no backfill/downgrade, migration/rollback/reopen/concurrency tests; the failed 2026-09-10 canary exercised one dedicated source, not production enrollment/rotation acceptance |
| Enrolled credential target pin | Integrated into sandboxservice; one real-source canary binding observed | Database-derived generation/proof, exact target scope and atomic whole-batch registration; the separate experimental resolver does not establish complete production authority resolution |
| Trusted target resolution | One frozen resolver per registry entry; executable wiring accepts only locked-down mocks | Compiled-policy scope projection, manifest/scope consistency, no fallback after resolution failure, and unchanged legacy mock pins; only the separate opt-in canary can produce its experimental provider pin |
| Credential startup recovery | Integrated with synthetic authority; two native owner-restart cases passed on 2026-09-09 at 11:32–11:35 UTC | SIGKILL with bound running runtime or existing unbound Create, retirement before failed inspection, retained occupancy/staged result, exact healthy cleanup and one Core interruption; no execution-source reopen/recreate. Same-boot tagged fixture, not host reboot or delayed absent Create; [scope](codex-control-boundary.md#native-owner-crash-and-recovery-witnesses) |
| Credential Run re-open/release | Integrated through a trusted Go construction option; no normal executable config wiring | Run-derived proof/scope, acquisition-once and retained authority on failure; tagged native controller fixture observes the physical lock through removal and its release before publication |
| Local held credential file | Linux primitive with controller and opaque runtime consumers | Descriptor pinning, advisory locks, replacement rejection and one-Create copy-safe handoff; one dedicated real-source handoff observed in the failed 2026-09-10 canary; no generic path/FD accessor |
| Credential identity/proof | Linux/amd64 native-ext4 adapter with Run comparison integration | Canonical UUID/export-handle digests and root/slot/locator pins; synthetic witnesses and one real-source enrollment in the failed 2026-09-10 canary; production enrollment/rotation acceptance remains open |
| Credential mounted-object bootstrap | Implemented component and controller-owned Docker consumer | Six local component cases plus the 10:24 UTC integrated witness on 2026-09-09; local peer/PID view, applied policy, UID/GID/capability and mounted-object verification before permit; [scope](codex-control-boundary.md#controller-owned-synthetic-v3-witness) |
| Bounded synthetic provider consumer | Implemented and locally tested on 2026-09-09 | One-use HTTP/1.1 consumer, request/stream budgets and cancellation/cleanup fault tests; composed with the controller's V3 fixture, no real upstream or production transport separation |
| Built-in ChatGPT operation inventory | Offline fresh/refresh native `exec` passed on 2026-09-09 21:04–21:05 UTC | Synthetic file auth and refresh persistence; default paths, WebSocket attempts and zstd HTTP fallback observed; no real provider or production allowlist; see [inventory and next decision](codex-provider-operations.md) |
| Fixed subscription HTTPS/SSE candidate | Offline fresh/refresh native `exec` passed on 2026-09-09 21:24 UTC | Separate custom-provider overlay, uncompressed JSON and zero observed upgrades; refreshed token persisted and used; header differences and real-server/tool compatibility remain gates; V3 unchanged |
| HTTPS consumer/native-tool composition | Offline pass on 2026-09-09 22:05 UTC | One refresh and two real strict-consumer dispatches, native Code Mode command and independent result, positive controls, connection/FD/owner-procfs checks and cleanup; child PID and ancestor procfs views explicitly distinguished. Temporary synthetic auth, tagged runtime restrictions; production binding remains blocked; [scope and next integration](codex-provider-operations.md#offline-integrated-boundary) |
| HTTPS through Core/controller lifecycle | Three offline cases passed on 2026-09-09 22:49–22:54 UTC | Exact mounted synthetic file refreshed in place through the existing held-source/bootstrap; completion/replay/removal failure, held-tool cancellation and owner recovery each ended in one scoped Core delivery after cleanup. Recovery reopened no credentials and created/attached no runtime. Tagged fixtures only; [scope, failures and next contract decision](codex-provider-operations.md#offline-controller-lifecycle) |
| Fixed provider byte relay | Linux component and local HTTPS/owner-loss composition implemented on 2026-09-09 | Pinned Unix socket object, concrete peer UID, loopback-only ingress, byte/connection/deadline bounds and joined cleanup. Endpoint/TLS ownership stays in the existing runtime-owner design. No normal executable wiring; the tagged canary now supplies controller lifetime hooks, a fixed upstream dialer and a distinct experimental pin; [design and scope](codex-provider-canary.md) |
| Fixed channel in native container | Two offline cases passed on 2026-09-09 23:58–23:59 UTC | Read-only socket identity and peer UID mapping, fake refresh/tool completion, TCP/Unix denial and protected-object non-inheritance; owner loss yields harness failure before deadline and a joined failed relay. Standalone driver, with exact cleanup; this standalone witness did not establish controller/held-credential integration; the dated canary above covers that subsequent work. Scoped procfs/control limits and retained startup failures: [native acceptance](codex-provider-transport.md#offline-native-channel-acceptance) |
| Synthetic V3 controller composition | One scoped local pass on 2026-09-09 at 10:24 UTC | Actual service/controller/Docker/HRP, one Create/Attach despite receipt replay, native command/readback, exact removal while locked and close before publication. Tagged fixture only; no Core/Connector path or approved production image; [scope](codex-control-boundary.md#controller-owned-synthetic-v3-witness) |
| Core ingress through synthetic V3 | Three focused local cases passed on 2026-09-09 at 10:53–10:56 UTC | Real Connector/execution HTTP over peer-authenticated Unix sockets, compiled exact Binding, Core dispatch/outbox and native controller consumer; source replacement denied before Create, lost Start reply recovered without duplicate Create, removal failure withheld output, held-tool cancellation cleaned up before delivery. Same-UID tagged fixture with an offline responder; [scope and remaining matrix](codex-control-boundary.md#core-ingress-and-focused-native-fault-witnesses) |
| Scoped opaque-session lifecycle | Implemented for the mock path | One-use references, age/turn bounds, exact-scope fences, reset and migration tests |
| Offline security witness | Implemented | Production decoder/policy/service/Core store with synthetic input; no network or credentials |
| Codex HRP/1 adapter | Implemented and unit-tested for the first `new_only` cut; not shipped as a target | Translation and failure-redaction tests; no image or accepted runtime profile |
| Codex native tool-network prerequisite | Opt-in canary implemented; local primitive witness only | Pinned CLI helper, positive control and IPv4/IPv6 TCP/UDP socket denial; this primitive alone does not prove full tool `exec` or production image/provider mediation; see [canary scope](codex-network-canary.md) |
| Codex synthetic exec integration | All five native cases passed in an offline guest on 2026-09-08; separate wrapper error retained | Exact adapter/launcher/CLI completion, network denial and positive control, provider-wait and held-tool cancellation; temporary guest compatibility profile, no-catalog tool gap and production gates remain; see [integration scope](codex-exec-integration.md) |
| Codex Profile v1 contract | Sealed but blocked; not accepted by the runtime | Exact CLI/model/auth/state/network/context/teardown semantics and stable contract fingerprint; live gates remain failed closed |
| Codex Profile v2 contract | Sealed but blocked; not accepted by the runtime | Fixed content-hashed private-messaging behavior at the developer layer; distinct adapter identity; no additional authority |
| Codex Profile v3 tool package | Versioned template and startup guard implemented; normal daemon execution blocked | Exact six-file package, host/one-agent capacity evidence, offline-guest file-write/command-exec, native IP network pair and running-tool cancellation passes; earlier failures retained, production image/ownership gates open; see [V3 scope](codex-profile-v3.md) |
| Offline Codex candidate check | Implemented, always execution-blocked | Total profile/target matching, closed local binding, non-authorizing digest, explicit model/tool compatibility blocker, opt-in metadata inspection and subprocess tests; no secret reads, leases or resolved runtime policy |
| Real Codex target | No production target implemented | No approved production image/auth/network/context profile; three opt-in real-provider Runs failed on 2026-09-10 and do not establish provider acceptance |
| Discord Connector | Not implemented | Protocol boundary exists; no Discord token, client, cursor, or delivery loop |
| Production security | Not claimed | Deployment identities, credentials, egress, cancellation, and live-path evidence remain open |

## Implemented control plane

### Ingress and admission

- `connectorwire` defines the small, versioned Connector contract. V1 admits
  text input and a closed action vocabulary; recognized control actions remain
  unsupported rather than being interpreted as arbitrary commands.
- `agentpolicy` compiles an operator-authored, exact Binding from one Connector,
  actor, and conversation to one immutable target revision.
- `agentservice` validates the event, applies the Binding, and linearizes an
  accepted request into a durable Run. Event replay is content-bound:
  byte-equivalent replay returns the original receipt, while a conflicting
  payload under the same retained event ID is rejected.
- Core persists the Binding and policy fingerprints used at admission. Later
  dispatch cannot silently substitute a target or broaden authority.

### Run and delivery lifecycle

- Core SQLite state owns durable Runs, dispatch leases, exact session scope,
  and Connector-scoped outbound delivery.
- `agentdispatch` recovers queued work, freezes the sandbox start request, and
  advances only through compare-protected transitions.
- Outbound recipients derive from the accepted Run. Runner output supplies
  content but cannot choose a Connector or conversation.
- A nonterminal-Run fence serializes each exact authorization/session scope.

### Sandbox and runtime boundary

- `sandboxd` accepts a closed execution request over a private Unix socket and
  verifies the peer UID at connection time.
- Target manifests fix the runner family, adapter version, protocol, image
  digest, workspace, session policy, limits, and profiles. The execution wire
  cannot override those values.
- The separate `harness-target/v2` data contract expresses no persistent Runner
  state or one logical persistent state ref. It has an independent hash domain
  and exact field-name validation; historical v1 bytes remain pinned. Explicit
  `sandboxd/v3` admits the locked-down mock through one version-aware execution
  path; `sandboxd/v2` still rejects v2. Schema v9 durably distinguishes no state
  from missing ownership, and only persistent state receives a mount. A fixed
  new-only mock artifact is tested as a real child process. See
  [Target manifests](target-manifest.md).
- The Docker runtime adapter emits fixed `argv`, uses rootless-runtime
  attestation, and never exposes the runtime socket to the Runner.
- A durable create intent precedes the external create. If the result is
  uncertain, reconciliation uses immutable labels and identity; it does not
  issue a speculative second create.
- Every controller terminal outcome is staged privately in sandbox schema v8.
  Public status and events remain nonterminal until trusted cleanup succeeds.
  One sandbox transaction then publishes the outcome and successor session,
  clears the runtime reference, and releases the writer lock. Core observes
  that result and commits its own terminal/outbox transaction separately.
  Fault tests cover cleanup failure, lost staging responses, late publication
  rollback, database reopen, and preservation of the original outcome without
  re-executing the harness. These are controller/store tests with a fake
  runtime, not proof of actual detached-descendant containment.
  A two-store integration test additionally verifies that Core creates no
  session or delivery before sandbox publication and exactly one delivery
  when it subsequently observes that publication, even after a deadline.
- Sandbox schema v10 adds durable credential generation, revocation and Run
  occupancy to that same transaction boundary. Synthetic tests exercise these
  transactions; the 2026-09-10 canary separately enrolled one dedicated real
  source. Historical targets remain credential-free; candidate checking,
  executable configuration and the Docker profile gate gain no new authority.
  See [credential source lifecycle](credential-source-lifecycle.md) for the
  implemented ordering and remaining physical-source/refresh requirements.
- Schema v11 stores proof in the immutable generation row. Source ownership,
  generation and proof register in one transaction; read-back and replay retain
  the exact pair even after revocation. Proofless synthetic history remains
  explicit and cannot acquire proof in place. Schema guards and reopen checks
  reject malformed/partial proofs. The failed 2026-09-10 canary exercised one
  real held-source enrollment; production enrollment remains unavailable.
- Strict enrolled-target registration reads that immutable generation/proof,
  compares independently approved workspace/auth/disclosure scope and composes
  all credential authority into a new durable target pin in the same transaction.
  Replay, rotation and mixed-batch rollback are tested; credential-free pins and
  legacy synthetic registration remain unchanged. sandboxservice now uses this
  strict path for every registry. Its single startup resolver supplies the base
  pin, explicit state ownership and optional independently approved credential
  scope; the service derives workspace/auth from the matching manifest. The
  compiled ingress policy can project the exact six-field scope without taking
  a request digest or reading enrollment. sandboxd uses the unified mock resolver,
  which rejects unsupported profiles before target registration, including v1.
  The separate opt-in canary also supplies a fixed experimental resolver and
  has exercised a real-source binding. Complete production resolution remains
  absent; a composed hash alone cannot prove it or enable normal execution.
- Under the daemon's existing exclusive process lock, controller startup revokes
  generations referenced by retained credential occupancy in one transaction.
  Failure blocks startup before runtime recovery or new work. Old accepted
  credential Runs become cleanup-only; staged outcomes and uncertain intent
  authority are retained until exact cleanup and atomic publication/release.
  Store opens, background reconciliation, shutdown and idle generations do not
  trigger blanket retirement. Constructor/store fault tests use synthetic
  authority and fake runtimes, without new schema or real credential access.
  Two tagged native restart cases also exercise this order with an actual
  killed controller-owner process. Its physical source lock disappears on death;
  durable occupancy and retirement retain the cleanup fence until exact removal.
- The Linux held-file primitive provides process-local pinning and revalidation.
  Its controller consumer now reads the admitted Run's unrevoked generation and
  proof in one transaction, compares frozen scope/binding values, then holds and
  verifies the native source. Duplicate offers cannot acquire again. Validation
  runs before Create/AttachStart and after cleanup; failures retire only that
  Run's occupied generation. Reconciliation retains handles until revocation,
  runtime cleanup and physical close precede durable publication/release.
  Close failure stays latched until process restart recovery. Publication failure
  or response loss cannot reopen the credential or leave a stale volatile fence.
  Fault tests use constructed proof and a private handle seam. A separate tagged
  native fixture uses real Hold/proof, service admission, Docker and HRP, and
  observes physical lock ordering. Normal executable configuration remains
  blocked; the opt-in real-source observations above retain their limited scope.
- The [credential enrollment contract](credential-source-enrollment.md) selects
  native-ext4 UUID/export-handle identity, immutable object/locator proof and
  conservative retirement after interrupted credential Runs. The isolated
  CaptureProof/VerifyProof adapter now implements digest collection/comparison,
  with synthetic held-file tests and a local native-ext4 backend test.
  Controller Run re-open and held-lock release now consume this boundary, but
  observations alone grant no runtime mount or complete target authority.
- The sandbox session mechanism stores synthetic mock session tokens only in
  sandbox state. Core sees opaque, exact-scope, one-use references with
  target-authored age and turn limits. A real provider-token boundary remains
  unproved.

## Security witness

`make demo-security` uses the production strict decoder, compiled policy,
`agentservice`, and Core SQLite store. It verifies:

1. request-supplied target fields and arbitrary actions are rejected;
2. a recognized but unsupported target-selection action creates no Run;
3. a non-exact actor/conversation tuple creates no Run;
4. an accepted queued Run and its immutable Binding evidence survive exact
   child-process `SIGKILL` and database reopen; and
5. exact replay deduplicates while conflicting replay is rejected without a
   replacement Run.

The child receives an empty environment. The witness does not start Docker,
open a network listener, contact Discord or a model provider, or read provider
credentials. It is intentionally not evidence for container isolation,
credential safety, whole-system crash recovery, or formal verification.

## Codex adapter and profile: present but not wired into a target

`internal/codexadapter` and `cmd/codex-runner` implement the first closed
`new_only` HRP/1 translation cut. The adapter:

- requires the sealed `gpt-5.6-sol` model alias and `medium` reasoning effort;
- constructs a fixed Codex invocation rather than accepting message-selected
  options;
- accepts only the closed terminal event needed by the outer protocol;
- bounds and redacts provider output and failures; and
- rejects resume, non-text input, and unsupported profiles.

`internal/codexprofile` seals the candidate CLI 0.151.0 artifact digest,
model/effort, profile-ref projection, single-file ChatGPT credential mechanism,
disposable state, mediated-control-only network claim, empty customization
allow-set, and post-quiescence output rule. The concrete local credential slot
is deliberately unresolved and excluded. Its contract fingerprint is pinned in
code and every contract field is fingerprint-relevant. This is configuration
evidence, not runtime evidence: the current Docker profile gate still rejects
the expressible Codex projection before any CLI call. See
`codex-profile-v1.md`.

The separate v2 contract preserves that authority envelope and adds one exact,
content-hashed private-messaging behavior profile. `codexadapter.MessagingConfig`
maps it to the documented `developer_instructions` config key, while the
untrusted user message remains byte-exact stdin and absent from argv/env. It
reports adapter `0.2.0-new-only`, so a future manifest cannot confuse it with
the context-free v1 behavior. Unit tests pin both contract fingerprints, the
fixed instruction bytes, the native role mapping, and pre-readiness rejection
of unknown profiles. An opt-in exact-CLI canary additionally checks byte-exact
developer/user role placement and absence of three hostile workspace-file
sentinels under an empty home. The debug subcommand cannot accept two
exec-only ignore flags, so that canary is decoding/placement evidence rather
than complete exec or provider-context closure. See `codex-profile-v2.md`.
This is model-behavior configuration, not prompt-injection protection or an
authorization boundary.

The tagged [synthetic exec fixture](codex-exec-integration.md) observed the full
local text path on 2026-09-08, including native request role placement and
precreated final-file consumption. Its no-catalog baseline had an empty
top-level tools array; that alone did not establish complete tool absence.
The explicit synthetic direct-mode catalog is only a lab delta. A same-day
exact-binary `debug models --bundled` check identified `code_mode_only` for
`gpt-5.6-sol`, conflicting with V1/V2's disabled Code Mode host. The
offline candidate reports `model_tool_compatibility`. V1/V2 remain unchanged;
the separate [V3 template](codex-profile-v3.md), added on 2026-09-09, pins and
configures the native host and checks package integrity before readiness.
Its canary reads native `input.additional_tools` and exercises actual results.
Host execution and one-agent capacity have component evidence. File writing
failed at the workstation's nested AppArmor boundary; a separate offline guest
passed the file-write subcase on 2026-09-09 04:23 UTC with a temporary guest
compatibility profile and a read-only package owned by the mapped test UID. Exact nonce
contents, two synthetic requests, V3 completion and quiescence passed; wrapper,
policy cleanup, domain teardown and evidence collection also passed separately.
On **2026-09-09 05:00 UTC**, a fresh guest passed only the native `command-exec`
subcase using the same offline recipe. A fixed probe's stdout/stderr, deliberate
exit 17, independent nonce file, CWD, UID 1001, `NoNewPrivs=1`, zero effective
capabilities and absent synthetic provider environment key were checked. The
outer V3 Run completed after two synthetic requests with no remaining
descendants; wrapper, policy cleanup, domain teardown and collection passed.
This adds command completion evidence, not new-package network, cancellation,
real-credential or production acceptance. Neither file-write nor the older
five direct-catalog cases was rerun for that check.
On **2026-09-09 05:28 UTC**, a separate fresh guest passed only the V3 network
allow/deny pair. In the control, a native tool reached the same listener used
by client inference once; in the denied case it returned `EPERM` with zero
probe hits while client inference still worked. IPv4/IPv6 TCP/UDP socket
creation succeeded in the control and returned `EPERM` under the unchanged
deny configuration. Each case had two synthetic requests, an independently
checked nonce file, V3 completion and descendant quiescence; all five result
axes passed. The control changed one test invocation network bit inside the
offline guest. Unix sockets, inherited FDs, provider mediation and cancellation
remain outside this witness; it does not enable a runtime target.
On **2026-09-09 05:55 UTC**, another fresh guest passed only V3 `command-cancel`.
The actual Code Mode tool held a parent-created lock and wrote an exact nonce
receipt; independent lock contention preceded cancellation. One synthetic
request and the sole V3 cancelled terminal at sequence 2 were observed. The
leader was reaped, all namespace descendants were gone and the original lock
was available before workspace/namespace teardown, in 5 ms on this run. All
five result axes passed. This is one running-tool cancellation witness;
timeout variants, detached descendants and exact-image cleanup before terminal
publication remain open. No earlier native case was rerun.
Earlier precondition failures remain retained. Workstation/server-host policy
and the product ownership guard were unchanged; production image composition
is still unverified. Bundled metadata does not establish the authenticated provider's
catalog, and V3 does not enable a runtime target. The earlier complete
tool/positive-control/held-lock cancellation fixture initially failed at nested
sandbox startup. A later same-day
minimal control and kernel journal identified the observed host's enforcing
AppArmor child capability restriction; no host policy was relaxed.
A subsequent fresh offline Ubuntu guest also failed the outer startup
preflight before any native case: retained logs show `unprivileged_userns`
denying `setpcap` and `net_admin`. That guest was shut down and its transient
domain removed. Binary/dependency checks alone did not establish a compatible
test-runtime namespace policy.
At 23:21 UTC, an authorized offline guest run reproduced the original refusal,
loaded a temporary exact-path bwrap compatibility exception and passed the
unprofiled refusal and nested/native startup controls. The unchanged static
fixture passed all five cases, including strict tool `EPERM`, the same-endpoint
positive control and held-lock cancellation. This is not a guest race result
or a production policy approval; no host security configuration changed.
The separate guest wrapper reported an error and lost its final serial summary.
Read-only disk extraction recovered the native exit 0 and complete results;
profile snapshots/kernel events verify profile removal, the generic policy hash
is unchanged and the transient VM is absent. The failed wrapper receipt remains
explicit. A local durable-log correction passed output-fault checks but has
not been executed in a guest; final live sysctl values were not independently
retained. See the integration scope for that limitation and dated evidence.
Cancellation during an active provider request did return the sole cancelled
terminal, close the connection and leave no namespace descendants before
outer teardown.
`ExecLauncher` now preserves empty invocation environments and bounds
inherited-pipe drain after leader exit; this does not prove descendant
quiescence or replace the outer runtime's release rule.

The repository ships no Codex Runner image or executable Codex target, and
`make build` does not produce `cmd/codex-runner`. Enabling a real path therefore
requires an explicit, reviewable image and target addition; configuration in the
shipped examples cannot select it. The profile also requires no persistent
Runner `/state`, which no valid v1 manifest can express. The v3 local mock
path now integrates TargetManifest v2, explicit ownership kind and conditional
mounts, but it deliberately rejects Codex. The complete production provider-profile resolver remains unimplemented.
The separate tagged canary now supplies fixed credential/network runtime
construction and local enrollment, pending real-provider acceptance.
Context, credential, network, cancellation, and teardown gates remain open,
including proof that repository-level, system, or managed customization cannot
enter the harness unexpectedly.

`codexprofile.Contract.MatchTarget` and `internal/codexcandidate` now implement
the offline subset: full sealed-profile matching against TargetManifest v2,
one closed local workspace/credential binding, a prefixed configuration digest
and optional metadata-only inspection. `hgwctl codex check` always reports
`blocked` and exits 3 for valid configuration; it does not load sandboxd's
config, register authority, open Core state or invoke a runtime. The public
candidate example has a placeholder image digest. Matching metadata cannot
validate auth, prevent races or supply executable mediation content. See
[the preflight contract and usage](codex-candidate-preflight.md).

## Open gates

The [content evolution and verification contract](content-evolution-and-verification.md)
was adopted on 2026-09-09. It defines typed-content extension boundaries and
change-specific evidence reuse; current protocols remain text-only and no media
implementation or real-target gate is completed by that decision.

The [live-path delivery plan](codex-live-path-plan.md), first reviewed on
2026-09-09 and updated on 2026-09-10, maps the eight candidate blockers to code
and evidence. Its synthetic delivery unit now connects provider control,
enrolled credential handoff and the fixed V3 runtime under fake ingress, with
the scoped evidence below. The subsequent
[response rejection and bounded failure handling](codex-provider-canary.md#actionable-rejection-and-bounded-failure-handling--2026-09-10)
package now has a real-Run witness for precise rejection and suppression of
later same-operation dispatch; response-contract compatibility remains an open
gate.
The [provider-control/credential-delivery decision](codex-control-boundary.md)
defines a bounded synthetic Responses consumer and a pre-execution mounted-object
gate. The verifier/bootstrap component has six passing local rootless cases
with synthetic files and a fixed synthetic successor. The bounded Responses
handler now has in-memory HTTP and lifetime/cleanup-fault evidence. The
[first combined rootless case](codex-control-boundary.md#first-composed-case-namespace-creation-rejected)
at **2026-09-09 08:16 UTC** passed mounted-source verification and dispatched two
native Responses requests, but failed native command execution at nested
namespace creation. Exact container removal and subsequent source unlock passed.
The [scoped compatibility follow-up](codex-control-boundary.md#runtime-diagnosis-and-passing-scoped-compatibility-case)
at **09:04 UTC** passed using a container-local seccomp profile and fixed UID
setup that preserved source ownership and cleared all capabilities before the
existing bootstrap gate. Native command/readback, quiescence and ordered cleanup
passed. This fixture does not approve the startup template for production.
The [controller-owned follow-up](codex-control-boundary.md#controller-owned-synthetic-v3-witness)
at **10:24 UTC** bound the fixture artifacts/policy into synthetic authority and
passed native enrollment, service/controller/Docker handoff, HRP and ordered
cleanup/publication. At **10:53–10:56 UTC**, the
[Core ingress follow-up](codex-control-boundary.md#core-ingress-and-focused-native-fault-witnesses)
passed source replacement denial, lost-reply/repeated-cleanup-failure recovery
and cancellation of a live native tool, through the real local HTTP interfaces
to one scoped outbox delivery. At **11:32–11:35 UTC**,
[native owner recovery](codex-control-boundary.md#native-owner-crash-and-recovery-witnesses)
passed SIGKILL with a bound runtime and with an existing unbound Create, retained
ownership through unavailable startup inspection, and healthy cleanup without
re-execution. At **19:54 / 20:12 UTC**, the
[termination follow-up](codex-control-boundary.md#deadline-and-resistant-descendant-witnesses)
passed a fixed resistant/`setsid` Runner and native held-tool deadline through
exact cleanup and one delivery. Still-absent delayed Create, native descendant
variants and production transport/context obligations remain open. At **20:28 UTC**,
[permanent admission feedback](codex-control-boundary.md#permanent-credential-admission-feedback)
passed revoked-generation/wrong-scope denial through the real service/HTTP/Core
path, producing one fixed failure after exact Run absence; transient failures
and existing Runs retain their prior behavior. At **21:04–21:05 UTC**, the
[built-in operation inventory](codex-provider-operations.md) passed fresh and
refreshed synthetic native file auth, including persistence. It narrows the
transport decision. The **21:24 UTC** fixed custom-provider candidate passed
uncompressed HTTPS/SSE and refreshed-token use; its header differences remain
explicit. The **22:05 UTC** offline composition covered operation enforcement
and scoped native-tool separation; the **22:49–22:54 UTC**
[controller lifecycle composition](codex-provider-operations.md#offline-controller-lifecycle)
added mounted-file refresh, cleanup/publication and cancellation/recovery.
The [bounded provider relay and transport decision](codex-provider-transport.md)
select an owner-hosted Unix/TLS operation endpoint and a network-none client
domain. The dated standalone native witness and subsequent
[runtime-owned canary](codex-provider-canary.md) now cover mount/UID/tool and
cleanup/publication integration within their experimental scope, with a distinct
opt-in pin. Normal executable configuration, production enrollment/rotation,
complete production authority and deployment isolation remain unresolved.
Real-provider acceptance failed in the three Runs recorded above; Discord
acceptance remains later work. The production target remains blocked.

### Deployment identities and local IPC

- provision separate Connector, Core, and sandbox service identities;
- verify private path ownership, setgid group traversal, socket `0660` modes,
  connect-time UID checks, restart behavior, and log redaction on the target
  host; and
- demonstrate that neither the Connector nor Runner can reach Core data,
  sandbox state, provider session state, or the rootless runtime socket.

### Real Codex target

- materialize and attest the sealed CLI artifact in a digest-pinned runner
  image;
- build on the locally verified v3/v2 mock state path without weakening its
  explicit profile gate or changing legacy TargetManifest/revision fingerprints;
- resolve immutable policy, auth, network, context, resource, and teardown
  authority plus the local credential slot/generation/source identity into a
  new target-revision security fingerprint;
- validate overlapping workspace/credential confidentiality domains before any
  egress-enabled target is selectable;
- close repository/system customization injection;
- validate the implemented generic terminal-publication mechanism against the
  exact runtime image's cleanup and descendant-quiescence behavior;
- run credential reach, refresh, revocation, output-redaction, provider-egress,
  tool-egress, cancellation, detached-descendant, and quiescence canaries; and
- exercise fake ingress against the real target before introducing any
  platform credential.

### Discord Connector

- normalize Discord's stable actor, channel, message, and event identities;
- keep bot credentials and gateway cursors inside the Connector domain;
- implement bounded durable ingress spool, reconnect/catch-up, replay, self-
  event rejection, and outbound completion semantics; and
- pass the isolated private-Discord adversarial cases before expanding to
  another platform.

## Deliberately deferred

- Claude Code and additional harness implementations;
- WhatsApp and other messaging platforms;
- attachments, rich interactions, remote provisioning, and remote approvals;
- dynamic skills, plugins, MCP servers, mounts, images, credentials, or network
  policy;
- workflow orchestration, multi-agent scheduling, Kubernetes, multi-host
  operation, and high availability; and
- ACP adoption, unless a real Runner conformance experiment demonstrates that
  it reduces adapter maintenance without replacing the HSG security envelope.

## Verification commands

The release checks require Go 1.26.7 or newer and are:

```bash
test -z "$(gofmt -l cmd demo internal)"
make build
go test -count=1 ./...
go test -race -count=1 ./...
go vet ./...
make demo-security
make config-check
make bakeoff-check
```

Passing these commands supports only the scopes named above. A green unit test
suite is not evidence that the disabled live integration is safe.
