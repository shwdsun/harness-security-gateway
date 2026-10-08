# Provider credential isolation: implementation plan

The goal is to keep reusable model-service authentication outside task-controlled
code while retaining useful Codex execution. `CRED-01` is the credential-recovery
test case in the comparison suite; `M1` is the wider delivery milestone, including
real-service compatibility, renewal, replies and cleanup. See [delivery criteria](milestones.md#credential-isolated-messaging)
and [core concepts](concepts.md#planning-test-and-design-identifiers).
The dated work-package notes below retain their original evidence scope;
[implementation status](implementation-status.md#credential-isolation) gives current readiness.

Updated: **2026-10-01**. Status: **isolated runtime/profile candidate wired; composed acceptance open**.
The client-side and trusted native-refresh offline compatibility probes below
have scoped positive evidence. Owner-only storage and managed-auth parsing are
implemented locally, along with the private native consumer and per-Run provider
adapter below. The [V4 runtime/profile candidate](codex-profile-v4.md) now wires
the owner borrow, separate local seed, pre-Create readiness, fast bootstrap,
root-controlled artifacts and startup gate. Complete native runtime/receiver,
service observation and secret-boundary acceptance remain open.
This narrows the existing [F7 gap](drift-ledger.md#missing--f7-credential-isolation-from-the-harness).
It does not change the deployed `credential-exposed-personal` classification,
authorize a live provider call, or supersede an immutable TargetRevision.

## Claim and present mechanism

[CRED-01](../bakeoff/cases.json) requires model-controlled tools to be unable to
recover reusable provider credentials from files, environment, process state,
protocol traffic, logs or persisted sessions. It is a P0 acceptance case, not
a daemon, error code or report of an observed credential theft.

```text
Discord -> Connector -> exact Core Binding -> durable Run
                                             |
                                  sandboxd / fixed TargetRevision
                                             |
                                disposable Runner with native Codex
                                  |                         |
                          workspace tools          fixed provider relay
                                                           |
                                              host operation endpoint -> provider
```

Connector owns the platform credential. Core owns authorization and durable
delivery, with no provider secret. The sandbox owner resolves an enrolled,
scope-bound credential generation and verifies the mounted object before
execution. The real `auth.json` is then a writable single-file bind inside the
Runner: native Codex loads it and persists refreshed tokens there. Native tools
can read that file. A dedicated account, `0600` mode or read-only bind would not
establish secrecy from code that retains read access.

The existing endpoint enforces operations and limits; it does not supply the
credential. `codexprovider.project` accepts client Authorization/account headers
and a client refresh token, and `upstreamResponse` forwards the projected
request. Confining network destinations cannot make a readable reusable token
non-reusable. The current classification is therefore accurate.

Code anchors: [profile](../internal/codexprofile/contract.go),
[mounted-object verification](../internal/dockerruntime/credential_linux_amd64.go),
[request projection](../internal/codexprovider/policy.go),
[fixed upstream](../internal/codexprovider/upstream.go),
[credential lifecycle](credential-source-lifecycle.md).

## Direction, subject to compatibility evidence

Extend the runtime-owned provider boundary to hold authentication outside the
entire untrusted Runner. Reuse its per-Run endpoint and existing credential
enrollment/occupancy where their assumptions remain valid. Do not add a generic
secret service, another agent loop, provider fields to Core/HRP, or a selectable
URL/token/path in message input.

```text
Runner: task + disposable local auth representation, no real provider secret
       -> one runtime-owned, Run-scoped endpoint
       -> validate operation and live authority
       -> construct upstream auth using owner-held credential
       -> fixed provider
```

The local representation may be copied by a tool; its secrecy is not the claim.
It must confer no provider authority outside its exact live Run channel. A nonce
alone is not process identity. The owner binds the channel to its Run, immutable
target, enrolled generation and deadline; requests cannot override these.
Tool access to the native control channel must remain denied and be rechecked
in the composed runtime. Even a compromised Runner must not obtain host
administration, another Run's channel or raw tokens.

For inference/catalog, replace client auth and account identity with owner-chosen
values after validating the local representation. Never treat client headers or
JWT claims as authority. Preserve the existing operation allowlist, bounded
requests, model/effort checks, response rules and no speculative retry.

Real refresh requests and responses stay outside the Runner. If the CLI requires
a refresh-shaped exchange, the boundary may return only a fresh local
representation. Real access, refresh and ID tokens must not cross that boundary,
including in errors or logs. This is a compatibility candidate, not permission
to invent an OAuth client or assume arbitrary fake JWTs work in production.

## Compatibility gate

Start with one bounded **offline** composition using the pinned CLI and existing
synthetic provider fixture. No real auth file, provider account or daemon is needed.
Use the actual fixed native path: `cmd/codex-provider-canary-runner` calls
`codexadapter.Run` with `ProviderCanaryLauncher`, and the offline bundle copies
that Runner as a pinned native input. Host-binary build roots alone omit this
consumer. See the corrected packaging entry in [drift ledger](drift-ledger.md).
Existing synthetic JWT/file-refresh tests show a useful fixture shape; they do
not establish credential substitution or production support. Determine:

1. Whether the subscription-mode CLI accepts disposable local identity data for
   startup, catalog, two inference turns and a native tool invocation.
2. Whether stale-cache and authentication-rejection paths can complete with
   owner-only synthetic provider tokens, without returning those tokens to the
   CLI or persisting them in its home/session state.
3. How trusted refresh is performed and persisted. Prefer a narrow native auth
   facility if the pinned client exposes one without launching model work or
   accepting repository configuration. The September 19 witness below establishes
   a fixed-version candidate, not a production consumer. A custom refresh
   implementation needs an explicit compatibility decision.

Official documentation checked on 2026-09-17 describes cached file credentials
and automatic native refresh ([authentication](https://learn.chatgpt.com/docs/auth)).
Its [CI/CD guidance](https://learn.chatgpt.com/docs/auth/ci-cd-auth) assumes a trusted
runner, serialized credential use and native refresh; it does not validate a
token-substitution gateway. Current docs do not prove behavior of CLI 0.151.0.
API-key authentication has a different access/billing contract; do not silently
switch the operator's subscription workflow to it.

If this probe fails, retain the present weaker classification and document the
specific obstacle. Do not expand network access, mount real credentials again
under an isolation label, or build a general auth platform to force a pass.

## Offline client compatibility result — 2026-09-17

The opt-in [substitution fixture](../internal/codexadapter/credential_substitution_linux_test.go)
used the actual `ProviderCanaryLauncher`, fixed CLI 0.151.0 and existing
`codexprovider.NewSynthetic` endpoint. A separate owner process generated random
synthetic upstream secrets; only local auth representations, the endpoint/CA,
fixed package, fixture executable and owned workspace/home entered each fresh
network-none container. The native tool read its local auth file and wrote a
marker independently checked against its returned tool output.

| Case | Observed operations | Result |
| --- | --- | --- |
| Fresh local auth | Two successful inference requests; no refresh | Passed at 02:14 UTC |
| Stale local auth | One refresh and local-token persistence; two successful inference requests | Passed at 02:14 UTC |
| Continuously rejected old auth | Two old-generation 401s, one refresh/persistence, two successful new-generation requests | Passed at 02:17 UTC |

An earlier rejection case failed its refresh assertion: after one 401 the
fixture incorrectly accepted the old auth on retry, and the client completed
without refresh. That failed result is retained. The corrected fixture rejects
the old generation continuously, bounds old attempts to two, and never raises
the endpoint or client retry budget. Only that case was rerun; the fresh/stale
results retain their original artifacts and dates.

All four created containers were independently absent after cleanup, without
rescue. Owner callbacks and local relays joined. Dynamic owner-secret canaries
were absent from the scanned client home, workspace and captured output. An
owner-secret poison body on 401 was replaced by the existing endpoint's fixed
error response. Final native reply matched the marker exactly.

This establishes that this fixed client can use local representations, including
its stale-cache and persistent-rejection refresh paths. It does **not** implement
or validate a real OAuth refresh broker: upstream auth replacement and owner
persistence were simulated callbacks. Client temporary output directories and
memory were not exhaustively scanned; cross-Run channel replay, owner crashes,
concurrent refresh and production artifact acceptance were not exercised.
The deployed profile therefore remains `credential-exposed-personal`.

At this point the next gate was the trusted refresh/write-back contract.
The [earlier native account-read witness](credential-source-lifecycle.md)
offers a candidate: it performed synthetic refresh with the pinned app-server,
but also returned success when a read-only source prevented persistence and did
not demonstrate clean exit. It cannot simply be promoted to a production helper.
Independent persistence and cleanup checks remain required before integration.

## Offline trusted native-refresh result — 2026-09-19

The [native-auth fixture](../internal/codexadapter/testdata/native-auth-probe/main_linux.go)
used CLI 0.151.0 in network-none containers, a loopback-only synthetic refresh
endpoint and a new auth file. It issued only initialize/initialized/account-read
messages; no thread, model turn, tool invocation or real credential was involved.
The owner independently checked the entire synthetic token group, account,
refresh timestamp, original inode/owner, `0600`, single link and supervisor fsync
after native process/output completion. The host independently checked the file
and stopped container. This extends the dated September 7 storage witness.

| Case | Observation | Consumer outcome |
| --- | --- | --- |
| Fresh | Non-forcing reads made no refresh request; forced reads refreshed and persisted once per process, across two processes | Accepted |
| Stale | One refresh was already observed when initialize returned; `account/read(false)` added none. A new process read the saved state without refresh, then `true` performed the next rotation | Accepted |
| Read-only source | One successful refresh response and a managed-account RPC result, but the host source remained byte-identical | Rejected independently of RPC success |
| Provider refusal | One refusal response; RPC reported no error but yielded no verified managed ChatGPT account; source unchanged | Rejected |
| Response withheld | Request received, no response; five-second RPC deadline, then bounded stop and join; source unchanged | Rejected as uncertain, without retry |

The first stale case failed its once-per-process assertion: combining stale
startup with an explicit forcing read produced two valid consecutive rotations.
That failure remains retained. A bounded continuation separated automatic
freshness from forced refresh, kept the one-rotation assertion, and exercised the
three previously unrun negative cases from fresh state. The successful fresh
case was reused. Six total experiment containers were removed by verified exact
identity, with no rescue cleanup. No deployed state changed.

Fresh/stale processes exited zero after stdin EOF. Read-only/refusal cases entered
the supervisor's TERM step and ultimately exited zero; the fixture did not
record the signal syscall result, so TERM necessity is not established. The
withheld-response process ended with SIGTERM 15 and joined. No case required
SIGKILL. Client/output joins and an empty PID namespace were checked. The first
fresh case observed zero active mock handlers after server Close; the continuation
also used bounded server Shutdown before its final snapshot.

Even this account-only invocation populated `installation_id` and built-in
skills in CODEX_HOME. The trusted consumer therefore needs an independent
temporary home; the enrolled slot must retain its single `auth.json` contract.
No model tools were requested, but disabling model work does not imply an
otherwise empty native home.

### Production consumer decision

Use the fixed native auth facility behind the existing trusted runtime/provider
owner. Do not implement OAuth or add another daemon. Keep its closed purposes
separate: ensure usable cached auth through a non-forcing read; refresh after a
provider rejection only when that invocation has not already produced a verified
automatic refresh. Do not unconditionally force a second rotation after stale
startup. Native request counts in this fixture are a compatibility observation,
not a provider-wide retry guarantee. The owner chooses the purpose from its own
verified state; a downstream refresh-shaped request cannot itself authorize a
real forced refresh or select an account.

The production consumer must satisfy these obligations before integration:

- Exclusive enrolled-generation occupancy and held-source identity cover every
  helper and provider operation. The new explicit owner borrow supplies narrow
  owner-only read/persistence access; the ordinary metadata
  API and old runtime handoff still grant no token read or fsync contract.
- Pin the executable, argv, closed RPC methods, environment, trusted endpoint
  policy and temporary home. Repository/user configuration, plugins, model work
  and remote-supplied options cannot reach this helper. The experimental URL
  override is not a production configuration interface.
- Separate a readiness result from evidence of a completed refresh. Parse and
  validate the persisted credential/account state, then validate and sync the
  held object after all writers stop. The synthetic expected token strings are
  a test oracle; production must not require tokens to change on every refresh
  or infer successful persistence solely from an RPC or timestamp.
- Bound cancellation and EOF/TERM/KILL teardown, join readers and callbacks, and
  include the trusted helper in owner-loss cleanup obligations. Killing a process
  or closing a held descriptor cannot release durable occupancy. An uncertain
  refresh or persistence failure retires the generation through the existing
  lifecycle; it never restores old token bytes or retries to hide uncertainty.
- Expose only the validated access/account data needed by the fixed provider
  transport inside the owner. Real token bytes, raw native diagnostics and refresh
  responses never enter the Runner, Core, HRP, session artifacts or public diagnostics.

The concrete helper placement, held-object handoff and crash/write-back ordering
must be verified during that implementation; the isolated container fixture does
not prove a host-process implementation. Native EOF behavior alone is not a
cleanup guarantee. Concurrent use, owner loss during refresh, partial writes,
power loss, real OAuth and the composed secret-reachability claim remain outside
this probe. The offline compatibility gate is resolved sufficiently to implement
the trusted consumer; CRED-01 and M1 remain open.

## Owner storage implementation — 2026-09-19

A subsequent code/evidence review separated three claims: native compatibility,
candidate storage, and verified real refresh. The synthetic probe knew the exact
returned token group; a production managed-account RPC plus an otherwise valid
old auth file cannot supply the same proof. A replacement runtime owner also
cannot treat an absent in-memory endpoint as proof that a future external native
helper has stopped. These are integration obligations, not reasons to rerun the
completed native probe or expand the gateway into an auth service.

The [owner storage component](../internal/credentialsource/owner_linux.go) now
provides scope/proof-bound access exclusive of the old mount capability, bounded
pinned-file reads and compare/write/truncate/fsync/readback on the enrolled inode.
Failure invalidates the held source, retains its locks and never rolls back
tokens. Closing a borrow cannot unlock the source or change its selected mode.
The [managed-auth parser](../internal/codexprovider/owner_auth.go) rejects ambiguous
file shapes, account/subject changes and refresh-time rollback, while allowing
unchanged token strings. These APIs do not dispatch requests or prove freshness.
See the [detailed storage contract](credential-source-lifecycle.md#owner-only-content-access--2026-09-19).

Independent review identified two concrete fixes in the first implementation:
formatting must not expose private secret fields, and the direct mount
observer must participate in the shared mode choice. The formatting counterexample
failed before its fix and then passed. Actual temporary-file fault tests cover
partial writes, failed sync/readback/close, stale baseline and replaced inode,
retained locks, shorter updates, concurrent Close and competing source modes.
The full regression also exposed two existing controller recovery paths; their
deterministic failures, corrections and passing final checks are recorded in
[dated implementation record](implementation-history.md#owner-credential-storage--2026-09-19).

No executable path selects the new borrow/parser and no new schema, daemon,
container or configuration was introduced. Next implement the native consumer's
refresh-result evidence and process/recovery contract, then connect the existing
provider boundary and isolated Runner representation. A valid candidate saved
successfully is not itself a verified OAuth refresh. CRED-01 and M1 remain open.

## Trusted native consumer candidate — 2026-09-20

The owner now has a private, currently unwired
[consumer implementation](../internal/codexprovider/owner_native_linux_amd64.go).
Its constructor is inert. The future per-Run provider must register it before
opening admission or starting a helper; failure retains the invocation object
until cleanup is proven. No current executable/profile can select this path.

Each invocation copies the owner-held managed auth into a new private temporary
home, launches only the fixed app-server account methods and observes at most one
native refresh. An ephemeral owner-private loopback relay validates the native
refresh request against the held baseline and forwards only the existing fixed
OAuth operation. It captures the complete access/refresh/ID token group from that
exchange. This URL is internally generated, not a new configuration or remote
option; the relay never serves the Runner. The candidate rejects partial token
responses instead of guessing the pinned native client's merge semantics.

After native initialization, an already attempted automatic stale refresh
suppresses another explicit force. Cached readiness requires unchanged storage;
a refreshed candidate must match the actual complete response and advance the
native persistence timestamp. Token strings themselves may stay unchanged. The
timestamp is only a write marker: it never replaces the observed response or
account/subject checks. The enrolled source is updated through OwnerAccess only
after process termination, both output readers and all admitted refresh callbacks
have joined. The existing compare/write/truncate/fsync/readback contract remains.

The [fixed Linux/amd64 launcher](../internal/codexprovider/native_launcher/README.md)
installs an inherited process-creation restriction before reading auth: threads
remain allowed, new TGIDs do not. It executes the digest-checked native ELF from
an inherited FD with fixed argv. This is a restriction on a trusted auth helper,
not a generic untrusted-code sandbox. The consumer supplies a closed environment
and fresh HOME/working directory; an existing `/etc/codex` customization tree is
rejected by this candidate. The new launcher still needs immutable artifact
provenance in the future isolated profile; none of the old profiles acquire it.

Cleanup targets the original process via pidfd. EOF, cancellation, a sent signal
or an OS error from Wait is insufficient: cleanup requires a valid terminal
process state and joined readers/callbacks. A nonzero/forced exit can be cleaned
up but cannot yield accepted auth. Unknown Wait or incomplete join retains the
resource obligation. Failure invalidates owner access, with no refresh replay or
credential rollback. The controller still owns generation retirement and durable
occupancy; connecting those actions is part of the remaining integration.

The candidate startup gate checks a fixed root-controlled, nondelegated cgroup v2
leaf for the existing owner service. It must execute after acquiring the global
process lock and before opening durable stores or constructing the controller.
Any additional member, zero PID, child cgroup, non-domain type, writable migration
boundary, privilege or unexpected scope refuses recovery. This assumes the
closed trusted host launch path and no concurrent administrator migration; it is
not an atomic snapshot proof against arbitrary process churn. The fixed helper
restriction prevents a previous helper from creating replacement TGIDs. Actual
service gate observation and entrypoint placement remain integration gates; an
absent in-memory endpoint does not independently prove process absence.

The affected native/filter witness now passes using fixed CLI 0.151.0 and only
synthetic, unchanged-token responses in a network-none container. Fresh and stale
invocations each refresh once and reach accepted test-storage persistence after
the consumer's joins. The initial native failure identified `emittedAtMs` on
notifications, absent from the first mock. A local counterexample reproduced the
failure, then the parser accepted that one optional nonnegative integer only on
notifications and discarded it. Unknown/case-alias keys, bad metadata types and
response/request placement still reject. The diagnostic build was not an
acceptance artifact; the passing witness used canonical source without overlays.
This renews native consumer compatibility, not actual HeldSource/provider/Runner
composition or the deployed cgroup gate. Earlier failed observations are retained.

## Per-Run provider authentication — 2026-09-27

The private [adapter](../internal/codexprovider/isolated_linux_amd64.go) composes
the existing Endpoint and native owner consumer. Construction creates only the
closed endpoint and random local representation. The runtime must register that
resource before Open, which resolves owner readiness before opening admission.
The one-time client seed contains fictional account/subject/email and independently
random local access/refresh values, with a fresh timestamp. Owner auth is never
an input to its encoding. A local value is matched exactly against its issuing
instance; client JWT claims do not select any authority.

Accepted inference/catalog requests receive owner-chosen upstream auth in a
separate request copy. A client Refresh validates the local value and changes
only the local representation, even without any prior rejection. The adapter
cannot use that request to authorize real OAuth. The recovery flow is:

```text
Ready(owner version 0, local 0)
  -> valid upstream 401: fence new old-auth requests; force native once
  -> verified persistence + full join: owner version 1, await local Refresh
  -> client Refresh: issue local 1, ready again
```

The original request receives a sanitized 401 and is never resent by the adapter.
Further old local auth receives local 401 until the native client refreshes it.
Concurrent and late responses carry their original in-memory owner version;
they cannot spend another recovery or revoke the newer representation. This
version is unrelated to the durable enrolled generation. A second 401 from the
current recovered owner fails closed and invalidates the original shared source.
403/429, transport/policy failure, timeout or SSE text never authorize recovery.

Refresh stays limited to one admitted HTTP request; Catalog stays limited to two.
A malformed local value may consume the existing Refresh slot without issuing
new auth. Independent review reproduced the resulting budget mismatch and the
adapter now checks the Endpoint's admission counter before starting recovery.
If the slot was already consumed, this Run stops without useless owner refresh
or treating the local mistake as credential corruption. A legitimate Refresh
admitted after recovery began waits for the joined result and can still finish.
Initial local auth is fresh so ordinary startup does not spend that slot.

Recovery runs synchronously under the existing 45-second exchange cancellation;
there is no detached task or larger retry budget. Close cancels admission and
joins native work, Endpoint workers and an outstanding Open. Timeout retains the
resource. Auth health is separate: the concrete consumer invalidates the same
HeldSource held by the controller, whose existing close path must retire it before
source close and durable release. A successful Close means joined resources, not
healthy credentials. No second taint table, service or Core/HRP field is needed.
Local responses carry private provenance so diagnostics do not claim an actual
upstream refresh/status for them.

The affected [fixed-native witness](../internal/codexprovider/isolated_pinned_linux_amd64_test.go)
uses exactly `initialAuth()` output. With synthetic upstreams and the actual
provider/native consumer, CLI 0.151.0 completes after one upstream 401, one owner
native refresh, one local 401 and one local Refresh. Unchanged owner token strings
work. Two test-storage commits distinguish cached readiness and later refresh;
dynamic raw owner canaries are absent from bounded client file/output and
diagnostic scans. The single network-none container was removed and absence
verified, with no rescue or external model/provider traffic.

This is auth compatibility and component lifecycle evidence. The fixture shares
PID/mount domains between client and owner and uses test storage; it proves no
final Runner secret boundary, actual enrollment, host service cgroup, HRP/tool
path or Catalog-401 behavior. Those are affected integration gates. No executable
or immutable target selects this adapter yet; original profiles remain unchanged.

Runtime wiring must also separate preparation from fast bootstrap admission:
the existing permit phase allows 10 seconds, while native readiness can take up
to 60 seconds plus cleanup. Register the resource and prepare owner auth before
launching the container; do not insert a slow native invocation into the old
permit phase or silently increase that profile's budget. Cancellation and
pre-Create failures still owe provider/helper joins before occupancy release.

## Lifetime and persistence obligations

- Acquire exclusive credential use through the existing owner/enrollment lane.
  Real storage is never mounted, inherited or serialized into the Runner.
- Define owner refresh persistence before wiring it: successful rotation followed
  by a crash or write failure must not silently restore an old credential or
  start another execution. Existing inode/proof checks cannot simply be reused
  if the new writer replaces the file; retain the proven object contract or
  explicitly version and verify the changed enrollment contract.
- Serialize refresh within a Run as well as across Runs. Refresh uncertainty
  blocks further authenticated work and retains necessary evidence; it does
  not trigger unbounded refresh or inference replay. Never roll credentials back.
- Close provider admission on cancellation, deadline or owner loss; discard
  local capabilities and join outstanding local operations during teardown.
  Already transmitted provider requests cannot be recalled. Container absence
  and existing durable cleanup obligations still govern publication/release.
- Existing local generation revocation blocks future starts; it does not revoke
  provider tokens or automatically cancel a live Run. Preserve that distinction.
  Stronger active-Run revocation behavior needs its own specification and tests.
- Restart cleans up old Runs; it never resurrects an old auth channel.
  A new Run gets a new channel. Old references cannot authorize future work.

## Focused acceptance and reuse

| Obligation | Minimal falsifier / positive control |
| --- | --- |
| Credential secrecy | Distinct synthetic owner-secret canaries absent from Runner mounts, environment, argv, readable proc/fd surfaces, tool output, streams, logs and persisted state; legitimate inference works |
| No transferable authority | Copy local representation to another Run, channel or post-close request; rejected before dispatch; matching live request succeeds |
| Owner-only auth | Attempt client account/token substitution and refresh-response disclosure; only owner auth reaches upstream, no provider token returns downstream |
| Refresh continuity | Fresh, stale and rejection-triggered refresh; serialized concurrency; rotation persisted; failed persistence and ambiguous refresh fail closed |
| Lifecycle | Cancel, owner death, restart and uncertain cleanup close channels without releasing live execution obligations or creating replacement work |
| Native composition | Pinned CLI completes tool call/readback while deterministic tool probes cannot recover owner secrets or gain provider/control access |

Canary absence alone is not a proof: inspect the reachable mount/process/channel
graph and pair denials with working positive controls. Review credential-bearing
auth errors. The provider remains trusted to handle credentials and receives
authorized task content; arbitrary provider data confidentiality is not solved.
Host-root/kernel compromise is outside this claim.

Reuse unchanged admission, identity, replay, reply-scope and cleanup mechanism
tests. Renew provider/credential/runtime composition and affected recovery tests;
do not rerun the historical bake-off for documentation or fixture edits.
For a coherent Go implementation run normal repository test/race/vet checks.
The existing recovery proof does not prove secret non-disclosure or refresh
correctness; revisit resource assumptions where ownership changes.

Deliver design, synthetic implementation, focused tests and candidate artifact
as one reviewable work package. Later real acceptance needs a new immutable
profile/image/TargetRevision, explicit credential migration and bounded provider
effects. An exposed old target is not an automatic fallback. No new device login
is assumed necessary until the prepared migration shows it.

Current position, **2026-10-05**: the owner storage/parser, native consumer and
provider adapter are wired into the opt-in V4 runtime as of October 1. The
September component records above retain their original scope and dates.
V4 remains blocked pending final composed and real-path acceptance; see
[the current profile](codex-profile-v4.md). The existing deployed authentication
path and credentials have not migrated. This plan and its opt-in fixtures do
not activate a profile or close CRED-01.
