# Runtime-owned provider canary

Preparation implemented **2026-09-10 UTC**. This is an opt-in local experiment,
not a production target, deployment, authenticated-provider acceptance or
Discord implementation. The normal build and `sandboxd` remain mock-only.

## Implemented ownership

`dockerruntime` creates one closed endpoint after a durable Run intent and the
one-use held-source claim, before Docker Create. It binds a fresh private Unix
socket and public CA read-only. The inert bootstrap verifies the exact applied
mount tuple, socket/CA identity, held auth object, PID/start identity and source
again before opening admission and releasing Permit. No path or runtime option
is added to messages, Core or HRP.

`CloseRunResources` stops admission and joins response owners before credential
release and terminal publication, including absent-container and failed-Create
paths. Docker also joins before removal. Failed joins retain cleanup responsibility
and durable occupancy. Recovery only cleans the old Run; it never creates or
opens an endpoint. Private CA keys exist only in the runtime owner's memory.
Public CA files/stale directories are retained as private evidence, not reuse
or resume capabilities. The [formal mapping](../formal/recovery/README.md#runtime-owner-resources-2026-09-10)
explicitly excludes endpoint quiescence from the existing mock model's proof.

The tagged fixed Runner uses the existing native adapter plus the pinned Unix
relay and fixed HTTPS overlay. Its wait joins the relay after native process
wait; exact outer container cleanup still owns detached descendants. The
`provider-canary/owner-join-v1` pin binds the owner executable, complete artifact
tuple, local paths, operation policy and synthetic/live mode separately from
the unchanged V3 profile and synthetic fixture pins.

## Fixed operation policy

Only refresh at `auth.openai.com/oauth/token`, the pinned CLI version's model
catalog at `chatgpt.com/backend-api/codex/models`, and Responses inference at
`chatgpt.com/backend-api/codex/responses` can reach upstream. Settings return a
local 404. CONNECT selects no arbitrary tunnel: TLS terminates at the owner,
and parsed method/authority/path map to a closed operation enum before a new
fixed upstream request is built.

Requests require HTTP/1.1, bounded headers/body, explicit model/medium effort,
streaming and `store:false`. Duplicate/aliased authority fields, upgrades,
compression, non-default tier, background jobs and provider-side built-in tools
are rejected. Local custom/function tools and native input remain untrusted
provider-visible data. Headers use a closed name list; upstream response headers
and error bodies are not relayed. Success bodies are JSON or SSE with an explicit
HTTP chunk end only after clean EOF. Interrupted producers remain truncated.

There are at most 16 accepted connections, four active exchanges, one refresh
and two catalog dispatches per Run; request and response bodies are each bounded
at 2 MiB. Header timeout is two seconds, active-response idle timeout 45 seconds,
and the Run has a 300-second ceiling. The client may consume the finite attempt
budget with retries; the owner performs no automatic retry or redirect. Its
fixed TLS dialer ignores proxy settings and uses host DNS/system certificate
roots; the live constructor rejects certificate-root environment overrides.
These host inputs remain trust assumptions, not claims proved by local TLS tests.

## Controlled entrypoint

Build `cmd/codex-provider-canary` and `cmd/codex-provider-canary-runner` explicitly
with `-tags=codexintegration`; build the Runner with `CGO_ENABLED=0`. Keep the
owner binary and its exact configuration together with private build evidence.
The candidate accepts only the measured cached image and fixed package/template.
It neither pulls an image nor installs anything.

The **offline local-owner check** is the explicit package set below. It exercises
synthetic history/admission/recovery, without native Codex or a real provider:

```sh
go test -tags=codexintegration ./internal/codexcanary ./cmd/codex-provider-canary
```

Use the corresponding race/vet checks for changes to that owner. The provider
package's ordinary Linux tests (`go test ./internal/codexprovider`) cover its
local transport seams. Provider code is not restricted to `codexintegration`;
changes there must follow the normal affected-source verification requirements.
Do not treat a broad `-tags=codexintegration ./...` command as this offline set:
it also selects native integration tests with separate CLI/runtime prerequisites.

The local `hsg-provider-canary/v1` configuration contains `state_root`, `run_id`
and the complete trusted `ProviderCanaryConfig` artifact tuple. It has no prompt,
model, upstream, proxy or arbitrary argv field. State uses dedicated private
`workspaces/project`, `credentials/slot`, and `provider` directories. The single
credential file is `credentials/slot/auth.json`; never use a normal Codex home.
This operator document is not a wire protocol or production configuration.

Default invocation with `-config /private/canary.json` reads configuration,
artifact bytes and credential **metadata only**. It returns a plan with exit
code **3**, even when local metadata matches. It does not open auth contents,
enroll, lock, create a database/socket/container, run Codex or access a provider.
The plan lists exact external effects and the inherited confidentiality limit.
Preflight also compiles the fixed Core configuration. The in-process Connector's
unused socket path has a separate directory; it must obey the normal directory
isolation rule even though this command never creates that socket or directory.

After a dedicated identity, exact host/configuration and effects are approved,
`-execute-plan <reviewed-digest>` arms one local Run. It uses real Core admission,
durable dispatch, enrollment and controller lifecycle with an in-process fake
message endpoint. It asks native Codex to write a Run-specific marker and return
one fixed answer, independently checks the private marker, and completes one
local delivery. It emits fixed result fields rather than native transcripts or
model text. The digest is an operator interlock, not a new authorization service.
Authenticated provider compatibility remains unresolved. The first armed command
failed local configuration validation; the corrected continuation admitted a Run
but failed during native execution, as recorded below.

Preserve state after any failure. `-recover-plan <same-digest>` runs cleanup only,
without ingest, dispatch, provider opening or credential execution reacquisition.
Its cleanup report also requires the exact durable Run to have no pending
intent/result/runtime or workspace/credential occupancy. Container absence
alone cannot report completed cleanup. An unresolved same-boot uncertain Create remains fenced; this command cannot
turn an absence observation into proof or authorize a host reboot. The tagged
native recovery fixture separately exercises the underlying recovery path.

## Evidence and remaining acceptance

On **2026-09-10 02:13 UTC**, the first approved real-canary attempt stopped at
Core configuration validation: the unused Connector socket's parent directory
also contained the intended Core/sandbox paths. The existing policy correctly
rejected that composition. No database, credential enrollment, runtime intent,
container or provider endpoint was created. Two empty preparation directories
and the failed report are retained; this is not authenticated-provider evidence.
The owner returned `cleanup_complete:false` before constructing its controller;
independent absence observations do not rewrite that result as a passing Run.

The corrected placeholder path stays outside the control directories. Preflight
now checks the same configuration, and execution validates its complete local
policy/scope before creating state directories. A regression using the public
V3 target example reproduced the rejection, then passed with the fix; it also
requires the old unsafe directory layout to remain rejected. Focused race checks
and vet passed. No authorization or directory-isolation rule was relaxed.

The **02:30–02:31 UTC** continuation completed one real-source enrollment and
one Core dispatch into the native runtime. It failed with `runner_failed` and
the fixed message `Codex execution failed`; no marker was produced. The owner
reported cleanup complete. Independent checks confirmed exact container absence,
owner process exit, no runtime reference/intent and no credential, workspace or
staged-result occupancy. Core retained one pending failure delivery with no
delivery attempts. The source retained the same object and observed metadata;
that does not prove a provider refresh or unchanged secret bytes.

The adapter used for that Run discarded bounded native stdout/stderr, combined native Wait
and relay Close failures, and emitted one fixed failure message. The provider owner
did not retain per-operation stage/status evidence. This Run therefore cannot
establish whether upstream authentication, catalog or inference succeeded, nor
identify the failing request or native/relay cause. No additional admitted Run
was started to fill that evidence gap. The subsequent diagnostic change below
does not retroactively explain this failure.

### Bounded diagnostic result — 2026-09-10

The opt-in owner's existing result now includes `provider_diagnostics`, captured
after its controller cleanup attempt. The private operator supervisor archives
that result. There is no new diagnostic socket, file path, message field or
normal daemon option. The endpoint retains at most 16 connection observations
in acceptance order, matching its existing total admission budget.

Each observation contains a closed operation name, last attempted stage, numeric
upstream HTTP status when available, and finished/cancelled flags. The subsequent
rejection-handling increment below adds closed reason/media fields and a local
dispatch-authorization flag. Stages separate
local CONNECT/TLS/parsing/policy/budget rejection, upstream dial/TLS/write/headers/
response policy, and response read/write/budget/completion. Settings remain a local
404 and have no upstream status. Rejected requests may have operation `unknown`.
An unfinished observation records admission only; it is not a live progress trace.
No URL/query, headers, bodies, tokens, account identifiers, raw errors, native
stdout/stderr or model text are retained in these fields.

The endpoint also reports opened/stopped/joined flags and its sticky cleanup-error
flag. A timed-out join stays unfinished; diagnostics neither release ownership
nor decide terminal publication. `joined` concerns only endpoint workers;
`complete` means a clean HTTP body and final chunk were written, not semantic
provider/model success. HTTP 200 alone does not establish that success either.
A null snapshot means no unambiguous endpoint observation, including cleanup-only
recovery. An owner killed before reporting may leave no snapshot. Neither absence
nor a partial snapshot is proof that no provider operation occurred.

The tagged Runner still waits for native execution and then joins the relay.
Failures retain the existing `harness_error` code and use one of three fixed
messages: `Codex native process failed`, `Codex provider relay failed`, or
`Codex native process and provider relay failed`. Other launchers retain the
generic message. Cancellation and output-limit handling keep their precedence;
raw native output and source errors remain discarded.

Offline fault checks cover success, upstream 401/403/429, policy rejection,
truncation/body limits, typed transport failures, cancellation and failed body
cleanup. Synthetic secrets in headers, URLs, bodies and errors are absent from
the serialized observations and failure frames. Snapshot mutation cannot change
endpoint state, the connection ceiling is unchanged, and observations survive
runtime ownership release without retaining that cleanup obligation. The owner
and Runner require new artifact pins before any further real test; the previously
executed plan and enrolled source history remain retained.

### Explicit continuation preparation — 2026-09-10

The tagged local owner also accepts `hsg-provider-canary/v2` at
`state_root/plans/<run_id>.json`. This trusted configuration adds a `continuation`
record containing `previous_run_id`, the SHA256 of the predecessor configuration,
`history_sha256`, and the device/inode identities of the existing Core and sandbox
database files. An unpinned preview reports `blocked_lineage_pin` with the proposed
record; it cannot execute. Preview reads selected database rows through read-only
SQLite connections, without creating, migrating or recovering state.

The new plan keeps the source location, permanent slot, workspace, image, tool
package and containment fixed. It requires the immediately next credential
generation and a distinct target revision; only the reviewed owner/Runner builds
may otherwise change. Its predecessor must have matching, published terminal
state with no unresolved foreign Run or ownership obligation. A fresh database
cannot replace retained enrollment history. File identity does not defend against
a trusted operator rolling back the same database object.

After separate approval, execution takes a persistent local process lock and
rechecks the pinned history. It compares the held physical source/proof before
using the existing store APIs to retire the previous **local HSG generation**
and register the next one. This is not provider logout or token revocation. A
partial registration remains fail-closed and can finish under the exact same
plan before admission; a child Run in either store blocks another execution.
The prior enrollment/proof, target, Run and pending delivery remain present.
Distinct local Connector and marker identities isolate the new test's result.

Recovery uses the same pinned plan and existing database objects, permits owned
SQLite journal recovery, then checks the predecessor rows before constructing the
lifecycle owner. It does not enroll or dispatch work. With no child admission and
no managed runtime, it preserves any partial enrollment preparation. Existing
controller recovery and uncertain-Create fences still apply.

Synthetic admission/dispatch/outbox tests verify old-result preservation,
retirement and exact replay, guarded mismatches, interrupted registration,
database replacement rejection, and read-only refusal followed by owned recovery
of a hot SQLite journal. Tagged tests/race/vet and the security demo passed.
This continuation was prepared without applying a real generation transition or
executing another real Run; authenticated provider acceptance remains open.

### Second real Run — 2026-09-10

After separate approval, the **04:51–04:52 UTC** continuation ran for about 60
seconds and failed with `runner_failed / Codex native process failed`. The
marker was absent. Its endpoint reported opened/stopped/joined with no cleanup
failure. The 16 retained exchanges comprised two completed catalog responses
with upstream HTTP 200, one local settings response and thirteen inference
responses with upstream HTTP 200 and final stage `upstream_policy`.

That stage groups response encoding, Location, Trailer, invalid/missing media
type and an unexpected parsed media type. The observed 200 excludes its 101
upgrade branch. No raw response headers or bodies were retained, so the exact
predicate and value remain unknown. Repeated 502 denials and native retries are
a code-supported explanation for the sequence, not a complete native failure
trace. These observations prove neither semantic authentication nor inference
completion, identical request payloads, provider-side usage, or the first Run's
cause. One Run permits bounded HTTP attempts; it is not one upstream request.

Read-only observations at **04:53–04:54 UTC** independently verified the exact
container's destruction/absence, owner process-group exit and zero credential,
workspace or staged-result occupancy. Both Runs are terminal with no runtime
reference/intent; both failed deliveries remain pending with zero attempts.
The next generation preserves the original source/proof, and the previous local
generation is retired. The source file's object/size/mtime metadata match;
credential byte equality is not established. Provider leaves retain only public
CA files. Cleanup-only recovery was unnecessary. A subsequent read-only preview
returned `blocked_run_exists` for the same consumed plan.

The next bounded work identified by this failed Run was actionable closed
failure reasons and suppression of new upstream dispatch after a deterministic
policy rejection, with representative offline response/concurrency/cleanup
checks. The separate implementation below addresses that work; it does not
identify the predicate rejected in this earlier Run. A specific compatibility
change requires evidence of the rejected response; authenticated completion
and the public messaging path remain open.

On **2026-09-10 00:37–00:39 UTC**, runtime-owned fake refresh/catalog/inference,
native command output, lost Start reply, removal failure and one scoped Core
delivery passed. On **00:45–00:47 UTC**, cancellation while a native tool held
a lock passed through cleanup and one cancellation delivery. Both independently
verified exact container absence, with no rescue cleanup. The older standalone
socket/FD/procfs witness retains its **2026-09-09 23:58–23:59 UTC** scope.

On **2026-09-10 00:49–00:52 UTC**, the runtime-owner SIGKILL case passed:
the synthetic tool/refresh witness preceded process death; failed observation
blocked startup after generation retirement; healthy recovery removed the exact
container before one Core interruption delivery. Recovery opened no execution
credentials, created/attached no runtime and never reopened a provider endpoint.
This is process replacement in the same host boot, not a host reboot or a proof
about an absent delayed Docker Create. The stopped container and stale private
socket path confer cleanup responsibility only.

An earlier **00:33–00:35 UTC** case failed after one refresh dispatch: raw
close-delimited TLS output was not accepted as a complete response. Explicit
HTTP chunk framing restored native refresh and progress; a component test also
requires producer errors to remain incomplete responses. The failed case and a
later sandbox link-quota failure are retained, not counted as product passes.

Normal Go tests, every package's race check, normal/tagged vet and the security
demo passed. Two SQLite-heavy race suites exceeded an initially shortened
three-minute package ceiling and passed with the normal ten-minute ceiling;
their internal assertions were unchanged. Long-path/unsafe-ancestor temporary
directory failures and a cgo temporary-file quota failure remain recorded.
The final canary owner also rejects a wrong execute/recover plan without creating
state, and its cleanup-report test rejects each retained durable fence.

Real authenticated catalog/model behavior, real refresh/revocation, real error
and residue handling, deployment identities and public Discord remain open.
V3's `credential-exposed-personal` classification still applies: native tools
can read the dedicated credential, and an allowed provider request can disclose
data. Preparing this canary does not establish credential secrecy or complete
production operation/context closure.

### Actionable rejection and bounded failure handling — 2026-09-10

The endpoint now records the first matching response-policy predicate as a
closed `reason`. Its response acceptance rules are unchanged:

| Reason | Rejected observation |
| --- | --- |
| `protocol_upgrade` | HTTP 101 |
| `content_encoding` | Nonempty Content-Encoding, including `identity` |
| `location` | Nonempty Location, including on HTTP 200 |
| `trailer` | Declared response trailers |
| `content_type_missing` | HTTP 200 with an empty/missing Content-Type |
| `content_type_invalid` | HTTP 200 with a nonempty Content-Type that fails MIME parsing |
| `media_type_mismatch` | Parsed HTTP 200 media differs from the operation's required JSON or SSE type |

For a parsed HTTP 200 response, `media_class` is one of `json`, `event_stream`,
`html` or `other`; raw MIME values and parameters are never retained. A completed
observation's `upstream_authorized` flag means local dispatch permission was
granted, not that network I/O, authentication or model completion succeeded.
Unfinished observations still record admission only.

The first typed response rejection blocks further upstream authorization for
that operation within the same endpoint. This transition and the last dispatch
check share the endpoint mutex; no mutex is held across upstream I/O. Rejection
is published before client error writes or closing a returned response body.
An otherwise admissible later request receives a fixed local 503, stage
`operation_rejected`, and the earlier rejection's reason. It has no new upstream
status or media classification. Request/connection/operation budgets retain
their existing precedence and limits; malformed requests do not gain authority.

The guarantee is **zero new upstream dispatch authorizations after the rejection
transition**, not a one- or four-request total for the Run. Calls authorized
earlier may finish later. Other operations, local settings, transport failures,
status-only failures and response truncation/body-limit failures keep their
existing behavior. Diagnostic stage strings do not control the block.

Local tests exercise actual TLS/HTTP response parsing, accepted MIME parameters,
non-200 controls and closed diagnostic output. Endpoint cases cover operation
isolation, status/transient progress, five successful calls followed by four
concurrently authorized failures, and later local rejections with nine total
callbacks. Separate held-callback and slow-body-close cases verify cancellation,
unfinished joins and rejection before cleanup completes. These tests add no
provider-compatibility or whole-runtime acceptance claim.

This changes ordinary Linux provider code, so ordinary repository and affected
tagged checks apply. Existing store/recovery, formal-model and native-runtime
observations retain their dates and assumptions. New owner/Runner artifact pins
and an explicit continuation preview are required before a further real Run.

Verification also corrected two fixture assumptions: completed endpoint batches
are observed under the endpoint mutex, without waiting on its worker WaitGroup
while admission remains open; the owner-loss test closes pooled idle TLS
connections before asserting failure of a new connection. Its request failure
and bounded relay join are checked separately. Production relay behavior and
response acceptance were unchanged by these fixture corrections.

On **2026-09-10 06:44–06:52 UTC**, final-source ordinary tests, full-repository
race and vet, and affected `codexintegration` race/vet selections passed.
The offline tagged test selection explicitly excluded the native
`TestCodexExecIntegration`; it does not claim a fresh native or real-provider
test. The provider package also passed 20 race iterations after its test
synchronization correction, and the revised owner-loss fixture passed 10.
The security demo passed with unchanged production sources. Initial failed
checks remain recorded separately from these results.

At **2026-09-10 06:49 UTC**, newly pinned owner/Runner artifacts and one retained-
history continuation passed default read-only preflight with `awaiting_operator`
and no findings. Both retained databases and both prior configurations were
unchanged; credential metadata matched before and after, without reading or
hashing its bytes. The third Run remains unexecuted. This is preparation
evidence, not a current authentication, Docker-service or real-provider
acceptance result.
