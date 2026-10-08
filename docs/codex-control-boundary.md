# Codex provider control and credential delivery

**2026-09-10 update:** the [runtime-owned provider canary](codex-provider-canary.md)
now implements endpoint lifetime, bootstrap mount verification, fixed upstream
operations and an opt-in local preparation command. Completion/replay, held-tool
cancel and owner recovery passed offline. Real credential/provider acceptance
and normal executable enablement remain open. The dated observations below
retain their original scope.

Design and component status, **2026-09-09 UTC**. The V3 execution path remains **blocked**.
This narrows the first work package in the [live-path plan](codex-live-path-plan.md).
It records a bounded synthetic request consumer, Core/Connector fixture and
controller-owned Docker handoff/recovery with local native evidence. Deployed
service identities and production provider composition remain unimplemented.

## Decision

Keep the fixed V3 native package, ChatGPT file authentication and dedicated RW
file bind. Implement provider request enforcement in the trusted runtime
boundary, with authority derived from one admitted Run. Keep credential
identity/enrollment in the existing sandbox owner. Core, Connector and HRP
gain no provider URL, credential locator, socket or runtime-option fields.

Start with the already exercised synthetic Responses operation. Do not emit a
real-provider authority pin until its actual operation set and enforcement are
complete. The built-in ChatGPT branch now has an
[offline fresh/refresh operation inventory](codex-provider-operations.md),
observed at **21:04–21:05 UTC**, including native file refresh and persistence.
Complete production traffic and operation enforcement remain **unresolved**.
The earlier custom-provider and app-server witnesses retain their own limits.

At **21:24 UTC**, a [separate fixed HTTPS/SSE candidate](codex-provider-operations.md#fixed-httpssse-candidate)
passed fresh/refresh file auth without WebSocket attempts or compression.
It changes provider identity and some headers, so it is not a V3 replacement
or real-server compatibility approval. Its [offline tool/consumer composition](codex-provider-operations.md#offline-integrated-boundary)
passed at **22:05 UTC**: refresh, two strict dispatches and native tool output,
positive controls, socket/descriptor and owner procfs checks, and cleanup.
The tool's inner PID namespace retains outer procfs visibility; PID-taking
calls and procfs access require separate reasoning. The
[offline controller lifecycle](codex-provider-operations.md#offline-controller-lifecycle)
then passed at **22:49–22:54 UTC**: mounted-file refresh preserving identity,
completion/replay/removal failure, held-tool cancellation and same-boot owner
recovery through one scoped Core delivery. Owner death did not imply immediate
container exit; durable occupancy and exact absence remain the publication
boundary. The normal V3 path and production transport remain unchanged. The
[next contract decision](codex-provider-operations.md#next-fixed-boundary) must
bind the complete operation/runtime enforcement before a new pin is assigned.

For Docker, use **verification of the mounted object before Codex starts**.
The runtime must inspect that object independently while a fixed bootstrap
waits. This preserves the single-file contract and avoids relying on a later
check of the source pathname. Local rootless feasibility and a tagged runtime
consumer were witnessed below; normal executable configuration stays blocked.

## What the selected package actually establishes

| Evidence | Supported conclusion | Limit |
| --- | --- | --- |
| [V3 native fixture](../internal/codexadapter/tools_canary_linux_test.go) | Fixed CLI can send bounded `POST /v1/responses` requests to a local HTTP simulator while native tool IP access is denied | Custom provider and synthetic environment bearer; no ChatGPT auth-file or production traffic equivalence |
| Dated single-file refresh witness summarized in [credential lifecycle](credential-source-lifecycle.md) | CLI 0.151.0 persisted a synthetic refresh through a RW bind; the RO control did not persist it | App-server `account/read`, internal test URL override, no native tool turn; RPC success alone did not attest persistence |
| [Built-in provider inventory](codex-provider-operations.md), 2026-09-09 21:04–21:05 UTC | Fresh and refreshed synthetic file auth completed native `exec`; default operation paths, WebSocket attempts and compressed HTTP fallback observed | Offline TLS simulator, temporary auth file and empty catalog; no real upstream, tool execution or production allowlist |
| Pinned CLI's `responses-api-proxy --help`, read on 2026-09-09 | An internal proxy command exists with a configurable upstream and optional dump/shutdown functions | Help is not a ChatGPT refresh, authorization, redaction or lifecycle audit; do not adopt this command as the mediator |
| [Adapter invocation](../internal/codexadapter/adapter.go) | Closed child environment; tool networking and native `network_proxy` are disabled | Default invocation has no provider endpoint; the separate tagged canary adds the fixed relay/CA overlay |
| [Runtime construction](../internal/dockerruntime/runtime.go), [credential consumer](../internal/dockerruntime/credential_linux_amd64.go) | Default mock-only; explicit tagged synthetic V3 template owns held-source handoff and verification before HRP | No normal executable credential configuration or real-provider route |

Current [OpenAI configuration documentation](https://learn.chatgpt.com/docs/config-file/config-reference)
describes `features.network_proxy` as a sandboxed-command proxy. That feature
does not supply HSG's provider-operation boundary. The same reference describes
`chatgpt_base_url` for login/service configuration, not complete redirection of
every Codex destination. These are current documentation observations, not
source equivalence to CLI 0.151.0.

The [documented CA variables](https://learn.chatgpt.com/docs/auth)
support HTTPS/login/WebSocket certificate configuration. This makes controlled
TLS termination a compatibility candidate; the dated inventory above now
establishes its scoped offline use with this binary. It does not establish
all routing or authorize installing a host CA. An opaque HTTPS
CONNECT tunnel can restrict destinations but cannot inspect encrypted methods
and paths. Do not call a CONNECT allowlist operation-level enforcement.

## First enforcement consumer: synthetic Responses

The [consumer](../internal/responsesgate/gate.go) is implemented as a small
HTTP/1.1 service for one deadline-bearing Run context. Its only upstream is an
in-process synthetic responder supplied by trusted construction. Forwarded
requests have no URL, host, dialer or credential locator. Its listener and
exact HTTP authority also come from the trusted fixture. The later
[controller-owned witness](#controller-owned-synthetic-v3-witness) implements
Run/runtime binding for the tagged synthetic fixture. Normal executable wiring remains unimplemented. The later tagged canary
binds its own fixed upstream and owner lifetime; real-server acceptance is open.

Implemented fixture policy, deliberately narrower than a general coding session:

| Input or resource | Rule |
| --- | --- |
| Operation | Exactly `POST /v1/responses`, no query, fragment, escaped-path alias or alternate authority |
| Authentication | One fresh synthetic bearer for the Run; reject missing/duplicate/mismatched authorization; this bearer alone is not process identity |
| Model | Exactly the V3 model and effort, with `stream:true`; strict JSON, depth at most 32, duplicate keys and security-field case aliases rejected before dispatch |
| Request body | At most 2 MiB with Content-Length framing; no compression, chunked request or trailers |
| Response | At most 2 MiB of uncompressed SSE from the fixed responder; reject redirect, upgrade or unexpected encoding/type; exceeding the bound aborts the stream |
| Headers | At most 16 KiB; construct only the fixed upstream content type and verified synthetic authorization, and the fixed SSE response content type; strip other application headers and reject conflicting routing/framing inputs |
| Work budget | At most two inference dispatches, including failed dispatches, and one active request per fixture Run; eight accepted connections/parsed attempts, including rejections; one exchange per connection |
| Time | Two-second header deadline, five-second read/idle deadline; the admitted Run deadline bounds the entire exchange and teardown |
| Other operations | Reject CONNECT, WebSocket, shutdown/admin routes, catalog, compaction, login, refresh and all other paths |
| Side effects | No external dial, DNS lookup, provider call or automatic retry; no body/token logging |

These are implemented synthetic limits, not measured provider limits. The
actual handler is exercised over in-memory HTTP connections. The
[scoped composed pass](#runtime-diagnosis-and-passing-scoped-compatibility-case)
also dispatched two requests from the exact native client and completed its
command/readback checks under the documented fixture. Request fields
outside model/reasoning/stream remain bounded opaque simulator input, not an
audited real-provider option set. Native tools and Code Mode retain their
existing implementation; HSG does not parse their output to dispatch another
agent loop.

The pinned Go HTTP server adds a 4096-byte initial header read allowance; the
consumer reserves that allowance inside its 16 KiB limit. The standard parser
normalizes identical duplicate Content-Length values and rejects conflicting
ones. The handler reconstructs only its two approved upstream headers and
never relays raw request framing to another HTTP parser.

The earlier simulated `POST /token` refresh is **not** added to this operation
set. Its isolated fixture accepted a synthetic refresh grant via a test-only
URL override. The first consumer must distinguish “synthetic credential object
delivered” from “native file authentication and refresh consumed.” Its receipt
must state the custom-provider/environment-bearer delta. A later combined auth
fixture must independently observe a triggered refresh and source persistence;
no real operation path is inferred from `/token` or strings in the executable.

## Transport and authority lifetime

The synthetic fixture's listener and Codex client run in an outer environment
with no external network route. Tools remain in the native denied-network
boundary. Reuse the positive client/negative tool IP witness, then add the
missing Unix/descriptor checks in the **same composed fixture**.

No socket for host administration, Core, sandboxd, Docker or provider management
enters the native domain. No mediator connection, listening descriptor or control descriptor may
survive into an untrusted tool. Native Code Mode's required stdio communication
remains allowed; it is not a general provider transport. Prevent access to a
parent's descriptors or memory, including `/proc`, ptrace and descriptor-copy
paths, in the composed runtime. A CLI flag or an absent environment variable
does not establish these properties.

For eventual external access, a private, fixed mediator ingress must be the
client domain's only outbound route, and tools must be unable to use it. Its
management plane stays outside that domain. The later
[transport decision](codex-provider-transport.md) selects a per-Run Unix socket
with TLS/operations in the existing runtime-owner process and an opaque
loopback relay inside the network-none container. The bounded relay and local
HTTPS/owner-loss composition exist. Separate offline native cases at
**2026-09-09 23:58–23:59 UTC** verified the read-only socket identity, mapped
peer UID, legitimate tool round trip, tool connection/descriptor denial and
owner-loss failure. Those cases use a standalone driver; endpoint lifetime
hooks, controller mount attestation and held-credential integration remain
unwired. This selects no bridge/firewall change, host TCP
listener or persistent proxy. Transport identity and denial of inherited/Unix
bypasses remain gates under that actual composed runtime.

Bind the handler and its budget to the existing Run, immutable resolved policy
and runtime identity. It starts closed. Open it only after the runtime handoff
checks; close admission and cancel active exchanges on cancellation, deadline,
credential invalidation or loss of the execution owner. An old Run is never
reactivated by replay or startup recovery. A mediator that can outlive the
container is an additional cleanup obligation: container absence alone cannot
release its authority. Prefer the same exact outer lifetime; do not quietly add
a persistent service or a second retry/recovery machine.

V3 remains **`credential-exposed-personal`**. A tool that can read auth.json may
encode its bytes in output or allowed model input. Transport separation limits
direct control access; it does not provide credential secrecy or general data
loss prevention. An external credential broker would require a new contract.

## Credential handoff: a gated Docker start

The candidate mechanism has one trusted runtime worker and a fixed inert
bootstrap in the immutable image. It does not ask the Runner to prove its own
authority. Proposed local boundaries below are not new wire messages:

1. The existing controller owns the Run's held source and proof. Commit the
   existing Create intent, then ask the runtime to prepare that Run with an
   **opaque, non-serializable handoff capability**. Bind it to the same held
   source, expected source digest, target, generation and Run. Do not expose a
   generic pathname/FD accessor or let a request construct this capability.
2. Create/start at most one exact container into the fixed bootstrap. Mount
   only the dedicated credential file at its sealed destination. The bootstrap
   accepts no task and starts neither Codex nor a provider client. Its only
   startup control is a bounded, one-use private launch phase on the attached
   stdio transport. The runtime adapter consumes this phase before exposing
   the existing HRP Process interface; it adds no public HRP operation or
   additional socket. A missing, extra, malformed or late launch frame fails.
   Owner disconnect or launch timeout exits without executing the Runner;
   EOF is never an implicit permit. The immutable entrypoint must reach this
   gate before reading workspace-controlled startup code or customization.
3. The trusted runtime worker pins the exact container init process and its
   mount/root view. Independently open the **mounted destination object**, check
   the single-file RW mount and metadata, derive its supported physical object
   digest and compare with the controller's still-held source. Also revalidate
   the original root/slot/locator. This worker must operate in an attested
   daemon/process namespace; a numeric PID, inspect path string or Runner
   acknowledgement alone is insufficient.
4. Only the controller's trusted verification may open the launch gate. The
   gate parser disappears when the fixed bootstrap execs the Runner; the
   remaining stdio carries only ordinary HRP. Close bootstrap-exclusive and
   verification descriptors before native execution; no provider socket or
   live management capability may be inherited by a tool.
   The container mount is now the checked object even if its original host
   pathname is later replaced. Existing invalidation, retirement and cleanup
   rules still apply; a replacement never silently becomes the mounted source.
5. Keep the source handle through exact cleanup. Destroy the launch/control
   capability with that runtime, validate/retire as necessary, close the held
   source, then use the existing terminal/outbox/unlock transaction.

The receiver must verify the mounted file independently of the source's path;
checking it again on the host before AttachStart leaves the race intact. It
must not rerun `Hold` against the container home: the host root/slot are absent
by design, and a bind mount has a different mount view. Reuse the supported
physical-object encoding, with explicit receiver mount/process attestation.
Do not substitute an inode-only or token-content comparison.

The [ContainerMount component](../internal/credentialsource/container_mount_linux_amd64.go)
now provides independent process/mount verification on a held source. It
retains a pidfd and proc directory; its Validate method remains an observation
under an inert immutable bootstrap. The caller owns serialized final validation,
permit delivery and source lifetime. A receiver mismatch latches the receiver
invalid; source validation retains its existing invalidation/lock semantics.
No raw descriptor, credential bytes or generic destination path is returned.

The optional controller `CredentialRuntime` interface and Docker consumer now
wire these steps for the tagged synthetic template described below. A deployment
must independently attest the exact rootless daemon's
process/namespace visibility, mounted-file identity support, image and private
attach channel. An unsupported view rejects execution. Do not relax source
identity, mount the whole credential directory, change host policy
opportunistically or treat bootstrap output as permission.

Bind the immutable image/bootstrap, receiver verification rules, launch-phase
version, handler limits, transport policy and teardown ownership into the
resolved non-credential authority before a target using them can be registered.
An image digest or the V3 contract fingerprint alone does not bind this behavior.

## Completed local receiver witness

The [fixed bootstrap](../cmd/credential-bootstrap/main_linux.go) and
[private launch phase](../internal/bootstrapgate/gate_linux.go) are implemented
and omitted from the default build. The phase waits at most ten seconds;
EOF/cancel/timeout/malformed input denies launch. Already queued extra bytes
are rejected. It reads no future HRP bytes in the valid flow; after exec, a
later duplicate permit is invalid Runner input and cannot start a second
process. The successor path and environment are fixed, never supplied by the
permit. Production correctness still requires runtime ownership of this pipe.

At **2026-09-09 06:59 UTC**, six cases passed on an existing local rootless
Docker runtime, cgroup v2/systemd, without a system security-policy change.
Each used fresh synthetic ext4 source data, the actual public held-source and
mounted-object code, an inert bootstrap and a fixed synthetic successor.
No Codex or provider ran. The cached mock image plus read-only fixture binaries
is a test composition, not an approved V3 image.

| Case | Independent result |
| --- | --- |
| Same object / in-place update | Native proof and receiver checks passed; successor marker read back through the attributed process; RW update reached the original source |
| Source replaced before mount | Source validation rejected before permit |
| Different object mounted, original host path restored | Receiver rejected `object_mismatch` while the original source itself remained valid |
| Wrong expected bootstrap identity | Executable digest check rejected before permit |
| Attach owner disconnected before permit | Bootstrap exited without a successful launch phase |
| Attach/start response lost before permit | Attach client killed; cleanup only, no second Create/start or permit |

All six exact containers were removed and absence checked. Independent flock
checks observed the source lock held after runtime removal and available only
after the source holder closed. The last two cases exercise a lost attach
client, not a controller crash with durable database recovery. The native
source was newly created for this witness; no production enrollment command,
credential generation registration or credential secrecy claim is added.

The [bootstrap tests](../internal/bootstrapgate/gate_linux_test.go) also cover
truncation, queued duplicate permission, cancellation/deadline and preserved
subsequent input; [receiver tests](../internal/credentialsource/container_mount_linux_amd64_test.go)
reject unbound process/cgroup and unsupported mount views. Do not repeat the
completed generic bind, refresh or receiver witness as an unfinished stage.

## Completed synthetic consumer witness

On **2026-09-09 UTC**, the [HTTP boundary tests](../internal/responsesgate/gate_test.go)
exercised the actual parser, handler and streaming path with a fixed in-process
responder and net.Pipe connections. They covered closed/open admission, exact
operation/model/authentication, ambiguous routing/framing, duplicate JSON keys,
header stripping, exact/oversized bodies, failed-dispatch budgets, concurrent
requests, fresh-Run bearer isolation and no second pipelined dispatch. This
consumer creates no dialer, network listener or provider connection itself.

The [lifetime tests](../internal/responsesgate/lifetime_test.go) use Go's virtual
test clock to check header/body/responder/stream stalls, Run deadline and client
disconnect. Stop cancels work and closes owned transport; the original Serve
call waits for admitted handlers and responder-body cleanup. Body, connection
or listener close failure latches a closed instance and returns `ErrCleanup`.
An uncooperative responder leaves completion outstanding. Normal EOF cancels
the exchange before closing its body. The callback is trusted fixture code;
it must honor context, make body reads interruptible, and join producer work
before Close returns.
It is not a plug-in or model-executable extension boundary.

Open is a one-use trusted Go operation, with no HTTP equivalent. Its runtime
caller must still bind the context, synthetic bearer, listener, resolved policy
and exact runtime identity to one admitted Run and serialize opening with final
handoff verification. No existing target or service is enabled by this component.
The HTTP envelope tests do not establish native tool IP/Unix/descriptor denial,
production provider compatibility or credential confidentiality.

## Composition and stop condition

### First composed case: namespace creation rejected

At **2026-09-09 08:16 UTC**, one offline rootless Docker fixture combined the
actual source/mounted-object verifier, fixed bootstrap, V3 adapter/native host
and bounded Responses consumer. The consumer ran inside the same container
lifetime with a fixed in-process responder. The
[new compatibility case](../internal/codexadapter/composition_canary_linux_test.go)
reused the existing native command's independent exit/output/file checks;
it did not rerun all earlier tool canaries or connect Core/service admission.

Mounted-source verification and final revalidation passed before the permit.
The native client dispatched two valid Responses requests through the consumer;
native Code Mode ran, but its nested command failed because `bwrap` could not
create a namespace. The expected command exit 17 and nonce file were not
observed. The second simulator response correctly failed its native-output
check rather than fabricating completion. Catalog refresh requests were denied
by the closed operation policy; no real provider traffic occurred.

The composed case is **FAIL**, with successful independent outer cleanup:
the exact container was removed, its absence checked, and the source lock was
still held until the holder subsequently closed. The synthetic file remained
unchanged. This does not establish pre-teardown descendant quiescence or the
controller's publication ordering, nor native file auth/refresh.

The fixture used a cached OS image, RO test binaries/package binds, network none,
no capabilities and no-new-privileges with the existing Docker seccomp profile.
No policy was relaxed or new image built. A subsequent read-only observation
found user-namespace creation enabled globally and AppArmor's unprivileged-userns
restriction enabled; no matching kernel event was available. The error alone
does not identify the denying policy. Earlier offline VM passes used a different
outer composition and cannot turn this result into a pass.

### Runtime diagnosis and passing scoped compatibility case

Later on **2026-09-09**, a fixed source-free
[syscall probe](../internal/codexadapter/testdata/namespace-probe/main.c) and the
attributed container's generated OCI policy established that Docker's applied
seccomp filter rejected namespace clone flags and unshare. One container-local
profile extended that captured policy with user/mount namespace clone, exact
userns unshare, mount/pivot_root and detach umount allowances. It retained the
other rules and kernel capability checks; this is additional syscall surface
for the fixture, not a production policy approval. See
[Docker's per-container mechanism](https://docs.docker.com/engine/security/seccomp/).

The **08:37 UTC** composed trial then failed at UID mapping. A source-free
[UID comparison](../internal/codexadapter/testdata/uid-map-probe/main.c) at
**08:48 UTC**, under identical seccomp, NNP=1 and empty capabilities, observed
UID 0 mapping rejected and UID 1000 mapping accepted. This supports the
[kernel's parent-UID-zero CAP_SETFCAP rule](https://man7.org/linux/man-pages/man7/user_namespaces.7.html).
Merely changing Docker's user changes the underlying host identity and conflicts
with owner-only credential binds and the existing receiver's same-owner check.

At **09:04 UTC**, the same composed case **passed** with that local seccomp
profile and a fixed, RO [UID setup fixture](../internal/codexadapter/testdata/uid-setup/main.c)
before the unchanged bootstrap. Its only initial capability was CAP_SETFCAP
inside the rootless container namespace. It mapped the same host owner to
nonzero inner UID/GID 1000, denied setgroups, and dropped all capabilities
before execing the existing bootstrap. The outer observer independently
verified the mapping, unchanged host identity, NNP=1 and empty effective,
permitted, inheritable, bounding and ambient capability sets before permit.
No host security configuration was changed. An earlier wrapper inspection
failure was retained; its container never started and was removed.

Mounted-source verification and final revalidation passed. Native execution
produced exit 17, exact stdout/stderr and the independently checked nonce file;
UID/CWD, NNP=1 and CapEff=0 checks passed. The actual consumer dispatched two
synthetic requests, V3 completion succeeded, and the existing in-namespace
quiescence assertion passed. Exact outer removal preceded source close/unlock;
the synthetic source stayed unchanged. This establishes compatibility of this
one frozen fixture, without invalidating the earlier failures.

The setup remains testdata, omitted from product builds. Promoting it requires
an immutable startup template and resolved authority that bind the setup,
namespace mapping, seccomp rules and independently enforced zero-capability
gate. A standalone helper or a `--cap-add` setting cannot enable a target.
Normal executable authority/configuration, transport separation and the remaining
concentrated acceptance cases are still open; no live provider was contacted.
The subsequent controller integration is recorded below. Extend the combined
path to existing Core/fake ingress and accept its failure behavior with the
[concentrated matrix](codex-live-path-plan.md#concentrated-acceptance-matrix).
If an essential composition check fails, stop and report that incompatibility.
No standalone digest helper, synthetic bearer, model verdict or partial test
may clear `network_mediation`, `credential_lifecycle` or any other real-target
blocker. Complete real operation discovery and transport acceptance remain
required before real credentials or an executable real-provider revision pin.

## Controller-owned synthetic V3 witness

On **2026-09-09 10:24:27–10:24:56 UTC**, a fresh local rootless fixture passed
the actual native enrollment -> sandboxservice admission -> controller ->
Docker -> private bootstrap -> HRP bridge -> V3/native command path.

The 10:02 UTC case had reported a pass. Subsequent review found that its test
Runner could mask a nonfatal cleanup error by calling `os.Exit(0)`. The final
fixture checks `t.Failed()` before releasing its terminal; only that affected
native case was repeated. The earlier result/source and this collection limit
are retained. A still earlier attempt stopped in read-only image metadata
preflight before creating any container; its optional-field lookup error is
also retained.

The [opaque handoff](../internal/credentialsource/handoff.go) borrows the held
source and binds its Run, manifest fingerprint and complete local Binding.
Copies share one Create claim, one receiver observation and revocation state.
It exposes no path, descriptor, token or held-source Close. Credential Runs
require the optional [runtime consumer](../internal/sandboxcontroller/types.go);
missing support fails closed without ordinary Create fallback. Ambiguous Create
retains the existing intent/recovery rules and cannot acquire another permit.

Before returning HRP pipes, the [Docker consumer](../internal/dockerruntime/credential_linux_amd64.go)
compares the local Unix peer and PID namespace, exact managed container/init
identity, applied mounts/security policy, mounted native object and enrolled
source. It independently requires host UID/GID preservation, inner UID/GID
1000, NNP=1 and all five capability sets empty. Final revalidation and closing
observer descriptors precede the one permit. Readiness timeout, disconnect,
verification error, partial permit or cancellation cannot authorize a retry.
This assumes an operator-owned local daemon/CLI and supported native-ext4/proc
visibility; an unknown process view is not silently accepted.

The [tagged constructor](../internal/dockerruntime/synthetic_v3_linux_amd64.go)
is absent from normal builds. It pins the manifest, full source locator,
fixed artifact digests, applied seccomp and UID startup template into an
explicitly synthetic base authority. The service composes its enrolled source
proof/scope into the durable target pin. Inventory is scoped by the synthetic
pin, so this fixture cannot sweep another runtime inventory. Normal sandboxd
configuration still accepts only locked-down mocks.

The [integration case](../internal/sandboxcontroller/credential_integration_linux_test.go)
uses the real service, controller, Docker adapter and existing HRP bridge.
Exact receipt replay produced only one Create and Attach. The existing native
command witness returned exit 17 and exact stdout/stderr, wrote a nonce receipt
in the mounted workspace and verified UID/CWD/NNP/capabilities and quiescence.
Its terminal was held until those checks passed. Independent outer readback
matched that receipt to the completed output. At exact removal, a second file
description still could not take the source lock; immediately before durable
publication it could. The source stayed unchanged and independent full-ID and
Run-label inventory checks found no container afterward.

This proves one offline controller/runtime lifecycle with a synthetic local
scope, empty auth file and in-container Responses simulator. It does not prove
Core/Connector admission, controller process-crash recovery for this image,
real auth/refresh, authenticated upstream behavior, provider/tool transport
separation or production startup approval. Existing component/fault/formal
evidence retains its own scope; it is reused rather than relabeled as a native
integrated failure matrix.

## Core ingress and focused native fault witnesses

On **2026-09-09 10:53–10:56 UTC**, three fresh fixtures passed the
[Core/native integration](../internal/sandboxcontroller/core_integration_linux_test.go).
The synthetic Connector client uses the real strict HTTP/Unix transport; the
compiled exact Binding determines the credential enrollment scope. Actual
Core storage/dispatch calls the execution HTTP/Unix endpoint, which invokes the
existing controller, Docker consumer, private bootstrap and HRP/V3 Runner.
The existing outbox/claim/complete path returns the result only to the admitted
Connector, conversation and original message. No product control-plane or
protocol change was required for this composition.

| Case | Independent observations |
| --- | --- |
| Enrolled source replaced, 10:52:45–10:53:06 UTC | The original empty-JSON object was retained and a new owned object installed at its path. The controller rejected it before any Create/Attach, retired its generation and released occupancy. Core delivered exactly the fixed policy-denial text. |
| Lost Start reply and unavailable removal, 10:53:34–10:54:44 UTC | The actual Unix HTTP connection closed after durable admission. Core retained the prepared request, re-offered its identical fingerprint and observed only one Create/Attach. Two injected removal failures left the container present, source physically locked, terminal unpublished and Core running with no delivery. Reconciliation removed the exact container while the source remained locked; source close preceded publication and the sole outbox delivery. |
| Cancelled held tool, 10:55:20–10:56:30 UTC | A nonce receipt and independent contention of the native tool's file lock were observed while the runtime was running. Cancellation used the existing local execution API; the fixed Runner did not cancel itself or supply terminal output. Exact outer cleanup released the tool lock and preceded credential close, publication and one cancellation delivery. Lost Start reply recovery also passed in this case. |

All three rejected another actor, conversation, self-event and unbound
Connector before Run allocation. Exact event replay reused the same Run;
changed content under the retained event ID was rejected. A second Connector
could not claim the result. Independent read-only Core queries found exactly
one Run, one inbound receipt and one delivered outbox row per case; repeated
completion/ingress/polling produced no extra delivery. The source-denial case
created no container; the other two each created one, both independently absent
by full ID and Run label afterward.

The host integration executable ran with Go's race detector. The unchanged
default-build sources reuse their dated unit/race/vet evidence; only the
affected tagged fixtures were built/checked and the focused native cases run.
A first prepared fixture was superseded before execution to enforce a hard
Create budget. The first executed fixture failed before runtime construction:
its Connector socket directory also exposed the execution socket. The existing
policy compiler rejected that layout; separate fixture directories fixed it
without relaxing validation. Both earlier attempts remain recorded.

The image, fixed UID/bootstrap and container-local seccomp template remain the
previous offline composition. Per-case paths/source identity and the separately
pinned cancellation successor are explicit synthetic deltas. The normal
binary configuration is still mock-only. These are real local components in
one test process under the same host UID, with an in-container synthetic
Responses consumer, not a deployed Connector/agentd/sandboxd topology or
provider/tool transport separation. Connector v1 cancellation remains
unsupported; the cancellation witness uses the local execution boundary.

The subsequent [owner recovery cases](#native-owner-crash-and-recovery-witnesses)
cover two process-crash points. The
[remaining concentrated matrix](codex-live-path-plan.md#concentrated-acceptance-matrix)
includes still-absent delayed Create, deadline and resistant/escaped descendants,
context closure and tool transport separation. Real enrollment,
authenticated provider behavior/refresh, separate service identities and
Discord acceptance remain blocked. No host security configuration, real
credential, upstream provider, image acquisition or deployment was changed.

## Native owner crash and recovery witnesses

On **2026-09-09 11:32–11:35 UTC**, two fresh rootless fixtures passed the
[tagged recovery integration](../internal/sandboxcontroller/core_recovery_integration_linux_test.go)
with the host race detector. Core and its Connector remain alive while a
separate controller process owns the execution socket, sandbox database and
actual persistent process lock. Each case kills that exact owner with SIGKILL,
then starts two sequential replacements against the unchanged database and
runtime policy. The first replacement injects unavailable Inspect; the next
uses the real runtime normally. Only the initial owner can Create or Attach.

| Crash point | Independent observations |
| --- | --- |
| Docker object exists before controller records its ID, 11:32:03–11:33:16 UTC | One Create, no Attach/Start. Durable same-boot intent had no runtime reference when the owner died. Both replacements resolved the same actual object through identity-checked intent lookup. Failed inspection retained intent and occupancy; healthy cleanup removed the original object before clearing intent and publishing. |
| Native tool running with bound runtime reference, 11:33:56–11:35:42 UTC | One Create/Attach. A nonce and independently contended tool lock established live work before SIGKILL. The container remained running immediately afterward and was exited but still present after the failed replacement. Healthy recovery removed it before publication; the tool lock was free afterward. One recorded orphan Docker helper was reaped. This case did not require Stop/Kill of a resistant container. |

In both cases, process death released the **physical credential file lock**;
the independent database snapshot retained its credential occupancy, workspace
writer lock, request fingerprint and runtime/intent authority unchanged. Startup
retirement was committed before every replacement runtime observation. Failed
startup retained the staged interruption and fences, started no serving workers
and produced no Core delivery. Healthy recovery independently observed exact
container absence while durable occupancy was still held, then published and
released it. Neither replacement reopened execution credentials, created a
container or attached a Runner. The persistent process-lock inode stayed the
same; all owned processes exited and both exact container IDs were absent.

Each Core database ended with one Run, one inbound receipt and one delivered
outbox row addressed to the admitted conversation/message. Event replay and
further polling produced no additional delivery. The fixed result was
“Run interrupted; it was not automatically retried.” A fresh Start using the
retired generation was denied without adding a sandbox Run or reviving authority.

At the time of these **11:32–11:35 UTC** witnesses, that denial returned generic
`internal`, which Core retried. The native cases verified admission denial, not
a user-visible retry/deadline sequence. The later
[permanent feedback correction](#permanent-credential-admission-feedback) closes
that classification gap with separate service/HTTP/Core evidence; it does not
retroactively change these native results.

These witnesses use empty synthetic auth, the unchanged offline artifacts and
same host UID. They cover owner-process death in one real host boot, with an
already existing container, not host reboot, an absent delayed daemon Create,
resistant/escaped descendants, production identity separation or real provider
revocation. No normal code, transaction, protocol or system security setting
changed for this slice. Unchanged default tests and formal evidence retain their
original dates and scope.

## Deadline and resistant descendant witnesses

On **2026-09-09 UTC**, the
[tagged termination integration](../internal/sandboxcontroller/core_termination_integration_linux_test.go)
passed two focused cases through the same actual Connector/Core/execution Unix
HTTP path, synthetic enrollment, controller and rootless Docker boundary. Each
created/attached one container. The host test ran with the race detector.

| Case | Observed boundary |
| --- | --- |
| Fixed resistant Runner, 19:53:52–19:54:55 UTC | An original child leader exited; its live child remained in a separate session, reparented to container PID 1 and holding a workspace lock. Exact-container Docker top, procfs namespace IDs and retained pidfds independently checked this shape. PID 1 emitted a fixed completed frame but remained alive across actual TERM. Docker Stop's existing five-second grace ended with exit 137; both pidfds signalled exit and the child lock became free before removal. |
| Native held-tool deadline, 20:11:00–20:12:31 UTC | The pinned native Codex package executed the fixed tool; a verified second synthetic request kept an unfinished response active. The tool lock was independently held at 20:12:27.446, before the frozen 20:12:28.388 deadline. At 20:12:28.895 the runtime was exited and the tool lock free. Exact removal and source close followed before one fixed deadline-failure delivery. No Docker Stop/Kill command was needed in this case. |

Both temporarily rejected RemoveStopped. While the exited container still
existed, the terminal remained staged, source physically locked, credential and
workspace occupancy held, and Core running with no delivery. Healthy removal
was independently observed before source close and publication. Read-only Core
checks found one Run, one receipt and one delivered outbox row per passing case;
event/completion replay and further polling produced no additional delivery.
All attempted containers were absent afterward, including failed attempts.

The resistant case uses a separately pinned
[adversarial HRP Runner](../internal/sandboxcontroller/testdata/resistant-runner/main_linux.go),
not a Codex launcher. It verifies generic outer containment of that process
shape; it does not establish native tool-launcher behavior for every descendant
shape. Forced termination occurred inside Docker Stop; the controller's separate
Kill fallback was not exercised. The native deadline case uses the existing
tool/package and a
[fixed deadline consumer](../internal/codexadapter/deadline_runner_linux_test.go).
It emits one unfinished synthetic message with bounded whitespace deltas;
there is no additional tool dispatch or completed model answer. Existing
request, idle, stream and execution limits stay unchanged.

Two earlier deadline attempts remain **failed**: at 19:55:44–19:57:04 UTC the
immediate-cancel fixture exited before the deadline; at 20:06:27–20:07:52 UTC a
comment-only heartbeat also failed to keep native work alive until the deadline.
The final fixture checks the second request and requires live work through the
last second. Each retry changed only the affected synthetic consumer/test
artifact; the passed resistant case was not rerun. Original source, binaries
and result lineage are retained. These are local evidence, not public CI.

No normal product code, protocol, module dependency, formal transition or host
security configuration changed. Unchanged default-build evidence is reused with
its existing dates and limits. Remaining gates include
absent delayed Create/reboot continuity, native descendant
variants, context closure, provider/tool transport separation, real enrollment,
provider behavior and deployed service/Discord acceptance.

## Permanent credential admission feedback

At **2026-09-09 20:28 UTC**, the
[service/HTTP/Core integration](../internal/agentdispatch/credential_integration_test.go)
passed revoked-generation and wrong-scope admission using synthetic enrollment,
the actual peer-checked Unix HTTP transport and two real SQLite stores. The
[service](../internal/sandboxservice/service.go) now returns the closed HTTP 403
`policy_denied` code. Core confirms the exact Run is absent and immediately
persists its existing policy-denied failure, with one fixed scoped outbox row:
“Run failed: execution was denied by policy.” No deadline advance is needed.
Ingress replay, further dispatch and polling add no Start or delivery; independent
readback finds no rejected sandbox Run, credential occupancy or workspace lock.

The [observation guards](../internal/agentdispatch/engine_test.go) preserve an
existing accepted/running Run or its published result; unavailable or denied
GetRun cannot authorize terminal publication. Internal, unavailable, workspace
busy and unknown Start errors remain retryable. The
[authority regression](../internal/sandboxservice/authority_test.go) preserves
the original admitted receipt after revocation and service reconstruction.
The [wire check](../internal/executionhttp/handler_test.go) exposes no cause,
source identity, credential path or generation detail.

This correction changes admission feedback, not authority, cleanup, media or
formal recovery transitions. The earlier native recovery fixture's expected
error is updated for future runs; no native container case was rerun for this
mapping change. Real enrollment, provider and deployed identity/Discord gates
remain open.
