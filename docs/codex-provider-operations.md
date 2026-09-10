# Pinned Codex provider operation inventory

**2026-09-10 update:** the [runtime-owned provider canary](codex-provider-canary.md)
now implements endpoint lifetime, bootstrap mount verification, fixed upstream
operations and an opt-in local preparation command. Completion/replay, held-tool
cancel and owner recovery passed offline. Real credential/provider acceptance
and normal executable enablement remain open. The dated observations below
retain their original scope.

Observed **2026-09-09 21:04:59–21:05:26 UTC**. This is an offline compatibility
witness for the built-in ChatGPT branch of CLI **0.151.0**, fixed V3 six-file
package, `gpt-5.6-sol` and medium effort. The real target remains **blocked**.

The [built-in inventory fixture](../internal/codexadapter/provider_inventory_linux_test.go)
keeps the adapter's native invocation and file-auth branch. It adds only the
fixture's Git-directory exception, temporary directory, child-only HTTP(S)
proxy and temporary CA. It does not replace the provider, base URL or refresh
URL, or disable native retries. A loopback TLS responder never dials upstream.
The owned rootless container had no external network, read-only root, UID 1000,
no capabilities, default seccomp and finite resource/time limits. Its only host
binds were the read-only test binary and content-verified tool package.

Both fresh synthetic credentials and an old `last_refresh` completed one
synthetic Responses turn. The latter performed one accepted refresh, persisted
the changed synthetic access token and then completed the turn. Namespace
quiescence and exact container removal/absence passed. This fixture uses a
temporary ordinary auth file; it does not repeat or extend the separate
enrolled-source/single-file mount witness.

## Observed operations

Counts are **fresh / refresh** for these two executions, not protocol constants
or a complete production allowlist. Only names, paths, byte counts and equality
to synthetic credentials are recorded; credential/header values and request
bodies are not archived by the observer.

| Authority and operation | Count | Local response and supported observation |
| --- | --- | --- |
| `chatgpt.com` — `GET /backend-api/codex/models` | 2 / 2 | 200 with an empty catalog; query key `client_version`; synthetic bearer and account header matched |
| `chatgpt.com` — `GET /backend-api/codex/responses` | 7 / 7 | WebSocket upgrade attempts rejected with 404; both turns subsequently used HTTP POST |
| `chatgpt.com` — `POST /backend-api/codex/responses` | 1 / 1 | `Content-Encoding: zstd`, Content-Length present, no query; fixed finite SSE reply consumed; synthetic bearer and account header matched |
| `chatgpt.com` — `GET /backend-api/wham/settings/user` | 1 / 1 | Rejected with 404; these two synthetic turns still completed |
| `auth.openai.com` — `POST /oauth/token` | 0 / 1 | Uncompressed refresh grant matched the exact synthetic refresh token; local JSON reply consumed and new access token persisted |

The inference request bodies were 16,307 / 16,301 compressed bytes. They were
bounded but not decompressed or semantically validated. The observer's suffix
dispatch is intentionally a discovery aid, not a reusable authorization rule.
The existing [synthetic consumer](codex-control-boundary.md#first-enforcement-consumer-synthetic-responses)
still accepts only its exact uncompressed `POST /v1/responses` contract; it was
not broadened to accept this traffic.

The synthetic JWT, empty catalog, HTTP/1.1-only TLS peer, rejected WebSocket
upgrade and fixed response differ from an authenticated server. Neither real
login/refresh acceptance, effective remote model/tool policy, successful
WebSocket operation nor all background destinations is established. A request
that bypasses the proxy cannot reach the internet in this fixture, but this
observer alone cannot inventory that attempted route. User-settings rejection
is an observed result here, not a conclusion that account or managed policy is
irrelevant in production. The roughly 11-second case durations include native
retry/fallback behavior; they are not provider latency measurements.

## Fixed HTTPS/SSE candidate

The next experiment passed at **21:24:33–21:24:46 UTC**, using the same pinned
CLI/package and corrected offline observer. Fresh and refresh each completed
with **zero observed WebSocket attempts and uncompressed JSON inference**.
The request's model, medium effort and `stream:true` matched. Synthetic bearer
and account headers matched; refresh persisted the new access token and the
subsequent inference used that new token. Quiescence, exact container cleanup
and unchanged frozen inputs passed.

This requires a **separate fixed custom provider candidate**. The retained
**00:44 UTC** feature listing for the same CLI bytes marks both legacy
`responses_websockets` flags removed/false; the later built-in inventory still
attempted WebSockets. The binary also contains the reserved-provider rejection.
Current [official configuration guidance](https://learn.chatgpt.com/docs/config-file/config-advanced)
forbids overriding the built-in `openai` ID. The
[provider reference](https://learn.chatgpt.com/docs/config-file/config-reference)
describes `supports_websockets`, and the
[sample](https://learn.chatgpt.com/docs/config-file/config-sample) lists the
compression switch. Documentation selected the candidate; the dated native
execution establishes this limited compatibility result.

The exact experimental overlay, expressed as TOML:

```toml
model_provider = "hsg-subscription-https"
features.enable_request_compression = false

[model_providers.hsg-subscription-https]
name = "HSG subscription HTTPS"
base_url = "https://chatgpt.com/backend-api/codex"
wire_api = "responses"
requires_openai_auth = true
supports_websockets = false
```

Only the tagged HTTPS candidate and composition/lifecycle fixtures supply this overlay.
The normal adapter,
V3 contract/fingerprint, target configuration and native retry defaults remain
unchanged. The fixture's V3 adapter identity does not authorize these extra
arguments in a real V3 Run. A future adopted contract must bind the candidate's
actual provider definition and enforcement, rather than reuse the V3 pin.

| Operation | Fresh / refresh | Observation |
| --- | --- | --- |
| Catalog GET | 2 / 2 | Same `/backend-api/codex/models`, empty local catalog accepted |
| Settings GET | 1 / 1 | Same `/backend-api/wham/settings/user`, local 404 remained nonfatal |
| Responses POST | 1 / 1 | Same HTTPS authority/path, uncompressed JSON bodies of 44,179 / 44,195 bytes; fixed SSE completion |
| Token refresh POST | 0 / 1 | Same default `/oauth/token`, synthetic grant accepted, persisted and used |
| WebSocket upgrade | 0 / 0 | No observed upgrade request or fallback sequence |

The inference header names also changed: `Version` and `X-Codex-Routing-Hint`
from the built-in witness were absent in this custom-provider witness. The
observer does not establish whether a real account/server requires those
headers. This is evidence for the **combined overlay**, not independent causal
proof for each switch, or full built-in/provider equivalence. The approximately
4.4-second cases are local fixture timings, not a production performance claim.
That 21:24 transport witness did not establish real catalog/model/tool behavior,
settings/managed-policy semantics, login, upstream acceptance or native tool
execution. The later composition below covers the scoped offline tool path.

## Offline integrated boundary

The [composition fixture](../internal/codexadapter/provider_composition_linux_test.go)
passed at **2026-09-09 22:05:30–22:05:39 UTC**, with the same fixed HTTPS
candidate, CLI/package and model/effort. One native Run refreshed synthetic file
credentials, consumed two strict Responses dispatches, executed the fixed
Code Mode command and returned its independently verified result. The updated
token was persisted and both inference requests required that new token.
There were two catalog GETs, one rejected settings GET and no observed upgrade
or compressed request. All six HTTP requests had the expected status.

This fixture adds exact operation checks before the existing
`responsesgate.Gate`, which still owns strict JSON authorization and finite SSE
bounds. In-memory HTTP connections exercise the actual Gate server without a
second OS listener. Accepted source authority/method/path, framing, bounded
metadata names and synthetic auth/account are checked before reconstructing
`POST /v1/responses`; untrusted headers are not forwarded. Refresh is one bounded
JSON grant with the fixed CLI client ID and synthetic refresh token. The catalog
is capped at two exact version queries with empty local replies. Settings are
still rejected. This is an executable **offline fixture policy**, with finite
buffered TLS replies and no upstream dialer, not a production streaming bridge.

The owned rootless container used UID 1000, no capabilities, no-new-privileges,
no external network, read-only root/package/artifact, bounded executable tmpfs
and the previously retained per-container native-bwrap compatibility seccomp
profile. No bootstrap capability or host policy change was needed. This is a
change from the earlier transport-only witness's default seccomp; it must be
included when reproducing or adopting the composition.

| Boundary | Positive control and observed native result |
| --- | --- |
| Same live TCP frontend | The native client completed HTTPS operations; the same helper outside the native tool sandbox connected. The native tool's new connection returned EPERM. |
| Pathname and abstract Unix sockets | Both fresh canaries returned their nonce outside the native sandbox. Both tool connection attempts returned EPERM. These canaries had no provider/control operation behind them; no provider Unix frontend was created. |
| Inherited descriptors | An intentionally inherited synthetic memfd was detected by object identity. The native tool inherited none of six protected objects, including the memfd, listener, live native-client sockets and accepted TLS sockets. Required Code Mode stdio remained functional. |
| Owner procfs descriptor and memory | A normal same-container helper could read the synthetic owner memfd. The native tool's exact `/proc/1/fd/<seed>` and `/proc/1/mem` opens returned EACCES. Ordinary-user controls also read a fresh child's seeded memory. |
| PID-taking memory/descriptor/ptrace APIs | Ordinary-user controls successfully exercised process_vm_readv, pidfd_open/getfd and non-stopping PTRACE_SEIZE against a fresh owned child. In the native tool's child PID namespace the outer owner has no numeric PID; these APIs were not misdirected to inner PID 1 or reported as measured EPERM. |

A material finding is that **the tool's PID namespace and its procfs mount
show different views**. The final helper observed inner PID 2, outer procfs PID
69 and `NStgid: 69 2`; the live outer owner's start-time matched and its NStgid
was only `1`. Reading the owner's namespace symlink was denied. This matches
Linux's documented distinction between [PID syscall and procfs views](https://man7.org/linux/man-pages/man7/pid_namespaces.7.html)
and the [NStgid ordering](https://man7.org/linux/man-pages/man5/proc_pid_status.5.html).
Consequently, a child PID namespace alone is insufficient to claim procfs
isolation. The probe verifies the mapping before testing the owner's exact
procfs objects. It neither scans memory nor treats arbitrary numeric PID 1 as
an authorized target. The observed EACCES/EPERM results bind the combined
runtime restrictions; they do not identify one policy mechanism as their sole
cause. Descriptor/memory observations are scoped canaries, not a general
proof against every future native-client bypass.

The first local race check found and fixed a fixture startup/Stop race. Three
native attempts retained failed verdicts while the probe's PID-view assumptions
were diagnosed; they already completed the functional round trip, but did not
establish the parent boundary. The final attempt added the verified mapping
and actual procfs denial checks. All four containers were stopped, removed by
verified full ID and independently absent. Final consumer/observer cleanup,
namespace quiescence and all 259 frozen source/artifact inputs passed.

## Offline controller lifecycle

At **2026-09-09 22:49–22:54 UTC**, three focused cases passed with this fixed
HTTPS candidate through the existing Core/Connector and execution Unix HTTP
transports, exact Binding, controller, held-source enrollment, mounted-object
bootstrap and Docker/HRP. The
[fixed provider Runner](../internal/codexadapter/provider_controller_linux_test.go)
reuses the operation consumer and native command/held-lock assertions. It
requires the exact synthetic subscription object already mounted at the
credential destination; there is no fallback auth copy or environment API key.
The [lifecycle checks](../internal/sandboxcontroller/provider_integration_linux_test.go)
verify that refresh preserves the enrolled file's inode and 0600 mode, accepts
only the fixed fake refreshed contents, and leaves the controller's existing
lock and publication rules intact. The controller does not parse provider auth.

| Case and UTC interval | Observed combined behavior |
| --- | --- |
| Completion/replay/cleanup, 22:49:17–22:50:22 | One refresh and two successful inference replies, independently verified native command/result. The observer and consumer joined before the withheld HRP terminal was released. Lost Start reply recovered by identical re-offer, with one Create/Attach. Two removal failures retained the physical credential lock and withheld delivery. Exact absence preceded source close, durable publication and one scoped Core result. |
| Held-tool cancellation, 22:51:09–22:52:15 | Refresh, first inference and a live native tool's nonce/contended lock were witnessed before cancellation through execution HTTP. Outer cleanup released the tool lock, removed the exact container and closed the credential source before one cancellation result. No synthetic completion was substituted. Start replay also retained one Create/Attach. |
| Owner SIGKILL/recovery, 22:52:58–22:54:39 | The same refreshed-file/live-tool point preceded the exact owner's death. Physical source locks were lost, while durable occupancy persisted. Failed startup inspection retired the generation and withheld output. Healthy same-boot recovery used zero credential reopens, Creates or Attaches; exact removal preceded one interruption result. The tool lock was released, helpers joined, and fresh work against the retired generation was denied. |

Each normal/pre-fault witness had two catalog requests, one settings 404 and
one refresh; completion had two inference successes, while both live fault
points had one. The owner-crash container was initially still running and had
exited by the failed-recovery observation. Its retained final witness includes
four later unsuccessful requests (502, 503, 503, 400), with no additional
successful inference. These are failure-path observations, not a successful
Runner completion or proof of instantaneous provider revocation on owner death.
The fault acceptance criterion is retained ownership and no publication until
exact runtime absence. Normal completion additionally requires joined consumer
cleanup; fault cleanup relies on the existing outer containment boundary.

The runtime reuses the earlier controller template: network-none, read-only
root/artifacts/package, RW owned workspace and one RW fake credential file,
512 MiB **noexec** tmpfs, finite CPU/memory/PID limits and pinned per-container
native-bwrap compatibility seccomp. The fixed UID bootstrap uses transient
SETFCAP, then drops all capability sets before mounted-object permit and
Runner execution as UID 1000. This differs from the standalone composition's
executable tmpfs and no-bootstrap setup; it preserves the held file's host
ownership. No host policy change was made, and the earlier FD/socket/procfs
probe matrix was not rerun or relabeled under this template.

An initial attempt at **22:40 UTC** was rejected during enrollment Hold,
before Create, because the chosen credential path had a group-writable
project ancestor. Fresh private roots under an already allowed root-owned
sticky temporary directory corrected fixture placement. The
[credential directory rules](credential-source-lifecycle.md#local-held-file-boundary)
were not weakened. That failed attempt remains a failure; all three executed
containers were independently absent by exact ID and Run label, without rescue
cleanup. Frozen source/artifact inputs were unchanged.

## Next fixed boundary

The scoped offline lifecycle composition is complete. The subsequent
[transport decision and bounded relay](codex-provider-transport.md) select one
per-Run Unix endpoint in the existing runtime-owner process, with TLS and
operation enforcement there and only opaque loopback forwarding in the
network-none container. Local HTTPS tests cover the component; separate
[native channel cases](codex-provider-transport.md#offline-native-channel-acceptance)
passed completion and owner loss at **2026-09-09 23:58–23:59 UTC**, including
the actual socket mount, peer UID mapping and native tool denial. The next
step is endpoint admission/close/join in the existing runtime/controller and
held-credential handoff. The standalone channel driver does not establish
durable cleanup/publication or recovery integration for that resource. Bind the
overlay, operation/metadata policy, client/tool boundary, credential handoff,
runtime restrictions and cleanup lifetime before assigning a replacement pin.
Keep these inside the runtime/adapter boundary; Core, Connector, HRP and media
types need no provider-specific fields. Couple any new pin to the complete
enforcement consumer. Do not invent a real provider revision or reuse V3's
fingerprint for these experimental arguments.

The real target remains blocked. Real login/refresh and upstream header
acceptance, catalog/model/tool and settings/managed-policy behavior, service
identity separation and production transport ownership remain gates. Core,
Connector, HRP and typed-content evolution are unchanged. V3 retains
`credential-exposed-personal`: an allowed request can carry task or credential
data. These results do not establish credential confidentiality.

## Verification and reuse

These Go files are restricted to `linux && codexintegration`. Tagged compilation,
vet and static build passed for the inventory, candidate and composition stages. The current focused TLS,
complete-body, refresh-response, destination rejection and cleanup test passed
with race; the HTTPS native fixture passed on its frozen static artifact.
The built-in native witness retains its earlier frozen source/artifact and
date; it was not rerun for the separate candidate. Earlier collector,
package-access, certificate-shape and response-framing failures remain private.
The candidate's initial compile typo was retained and corrected before native
execution. The composition received tagged compilation/vet/static build, ten
focused operation-boundary cases, the observer test and positive controls with
race, followed by the final native run. None of the retained failed attempts
counts as a product pass.

The controller extension added tagged compilation/vet, fixed complete/cancel
Runner artifacts, a race-enabled host controller and focused synthetic-auth,
operation, TLS and native-result evidence tests with race. The three native
cases above used those exact artifacts. One controller build exhausted the
bounded temporary filesystem; a separate build used existing cached race
dependencies and private workspace scratch. No system quota, mount or policy
was changed. Both that build failure and the pre-Create path rejection remain
recorded separately from the passing evidence.

Only tagged fixtures and documentation changed in those inventory/composition
stages. They reused the unchanged normal Go suite, whole-suite race, vet and
security demo completed at **20:29–20:34 UTC** with their original scope. The
later [relay component](codex-provider-transport.md) adds normal-build code and
has its own regression record. The native channel extension adds only tagged
fixtures/testdata and documentation; it reuses unchanged normal Go test/race/vet
results from **23:23–23:26 UTC**, with fresh tagged builds/vet and a race-enabled
host endpoint. Its startup failures and limited parent-memory positive control
are recorded in the channel document. No admission/recovery/formal,
media or remote-host experiment needed repeating for this inventory. Earlier
native-tool results retain their original provider scope; the new combined
witness has only the scope stated above. No real provider,
Claude/Fable, Discord, system trust, host security policy or deployed target was
changed.
