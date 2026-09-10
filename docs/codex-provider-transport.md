# Fixed provider channel and owner lifetime

Design selected **2026-09-09 UTC**. The **2026-09-10**
[runtime-owned canary](codex-provider-canary.md) now adds controller lifetime
integration, verified socket/CA bootstrap, fixed upstream dialing and a separate
experimental pin. Offline native completion, cancellation and owner recovery
pass. Production runtime wiring, authenticated-provider acceptance and a new
production Codex contract remain **blocked**.

## Ownership decision

The [offline controller witness](codex-provider-operations.md#offline-controller-lifecycle)
showed that a container-hosted request consumer can briefly survive its
controller. Put the eventual per-Run endpoint, TLS termination, operation
enforcement and upstream connections inside the **existing sandbox runtime-owner
process**. Keep one network-none execution container and one per-Run Unix socket.
A small loopback relay inside the container forwards bytes only to that fixed
socket. TLS ends at the owner; the relay receives no CA signing key and never
chooses an external destination or authorizes a request.

```text
native Codex HTTPS client
    -> container loopback byte relay
    -> one pinned per-Run Unix socket
    -> runtime owner: TLS + operation enforcement -> fixed upstream operation
```

The final upstream arrow is implemented in the opt-in canary but has not been
exercised against a real provider. All acceptance here still ends in an
in-process synthetic responder. A
forwarded CONNECT is input for owner-side TLS/operation checks, never permission
to create an opaque external tunnel. This selects no host TCP listener, Docker
bridge/firewall change, persistent proxy daemon or second recovery machine.
Core, Connector and HRP retain their current contracts; provider fields do not
enter messages. The runtime supplies the fixed socket mount and public CA;
the immutable adapter supplies the matching proxy/CA configuration.

Native tools must be unable to connect to either the loopback relay or Unix
socket, inherit an established channel, or recover one through descriptors or
memory. A loopback address and provider bearer alone are not process identity.
The previous socket/FD/procfs canaries motivate the design. The separately
dated native acceptance below checks the new host-socket mount and relay;
neither witness establishes general credential confidentiality.

## Implemented relay boundary

[`providerrelay`](../internal/providerrelay/relay_linux.go) is a Linux component
with trusted construction inputs: one existing socket, one concrete expected
peer UID and one deadline-bearing Run context. No normal executable uses it yet.
It does not read credentials, terminate TLS, parse HTTP, dial IP destinations,
perform DNS, retry a connection or expose a management route.

| Resource or action | Implemented bound |
| --- | --- |
| Endpoint | `openat2` without symlinks; retain an `O_PATH` descriptor to one Unix socket. Reject root/overflow peer identities, mismatched socket owner and world access. |
| Dial | Connect through the held descriptor's procfs path; never re-resolve the original name. Verify Linux connect-time peer UID before copying any bytes; a missing or mismatched peer closes the relay. |
| Listener | Fresh IPv4 loopback port, with no caller-selected TCP listen address. |
| Capacity | At most 16 accepted connections and four active pairs. Excess concurrent clients close before an owner connection is made. At total admission exhaustion, join already admitted exchanges. |
| Bytes | At most 4 MiB per direction per connection, including TLS framing. Reaching that ceiling closes both directions and the relay with a budget error. |
| Time | Two-second dial timeout and the original Run deadline for all copying. The caller must cancel that context on revocation/cancellation. |
| Cleanup | Either stream ending closes both directions; no half-close continuation. `Close` stops admission and joins dial/copy workers before releasing the pinned socket. No body/header/token logging. |

These are finite **component ceilings**, not accepted production request or
media limits. The future runtime/adapter contract must bind compatible limits
alongside the actual operation/stream policy. Image/file support can change
that content/adapter contract without adding a destination selector or changing
Core authorization and recovery rules.

The held socket prevents pathname replacement from redirecting an existing
relay to another Run's endpoint. Peer UID is checked in the relay's namespace;
it does not distinguish two same-UID Runs by itself. Deployment still needs
protected per-Run paths, the exact read-only socket mount and verified UID
mapping. Nobody/overflow or root is not an acceptable fallback identity.

## Required runtime integration

The endpoint must start closed, bound to one admitted Run, immutable resolved
policy and verified runtime. Open operation admission only after mounted-object
and runtime checks and immediately before permitting native execution. The
relay itself grants no operation authority. On cancellation, deadline or
credential invalidation, first close owner-side admission and active exchanges.
Existing runtime cleanup must then join that endpoint, remove the exact
container and release held credentials before terminal publication.

Owning all mediator connections in the existing process avoids a surviving
proxy helper on process death. It does not undo a request already accepted by
an upstream. Recovery must retire the old generation, retain existing durable
occupancy, clean the old runtime and never reopen its endpoint. A stale socket
pathname is evidence, not a resume capability. New Runs get distinct endpoint
objects. The canary now adds these hooks and extends its cleanup witness; container
absence alone cannot prove cleanup of a live owner-side endpoint. The
[updated formal mapping](../formal/recovery/README.md#runtime-owner-resources-2026-09-10)
records this stronger implementation obligation without claiming the mock
model proves endpoint quiescence.

## Local acceptance and remaining gates

The component tests cover pinned-object dialing despite pathname replacement,
refusal after the original owner disappears, concurrent/total/byte limits,
connect-time UID comparison, context deadline and concurrent joined close.
The [HTTPS composition](../internal/codexadapter/provider_relay_linux_test.go)
uses the existing strict operation fixture and Responses Gate over an actual
Unix listener and TLS connection: synthetic refresh and inference succeed;
changed effort is rejected before responder dispatch. A separate test kills
only its exact spawned endpoint-owner process after a live request witness.
That active TLS request fails without reaching its timeout, and the old pinned
endpoint refuses another request. This is a local Go-client/process witness,
not a native Codex/container-mount or production performance result.

The first crash fixture timed out before readiness. A bounded diagnosis
observed its test-directory leaf at 0775 and the child's explicit private-root
rejection. A fresh `MkdirTemp` owner directory supplies 0700 regardless of the
test harness's leaf mode. The test now observes early child exit and retains
bounded startup diagnostics. No endpoint check or host policy was relaxed;
the failed attempts remain failures.

## Offline native channel acceptance

The [fixed native fixture](../internal/codexadapter/provider_native_linux_test.go)
passed completion at **2026-09-09 23:58 UTC** and owner loss at
**23:58–23:59 UTC**. One host test process owns the Unix listener, TLS keys,
strict operation fixture and Responses Gate. One network-none container uses
the unchanged six-file V3 package and fixed HTTPS overlay. It reuses the pinned
UID setup, per-container compatibility seccomp, noexec tmpfs and resource
limits. Only its fresh workspace and synthetic auth file are writable binds;
the socket, public CA/identity and executable artifacts are read-only.

| Check | Observed result and limit |
| --- | --- |
| Mounted endpoint | Host/container device and inode matched, socket mode 0600 and UID/GID 1000, exact read-only mount. Direct Unix connect and peer UID/GID passed. The host peer PID appears as 0 in the container namespace; PID 0 was not treated as process identity. |
| Legitimate client | One synthetic refresh, two catalog responses, one expected settings rejection and two successful inference dispatches; a fixed native Code Mode command and independent output matched. Refresh preserved the exact single-file bind and mode. |
| Tool connections | Direct Unix and outside-sandbox TCP controls succeeded. The native tool's relay TCP and mounted Unix connection attempts both returned EPERM. |
| Descriptor/procfs scope | Eight protected objects covered the synthetic memfd plus live relay/client sockets; none were inherited by the tool. An intentionally inherited memfd and owner procfd were accessible in the outside-sandbox child. Native tool access to the exact container owner's procfd/memory returned EACCES. |
| PID/memory limit | The tool has a child PID namespace with ancestor procfs, verified through both PID lists and owner start time. Owner PID-taking probes were therefore not issued. The outside-sandbox child's parent-memory control was itself denied, so this stage adds no differential memory-denial or credential-secrecy proof; earlier owned-child controls retain their dates. |
| Owner loss | After independent tool verification and an active second inference callback, the driver killed only its exact owner child. Native execution returned `RunFailed`/`harness_error` before its deadline, and the joined relay reported `ErrEndpoint`. The killed owner has no successful test verdict or second-response completion witness. |
| Cleanup | Both clients joined the relay and checked descendant quiescence. The driver joined the host owner before exact stopped-container removal and independently verified absence by full ID and experiment label. Neither passing case needed rescue cleanup. |

The fault case reached its terminal roughly 24 seconds after owner SIGKILL.
This is a bounded local failure observation, not immediate native cancellation
or a latency guarantee. Keep the existing cancellation/teardown ownership:
runtime integration must actively terminate a cancelled Run rather than wait
for the native client to finish reporting a transport error. No accepted
upstream request was involved in this experiment.

Earlier attempts remain failures. The first driver expected a short capability
name where Docker reports the canonical `CAP_SETFCAP`; it stopped before
container Start. The next fixtures passed socket/UID controls but never reached
CONNECT: they omitted the existing bootstrap's private disposable-home setup
and pre-created an output directory that the adapter must create exclusively.
Matching those existing contracts fixed startup. The observed home began at
0755 and was tightened to 0700 inside disposable container tmpfs only. No
adapter check, auth-file permission, host policy or container capability was
relaxed. Tagged compilation/vet/static builds and a race-enabled host owner
back the final native artifacts; all normal Go sources remain unchanged from
the **23:23–23:26 UTC** full test/race/vet verification.

At this 2026-09-09 checkpoint, the next step was admission/close/join in the
**existing runtime/controller cleanup**, with socket/CA mount attestation and
held-credential bootstrap. The **2026-09-10** canary completes that integration. The standalone driver is not Core,
durable recovery or post-cleanup publication integration. Reuse unchanged
protocol/formal/credential evidence within its assumptions; extend the cleanup
assumption for the new owner resource. Full operation/body/metadata policy,
real login/refresh, header/catalog/model/settings behavior and upstream
acceptance remain separate gates before any replacement pin. V3 retains
`credential-exposed-personal`; Discord and the real target remain disabled.
