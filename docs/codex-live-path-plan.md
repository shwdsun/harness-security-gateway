# Codex live-path implementation and acceptance plan

Reviewed against local source and dated evidence on **2026-09-10 UTC**.
This is a delivery plan. The real target remains **blocked**; no image,
credential, runtime configuration or deployment is authorized by this document.
[Implementation status](implementation-status.md) remains authoritative.

The runtime-owned synthetic delivery unit is now implemented and fault-tested.
The [controlled real-provider canary](codex-provider-canary.md) has a fixed
experimental consumer, local enrollment/dispatch entrypoint and read-only
preparation report. Two separately approved real Runs on **2026-09-10** failed
without the completion marker; the second recorded grouped response-policy
rejections whose exact predicate is still unknown. Exact cleanup was separately
observed. Real-provider acceptance remains open. The subsequent local
[rejection diagnosis and bounded failure handling](codex-provider-canary.md#actionable-rejection-and-bounded-failure-handling--2026-09-10)
implementation prepares a more informative controlled attempt. Its new artifacts
and continuation preview precede any separately authorized real execution;
Discord and deployment composition follow provider acceptance.

Apply the [content evolution and verification contract](content-evolution-and-verification.md)
while connecting this path: preserve the content extension boundary, record
affected guarantees, reuse unchanged evidence and consolidate acceptance. This
does not add media implementation or a new research stage to the current delivery.

## Existing evidence to reuse

| Boundary | Evidence available | Limit |
| --- | --- | --- |
| Exact admission, durable replay and disclosure destination | Existing `agentpolicy`, `agentservice`, Core store and protocol tests | Deployment identities and a Discord transport are separate |
| Immutable enrollment/proof and target composition | [Strict service registration](../internal/sandboxservice/authority.go), [enrolled target storage](../internal/sandboxstore/credential_target.go) and their tests | The opt-in canary exercised one real-source enrollment and a same-source generation transition on 2026-09-10; production enrollment/configuration remains absent |
| Run credential reopen, revocation, release and startup retirement | [Credential consumer](../internal/sandboxcontroller/credential.go), [execution tests](../internal/sandboxcontroller/credential_execution_test.go), [native handoff case](../internal/sandboxcontroller/credential_integration_linux_test.go) | Native synthetic enrollment/service/controller/Docker/HRP composition passed at 2026-09-09 10:24 UTC; subsequent real-source handoffs occurred only in the two failed opt-in Runs, with normal configuration still blocked |
| Bounded synthetic provider requests | [Responses consumer](codex-control-boundary.md#completed-synthetic-consumer-witness), [Core/native composition](codex-control-boundary.md#core-ingress-and-focused-native-fault-witnesses) | Native command/readback and scoped Core delivery passed under the tagged synthetic V3 template; real upstream and production transport separation remain absent |
| Cleanup before public terminal and durable occupancy release | [Cleanup](../internal/sandboxcontroller/cleanup.go), [publication tests](../internal/sandboxcontroller/publication_test.go), [formal recovery pilot](../formal/recovery/README.md), [native owner recovery](codex-control-boundary.md#native-owner-crash-and-recovery-witnesses) | A live owner holds the physical source lock through cleanup; SIGKILL loses that lock, so retirement and durable occupancy fence recovery until exact removal and publication |
| V3 package, native host and one-agent capacity | [V3 configuration and canary](codex-profile-v3.md) | Measured cached package, not authenticated image provenance |
| V3 file write / command execution | Offline guest passes at 2026-09-09 04:23 / 05:00 UTC | Temporary guest compatibility profile, mapped package owner and read-only mount |
| V3 IP network control/deny pair | Offline guest pass at 2026-09-09 05:28 UTC | New IP sockets and local HTTP; no provider mediation or Unix/inherited-FD claim |
| V3 cancellation while a tool holds a lock | Offline guest pass at 2026-09-09 05:55 UTC | Quiescence observed after adapter return; not outer cleanup before public terminal publication |

The component details and earlier failures remain in [V3 scope](codex-profile-v3.md).
Private host/provider observations retain their dates. They are not current
host attestations, public CI results or production approval.

## Where the real path stops today

[Config.ResolveTargetAuthority](../internal/sandboxconfig/authority.go) accepts
only the configured closed mock profile. The [sandboxd constructor](../cmd/sandboxd/main.go)
uses that resolver and does not wire `WithCredentialBindings`.
The default [Docker runtime](../internal/dockerruntime/runtime.go) rejects unsupported
profiles and constructs network-none containers with no credential mount.
An explicit `codexintegration` constructor now exercises the optional
[controller CredentialRuntime interface](../internal/sandboxcontroller/types.go)
with an opaque, one-Create held-source handoff. Its consumer independently
verifies the mounted object and releases the bootstrap before exposing HRP.
`HeldSource` still exposes neither bytes nor an FD/mount path. The constructor's
pin denotes only the frozen offline fixture, not real-provider authority.

The candidate entrypoint exists, but [the default build](../Makefile) omits it
and only the mock image recipe is present. Changing the example image digest
or removing one profile rejection would leave the other obligations unmet.
The eight [offline diagnostic blockers](../internal/codexcandidate/check.go)
therefore remain unchanged. The following is their complete work mapping:

| Diagnostic blocker | Remaining implementation or acceptance | Delivery dependency |
| --- | --- | --- |
| `image_provenance` | Trusted artifact acquisition/build record; complete immutable image, OS prerequisites, exact entrypoint, owner/mount composition and preloaded digest | Runtime composition |
| `model_tool_compatibility` | Reuse bundled-catalog/native host evidence; separately verify the authenticated provider's effective model/tool behavior | Runtime composition, then live provider acceptance |
| `network_mediation` | Implement content-bound provider control policy and enforcement; test tool denial across IP, Unix sockets and inherited handles | Authority and runtime consumer |
| `context_closure` | Verify fixed instructions/builtins and reject unapproved repository, user, system and managed customization in the exact image | Runtime composition |
| `credential_lifecycle` | Trusted initial enrollment, executable bindings, exact-object handoff and refresh/revocation/residue checks | Authority and runtime consumer; real refresh later |
| `confidentiality_domains` | Validate resolved workspace/state/credential overlap and exact disclosure scope before selecting an egress-enabled target | Authority and deployment |
| `revision_security_binding` | Bind executable resolved policy/auth/network/context/resources/teardown and enrolled identity; descriptive refs or candidate hashes are insufficient | Authority and runtime consumer |
| `runtime_canaries` | Exercise actual services, runtime and fixed image through one complete lifecycle and fault matrix | Concentrated acceptance |

## Synthetic delivery: original plan and dated evidence

The following preserves the **2026-09-09** work breakdown and its dated outcomes.
The synthetic consumer is now implemented through opt-in fixtures; its original
design tasks are not new pending stages. Remaining production gates and the
current next package are identified above. The consumer path is:

```text
fake Connector -> existing Core admission -> sandboxd immutable authority
  -> admitted Run / enrolled source -> exact runtime handoff
  -> fixed V3 Runner -> controlled synthetic provider
  -> exact runtime cleanup -> credential close -> public terminal/outbox
```

Implement it in three dependent work packages, reviewed as one stage:

1. **Resolve authority that has an enforcement consumer.** Design provider
   control and credential delivery together. Freeze the permitted operations,
   destination/redirect rules, request/response bounds, mediation identity and
   lifetime, including any authentication/refresh operations actually needed.
   The operation set and transport separation are still unresolved; derive
   them from the pinned implementation and scoped observations, not guessed
   hostnames or a generic proxy interface. Implement the narrow consumer and
   bind its actual policy content. No complete real-provider authority pin may
   be emitted while a required enforcement part is missing.
2. **Connect the existing credential lifecycle and exact runtime.** Add the
   trusted local enrollment/configuration consumer under existing exclusive
   sandbox ownership. Use the existing generation/proof transaction and exact
   compiled scope. Resolve how the runtime receives the same held object
   without a later path substitution, and make its lifetime follow the Run.
   Compose the fixed image, namespace/UID/mount policy, context, resources and
   provider-control boundary. Preserve the generic controller's staged outcome,
   cleanup, close and publication sequence. Missing inputs fail before runtime
   authority is granted; existing mock behavior and legacy hashes remain stable.
3. **Accept the whole consumer with one frozen fixture.** Exercise real service
   and runtime boundaries using fake ingress, owned synthetic credentials and a
   fixed responder. Explicitly bind every simulator-only transport/auth delta.
   Use one image/policy identity and isolated per-case Run state in a bounded
   offline environment. Consolidate the report while retaining separate test,
   wrapper, policy-cleanup, runtime-teardown and collection verdicts.

The [provider-control/credential-delivery decision](codex-control-boundary.md)
now defines the narrow synthetic Responses consumer and a candidate Docker
handoff: independent verification of the mounted object while an inert
bootstrap waits, before Codex or provider access starts. The verifier/bootstrap
pair now has six passing local rootless cases with synthetic source data and
a fixed synthetic successor. The later controller-owned consumer is described
below; normal executable configuration is still blocked.
The bounded synthetic Responses handler is now implemented and tested over
in-memory HTTP connections, including request/stream limits and cleanup faults.
Its first combined rootless fixture on **2026-09-09 08:16 UTC** passed mounted
source verification and reached native Responses dispatch, but nested command
namespace creation was rejected. The case failed; exact outer cleanup and
subsequent source unlock passed. The
[scoped runtime diagnosis](codex-control-boundary.md#runtime-diagnosis-and-passing-scoped-compatibility-case)
at **09:04 UTC** obtained a pass using a local seccomp profile and fixed UID
setup before the unchanged bootstrap. All capabilities were independently
observed empty before permit, with unchanged host/source ownership; native
command/readback, in-namespace quiescence and outer cleanup passed. The startup
template still needs production artifact/authority approval. At **10:24 UTC**,
the [controller-owned follow-up](codex-control-boundary.md#controller-owned-synthetic-v3-witness)
passed native enrollment, service admission, one Docker Create/Attach despite
receipt replay, mounted-object/policy validation, HRP/native completion and
physical lock release after exact removal but before publication. Its explicit
tagged constructor binds the fixed inputs into synthetic authority and scopes
inventory to that fixture. No Core or Connector was in this case.

At **10:53–10:56 UTC**, the
[Core/native follow-up](codex-control-boundary.md#core-ingress-and-focused-native-fault-witnesses)
passed three focused cases using compiled exact Binding, real Connector and
execution Unix HTTP endpoints, Core dispatch/outbox and the verified consumer.
It covered source replacement before Create, a lost Start response with exact
re-offer, repeated removal failure followed by reconciliation, and externally
cancelled native work. Only two containers were required; the source-denial
case created none. No normal executable configuration was enabled.

At **11:32–11:35 UTC**, the
[owner recovery follow-up](codex-control-boundary.md#native-owner-crash-and-recovery-witnesses)
passed SIGKILL during native work and after Create but before reference binding.
Both retained cleanup authority through a failed replacement, then recovered
the original Run without new Create, Attach or credential execution-source open.
The physical lock vanished on owner death; durable occupancy and startup
retirement supplied the recovery fence.

The [termination follow-up](codex-control-boundary.md#deadline-and-resistant-descendant-witnesses)
passed a fixed resistant/`setsid` descendant at **19:53–19:54 UTC** and native
held-tool deadline at **20:11–20:12 UTC**. Both retained staged results and source
occupancy through unavailable removal. The resistant Runner is an adversarial
HRP fixture; native descendant variants retain their own acceptance boundary.

At **20:28 UTC**, the
[permanent feedback correction](codex-control-boundary.md#permanent-credential-admission-feedback)
passed the actual service/HTTP/Core path: retired-generation or wrong-scope Start
returns a closed policy denial, and Core finishes once absence is confirmed.
Existing or uncertain Runs retain their observation path; no credential details
or new message authority are exposed.
Reuse unchanged Connector/Runner, media-boundary, native tool and formal evidence;
do not repeat these passing cases without a changed dependency. The
[built-in operation inventory](codex-provider-operations.md) passed fresh and
refreshed synthetic file auth at **21:04–21:05 UTC**, revealing WebSocket
attempts and compressed HTTP fallback. A
[separate fixed HTTPS/SSE candidate](codex-provider-operations.md#fixed-httpssse-candidate)
passed at **21:24 UTC** with uncompressed inference and refresh persistence/use,
and no WebSocket attempts. Its custom provider also changes some headers;
real-server compatibility and a separately bound contract remain gates.
The [offline operation/tool composition](codex-provider-operations.md#offline-integrated-boundary)
passed at **22:05 UTC**: strict consumer, refresh, native tool round trip,
positive controls, connection/FD/procfs checks and cleanup. The tool's PID
namespace and procfs view differ; the recorded checks account for both.
The subsequent [offline controller lifecycle](codex-provider-operations.md#offline-controller-lifecycle)
passed at **22:49–22:54 UTC**, combining mounted-file refresh and stable identity
with replay/removal failure, held-tool cancellation and owner-crash recovery.
It reused the earlier controller UID/bootstrap and noexec-tmpfs template; the
standalone FD/socket/procfs observations retain their original runtime scope.
The [transport decision and bounded relay](codex-provider-transport.md) now
select the existing runtime owner for TLS/operation enforcement and one per-Run
Unix endpoint, with opaque forwarding inside the network-none container. Local
HTTPS composition and separate native completion/owner-loss cases pass. The
**2026-09-09 23:58–23:59 UTC** native witness verifies socket mount identity,
UID mapping, tool connection/descriptor denial and joined standalone cleanup.
That checkpoint left endpoint admission/close/join and socket/CA attestation
for the existing runtime/controller. The **2026-09-10** canary now implements
and measures that cleanup/publication and recovery integration; the older
standalone driver itself still supplies none of those guarantees. Its roughly 24-second owner-loss
terminal delay is not an immediate cancellation guarantee.
Bind the actual overlay, operation/metadata policy and runtime lifetime before
creating a replacement pin. Complete production operations remain unresolved.
A schema or digest helper without the complete enforcement consumer is not the
completion criterion.

Two constraints govern that design:

- V3 inherits **`credential-exposed-personal`** and the dedicated single-file
  RW credential bind from [the sealed credential contract](codex-profile-v1.md).
  A fresh-IP deny test or synthetic environment-key exclusion does not show
  reusable credentials are hidden from native tools. An allowed provider
  request can carry workspace or credential data. Stronger credential hiding
  requires a separately versioned, reviewed contract; it must not silently
  replace V3 or be claimed by this plan.
- A provider endpoint accessible to both client and tools does not establish
  mediation. The chosen process/transport boundary must prevent tools from
  exercising control authority through local sockets, inherited descriptors or
  another path. Native built-in communication that is required for Code Mode
  needs an explicit scope; “all Unix sockets denied” is not an assumed solution.

If the required handoff or separation cannot be achieved within the selected
contract/runtime, preserve the blocked gate and report that specific decision.
Do not mount the whole credential directory, expose a generic FD/path API to
messages, adopt a replaced file, or generate a placeholder authority pin.

## Concentrated acceptance matrix

These are scenario families within the new consumer, not separate protocol
projects or reasons to rerun unchanged old component experiments.

| Scenario | Required independent observations |
| --- | --- |
| Authorized work and replay | Exact Binding/revision; one durable Run and at most one Create; permitted synthetic control request and owned output; replay causes no second acquisition/Create; result reaches only the admitted destination |
| Authority or source mismatch | Changed scope/policy, missing proof, revoked generation or changed source denies new authority; a retained uncertain intent remains attached to its original Run for cleanup |
| Credential handoff and update | Runtime observes the checked synthetic object; in-place update keeps identity, replacement invalidates it; a live owner holds the source through cleanup, while crash recovery retains durable fences despite physical lock loss; no accidental credential copy into images, Core/Connector state or trusted diagnostics |
| Tool and context boundaries | Positive client control plus tool IP/Unix/FD denial at the selected authority boundary; only approved customization loads; independent marker/readback probes; image limits and inaccessible Core/sandbox/runtime-socket domains checked |
| Completion, cancel and timeout | Exercise normal completion, held-tool cancel, deadline, TERM resistance and leader-exits-first/`setsid` descendants; public terminal/outbox and unlock follow exact outer cleanup, not merely CLI exit |
| Crash, uncertain Create and recovery | Inject late Create, lost response, cleanup failure and owner restart; retain fences until proof, never recreate during recovery, retire occupied credential generations before workers; healthy cleanup resumes when the stated runtime/storage conditions recover |

The **2026-09-09 10:53–10:56 UTC** integrated cases cover authorized ingress,
event/Start/delivery replay and exact output destination; changed source denial;
completion, local execution cancellation while a native tool holds a lock;
and lost Start response/repeated removal failure with healthy reconciliation.
The **11:32–11:35 UTC** cases additionally cover a killed owner with a bound
native runtime and with an existing, still-unbound Docker object, failed startup
inspection and healthy recovery. The later termination cases cover native work
through its frozen deadline and a fixed adversarial TERM-resistant/leader-exits-
first/`setsid` process shape. The earlier recovery container exited before healthy
recovery; it is not relabeled as resistant-process evidence. Absent delayed
daemon Create, host reboot, native launcher descendant variants, full tool
IP/Unix/FD mediation, context closure and real credential updates remain open.
Existing component/model evidence retains its original scope.
The synchronous Core dispatcher and same-UID Unix listeners are actual product
components in a fixture; the recovery owner is a separate test process, not a
deployed sandboxd or a separate service identity.

Use the existing independent transaction/property tests and model corpus for
their covered transitions. Revisit the model mapping when those transitions or
assumptions change. Formal proof over the abstraction cannot replace actual
file handoff, native syscall, container, provider or transport evidence.
Trusted diagnostic redaction does not prevent a tool that can read a credential
from encoding it in its output or in an allowed provider request; V3 retains
that declared confidentiality limit.
Keep existing shared decoder tests; add new entrypoint tests only for new
authority or behavior. Preserve both rejection and successful-progress checks.

Stage completion requires every required scenario to pass with its named
evidence, or an explicit unresolved gate. Environment failure, skip, missing
artifact, timeout or an unobserved operation cannot pass. After a failure,
preserve evidence and diagnose the changed boundary before another attempt.
Run appropriate Go checks after code freezes and host/image tests once the
composed fixture is ready, with fresh per-case state. A new image, policy or
consumer invalidates the relevant composition evidence; unchanged primitive
results need not be regenerated merely to repeat their assertions.

## What follows, and what does not change

The synthetic stage's successful outcome is an implemented and measured local
execution boundary. It cannot satisfy real login, authenticated catalog,
refresh, provider-side revocation or public Discord gates.

Next, use fake ingress with the reviewed target and a dedicated provider
identity to accept real authentication, allowed control traffic, refresh,
credential loss/revocation and redaction. Exact external effects and current
host/identity state must be reviewed at that time. Only then implement and
accept the private Discord Connector: stable identities, private token/cursor,
durable spool, reconnect/catch-up, replay/self-event rejection and delivery
semantics under separate service identities. No public Discord implementation
exists today; private connectivity observations do not substitute for it.

This plan adds no new platform, agent loop, generic profile engine or mandatory
formal/model-review ceremony. No target becomes selectable through the offline
diagnostic, a model verdict or a documentation update.
