# Patched-artifact Discord-to-Codex verification — 2026-10-21

Seven project Go executables rebuilt with **Go 1.26.10** passed a fresh real
Discord-to-Codex task on **2026-10-21 UTC**, after correction of a missed security
patch floor. The guest task interval was 06:26:52–06:27:14 UTC; an independent
platform read verified the receiver Bot's exact reply. The owned VM was
separately confirmed gracefully absent at 06:27:22 UTC. This task has its own
Run, message, artifacts and observations; the earlier 05:43 UTC Go 1.26.9 result
below remains historical evidence for those earlier bytes.

## Security correction and verification scope

The primary coding agent selected Go 1.26.9 using dated source CI and omitted
a fresh advisory scan before the first rebuild. **Go 1.26.10 had already been
released on October 19**, with a `crypto/x509` security correction. Fresh main
[CI for `507dfd0`](https://github.com/shwdsun/harness-security-gateway/actions/runs/39552133985)
reported [GO-2026-6809](https://pkg.go.dev/vuln/GO-2026-6809), concerning
compromised intermediate certificates, and blocked final completion. The
historical source CI cited below was not a current advisory check. The original
compatibility pass remains valid within its dated scope; it is not security
acceptance for the corrected toolchain. See the
[official Go release history](https://go.dev/doc/devel/release#go1.26.10).

A controlled comparison against the official Go vulnerability database used
fresh caches, the same frozen source and the same scanner. Both default and
`codexintegration` graphs reported the advisory with Go 1.26.9; both reported
no reachable Go vulnerabilities with Go 1.26.10. The new build source also passed
fresh scans of both graphs without suppression or exclusions. These results
cover reachable Go vulnerabilities for the scanned graphs and database
observation; they do not audit every native executable, image package or
possible security defect. The evidence does not establish a particular cache
failure as the cause of the original omission.

## Go 1.26.10 actual result — 06:27 UTC

| Boundary | Actual corrected-artifact observation | Limit |
| --- | --- | --- |
| Installed artifacts and configuration | All seven new ELF hashes and three configuration hashes matched before the task and after service cleanup | Project Go artifacts, not a rebuild of every third-party program |
| Running services | Effective commands and sampled `/proc/PID/exe` identities/hashes matched the new Core, Owner and Connector executables | Three main processes at observation time; native helpers were bound through their pinned launch/mount chain rather than independently sampled as every live executable |
| Fresh task and reply | One new completed Run, exact marker/output and one independently checked reply to its new Discord message | Two official Bots in one private guild text channel; no human direct-message experiment |
| Containment | One joined create/start/exit/removal chain, 36 present-container samples and 35 running namespace observations; fixed helper mounts and network/capability/filesystem guards passed | Finite runtime observations, not a kernel or whole-process-history proof |
| Real-token witness | Three real-token values compared over 276 file/process/metadata observations and 601,132 bytes; zero exact matches; one complete live snapshot included the native client and final token set | Passive bounded surfaces, with retained live bytes rechecked against final tokens; no active protocol/FD or every raw tool stream interception |
| Authority and history | Generation 2 retired once through the existing Store API; canonical generation 3 and a new immutable target/scope used the same physical source and original three database objects; both old Owner Runs and their authority history remained | No SQL reset or retention change; no Core or Connector rows were removed in this corrected phase |
| Cleanup | Three HSG services normally stopped, runtime empty and durable state idle; owned VM gracefully absent with captured pre-existing lab metadata unchanged | Secret-bearing disks remain retained; shutdown is not destruction or provider revocation |

No access-token or source-content change was observed. This is fresh artifact
and real-service compatibility evidence, not another observed credential
renewal. The qualified October 19 renewal inference keeps its original artifact
scope and trusted-owner assumptions. No provider credential bytes or
credential-content hashes were exported in these receipts. Trusted local
administration, kernel, authentication Owner and fixed native package remain
assumptions; the finite witness is not universal credential secrecy.

The same owned guest/source/database lineage was advanced rather than reset.
Its two old Owner Runs, generations and targets were preserved; new authority
used generation 3 and a distinct revision/Binding. Structured successful
canonical enrollment and exact durable proof were joined before serving.
Authenticated GET/405 readiness preceded strict target checks and downstream
startup. The new task did not reuse the earlier message, Run or reply. The Run
limit remained 300 seconds; the 900-second campaign observation window and
1500-second campaign watchdog did not extend that execution limit.

## Corrected build provenance

The new build source was
[`b98c263`](https://github.com/shwdsun/harness-security-gateway/commit/b98c263e93759bd226f78771a0241600400f389e).
It raises the Go security floor to 1.26.10; application Go source is unchanged.

Go 1.26.10 source verification passed ordinary and `codexintegration`-tagged
tests, the full ordinary race suite, selected experimental race checks for
`internal/dockerruntime` and `internal/codexprovider`, and vet for both build
graphs. The security witness, configuration and bakeoff-schema checks also
passed. The tagged source tests retain the existing exclusion of the separate
live-provider case `TestCodexExecIntegration`; no new exclusion was added. The
fresh task above separately verifies the actual deployed path.

The frozen manifest contains 82,015,033 bytes across the seven artifacts below.
The C identity/launch helpers, native six-file Codex package, runtime image and
containment policy remain pinned. Earlier controlled substitution,
poisoned-response, cancellation and crash/recovery cases keep their original
dates, binaries and assumptions. Their unchanged mechanisms were not rerun as
new real-provider fault experiments; the affected artifact boundary received
this new task, installed/live audit and finite token witness.

| Project artifact | Go 1.26.10 SHA-256 |
| --- | --- |
| Gateway service (`agentd`) | `92812a0dfff5f19262894a0e85f97f296b8c505378d8dc3f8558e5f0d619aa9d` |
| Execution service (`sandboxd-codex`) | `69f16c4cdc52d0aea40aa4e4abb280a10a91d33de71e43e681a9dbc899a54a80` |
| Discord connector (`discord-connector`) | `dd7bd1a2629fcdfb5af2e7df69b525f2ed569d57631d786ed6175990662e6eae` |
| Local configuration utility (`hgwctl`) | `f7821cc20cc62907eafee21234d3d23e3ef1e9af7cfa0b4300071b7625c7d1ec` |
| Native Runner (`codex-isolated-runner`) | `95766c75d76e7eac661d8409e53527387ffdcaf6a75986b16a332a206ad034f9` |
| Credential bootstrap (`credential-bootstrap`) | `03a3078a2b247bb174a8e091919e8ea2a4e0fa151c2fc580bf31a808b5d362d9` |
| Startup check executable (`startup-canary`) | `2146e4076b07d95c9ebb4e703d6bd56bccc79c9f880136d262c9ac4b58be06dc` |

The public offline recipe remains a profile-v3 recipe. This fixed private
profile-v4 correction is not a supported updater, personal-pilot release or
production activation. Source regression, independent review, publication and
exact published-head CI are separate from the successful real task; a real-path
pass does not override a failing vulnerability gate. Detailed receipts remain
private. Setup, the fresh task, platform checks and owned cleanup added zero
operator commands, authentication steps, messages or confirmations; no Claude
review was invoked. This bounded result is not a measured productivity claim.

## Earlier Go 1.26.9 verification — 05:43 UTC

Seven project Go executables were rebuilt with **Go 1.26.9**, installed in the
existing isolated laboratory deployment, and verified through one new real
Discord-to-Codex task on **2026-10-21 UTC**. The task completed at 05:43 UTC;
an independent platform read confirmed the receiver Bot's reply to the original
message. The gateway recorded one new Run and one correlated container with
create, start, exit and removal events. The expected marker content passed.

This supplied affected-artifact and real-path compatibility evidence for that
build. It did not establish the current security floor described above. The
[October 19 acceptance](real-service-acceptance-2026-10-19.md)
remains a separate dated result for its old binaries. No new credential renewal
was observed on October 21. This report does not turn the previous renewal
inference or controlled failure cases into new real-provider observations.

### What was checked

| Boundary | Actual October 21 observation | Limit |
| --- | --- | --- |
| Deployed artifacts | All seven installed ELF hashes matched the frozen build manifest before the task and after service cleanup; three configuration hashes also matched | Project Go executables, not every third-party program in the image |
| Running services | Effective commands and sampled `/proc/PID/exe` paths, object identities and hashes matched the new Core, Owner and Connector executables | Three main processes at the observation time, not complete process history or an independent audit of every unit-hardening byte |
| Task and reply | One new completed Run, expected marker, exact requested output and one independently checked Discord reply | Two official Bots in one private guild text channel; human direct messages were not exercised |
| Containment | Fixed new native-helper mounts, read-only root, network-none container, restricted capabilities, seccomp and no-new-privileges; running user, mount, network and PID namespaces differed from guest Root | Finite runtime samples and lifecycle events, not a kernel proof |
| Provider-token observations | Three distinct real-token values, 407 file/process/metadata observations and 3,238,351 scanned bytes; zero exact matches and one complete live snapshot containing the native client | Passive sampled surfaces; active protocol/FD streams, all raw tool data, encodings and whole history are not covered |
| Credentials and history | Old generation retired once; new generation and target bound to the same physical source and original database objects; prior Owner task history retained | Core's expired terminal receipts were normally collected under the existing retention policy; not every old row in every store is retained |
| Cleanup | Three HSG services normally stopped, runtime empty, durable obligations idle; owned VM gracefully absent with captured pre-existing lab metadata unchanged | Protected secret-bearing disks remain retained; shutdown is not credential destruction or revocation |

The live scanner's retained bytes were checked again against the final token set.
No provider credential bytes or credential-content hashes were exported in its
receipts. Platform Bot credentials keep their separate Connector boundary.

The source object identity and sampled before/after content matched; no new
source change or refresh was observed. The result establishes useful
real-service compatibility with the patched
artifacts, **not a new observed refresh or refresh exchange**. The qualified
natural-renewal evidence remains dated October 19 under its stated trusted-owner
assumptions. Local administrator, kernel, trusted authentication Owner and fixed
native package remain trusted here.

### Build and change scope

The build source was
[`abcb8be`](https://github.com/shwdsun/harness-security-gateway/commit/abcb8be339dd7b4a8d2866a86e8b310db8c0d1f8).
[Its source CI](https://github.com/shwdsun/harness-security-gateway/actions/runs/39247672327)
passed on October 19, including default and experimental build graphs, race/vet
checks, mock-image builds and reachable Go vulnerability scans. The October 21
build froze the compiled input closure and actually produced these new bytes;
source CI alone was not used as deployment acceptance.

| Project artifact | SHA-256 |
| --- | --- |
| Gateway service (`agentd`) | `2b9c0f4d8c5425aeed0c773e5f107be71fd59e4d446e144c8456b18acaf5c52b` |
| Execution service (`sandboxd-codex`) | `217f8bb91a3f7f84ac47e48a1f11c7d52c752b92c18b6bc5783676e757536df9` |
| Discord connector (`discord-connector`) | `a73728fe522f775d686a14dd983b368da341328fd047f4f69fc815dfe30916ab` |
| Local configuration utility (`hgwctl`) | `a15661473874801677470f4064aa4652d066081086df366647bc3714fc28eb5d` |
| Native Runner (`codex-isolated-runner`) | `8fe3e41c0eea9697f910423d57fa6959a3894b8d39536be7035e86138d37d55a` |
| Credential bootstrap (`credential-bootstrap`) | `b6cdcf052cdda349e630e223896483c55153bf08f3585805129964729652d59b` |
| Startup check executable (`startup-canary`) | `af47c2b6e6aeaf0844f99e0b83ad3a1e820e80d60938ab1758c1fbc1709e442a` |

The C identity/launch helpers, native third-party Codex package, runtime image
and containment policy remained pinned. The native helper mounts were observed
in the actual task container. They were not all sampled as separate live host
process executables, and the third-party image was not entirely rebuilt.

No gateway Go source changed for this verification. Earlier controlled
substitution, poisoned-response, cancellation and crash/recovery cases retain
their original dates, test executables and assumptions. Their unchanged mechanism
source and native-package inputs support reuse after this compiler patch; they
were not rerun as real-provider fault experiments for the new ELF hashes. The
Go 1.26.9 real task, installed/running artifact checks and finite token witness
supply that build's affected deployment evidence. The public offline build recipe remains
a profile-v3 recipe; this private profile-v4 campaign is not a supported updater.

### Preserved pre-task failures and remaining product limits

Two private campaign checks stopped before any task was sent. First, a completed
credential enrollment could not satisfy a positive systemd process-timestamp
assertion: the inactive unit reported zero timestamps. Exact read-only database
and journal evidence established the committed result; it was adopted without
another retirement or enrollment. Unit garbage collection is a plausible
explanation of the zero timestamps, not a directly observed event.

Second, the evidence was consistent with a startup race: service start jobs
completed, the new target was absent after cleanup, and Owner cancellation
followed the campaign's stop request. The first exception detail was not retained.
The script queried complete target state immediately after exec, and a socket
can already exist before the Owner registers its target. The correction
used the existing authenticated local HTTP handler's nonmutating GET response
before strict authority checks, then started downstream services in order. It
added no endpoint or authority and did not ignore invalid state. Both failed
results remain failed and preserved; no uncertain task was replayed.

The agent performed setup, diagnosis, the single task, independent reply checks
and cleanup without another operator command, authentication, message or Enter
prompt. Separate Codex-agent reviews were advisory and disclosed their component
authorship; no Claude review was invoked. This bounded zero-additional-step
result is not a measured productivity or general installation-usability claim.

Supported installation, updates, long-running behavior and recovery for a
[personal pilot](milestones.md#usable-personal-pilot) remain open. This experiment
is not production activation, a release, a universal credential-secrecy proof or
approval for arbitrary deployments. Detailed deployment receipts remain private.
