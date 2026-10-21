# Patched-artifact Discord-to-Codex verification — 2026-10-21

Seven project Go executables were rebuilt with **Go 1.26.9**, installed in the
existing isolated laboratory deployment, and verified through one new real
Discord-to-Codex task on **2026-10-21 UTC**. The task completed at 05:43 UTC;
an independent platform read confirmed the receiver Bot's reply to the original
message. The gateway recorded one new Run and one correlated container with
create, start, exit and removal events. The expected marker content passed.

This renews the affected artifact and real-path evidence after the compiler
security update. The [October 19 acceptance](real-service-acceptance-2026-10-19.md)
remains a separate dated result for its old binaries. No new credential renewal
was observed on October 21. This report does not turn the previous renewal
inference or controlled failure cases into new real-provider observations.

## What was checked

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

## Build and change scope

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
current real task, installed/running artifact checks and finite token witness
supply the affected deployment evidence. The public offline build recipe remains
a profile-v3 recipe; this private profile-v4 campaign is not a supported updater.

## Failures, recovery and remaining work

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
