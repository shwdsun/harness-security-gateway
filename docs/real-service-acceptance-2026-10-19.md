# Bounded Discord-to-Codex acceptance — 2026-10-19

One fixed experimental deployment completed a real Discord-to-Codex task with
isolated provider authentication on **2026-10-19 UTC**. A separate official
tester Bot sent the task to the receiver Bot in an operator-controlled private
guild text channel. A human direct-message path was not exercised in this
campaign. The task created the expected file and content, returned the exact
requested reply, and cleaned up.
An independent platform read confirmed the receiver Bot's actual reply matched
the gateway's delivery receipt. The experiment admitted one task and created
one container, with correlated create, start, exit and removal events.

Final review accepted the credential-isolated messaging milestone (`M1`),
including its reusable-provider-credential condition (`CRED-01`), **only for the
[Codex profile v4](codex-profile-v4.md), exact artifacts below and tested
deployment**, combining the real result with the separately scoped mechanism
and failure evidence. The [roadmap](milestones.md#credential-isolated-messaging)
defines those criteria. Supported installation, a maintainable personal pilot
and production activation remain separate goals. Neither this result nor a
source merge enables another target.

## What was observed

| Boundary | Observation | Limit |
| --- | --- | --- |
| Useful work and reply | One completed task in both gateway and execution stores; exact file/content and reply; one independently observed platform reply | One authorized text task, one fixed Codex client and one private experimental deployment |
| Runtime containment | Fixed mount policy, read-only root, network-none container, restricted capabilities, seccomp and no-new-privileges; running user, mount, network and PID namespaces differed from the guest administrator | Sampled observations and lifecycle events; not a proof of all kernel behavior or historical process state |
| Credential renewal and persistence | The actual access-token field changed in place, the source object identity remained unchanged, the task succeeded and the enrollment remained unretired | Accepted natural renewal is inferred under the trusted-owner assumptions below; no direct upstream refresh-exchange receipt or rotation count |
| Real-token observations | Six distinct before/current/after provider-token values were compared across 333 file, process-field and metadata observations and 3,272,194 bytes; no exact matches | Finite passive observations; does not cover every raw protocol or tool stream |
| Cleanup | The three gateway services stopped, container inventory was empty, and durable runtime intent, workspace-lock, credential-occupancy and staged-terminal obligations were idle | The named task and deployment; earlier failure cases have their own evidence |
| Laboratory closure | The owned VM shut down normally; its absence and preservation of pre-existing laboratory metadata were independently checked | This closes the laboratory campaign; it does not create or approve a production deployment |

The real-token witness obtained one complete snapshot containing the actual
native Codex process. It checked bounded writable temporary files, process
environment and arguments, executable/file-descriptor link metadata, and
post-stop workspace, temporary client, service-state, campaign-receipt and
service-journal surfaces. Retained live bytes were checked again against the
final token set; the final token generation had a complete live sample.
Credential bytes and credential digests were not included in the receipts.

The witness did **not** read active protocol or file-descriptor streams, or scan
every raw tool argument, tool response or discarded diagnostic. File-descriptor
links were metadata observations, not reads of their active contents. Exact
token matching is not a proof against every encoding, transformation or timing
of disclosure. The reusable tokens examined were model-provider credentials;
the platform credential has its separate Connector trust boundary.

## Renewal inference and trust assumptions

The gateway's trusted authentication Owner was the only permitted writer of the
provider source during the observation interval. A changed access-token field,
unchanged physical source identity, successful canonical task and healthy
enrollment support accepted natural renewal and persisted authentication under
that assumption. A timestamp or formatting change alone would not pass.

This interpretation also depends on the unchanged
[native acceptance and commit path](../internal/codexprovider/owner_native_linux_amd64.go)
and [refresh validation](../internal/codexprovider/owner_refresh_linux.go): accepted
native state must satisfy the refresh contract before the Owner persists it.
It is a qualified inference from behavior and the trusted implementation,
rather than a packet trace of the provider's authentication exchange. The local
administrator, trusted Owner, pinned native software and kernel remain trusted.

## Exact artifacts and reuse of mechanism evidence

The tested source baseline was
[`a6b2736`](https://github.com/shwdsun/harness-security-gateway/commit/a6b27365478058de7464796b8ef2a895887b3151).
The selected cached artifacts matched the fresh VM's seed and dated installed
artifact receipt. The production Core and Owner compiled project-source
closures and the Runner's 52 project/module inputs matched that baseline.
The Connector was the October 8 rebuild containing the reviewed delivery and
response-boundary corrections. This was not a newly reproduced build or a
post-task hash scan of every installed file.

| Artifact | SHA-256 |
| --- | --- |
| Gateway service (`agentd`) | `704a63ddc2d638f024de1d57b32963c724b7f76053df43cdcfd8f6dd1843a550` |
| Execution service (`sandboxd-codex`) | `a3eff7fe6e8549d3a59892352c20e791e9a07489255ab7ae314d3f28feca5707` |
| Native Runner | `e5f7515ab1af05e84be714c9fe656c14354d8dfd82afde321e60a00664ef182e` |
| Discord Connector | `7c4f7b11a92f87971a3bf3e38641b5806c503b51f561aa6337d517bd662d05ae` |

The separate **October 6** native cases retain their original, bounded scopes:
inference authentication rejection and renewal, catalog rejection, cancellation
during recovery, helper loss, and Owner crash/restart on the same database.
The [profile record](codex-profile-v4.md#remaining-acceptance) preserves those
results and failures. Current production Owner sources matched their recorded
production-source closure, and twelve shared native/client-package artifacts
matched the new deployment. The composed test Owners were case-specific test
executables, not the production Owner used for the real task.

Those source/artifact checks support reuse of unchanged substitution,
poison-response, Runner-protocol sanitization and failure-path mechanisms;
they do not turn synthetic cases into real-provider observations or make an
old whole-tree snapshot current. The October 19 task supplies its own real
compatibility, reply, renewal-inference, containment and cleanup evidence.

Earlier authentication, provisioning and observer failures were preserved.
A demonstrated missing volatile-directory boot recipe was repaired using the
documented ownership and permission layout; no security boundary was widened.
The failed enrollment was resolved through exact diagnostics and absence of
all stores and sidecars before another enrollment attempt. No uncertain task
was replayed. Detailed receipts remain private because they contain deployment
identifiers; this page publishes the result and its limits, not raw transcripts,
credentials or host configuration.
