# Deployment and artifact lifecycle

This document explains what can be run from this repository today, where each
component is intended to live, and when external artifacts may be acquired. It
is a deployment contract and roadmap, not a claim that a production
Discord-to-Codex release exists.

The authoritative implementation status remains
[implementation-status.md](implementation-status.md). Trust boundaries and
protocol behavior remain authoritative in [architecture.md](architecture.md),
[connector-protocol.md](connector-protocol.md), and
[runner-protocol.md](runner-protocol.md).

## Supported paths today

| Path | Components | Credentials or network | Claim |
| --- | --- | --- | --- |
| Offline witness | production decoders, policy, service, and Core store with synthetic input | none required | five narrow deterministic security properties |
| Local mock runbook | fake Connector, `agentd`, `sandboxd`, rootless Docker, and one mock Runner container per Run | no platform/model credential; a controlled registry may be needed before execution | protocol, persistence, and local runtime integration under the runbook's stated limits |
| Real Discord to Codex | not shipped | would require both platform and provider credentials | no public deployment or security claim |

Use `make demo-security` for the first path. Use the
[local mock runbook](runbook.md) for the second. The runbook is deliberately
manual: its checks are part of the experiment and must not be hidden by an
installer.

A private experimental vertical slice may prove that a Discord message can
reach an installed Codex CLI. Such connectivity evidence does not turn the
public mock implementation into a deployable target and does not establish the
service-identity, container, credential, egress, or teardown boundaries listed
as open gates.

## Intended topology

```text
messaging platform
       |
       v
long-running Connector       platform credential only
       |
       | dedicated Unix socket
       v
long-running agentd          Core database and exact Bindings
       |
       | dedicated Unix socket
       v
long-running sandboxd        target/workspace state + one exact rootless socket
       |
       | fixed create request; --pull=never; HRP/1 over pipes
       v
ephemeral Runner container   one Run + one workspace + bounded harness authority
       |
       +-- thin HRP adapter -> pinned Codex/Claude/other harness
       |
       +-- future reviewed provider path
             -> narrow auth/egress proxy -> model provider
```

Containerization is a packaging choice around a trust boundary, not the trust
boundary itself. The following placement rules are normative:

- One Connector instance owns one platform account/token. It is long-running
  and may be a container or a dedicated host service, but it receives neither
  a workspace, model credential, Core database, nor runtime socket.
- `agentd` is a long-running service and the only online Core database owner.
  It receives neither platform/model credentials, workspaces, nor a container
  runtime socket.
- `sandboxd` is a long-running service next to the operator-selected rootless
  runtime. It alone receives the exact local runtime socket. Putting it inside
  a container that receives that socket does not reduce the socket's authority
  and is not an isolation claim.
- A Runner is disposable and belongs to exactly one Run. It receives no
  platform credential, Core database, other target, or runtime socket. The
  current runtime starts it with a digest reference, fixed entrypoint and
  arguments, `--pull=never`, no network, a read-only root filesystem, dropped
  capabilities, and bounded mounts/resources. A future networked target
  requires new runtime support plus a different reviewed profile and
  TargetRevision; configuration alone cannot enable it.
- A future auth/egress proxy, if used, owns the provider credential and permits
  only the target's reviewed model operation. Merely allowing a hostname is not
  credential mediation.

Production placement requires distinct service identities and private path and
socket permissions. Running every process under one UID, using a broad shared
group, exposing a rootful/remote/proxied Docker endpoint, or mounting the host's
live checkout is outside the intended deployment boundary.

## Harness and Connector packaging

Harness-specific behavior belongs in the Runner artifact:

```text
runner-codex  = thin HRP adapter + pinned Codex executable + fixed profile
runner-claude = thin HRP adapter + pinned Claude executable + fixed profile
```

The image and immutable TargetManifest select this combination. Adding a
harness therefore adds a reviewed Runner artifact and target revision, not a
vendor branch in `agentd` and not a message-selectable plugin.

Platform-specific behavior belongs in a Connector artifact. A Discord
Connector image or binary contains the reviewed Connector implementation and
its pinned libraries, but not its bot token or an execution target. Adding a
platform implements the same closed Connector protocol; it does not change the
Runner or grant platform input more authority.

Fixed instructions that adapt a harness's behavior to private messaging are
part of the Runner/target profile. Their exact bytes and native harness mapping
must be content-bound by the profile fingerprint and adapter identity. They are
not a prompt assembled by the Connector; changing them requires a new adapter
identity, image digest, and immutable target revision.

## Intended configuration ownership

Configuration follows the component whose authority it describes:

| Owner | Operator-provisioned configuration or state | Excluded |
| --- | --- | --- |
| Connector | one platform account, stable platform scope, cursor/spool, and platform credential in Connector-private storage | target, workspace, model credential, runtime options |
| `agentd` | exact Binding and policy revision; Core database of events, Runs, outbox, and opaque session refs | platform/model credentials, target implementation, workspace paths exposed to messages |
| `sandboxd` | immutable target manifests, resolved policy/profile refs, workspace roots/locks, private vendor sessions, and exact runtime endpoint | platform credential and Core database |
| Runner artifact/profile | fixed adapter, harness executable, native instruction mapping, entrypoint, and content-bound behavior | deployment secrets and message-selected configuration |
| Auth boundary | provider credential slot/generation and narrowly mediated provider access, once a reviewed profile exists | Connector, Core, workspace, and image layers |

The Connector therefore does not specialize or configure a sandbox. It sends
authenticated platform facts through the closed protocol. `agentd` resolves
the already configured exact Binding, and `sandboxd` resolves the immutable
target. Any operator UI or future provisioning tool may edit these owned
configuration sources offline, but it must not collapse them into one shared
option map or permit a message to supply their values.

## Artifact-acquisition boundary

There are two deliberately separate phases.

### Build and provision

Only a trusted operator or controlled build system may:

1. fetch version-pinned source, base images, language modules, Connector
   libraries, or harness distributions;
2. build and test a fixed Connector or Runner artifact;
3. inspect and record the resulting image repository digest and relevant build
   evidence;
4. publish to or preload from an operator-controlled registry/cache; and
5. configure a new immutable TargetRevision that names the exact locally
   available digest and closed policy/profile references.

Networked acquisition is permitted in this phase only as an explicit operator
action. An offline, verified cache is preferable where practical. A version
pin or lock file alone is not provenance; production release work still needs
a documented source/trust policy, build receipt, vulnerability response, and
repeatable verification appropriate to each artifact.

Secrets are not build inputs. Platform tokens, provider login state, and local
credential-slot bindings are provisioned separately into their documented
trust domains and must not appear in image layers, source control, build logs,
or public configuration.

### Run

At message/Run time, HSG must not:

- build or pull an image;
- run a package manager or self-update a harness;
- download a Connector/Runner library, skill, plugin, MCP server, or config;
- accept an image, version, path, command, environment, mount, credential, or
  network option from a message; or
- silently replace a missing digest with a tag or newer artifact.

The selected digest must already exist in the attested rootless image store;
otherwise the Run fails closed. Provider requests made by a future, already
admitted and explicitly network-enabled target are runtime execution, not
artifact acquisition, and remain subject to that target's credential and
egress policy.

The current mock image is stricter: `make mock-image` invokes the build with
network disabled, and the final image is `scratch` plus the compiled mock
binary. A future real Connector or Codex Runner may need controlled acquisition
during its build, but never on receipt of a message.

## Lifecycle and change control

The intended release flow is:

```text
review inputs/profile
  -> build and test artifact
  -> record/preload exact digest
  -> configure immutable revision and exact Binding
  -> start long-running services
  -> admit durable Run
  -> create one preloaded Runner with --pull=never
  -> stream HRP/1
  -> prove stop/removal and reconcile durable state
```

Updating a Connector, adapter, harness executable, fixed instruction profile,
skill bundle, credential binding, egress profile, base image, or runtime policy
is a deployment change. Where it changes target semantics or authority, it
requires a newly reviewed artifact/profile and TargetRevision; it is never an
in-place command issued by chat.

The MVP does not ship dynamic skills or plugins. A future fixed skill bundle
may be built into or otherwise content-bound by a TargetRevision. A message can
invoke only authority that the operator preauthorized; it cannot install or
select such a bundle.

## Why there is no turnkey deployment yet

A Compose file or one-shot install script would currently imply decisions that
the repository has not proved: production UID/group ownership, secret
provisioning, registry trust, a real Codex image, provider authentication,
provider-versus-tool egress, cancellation, descendant cleanup, and a durable
Discord cursor/spool. Hiding those choices would make the prototype easier to
start but harder to assess safely.

The next legitimate deployment increment is narrow: satisfy the documented
Codex target gates, exercise fake ingress against that real target, and only
then add the private Discord Connector. A turnkey installer becomes appropriate
after that exact path has repeatable provisioning, rollback, and adversarial
evidence. Until then, use only the two supported paths above and preserve each
manual precondition as observable evidence.
