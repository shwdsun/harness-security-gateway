# Offline Codex development bundle

This recipe prepares the existing measured fixed-target template for review.
It compiles the service binaries and assembles pinned, non-secret native inputs
without Docker, network acquisition, credentials, enrollment or service startup.
It is not a production image, installer or authorization to activate a target.
The native tuple retains the scoped September 10–11, 2026 evidence; rebuilding
the host owner changes its hash and requires a new exact deployment authority.

## Assemble from already verified inputs

Use Linux/amd64, Python 3.11+ and the exact Go version in `inputs.lock.json`.
Provision the Go module cache separately from `go.mod`/`go.sum`. The recipe
verifies that cache and sets `GOPROXY=off`, `GOSUMDB=off`, `GOTOOLCHAIN=local`,
`GOWORK=off`, `GOENV=off`, `CGO_ENABLED=0` and fixed build flags. The builder
must be a trusted non-root user; its tools/cache/source must remain stable.
These application settings do not themselves provide network containment.

Two explicit input directories are required:

| Input | Exact contents |
| --- | --- |
| `--native-artifacts` | `uid-setup`, `credential-bootstrap`, `codex-provider-runner`, `startup-canary`, `seccomp.json` |
| `--tool-package` | The six files and parent directories listed under `tool_package` in `inputs.lock.json` |

The lock records exact sizes/hashes for the measured development artifacts.
The UID helper originated in `internal/codexadapter/testdata/uid-setup`, the
bootstrap in `cmd/credential-bootstrap`, and the Runner in
`cmd/codex-provider-canary-runner`. The retained startup helper and seccomp
artifact also belong to that measured fixture. This recipe deliberately reuses
those exact bytes; it does not rebuild/promote fixture helpers, acquire a new
native distribution, authenticate upstream provenance or reapprove their image.
Missing inputs require a separate acquisition/rebuild decision, not replacing
the lock with whichever binary happens to be installed in a personal home.

Extra entries, symlinks, hardlinks, special files, unsafe ownership/write modes
and hash/size mismatches are rejected. Only the eleven named input files are
copied. Never point these options at a credential directory or a harness home.
The output must be a new directory outside source and input trees. Build caches
and temporary files are the only other writes; failure retains partial work.

```sh
export GOMODCACHE=/absolute/offline-go-modules
export GOCACHE=/absolute/private-go-cache
export GOTMPDIR=/absolute/private-build-temp
python3 deploy/codex/build.py \
  --go /absolute/go1.26.7/bin/go \
  --native-artifacts /absolute/verified-native-artifacts \
  --tool-package /absolute/verified-six-file-package \
  --output /absolute/new-bundle-directory
```

Success emits `BUNDLE.SHA256` last. `bundle.tar` contains four static service
binaries, the pinned native/package files, review-only templates, this guide,
license, `manifest.json` and `SHA256SUMS`. The manifest binds the build source
files, Go executable, fixed image/profile and payload hashes. It contains no
host paths, account state or build timestamps. The archive has normalized
metadata; identical source, toolchain and native inputs should produce identical
bytes even in another source/output directory. Compare two independent builds
and retain both receipts before calling a particular assembly reproducible.
This is repeatable assembly, not a reproducible source build of the external
native distribution. Hashes detect differences; they do not authenticate origin.

From the output directory, `sha256sum -c BUNDLE.SHA256` verifies the archive;
from `payload`, `sha256sum -c SHA256SUMS` verifies its files. The archive's UID 0
metadata is normalization, not the intended ownership of an installed tree.
Do not extract it over a live installation.

## Separate identities and storage

The templates use explicit example IDs, not reserved or automatically allocated
identities. Check host collisions, group membership and ancestor access first.
If IDs change, update the templates, both peer UID fields and the direct runtime
endpoint together. Keep the container's internal UID 1000 mapping unchanged.

| Service | Example UID | Extra IPC groups | Private storage |
| --- | --- | --- | --- |
| agentd | 21001 | `hgw-local-ipc` (21101), `hgw-sandbox-ipc` (21102) | `/var/lib/hgw-agentd`, Core DB |
| sandboxd | 21002 | `hgw-sandbox-ipc` (21102) | `/var/lib/hgw-sandboxd`, sandbox DB, workspace, provider and credential state |
| local test Connector | 21003 | `hgw-local-ipc` (21101) | `/var/lib/hgw-connector-local` |

`/run/hgw/local` belongs to agentd and `hgw-local-ipc`; `/run/hgw/sandbox`
belongs to sandboxd and `hgw-sandbox-ipc`. Each directory is exactly setgid
`02710`. The owner can create/remove its socket; the peer can traverse to the
known socket but cannot list or replace entries. Socket mode is `0660` and its
GID inherits from the parent. The server still checks the exact configured
`SO_PEERCRED` UID before reading application bytes. An unrelated member of the
IPC group does not acquire protocol authority.

For a distinct peer UID, daemon preparation now requires this pre-existing
layout. It rejects symlinks, wrong owner/mode and ancestors replaceable by other
users. It never creates/chmods a shared directory. Ancestors must be root- or
listener-owned and deny group/other writes, apart from sticky directories such
as `/tmp` for isolated fixtures. The operator must separately prove
the peer can traverse every ancestor and has the expected group. These are
startup observations under trusted provisioning, not a defense against a host
administrator concurrently replacing paths. Same-UID development retains
private `0700` parents and `0600` sockets; private data dirs are unchanged.

Install service binaries into an operator-owned, service-non-writable
`/opt/hgw/codex-dev/bin`. Keep `/etc/hgw` operator-owned and non-writable by
services; use separate `0640 root:hgw-agentd` and `0640 root:hgw-sandboxd` config
files. The native inputs/package belong under sandboxd's private artifact root,
owned by sandboxd, with executable files `0555`, data `0444`, and directories
not writable by group/others. The current rootless UID mapping needs this host
ownership for its bound native package; making those files host-root-owned can
map them to an unmapped container UID and fail its startup guard. The runtime
binds them read-only. This remains the measured development ownership model.

Rootless Docker must independently exist under the sandboxd identity at
`/run/user/21002/docker.sock`, with its attested direct endpoint, native-ext4
credential storage and exact preloaded image. The service template neither
creates that runtime nor pulls/loads an image. Do not emulate its runtime
directory or add the Connector/Core to a Docker group. No host sysctl,
AppArmor, bubblewrap policy, network or daemon setting is changed by assembly.

The `.sysusers`, `.tmpfiles` and `.service` files are review-only. Applying
sysusers/tmpfiles can create accounts or change existing directory ownership;
starting a service can reconcile durable state and enable repeated Runs from
its Binding. None is applied by the recipe. There is no Connector autostart,
`[Install]` target, automatic restart, login or enrollment hook. The local fake
Connector is a test boundary; no Discord implementation is implied. Service
units express identity/ownership and shutdown, not a complete host-hardening
profile. Force-killing a service is not proof that Docker descendants stopped;
retain its recovery obligations and verify exact runtime cleanup.

## Host foundation and runtime ownership

Keep the initial host preparation credential-free and inactive. Record the
actual NSS name/UID/GID collision checks, destination absence, parent ownership,
filesystem type and existing runtime before applying the example identities.
Use the native `systemd-sysusers` and `systemd-tmpfiles` tools with the exact
reviewed files. Both can change host state; tmpfiles can also change existing
ownership/modes. Recheck the frozen preconditions and stop on drift rather than
repairing a live tree. A one-shot tmpfiles invocation does not install a boot
policy; persist that policy only as part of the later activation plan.

The sandbox account also needs its own non-overlapping subordinate UID and GID
ranges, each at least 65,536 IDs. Check existing assignments and ordinary IDs;
do not copy another account's range. This is separate from the container's
fixed internal UID and from the two IPC groups. The requirements are described
in [Docker's rootless setup](https://docs.docker.com/engine/security/rootless/).

Manage rootless Docker as the sandbox account's **user** service. Docker does
not support running its rootless daemon as a system-wide service with `User=`;
this restriction does not concern the separate HSG service templates. See the
[Docker service guidance](https://docs.docker.com/engine/security/rootless/tips/).
The packaged setup helper's `install` embeds the caller's ambient `PATH` in the
generated unit, starts and enables the daemon, and creates and selects a
`rootless` CLI context; `--force` also suppresses a failed RootlessKit check.
It is therefore not a prerequisite check. The review-only
`hgw-sandboxd-docker.service` is the equivalent unit with a fixed `PATH` and a
separate data root, `/var/lib/hgw-sandboxd/docker`, outside every sandboxd
storage and control path. Install it as that account's
`~/.config/systemd/user/docker.service`; sandboxd uses the direct socket, never
a CLI context. Keep the existing developer runtime, unit and storage separate.
Do not use `--force` or relax host policy to turn a failed runtime prerequisite
into a pass.

## Install artifacts and the sandbox runtime

Record these as separate effects, in order; each depends on the previous one.
None enrolls a credential, opens a database or starts an HSG service.

1. **Artifacts.** Verify `BUNDLE.SHA256`, then the archive's `SHA256SUMS` and
   manifest. Create each destination once, never over an existing name. Service
   binaries go to `/opt/hgw/codex-dev/bin` as `root:root 0555`. Native files and
   the six-file package go to `/var/lib/hgw-sandboxd/artifacts/{native,codex-package}`,
   owned by the sandbox UID with the manifest's `0555`/`0444` modes and `0555`
   directories. Configs are `/etc/hgw/sandboxd.json` (`0640 root:hgw-sandboxd`)
   and `/etc/hgw/agentd.json` (`0640 root:hgw-agentd`); their artifact and owner
   hashes must equal the installed bytes.
2. **Actual-identity checks.** As UID 21002 with an empty environment, notably
   without `SSL_CERT_FILE`/`SSL_CERT_DIR`, `sandboxd-codex -check` needs the
   workspace, credential-slot and `0700` provider directories to exist under
   that UID, but no auth file, runtime socket or database. As UID 21001,
   `hgwctl session scope` must reproduce the sandbox configuration's scope.
3. **Runtime.** Lingering starts the account's user manager now and at boot,
   including the host's globally enabled user sockets and timers. Enabling
   `docker.service` for boot autostart is a separate decision; start it without
   enabling until activation is approved. Accept exactly one `name=rootless`
   option, cgroup v2 with the systemd driver, the fixed data root, delegated
   `cpu`/`memory`/`pids` controllers, a socket owned by the sandbox UID and an
   empty inventory.
4. **Image.** Import the exact digest offline, for example `docker save` from an
   existing store into `docker load` under the sandbox UID, or separately
   approve a registry pull by digest; never retag. Accept the exact image ID and
   repository digest. One unlabeled `--pull=never --network none` container must
   show the target's memory/CPU/PID limits and the container-root mapping to the
   sandbox UID, and must be removed.

Native-ext4 source proof is captured later by explicit enrollment under the
actual identity and storage. Cold source/database transition, a new generation,
a bounded Run and service activation remain the separate steps below.

When reusing an already enrolled source, the example `personal-codex` slot and
generation 1 are not a migration recipe. Preserve the source's existing logical
slot and full database lineage. A copied auth file is a different physical
source, even if its token bytes match. A new empty database cannot demonstrate
retirement or preserve previous source ownership. Review the old owner shutdown,
remaining deliveries, cold file/database transition, explicit higher generation
and new TargetRevision before enrollment. Neither UID changes nor restoration
of an old backup may silently revive retired authority. See the
[source contract](../../docs/credential-source-enrollment.md) and
[startup/enrollment guide](../../docs/codex-daemon-startup.md).

## Prepare an exact activation separately

1. Review the staged hashes, example IDs, filesystem/identity effects and
   existing state. Provisioning/activation needs an explicit local operation;
   an offline bundle grants none.
2. Use the [native identity witness](../../internal/localhttp/testdata/identity-witness/README.md)
   for distinct synthetic OS identities and empty non-provider state: intended
   peer succeeds, wrong UID is byte-silent, the peer cannot replace the socket,
   and Core/Connector cannot read sandbox storage. It passed in an offline
   rootless container on September 11, 2026. Repeat relevant identity/path checks
   for the actual deployment; no real credential or paid Run is needed for IPC.
3. Populate private copies of the JSON examples with the exact artifact and
   owner hashes, intended TargetRevision and compiled `hgwctl session scope`.
   They intentionally contain zero-hash/scope placeholders; assembly does not
   silently bind an operator or choose a credential generation.
4. Run `sandboxd-codex -config ... -check` as the intended sandboxd identity.
   It checks configuration/artifacts without auth contents, DB, Docker/provider
   access, enrollment or socket preparation. A pass does not prove peer access,
   enrollment, image availability or service readiness.
5. Preserve the previous configuration, binaries, DB objects, source lineage and
   cleanup history. Changing UID, paths, binary or scope changes authority and
   can invalidate credential proof. Review the exact transition and retirement
   before new enrollment; do not copy/reset a DB or move/chown a live auth file
   to make this template pass. Stop/reconcile the old owner before handover.
6. Only after that review, approve the concrete installation/enrollment and
   activation. Retain rollback inputs; rollback never silently rewinds a
   retirement or adopts an unknown runtime. Production image provenance,
   adversarial/native acceptance and private Discord remain separate open gates.

The local directory tests establish permission rejection and inherited socket
GID using one OS user. The native witness adds actual cross-UID reachability and
file isolation within its recorded container. Host provisioning and service
activation still need separate evidence. Unchanged lifecycle/formal/native
evidence keeps its original dates and assumptions; do not rerun every protocol
test or a real provider Run for an unchanged input merely to populate a new log.
