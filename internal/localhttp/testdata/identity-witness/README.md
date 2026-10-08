# Native service identity witness

This opt-in Linux fixture checks the deployment boundary that same-user unit
tests cannot establish. It runs the production `localhttp` listener/client and
`privatefs` guard under distinct kernel UIDs, using only synthetic data. It does
not start agentd, sandboxd, a provider, or a Run. No service binary includes it.

The fixture has fixed roles and paths; it accepts no user-supplied UID, command,
mount, socket or credential option. Ordinary `go test ./...` skips `testdata`.
Run it when changing peer authentication or the service identity/permission
layout. Changes to message content do not require rerunning this witness unless
they also change these trust boundaries.

| Role | UID and primary GID | Supplementary IPC groups |
| --- | --- | --- |
| Core | 21001 | 21101, 21102 |
| Sandbox | 21002 | 21102 |
| Local Connector | 21003 | 21101 |
| Outsider | 21004 | 21101, 21102 |

These match the service examples in [`deploy/codex`](../../../../deploy/codex/README.md).
The outsider deliberately has both IPC groups. Membership allows reaching the
socket; authentication still requires the exact UID. The process checks all
real/effective/saved/filesystem UIDs and GIDs, supplementary groups, zero
effective/permitted/inheritable/ambient capabilities, and `NoNewPrivs=1`.

The acceptance matrix is deliberately small:

- Connector → Core and Core → Sandbox each complete one JSON request over the
  production Unix transport. Each listener sees exactly one HTTP handler call.
- Connector → Sandbox and Sandbox → Core fail at filesystem access with EACCES.
- The outsider successfully dials each socket but receives zero bytes and a
  connection close/reset. A timeout does not pass. Existing localhttp unit tests
  separately check that authentication precedes connection Read/Write.
- Intended peers and the outsider cannot list the socket parent, create an
  entry, rename or unlink the socket. Socket owner/group/mode and inodes remain
  unchanged until their listeners remove them at shutdown.
- Each service reads its own private marker and root-owned operator config.
  It cannot write, chmod, rename or unlink its config. Other roles cannot read
  or write private markers, create private entries, or read foreign configs.

## Prepare and execute

Build offline with the repository's cached toolchain/modules. Use a fresh,
owner-only absolute output directory outside the public source tree:

```sh
CGO_ENABLED=0 GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local \
  go build -mod=readonly -trimpath -buildvcs=false \
  -o "$WITNESS_DIR/identity-witness" ./internal/localhttp/testdata/identity-witness
chmod 0555 "$WITNESS_DIR/identity-witness"
```

Before an authorized execution, record the source/binary SHA-256, direct
rootless runtime endpoint, already-cached image digest, exact operation below,
unique test name/labels and cleanup ownership. Check that the image declares
no volumes. Hold the existing HSG runtime-owner process lock and confirm no
managed product containers or conflicting owner. Do not pull an image, mount
credentials/source/runtime sockets, or change host accounts or security policy
to make the fixture pass. A missing environment prerequisite is not a pass.

Use one ephemeral container with the following create specification. Variables
are local operator inputs frozen in the execution record, never message fields.
The command creates a stopped container; independently inspect its exact ID,
labels, mount, capabilities and network settings before starting it.

```sh
docker --host "$WITNESS_ENDPOINT" create --pull=never \
  --name "$WITNESS_NAME" --label "io.harness-gateway.identity-witness=$WITNESS_NONCE" \
  --network=none --read-only --ipc=private --user=0:0 \
  --cap-drop=ALL --cap-add=CHOWN --cap-add=FOWNER --cap-add=KILL \
  --cap-add=SETUID --cap-add=SETGID --group-add=21101 --group-add=21102 \
  --security-opt=no-new-privileges --pids-limit=64 --memory=268435456 --cpus=1 \
  --tmpfs=/fixture:rw,nosuid,nodev,noexec,size=16m,mode=0755 \
  --mount="type=bind,source=$WITNESS_DIR/identity-witness,target=/identity-witness,readonly,bind-propagation=rprivate" \
  --entrypoint=/identity-witness --workdir=/fixture --hostname=identity-fixture \
  --log-driver=none --env HSG_IDENTITY_WITNESS=1 --env HOME=/nonexistent \
  --env PATH=/usr/bin:/bin --env LANG=C.UTF-8 --env GOMAXPROCS=2 \
  "$WITNESS_IMAGE_DIGEST" controller
```

PID 1 checks its fixed capability set, read-only root/binary mounts, empty
nosuid/nodev/noexec tmpfs and loopback-only network before creating files.
Its five capabilities provision synthetic ownership and launch/terminate fixed
child identities; they include no DAC_OVERRIDE or SYS_ADMIN. Supplementary
IPC groups avoid needing FSETID to set the shared directories' setgid bits.
These are test bootstrap permissions, not service capabilities. See
[Linux capabilities](https://man7.org/linux/man-pages/man7/capabilities.7.html)
for the ownership, group and process-signalling rules.

Attach to the exact verified ID with a bounded external supervisor (90 seconds
is sufficient; child execution has a 45-second bound). Require exit code 0 and
one complete `hsg-identity-witness/v1` JSON report with `passed: true`. Validate
all eight child receipts and the full matrix above. Inspect exited state/PID 0,
remove only that verified container, then independently verify exact absence
and unchanged managed product inventory before releasing the process lock.
An uncertain create must be reconciled by the frozen name/labels/specification;
never blindly retry it. Preserve failure output and cleanup evidence.

## Evidence limits

Numeric IDs here are kernel identities inside one rootless user namespace.
This checks Linux DAC and the production peer-UID listener in that environment.
It does not provision host service accounts or prove systemd placement, direct
runtime access under a new owner, credential migration/enrollment, full daemon
integration, Discord readiness or production acceptance. Those need their own
concrete deployment plan. The original ordinary suite, race checks and previous
native/provider evidence retain their dated, narrower scope.
