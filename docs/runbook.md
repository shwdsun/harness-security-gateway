# Local mock runbook

This runbook exercises the implemented mock vertical slice on the prepared
host. Run it as the unprivileged user that owns the configured rootless Docker
daemon. Do not use `sudo`, a rootful Docker context, a real checkout, or any
platform/model credential.

This is an advanced local runbook, not the zero-setup demo. It requires Go,
`jq`, a directly owned rootless Docker daemon, and an image workflow that
produces a nonempty repository digest. The prepared BuildKit path may record a
local `RepoDigest`; another engine may require an operator-controlled registry.
Use `make demo-security` for the credential-free, Docker-free witness.

The example configuration documents target `project-mock` and session mode
`opaque_resume`. Its `project-mock-unset` revision and all-zero image digest are
deliberate placeholders; the commands below derive a local immutable revision
from the image actually built.

## 1. Build and verify the host boundary

From the repository root:

```bash
make build
make test
make vet

docker context show
docker context inspect "$(docker context show)" \
  --format '{{.Endpoints.docker.Host}}'
docker info --format '{{json .SecurityOptions}}'

HG_EXPECTED_DOCKER_ENDPOINT="unix:///run/user/$(id -u)/docker.sock"
test "$(docker context inspect "$(docker context show)" \
  --format '{{.Endpoints.docker.Host}}')" = "$HG_EXPECTED_DOCKER_ENDPOINT"
```

The selected endpoint must be exactly the current user's local socket shown
above, and the security options must contain exactly one `name=rootless`. Stop
if either check differs. V1 rejects rootful, proxy, forwarded, remote, and
alternate Unix endpoints; `sandboxd` does not inherit the ambient context.

Build the deterministic mock adapter into that rootless image store:

```bash
HG_MOCK_REPOSITORY="${HG_MOCK_REPOSITORY:-harness-gateway/mock-runner}"
HG_MOCK_IMAGE="${HG_MOCK_REPOSITORY}:dev"
make mock-image MOCK_IMAGE="$HG_MOCK_IMAGE"
```

If the reported `RepoDigests` array is empty, stop. Push the tag through an
operator-controlled registry and pull the resulting digest into this same
rootless image store before continuing. Registry bootstrap and trust policy are
deployment choices and are intentionally not hidden inside this runbook.

The target manifest accepts only a repository digest. Inspect the image and
create local daemon configs using the exact locally recorded `RepoDigest`:

```bash
set -euo pipefail

HG_EXPECTED_DOCKER_ENDPOINT="unix:///run/user/$(id -u)/docker.sock"
HG_LOCAL_UID="$(id -u)"
HG_MOCK_REPOSITORY="${HG_MOCK_REPOSITORY:-harness-gateway/mock-runner}"
HG_MOCK_IMAGE="${HG_MOCK_REPOSITORY}:dev"
HG_MOCK_REPO_DIGEST="$(
  docker image inspect "$HG_MOCK_IMAGE" \
    --format '{{json .RepoDigests}}' |
  jq -r --arg repository "$HG_MOCK_REPOSITORY" \
    'first(.[] | select(startswith($repository + "@sha256:"))) // empty'
)"
test -n "$HG_MOCK_REPO_DIGEST"
HG_MOCK_DIGEST_HEX="${HG_MOCK_REPO_DIGEST##*@sha256:}"
test "${#HG_MOCK_DIGEST_HEX}" -eq 64
HG_LOCAL_REVISION="project-mock-${HG_MOCK_DIGEST_HEX}"
HG_LOCAL_STATE_REF="${HG_LOCAL_REVISION}-state"
printf '%s\n' "$HG_MOCK_REPO_DIGEST"

jq --argjson uid "$HG_LOCAL_UID" \
  --arg revision "$HG_LOCAL_REVISION" \
  '.connectors[].peer_uid = $uid |
   .bindings[].target.revision = $revision' \
  config/agentd.example.json > config/agentd.local.json
jq --arg image "$HG_MOCK_REPO_DIGEST" \
  --arg endpoint "$HG_EXPECTED_DOCKER_ENDPOINT" \
  --argjson uid "$HG_LOCAL_UID" \
  --arg revision "$HG_LOCAL_REVISION" \
  --arg state "$HG_LOCAL_STATE_REF" \
  '.peer_uid = $uid |
   .runtime.endpoint = $endpoint |
   .runner_states[0].ref = $state |
   .runner_states[0].directory = $state |
   .targets[0].revision = $revision |
   .targets[0].runner.image = $image |
   .targets[0].state_ref = $state' \
  config/sandboxd.example.json > config/sandboxd.local.json
chmod 0644 config/agentd.local.json config/sandboxd.local.json
```

Target revisions are immutable. If rebuilding the image changes the digest and
the sandbox database already pins the generated revision, do not keep that
revision while replacing its digest. Re-run the derivation above so the exact
`agentd` Binding, target revision, and runner-state ref/directory move together.
For a first schema-v6 registration, do not pre-create that target's state
directory: sandboxd observes the exact path absent, atomically commits its
historical owner, and only then creates the private leaf. Exact restart uses
the durable owner idempotently. Reusing an old ref or directory fails even when
the old Target is absent from current config or the directory was emptied and
recreated.

A target-bearing schema-v1–v5 sandbox database intentionally refuses automatic
v6 migration because its historical state path cannot be reconstructed. Do not
delete the database, rename/delete state directories, or edit SQLite to make
startup pass. Use a reviewed cold migration or a new disposable lineage; no
general offline migration command is implemented yet. The generated values are
suitable only when they still match a schema-v6 owner or when starting a
genuinely new disposable database and absent state path.

The value in `targets[0].runner.image` must exactly match an entry from the
local image's `.RepoDigests`. The all-zero example digest is never a runnable
value. A Docker image ID from `.Id`, a tag such as `:dev`, or a guessed digest
is not a substitute. If `.RepoDigests` is empty, load or pull the image through
a trusted image workflow that records a repository digest, then repeat this
step.

The config files must remain regular, non-symlink files that are not writable
by group or others. All relative paths inside them resolve from the `config/`
directory, not from the daemon's working directory.

This runbook deliberately sets both peer UIDs to the current OS user.
The credential check remains active and the sockets remain `0600`, but this is
not evidence of cross-identity isolation.

## 2. Start the three processes

In terminal 1, from the repository root:

```bash
./bin/sandboxd -config config/sandboxd.local.json
```

V1 allows only one `sandboxd` under the current OS user. The daemon holds
`/run/user/$(id -u)/harness-gateway-sandboxd.lock`, regardless of its config or
database path; a second instance must fail closed. The regular `0600` lock file
is persistent and must not be deleted while diagnosing or running the daemon.

Wait until the socket exists:

```bash
test -S runtime/sandboxd.sock
```

In terminal 2:

```bash
./bin/agentd -config config/agentd.local.json
```

Wait until the dedicated fake-connector socket exists:

```bash
test -S runtime/connectors/fake-personal/agentd.sock
```

In terminal 3, submit one allowed text event and wait for its durable reply:

```bash
HG_FAKE_CONNECTOR_SOCKET="$(pwd -P)/runtime/connectors/fake-personal/agentd.sock"
./bin/fake-connector \
  -socket "$HG_FAKE_CONNECTOR_SOCKET" \
  -text 'hello from the local runbook' \
  -wait 90s
```

The Connector HTTP client deliberately requires an absolute Unix-socket path;
the relative path used by the `test -S` readiness check is not valid for its
`-socket` argument.

Success prints exactly one line shaped like:

```text
mock completed: input_sha256=<64 lowercase hexadecimal characters>
```

Run the command a second time with different text to exercise the same
conversation and target after the first `opaque_resume` session mapping has
been committed. The vendor session token remains in the sandbox database;
`agentd` sees only its random opaque reference.

## 3. Shut down and check cleanup

Send `Ctrl-C` to `agentd`, then to `sandboxd`, and wait for both commands to
exit. Check that the ephemeral authority surfaces are gone:

```bash
test ! -S runtime/connectors/fake-personal/agentd.sock
test ! -S runtime/sandboxd.sock

docker container ls --all \
  --filter 'label=io.harness-gateway.managed=v1' \
  --format '{{.ID}}\t{{.Names}}\t{{.Status}}'
```

The final Docker command must print nothing. Non-empty output is a failed
cleanup/reconciliation check; restart `sandboxd` with the same immutable
configuration. Startup reconciles database records first and then inventories
identity-verified managed containers. Investigate if anything remains; do not
delete the state database or issue a replacement `docker create`.

The SQLite databases, `runtime/workspaces/project-main`, and the generated
directory under `runtime/runner-state/` intentionally remain. They are durable
state, not leaked ephemeral containers. Do not delete them merely to make this
check look clean.

The schema-v6 `runner_state_owners` row also remains after a Target is removed.
Filesystem cleanup does not release or transfer that historical ownership.

The global lock file also intentionally remains after shutdown. The kernel
lock is released when `sandboxd` exits; persistence of the file is part of the
safe ownership check.

## Offline session status and reset

`hgwctl` is a local operator tool, not a message or sandbox control surface.
Stop `agentd` before using it; the command must fail if agentd still holds the
Core database-derived lock. It resolves the complete six-field session key from
the trusted config and one Binding label—there is no raw database-path, scope,
force, vendor-token, or sandbox option.

This fence assumes one stable Core database pathname. Run agentd and `hgwctl`
from the same operator-owned config; do not hard-link the database, expose the
file through a second bind-mount path, rename/unlink/replace it, or remount its
parent while either process may run. The Core opener rejects a database it
observes with more than one hard link, but it cannot prove the absence of a
single-file bind alias or defeat a malicious same-UID operator. Those are
deployment violations, not supported alternate access paths.

Inspect the example Binding after the Core database has been created:

```bash
./bin/hgwctl session status \
  -config config/agentd.local.json \
  -binding fake-private-dm
```

The one-line `hgwctl/session-status/v1` JSON says whether a current opaque ref
exists and whether an exact-scope nonterminal Run remains. To detach the exact
ref you just observed:

```bash
HG_EXPECTED_SESSION_REF="$(
  ./bin/hgwctl session status \
    -config config/agentd.local.json \
    -binding fake-private-dm |
  jq -er 'select(.session_present == true) | .session_ref'
)"

./bin/hgwctl session reset \
  -config config/agentd.local.json \
  -binding fake-private-dm \
  -expected-session-ref "$HG_EXPECTED_SESSION_REF"

unset HG_EXPECTED_SESSION_REF
```

Only result `reset` exits successfully. `not_found`, `ref_mismatch`, a live
exact-scope Run, a missing database, a non-current/drifted migration ledger, a
SQLite integrity/foreign-key failure, or a held agentd lock is a non-success.
Reset removes only Core's current pointer; sandboxd's immutable private lineage
and vendor token history are not changed. The next Run for that Binding starts
a new harness session. There is no remote or chat reset in V1.

If the reset process or its output is interrupted and the commit receipt is
ambiguous, do not repeat it blindly. Run `session status` with the same config
and Binding: an absent pointer proves the reset landed; the same ref proves it
did not; a different ref requires a new operator inspection and must not be
matched with the stale expected value.

An `invalid_session` result does not clear or replace the saved ref. This is
intentional fail-closed behavior: later messages for that same Binding will
continue attempting the stale ref and receive the same bounded failure until
the operator stops agentd, inspects the current ref, and applies the exact
offline reset above. Do not expect a later message or daemon restart to create
a fresh session automatically.

Changing a Binding's Connector, actor, conversation, target, or target revision
creates a different exact session scope. `hgwctl -binding` resolves only the
Binding facts in the config supplied to that invocation; it does not search
historical scopes. A pointer under the previous exact scope remains inert and
is not garbage-collected. Preserve the previous exact Binding facts or reviewed
config if that historical pointer may need local status/reset; do not assume a
reused Binding ID selects it.

Every `opaque_resume` TargetRevision also sets a finite resume-admission age
and turn count. Choose them so planned offline reset cadence is acceptable.
Admission just before the age horizon remains authorized for that one frozen,
deadline-bounded Run even if controller delay crosses the horizon; its
successor inherits the old expiry and is therefore unusable for another turn.
Age/turn exhaustion follows the same `invalid_session` and exact-reset
procedure—there is deliberately no automatic rollover.

The database must already have the exact current migration ledger. `hgwctl`
never creates or upgrades it and never changes its configured SQLite page cap.
Ledger, `quick_check`, and foreign-key validation do not cryptographically
attest every `sqlite_master` object against a trusted local writer; deliberate
DDL tampering remains outside this maintenance claim.
The persistent `agentd.sqlite3.lock` file may be created on first ownership and
must not be deleted. An older agentd binary that predates this lock cannot be
fenced by the new tool; stop every old process before the first upgrade.

## Schema-v7 lifecycle upgrade boundary

Stop historical binaries before opening either database with this version.
Core v7 upgrades a v6 database only if each exact six-field scope has at most
one nonterminal Run; duplicate live scopes return
`ErrUnsafeLegacySessionLifecycleState` before the unique-index DDL. Sandbox v7
upgrades older history only when there are no session rows and no nonterminal
Runs. Otherwise it returns `ErrUnsafeSessionLifecycleState` before adding the
lifecycle columns/tables, because old rows cannot prove one-use consumption,
lineage expiry, or frozen turn policy.

Do not delete, edit, or relabel the rejected evidence. Preserve both databases,
prove all old runtime authority quiescent, and use a separately reviewed cold
migration or a genuinely new disposable lineage. `hgwctl` intentionally cannot
perform this migration; it accepts only an already-current exact ledger.

## Uncertain-create recovery

Before the only container-create call, schema v3 stores a pending intent and
the host boot ID. If the create result is uncertain, `sandboxd` retains the Run
and workspace lock and performs only read-only intent lookups:

- if the exact, fully verified container is found for a v3 intent with a boot
  ID, `sandboxd` cleans it and then clears the intent;
- if it is absent during the same host boot, the intent and workspace lock
  remain. One absent result is not a completion fence;
- after a host reboot, `sandboxd` must first look up the intent again. Only an
  absent result then permits it to clear the v3 intent and lock;
- an unsupported legacy/manual pending row with no boot ID is never cleared
  automatically, regardless of lookup result. A verified visible container may
  be cleaned, but the row and lock remain. Stop the daemon, preserve the
  database and Docker inspection evidence, and use an explicit reviewed
  operator recovery; do not delete the row or database just to unlock the
  workspace.

Never retry the create, manually create the deterministic name, or interpret a
Docker-daemon restart as a host-boot change. If the v3 intent stays absent, a
host reboot followed by rootless-Docker and `sandboxd` startup is the built-in
proof path. This recovery by itself is not evidence that the full end-to-end
run passed.

## Pre-v3 state databases

After every old `sandboxd` authority has been stopped, an empty schema-v1 or
schema-v2 sandbox database upgrades automatically. The current process lock
cannot fence a historical binary that never acquired that lock, so never run
old and new daemons concurrently during the upgrade. A pre-v3 database
containing even one Run fails startup with
`ErrColdMigrationRequired` and is left byte-for-byte logically unchanged by the
migration transaction. This is intentional: old rows cannot prove whether an
earlier Docker Create is still in flight, including rows that already contain a
runtime reference or terminal result.

There is no automatic in-place conversion for that state. Stop the old
`sandboxd`, preserve the database and managed-container inspection evidence,
and use a reviewed cold procedure that includes a host reboot before creating a
fresh v3 database. Do not delete or edit the old database merely to bypass the
startup refusal. The pre-v3 schemas were development formats, not a released
upgrade contract.
