# Fixed Codex target in sandboxd

Status, **2026-09-11**: opt-in startup, explicit enrollment and restart
composition are implemented with deterministic tests. The
[first ordinary-service Run](#first-ordinary-service-run--2026-09-11) passed
through fake ingress at **00:47 UTC**, with independent cleanup checks at
**00:48 UTC**. Production deployment and public Discord remain unestablished.

The [fifth real canary](codex-provider-canary.md#fifth-real-run--2026-09-10)
already exercised the fixed native Runner and provider channel. This increment
connects that template to the existing `sandboxd` executable and lifecycle,
with a separate daemon authority pin. It adds no daemon, agent loop, wire field,
provider selector, or remote credential operation.

## Closed configuration and authority

[`sandboxd.codex.example.json`](../config/sandboxd.codex.example.json) is a
placeholder template, not a ready configuration. `sandboxd/codex-v1` requires:

- exactly one V3 Codex target, one workspace and one credential slot/generation;
- `runner_state: {"kind":"none"}`, `new_only`, the fixed cached image and the
  V3 messaging limits, including 300 seconds and 2,000 output bytes;
- the complete independently approved six-field Core scope;
- separate workspace, credential, provider, tool-package and control storage;
- exact local paths and SHA-256 values for the UID setup, credential bootstrap,
  Runner, startup canary helper and seccomp artifact; and
- the SHA-256 of the actual running `sandboxd` executable, checked through
  `/proc/self/exe`, plus the fixed six-file Codex package content.

All fields use exact names and non-null values. There are no provider URLs,
commands, argument lists, environment maps, mount options or tool-selection
fields. Existing `sandboxd/v2` and `sandboxd/v3` remain mock configurations and
their historical manifest/revision fingerprint encodings are unchanged.

The artifact constructor checks local files but creates no endpoint, reads no
credential and makes no Docker/provider call. The daemon pin binds the checked
fixed runtime, provider operation policy, owner executable and complete local
configuration under `harness-security-gateway.codex-daemon/v1`. Strict service
registration then reads the selected immutable enrollment, checks the approved
scope and composes the source/proof/generation into the durable TargetRevision.
A candidate digest, successful metadata check or model review cannot replace
these steps. Reusing a revision after changing its resolved authority fails.

Unlike the single-canary inventory filter, this daemon lists the user's whole
HSG-managed runtime inventory. An unknown target, changed pin or unverified
container blocks startup. It cannot be hidden by selecting a new configuration.
Preserve the old configuration/binary/database for exact recovery before an
upgrade. A schema change is not permission to adopt or delete old resources.

## Operator preparation

Use Linux/amd64 and the reviewed local rootless runtime/storage prerequisites.
The direct runtime endpoint remains `/run/user/<effective-uid>/docker.sock`;
no ambient Docker context, remote endpoint, image pull or host-policy change is
performed. Provision the native-ext4 credential slot separately, under its
[source/enrollment contract](credential-source-enrollment.md). Credentials
must not come from the ordinary personal harness home or enter source control.

Build the opt-in executable from the reviewed source and retain its hash:

```sh
go build -trimpath -tags=codexintegration -o bin/sandboxd-codex ./cmd/sandboxd
sha256sum bin/sandboxd-codex
```

Provision the already reviewed artifact tuple and populate a private copy of
the example. The `runner` artifact is built from
`cmd/codex-provider-canary-runner`: its fixed native overlay accepts ordinary
HRP text; the canary's marker prompt belongs to its separate owner, not this
Runner. `canary` names the fixed startup-check helper and grants no extra Run.
The cached base image and bind-mounted package remain a measured development
template, not an approved production image or a new acquisition recipe.

Obtain the scope from the exact operator-owned `agentd` configuration:

```sh
bin/hgwctl session scope -config /srv/hsg/config/agentd.json -binding private
```

Copy the result's `scope` object into the private sandbox configuration. This
command compiles the existing Binding and exports its exact scope without
opening the Core database, acquiring its maintenance lock, or accessing sandbox
state. It accepts only a configured Binding ID. The result describes that file,
not which configuration a running service has loaded, and grants no authority.
Check the target ID/revision and actual operator intent before provisioning it.

Now check the configuration and fixed artifacts:

```sh
bin/sandboxd-codex -config /srv/hsg/config/sandboxd-codex.json -check
```

`-check` neither creates directories/databases/locks nor inspects enrollment or
credential contents. It does not contact Docker, confirm image availability,
attest the host, log in, or contact a provider. It can succeed with no auth file;
this deliberately does not mean Run readiness. Default builds reject this
schema before startup effects. `-check` and `-enroll-credential` cannot combine.

## Explicit enrollment, then service startup

The following commands have effects and require an approved local operation.
Do not run them merely because the example or read-only check exists. Keep all
canary owners and other sandbox mutation tools stopped during daemon ownership.

```sh
bin/sandboxd-codex -config /srv/hsg/config/sandboxd-codex.json -enroll-credential
```

Enrollment acquires the same user-global process lock as `sandboxd`, prepares
its private local storage, and opens/migrates only the sandbox reconciliation
database. It requires no retained Run/cleanup obligation and an empty verified
managed-runtime inventory before holding the source. It captures native proof,
validates the held object, and atomically registers exactly the configured
generation, proof and approved scope. It revalidates and closes the handle;
post-commit validation/close failure attempts conservative retirement and
returns an error. An uncertain result requires exact record inspection.

The operation has a 30-second context bound for cooperative database/runtime
work. It never picks a generation, retires earlier history to make registration
pass, replaces/moves auth files, logs in, refreshes, creates a container or
starts an execution listener. Exact enrollment replay cannot undo retirement.
Initial proof acquisition reads metadata/identity, not credential contents.

After separately approving service activation:

```sh
bin/sandboxd-codex -config /srv/hsg/config/sandboxd-codex.json
```

Ordinary startup registers the already enrolled target and uses the existing
execution HTTP/controller path. It never enrolls or scans an auth file into
cached readiness. The next correctly scoped admitted Run performs the existing
fresh held-source comparison, durable intent, mounted-object bootstrap and
per-Run provider opening. Its input comes from Core's existing text contract.
Only the fixed `chatgpt.com` operations and bounded `auth.openai.com` refresh
can reach an upstream; prompt, context and tool results may leave through that
allowed channel. Activation authorizes potentially repeated Runs from that
Binding, so it is broader than a single-canary approval.

Idle restart preserves the same enrollment. A restart with retained credential
occupancy retires that generation before cleanup and never reacquires it for
execution. Recovery queries and cleans the original runtime without creating a
new one or opening a provider endpoint. Re-enrollment after retirement requires
an explicitly selected higher generation and new TargetRevision after cleanup.
There is no automatic rotation or general credential-maintenance CLI here.

## Evidence and remaining limits

Focused tests cover closed configuration and storage-domain rejection, frozen
authority, source/proof mismatch, exact enrollment replay, failed observation
and close, pending work, foreign inventory, wrong scope, revision reuse, idle
restart and interrupted-Run retirement/cleanup. The scope-export test runs with
the Core lock already held and its database absent. Runtime substitutions in
these tests are synthetic and never dispatch Docker or provider work.

On **2026-09-10**, the focused checks passed at **22:35 UTC**, normal/tagged vet,
build and the five-property security demo at **22:36 UTC**, tagged affected-package
race checks by **22:42 UTC**, and the full default race suite by **22:45 UTC**.
The first ordinary suite exposed an existing asynchronous test wait; staging
can become visible before its later runtime lookup. The test now waits for
both observations with the same safety assertions. Only this test changed
after those race suites; 30 tagged race repetitions and the final complete
ordinary suite passed at **22:47 UTC** on the corrected tree.

The actual newly built daemon passed `-check` at **22:40:43–22:40:49 UTC** using
previously pinned non-secret artifacts and fresh empty fixture storage. No auth
file or database existed; before/after fixture metadata was identical. It made
no enrollment, Docker, provider or service-start operation. These observations
do not establish runtime availability, source proof or a deployable host.

The existing lifecycle/store and provider tests remain the applicable regression
suite; no new formal state machine or HTTP protocol is introduced. The native
canary and local startup checks retain their original dates and limitations;
the separate real execution evidence follows.

## First ordinary-service Run — 2026-09-11

Using source `829e0c3`, one separately authorized fake text event traversed
`fake-connector` → ordinary `agentd` → opt-in `sandboxd` → the existing fixed
native Codex Runner and provider channel. Core admitted its own new Run ID;
the canary-owner executable did not dispatch this Run. The controlled operation
lasted **00:47:04–00:47:38 UTC**, including enrollment and service startup/stop.
Core's admitted Run completed in **23.391 seconds**, with one dispatch, the
expected native reply, a tool-written marker and one completed local delivery.

The operation retained the original dedicated device-login source, workspace,
artifact tuple and both database objects. After an explicitly approved one-way
retirement of generation 5 under local ownership locks, ordinary
`sandboxd -enroll-credential` registered generation 6. Independent comparison
verified the same source/full physical proof and the newly approved exact
scope before either service started. The retirement was a bounded local
maintenance operation, not an implicit enrollment feature or new general CLI.
All five preceding Runs and deliveries remained intact.

The temporary Connector had one Binding and a one-receipt quota. The receipt's
3,600-second retention exceeded the 660-second main budget and shutdown grace.
The supervisor launched its fake client once. Existing receipt retention and
quota checks bound additional distinct events during that activation, assuming
a stable host clock; this is not a permanent single-use Binding. No additional
paid Run was submitted to retest the existing denial behavior.

At **00:48:20 UTC**, independent read-only checks confirmed one exact container's
create/attach/start/die/destroy events and absence, empty managed inventory and
process groups, six terminal Runs, no runtime reference/pending intent, and zero
credential occupancy, workspace locks or staged terminals. Both services exited
normally. The marker and one delivered result matched expectations; all prior
database history and the original credential metadata were unchanged. Generation
6 remained idle/enrolled, with 1–5 retired. Source/config/executable pins were
verified unchanged through execution at **00:49 UTC**.

This establishes a scoped ordinary-service path to a real provider using fake
ingress. It does not test Discord, separate service identities, production image
provenance, the full adversarial matrix or real refresh/revocation. The normal
daemon did not export provider-operation snapshots, so HTTP operation counts,
response stages and refresh activity are unobserved for this Run; unchanged auth
metadata is a narrower fact. No raw native/provider transcript was archived as
diagnostics. No new product code, host-policy change, image pull, login, ongoing
service activation or further Run was needed. The one-Run permission is consumed.

The next bounded deployment work is reproducible fixed-target packaging and
separate service-identity configuration, prepared and checked before any host
activation. Keep the completed fake-ingress witness and existing verification;
only changed artifacts or unresolved boundaries require new evidence.

The `credential-exposed-personal` residual remains: native tools may read the
dedicated credential. Per-Run CA files/directories remain private retained
evidence after joined cleanup, with no reuse capability or automatic retention
collector. Stable storage lineage and trusted host provisioning remain
assumptions. Production image provenance, separate service identities, the full
native adversarial matrix, operational retention/maintenance and public Discord
acceptance remain open. No system security policy is modified by these commands.
