# Drift ledger

Current-state output of the trace test defined in
[first-principles.md](first-principles.md). Every mechanism is asked which
axiom it serves and through which forced consequence, and is labelled
`necessary`, `chosen`, `expired`, `orphan`, or — for a consequence with no
mechanism — `missing`.

**This file is replaced, not appended.** It records what is true now. Accumulated
history belongs in [implementation-status.md](implementation-status.md); a
ledger that grows chronologically has stopped being a ledger.

Measured 2026-09-14 against the repository at that time; the F5 entries were
revised on 2026-09-16 after the credential rotation witness ran.

## Method and its limit

Tracing is at **package granularity**, using each package's stated purpose and
the import graph. A package counts as `necessary` when its declared
responsibility traces to a forced consequence.

This yields an **upper bound**, not a measurement. A package classified
`necessary` may still contain mechanism that is merely chosen; the reverse does
not occur, because a package whose purpose does not trace cannot contain
something that does. Tightening the bound requires file-level review of the
three largest stores, which this pass did not do.

Reachability is computed from the five binaries the offline bundle actually
builds: `agentd`, `sandboxd`, `hgwctl`, `fake-connector`, `discord-connector`.

## Size

**2026-09-17 correction:** this historical classification omitted copied native
Runner inputs. See the corrected adapter/relay entries below. The table cannot
be used as current whole-product reachability or orphan percentages.

Production Go, `internal/` only (27,754 lines across 39 packages):

| Class | Packages | Prod lines | Share | Test lines |
| --- | --- | --- | --- | --- |
| `necessary` (upper bound) | 28 | 19,481 | 70.2% | 27,276 |
| `chosen` | 6 | 5,671 | 20.4% | 6,139 |
| off-path (`orphan` candidates) | 5 | 2,602 | 9.4% | 7,014 |

`chosen` is the rootless Docker runtime, the Discord Connector, and the four
Codex-specific packages that a shipped binary links. Each serves a forced
consequence that an alternative mechanism could also serve; none is the
consequence itself.

Known deduction pending against the `necessary` bound: roughly 1,263 lines of
schema migration across the two stores. Migration protects durable
authorization state, so it serves F5 and F8, but a migration framework is a
consequence of choosing a persistent relational store rather than of the
consequences themselves. A file-level pass should reclassify it.

## Entries

### `orphan` — `responsesgate` (469 prod, 1,087 test)

No non-test code imports it, anywhere in the repository. Its five importers are
all `codexintegration`-tagged test files in `codexadapter`. The package
documentation states that "trusted runtime code must bind one instance to one
admitted Run"; no trusted runtime code does.

*Resolution determined 2026-09-16:* it is test support and always was. Its own
package comment says it is "not a provider proxy", and `Gate` mints a fresh
synthetic bearer of its own to check that a client used it — it is a fake
upstream, not a mediator. The sentence claiming that "trusted runtime code must
bind one instance to one admitted Run" oversells a fixture and is what made it
look like an unwired production component. It belongs under test support, and
the confusion it caused is the reason `codexprovider`'s mediation was briefly
mistaken for credential isolation.

### Corrected 2026-09-17 — `codexadapter` is in the fixed native Runner

The earlier off-path conclusion counted only the five host binaries compiled
by the bundle builder. It omitted copied native artifacts. The pinned native
input `codex-provider-runner` is copied by `deploy/codex/build.py` and mounted by
`internal/dockerruntime/synthetic_v3_linux_amd64.go` as `/codex-tools-runner`.
`cmd/credential-bootstrap` executes that path; its source entrypoint,
`cmd/codex-provider-canary-runner`, calls `codexadapter.Run` with
`MessagingToolsConfig` and `ProviderCanaryLauncher`. The adapter is part of the
fixed native path, not a competing unused packaging design.

A 2026-09-17 read-only cross-check of the retained native artifact matched the
locked SHA256 `f260ca92f157c2f24836b35b43149f7bd88ca77f9dc541bf21cc367766873e45`,
its Go build info named that entrypoint, and its historical successful build
receipt matched the artifact and the four inspected current adapter/launcher
source files. This is not a fresh reproducible build or a new deployment witness.

*Resolution:* document the copied artifact and its provenance in the supported
launch chain. Reuse its real adapter/launcher in the credential-isolation probe;
do not remove it or require an architecture rewrite based on host-only reachability.

### `orphan` — experiment scaffolding (1,129 prod)

The earlier host-only pass grouped `codexcanary` (817), `providerrelay` (255)
and `providerfixture` (57) here. The 2026-09-17 correction above also affects
`providerrelay`: `ProviderCanaryLauncher` invokes it in the copied Runner.
Canary drivers and synthetic fixtures retain their separate evidence-support
roles, but a package must be classified against all delivered executables.

The earlier 2,602 production / 7,014 test-line off-path total and the aggregate
table above are historical host-root statistics, not valid whole-bundle orphan
measurements. No corrected whole-bundle percentages are claimed by this bounded
audit. Do not use the old totals to justify deleting code.

### Tension — `codexprovider` ships in the default build

Its documentation says it is "a blocked canary candidate, not a selectable
production target", yet it is in the dependency closure of the untagged
`sandboxd` build, entering through `dockerruntime`. Code outranks prose, so
either the documentation understates what ships or the dependency should not
exist.

### Tension — the opt-in tag does not isolate packages

`go list -deps ./cmd/sandboxd` returns an identical internal package set with
and without `codexintegration`. The tag selects files inside packages; it does
not keep experimental packages out of the production binary. "Opt-in" therefore
describes behavior, not linkage.

### resolved — F5 credential rotation

Closed on 2026-09-16 with a live witness. The enrolled auth object was replaced
by a byte-identical copy: the next Run was refused at credential acquisition and
its generation retired, the next enrollment produced a different source digest
while generations 1-8 all shared one, and authority returned only after an
explicit operator enrollment on a new TargetRevision. A revision is permanently
bound to one generation, so rotating the object requires advancing the revision
too.

### resolved — F5 unattended recovery from a permanently refused event

The Connector holds its ingress cursor still when Core refuses an event, so the
message is presented again. That is correct for a transient refusal — the live
fence witness showed a refused message is retried and not lost — and wrong for a
permanent one. `event_expired` can never succeed, so a single message older than
Core's accept window wedges the cursor and every later message with it.

Any outage longer than the accept window therefore leaves an unattended
Connector permanently unable to admit anything until an operator steps over the
message by hand. F5 makes that a boundary gap: holding authority unattended is
part of the boundary, and this path cannot recover on its own.

Closed in code on 2026-09-16. `PollOnce` now distinguishes the two refusals that
are about the event itself, `event_expired` and `event_conflict`, from every
other code. Those two advance the cursor under their own closed skip label; a
configuration refusal still holds it, because skipping past one would discard
every message rather than one. The transient case keeps its previous behaviour
and has its own regression test, since that is what the live fence witness
depends on. Installed and witnessed on the live channel on 2026-09-16: an event
left to age past the accept window was refused under its closed label, the cursor
advanced past it, no retry was logged and nothing was admitted.

### `missing` — F7 credential isolation from the harness

`CRED-01` in the bake-off asserts that model-controlled tools cannot recover a
reusable provider credential. The deployed profile is classified
`credential-exposed-personal` and mounts the real `auth.json` into the
container at `/tmp/hgw-codex-home/auth.json`, so native tools can read it.

What exists is *operation* mediation, not credential isolation:
`codexprovider`'s policy fixes which upstream operations and headers are
allowed, and `Authorization` is on the allowed list because the container sends
its own. The owner enforces where traffic may go; it never holds the credential.

F7 is explicit that the harness must not reach anything convertible into
authority, and a reusable provider credential is the clearest such thing. This
is a deliberate, documented weaker claim rather than an oversight — but it is a
P0 hard gate in the bake-off, which means the comparison cannot currently reach
`CONTINUE` on the credential axis.

*Resolution:* the owner holds `auth.json`, the container receives something that
is not reusable outside its own per-Run channel, and the owner substitutes the
real credential upstream and absorbs refresh. The unknown is whether the CLI
accepts a substitute: it parses the access token — `Chatgpt-Account-Id` is an
allowed header — so a random placeholder may not survive. A custom-provider
overlay was measured on 2026-09-09 but an API-key result cannot stand in for a
subscription-login credential. This is research, not wiring.

The [2026-09-17 bounded work package](credential-isolation-plan.md) narrows this
direction to an offline compatibility gate, owner-only credential/refresh
obligations and focused acceptance. It is a design candidate, not a resolved gap.

**2026-09-19 update:** the fixed client's substitution and trusted native-refresh
compatibility now have offline synthetic evidence. Owner-only storage and strict
auth parsing are implemented locally, still unwired. This resolves the earlier
client-compatibility question only for the tested fixed version; helper recovery,
verified refresh results, provider/profile integration and real acceptance remain.
F7/CRED-01 stays open and the deployed profile keeps its exposed classification.

**2026-09-27 update:** the private native consumer and per-Run provider adapter
are now implemented, with fixed-native evidence for owner-only recovery and
client-local refresh. The old exposed executable still uses the mounted source.
Remaining work is isolated profile/runtime/startup/artifact wiring plus combined
and real acceptance; [current scope](credential-isolation-plan.md#per-run-provider-authentication--2026-09-27).
This component result neither closes F7/CRED-01 nor reclassifies the old profile.

**2026-10-01 update:** [V4](codex-profile-v4.md) adds opt-in owner-only runtime
wiring with a separate profile/schema/pin, disposable local seed verification,
pre-Create readiness and helper-absence startup gate. It remains a blocked
candidate: complete native runtime/receiver, Runner secrecy and real acceptance
are still required. Older exposed revisions and dated deployment observations
remain unchanged; F7/CRED-01 stays open.

## What this pass did not do

- File-level tracing inside `sandboxstore`, `sandboxcontroller` and `corestore`,
  which together hold 47% of the `necessary` bound.
- Any `expired` determination. That requires each `chosen` mechanism's original
  premise to be written down first, and the premises are currently implicit.
