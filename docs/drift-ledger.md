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

*Resolution:* either a shipped path binds it, or it moves to test support, or it
is removed. Production code reachable from nothing is not a boundary.

### `orphan` — `codexadapter` (1,004 prod, 5,422 test)

Not reachable from any of the five shipped binaries. It is linked only by
`cmd/codex-runner`, `cmd/codex-tools-runner` and `cmd/codex-provider-canary-runner`,
none of which the bundle builds, and the pinned tool package contains no such
binary.

This is the concrete form of the status page's own heading, *"Codex adapter and
profile: present but not wired into a target"*. Two packaging designs coexist:
the documented `runner-codex image → thin HRP adapter → Codex CLI` layering,
and the fixed native startup path that actually runs. Only the second ships.
Its 5.4:1 test-to-code ratio is the highest in the repository, so the unshipped
design is also the most heavily verified one.

*Resolution:* decide which packaging is the product. Keeping both is a
maintenance obligation that no consequence requires.

### `orphan` — experiment scaffolding (1,129 prod)

`codexcanary` (817), `providerrelay` (255) and `providerfixture` (57) are
reachable only from tagged canary binaries. They produced retained evidence,
which is legitimate under A5, but A5 governs claims rather than shipped
mechanism. Their continued presence is a choice and should be recorded as one.

Off-path code totals 2,602 production and 7,014 test lines — 9.4% of production
and 16.6% of test code that no shipped binary reaches.

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
depends on. Awaiting installation on the host.

## What this pass did not do

- File-level tracing inside `sandboxstore`, `sandboxcontroller` and `corestore`,
  which together hold 47% of the `necessary` bound.
- Any `expired` determination. That requires each `chosen` mechanism's original
  premise to be written down first, and the premises are currently implicit.
