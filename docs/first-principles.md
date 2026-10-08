# First principles

This document sits between [design-principles.md](design-principles.md), which
states the laws the system follows, and [architecture.md](architecture.md),
which states the structure it has. It records what the project assumes about the
world and what those assumptions force. Nothing here is a preference: every
entry is either an axiom or a consequence of one.

Its purpose is traceability in one direction. Evidence accumulates in
[implementation-status.md](implementation-status.md), which can only be read
forward in time. This document can be read downward. A mechanism that cannot be
traced back up through it is either a choice that must be recorded as a choice,
or scope that entered without anything requiring it.

This document makes no evidence claim. What is built, checked and still open
remains authoritative in `implementation-status.md`.

## Axioms

These are irreducible. They can be rejected, but not derived. Rejecting one
invalidates every consequence that depends on it.

**A0 — The system must cause real work.**
An untrusted messaging entry point must produce useful execution on a real
machine. This is the axiom that makes the problem non-trivial: a gateway that
refuses everything satisfies every security property and is worthless. Every
consequence below must remain compatible with A0, which is why none of them is
simply "do less".

**A1 — Everything that flows is untrusted.**
Message content, repository content, model output, runner output, imported
artifacts and platform-delivered payloads. Untrusted has a precise meaning
here: such data may influence *what work is done*; it may never influence *what
work is permitted*.

**A2 — The harness is a powerful confused deputy.**
It can take arbitrary action within whatever it can reach, it is steered by A1
data, and its own refusal behavior is not a bound. Treat its full capability as
directed by the untrusted input it reads.

**A3 — The operator is absent at execution time.**
One human owns the problem, threat model, invariants, policy and release. That
human is not present when a message arrives. There is no second reviewer, no
interactive approval, and no remote authority.

**A4 — Only the kernel is trusted to enforce.**
Process credentials, user and group identity, filesystem permission bits,
namespaces and kernel-supplied peer credentials. Everything above them —
language-level checks, in-process validation, container defaults, prompts,
model refusals — changes likelihood, not reachability.

**A5 — A claim without a falsifier is not held.**
This axiom is epistemic: it governs what may be asserted, not what code does.

## Forced consequences

Each consequence states its derivation and the observation that would break it.

**F1 — Authority is pre-bound and exact.** *(A0 + A1)*
A0 requires a message to cause work; A1 forbids the message from carrying
authority. The only remaining position for authority is outside the message and
prior to it. It must also be exact: if pre-bound authority offers a set and the
message selects a member, the message holds authority over that selection.
Authorization is therefore a total function from authenticated transport facts
to one target — `(connector, actor, conversation) → one TargetRevision`.
*Falsifier:* any path where message content changes which target, revision,
image, path, command, environment, mount, network rule or credential is used.

**F2 — Authority-bearing values must be inexpressible, not filtered.** *(A1 + A4)*
A filter is a correctness property of every component that handles the value,
and A4 denies that component-internal correctness is a boundary. The value must
be absent from the schema, so that no downstream component can carry the bug.
*Falsifier:* an authority-bearing field accepted at the wire and rejected later.

**F3 — The approved envelope is immutable and frozen at admission.** *(A1 + A2)*
Harness output is A1 data. If the envelope could change after admission, A2's
output would reach its own limits. The TargetRevision is therefore immutable
and pinned at the moment of admission, and changing the bytes changes the
identity rather than the contents.
*Falsifier:* an in-flight Run whose image, workspace, profile, policy or limits
differ from those recorded when it was admitted.

**F4 — Every question is pre-decided or fails closed.** *(A3)*
With no operator present, a question the system cannot answer from durable
operator-owned state has exactly two outcomes: a pre-existing answer, or
refusal. "Ask the human" is unavailable by A3, and "assume the reasonable
default" is unavailable because that is a decision derived at runtime from
untrusted context.
*Falsifier:* any runtime branch resolving ambiguity by inference, heuristics or
model judgement instead of pre-existing state.

**F5 — Holding authority unattended is part of the boundary, not operations.** *(A0 + A3)*
Work must remain possible while nobody is watching. Credentials expire, hosts
restart, runtimes fail. Enrollment, generation identity, retirement, rotation,
restart and recovery are therefore security mechanisms rather than
administration: each is a moment at which authority could be silently created,
duplicated, extended or lost.
*Falsifier:* any credential, restart or recovery path that yields usable
authority whose provenance is not an explicit operator enrollment.

**F6 — Isolation is kernel identity.** *(A4)*
Trust domains must be distinct kernel identities, communicating over channels
where the kernel itself authenticates the peer, with private storage enforced by
permission bits. Running domains under one identity and relying on internal
checks validates the protocol, not the isolation.
*Falsifier:* two domains separated only by configuration, or a peer accepted
without a kernel-supplied credential check.

**F7 — The harness must not reach anything convertible into authority.** *(A2 + A4)*
Reaching the runtime socket, Core's durable state, a platform credential,
another target's manifest or a foreign workspace converts capability into
authority, and A2 guarantees that reach is exercised if it exists. The absence
must be structural — not granted and not reachable — rather than declared.
*Falsifier:* any path from Runner execution to the runtime socket, Core state, a
platform credential or a foreign workspace.

**F8 — The authorization decision is durable and precedes execution.** *(A0 + A2 + A3)*
Execution has external side effects, crashes are certain, and no operator is
available to adjudicate afterwards. A record created after or alongside
execution would leave side effects with no decision, forcing recovery to invent
one. One durable Run is therefore created before execution, and every later
event — duplicate delivery, restart, ambiguous runtime creation, cancellation —
reconciles to that same record instead of producing a second.
*Falsifier:* any recovery path that produces a second external execution or a
replacement authorization.

**F10 — The harness's reach outward is bounded like its reach inward.** *(A1 + A2)*
A2's capability is directed by A1 data, so every outbound channel the harness
holds is an outbound channel an untrusted message controls. Reading the
workspace is legitimate work; sending it wherever a message asks is not, and a
reply, a log line and an evidence file are outbound channels too. Egress and
disclosure are therefore pre-approved capabilities with named destinations and
named contents, not defaults.
*Falsifier:* any path where a message causes workspace content, a credential, a
vendor session reference or host detail to leave for a destination or into a
record the operator did not approve.

**F11 — Every execution is bounded before it starts.** *(A2 + A3 + A4)*
A2 consumes whatever it is given, and by A3 nobody is watching to stop it. A
bound set after the fact, or enforced by the harness's own cooperation, is not a
bound. Processor time, memory, process count, wall time, output bytes, event
count and persistent growth are therefore fixed before admission and enforced
below the harness.
*Falsifier:* any resource a Run can consume without a pre-set bound enforced
outside it.

**F9 — Claims carry their scope.** *(A5)*
A property is stated together with the conditions under which it was checked.
One host, one Run or one profile is evidence about that host, Run or profile;
generalizing is a separate claim requiring separate evidence.
*Falsifier:* a stated property with no check that could have failed.

## Where derivation stops

The following are **not** forced by A0–A5. Each satisfies some consequence
above, but so would alternatives. They are legitimate only while their own
stated reason holds, and they are where drift begins.

| Choice | What it serves | What is actually forced |
| --- | --- | --- |
| Messaging as the entry point; Discord first | A0 | that some untrusted entry point exists |
| Codex as the first harness | A0 | that the harness is replaceable behind a narrow adapter |
| REST polling with a Connector-owned cursor | F8 | durable ingress owned by a domain that can be held responsible |
| Rootless Docker as the execution runtime | F6, F7 | kernel-enforced isolation and structural unreachability |
| One live Run per authorization scope | F4, F7 | a bounded blast radius; the bound of exactly one is chosen |
| SQLite for durable state | F8 | durability and single-decision reconciliation |
| Filesystem-identity credential source contract | F5 | provenance, non-duplication and ordered generations |
| Text-only content | F2 | closed contracts; no axiom forbids other media |
| Single host | — | A3 says single operator, not single machine |

## How to use this document

For any mechanism, ask which axiom it serves and through which consequence.
There are four possible answers for a mechanism that exists, and one for a
mechanism that does not:

- **necessary** — it traces to a consequence, which traces to an axiom.
  Changing it requires changing an axiom.
- **chosen** — it traces to a recorded choice whose stated reason still holds.
  The reason and the premise it depends on must both be written down.
- **expired** — it traces to a choice whose premise no longer holds. It still
  passes its tests; it is defending a world that changed.
- **orphan** — it does not trace. Either the trace is merely unwritten, or the
  mechanism is scope that entered without anything requiring it. Design law 7
  applies: complexity must earn its place.
- **missing** — a consequence with no mechanism. This is drift in the other
  direction and is easy to miss, because nothing fails.

The current output of this test is [drift-ledger.md](drift-ledger.md).

F5 supplied the first worked example. Rotation had no evidence, so it was
`missing`; it now has a live witness, and running that witness surfaced a second
`missing` in the same consequence — an unattended Connector cannot recover by
itself from a permanently refused event. Closing one gap exposed the next,
which is what a consequence with a falsifier is for.
