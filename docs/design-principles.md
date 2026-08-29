# Design principles

## Nature

Harness Security Gateway is designed as a security boundary between a
natural-language request and a coding harness that can act on a machine. The
current pre-alpha proves only the implemented control-plane properties and mock
path described in [implementation-status.md](implementation-status.md); it is
not yet a production containment boundary or an agent platform.

Its central rule is:

> Messages may invoke an operator-preauthorized execution envelope; they may
> never select or widen that envelope.

This is more precise than saying that a message has no authority. An admitted
message can cause real work, but only through an exact authority relation that
already exists outside the message, model, repository, and Connector.

```text
untrusted intent + authenticated transport facts
                     |
                     v
          exact operator-owned Binding
                     |
                     v
       one immutable TargetRevision -> one durable Run
                                          |
                                          v
                              replaceable Harness execution
```

## Design laws

### 1. Keep identity, intent, and authority distinct

The Connector reports authenticated platform facts. Message content describes
desired work. Only local operator policy decides which immutable target those
facts may invoke. Neither natural language nor model interpretation is
authorization evidence.

### 2. Remove authority-bearing choices from untrusted contracts

The wire does not accept a target, command, image, path, mount, environment,
network rule, credential, plugin, skill bundle, MCP server, or vendor option.
The preferred security mechanism is a choice the untrusted caller cannot
express, not an open value that every downstream component must remember to
filter.

### 3. Treat authorization as durable state

Admission creates one durable `Run` before execution. The Run is the receipt
and recovery identity of one authorization decision, not merely job metadata.
Duplicate delivery, restart, ambiguous runtime creation, and recovery must
reconcile that same decision; they must not silently manufacture replacement
authority or a second external execution.

### 4. Make authority follow ownership

Transport identity, admission, execution estate, and harness reasoning have
different owners and failure domains:

- a Connector owns one platform protocol and credential;
- Core owns Bindings, admission, Runs, replay, and outbound scope;
- the sandbox domain owns immutable targets, workspaces, runtime state, and
  private provider-session state;
- the Harness owns reasoning, context management, tools, and any internal
  orchestration.

Persistence does not collapse those owners. A Run, provider session, context
window, workspace, sandbox, and harness process are different lifecycles.

For an `opaque_resume` target, conversational continuity is a chain of
independently admitted Runs. A one-use, exact-scope provider-session reference
may carry continuity to the next Run, but it never admits that Run or changes
its Binding, TargetRevision, workspace, or profile. An invalid requested
reference fails closed; it is never converted automatically into a fresh
session. HSG does not treat a provider session as a Core-owned conversation log
or model context window.

### 5. Put probabilistic execution and delegated capabilities inside deterministic limits

Models, prompts, and classifiers can reduce the likelihood of an unwanted
action; they do not define what is reachable. Identity checks, closed
contracts, filesystem and runtime boundaries, credential mediation, egress,
resource limits, and lifecycle rules define the maximum blast radius. A
container name or a model refusal is not itself a containment claim.

Credentials and egress are capabilities with owners, scopes, and lifetimes.
The secure default keeps reusable credentials outside model-controlled code and
mediates the narrow operation that needs them. Permitting a provider domain is
still a capability grant, not a confidentiality guarantee: a permitted endpoint
may expose many functions and can itself carry data. A profile that cannot meet
the default must carry an explicit weaker claim instead of inheriting a general
"sandboxed" label.

### 6. Keep the boundary stable and the Harness replaceable

Model and harness behavior changes faster than the authority boundary should.
Provider-specific session, permission, tool, and context behavior stays behind
a narrow Runner adapter. Compatibility protocols may reduce adapter work, but
they never replace ingress identity, Binding admission, Target revision
control, or durable Run semantics.

### 7. Require evidence and make complexity earn its place

Every security claim needs a falsifier: an attack, failure, or state transition
that would disprove it. Every new field, tool, platform, protocol, agent, and
maintenance path adds authority and evidence cost. It enters Core only when a
real path needs it, deterministic enforcement belongs there, and a simpler
boundary cannot preserve the same property.

## Engineering practice

Work normally follows this chain:

```text
claim -> threat or counterexample -> closed contract -> mechanism
      -> deterministic test -> production-shaped canary -> residual limit
```

The evidence vocabulary is deliberately strict:

- **design assumption**: accepted for progress but not yet demonstrated;
- **implemented invariant**: enforced by the cited code and deterministic
  tests within a named scope;
- **observed behavior**: measured under a pinned model, harness, runtime, and
  experiment profile, without generalizing beyond it;
- **external precedent**: another system or publication supporting a design
  direction, not proof about this implementation;
- **known residual**: an authority or failure mode the current claim excludes.

Agent behavior is evaluated by durable end state and side effects, not by the
agent claiming success or following one preferred trajectory. Deterministic
authority properties require deterministic checks. Stochastic harness behavior
uses repeated trials and an explicit observation scope. Traces are diagnostic;
they are not a substitute for state evidence and need not expose hidden
chain-of-thought.

AI-assisted development follows the same authority rule as the product:

- people own the problem, threat model, invariants, acceptance, and release;
- models assist with research, candidate designs, implementation, and
  adversarial review;
- code, tests, runtime evidence, and primary sources decide whether a model
  finding is accepted;
- model agreement never authorizes a design change by itself.

## Change test

Before widening the system, answer:

1. Which existing user path or security property requires this change?
2. Which trust domain owns the authoritative state?
3. Can message, model, repository, or Connector data name or widen a resource?
4. What are the replay, crash, cancellation, revocation, and recovery rules?
5. Can enforcement remain outside the model context and use a closed contract?
6. What experiment would falsify the claim, and what residual remains?
7. Should the behavior remain inside a Target or Runner instead of Core?
8. Which simpler component or refusal preserves the same outcome?

An unclear answer normally means defer. Caller-selected authority, arbitrary
option maps, probabilistic-only admission, a second agent loop, or undefined
failure semantics mean reject.

## Practice basis and limits

These principles apply established systems and security ideas to an unusually
powerful natural-language entry point:

| Basis | Expression in Harness Security Gateway |
| --- | --- |
| Saltzer and Schroeder: economy of mechanism, fail-safe defaults, complete mediation, and least privilege | small closed protocols, exact Binding checks, absent ambient authority, fail-closed recovery |
| NIST SP 800-207: protect resources rather than trusting network location or ownership | authorization is resource- and identity-specific; local or containerized does not imply trusted |
| Capability-oriented and safe-interface design | untrusted inputs cannot represent authority-bearing resources; immutable Target revisions carry the approved envelope |
| Transactional and idempotent distributed-systems practice | admission linearizes into a durable Run; retries and uncertain side effects retain one identity |
| Contemporary agent containment and evaluation practice | probabilistic reasoning is separated from environmental limits; outcomes and side effects outrank self-report |

Primary references:

- J. H. Saltzer and M. D. Schroeder, *The Protection of Information in
  Computer Systems* (1975): <https://doi.org/10.1109/PROC.1975.9939>.
- NIST SP 800-207, *Zero Trust Architecture*:
  <https://csrc.nist.gov/pubs/sp/800/207/final>.
- Google, *An Introduction to Google's Approach for Secure AI Agents*:
  <https://research.google/pubs/an-introduction-to-googles-approach-for-secure-ai-agents/>.

The references are intellectual and empirical precedent, not a formal proof or
a production certification. Current implementation evidence and unproved gates
remain authoritative in `implementation-status.md`; product scope and non-goals
remain authoritative in `positioning.md` and `architecture.md`.
