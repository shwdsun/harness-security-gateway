# Engineering case study: authority and evidence in AI-assisted development

Case study updated **2026-10-08**; literature snapshot **2026-10-07**.

Harness Security Gateway is an independently developed, single-user gateway
for requesting coding work through private messaging. Its first intended path
is Discord to one immutable Codex target. This case study explains the design
judgment and verification work behind that practical goal. It does not change
the [product scope](positioning.md) or introduce an agent platform.

For a quick review:

- **Engineering reviewers:** follow the decisions below into the linked code
  and regression tests, then inspect the [security witness](../demo/security/main.go).
- **Research reviewers:** inspect the [recovery experiment](../formal/recovery/README.md)
  and its assumptions before considering the proposed questions below.
- **Readers assessing AI-assisted work:** examine who owns acceptance, what
  evidence can contradict a model, and which outcomes remain unmeasured.

This is an **early development baseline (pre-alpha)**. Source integration is
separate from acceptance of a real deployment. The current credential-isolation
design still needs real-provider compatibility, credential renewal and complete
private-Discord validation. Historical deployment observations and controlled
tests apply only to their stated profiles. [Implementation status](implementation-status.md)
and the [credential-isolated messaging criteria](milestones.md#credential-isolated-messaging)
govern those claims. [Core concepts](concepts.md) define task records (`Run`),
authorization rules (`Binding`) and execution targets before the code mappings below.

## Decisions that can be inspected

The central design question is how an untrusted request can trigger useful
execution without choosing its authority. The answer combines small interfaces,
explicit ownership and durable state; it does not depend on a model refusing
every hostile instruction. The [design principles](design-principles.md) explain
the tradeoffs, and [architecture](architecture.md) identifies their owners.

| Decision and reason | Inspectable mechanism and falsifier |
| --- | --- |
| Keep execution configuration out of message admission. This reduces the choices that downstream components must safely interpret. | [Inbound types](../internal/connectorwire/types.go) and [strict-decoding tests](../internal/connectorwire/connectorwire_test.go) reject unknown fields and malformed unions. The [security witness](../demo/security/main.go) checks injected target fields and confirms that the recognized but unsupported `select_target` action creates no Run. |
| Authorize an exact identity relationship. Independent actor and conversation allowlists could accidentally authorize their cross-product. | [`Endpoint.Authorize`](../internal/agentpolicy/policy.go) looks up the actor/conversation pair within a Connector-bound endpoint. [`TestExactBindingAuthorizationRejectsCartesianProduct`](../internal/agentpolicy/policy_test.go) checks mismatches; configuration-snapshot tests check later mutation. |
| Preserve the admission decision across redelivery. A retry should not manufacture another authorization. | [`IngestTextRun`](../internal/corestore/runs.go) commits the Run and receipt together. [`TestInboundDedupeCreatesExactlyOneQueuedRun`](../internal/corestore/corestore_test.go) checks duplicate identity, conflicting payloads and row counts. |
| Derive reply scope from the accepted Run. Output content should not select a new recipient. | The [outbox](../internal/corestore/outbox.go) joins each delivery to its Run; [`TestRunDerivedDeliveryAPIHasNoDestinationAuthority`](../internal/corestore/corestore_test.go) pins the input to ID and text. This is a Core destination-authority claim, not proof of platform delivery. |
| Reconcile uncertain execution before releasing ownership. An absent observation can precede a late container creation. | [`reconcileRun`](../internal/sandboxcontroller/reconcile.go) follows stored identity and cleanup state. The [recovery pilot tests](../internal/sandboxcontroller/recovery_pilot_test.go) inject late materialization and response loss and check that recovery does not issue another Create. |

These choices intentionally trade flexibility for a smaller authority surface.
Harness reasoning and context management stay behind the Runner boundary;
adding another planner or dynamic plugin selector would add obligations outside
the current product need. The [access-control contract](access-control.md)
also states residuals: a compromised Connector can forge events within its
configured Bindings, and the local operator remains the trust root.

## What the verification establishes

The offline witness is a compact entry point: `make demo-security` exercises
production decoding, policy, service and Core SQLite code with synthetic input.
It kills the admitting child process after acknowledgment, reopens the database,
checks the original Run, and rejects a changed payload under the retained event
ID. Its [regression](../demo/security/main_test.go) checks the five reported
properties. No network, provider credential or container is needed.

This demonstrates narrow admission and persistence behavior. Replay identity
holds within the retained receipt window and the same non-rolled-back Core
persistence lineage; it is not an unlimited exactly-once claim. A completion
message alone cannot establish runtime cleanup, credential isolation or delivery.
Those require their own observations and remain subject to the current gates.

The formal recovery pilot asks whether completion or workspace release can
occur while an uncertain Create can still materialize, or a runtime remains.
Its [Z3 checker](../formal/recovery/check.py) checks an inductive invariant in
a one-Run abstraction. The [Go tests](../internal/sandboxcontroller/recovery_pilot_test.go)
replay model traces through actual recovery code and SQLite, alongside a seeded
property-test baseline; the external runtime is fake.

The distinction matters: induction covers arbitrary action-sequence length in
that abstraction; trace replay samples implementation conformance. Neither is
a proof that Go refines the model. Atomic storage, serialized recovery, exact
cleanup and one-shot materialization are explicit assumptions. Initial dispatch,
credentials and real containers are outside the pilot. Its separate Create-count
test must not be credited to the abstract invariant proof. See the
[mapping, negative controls and comparison protocol](../formal/recovery/README.md).

## AI assistance and individual accountability

The project is developed by an individual with AI assistance. The
[repository contract](../AGENTS.md) assigns scope, security claims and release
decisions to the human maintainer. Models assist with research, candidate
designs, implementation and adversarial review; they do not supply acceptance
authority. This division is part of the
[engineering practice](design-principles.md#engineering-practice).

A useful review record connects a proposed finding to a code path, a
counterexample or test, an adjudication, and any remaining limitation. Agreement
between models cannot substitute for that chain. A failed review transport is
also different from a completed review finding no defect. Public documentation
can preserve decisions and evidence scope without publishing private transcripts.

The October 8 integration review provides a concrete example: reproducible
counterexamples showed a bot credential following an HTTP redirect, an incomplete
multi-part reply being acknowledged as delivered, and Unicode corruption at a
byte cutoff. Review also exposed lost outbound rate-limit pacing and a misleading
delivery counter. The accepted changes are checked by
[response-boundary regressions](../internal/discordconnector/response_boundaries_test.go)
and [durable-progress/restart regressions](../internal/discordconnector/delivery_progress_test.go).
These findings demonstrate useful review work on this change; they do not
establish a general defect-detection rate or absence of other defects.

One development lesson is that completing a local step can still leave the
overall workflow unsuccessful when diagnosis and recovery repeatedly return to
the operator. The repository contract therefore counts manual-action requests
across an objective and requires redesign before a third request. Preparation,
verification and recoverable agent work should precede a necessary handoff.

That protocol is a design constraint and a response to process failure, not a
measured productivity result. Request counts alone also miss manual substeps,
waiting and context switches. This case study claims no reduction in human
effort, no percentage of AI-authored code, and no causal speedup. Functional
results, security evidence and compliance with the working agreement need
separate assessment.

## Recent external context

The following primary sources were published within **2026-07-07–2026-10-07**
and checked for this snapshot. They motivate questions and evaluation choices;
they do not prove HSG's properties or establish its novelty.

| Source and publication date | Relevant observation or position | Limit |
| --- | --- | --- |
| [Databricks coding-agent benchmark](https://www.databricks.com/blog/benchmarking-coding-agents-databricks-multi-million-line-codebase), 2026-07-08 | Uses reviewed tasks and held-out tests; discovered answer leakage through Git history. Evaluation infrastructure itself needs scrutiny. | Private, filtered company benchmark; rankings and productivity claims do not transfer to HSG. |
| [IssueTrojanBench](https://arxiv.org/abs/2607.20759), v1 2026-07-22 | Tests malicious issue content across coding agents and delivery vectors, motivating enforcement outside natural-language interpretation. | Preprint; two Python repositories and selected models, agents and prompts. Attack rates are configuration-specific. |
| [METR incident investigation](https://metr.org/blog/2026-08-26-openai-hugging-face-incident-investigation/), 2026-08-26 | Documents unintended communication through shared infrastructure and attempts to manipulate observations. | Bounded investigation, incomplete activity capture and substantial AI-assisted analysis; not a complete assessment of remediation. |
| [CCC Beyond Code report announcement](https://cccblog.org/2026/08/31/engineering-trustworthy-large-scale-software-systems-with-ai-new-report-released/), 2026-08-31 | Identifies requirements, verification and preservation of design rationale as research priorities. | Workshop findings and agenda, based on a February workshop; not a productivity experiment. This citation is the verified announcement. |
| [Arena HarnessTax](https://arena.ai/blog/coding-agents-harness-tax), 2026-09-16, updated 09-18 | Compares 21 model–harness pairs; cost can differ despite similar task success. | Thirty tasks from each of two public benchmarks, three attempts each; possible training exposure and differing harness settings. |
| [Arena judge self-preference study](https://arena.ai/blog/llm-judge-self-preference), 2026-09-30, updated 10-06 | Finds that model agreement and human preference can diverge, including with different model judges. | Text preference judgments, not security-review accuracy; does not measure this project's review process. |

## Falsifiable questions for further work

These are proposed investigations, not completed results or permission to
expand the product. They can use bounded fixtures and retained evidence before
requiring additional integrations.

| Question | Measurement that could contradict the proposed benefit |
| --- | --- |
| Does the closed authority contract hold through replay and recovery? | Mutate authority-bearing inputs and inject crash/retry schedules; inspect admitted revisions, Run identities and external Create counts. An unauthorized change or duplicate creation is a counterexample. |
| Does model-trace replay add value beyond ordinary tests? | Apply the same isolated mutations to both approaches; record additional defects detected, setup cost and maintenance after semantic changes. Equal detection with higher upkeep would weaken the benefit. |
| Does independent AI review improve engineering outcomes? | Record additional reproducible findings, false positives and adjudication effort against a single-review baseline. More agreement without added valid findings would not demonstrate improvement. |
| Does preparing recovery before a handoff reduce operator burden? | Prospectively record requests, manual substeps, waiting and rework while holding acceptance and authority fixed. Lower request counts with more manual work or weaker checks would fail the objective. |

The inspectable contribution is the reasoning from a practical need to a small
contract, its implementation, attempts to falsify it, and an explicit account
of what remains unproved. The gateway must still earn its operational claims.
