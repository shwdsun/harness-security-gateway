# Local checkpoint assessment — 2026-09-10

This checkpoint consolidates the public work since `e4318df`. The local
implementation, scoped offline witnesses, two authorized real-provider Runs and
the requested design/practice review have reached a recordable boundary.
**At this checkpoint, both real Runs had failed and the production path was blocked.**
[Implementation status](implementation-status.md) retains the detailed evidence
and open gates. A source checkpoint does not establish merge, release or
deployment status.

Later on the same date, the [fifth controlled Run](codex-provider-canary.md#fifth-real-run--2026-09-10)
completed native inference, a tool-written marker, local delivery and cleanup
at **21:52–21:53 UTC**. The original assessment and verification table below
retain their earlier scope; production and public Discord remain blocked.

## Completed local scope

- Credential source identity/proof, immutable generation/target binding, held
  source handoff and ordered release/recovery through the existing controller
  and store. Normal daemon configuration continues to accept only mocks.
- The opt-in V3 native package, mounted-object bootstrap, provider operation
  endpoint/relay and controller-owned cleanup. Focused synthetic native cases
  cover tool completion, cancellation, replay, cleanup failure and owner loss
  within their documented runtime and identity assumptions.
- A local provider-canary owner with artifact-bound preparation, explicit
  execution, bounded diagnostics and history-preserving continuation. Two real
  Runs failed on 2026-09-10; exact container absence and released cleanup fences
  were independently observed. Both failed histories remain retained.
- An opt-in [formal recovery pilot](../formal/recovery/README.md) and the
  [content evolution and verification contract](content-evolution-and-verification.md).
  The pilot proves an abstract invariant under explicit assumptions and samples
  implementation conformance. Media support and whole-system proof are absent.

## Reflection and decisions

Keep the authority and ownership design: exact admission selects an immutable
target, the runtime owner contains execution, and cleanup precedes credential
release and public completion. The observed failure does not justify another
agent loop, generic proxy, protocol redesign or expanded feature scope.

The verification process needs a more decisive experiment boundary. The first
real Run retained no operation diagnostics. The second added bounded diagnostics
but still grouped several response predicates into `upstream_policy`; thirteen
inference exchanges reached that stage with upstream HTTP 200. This identifies
where to investigate, but neither the exact cause nor successful authentication
or inference. Future diagnostic attempts must distinguish their remaining
hypotheses before another costly live call. Preserve rejection rules until the
specific incompatibility is known.

Fable 5.1 at max effort completed an independent review and one follow-up on
2026-09-10; complete responses and code-grounded adjudication are archived
privately. The resulting direction is narrower diagnostics, suppression of new
dispatch authority after deterministic rejection, and one coherent delivery
package. Reviewer claims about HTTP 200, deployment isolation and total request
counts were corrected against evidence; agreement is not a security approval.

Keep decomposition around ownership and testable guarantees, then combine
design, implementation, affected checks, artifacts and execution preview as one
work package. Commit that package after local verification, recording unresolved
acceptance separately. This cumulative checkpoint is larger than that intended
cadence. Reuse tests and formal results when their assumptions remain valid;
new content types should add their own decoding/resource obligations without
automatically restarting unchanged lifecycle or protocol verification.

## Verification carried into this checkpoint

All times below are **2026-09-10 UTC**, local observations rather than public CI.
Before documentation consolidation, all 339 public source files matched the
preceding archived source hashes. This consolidation changes documentation only.

| Check | Observed result and reuse boundary |
| --- | --- |
| Ordinary Go tests / race / vet | Forty packages passed tests at 03:44 and race at 03:51; vet passed at 03:47. Default-build production code is unchanged since those checks; subsequent tagged canary edits are covered below. |
| Tagged local canary | Tests passed at 04:28 and 04:31, race at 04:33, vet at 04:32, owner build at 04:33 and the security demo at 04:32. No later Go source edits. |
| Wider tagged selection | The 03:48 selection failed because the historical native integration test lacked `codex` in its closed PATH. An explicit offline adapter follow-up passed at 03:49; selected provider/runtime/canary packages passed, including diagnostic test additions made during the earlier check sequence. The full tagged selection is not recorded as passing. |
| Native composition and formal pilot | Retain the dates, environments, assumptions and failures in their linked scope documents. These results are not renewed by this checkpoint. |
| Real-provider acceptance | Both Runs failed. The second ended at 04:52; independent cleanup observations followed at 04:53–04:54. Marker completion, effective authenticated model behavior and the full refresh/revocation acceptance remain open. |

## Next work package

This was the next package proposed at the source checkpoint. Its subsequent
[implementation and evidence](codex-provider-canary.md#actionable-rejection-and-bounded-failure-handling--2026-09-10)
are tracked separately; the checkpoint's original verification results retain their scope.

Prepare **actionable response rejection and bounded failure handling**: closed
typed failure reasons, a closed media classification and operation-scoped state
checked at upstream dispatch authorization. The general guarantee is zero new
dispatch authorizations after a deterministic rejection transition. Previously
authorized work may finish later; four concurrent exchanges is not a universal
four-request total for a Run.

Cover representative response shapes, sequential and concurrent rejection,
transient/other-operation progress, and cancellation/join while callbacks are
active. The provider implementation participates in normal Linux builds, so
select affected ordinary tests/race/vet and the coherent repository checks.
Revisit formal/native evidence only where its assumptions change. Complete the
candidate artifacts and a concrete execution preview together. This package is
not implemented by the checkpoint, and a new real execution needs authorization
covering its exact effects.
