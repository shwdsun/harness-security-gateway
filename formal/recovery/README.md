# Uncertain-create recovery experiment

This opt-in pilot compares ordinary stateful property tests with an actual SMT
invariant check connected to the existing Go/SQLite recovery implementation.
It adds no product behavior or runtime authority. Normal builds/tests do not
require Z3; the extra implementation tests use the `formalpilot` build tag.

## Question and scope

Can recovery publish completion or release a writable workspace while an
uncertain Create can still materialize a runtime, or a runtime remains?
Can recovery itself dispatch another Create?

The trial starts **after one Create returned an uncertain result**. One Run,
one writable workspace, one known intent boot, no bound runtime reference,
new-only mock target, no credentials, and one serialized recovery owner.
It exercises actual `Controller.reconcileRun`, its cleanup helpers and real
SQLite transactions. Only the external runtime and specified failures are fake.
It does not exercise initial dispatch, controller scheduling, the wire protocol,
session continuation, enrollment, legacy unknown boots or a live container.

## Evidence and trust boundary

`check.py` checks initialization and preservation of an inductive invariant
for every abstract action using **Z3 4.16.0**. An unsatisfiable obligation means
no violating assignment exists in this abstraction, trusting the encoding and
solver. The induction covers arbitrary action-sequence length; it does not
generalize the fixed one-Run domain or prove the Go implementation refines it.
There is no independent proof-certificate checker in this pilot.

The checked-in corpus contains shortest representative traces to each reachable
abstract state, selected failure/response-loss/reopen schedules, and schedules
from two bad-model counterexamples. The Go test compares every observed state
along those traces. This is sampled **implementation conformance**, even though
the abstract model's invariant is inductive. State coverage is not coverage of
every implementation history or internal interleaving.

The ordinary baseline uses 64 deterministic seeds, 16 actions each, without
consulting model states. It asserts safety using directly observed durable
fields, fake runtime objects, pending late creation and recorded Create calls.
Both arms use the same fixtures and the same after-absent-lookup late-completion
hook. Each trace also has a healthy changed-boot recovery suffix to reject a
permanently stuck implementation. This is bounded progress evidence, not a
temporal liveness proof. Seeds/action logs are replayable; there is no automatic
shrinker in this small baseline.

The healthy suffix explicitly simulates a changed boot. After exact removal
followed by a failed intent-clear transaction, this model and the implementation
retain the fence in the same boot: the durable state no longer records proof
of that removal. An explicit trace shows release after a changed boot. This is
an availability consequence, not evidence of automatic recovery without reboot.

### Explicit assumptions

1. One authorized Create has at most one object materialization. After an exact
   successful removal, that same operation cannot materialize/revive it again.
   `handler` means an **unspent ability to materialize**, not OS process liveness.
   A server handler may remain alive after materialization without violating
   this model. The pilot does not establish this contract for Docker.
   In particular, downstream retries or duplicate delivery of the same create
   operation must not bypass it. This ability is a ghost observation in the
   fixture, not something production code can query directly.
2. A genuine changed host boot kills old materialization authority, but existing
   objects may survive. Equal/unequal epochs are sound equality tokens, not wall
   clocks; no time-based epoch comparison or lease expiry is modeled.
3. Lookup identifies exactly the authorized object at its observation point.
   A successful exact cleanup proves removal/quiescence. External object
   resurrection, other actors and ambiguous identity are outside this model.
   Indeterminate/partially materialized lookup or cleanup results are not
   silently treated as exact successful cleanup by this assumption.
4. SQLite transactions are atomic and durable at the API boundaries used here.
   The occupied workspace has no automatic lease expiration. Reopen in this
   fixture is a clean close/reopen, **not** a SIGKILL, fsync or power-loss test.
5. Recovery is serialized. The abstraction summarizes a complete recovery call,
   exposing outcomes at stage, clear and publish transactions and one explicit
   in-call late-materialization schedule. It is not an abstraction proof of all
   controller/internal/external concurrency.

Removing assumptions 1 or atomic publication produces modeled counterexamples.
Those are **assumption sensitivity controls**, not confirmed product bugs.
Existing crash, transaction-rollback, IPC and real-runtime evidence retain
their independent responsibilities. No implementation tests are removed.

### Model-to-code mapping

| Model observation/action | Actual trial connection |
| --- | --- |
| `pending` | `Run.RuntimeIntentPending` read from SQLite |
| `fence` | `Run.WorkspaceLockHeld` derived from the durable workspace lock |
| `done`, `staged` | public Run state and `Run.TerminalPending` |
| `handler`, `object` | fixture's armed late creation and actual fake-runtime object table |
| `same` | fixed known intent boot vs controller's current boot token |
| recovery | `internal/sandboxcontroller/reconcile.go`: `reconcileRun`, `reconcilePendingIntent` |
| clear | real `sandboxstore.ClearRuntimeIntent`; before-call failure or after-commit response loss |
| publish | real `sandboxstore.ConfirmRuntimeStopped`; before-call failure or after-commit response loss |
| stage | real `sandboxstore.StageTerminal`; before-call failure or after-commit response loss |
| removal | real controller cleanup with fake Remove failure/response loss and Inspect read-back |
| `lookup_late` | fake lookup saves absence, materializes the object, returns the earlier absence to the actual recovery code |
| `restart` | close/reopen real store, preserving the fake external handler/object |

Clear-response loss is resolved by existing durable read-back. Publication and
staging response loss can return an error after committing; subsequent actions
read committed state. Read-back failure, malformed states, transaction-internal
failure and other scheduling points are not newly covered by this pilot.

## Running it

Obtain the official portable Z3 4.16.0 distribution from the
[Z3 release](https://github.com/Z3Prover/z3/releases/tag/z3-4.16.0).
The x64 glibc 2.39 ZIP SHA256 is
`7288c49a5bd6dbafd7b0b0d1f65956b91672da24b08f09242919af159be3418e`.
Use an appropriate host; do not install it into the application image.

From the repository, with `Z3_PILOT_DIR` pointing to the extracted distribution:

```sh
PYTHONDONTWRITEBYTECODE=1 \
Z3_LIBRARY_PATH="$Z3_PILOT_DIR/bin" \
PYTHONPATH="$Z3_PILOT_DIR/bin/python" python3 formal/recovery/check.py

go test -tags=formalpilot -count=1 ./internal/sandboxcontroller -run '^TestRecoveryPilot'
go test -tags=formalpilot -race -count=1 ./internal/sandboxcontroller -run '^TestRecoveryPilot'
```

The checker rejects `unknown`, an unsatisfied obligation, wrong solver version,
missing positive witnesses, undetected negative controls or a stale corpus.
It also reports equivalent action relations: `reconcile`, `clear_lost`,
`publish_lost` and `remove_lost` have identical modeled post-states. They still
exercise different failure/read-back paths in Go. Raw query/trace counts are
not counts of distinct guarantees. A dedicated witness requires `lookup_late`
to actually materialize an object while retaining the intent and fence.
After reviewing a model change, explicitly use `--write-traces` to regenerate
`traces.json`. Running both commands is a conventional CI-compatible entrypoint;
this pilot does not add a CI service, mandatory solver download or new Go module.

Revisit the mapping when recovery/cleanup, the stage/clear/publication method
bodies, relevant schema semantics or these assumptions change. Merely keeping
the model and implementation tests in CI does not establish that mapping.

### Runtime-owner resources (2026-09-10)

The controller now calls `Runtime.CloseRunResources(runID)` before held-source
release and `ConfirmRuntimeStopped`, including an absent container or a failure
before container creation. Docker also joins the per-Run provider endpoint
before exact container removal. A failed/timed-out join retains the unpublished
terminal and credential occupancy for reconciliation; recovery never recreates
an endpoint. Process death closes the old owner's descriptors, while existing
durable intent and generation fences still govern container cleanup.

This strengthens the implementation obligation behind assumption 3. The
one-Run mock model has no provider callbacks or credential ownership: its fake
runtime implements a vacuous successful join. The induction is unchanged and
does **not** prove endpoint quiescence. `TestRunResourceJoinPrecedesCredentialCloseAndPublication`
connects failed/recovered joins to real store publication, and endpoint tests
hold a response-body owner across cancellation to distinguish Stop from joined
Close. Native composition supplies mount/bootstrap/lifetime evidence separately.
Progress depends on owned I/O being interruptible and cleanup observations
recovering; an uncooperative callback remains a cleanup failure, not a pass.

## Comparison protocol

Use the same three isolated source mutations against existing lifecycle
regressions, the independent seeded property oracle, and model-trace replay:
same-boot absence accepted as a clear; ignored exact-removal failure; and a
speculative second Create from pending-intent recovery. The first two also have
SMT counterexamples. The third is **test-only**: the model omits initial dispatch
and contains no Create-count proof. Do not credit its detection to SMT.

Report mutation detection separately from compilation failure, solver time
separately from test/fixture and setup cost, and abstract guarantees separately
from implementation conformance. A successful experiment need not find a new
bug. No test deletion or broad return-on-investment claim follows from this
single sample; maintenance across later semantic changes is not yet measured.
