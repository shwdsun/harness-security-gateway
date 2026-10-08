#!/usr/bin/env python3
"""A single recovery experiment, not a verifier for the Go implementation.

Requires Z3 4.16.0 Python bindings. No downloads or installation happen here.
Induction checks all lengths in this seven-Boolean abstraction; BMC is used
only for short negative controls. See README.md for the external assumptions.
"""

import argparse
from collections import deque
import hashlib
import json
from pathlib import Path
import time

import z3

FIELDS = ("pending", "fence", "done", "staged", "handler", "object", "same")
ACTIONS = (
    "reconcile", "late", "restart", "reboot", "remove_fail", "clear_fail",
    "publish_fail", "lookup_late", "clear_lost", "publish_lost", "stage_fail",
    "stage_lost", "remove_lost",
)
INITIAL = dict(zip(FIELDS, (True, True, False, False, True, False, True)))


def state(prefix):
    return {name: z3.Bool(f"{prefix}_{name}") for name in FIELDS}


def equal(left, right):
    return z3.And(*(left[k] == right[k] for k in FIELDS))


def safety(s):
    risk = z3.Or(s["handler"], s["object"])
    return z3.And(
        z3.Implies(risk, z3.And(s["fence"], z3.Not(s["done"]))),
        z3.Implies(z3.Not(s["pending"]), z3.Not(risk)),
        s["done"] == z3.Not(s["fence"]),
    )


def invariant(s):
    return z3.And(
        safety(s),
        # "handler" means an unspent ability to materialize the object,
        # not that the external server process has stopped executing.
        # One-shot materialization and no resurrection are assumptions.
        z3.Implies(s["handler"], z3.And(s["same"], z3.Not(s["object"]))),
        z3.Implies(s["staged"], z3.Not(s["done"])),
        z3.Implies(z3.Not(s["pending"]), z3.Or(s["staged"], s["done"])),
    )


def step(s, action, variant="correct"):
    """Post-call abstraction; faults expose separate durable transactions.

    lookup_late explicitly interleaves materialization after an absent
    observation, before the real recovery helper uses that observation.
    clear_lost/removal_lost include successful read-back in this scope.
    """
    out = dict(s)
    if action == "late":
        out["object"] = z3.Or(s["object"], s["handler"])
        out["handler"] = s["handler"] if variant == "resurrection" else z3.BoolVal(False)
        return out
    if action == "restart":
        return out
    if action == "reboot":
        out.update(same=z3.BoolVal(False), handler=z3.BoolVal(False))
        return out

    active = z3.Not(s["done"])
    staged = z3.Or(s["staged"], z3.And(active, action != "stage_fail"))
    proceed = z3.And(active, z3.Or(s["staged"], action not in ("stage_fail", "stage_lost")))
    late = z3.And(proceed, z3.Not(s["object"]), s["handler"], action == "lookup_late")
    removed = z3.And(proceed, s["object"], action != "remove_fail")
    clear_allowed = z3.And(proceed, z3.Or(
        removed,
        z3.And(z3.Not(s["object"]), z3.Or(z3.Not(s["same"]), variant == "same_epoch_absence")),
        z3.And(s["object"], variant == "ignore_remove_failure"),
    ))
    cleared = z3.And(s["pending"], clear_allowed, action != "clear_fail")
    pending = z3.And(s["pending"], z3.Not(cleared))
    removal_ok = z3.Or(z3.Not(s["object"]), removed, variant == "ignore_remove_failure")
    publish = z3.And(proceed, removal_ok, z3.Not(pending), action != "publish_fail")
    out.update(
        pending=pending,
        fence=z3.And(s["fence"], z3.Not(publish)),
        done=z3.Or(s["done"], z3.And(publish, variant != "split_publish")),
        staged=z3.And(staged, z3.Not(publish)),
        handler=z3.And(s["handler"], z3.Not(late)),
        object=z3.And(z3.Or(s["object"], late), z3.Not(removed)),
    )
    return out


def solve(formula):
    solver = z3.Solver()
    solver.set(timeout=10000)
    solver.add(formula)
    result = solver.check()
    if result == z3.unknown:
        raise RuntimeError(f"solver returned unknown: {solver.reason_unknown()}")
    return result, solver


def concrete(s, action):
    result = step({k: z3.BoolVal(v) for k, v in s.items()}, action)
    values = {k: z3.simplify(v) for k, v in result.items()}
    if any(not (z3.is_true(v) or z3.is_false(v)) for v in values.values()):
        raise RuntimeError("non-ground concrete transition")
    return {k: z3.is_true(v) for k, v in values.items()}


def action_classes(s):
    # Different real fault points can have identical observable model effects.
    # Report this instead of presenting each raw query as a distinct guarantee.
    groups = []
    for action in ACTIONS:
        for group in groups:
            difference = z3.And(invariant(s), z3.Not(equal(step(s, action), step(s, group[0]))))
            result, _ = solve(difference)
            if result == z3.unsat:
                group.append(action)
                break
        else:
            groups.append([action])
    return groups


def trace(name, actions):
    states = [INITIAL]
    for action in actions:
        states.append(concrete(states[-1], action))
    return {"name": name, "actions": actions, "states": states}


def counterexample(variant):
    # These are deliberately bounded diagnostics, not the inductive proof.
    for depth in range(1, 6):
        states = [state(f"bmc_{i}") for i in range(depth + 1)]
        choices = [z3.Int(f"action_{i}") for i in range(depth)]
        formula = [equal(states[0], INITIAL), z3.Not(safety(states[-1]))]
        for i in range(depth):
            formula.append(z3.Or(*(z3.And(choices[i] == j, equal(states[i + 1], step(states[i], a, variant)))
                                   for j, a in enumerate(ACTIONS))))
        result, solver = solve(z3.And(*formula))
        if result == z3.sat:
            # Choose a stable, lexicographically first shortest diagnostic.
            # Otherwise equivalent solver witnesses can churn the corpus.
            for choice in choices:
                for j in range(len(ACTIONS)):
                    solver.push()
                    solver.add(choice == j)
                    candidate = solver.check()
                    solver.pop()
                    if candidate == z3.unknown:
                        raise RuntimeError("unknown while canonicalizing counterexample")
                    if candidate == z3.sat:
                        solver.add(choice == j)
                        break
            if solver.check() != z3.sat:
                raise RuntimeError("counterexample canonicalization failed")
            model = solver.model()
            actions = [ACTIONS[model.eval(a).as_long()] for a in choices]
            observed = [{k: z3.is_true(model.eval(s[k], model_completion=True)) for k in FIELDS} for s in states]
            return {"variant": variant, "depth": depth, "actions": actions, "states": observed}
    raise RuntimeError(f"negative control {variant} not detected within five steps")


def corpus():
    # Shortest representative traces to every reachable abstract state.
    # This is NOT every implementation history or internal interleaving.
    paths, queue = {tuple(INITIAL.values()): []}, deque([INITIAL])
    while queue:
        before = queue.popleft()
        for action in ACTIONS:
            after = concrete(before, action)
            key = tuple(after.values())
            if key not in paths:
                paths[key] = paths[tuple(before.values())] + [action]
                queue.append(after)
    traces = [trace(f"reachable_{i}", actions) for i, actions in enumerate(paths.values())]
    # Shared schedules for boundary failure/response-loss and reopen checks.
    for fault in ACTIONS:
        if fault in ("late", "restart", "reboot"):
            continue
        traces.append(trace(f"visible_{fault}", ["late", fault, "restart", "reconcile"]))
    traces.extend([
        trace("absence_late_during_lookup", ["lookup_late", "restart", "reconcile"]),
        trace("absence_staged_response_lost", ["stage_lost", "restart", "lookup_late", "reconcile"]),
        trace("absent_changed_boot_clear_failure", ["reboot", "clear_fail", "restart", "reconcile"]),
        trace("absent_changed_boot_clear_lost", ["reboot", "clear_lost", "restart", "reconcile"]),
        trace("removed_clear_failed_then_boot", ["late", "clear_fail", "restart", "reboot", "reconcile"]),
    ])
    return traces, len(paths)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write-traces", action="store_true", help="explicitly regenerate the checked-in corpus")
    args = parser.parse_args()
    if z3.get_version_string() != "4.16.0":
        raise RuntimeError("this pilot pins Z3 4.16.0; re-audit before changing the solver")
    started = time.monotonic()
    s = state("induction")
    obligations = {"initialization": z3.And(equal(s, INITIAL), z3.Not(invariant(s)))}
    obligations.update({f"preservation/{a}": z3.And(invariant(s), z3.Not(invariant(step(s, a)))) for a in ACTIONS})
    for name, formula in obligations.items():
        result, solver = solve(formula)
        if result != z3.unsat:
            raise RuntimeError(f"{name} failed: {solver.model()}")

    controls = [counterexample(v) for v in ("same_epoch_absence", "ignore_remove_failure", "split_publish", "resurrection")]
    traces, reachable = corpus()
    for control in controls[:2]:
        # Replay the bad-model schedule against the correct transition oracle.
        traces.append(trace(f"counterexample_{control['variant']}", control["actions"]))
    data = ("[\n" + ",\n".join(json.dumps(t, separators=(",", ":")) for t in traces) + "\n]\n").encode()
    path = Path(__file__).with_name("traces.json")
    if args.write_traces:
        path.write_bytes(data)
    elif not path.exists() or path.read_bytes() != data:
        raise RuntimeError("corpus differs: review the model change, then explicitly --write-traces")
    # Non-vacuity: these outcomes must actually be reachable, not only safe.
    ends = [t["states"][-1] for t in traces]
    witnesses = (
        any(s["done"] and not s["fence"] for s in ends),
        any(not s["pending"] and s["fence"] for s in ends),
        any(s["object"] and not s["handler"] for s in ends),
        any(a == "lookup_late" and before["handler"] and not before["object"]
            and after["object"] and not after["handler"] and after["pending"] and after["fence"]
            for t in traces for a, before, after in zip(t["actions"], t["states"], t["states"][1:])),
    )
    if not all(witnesses):
        raise RuntimeError(f"missing non-vacuity witnesses: {witnesses}")
    print(json.dumps({
        "solver": z3.get_version_string(), "inductive_obligations_unsat": len(obligations),
        "action_equivalence_classes_under_invariant": action_classes(s),
        "reachable_abstract_states": reachable, "conformance_traces": len(traces),
        "corpus_sha256": hashlib.sha256(data).hexdigest(),
        "negative_controls": controls, "wall_seconds": round(time.monotonic() - started, 4),
        "claim": "conditional abstract-model induction, not Go refinement or a live-runtime proof",
    }, indent=2))


if __name__ == "__main__":
    main()
