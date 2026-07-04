"""OODA closed loop with an explicit EXPLORE -> VERIFY -> CANON control flow.

PR-9 (GPT 2nd audit): the earlier loop broke on the first success, so a candidate could
never accumulate the required confirmations — promotion was unreachable in the integrated
loop. Now, when a candidate first clears the success bar, the loop does NOT stop: it enters
a VERIFY phase and re-runs the SAME candidate with independent seeds. Promotion happens
only after `min_confirmations` distinct qualifying runs of that candidate. A verify run
that fails the bar abandons the candidate and returns to EXPLORE.

Run:  python -m continuityos.sim.loop --objective X --iters N   (or `cos sim`)
Etaps 8 (gRPC to real Pandora) and 9 (prod stack) remain — see SIM_OS_BUILD_PLAN.
"""
from __future__ import annotations
import argparse
import json
from .contracts import (
    SimulationSpec, Objective, SimulationConstraints, ExecutionBudget,
    StoppingCriteria, CanonicalState, OptimizationDirection, SimStatus,
)
from .pandora_mock import run_simulation
from .pandora_mock import MAX_RUN_COST
from .detector import HallucinationDetector
from .memory_plane import make_memory_plane, candidate_id
from .gateway import GovernanceGateway, Verdict
from .rollback import RollbackLedger, RollbackTrigger, execute_rollback


def _reserve_and_run(spec, budget_left, seed=None):
    """Affordability preflight (PR-9.2, GPT audit): RESERVE the bounded worst-case run
    cost BEFORE executing, so a run can never push the budget below zero. Returns
    (result_or_None, new_budget, affordable). If unaffordable, the run is NOT invoked."""
    if budget_left < MAX_RUN_COST:
        return None, budget_left, False               # cannot afford -> do not run
    reserved = budget_left - MAX_RUN_COST             # hold worst-case
    res = run_simulation(spec, seed=seed)
    actual = res.resource_consumption.compute_tokens_used
    return res, reserved + (MAX_RUN_COST - actual), True   # settle: release unused reserve


def build_spec(objective_name: str, params: dict, provenance: list) -> SimulationSpec:
    # NOTE (P1-6): hard_bounds=2.0 and empty CanonicalState are DEMO defaults. A real
    # deployment injects the operator's actual canon; the gateway enforces whatever is loaded.
    return SimulationSpec(
        objective=Objective(primary_metric=objective_name, target_value=1.0,
                            optimization_direction=OptimizationDirection.MAXIMIZE),
        parameters=params,
        constraints=SimulationConstraints(hard_bounds={k: 2.0 for k in params}),
        budget=ExecutionBudget(),
        stopping_criteria=StoppingCriteria(success_threshold=0.95, failure_threshold=0.01,
                                           plateau_patience=3, plateau_min_delta=1e-3),
        operator_canon=CanonicalState(),
        provenance=provenance,
    ).finalize()


def run_loop(objective_name: str, iters: int, verbose: bool = True,
             allow_stub: bool = False, policy=None) -> dict:
    mem = make_memory_plane(allow_stub=allow_stub, policy=policy)   # fail-closed unless stub opt-in
    detector = HallucinationDetector()
    gateway = GovernanceGateway()
    rb_ledger = RollbackLedger()
    params = {"x": 0.05, "y": 0.9}
    budget_total = 50_000
    budget_left = budget_total
    best = -1.0
    stale = 0
    provenance: list = []
    stop_reason = "max_iters"
    i = 0

    def _rollback(objective, trigger, detail):
        ev = execute_rollback(mem, objective, trigger, rb_ledger, detail)
        if verbose:
            tag = "ROLLBACK FAILED" if ev.failed else f"rollback -> canon #{ev.restored_ref}"
            print(f"  {trigger.value}: {detail} -> {tag}")
        return ev

    for i in range(1, iters + 1):
        spec = build_spec(objective_name, params, provenance)
        decision = gateway.evaluate(spec, budget_left, budget_total)
        if decision.verdict == Verdict.DENY:
            ev = _rollback(objective_name, RollbackTrigger.GATEWAY_DENY, decision.reasons[0])
            stop_reason = "rollback_failed" if ev.failed else "gateway_deny"; break
        if decision.verdict == Verdict.HOLD:
            ev = _rollback(objective_name, RollbackTrigger.BUDGET_HOLD, decision.reasons[0])
            stop_reason = "rollback_failed" if ev.failed else "budget_hold"; break

        # P0 (PR-9.2): reserve the next run's bounded cost BEFORE running — never overrun.
        result, budget_left, affordable = _reserve_and_run(spec, budget_left)
        if not affordable:
            ev = _rollback(objective_name, RollbackTrigger.BUDGET_HOLD,
                           "cannot afford next run (budget reservation)")
            stop_reason = "rollback_failed" if ev.failed else "budget_hold"; break
        metric = result.metrics[objective_name]
        mem.record(spec, result)
        provenance = [spec.spec_id]
        improved = metric - best
        best = max(best, metric)
        stale = 0 if improved > spec.stopping_criteria.plateau_min_delta else stale + 1
        sig = detector.observe(spec.parameters, metric, spec.spec_id)
        if verbose:
            print(f"iter {i}: EXPLORE {decision.verdict.value} metric={metric:.4f} "
                  f"best={best:.4f} budget={budget_left} spec={spec.spec_id[:8]}")

        # --- VERIFY phase (P0-B): a promising candidate must replicate before canon ---
        if metric >= spec.stopping_criteria.success_threshold:
            cid = candidate_id(spec)
            promoted = False
            verify_halted = False
            for vseed in range(1, mem.policy.min_confirmations * 3 + 1):
                # P0-1 (GPT 3rd audit): VERIFY must NOT bypass the budget/governance gate.
                vdec = gateway.evaluate(spec, budget_left, budget_total)
                if vdec.verdict in (Verdict.HOLD, Verdict.DENY):
                    trig = (RollbackTrigger.BUDGET_HOLD if vdec.verdict == Verdict.HOLD
                            else RollbackTrigger.GATEWAY_DENY)
                    ev = _rollback(objective_name, trig, f"verify halted: {vdec.reasons[0]}")
                    stop_reason = ("rollback_failed" if ev.failed else
                                   ("budget_hold" if vdec.verdict == Verdict.HOLD else "gateway_deny"))
                    verify_halted = True; break
                # P0 (PR-9.2): affordability preflight — reserve before the verify run.
                vres, budget_left, affordable = _reserve_and_run(spec, budget_left, seed=vseed)
                if not affordable:
                    ev = _rollback(objective_name, RollbackTrigger.BUDGET_HOLD,
                                   "cannot afford verify run (budget reservation)")
                    stop_reason = "rollback_failed" if ev.failed else "budget_hold"
                    verify_halted = True; break
                vmetric = vres.metrics[objective_name]
                rec = mem.record(spec, vres, seed=vseed)         # P1-3: keyed by seed
                if verbose:
                    print(f"        VERIFY(cid {cid}) run#{vseed} metric={vmetric:.4f} -> {rec['canon']}")
                if str(rec["canon"]).startswith("verified"):
                    promoted = True; break
                if vmetric < mem.policy.verify_threshold:
                    mem.reject_candidate(cid)                    # P0-2: clear stale evidence
                    if verbose:
                        print(f"        candidate abandoned (below verify bar {mem.policy.verify_threshold}); evidence cleared")
                    break
            if verify_halted:
                break
            if promoted:
                stop_reason = "verified_success"; break
            if result.next_candidate:
                params = result.next_candidate.parameters
            continue

        if sig.is_hallucination:
            ev = _rollback(objective_name, RollbackTrigger.HALLUCINATION_LOOP, sig.detail)
            stop_reason = "rollback_failed" if ev.failed else "hallucination_loop"; break
        if result.next_candidate:
            params = result.next_candidate.parameters

    sz = mem.sizes()
    last_rb = rb_ledger.last()
    summary = {"objective": objective_name, "iterations": i, "best_metric": round(best, 6),
               "stop_reason": stop_reason, "canon_size": sz["canon"],
               "experiment_size": sz["experiment"], "budget_left": budget_left,
               "rollbacks": len(rb_ledger.events),
               "last_rollback": (last_rb.trigger.value if last_rb else None),
               "rollback_failed": bool(last_rb and last_rb.failed)}
    if verbose:
        print("SUMMARY:", json.dumps(summary))
    return summary


def main(argv=None):
    ap = argparse.ArgumentParser(prog="cos sim", description="Sim-OS OODA loop (mock Pandora)")
    ap.add_argument("--objective", default="test_metric")
    ap.add_argument("--iters", type=int, default=8)
    ap.add_argument("--mock", action="store_true", help="use ephemeral in-memory plane (no durable store)")
    a = ap.parse_args(argv)
    run_loop(a.objective, a.iters, allow_stub=a.mock)
    return 0


if __name__ == "__main__":
    main()
