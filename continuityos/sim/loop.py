"""OODA closed loop: Gateway -> Spec -> Pandora -> Memory -> Detector -> Rollback.

The full self-improving simulation loop (ContinuityOS <-> Pandora) on the mock engine.
Run:  python -m continuityos.sim.loop --objective X --iters N   (or `cos sim run`)

Etaps 4-7 integrated: real risk-scoring gateway (§2), bitemporal canon/experiment
memory (§3.3), hallucination detector (§4.1), autonomous rollback (§4.2). Etaps 8-9
(gRPC to real Pandora, prod stack Temporal/OPA/XTDB/Ray) are TODO — see
Trade/HANDOFF/SIM_OS_BUILD_PLAN_20260704.md.
"""
from __future__ import annotations
import argparse
import json
from .contracts import (
    SimulationSpec, Objective, SimulationConstraints, ExecutionBudget,
    StoppingCriteria, CanonicalState, OptimizationDirection, SimStatus,
)
from .pandora_mock import run_simulation
from .detector import HallucinationDetector
from .memory_plane import make_memory_plane
from .gateway import GovernanceGateway, Verdict
from .rollback import RollbackLedger, RollbackTrigger, execute_rollback


def build_spec(objective_name: str, params: dict, provenance: list) -> SimulationSpec:
    # NOTE (P1-6, GPT audit): the hard_bounds=2.0 and empty CanonicalState below are
    # DEMO defaults for the mock loop. A real deployment must inject the operator's
    # actual canon (limits, forbidden regions) into constraints/operator_canon — the
    # gateway then enforces the real rules, not these placeholders.
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


def run_loop(objective_name: str, iters: int, verbose: bool = True) -> dict:
    mem = make_memory_plane()               # §3.3 bitemporal canon/experiment
    detector = HallucinationDetector()      # §4.1 epistemic-safety
    gateway = GovernanceGateway()           # §2 risk-scoring gate
    rb_ledger = RollbackLedger()            # §4.2 autonomous rollback
    params = {"x": 0.05, "y": 0.9}          # deliberately off-optimum (0.5,0.5)
    budget_total = 50_000
    budget_left = budget_total
    best = -1.0
    stale = 0
    provenance: list = []
    stop_reason = "max_iters"
    i = 0

    for i in range(1, iters + 1):
        spec = build_spec(objective_name, params, provenance)
        decision = gateway.evaluate(spec, budget_left, budget_total)
        verdict = decision.verdict
        if verdict == Verdict.DENY:
            stop_reason = "gateway_deny"
            ev = execute_rollback(mem, objective_name, RollbackTrigger.GATEWAY_DENY,
                                  rb_ledger, decision.reasons[0])
            if verbose:
                print(f"iter {i}: DENY (risk {decision.risk_score}) — {decision.reasons[0]}"
                      f" -> rollback to canon #{ev.restored_ref}")
            break
        if verdict == Verdict.HOLD:
            stop_reason = "budget_hold"
            ev = execute_rollback(mem, objective_name, RollbackTrigger.BUDGET_HOLD,
                                  rb_ledger, decision.reasons[0])
            if verbose:
                print(f"iter {i}: HOLD (risk {decision.risk_score}) — {decision.reasons[0]}"
                      f" -> rollback to canon #{ev.restored_ref}")
            break

        result = run_simulation(spec)
        budget_left -= result.resource_consumption.compute_tokens_used
        metric = result.metrics[objective_name]
        confident = result.status == SimStatus.SUCCESS and metric > best
        mem.record(spec, result, confident)
        provenance = [spec.spec_id]

        improved = metric - best
        best = max(best, metric)
        stale = 0 if improved > spec.stopping_criteria.plateau_min_delta else stale + 1

        sig = detector.observe(spec.parameters, metric, spec.spec_id)   # §4.1

        if verbose:
            print(f"iter {i}: verdict={verdict.value} metric={metric:.4f} best={best:.4f} "
                  f"budget={budget_left} energy={sig.energy} spec={spec.spec_id[:8]}")

        if metric >= spec.stopping_criteria.success_threshold:
            stop_reason = "success"
            break
        if sig.is_hallucination:
            stop_reason = "hallucination_loop"
            ev = execute_rollback(mem, objective_name, RollbackTrigger.HALLUCINATION_LOOP,
                                  rb_ledger, sig.detail)
            if verbose:
                print(f"  !! hallucination ({sig.detail}) -> rollback to canon #{ev.restored_ref}")
            break
        if result.next_candidate:
            params = result.next_candidate.parameters

    sz = mem.sizes()
    last_rb = rb_ledger.last()
    summary = {"objective": objective_name, "iterations": i, "best_metric": round(best, 6),
               "stop_reason": stop_reason, "canon_size": sz["canon"],
               "experiment_size": sz["experiment"], "budget_left": budget_left,
               "rollback_ref": mem.rollback_ref(objective_name),
               "rollbacks": len(rb_ledger.events),
               "last_rollback": last_rb.trigger.value if last_rb else None}
    if verbose:
        print("SUMMARY:", json.dumps(summary))
    return summary


def main(argv=None):
    ap = argparse.ArgumentParser(prog="cos sim", description="Sim-OS OODA loop (mock Pandora)")
    ap.add_argument("--objective", default="test_metric")
    ap.add_argument("--iters", type=int, default=5)
    a = ap.parse_args(argv)
    run_loop(a.objective, a.iters)
    return 0


if __name__ == "__main__":
    main()
