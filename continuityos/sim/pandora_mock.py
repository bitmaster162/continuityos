"""Mock Pandora — stateless sim engine stub (§ etap 2, cp-0318 scaffold).

Lets the OODA loop run end-to-end WITHOUT the real Pandora. Replace with a gRPC
client to the real parametric engine later (§1 / §5 Ray/Isaac). The mock does a
primitive hill-climb toward the objective target so the loop shows convergence,
plateau, and budget behaviour.
"""
from __future__ import annotations
import random
import time
from .contracts import (
    SimulationSpec, SimulationResult, SimStatus, FailureMode,
    ResourceConsumption, NextCandidateRecommendation, Anomaly,
    OptimizationDirection,
)

# Bounded worst-case compute cost of a single run. The control loop RESERVES this
# before each run so budget can never be crossed below zero (PR-9.2). A real Pandora
# must declare its own max_compute_tokens in the run contract.
MAX_RUN_COST = 5000


def _score(params: dict, objective) -> float:
    """Toy objective surface: smooth bowl around an implicit optimum at 0.5 per param,
    scaled toward the target. Deterministic-ish with light noise for realism."""
    if not params:
        return 0.0
    dist = sum((v - 0.5) ** 2 for v in params.values()) / len(params)
    quality = max(0.0, 1.0 - dist)                 # 0..1, peaks when params ~0.5
    return quality * objective.target_value


def run_simulation(spec: SimulationSpec, seed: int | None = None) -> SimulationResult:
    """Execute one stateless simulation for the given spec."""
    t0 = time.time()
    rng = random.Random(seed if seed is not None else spec.spec_id)

    # constraint check (Pandora terminates on breach)
    for p, v in spec.parameters.items():
        cap = spec.constraints.hard_bounds.get(p)
        if cap is not None and abs(v) > cap:
            return SimulationResult(
                spec_id=spec.spec_id, status=SimStatus.FAILURE,
                metrics={spec.objective.primary_metric: 0.0},
                failure_mode=FailureMode.CONSTRAINT_VIOLATION,
                anomalies=[Anomaly("constraint", 1.0, f"{p}={v} exceeds {cap}")],
                resource_consumption=ResourceConsumption(1000, time.time() - t0, 1),
            )

    base = _score(spec.parameters, spec.objective)
    metric = base + rng.uniform(-0.02, 0.02) * spec.objective.target_value
    metric = max(0.0, metric)

    # gradient-ish nudge for the next candidate: pull each param toward 0.5
    nxt = {p: v + 0.5 * (0.5 - v) + rng.uniform(-0.05, 0.05)
           for p, v in spec.parameters.items()}
    expected = _score(nxt, spec.objective) - base

    sc = spec.stopping_criteria
    if metric >= sc.success_threshold:
        status = SimStatus.SUCCESS
    elif metric <= sc.failure_threshold:
        status = SimStatus.FAILURE
    else:
        status = SimStatus.SUCCESS  # in-progress iterations report ok; loop decides plateau

    return SimulationResult(
        spec_id=spec.spec_id, status=status,
        metrics={spec.objective.primary_metric: round(metric, 6)},
        resource_consumption=ResourceConsumption(
            compute_tokens_used=rng.randint(500, 5000),
            wall_time_seconds=round(time.time() - t0, 4),
            api_calls_used=1,
        ),
        next_candidate=NextCandidateRecommendation(
            parameters={k: round(v, 6) for k, v in nxt.items()},
            expected_gain=round(expected, 6),
            rationale="hill-climb toward param optimum (mock)",
        ),
    )
