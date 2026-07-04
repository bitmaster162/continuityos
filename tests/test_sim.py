"""Sim-OS invariant tests (PR-9 / PR-9.1, GPT audits). Guard the hardened guarantees so
CI catches regressions — the module self-tests alone weren't enough."""
import tempfile, os
from types import SimpleNamespace
from continuityos.sim.contracts import (
    SimulationSpec, Objective, SimulationConstraints, ExecutionBudget,
    StoppingCriteria, CanonicalState, OptimizationDirection,
    SimulationResult, SimStatus, ResourceConsumption, NextCandidateRecommendation,
)
from continuityos.sim.memory_plane import make_memory_plane, PromotionPolicy, candidate_id, RealMemoryPlane
from continuityos.sim.gateway import GovernanceGateway, Verdict
from continuityos.sim.rollback import RollbackLedger, RollbackTrigger, execute_rollback
import continuityos.sim.loop as L


def _spec(objective="edge", params=None, budget_tokens=100_000):
    return SimulationSpec(
        objective=Objective(objective, 1.0, OptimizationDirection.MAXIMIZE),
        parameters=params or {"x": 0.4},
        constraints=SimulationConstraints(hard_bounds={"x": 2.0}),
        budget=ExecutionBudget(compute_tokens=budget_tokens),
        stopping_criteria=StoppingCriteria(0.95, 0.01),
        operator_canon=CanonicalState(),
    ).finalize()

def _res(m):
    return SimpleNamespace(metrics={"edge": m}, status=SimpleNamespace(value="success"))

def _sim(spec, metric, tokens=100):
    return SimulationResult(
        spec_id=spec.spec_id, status=SimStatus.SUCCESS, metrics={spec.objective.primary_metric: metric},
        resource_consumption=ResourceConsumption(tokens, 0.0, 1),
        next_candidate=NextCandidateRecommendation(parameters=dict(spec.parameters)))

def _pol(min_conf=2):
    return PromotionPolicy(verify_threshold=0.9, min_confirmations=min_conf)


# --- P0-1: spec_id is a full content hash ---
def test_spec_id_covers_all_material_fields():
    assert _spec(budget_tokens=100).spec_id != _spec(budget_tokens=1_000_000).spec_id


# --- P0-A: confirmations are candidate-scoped, not objective-scoped ---
def test_different_candidates_do_not_co_confirm():
    mp = make_memory_plane(allow_stub=True, policy=_pol())
    mp.record(_spec(params={"x": 0.4}), _res(0.95), seed=1)
    mp.record(_spec(params={"x": 0.9}), _res(0.95), seed=1)   # DIFFERENT candidate
    assert mp.sizes()["canon"] == 0
    mp.record(_spec(params={"x": 0.4}), _res(0.96), seed=2)   # same candidate, new seed -> promote
    assert mp.sizes()["canon"] == 1


# --- P1-3: replication identity is candidate+seed; same seed can't double-count ---
def test_same_candidate_same_seed_no_double_count():
    mp = make_memory_plane(allow_stub=True, policy=_pol())
    sp = _spec(params={"x": 0.4})
    mp.record(sp, _res(0.95), seed=1)
    mp.record(sp, _res(0.95), seed=1)                          # SAME seed
    assert mp.sizes()["canon"] == 0, "same candidate+seed must not count as replication"


# --- P0-2: a rejected candidate loses pending confirmations ---
def test_rejected_candidate_resets_confirmations():
    mp = make_memory_plane(allow_stub=True, policy=_pol())
    sp = _spec(params={"x": 0.4})
    assert mp.record(sp, _res(0.95), seed=1)["confirmations"] == 1
    mp.reject_candidate(candidate_id(sp))
    assert mp.record(sp, _res(0.95), seed=2)["confirmations"] == 1, "reject must restart from zero"
    assert mp.sizes()["canon"] == 0


# --- P0-B: DETERMINISTIC — a good candidate MUST reach verified canon in the loop ---
def test_verification_phase_promotes_deterministically(monkeypatch):
    monkeypatch.setattr(L, "run_simulation", lambda spec, seed=None: _sim(spec, 0.99))
    s = L.run_loop("edge", iters=6, verbose=False, allow_stub=True)
    assert s["stop_reason"] == "verified_success", f"expected promotion, got {s['stop_reason']}"
    assert s["canon_size"] >= 1


# --- P0-1: VERIFY must not bypass the budget gate ---
def test_verify_respects_budget_gate(monkeypatch):
    monkeypatch.setattr(L, "run_simulation", lambda spec, seed=None: _sim(spec, 0.99, tokens=9000))
    s = L.run_loop("edge", iters=6, verbose=False, allow_stub=True, policy=_pol(min_conf=6))
    assert s["stop_reason"] in ("budget_hold", "rollback_failed", "verified_success")
    assert s["budget_left"] >= -9000, f"verify overran the budget gate: {s['budget_left']}"


# --- P0-D: rollback fails closed ---
def test_rollback_failure_is_flagged():
    class Broken:
        def rollback_ref(self, o): return 1
        def restore_to(self, o, r): raise RuntimeError("store down")
    ev = execute_rollback(Broken(), "edge", RollbackTrigger.GATEWAY_DENY, RollbackLedger(), "x")
    assert ev.failed is True

def test_rollback_success_not_flagged():
    class Ok:
        def rollback_ref(self, o): return 5
        def restore_to(self, o, r): return {"restored_canon": r}
    ev = execute_rollback(Ok(), "edge", RollbackTrigger.HALLUCINATION_LOOP, RollbackLedger(), "x")
    assert ev.failed is False and ev.restored_ref == 5


# --- P1-A / P0-C durable: rehydrate + rollback survive a restart ---
def _durable(db, min_conf=2):
    return RealMemoryPlane(db, policy=_pol(min_conf))

def test_rehydrate_restores_current_canon_after_restart():
    db = os.path.join(tempfile.mkdtemp(), "sim.db")
    mp = _durable(db)
    mp.record(_spec(params={"x": 0.4}), _res(0.95), seed=1)
    mp.record(_spec(params={"x": 0.4}), _res(0.96), seed=2)   # -> canon
    ref = mp.rollback_ref("edge"); assert ref is not None
    assert _durable(db).rollback_ref("edge") == ref, "rehydrate must recover current canon from DB"

def test_true_rollback_A_to_B_back_to_A_survives_restart():
    # canon A -> canon B supersedes A -> rollback to A -> restart -> current state IS A
    db = os.path.join(tempfile.mkdtemp(), "sim.db")
    mp = _durable(db)
    mp.record(_spec(params={"x": 0.4}), _res(0.95), seed=1)
    mp.record(_spec(params={"x": 0.4}), _res(0.96), seed=2)   # -> canon A
    a_ref = mp.rollback_ref("edge")
    a_text = mp.m.store.get(a_ref)["text"]
    mp.record(_spec(params={"x": 0.6}), _res(0.97), seed=1)
    mp.record(_spec(params={"x": 0.6}), _res(0.98), seed=2)   # -> canon B supersedes A
    assert mp.rollback_ref("edge") != a_ref, "B must supersede A"
    mp.restore_to("edge", a_ref)                              # rollback B -> A (durable)
    mp2 = _durable(db)                                        # restart
    cur = mp2.rollback_ref("edge")
    assert mp2.m.store.get(cur)["text"] == a_text, \
        "after A->B->rollback(A)->restart, current canon must carry A's state"

def test_broken_store_fails_closed():
    bad = tempfile.mkdtemp()                                  # a directory, not a db file
    raised = False
    try:
        make_memory_plane(db=bad, allow_stub=False)
    except Exception:
        raised = True
    assert raised, "broken store (open failure) must fail closed, never silent stub"

def test_rehydrate_query_failure_fails_closed():
    # store OPENS fine but the rehydrate QUERY fails -> must propagate, not empty state
    db = os.path.join(tempfile.mkdtemp(), "sim.db")
    mp = _durable(db)
    class BadCon:
        def execute(self, *a, **k): raise RuntimeError("query failed")
    mp.m.store.con = BadCon()
    raised = False
    try:
        mp._rehydrate()
    except Exception:
        raised = True
    assert raised, "rehydrate query failure must fail closed (propagate), not silently empty canon"


# --- gateway verdicts ---
def test_gateway_denies_canon_breach():
    assert GovernanceGateway().evaluate(_spec(params={"x": 3.0}), 9000, 10000).verdict == Verdict.DENY

def test_gateway_holds_on_no_budget():
    assert GovernanceGateway().evaluate(_spec(), 0, 10000).verdict == Verdict.HOLD
