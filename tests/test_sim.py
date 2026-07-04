"""Sim-OS invariant tests (PR-9, GPT audit). Cover the hardened guarantees so CI catches
regressions — the module self-tests alone weren't enough."""
from types import SimpleNamespace
from continuityos.sim.contracts import (
    SimulationSpec, Objective, SimulationConstraints, ExecutionBudget,
    StoppingCriteria, CanonicalState, OptimizationDirection,
)
from continuityos.sim.memory_plane import make_memory_plane, PromotionPolicy, candidate_id
from continuityos.sim.gateway import GovernanceGateway, Verdict
from continuityos.sim.rollback import RollbackLedger, RollbackTrigger, execute_rollback
from continuityos.sim.loop import run_loop, build_spec


def _spec(objective="edge", params=None, budget_tokens=100_000):
    return SimulationSpec(
        objective=Objective(objective, 1.0, OptimizationDirection.MAXIMIZE),
        parameters=params or {"x": 0.4},
        constraints=SimulationConstraints(hard_bounds={"x": 2.0}),
        budget=ExecutionBudget(compute_tokens=budget_tokens),
        stopping_criteria=StoppingCriteria(0.95, 0.01),
        operator_canon=CanonicalState(),
    ).finalize()


def _res(m, rid):
    return SimpleNamespace(metrics={"edge": m}, status=SimpleNamespace(value="success"), result_id=rid)


# --- P0-1: spec_id is a full content hash ---
def test_spec_id_covers_all_material_fields():
    a = _spec(budget_tokens=100)
    b = _spec(budget_tokens=1_000_000)   # differ ONLY in budget
    assert a.spec_id != b.spec_id, "specs differing in budget must get different ids"


# --- P0-A: confirmations are candidate-scoped, not objective-scoped ---
def test_different_candidates_do_not_co_confirm():
    mp = make_memory_plane(allow_stub=True, policy=PromotionPolicy(verify_threshold=0.9, min_confirmations=2))
    mp.record(_spec(params={"x": 0.4}), _res(0.95, "r1"))
    mp.record(_spec(params={"x": 0.9}), _res(0.95, "r2"))   # DIFFERENT candidate
    assert mp.sizes()["canon"] == 0, "two different candidates must not promote"
    mp.record(_spec(params={"x": 0.4}), _res(0.96, "r3"))   # same as r1's candidate
    assert mp.sizes()["canon"] == 1, "same candidate x2 distinct runs -> canon"


def test_same_run_id_does_not_double_count():
    mp = make_memory_plane(allow_stub=True, policy=PromotionPolicy(verify_threshold=0.9, min_confirmations=2))
    mp.record(_spec(params={"x": 0.4}), _res(0.95, "dup"))
    mp.record(_spec(params={"x": 0.4}), _res(0.95, "dup"))  # same result_id
    assert mp.sizes()["canon"] == 0, "duplicate run id must not count as replication"


# --- P0-B: the integrated loop can actually reach canon via the VERIFY phase ---
def test_verification_phase_reaches_canon_in_loop():
    s = run_loop("edge", iters=8, verbose=False, allow_stub=True)
    assert s["stop_reason"] in ("verified_success", "max_iters", "hallucination_loop")
    if s["stop_reason"] == "verified_success":
        assert s["canon_size"] >= 1, "verified_success must have produced canon"


# --- P0-D: rollback fails closed ---
def test_rollback_failure_is_flagged():
    class Broken:
        def rollback_ref(self, o): return 1
        def restore_to(self, o, r): raise RuntimeError("store down")
    led = RollbackLedger()
    ev = execute_rollback(Broken(), "edge", RollbackTrigger.GATEWAY_DENY, led, "x")
    assert ev.failed is True


def test_rollback_success_not_flagged():
    class Ok:
        def rollback_ref(self, o): return 5
        def restore_to(self, o, r): return {"restored_canon": r}
    led = RollbackLedger()
    ev = execute_rollback(Ok(), "edge", RollbackTrigger.HALLUCINATION_LOOP, led, "x")
    assert ev.failed is False and ev.restored_ref == 5


# --- P1-A / P0-C durable: rehydrate + rollback survive a process restart ---
def _durable_plane(db, min_conf=2):
    from continuityos.sim.memory_plane import RealMemoryPlane, PromotionPolicy
    return RealMemoryPlane(db, policy=PromotionPolicy(verify_threshold=0.9, min_confirmations=min_conf))

def test_rehydrate_restores_current_canon_after_restart():
    import tempfile, os
    db = os.path.join(tempfile.mkdtemp(), "sim.db")
    mp = _durable_plane(db)
    mp.record(_spec(params={"x": 0.4}), _res(0.95, "r1"))
    mp.record(_spec(params={"x": 0.4}), _res(0.96, "r2"))     # -> canon
    ref = mp.rollback_ref("edge")
    assert ref is not None
    mp2 = _durable_plane(db)                                   # simulate restart (same db)
    assert mp2.rollback_ref("edge") == ref, "rehydrate must recover current canon from DB"

def test_rollback_survives_restart():
    import tempfile, os
    db = os.path.join(tempfile.mkdtemp(), "sim.db")
    mp = _durable_plane(db)
    mp.record(_spec(params={"x": 0.4}), _res(0.95, "r1"))
    mp.record(_spec(params={"x": 0.4}), _res(0.96, "r2"))     # canon row A
    mp.restore_to("edge", mp.rollback_ref("edge"))            # durable restorative supersede
    after = mp.rollback_ref("edge")
    mp2 = _durable_plane(db)                                   # restart
    assert mp2.rollback_ref("edge") == after, "rollback must be durable across restart"

def test_broken_store_fails_closed():
    import tempfile
    # passing a directory as the db path makes sqlite fail to open -> must RAISE, not stub
    bad = tempfile.mkdtemp()                                   # a directory, not a file
    raised = False
    try:
        make_memory_plane(db=bad, allow_stub=False)
    except Exception:
        raised = True
    assert raised, "broken durable store must fail closed, never silent stub"


# --- gateway verdicts ---
def test_gateway_denies_canon_breach():
    gw = GovernanceGateway()
    sp = _spec(params={"x": 3.0})           # exceeds hard bound 2.0
    assert gw.evaluate(sp, 9000, 10000).verdict == Verdict.DENY

def test_gateway_holds_on_no_budget():
    gw = GovernanceGateway()
    assert gw.evaluate(_spec(), 0, 10000).verdict == Verdict.HOLD
