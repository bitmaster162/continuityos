from continuityos.routing import Router, RoleGuard, classify_task


def test_cheap_tasks_go_local():
    r = Router()
    assert r.route("summarize arena stats", risk=0.1) == "local"
    assert r.route("extract closed trades", risk=0.2) == "local"


def test_hard_tasks_go_premium():
    r = Router()
    assert r.route("design the 185->fin migration architecture", risk=0.4) == "premium"
    assert r.route("research market-neutral edges 2026", risk=0.3) == "premium"


def test_high_risk_escalates_to_human():
    r = Router()
    assert r.route("deploy to prod", risk=0.9) == "human"


def test_web_tasks_go_browser():
    assert Router().route("fetch competitor pricing page", risk=0.1) == "browser"


def test_budget_scales_with_risk():
    r = Router()
    assert r.budget(0.1)["max_steps"] == 6
    assert r.budget(0.7)["max_steps"] == 24


def test_write_needs_hitl_above_threshold():
    r = Router()
    assert r.needs_hitl_for_write(0.8) is True
    assert r.needs_hitl_for_write(0.5) is False


def test_roleguard_stops_looping():
    g = RoleGuard(max_repeat=2)
    assert g.check("s1", "same output")
    assert g.check("s1", "same output")
    assert not g.check("s1", "same output")  # 3rd identical -> loop


def test_classify_task_basic():
    assert classify_task("summarize the digest") == "summarize"
    assert classify_task("implement the patch") == "code"
