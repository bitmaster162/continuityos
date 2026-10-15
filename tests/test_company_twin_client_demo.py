"""Bounded offline tests for the fictional Northstar Labs client walkthrough."""
from __future__ import annotations

import json
from pathlib import Path
import threading
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest

from continuityos.company_twin_console import CompanyTwinConsoleError, build_snapshot
from demo.company_twin_client_demo import (
    BASE_FIXTURE, HTML_FILE, PEOPLE, build_demo_bundle, make_demo_server,
)


@pytest.fixture(scope="module")
def bundle():
    return build_demo_bundle()


def snapshot(bundle, principal: str, at: str = "2025-12-31T23:59:59Z"):
    return build_snapshot(bundle, principal_id=principal, as_of=at)


def test_fixture_is_pinned_2025_synthetic_and_has_no_real_connectors(bundle):
    assert BASE_FIXTURE.name == "northstar_labs_2025.json"
    assert bundle["memory"]["organization"]["synthetic"] is True
    assert bundle["runtime"]["read_only"] is True
    assert bundle["runtime"]["can_execute"] is False
    assert bundle["runtime"]["execution_authority"] == "NONE"
    assert bundle["memory"]["period"] == {
        "start": "2025-01-01T00:00:00Z", "end": "2025-12-31T23:59:59Z"
    }
    assert all("synthetic" in record["source_ref"]
               for record in bundle["memory"]["evidence"])
    assert all(not str(p["id"]).startswith("principal_") for p in bundle["memory"]["principals"])


def test_12_humans_three_teams_and_one_supervised_agent(bundle):
    policy = bundle["policy"]
    humans = [actor for actor in policy["actors"] if actor["actor_kind"] == "HUMAN"]
    agents = [actor for actor in policy["actors"] if actor["actor_kind"] == "AGENT"]
    assert len(PEOPLE) == len(humans) == 12
    assert len(agents) == 1
    assert [a["role"] for a in humans].count("DIRECTOR") == 1
    assert {p["team_id"] for p in humans if "team_id" in p} == {
        "sales", "product", "engineering"
    }
    assert agents[0]["manager_actor_id"] == "actor:cara"
    assert len(bundle["memory"]["principals"]) == 13
    assert len(policy["delegations"]) == 1
    assert set(policy["delegations"][0]["actions"]) == {"READ", "PROPOSE"}
    assert policy["delegations"][0]["scopes"] == ["team:engineering"]


def test_historical_replay_changes_and_decision_lineage_is_authorized(bundle):
    march = snapshot(bundle, "alice", "2025-03-31T23:59:59Z")
    december = snapshot(bundle, "alice")
    assert march["counts"]["decisions"] == 2
    assert december["counts"]["decisions"] == 5
    assert march["counts"]["events"] < december["counts"]["events"]
    assert any(d["id"] == "dec_mar_pause_paid" and d["replay_status"] == "ACTIVE"
               for d in march["decisions"])
    assert any(d["id"] == "dec_mar_pause_paid" and d["replay_status"] == "SUPERSEDED"
               for d in december["decisions"])
    assert december["decision_lineages"]["dec_sep_resume_paid"] == [
        "dec_sep_resume_paid", "dec_mar_pause_paid"
    ]
    names = {p["id"]: p["name"] for p in bundle["memory"]["principals"]}
    for d in december["decisions"]:
        assert d["decided_by_name"] == names[d["decided_by_principal"]]
        assert d["rationale"] and d["evidence_ids"]
    assert december["organization"]["synthetic"] is True


def test_sales_cannot_read_engineering_or_restricted_finance(bundle):
    director = snapshot(bundle, "alice")
    sales = snapshot(bundle, "bob")
    evidence_dir = {r["id"] for r in director["evidence"]}
    evidence_sales = {r["id"] for r in sales["evidence"]}
    assert "ev_jun_cash" in evidence_dir
    assert "ev_jun_cash" not in evidence_sales
    assert "ev_demo_eng_task" not in evidence_sales
    assert "ev_demo_sales_mail" in evidence_sales
    assert "ev_demo_sales_task" in evidence_sales
    assert all(not item["scope"].startswith("restricted:") for item in sales["decisions"])


def test_agent_delegation_is_read_propose_only_and_managed_by_human(bundle):
    agent = snapshot(bundle, "agent_atlas")
    assert agent["actor"]["actor_kind"] == "AGENT"
    assert agent["actor"]["manager"]["name"] == "Cara Ionescu"
    assert agent["capabilities"]["READ"]["allowed"] is True
    assert agent["capabilities"]["PROPOSE"]["allowed"] is True
    for action in ("APPROVE", "DELEGATE", "REVOKE", "DELETE", "EXPORT", "EXECUTE"):
        assert agent["capabilities"][action]["allowed"] is False
    assert agent["governance"] == {
        "execution_authority": "NONE",
        "can_execute": False,
        "can_trade": False,
        "capital_permission": "DENY",
    }
    assert len(agent["proposals"]) == 1
    assert agent["proposals"][0]["status"] == "PENDING_HUMAN_REVIEW"
    assert all(x["scope"] == "team:engineering" for x in agent["evidence"])
    assert not agent["lifecycle_previews"]


def test_no_agent_authorization_after_delegation_expiry(bundle):
    # P2C evaluates expiry at the requested time; the demo itself ends in 2025.
    changed = json.loads(json.dumps(bundle))
    changed["policy"]["delegations"][0]["expires_at"] = "2025-07-01T00:00:00Z"
    denied = snapshot(changed, "agent_atlas")
    assert denied["capabilities"]["READ"]["allowed"] is False
    assert denied["capabilities"]["PROPOSE"]["allowed"] is False
    assert denied["counts"]["evidence"] == 0
    assert denied["proposals"] == []


def test_director_worker_and_robot_see_different_actor_graph(bundle):
    director = snapshot(bundle, "alice")
    worker = snapshot(bundle, "bob")
    robot = snapshot(bundle, "agent_atlas")
    assert len(director["organization_graph"]["nodes"]) == 13
    assert len(worker["organization_graph"]["nodes"]) < 13
    names = {n["name"] for n in robot["organization_graph"]["nodes"]}
    assert "Cara Ionescu" in names and "Atlas Research Agent" in names
    assert "Dana Moore" not in names


def test_source_aware_synthetic_email_and_task_timeline(bundle):
    dates = {x["id"] for x in snapshot(bundle, "alice")["timeline"]}
    assert "evt_demo_eng_task" in dates
    assert "evt_demo_product_mail" in dates
    assert "evt_demo_sales_task" in dates
    kinds = {r["kind"] for r in bundle["memory"]["evidence"]}
    assert {"email", "task"}.issubset(kinds)


def test_no_external_dependencies_or_unmarked_demo_screen():
    html = HTML_FILE.read_text(encoding="utf-8")
    assert "Synthetic demo" in html and "Fictional company" in html
    assert "not user authentication" in html.lower() or "not user authentication" in html
    assert "textContent" in html
    assert "<script src=" not in html
    assert "https://" not in html
    assert 'min="2025-01-01" max="2025-12-31"' in html
    assert "APPROVE" in html and "EXECUTE" in html


def test_loopback_only_rejects_nonlocal_bind():
    with pytest.raises(CompanyTwinConsoleError):
        make_demo_server(host="0.0.0.0", port=0)


def test_read_only_http_snapshot_and_no_mutating_methods(bundle):
    server = make_demo_server(port=0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = "http://127.0.0.1:%d/" % server.server_address[1]
        with urlopen(url, timeout=5) as response:
            page = response.read().decode("utf-8")
            assert "Fictional company" in page
            assert response.headers.get("Content-Security-Policy")
        q = "api/snapshot?principal=agent_atlas&as_of=2025-12-31T23%3A59%3A59Z"
        with urlopen(url + q, timeout=5) as response:
            value = json.loads(response.read())
            assert value["capabilities"]["EXECUTE"]["allowed"] is False
            assert value["organization"]["synthetic"] is True
        for method in ("POST", "PUT", "PATCH", "DELETE"):
            with pytest.raises(HTTPError) as exc:
                urlopen(Request(url + q, data=b"{}", method=method), timeout=5)
            assert exc.value.code == 405
        with pytest.raises(HTTPError) as denied:
            urlopen(url + "api/snapshot?principal=unknown&as_of=2025-12-31T23:59:59Z", timeout=5)
        assert denied.value.code == 403
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
