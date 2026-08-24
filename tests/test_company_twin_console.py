from __future__ import annotations

import copy
import json
import threading
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest

import continuityos.company_twin_console as c


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "examples" / "company_twin_console" / "continuityos_lab_console.json"
AT = "2026-08-24T01:33:00Z"


def bundle():
    return c.synthetic_demo_bundle()


def ids(snapshot, collection):
    return {item["id"] for item in snapshot[collection]}


def all_text(snapshot):
    return json.dumps(snapshot, sort_keys=True)


def test_builtin_bundle_validates():
    c.validate_bundle(bundle())


def test_snapshot_is_deterministic():
    a = c.build_snapshot(bundle(), principal_id="principal_director", as_of=AT)
    b = c.build_snapshot(bundle(), principal_id="principal_director", as_of=AT)
    assert a == b


def test_director_sees_company_engineering_operations_and_finance():
    s = c.build_snapshot(bundle(), principal_id="principal_director", as_of=AT)
    text = all_text(s)
    assert "ev_finance" in text
    assert "ev_replay_fix" in text
    assert "ev_ops" in text
    assert s["actor"]["role"] == "DIRECTOR"


def test_director_does_not_see_cross_tenant_resource():
    s = c.build_snapshot(bundle(), principal_id="principal_director", as_of=AT)
    text = all_text(s)
    assert "ev_other_tenant" not in text
    assert "Other tenant secret" not in text


def test_engineering_worker_never_leaks_finance_identifiers():
    s = c.build_snapshot(bundle(), principal_id="principal_eng_worker", as_of=AT)
    text = all_text(s)
    assert "ev_finance" not in text
    assert "dec_finance_guard" not in text
    assert "ent_fin" not in text
    assert "restricted:finance" not in text


def test_operations_worker_never_leaks_engineering_identifiers():
    s = c.build_snapshot(bundle(), principal_id="principal_ops_worker", as_of=AT)
    text = all_text(s)
    assert "ev_replay_fix" not in text
    assert "dec_robot_research" not in text
    assert "ent_eng" not in text
    assert "team:engineering" not in text


def test_robot_sees_engineering_but_not_company_ops_or_finance_memory():
    s = c.build_snapshot(bundle(), principal_id="principal_research_robot", as_of=AT)
    text = all_text(s)
    assert "ev_replay_fix" in text
    assert "ev_robot_prop" in text
    assert "ev_p2c" not in text
    assert "ev_ops" not in text
    assert "ev_finance" not in text


def test_robot_confidential_engineering_record_is_hidden_by_delegation_abac():
    s = c.build_snapshot(bundle(), principal_id="principal_research_robot", as_of=AT)
    assert "ev_eng_secret" not in ids(s, "evidence")
    assert "Confidential engineering note" not in all_text(s)


def test_engineering_worker_can_see_confidential_engineering_record():
    s = c.build_snapshot(bundle(), principal_id="principal_eng_worker", as_of=AT)
    assert "ev_eng_secret" in ids(s, "evidence")


def test_robot_authority_is_read_propose_only_and_execute_absent():
    s = c.build_snapshot(bundle(), principal_id="principal_research_robot", as_of=AT)
    caps = s["capabilities"]
    assert caps["READ"]["allowed"] is True
    assert caps["PROPOSE"]["allowed"] is True
    assert caps["APPROVE"]["allowed"] is False
    assert caps["APPROVE"]["reason"] == "AGENT_AUTHORITY_CEILING"
    assert caps["EXECUTE"]["allowed"] is False
    assert caps["EXECUTE"]["reason"] == "NOT_IN_P2C_POLICY_ACTIONS"
    assert s["governance"]["can_execute"] is False


def test_worker_has_no_approve_export_delete_authority():
    s = c.build_snapshot(bundle(), principal_id="principal_eng_worker", as_of=AT)
    for action in ("APPROVE", "EXPORT", "DELETE", "LEGAL_HOLD"):
        assert s["capabilities"][action]["allowed"] is False


def test_director_company_controls_are_policy_backed():
    s = c.build_snapshot(bundle(), principal_id="principal_director", as_of=AT)
    for action in ("READ", "PROPOSE", "APPROVE", "DELEGATE", "REVOKE", "EXPORT", "DELETE", "LEGAL_HOLD"):
        assert s["capabilities"][action]["allowed"] is True
        assert len(s["capabilities"][action]["receipt_sha256"]) == 64


def test_director_lifecycle_controls_are_plan_only():
    s = c.build_snapshot(bundle(), principal_id="principal_director", as_of=AT)
    assert {item["operation"] for item in s["lifecycle_previews"]} == {"EXPORT", "DELETE", "LEGAL_HOLD"}
    assert all(item["effect"] == "PLAN_ONLY" for item in s["lifecycle_previews"])
    assert all(item["mutated"] is False for item in s["lifecycle_previews"])


def test_non_director_lifecycle_controls_are_not_exposed():
    for principal in ("principal_eng_worker", "principal_ops_worker", "principal_research_robot"):
        s = c.build_snapshot(bundle(), principal_id=principal, as_of=AT)
        assert s["lifecycle_previews"] == []


def test_historical_replay_changes_decision_state():
    early = c.build_snapshot(bundle(), principal_id="principal_director", as_of="2026-02-15T00:00:00Z")
    late = c.build_snapshot(bundle(), principal_id="principal_director", as_of=AT)
    assert "dec_localfirst" in ids(early, "decisions")
    assert "dec_company_twin" not in ids(early, "decisions")
    assert "dec_policy_plane" not in ids(early, "decisions")
    assert "dec_policy_plane" in ids(late, "decisions")


def test_visible_decision_lineage_is_recomputed_after_policy_filtering():
    s = c.build_snapshot(bundle(), principal_id="principal_director", as_of=AT)
    assert s["decision_lineages"]["dec_policy_plane"] == ["dec_policy_plane", "dec_company_twin", "dec_localfirst"]
    by_id = {item["id"]: item for item in s["decisions"]}
    assert by_id["dec_localfirst"]["replay_status"] == "SUPERSEDED"
    assert by_id["dec_company_twin"]["replay_status"] == "SUPERSEDED"
    assert by_id["dec_policy_plane"]["replay_status"] == "ACTIVE"


def test_robot_does_not_leak_company_decision_lineage():
    s = c.build_snapshot(bundle(), principal_id="principal_research_robot", as_of=AT)
    text = all_text(s)
    assert "dec_policy_plane" not in text
    assert "dec_company_twin" not in text
    assert "dec_localfirst" not in text


def test_policy_receipts_only_reference_surviving_visible_records():
    s = c.build_snapshot(bundle(), principal_id="principal_eng_worker", as_of=AT)
    visible = set()
    for collection in c.RECORD_COLLECTIONS:
        visible.update(ids(s, collection))
    refs = {item["resource_ref"] for item in s["policy_receipts"]}
    assert refs.issubset(visible)
    assert "ev_finance" not in refs
    assert "ev_other_tenant" not in refs


def test_director_graph_sees_full_synthetic_organization():
    s = c.build_snapshot(bundle(), principal_id="principal_director", as_of=AT)
    nodes = {item["id"] for item in s["organization_graph"]["nodes"]}
    assert nodes == {"actor_director", "actor_eng", "actor_ops", "actor_robot"}


def test_ops_graph_does_not_expose_engineering_or_robot_actor():
    s = c.build_snapshot(bundle(), principal_id="principal_ops_worker", as_of=AT)
    nodes = {item["id"] for item in s["organization_graph"]["nodes"]}
    assert nodes == {"actor_director", "actor_ops"}


def test_robot_graph_contains_only_self_and_human_manager():
    s = c.build_snapshot(bundle(), principal_id="principal_research_robot", as_of=AT)
    nodes = {item["id"] for item in s["organization_graph"]["nodes"]}
    assert nodes == {"actor_robot", "actor_eng"}
    assert s["actor"]["manager"]["id"] == "actor_eng"


def test_engineering_manager_graph_contains_managed_robot():
    s = c.build_snapshot(bundle(), principal_id="principal_eng_worker", as_of=AT)
    nodes = {item["id"] for item in s["organization_graph"]["nodes"]}
    assert nodes == {"actor_director", "actor_eng", "actor_robot"}


def test_agent_delegation_is_visible_to_agent_but_not_unrelated_worker():
    robot = c.build_snapshot(bundle(), principal_id="principal_research_robot", as_of=AT)
    ops = c.build_snapshot(bundle(), principal_id="principal_ops_worker", as_of=AT)
    assert [item["id"] for item in robot["delegations"]] == ["deleg_director_robot_eng"]
    assert ops["delegations"] == []


def test_proposal_visibility_is_policy_aware():
    director = c.build_snapshot(bundle(), principal_id="principal_director", as_of=AT)
    eng = c.build_snapshot(bundle(), principal_id="principal_eng_worker", as_of=AT)
    robot = c.build_snapshot(bundle(), principal_id="principal_research_robot", as_of=AT)
    ops = c.build_snapshot(bundle(), principal_id="principal_ops_worker", as_of=AT)
    assert len(director["proposals"]) == 1
    assert len(eng["proposals"]) == 1
    assert len(robot["proposals"]) == 1
    assert ops["proposals"] == []


def test_future_proposal_is_not_visible_in_historical_replay():
    s = c.build_snapshot(bundle(), principal_id="principal_director", as_of="2026-04-01T00:00:00Z")
    assert s["proposals"] == []


def test_runtime_summary_stays_read_only_and_r21h():
    s = c.build_snapshot(bundle(), principal_id="principal_director", as_of=AT)
    assert s["runtime"]["read_only"] is True
    assert s["runtime"]["twin_baseline"] == "R21H"
    assert s["runtime"]["can_execute"] is False


def test_unknown_principal_fails_with_generic_console_error():
    with pytest.raises(c.CompanyTwinConsoleError, match="snapshot unavailable"):
        c.build_snapshot(bundle(), principal_id="principal_missing", as_of=AT)


def test_non_loopback_bind_is_rejected():
    with pytest.raises(c.CompanyTwinConsoleError, match="non-loopback"):
        c.make_server(host="0.0.0.0", port=0, bundle=bundle())


def test_loopback_server_get_and_head_and_write_methods_fail_closed():
    server = c.make_server(host="127.0.0.1", port=0, bundle=bundle())
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    try:
        url = f"http://{host}:{port}/api/snapshot?principal=principal_director&as_of={AT}"
        with urlopen(url, timeout=3) as response:
            payload = json.loads(response.read().decode("utf-8"))
            assert response.status == 200
            assert payload["read_only"] is True
        request = Request(url, method="HEAD")
        with urlopen(request, timeout=3) as response:
            assert response.status == 200
            assert response.read() == b""
        for method in ("POST", "PUT", "PATCH", "DELETE"):
            request = Request(f"http://{host}:{port}/", data=b"{}", method=method)
            with pytest.raises(HTTPError) as exc:
                urlopen(request, timeout=3)
            assert exc.value.code == 405
            body = json.loads(exc.value.read().decode("utf-8"))
            assert body == {"error": "read-only console"}
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def test_http_unknown_principal_does_not_leak_resource_metadata():
    server = c.make_server(host="127.0.0.1", port=0, bundle=bundle())
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    try:
        url = f"http://{host}:{port}/api/snapshot?principal=missing&as_of={AT}"
        with pytest.raises(HTTPError) as exc:
            urlopen(url, timeout=3)
        assert exc.value.code == 403
        body = json.loads(exc.value.read().decode("utf-8"))
        assert body == {"error": "snapshot unavailable"}
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def test_ui_uses_textcontent_and_not_innerhtml():
    assert "textContent" in c._UI
    assert "innerHTML" not in c._UI


def test_source_fixture_matches_portable_console_contract_when_present():
    if not FIXTURE.exists():
        pytest.skip("source-only Company Twin P2D fixture is not packaged in wheel")
    loaded = c.load_bundle(FIXTURE)
    portable = bundle()
    assert loaded["memory"] == portable["memory"]
    assert loaded["policy"] == portable["policy"]
    assert loaded["proposals"] == portable["proposals"]
    assert loaded["runtime"] == portable["runtime"]


def test_bundle_principal_mismatch_fails_closed():
    bad = bundle()
    bad["memory"]["principals"] = bad["memory"]["principals"][:-1]
    with pytest.raises(c.CompanyTwinConsoleError, match="principals"):
        c.validate_bundle(bad)


def test_runtime_summary_cannot_claim_write_mode():
    bad = bundle()
    bad["runtime"]["read_only"] = False
    with pytest.raises(c.CompanyTwinConsoleError, match="read-only"):
        c.validate_bundle(bad)


def test_snapshot_does_not_mutate_bundle():
    b = bundle()
    before = copy.deepcopy(b)
    c.build_snapshot(b, principal_id="principal_director", as_of=AT)
    assert b == before
