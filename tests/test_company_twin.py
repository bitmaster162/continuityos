from __future__ import annotations

import copy
import json
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest

import continuityos.company_twin as ct
import continuityos.company_twin_explorer as explorer


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "examples" / "company_twin" / "northstar_labs_2025.json"
SCHEMA = ROOT / "docs" / "schemas" / "company_twin_p2a.schema.json"


def _data():
    return ct.load_dataset(FIXTURE)


def test_synthetic_fixture_is_valid_and_covers_all_twelve_months():
    data = _data()
    assert data["organization"]["synthetic"] is True
    assert data["schema_version"] == "company-twin-p2a/1"
    assert {int(event["occurred_at"][5:7]) for event in data["events"]} == set(range(1, 13))
    summary = ct.summarize(data)
    assert summary.organization_name == "Northstar Labs"
    assert summary.records >= 50


def test_schema_artifact_declares_temporal_truth_and_scope_contracts():
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["properties"]["schema_version"]["const"] == "company-twin-p2a/1"
    record = schema["$defs"]["recordBase"]["properties"]
    assert record["truth_class"]["enum"] == ["FACT", "EVIDENCE", "INFERENCE"]
    assert record["scope"]["minLength"] == 1


def test_replay_is_temporal_and_read_only():
    data = _data()
    before = copy.deepcopy(data)
    feb = ct.replay(data, principal_id="alice", as_of="2025-02-28T23:59:59Z")
    dec = ct.replay(data, principal_id="alice", as_of="2025-12-31T23:59:59Z")
    assert feb["read_only"] is True
    assert len(feb["events"]) < len(dec["events"])
    assert all(item["occurred_at"] <= "2025-02-28T23:59:59Z" for item in feb["events"])
    assert data == before


def test_sales_scope_cannot_see_restricted_finance_records_or_ids():
    snapshot = ct.replay(_data(), principal_id="bob", as_of="2025-12-31T23:59:59Z")
    encoded = json.dumps(snapshot, sort_keys=True)
    assert "restricted:finance" not in snapshot["authorized_scopes"]
    for forbidden in (
        "ent_cashplan",
        "rel_cashplan_company",
        "ev_jun_cash",
        "evt_jun",
        "dec_jun_hiring_freeze",
        "out_dec_hiring",
        "inf_dec_keyperson",
    ):
        assert forbidden not in encoded


def test_ceo_scope_sees_restricted_finance_history():
    snapshot = ct.replay(_data(), principal_id="alice", as_of="2025-12-31T23:59:59Z")
    encoded = json.dumps(snapshot, sort_keys=True)
    assert "restricted:finance" in snapshot["authorized_scopes"]
    assert "dec_jun_hiring_freeze" in encoded
    assert "ev_jun_cash" in encoded


def test_cross_scope_reference_fails_closed_without_metadata_leak():
    data = _data()
    public_event = next(item for item in data["events"] if item["id"] == "evt_may")
    public_event["evidence_ids"] = ["ev_jun_cash"]
    snapshot = ct.replay(data, principal_id="bob", as_of="2025-12-31T23:59:59Z")
    encoded = json.dumps(snapshot, sort_keys=True)
    assert "evt_may" not in encoded
    assert "ev_jun_cash" not in encoded


def test_decision_replay_tracks_supersession_and_lineage():
    data = _data()
    august = ct.replay(data, principal_id="bob", as_of="2025-08-31T23:59:59Z")
    august_by_id = {item["id"]: item for item in august["decisions"]}
    assert august_by_id["dec_mar_pause_paid"]["replay_status"] == "ACTIVE"

    october = ct.replay(data, principal_id="bob", as_of="2025-10-31T23:59:59Z")
    october_by_id = {item["id"]: item for item in october["decisions"]}
    assert october_by_id["dec_mar_pause_paid"]["replay_status"] == "SUPERSEDED"
    assert october_by_id["dec_sep_resume_paid"]["replay_status"] == "ACTIVE"

    lineage = ct.decision_lineage(
        data,
        principal_id="bob",
        decision_id="dec_sep_resume_paid",
        as_of="2025-10-31T23:59:59Z",
    )
    assert [item["id"] for item in lineage] == [
        "dec_sep_resume_paid",
        "dec_mar_pause_paid",
    ]


def test_truth_classes_keep_inference_separate_from_historical_evidence():
    snapshot = ct.replay(_data(), principal_id="alice", as_of="2025-12-31T23:59:59Z")
    assert snapshot["truth_classes"] == {
        "historical_records": ["FACT", "EVIDENCE"],
        "model_interpretation": ["INFERENCE"],
    }
    assert all(item["truth_class"] == "EVIDENCE" for item in snapshot["evidence"])
    assert all(item["truth_class"] == "FACT" for item in snapshot["events"])
    assert all(item["truth_class"] == "INFERENCE" for item in snapshot["inferences"])


def test_unknown_principal_and_out_of_period_replay_fail_closed():
    data = _data()
    with pytest.raises(KeyError):
        ct.replay(data, principal_id="mallory", as_of="2025-12-01T00:00:00Z")
    with pytest.raises(ValueError):
        ct.replay(data, principal_id="bob", as_of="2026-01-01T00:00:00Z")


def test_explorer_is_loopback_only_and_rejects_mutation_routes():
    assert explorer._is_loopback_host("127.0.0.1") is True
    assert explorer._is_loopback_host("localhost") is True
    assert explorer._is_loopback_host("0.0.0.0") is False
    assert explorer._is_loopback_host("192.168.1.10") is False

    server = ThreadingHTTPServer(("127.0.0.1", 0), explorer._make_handler(FIXTURE))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        with urlopen(f"{base}/health", timeout=2.0) as response:
            health = json.loads(response.read().decode("utf-8"))
        assert health == {
            "can_execute": False,
            "execution_authority": "NONE",
            "ok": True,
            "product": "Company Twin P2A",
            "read_only": True,
        }

        with urlopen(f"{base}/api/meta", timeout=2.0) as response:
            meta = json.loads(response.read().decode("utf-8"))
        assert meta["read_only"] is True
        assert meta["organization"]["synthetic"] is True

        replay_url = (
            f"{base}/api/replay?"
            "principal=bob&as_of=2025-12-31T23%3A59%3A59Z"
        )
        with urlopen(replay_url, timeout=2.0) as response:
            payload = json.loads(response.read().decode("utf-8"))
        assert payload["read_only"] is True
        assert payload["principal_id"] == "bob"

        for method in ("POST", "PUT", "PATCH", "DELETE"):
            request = Request(f"{base}/api/replay", data=b"{}", method=method)
            with pytest.raises(HTTPError) as excinfo:
                urlopen(request, timeout=2.0)
            assert excinfo.value.code == 405
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2.0)


def test_explorer_ui_has_no_mutation_calls_or_unsafe_html_rendering():
    text = explorer._UI
    assert "READ ONLY" in text
    assert "FACT / EVIDENCE" in text
    assert "INFERENCE" in text
    assert "textContent" in text
    assert "innerHTML" not in text
    assert "method:'POST'" not in text
    assert 'method:"POST"' not in text
    assert "/models/load" not in text
    assert "/models/unload" not in text
