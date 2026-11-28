"""Current/scoped continuity through existing MCP routes, without a service."""
from __future__ import annotations

import json
import time

import pytest

from continuityos.continuity import Continuity
from continuityos.memory import Memory
from continuityos.mcp_server import Server, TOOLS
from continuityos.twin import Twin


@pytest.fixture
def server(tmp_path):
    # Exercise the real dispatch on a synthetic store, without constructor
    # configuration reads, a stdio loop, broker, or any listening service.
    memory = Memory(str(tmp_path / "mcp-synthetic.db"))
    value = object.__new__(Server)
    value.m = memory
    value.c = Continuity(memory)
    value.t = Twin(memory)
    value.turns = 0
    value.std = 10
    yield value
    memory.store.con.close()


def _json(server, name, **arguments):
    return json.loads(server.call(name, arguments))


def test_catalog_advertises_context_selection_without_broker_authority():
    catalog = {tool["name"]: tool for tool in TOOLS}
    for name in ("handoff", "doctor", "checkpoint", "set_frontier", "predict", "alignment", "srd_status"):
        schema = catalog[name]["inputSchema"]
        assert {"project", "subject"} <= set(schema["properties"])
        assert schema["additionalProperties"] is False
    for name in ("preflight_exec", "execute_preflight", "preflight_action"):
        assert "project" not in catalog[name]["inputSchema"]["properties"]
    assert catalog["handoff"]["inputSchema"]["properties"]["format"]["default"] == "text"
    assert "calibrated" in catalog["predict"]["description"]


def test_handoff_scope_selects_current_project_and_keeps_global_canon(server):
    server.c.add_canon("Global rule remains applicable.")
    a = Continuity(server.m, project="A", subject="robert")
    b = Continuity(server.m, project="B", subject="robert")
    other = Continuity(server.m, project="A", subject="other")
    a.add_canon("A current constraint.")
    b.add_canon("B private constraint sentinel.")
    other.add_canon("Other subject sentinel.")
    checkpoint = a.checkpoint("A selected decision", "A next step", "fixture:A")
    b.checkpoint("B newer decision sentinel", "B next step", "fixture:B")
    count = server.m.count()

    result = _json(server, "handoff", project="A", subject="robert", format="json")
    assert result["complete"] is True and result["status"] == "READY"
    assert result["scope"] == {"project": "A", "subject": "robert"}
    assert result["payload"]["last_checkpoint"]["id"] == checkpoint
    assert {row["text"] for row in result["payload"]["canon"]} == {
        "Global rule remains applicable.", "A current constraint."}
    text = server.call("handoff", {"project": "A", "subject": "robert"})
    assert text.startswith("# ContinuityOS handoff pack")
    assert "A next step" in text and "B newer" not in text and "Other subject" not in text
    assert "omitted: 0" in text
    assert result["authority_granted"] is False and result["origin_verified"] is False
    assert server.m.count() == count


def test_existing_checkpoint_frontier_and_doctor_routes_round_trip_scope(server):
    args = {"project": "A", "subject": "robert"}
    checkpoint = server.call("checkpoint", {**args, "summary": "Paused while evidence is missing",
                                            "next_action": "", "proof": "fixture:pending",
                                            "lifecycle": "PAUSED"})
    assert checkpoint.startswith("checkpoint #")
    server.call("set_frontier", {**args, "kind": "trunk", "item": "A only"})
    scoped = _json(server, "handoff", **args, format="json")
    assert scoped["payload"]["last_checkpoint"]["meta"]["lifecycle"] == "PAUSED"
    assert scoped["payload"]["frontiers"][0]["text"] == "A only"
    global_state = _json(server, "handoff", format="json")
    assert global_state["payload"]["last_checkpoint"] is None
    report = _json(server, "doctor", **args)
    assert report["scope"] == args and report["lifecycle"] == "PAUSED"
    assert report["proof_verification"] == "NOT_PERFORMED" and report["authority_granted"] is False
    assert "checkpoint_fresh" not in {check["check"] for check in report["checks"]}


def test_srd_uses_all_current_canon_and_reports_actual_snapshot_coverage(server):
    for index in range(12):
        server.c.add_canon(f"Current mandatory canon marker {index}.")
    old = server.c.add_canon("Obsolete rule sentinel.")
    replacement = server.m.supersede(old, "Replacement mandatory rule.", namespace="canon")
    now = time.time()
    server.m.remember("Future rule sentinel.", namespace="canon", valid_from=now + 3600)
    server.m.remember("Expired rule sentinel.", namespace="canon", valid_to=now - 1)
    server.m.remember("Revoked rule sentinel.", namespace="canon", meta={"status": "REVOKED"})
    server.m.remember("Unreviewed rule sentinel.", namespace="canon",
                      meta={"review_status": "UNREVIEWED", "accepted": False})
    count = server.m.count()
    server.turns = server.std - 1

    result = _json(server, "srd_status")
    assert result["reinject_due"] is True and result["reminder_emitted"] is True
    assert result["context_complete"] is True and result["context_status"] == "READY"
    assert len(result["canon_reminder"]) == result["counts"]["canon"] == 13
    assert result["canon_returned_count"] == 13 and result["canon_omitted_count"] == 0
    assert "Current mandatory canon marker 11." in result["canon_reminder"]
    assert f"mem:{replacement}" in result["canon_refs"]
    assert not any("sentinel" in item for item in result["canon_reminder"])
    assert result["excluded_candidate_counts"] == {"canon": 1}
    assert result["interval_basis"] == "LEGACY_LOCAL_POLICY_NOT_CALIBRATED"
    assert result["authority_granted"] is False and result["origin_verified"] is False
    assert server.m.count() == count


def test_srd_scope_is_fresh_and_does_not_inject_other_project_canon(server):
    a = Continuity(server.m, project="A", subject="robert")
    b = Continuity(server.m, project="B", subject="robert")
    a.add_canon("A original rule.")
    b.add_canon("B unrelated rule sentinel.")
    server.turns = server.std
    before = _json(server, "srd_status", project="A", subject="robert")
    assert before["canon_reminder"] == ["A original rule."]
    a.add_canon("A newly recorded constraint.")
    server.turns = server.std
    after = _json(server, "srd_status", project="A", subject="robert")
    assert set(after["canon_reminder"]) == {"A original rule.", "A newly recorded constraint."}
    assert before["snapshot_sha256"] != after["snapshot_sha256"]
    assert after["scope"] == {"project": "A", "subject": "robert"}


def test_srd_budget_hold_emits_nothing_and_preserves_pending_reminder(server):
    server.c.add_canon("Required canon must not silently disappear.")
    server.turns = server.std
    held = _json(server, "srd_status", max_items=0)
    assert held["reinject_due"] is True and held["reminder_emitted"] is False
    assert held["context_status"] == "HOLD" and held["context_complete"] is False
    assert held["canon_reminder"] == held["canon_refs"] == []
    assert held["canon_omitted_count"] == 1 and held["turns"] >= server.std
    assert held["overflow"]["reasons"] == ["ITEM_BUDGET_EXCEEDED"]
    ready = _json(server, "srd_status")
    assert ready["reinject_due"] is True and ready["reminder_emitted"] is True
    assert ready["turns"] == 0 and ready["canon_omitted_count"] == 0


def test_srd_not_due_distinguishes_available_context_from_emitted_reminder(server):
    server.c.add_canon("A current rule awaiting the reminder cadence.")
    result = _json(server, "srd_status")
    assert result["context_complete"] is True and result["reminder_emitted"] is False
    assert result["canon_reminder"] == [] and result["counts"]["canon"] == 1
    assert result["canon_returned_count"] == 0 and result["canon_omitted_count"] == 1


def test_handoff_explicit_budget_holds_without_leaking_partial_text(server):
    server.c.add_canon("A canon sentinel too large for this requested budget.")
    result = _json(server, "handoff", format="json", max_bytes=1)
    assert result["status"] == "HOLD" and result["payload"] is None
    assert result["complete"] is False and result["counts"]["canon"] == 1
    text = server.call("handoff", {"max_bytes": 1})
    assert "HOLD" in text and "canon sentinel" not in text


def test_twin_mcp_routes_use_selected_scope_and_honest_evidence_status(server):
    a = Continuity(server.m, project="A", subject="robert")
    b = Continuity(server.m, project="B", subject="robert")
    aid = a.add_canon("Never publish the scoped release secrets.")
    bid = b.add_canon("Never publish the scoped release secrets.")
    args = {"project": "A", "subject": "robert"}
    prediction = _json(server, "predict", **args, situation="publish scoped release secrets")
    alignment = _json(server, "alignment", **args, proposed_action="publish scoped release secrets")
    assert prediction["prediction_status"] == "NOT_A_BEHAVIORAL_PREDICTION"
    assert prediction["scope"] == alignment["scope"] == args
    assert {item["id"] for item in prediction["evidence"]} == {aid}
    assert bid not in {item["id"] for item in alignment["relevant_rules"]}
    assert alignment["semantic_compatibility"] == "UNVERIFIED"
    assert alignment["authority_granted"] is False


@pytest.mark.parametrize("arguments", [
    {"project": ""}, {"subject": None}, {"project": 4},
    {"max_items": True}, {"max_bytes": -1}, {"format": "partial"},
    {"scope": {"project": "silently-ignored"}},
])
def test_invalid_context_selector_or_budget_fails_before_snapshot(server, monkeypatch, arguments):
    def forbidden(**kwargs):
        raise AssertionError("invalid options must be rejected before snapshot read")

    monkeypatch.setattr(server.c, "handoff_snapshot", forbidden)
    with pytest.raises(ValueError):
        server.call("handoff", arguments)
