from __future__ import annotations

import json
from pathlib import Path

import pytest

import continuityos.current_effect_boundary as boundary
from continuityos.current_work import build_current_work_from_db, compile_project_work
from continuityos.operational_memory import OperationalMemory

PROJECT = "project:continuityos"
REF = {"sha256": "a" * 64, "locator": "evidence://r35"}


def projection(*, claims=None, decisions=None):
    body = {
        "schema": "continuityos.common_operational_memory.projection.v1",
        "mode": "SHADOW_ONLY",
        "event_cursor": 7,
        "event_chain_head": "b" * 64,
        "valid_at": "2026-08-09T12:00:00.000000Z",
        "claims": list(claims or []),
        "decisions": list(decisions or []),
        "broker_custody": [],
        "ceilings": {
            "accepted_truth_owner": "CONTROL_CENTER",
            "content_acceptance": "NOT_PERFORMED",
            "state_apply": "DISABLED",
            "can_trade": False,
            "capital_permission": "DENY",
            "deploy_permission": "DENY",
            "self_application": False,
        },
        "projection_sha256": "c" * 64,
    }
    return body


def claim(predicate, value, *, scope="global", cid="clm-1", evidence_state="SOURCE_BACKED"):
    return {
        "claim_id": cid,
        "subject_id": PROJECT,
        "predicate": predicate,
        "value": value,
        "scope": scope,
        "evidence_state": evidence_state,
        "valid_from": "2026-08-09T10:00:00.000000Z",
        "valid_to": None,
        "recorded_at": "2026-08-09T10:00:00.000000Z",
        "supersedes_id": None,
        "source_event_id": "evt-1",
        "evidence_refs": [REF],
        "claim_hash": "d" * 64,
    }


def decision(state, value, *, did="dec-1"):
    return {
        "decision_id": did,
        "subject_id": PROJECT,
        "decision_type": "NEXT_ACTION",
        "state": state,
        "value": value,
        "rationale": "bounded next step",
        "authority_class": "HUMAN" if state != "PROPOSED" else "AGENT",
        "authority_id": "ROBERT" if state != "PROPOSED" else "GPT",
        "authority_ref": "decision://r35" if state != "PROPOSED" else None,
        "recorded_at": "2026-08-09T11:00:00.000000Z",
        "supersedes_id": None,
        "source_event_id": "evt-2",
        "evidence_refs": [REF] if state != "PROPOSED" else [],
        "decision_hash": "e" * 64,
    }


def set_current(monkeypatch):
    monkeypatch.setenv(boundary.ENV_CHALLENGE, "challenge.json")
    monkeypatch.setenv(boundary.ENV_CHALLENGE_SHA, "f" * 64)
    monkeypatch.setenv(boundary.ENV_ACK, "ack.json")
    monkeypatch.setenv(boundary.ENV_REQUIRED, "1")
    monkeypatch.setattr(
        boundary,
        "verify_current_runtime_binding",
        lambda *args, **kwargs: {
            "terminal": "CURRENT_RUNTIME_BINDING_PASS",
            "binding_verified": True,
            "authority_generation": "R64",
            "challenge_id": "1" * 64,
            "challenge_sha256": "f" * 64,
            "ack_sha256": "2" * 64,
        },
    )


def clear_current(monkeypatch):
    for name in (
        boundary.ENV_CHALLENGE,
        boundary.ENV_CHALLENGE_SHA,
        boundary.ENV_ACK,
        boundary.ENV_REQUIRED,
    ):
        monkeypatch.delenv(name, raising=False)


def test_accepted_next_action_wins_but_never_authorizes_execution():
    p = projection(
        claims=[claim("project.goal", "finish operational memory", cid="goal")],
        decisions=[decision("ACCEPTED", {"action": "ship R35", "priority": 90})],
    )
    result = compile_project_work(p, PROJECT)
    assert result["terminal"] == "CURRENT_WORK_PASS"
    assert result["reason"] == "ACCEPTED_NEXT_ACTION_SELECTED"
    assert result["next_action"]["action"] == "ship R35"
    assert result["next_action"]["authority_status"] == "ACCEPTED_OPERATIONAL_DECISION"
    assert result["decision_needed"] is False
    assert result["execution_authorized"] is False
    assert result["effects"]["agent_dispatch"] is False
    assert result["effects"]["can_trade"] is False


def test_hold_decision_stops_selection_even_when_claim_candidate_exists():
    p = projection(
        claims=[claim("project.next_action", {"action": "candidate", "priority": 100}, cid="candidate")],
        decisions=[decision("HOLD", {"action": "do not proceed"})],
    )
    result = compile_project_work(p, PROJECT)
    assert result["terminal"] == "CURRENT_WORK_HOLD"
    assert result["reason"] == "NEXT_ACTION_HOLD"
    assert result["next_action"] is None


def test_two_current_terminal_next_action_decisions_fail_closed():
    p = projection(
        decisions=[
            decision("ACCEPTED", "one", did="dec-a"),
            decision("HOLD", "two", did="dec-b"),
        ]
    )
    result = compile_project_work(p, PROJECT)
    assert result["terminal"] == "CURRENT_WORK_REVISE"
    assert result["reason"] == "PROJECT_MEMORY_CONFLICT"
    assert "multiple current terminal NEXT_ACTION decisions" in result["errors"]


def test_active_blocker_tightens_accepted_action_to_hold():
    p = projection(
        claims=[
            claim(
                "project.blocker",
                {"id": "ci", "title": "CI red", "status": "OPEN", "blocks": ["dec-1"]},
                scope="ci",
                cid="blocker",
            )
        ],
        decisions=[decision("ACCEPTED", {"action": "merge", "id": "dec-1"})],
    )
    result = compile_project_work(p, PROJECT)
    assert result["terminal"] == "CURRENT_WORK_HOLD"
    assert result["reason"] == "ACCEPTED_NEXT_ACTION_BLOCKED"
    assert result["next_action"]["blocked_by_active"] == ["ci"]
    assert result["execution_authorized"] is False


def test_without_terminal_decision_highest_priority_unblocked_proposal_is_selected():
    p = projection(
        claims=[
            claim("project.next_action", {"action": "low", "priority": 10}, scope="a", cid="low"),
            claim("project.next_action", {"action": "high", "priority": 80}, scope="b", cid="high"),
            claim(
                "project.open_loop",
                {"id": "loop", "title": "loop", "status": "OPEN", "next_action": "loop action", "priority": 50},
                scope="loop",
                cid="loop-claim",
            ),
        ]
    )
    result = compile_project_work(p, PROJECT)
    assert result["terminal"] == "CURRENT_WORK_PASS"
    assert result["reason"] == "PROPOSED_NEXT_ACTION_SELECTED"
    assert result["next_action"]["action"] == "high"
    assert result["next_action"]["authority_status"] == "PROPOSED_FROM_CLAIM"
    assert result["decision_needed"] is True
    assert result["execution_authorized"] is False


def test_malformed_recognized_project_claim_is_revise_not_silently_ignored():
    p = projection(claims=[claim("project.open_loop", {"status": "OPEN"}, scope="bad", cid="bad")])
    result = compile_project_work(p, PROJECT)
    assert result["terminal"] == "CURRENT_WORK_REVISE"
    assert result["reason"] == "PROJECT_MEMORY_CONFLICT"
    assert any("open_loop.title" in item for item in result["errors"])


def test_project_filter_never_uses_another_projects_action():
    other = claim("project.next_action", "wrong", cid="other")
    other["subject_id"] = "project:other"
    p = projection(claims=[other])
    result = compile_project_work(p, PROJECT)
    assert result["terminal"] == "CURRENT_WORK_PASS"
    assert result["reason"] == "NO_NEXT_ACTION_RECORDED"
    assert result["next_action"] is None


def test_missing_operational_db_is_not_created(tmp_path):
    path = tmp_path / "missing" / "memory.db"
    result = build_current_work_from_db(path, PROJECT)
    assert result["terminal"] == "CURRENT_WORK_REVISE"
    assert result["reason"] == "OPERATIONAL_MEMORY_MISSING"
    assert not path.exists()
    assert not path.parent.exists()


def test_real_operational_memory_projection_is_read_only_under_current_binding(monkeypatch, tmp_path):
    clear_current(monkeypatch)
    path = tmp_path / "operational.db"
    with OperationalMemory(str(path)) as memory:
        memory.record_claim(
            subject_id=PROJECT,
            predicate="project.goal",
            value="make continuity useful",
            scope="global",
            evidence_state="SOURCE_BACKED",
            evidence_refs=[REF],
            actor_type="DETERMINISTIC_CONTROLLER",
            actor_id="controller",
            valid_from="2026-08-09T10:00:00+00:00",
            recorded_at="2026-08-09T10:00:00+00:00",
        )
        memory.record_claim(
            subject_id=PROJECT,
            predicate="project.open_loop",
            value={
                "id": "r35",
                "title": "Build projector",
                "status": "OPEN",
                "next_action": "finish R35",
                "priority": 70,
            },
            scope="r35",
            evidence_state="SOURCE_BACKED",
            evidence_refs=[REF],
            actor_type="DETERMINISTIC_CONTROLLER",
            actor_id="controller",
            valid_from="2026-08-09T10:01:00+00:00",
            recorded_at="2026-08-09T10:01:00+00:00",
        )
    before = path.read_bytes()

    set_current(monkeypatch)
    result = build_current_work_from_db(path, PROJECT)

    assert result["terminal"] == "CURRENT_WORK_PASS"
    assert result["next_action"]["action"] == "finish R35"
    assert result["operational_memory"]["verified"] is True
    assert path.read_bytes() == before
    assert not (tmp_path / "operational.db-wal").exists() or (tmp_path / "operational.db-wal").stat().st_size == 0


def test_capsule_hash_is_deterministic():
    p = projection(claims=[claim("project.next_action", "same", cid="same")])
    first = compile_project_work(json.loads(json.dumps(p)), PROJECT)
    second = compile_project_work(json.loads(json.dumps(p)), PROJECT)
    assert first["capsule_sha256"] == second["capsule_sha256"]
