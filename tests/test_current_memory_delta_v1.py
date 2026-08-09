from __future__ import annotations

import copy
from pathlib import Path

import continuityos.current_effect_boundary as boundary
from continuityos.current_memory_delta import (
    PROPOSAL_SCHEMA,
    REQUEST_SCHEMA,
    build_memory_delta_proposal_from_db,
    compile_memory_delta_proposal,
)
from continuityos.operational_memory import OperationalMemory

PROJECT = "project:continuityos"
REF = {"sha256": "a" * 64, "locator": "evidence://r36"}


def projection(*, claims=None, decisions=None):
    return {
        "schema": "continuityos.common_operational_memory.projection.v1",
        "mode": "SHADOW_ONLY",
        "event_cursor": 9,
        "event_chain_head": "b" * 64,
        "valid_at": "2026-08-09T13:00:00.000000Z",
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


def claim(cid="clm-current", predicate="project.open_loop", scope="r36", value=None):
    return {
        "claim_id": cid,
        "subject_id": PROJECT,
        "predicate": predicate,
        "value": value if value is not None else {"id": scope, "title": scope, "status": "OPEN"},
        "scope": scope,
        "evidence_state": "SOURCE_BACKED",
        "valid_from": "2026-08-09T12:00:00.000000Z",
        "valid_to": None,
        "recorded_at": "2026-08-09T12:00:00.000000Z",
        "supersedes_id": None,
        "source_event_id": "evt-claim",
        "evidence_refs": [REF],
        "claim_hash": "d" * 64,
    }


def decision(did="dec-current", decision_type="NEXT_ACTION", state="PROPOSED"):
    return {
        "decision_id": did,
        "subject_id": PROJECT,
        "decision_type": decision_type,
        "state": state,
        "value": {"action": "old"},
        "rationale": "old",
        "authority_class": "AGENT",
        "authority_id": "GPT",
        "authority_ref": None,
        "recorded_at": "2026-08-09T12:00:00.000000Z",
        "supersedes_id": None,
        "source_event_id": "evt-decision",
        "evidence_refs": [],
        "decision_hash": "e" * 64,
    }


def work(project_id=PROJECT):
    return {
        "schema": "continuityos.current_work.project_capsule/v1",
        "terminal": "CURRENT_WORK_PASS",
        "reason": "NO_NEXT_ACTION_RECORDED",
        "project_id": project_id,
        "capsule_sha256": "f" * 64,
        "execution_decision": "HOLD",
        "execution_authorized": False,
    }


def request(operations):
    return {
        "schema": REQUEST_SCHEMA,
        "project_id": PROJECT,
        "operations": operations,
        "rationale": "update operational project memory after verified evidence",
    }


def set_current(monkeypatch):
    monkeypatch.setenv(boundary.ENV_CHALLENGE, "challenge.json")
    monkeypatch.setenv(boundary.ENV_CHALLENGE_SHA, "1" * 64)
    monkeypatch.setenv(boundary.ENV_ACK, "ack.json")
    monkeypatch.setenv(boundary.ENV_REQUIRED, "1")
    monkeypatch.setattr(
        boundary,
        "verify_current_runtime_binding",
        lambda *args, **kwargs: {
            "terminal": "CURRENT_RUNTIME_BINDING_PASS",
            "binding_verified": True,
            "authority_generation": "R64",
            "challenge_id": "2" * 64,
            "challenge_sha256": "1" * 64,
            "ack_sha256": "3" * 64,
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


def test_record_claim_proposal_is_base_bound_not_applied():
    result = compile_memory_delta_proposal(
        projection(),
        work(),
        request([{
            "op": "RECORD_CLAIM",
            "predicate": "project.open_loop",
            "scope": "r37",
            "value": {"id": "r37", "title": "next", "status": "OPEN"},
            "evidence_state": "INFERENCE",
            "evidence_refs": [REF],
        }]),
    )
    assert result["terminal"] == "CURRENT_MEMORY_DELTA_PROPOSAL_PASS"
    assert result["schema"] == PROPOSAL_SCHEMA
    assert result["base"]["projection_sha256"] == "c" * 64
    assert result["base"]["event_chain_head"] == "b" * 64
    assert result["base"]["current_work_capsule_sha256"] == "f" * 64
    assert result["operations"][0]["subject_id"] == PROJECT
    assert result["apply_status"] == "NOT_APPLIED"
    assert result["apply_implemented"] is False
    assert result["execution_authorized"] is False
    assert result["effects"]["operational_memory_write"] is False


def test_supersede_claim_binds_exact_current_claim_hash():
    result = compile_memory_delta_proposal(
        projection(claims=[claim()]),
        work(),
        request([{
            "op": "SUPERSEDE_CLAIM",
            "supersedes_id": "clm-current",
            "value": {"id": "r36", "title": "done", "status": "DONE"},
            "evidence_state": "VERIFIED",
            "evidence_refs": [REF],
        }]),
    )
    op = result["operations"][0]
    assert result["terminal"] == "CURRENT_MEMORY_DELTA_PROPOSAL_PASS"
    assert op["predicate"] == "project.open_loop"
    assert op["scope"] == "r36"
    assert op["supersedes_id"] == "clm-current"
    assert op["superseded_hash"] == "d" * 64


def test_stale_or_foreign_supersede_fails_closed():
    result = compile_memory_delta_proposal(
        projection(claims=[claim()]),
        work(),
        request([{
            "op": "SUPERSEDE_CLAIM",
            "supersedes_id": "clm-not-current",
            "value": "x",
            "evidence_state": "VERIFIED",
            "evidence_refs": [REF],
        }]),
    )
    assert result["terminal"] == "CURRENT_MEMORY_DELTA_PROPOSAL_REVISE"
    assert result["reason"] == "DELTA_OPERATION_INVALID"
    assert "not a current project claim" in result["errors"][0]


def test_one_proposal_cannot_supersede_same_claim_twice():
    raw = {
        "op": "SUPERSEDE_CLAIM",
        "supersedes_id": "clm-current",
        "value": "new",
        "evidence_state": "VERIFIED",
        "evidence_refs": [REF],
    }
    result = compile_memory_delta_proposal(
        projection(claims=[claim()]), work(), request([copy.deepcopy(raw), copy.deepcopy(raw)])
    )
    assert result["terminal"] == "CURRENT_MEMORY_DELTA_PROPOSAL_REVISE"
    assert "superseded twice" in result["errors"][0]


def test_terminal_decision_requires_evidence_and_external_authority():
    bad = compile_memory_delta_proposal(
        projection(),
        work(),
        request([{
            "op": "RECORD_DECISION",
            "decision_type": "NEXT_ACTION",
            "state": "ACCEPTED",
            "value": {"action": "merge"},
            "rationale": "approved",
            "evidence_refs": [],
        }]),
    )
    assert bad["terminal"] == "CURRENT_MEMORY_DELTA_PROPOSAL_REVISE"
    assert "requires immutable evidence_refs" in bad["errors"][0]

    good = compile_memory_delta_proposal(
        projection(),
        work(),
        request([{
            "op": "RECORD_DECISION",
            "decision_type": "NEXT_ACTION",
            "state": "ACCEPTED",
            "value": {"action": "merge"},
            "rationale": "approved",
            "evidence_refs": [REF],
        }]),
    )
    assert good["terminal"] == "CURRENT_MEMORY_DELTA_PROPOSAL_PASS"
    op = good["operations"][0]
    assert op["required_authority"] == "HUMAN_OR_DETERMINISTIC_CONTROLLER"
    assert "authority_id" not in op
    assert good["execution_authorized"] is False


def test_proposed_decision_remains_proposal_review_only():
    result = compile_memory_delta_proposal(
        projection(),
        work(),
        request([{
            "op": "RECORD_DECISION",
            "decision_type": "NEXT_ACTION",
            "state": "PROPOSED",
            "value": {"action": "review R37"},
            "rationale": "candidate",
            "evidence_refs": [],
        }]),
    )
    assert result["terminal"] == "CURRENT_MEMORY_DELTA_PROPOSAL_PASS"
    assert result["operations"][0]["required_authority"] == "PROPOSAL_REVIEW"
    assert result["apply_status"] == "NOT_APPLIED"


def test_supersede_decision_binds_current_decision_hash():
    result = compile_memory_delta_proposal(
        projection(decisions=[decision()]),
        work(),
        request([{
            "op": "SUPERSEDE_DECISION",
            "supersedes_id": "dec-current",
            "state": "HOLD",
            "value": {"action": "old"},
            "rationale": "new blocker",
            "evidence_refs": [REF],
        }]),
    )
    assert result["terminal"] == "CURRENT_MEMORY_DELTA_PROPOSAL_PASS"
    op = result["operations"][0]
    assert op["decision_type"] == "NEXT_ACTION"
    assert op["superseded_hash"] == "e" * 64
    assert op["required_authority"] == "HUMAN_OR_DETERMINISTIC_CONTROLLER"


def test_request_project_must_match_current_work_capsule():
    result = compile_memory_delta_proposal(
        projection(),
        work("project:other"),
        request([{
            "op": "RECORD_CLAIM",
            "predicate": "project.status",
            "scope": "global",
            "value": "x",
            "evidence_state": "UNKNOWN",
            "evidence_refs": [],
        }]),
    )
    assert result["terminal"] == "CURRENT_MEMORY_DELTA_PROPOSAL_REVISE"
    assert result["reason"] == "CURRENT_WORK_BINDING_INVALID"


def test_malformed_top_level_request_fails_closed():
    result = compile_memory_delta_proposal(
        projection(), work(), {"schema": REQUEST_SCHEMA, "project_id": PROJECT, "operations": [], "extra": True}
    )
    assert result["terminal"] == "CURRENT_MEMORY_DELTA_PROPOSAL_REVISE"
    assert result["reason"] == "DELTA_REQUEST_INVALID"


def test_proposal_id_is_deterministic():
    req = request([{
        "op": "RECORD_CLAIM",
        "predicate": "project.status",
        "scope": "global",
        "value": {"state": "same"},
        "evidence_state": "VERIFIED",
        "evidence_refs": [REF],
    }])
    first = compile_memory_delta_proposal(copy.deepcopy(projection()), copy.deepcopy(work()), copy.deepcopy(req))
    second = compile_memory_delta_proposal(copy.deepcopy(projection()), copy.deepcopy(work()), copy.deepcopy(req))
    assert first["proposal_id"] == second["proposal_id"]
    assert first["request_sha256"] == second["request_sha256"]


def test_missing_db_is_never_created(tmp_path):
    path = tmp_path / "missing" / "memory.db"
    result = build_memory_delta_proposal_from_db(path, request([{
        "op": "RECORD_CLAIM",
        "predicate": "project.status",
        "scope": "global",
        "value": "x",
        "evidence_state": "UNKNOWN",
        "evidence_refs": [],
    }]))
    assert result["terminal"] == "CURRENT_MEMORY_DELTA_PROPOSAL_REVISE"
    assert result["reason"] == "OPERATIONAL_MEMORY_MISSING"
    assert not path.exists()
    assert not path.parent.exists()


def test_real_db_is_unchanged_when_proposal_built_under_current_session(monkeypatch, tmp_path):
    clear_current(monkeypatch)
    path = tmp_path / "operational.db"
    with OperationalMemory(str(path)) as memory:
        memory.record_claim(
            subject_id=PROJECT,
            predicate="project.status",
            value={"state": "before"},
            scope="global",
            evidence_state="SOURCE_BACKED",
            evidence_refs=[REF],
            actor_type="DETERMINISTIC_CONTROLLER",
            actor_id="controller",
            valid_from="2026-08-09T12:00:00+00:00",
            recorded_at="2026-08-09T12:00:00+00:00",
        )
        current = memory.projection()["claims"][0]
    before = path.read_bytes()

    set_current(monkeypatch)
    result = build_memory_delta_proposal_from_db(path, request([{
        "op": "SUPERSEDE_CLAIM",
        "supersedes_id": current["claim_id"],
        "value": {"state": "after"},
        "evidence_state": "VERIFIED",
        "evidence_refs": [REF],
    }]))

    assert result["terminal"] == "CURRENT_MEMORY_DELTA_PROPOSAL_PASS"
    assert result["apply_status"] == "NOT_APPLIED"
    assert result["operations"][0]["superseded_hash"] == current["claim_hash"]
    assert path.read_bytes() == before
    wal = Path(str(path) + "-wal")
    assert not wal.exists() or wal.stat().st_size == 0
