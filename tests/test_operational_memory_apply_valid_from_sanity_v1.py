from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path

import continuityos.operational_memory_apply as apply
import continuityos.operational_memory_temporal_guard as temporal_guard
from continuityos.current_memory_apply_check import check_authorized_memory_delta
from continuityos.current_memory_delta import REQUEST_SCHEMA, build_memory_delta_proposal_from_db
from continuityos.operational_memory import OperationalMemory, _canonical_json

PROJECT = "project:r50-apply-valid-from"
NOW = datetime(2026, 8, 10, 6, 0, 0, tzinfo=timezone.utc)


def _write(path: Path, value) -> str:
    payload = _canonical_json(value).encode("utf-8")
    path.write_bytes(payload)
    return hashlib.sha256(payload).hexdigest()


def _fixture(tmp_path: Path, *, valid_from: str | None, valid_to: str | None = None):
    seed_time = "2026-08-10T05:30:00Z"
    db = tmp_path / "memory.db"
    with OperationalMemory(str(db)) as memory:
        memory.record_claim(
            subject_id=PROJECT,
            predicate="project.status",
            scope="global",
            value={"state": "READY"},
            evidence_state="UNKNOWN",
            evidence_refs=[],
            valid_from=seed_time,
            actor_type="DETERMINISTIC_CONTROLLER",
            actor_id="R50_TEST_SEED",
            recorded_at=seed_time,
        )
        assert memory.verify()["ok"] is True

    operation = {
        "op": "RECORD_CLAIM",
        "predicate": "project.open_loop",
        "scope": "r50",
        "value": {"id": "r50", "status": "OPEN"},
        "evidence_state": "UNKNOWN",
        "evidence_refs": [],
    }
    if valid_from is not None:
        operation["valid_from"] = valid_from
    if valid_to is not None:
        operation["valid_to"] = valid_to
    request = {
        "schema": REQUEST_SCHEMA,
        "project_id": PROJECT,
        "operations": [operation],
        "rationale": "R50 apply valid_from temporal regression",
    }
    proposal = build_memory_delta_proposal_from_db(db, request)
    assert proposal["terminal"] == "CURRENT_MEMORY_DELTA_PROPOSAL_PASS"
    proposal_path = tmp_path / "proposal.json"
    proposal_sha = _write(proposal_path, proposal)
    return db, proposal, proposal_path, proposal_sha


def _authorization(proposal, proposal_sha: str):
    base = proposal["base"]
    return {
        "schema": apply.AUTH_SCHEMA,
        "decision": apply.AUTH_DECISION,
        "proposal_id": proposal["proposal_id"],
        "proposal_file_sha256": proposal_sha,
        "project_id": proposal["project_id"],
        "base_projection_sha256": base["projection_sha256"],
        "base_event_cursor": base["event_cursor"],
        "base_event_chain_head": base["event_chain_head"],
        "operation_count": len(proposal["operations"]),
        "authority_class": "DETERMINISTIC_CONTROLLER",
        "authority_id": "R50_TEST_CONTROLLER",
        "authority_ref": "test://r50/apply-valid-from",
        "apply_recorded_at": "2026-08-10T06:00:00Z",
        "rationale": "R50 apply valid_from authorization",
    }


def test_future_valid_from_is_rejected_by_r44_and_r37_without_write(monkeypatch, tmp_path):
    db, proposal, proposal_path, proposal_sha = _fixture(
        tmp_path,
        valid_from="9999-12-31T23:59:59Z",
    )
    auth_path = tmp_path / "authorization.json"
    _write(auth_path, _authorization(proposal, proposal_sha))
    monkeypatch.setattr(temporal_guard, "_utc_now", lambda: NOW)

    checked = check_authorized_memory_delta(db, proposal_path, auth_path)
    assert checked["terminal"] == "CURRENT_MEMORY_APPLY_CHECK_REVISE"
    assert checked["reason"] == "APPLY_ARTIFACT_INVALID"
    assert any("operations[0].valid_from exceeds apply_recorded_at" in item for item in checked["errors"])

    before = db.read_bytes()
    monkeypatch.setattr(apply, "inspect_current_session", lambda: {"mode": apply.MODE_LEGACY})
    applied = apply.apply_authorized_memory_delta(db, proposal_path, auth_path)
    assert applied["terminal"] == "CURRENT_MEMORY_APPLY_REVISE"
    assert applied["reason"] == "APPLY_ARTIFACT_INVALID"
    assert any("operations[0].valid_from exceeds apply_recorded_at" in item for item in applied["errors"])
    assert db.read_bytes() == before


def test_valid_from_equal_to_apply_authority_is_accepted(monkeypatch, tmp_path):
    db, proposal, proposal_path, proposal_sha = _fixture(
        tmp_path,
        valid_from="2026-08-10T06:00:00Z",
    )
    auth_path = tmp_path / "authorization.json"
    _write(auth_path, _authorization(proposal, proposal_sha))
    monkeypatch.setattr(temporal_guard, "_utc_now", lambda: NOW)

    checked = check_authorized_memory_delta(db, proposal_path, auth_path)
    assert checked["terminal"] == "CURRENT_MEMORY_APPLY_CHECK_READY"
    assert checked["reason"] == "ARTIFACTS_BASE_AND_OPERATION_TARGETS_VALIDATED"


def test_historical_valid_from_with_future_valid_to_remains_accepted(monkeypatch, tmp_path):
    db, proposal, proposal_path, proposal_sha = _fixture(
        tmp_path,
        valid_from="2026-08-01T00:00:00Z",
        valid_to="2027-08-01T00:00:00Z",
    )
    auth_path = tmp_path / "authorization.json"
    _write(auth_path, _authorization(proposal, proposal_sha))
    monkeypatch.setattr(temporal_guard, "_utc_now", lambda: NOW)

    checked = check_authorized_memory_delta(db, proposal_path, auth_path)
    assert checked["terminal"] == "CURRENT_MEMORY_APPLY_CHECK_READY"


def test_omitted_valid_from_remains_accepted_and_defaults_at_r37(monkeypatch, tmp_path):
    db, proposal, proposal_path, proposal_sha = _fixture(tmp_path, valid_from=None)
    auth_path = tmp_path / "authorization.json"
    _write(auth_path, _authorization(proposal, proposal_sha))
    monkeypatch.setattr(temporal_guard, "_utc_now", lambda: NOW)

    checked = check_authorized_memory_delta(db, proposal_path, auth_path)
    assert checked["terminal"] == "CURRENT_MEMORY_APPLY_CHECK_READY"


def test_r46_r48_r50_apply_guards_remain_composed():
    assert getattr(apply._validate_authorization, "__continuityos_r46_temporal_guarded__", False) is True
    assert getattr(apply._validate_authorization, "__continuityos_r50_apply_valid_from_guarded__", False) is True
    assert getattr(apply.apply_authorized_memory_delta, "__continuityos_r48_replay_guarded__", False) is True
    assert getattr(check_authorized_memory_delta, "__continuityos_r48_replay_guarded__", False) is True
