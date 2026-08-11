from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path

import continuityos.operational_memory_apply as apply
from continuityos.current_memory_apply_check import check_authorized_memory_delta
from continuityos.current_memory_delta import REQUEST_SCHEMA, build_memory_delta_proposal_from_db
from continuityos.operational_memory import OperationalMemory, _canonical_json

PROJECT = "project:r48-replay-identity"


def _write(path: Path, value) -> str:
    payload = _canonical_json(value).encode("utf-8")
    path.write_bytes(payload)
    return hashlib.sha256(payload).hexdigest()


def _fixture(tmp_path: Path):
    now = datetime.now(timezone.utc)
    seed_time = (now - timedelta(seconds=30)).isoformat(timespec="microseconds").replace("+00:00", "Z")
    valid_from = (now - timedelta(seconds=20)).isoformat(timespec="microseconds").replace("+00:00", "Z")
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
            actor_id="R48_TEST_SEED",
            recorded_at=seed_time,
        )
        assert memory.verify()["ok"] is True
    request = {
        "schema": REQUEST_SCHEMA,
        "project_id": PROJECT,
        "operations": [{
            "op": "RECORD_CLAIM",
            "predicate": "project.open_loop",
            "scope": "r48",
            "value": {"id": "r48", "status": "OPEN"},
            "evidence_state": "UNKNOWN",
            "evidence_refs": [],
            "valid_from": valid_from,
        }],
        "rationale": "R48 replay authorization identity regression",
    }
    proposal = build_memory_delta_proposal_from_db(db, request)
    assert proposal["terminal"] == "CURRENT_MEMORY_DELTA_PROPOSAL_PASS"
    proposal_path = tmp_path / "proposal.json"
    proposal_sha = _write(proposal_path, proposal)
    return db, proposal, proposal_path, proposal_sha, now


def _authorization(proposal, proposal_sha: str, authority_id: str, timestamp: datetime):
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
        "authority_id": authority_id,
        "authority_ref": f"test://r48/{authority_id}",
        "apply_recorded_at": timestamp.isoformat(timespec="microseconds").replace("+00:00", "Z"),
        "rationale": f"R48 authorization {authority_id}",
    }


def test_exact_authorization_replay_remains_idempotent(monkeypatch, tmp_path):
    db, proposal, proposal_path, proposal_sha, now = _fixture(tmp_path)
    auth_a = tmp_path / "auth-a.json"
    auth_a_sha = _write(auth_a, _authorization(proposal, proposal_sha, "AUTH_A", now))
    monkeypatch.setattr(apply, "inspect_current_session", lambda: {"mode": apply.MODE_LEGACY})

    first = apply.apply_authorized_memory_delta(db, proposal_path, auth_a)
    assert first["terminal"] == "CURRENT_MEMORY_APPLY_PASS"
    assert first["authorization_file_sha256"] == auth_a_sha
    before = db.read_bytes()

    checked = check_authorized_memory_delta(db, proposal_path, auth_a)
    assert checked["terminal"] == "CURRENT_MEMORY_APPLY_CHECK_ALREADY_APPLIED"
    assert checked["authorization_file_sha256"] == auth_a_sha

    replay = apply.apply_authorized_memory_delta(db, proposal_path, auth_a)
    assert replay["terminal"] == "CURRENT_MEMORY_APPLY_ALREADY_APPLIED"
    assert replay["authorization_file_sha256"] == auth_a_sha
    assert replay["durable_apply_event"]["payload"]["authorization_file_sha256"] == auth_a_sha
    assert db.read_bytes() == before


def test_different_authorization_replay_is_rejected_by_r44_and_r37_without_write(monkeypatch, tmp_path):
    db, proposal, proposal_path, proposal_sha, now = _fixture(tmp_path)
    auth_a = tmp_path / "auth-a.json"
    auth_b = tmp_path / "auth-b.json"
    auth_a_sha = _write(auth_a, _authorization(proposal, proposal_sha, "AUTH_A", now))
    auth_b_sha = _write(auth_b, _authorization(proposal, proposal_sha, "AUTH_B", now + timedelta(seconds=1)))
    assert auth_a_sha != auth_b_sha
    monkeypatch.setattr(apply, "inspect_current_session", lambda: {"mode": apply.MODE_LEGACY})

    first = apply.apply_authorized_memory_delta(db, proposal_path, auth_a)
    assert first["terminal"] == "CURRENT_MEMORY_APPLY_PASS"
    before = db.read_bytes()

    checked = check_authorized_memory_delta(db, proposal_path, auth_b)
    assert checked["terminal"] == "CURRENT_MEMORY_APPLY_CHECK_REVISE"
    assert checked["reason"] == "REPLAY_AUTHORIZATION_IDENTITY_MISMATCH"
    assert checked["apply_status"] == "ALREADY_APPLIED"
    assert checked["presented_authorization_file_sha256"] == auth_b_sha
    assert checked["durable_authorization_file_sha256"] == auth_a_sha
    assert checked["durable_apply_event"]["payload"]["authorization_file_sha256"] == auth_a_sha
    assert checked["effectful_gate_required"] is False
    assert db.read_bytes() == before

    replay = apply.apply_authorized_memory_delta(db, proposal_path, auth_b)
    assert replay["terminal"] == "CURRENT_MEMORY_APPLY_REVISE"
    assert replay["reason"] == "REPLAY_AUTHORIZATION_IDENTITY_MISMATCH"
    assert replay["historical_apply_status"] == "ALREADY_APPLIED"
    assert replay["presented_authorization_file_sha256"] == auth_b_sha
    assert replay["durable_authorization_file_sha256"] == auth_a_sha
    assert replay["durable_apply_event"]["payload"]["authorization_file_sha256"] == auth_a_sha
    assert db.read_bytes() == before


def test_r46_r47_and_r48_apply_guards_remain_composed():
    assert getattr(apply._validate_authorization, "__continuityos_r46_temporal_guarded__", False) is True
    assert getattr(apply.apply_authorized_memory_delta, "__continuityos_r48_replay_guarded__", False) is True
    assert getattr(check_authorized_memory_delta, "__continuityos_r48_replay_guarded__", False) is True
