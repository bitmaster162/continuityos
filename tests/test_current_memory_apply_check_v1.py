from __future__ import annotations

import hashlib
import json
from pathlib import Path

from continuityos.current_memory_apply_check import check_authorized_memory_delta
from continuityos.current_memory_delta import REQUEST_SCHEMA, build_memory_delta_proposal_from_db
from continuityos.operational_memory import OperationalMemory, _canonical_json, _sha256_text
import continuityos.operational_memory_apply as apply

PROJECT = "project:r44-apply-check"


def _write(path: Path, value) -> str:
    payload = _canonical_json(value).encode("utf-8")
    path.write_bytes(payload)
    return hashlib.sha256(payload).hexdigest()


def _seed(db: Path):
    with OperationalMemory(str(db)) as memory:
        memory.record_claim(
            subject_id=PROJECT,
            predicate="project.status",
            scope="global",
            value={"state": "OLD"},
            evidence_state="UNKNOWN",
            evidence_refs=[],
            valid_from="2026-08-10T01:00:00Z",
            recorded_at="2026-08-10T01:00:00Z",
            actor_type="DETERMINISTIC_CONTROLLER",
            actor_id="R44_TEST_SEED",
        )
        return next(row for row in memory.projection()["claims"] if row["subject_id"] == PROJECT)


def _proposal_and_auth(tmp_path: Path, db: Path):
    current = _seed(db)
    request = {
        "schema": REQUEST_SCHEMA,
        "project_id": PROJECT,
        "operations": [{
            "op": "SUPERSEDE_CLAIM",
            "supersedes_id": current["claim_id"],
            "value": {"state": "NEW"},
            "evidence_state": "UNKNOWN",
            "evidence_refs": [],
        }],
        "rationale": "R44 exact apply-check test",
    }
    proposal = build_memory_delta_proposal_from_db(db, request)
    assert proposal["terminal"] == "CURRENT_MEMORY_DELTA_PROPOSAL_PASS"
    proposal_path = tmp_path / "proposal.json"
    proposal_sha = _write(proposal_path, proposal)
    base = proposal["base"]
    auth = {
        "schema": apply.AUTH_SCHEMA,
        "decision": apply.AUTH_DECISION,
        "proposal_id": proposal["proposal_id"],
        "proposal_file_sha256": proposal_sha,
        "project_id": PROJECT,
        "base_projection_sha256": base["projection_sha256"],
        "base_event_cursor": base["event_cursor"],
        "base_event_chain_head": base["event_chain_head"],
        "operation_count": len(proposal["operations"]),
        "authority_class": "DETERMINISTIC_CONTROLLER",
        "authority_id": "R44_TEST_CONTROLLER",
        "authority_ref": "test://r44/apply-check",
        "apply_recorded_at": "2026-08-10T04:00:00Z",
        "rationale": "point-in-time apply readiness test",
    }
    auth_path = tmp_path / "authorization.json"
    _write(auth_path, auth)
    return proposal, proposal_path, auth, auth_path


def test_exact_proposal_and_authorization_are_ready_without_db_write(tmp_path):
    db = tmp_path / "memory.db"
    proposal, proposal_path, _, auth_path = _proposal_and_auth(tmp_path, db)
    before = hashlib.sha256(db.read_bytes()).hexdigest()

    result = check_authorized_memory_delta(db, proposal_path, auth_path)

    assert result["terminal"] == "CURRENT_MEMORY_APPLY_CHECK_READY"
    assert result["apply_ready"] is True
    assert result["apply_status"] == "NOT_APPLIED"
    assert result["execution_authorized"] is False
    assert result["authorization_identity_authenticated"] is False
    assert result["proposal_id"] == proposal["proposal_id"]
    assert result["operation_targets"][0]["target"] == proposal["operations"][0]["supersedes_id"]
    assert hashlib.sha256(db.read_bytes()).hexdigest() == before


def test_memory_drift_after_proposal_fails_stale_base(tmp_path):
    db = tmp_path / "memory.db"
    _, proposal_path, _, auth_path = _proposal_and_auth(tmp_path, db)
    with OperationalMemory(str(db)) as memory:
        memory.record_claim(
            subject_id=PROJECT,
            predicate="project.note",
            scope="global",
            value="drift",
            evidence_state="UNKNOWN",
            evidence_refs=[],
            valid_from="2026-08-10T02:00:00Z",
            recorded_at="2026-08-10T02:00:00Z",
            actor_type="DETERMINISTIC_CONTROLLER",
            actor_id="R44_DRIFT",
        )

    result = check_authorized_memory_delta(db, proposal_path, auth_path)

    assert result["terminal"] == "CURRENT_MEMORY_APPLY_CHECK_REVISE"
    assert result["reason"] == "STALE_OPERATIONAL_MEMORY_BASE"
    assert result["apply_ready"] is False


def test_hash_consistent_malicious_target_is_rejected_before_effectful_gate(tmp_path):
    db = tmp_path / "memory.db"
    proposal, proposal_path, auth, auth_path = _proposal_and_auth(tmp_path, db)
    proposal["operations"][0]["supersedes_id"] = "clm-" + "f" * 32
    body = {key: proposal[key] for key in apply.PROPOSAL_BODY_KEYS}
    proposal["proposal_id"] = "omdp-" + _sha256_text(_canonical_json(body))[:40]
    proposal_sha = _write(proposal_path, proposal)
    auth["proposal_id"] = proposal["proposal_id"]
    auth["proposal_file_sha256"] = proposal_sha
    _write(auth_path, auth)

    result = check_authorized_memory_delta(db, proposal_path, auth_path)

    assert result["terminal"] == "CURRENT_MEMORY_APPLY_CHECK_REVISE"
    assert result["reason"] == "OPERATIONAL_MEMORY_PREFLIGHT_FAILED"
    assert any("supersedes claim missing" in item for item in result["errors"])


def test_exact_applied_proposal_is_reported_as_already_applied(tmp_path):
    db = tmp_path / "memory.db"
    proposal, proposal_path, _, auth_path = _proposal_and_auth(tmp_path, db)
    applied = apply.apply_authorized_memory_delta(db, proposal_path, auth_path)
    assert applied["terminal"] == "CURRENT_MEMORY_APPLY_PASS"
    before = hashlib.sha256(db.read_bytes()).hexdigest()

    result = check_authorized_memory_delta(db, proposal_path, auth_path)

    assert result["terminal"] == "CURRENT_MEMORY_APPLY_CHECK_ALREADY_APPLIED"
    assert result["reason"] == "EXACT_PROPOSAL_ALREADY_APPLIED"
    assert result["proposal_id"] == proposal["proposal_id"]
    assert result["effectful_gate_required"] is False
    assert hashlib.sha256(db.read_bytes()).hexdigest() == before
