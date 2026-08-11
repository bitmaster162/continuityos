from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from continuityos.current_memory_apply_auth_request import build_apply_authorization_request
from continuityos.current_memory_delta import REQUEST_SCHEMA, build_memory_delta_proposal_from_db
from continuityos.operational_memory import OperationalMemory, _canonical_json
import continuityos.operational_memory_apply as apply

PROJECT = "project:r45-auth-request"


def _write(path: Path, value) -> str:
    payload = _canonical_json(value).encode("utf-8")
    path.write_bytes(payload)
    return hashlib.sha256(payload).hexdigest()


def _proposal(tmp_path: Path, db: Path):
    with OperationalMemory(str(db)) as memory:
        memory.record_claim(
            subject_id=PROJECT,
            predicate="project.status",
            scope="global",
            value={"state": "OLD"},
            evidence_state="UNKNOWN",
            evidence_refs=[],
            valid_from="2026-08-10T03:00:00Z",
            recorded_at="2026-08-10T03:00:00Z",
            actor_type="DETERMINISTIC_CONTROLLER",
            actor_id="R45_SEED",
        )
        current = next(row for row in memory.projection()["claims"] if row["subject_id"] == PROJECT)
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
        "rationale": "R45 authority-review packet test",
    }
    proposal = build_memory_delta_proposal_from_db(db, request)
    assert proposal["terminal"] == "CURRENT_MEMORY_DELTA_PROPOSAL_PASS"
    path = tmp_path / "proposal.json"
    sha = _write(path, proposal)
    return proposal, path, sha


def _valid_auth_from_packet(packet, *, apply_time="2026-08-10T03:01:00Z"):
    auth = dict(packet["authorization_skeleton"])
    auth.update({
        "decision": apply.AUTH_DECISION,
        "authority_class": "DETERMINISTIC_CONTROLLER",
        "authority_id": "R45_TEST_CONTROLLER",
        "authority_ref": "test://r45/explicit-approval",
        "apply_recorded_at": apply_time,
        "rationale": "explicit separate authority action for test",
    })
    return auth


def test_packet_binds_exact_fields_but_skeleton_cannot_authorize(tmp_path):
    db = tmp_path / "memory.db"
    proposal, proposal_path, proposal_sha = _proposal(tmp_path, db)
    before = hashlib.sha256(db.read_bytes()).hexdigest()

    packet = build_apply_authorization_request(db, proposal_path)

    assert packet["terminal"] == "CURRENT_MEMORY_APPLY_AUTH_REQUEST_PASS"
    assert packet["proposal_id"] == proposal["proposal_id"]
    assert packet["proposal_file_sha256"] == proposal_sha
    assert packet["expected_base"] == apply._expected_base(proposal)
    assert packet["operation_count"] == 1
    assert packet["authorization_artifact_created"] is False
    assert packet["authorization_granted"] is False
    assert packet["authorization_identity_authenticated"] is False
    assert packet["authorization_skeleton_is_r37_valid"] is False
    assert packet["execution_authorized"] is False
    assert packet["authorization_skeleton"]["decision"] is None
    assert packet["authorization_skeleton"]["authority_class"] is None
    assert hashlib.sha256(db.read_bytes()).hexdigest() == before

    with pytest.raises(ValueError):
        apply._validate_authorization(
            packet["authorization_skeleton"],
            proposal=proposal,
            proposal_file_sha256=proposal_sha,
        )


def test_separate_explicit_fill_can_form_r37_authorization_without_packet_granting_it(tmp_path):
    db = tmp_path / "memory.db"
    proposal, proposal_path, proposal_sha = _proposal(tmp_path, db)
    packet = build_apply_authorization_request(db, proposal_path)
    auth = _valid_auth_from_packet(packet)

    validated = apply._validate_authorization(auth, proposal=proposal, proposal_file_sha256=proposal_sha)

    assert validated["decision"] == apply.AUTH_DECISION
    assert validated["authority_class"] == "DETERMINISTIC_CONTROLLER"
    assert packet["authorization_granted"] is False
    assert packet["execution_authorized"] is False


def test_stale_memory_base_refuses_authority_request(tmp_path):
    db = tmp_path / "memory.db"
    _, proposal_path, _ = _proposal(tmp_path, db)
    with OperationalMemory(str(db)) as memory:
        memory.record_claim(
            subject_id=PROJECT,
            predicate="project.note",
            scope="global",
            value="drift",
            evidence_state="UNKNOWN",
            evidence_refs=[],
            valid_from="2026-08-10T03:00:01Z",
            recorded_at="2026-08-10T03:00:01Z",
            actor_type="DETERMINISTIC_CONTROLLER",
            actor_id="R45_DRIFT",
        )

    packet = build_apply_authorization_request(db, proposal_path)

    assert packet["terminal"] == "CURRENT_MEMORY_APPLY_AUTH_REQUEST_REVISE"
    assert packet["reason"] == "STALE_OPERATIONAL_MEMORY_BASE"
    assert packet["authorization_granted"] is False


def test_already_applied_proposal_does_not_request_authority_again(tmp_path):
    db = tmp_path / "memory.db"
    proposal, proposal_path, proposal_sha = _proposal(tmp_path, db)
    packet = build_apply_authorization_request(db, proposal_path)
    auth = _valid_auth_from_packet(packet)
    auth_path = tmp_path / "authorization.json"
    _write(auth_path, auth)
    applied = apply.apply_authorized_memory_delta(db, proposal_path, auth_path)
    assert applied["terminal"] == "CURRENT_MEMORY_APPLY_PASS"
    before = hashlib.sha256(db.read_bytes()).hexdigest()

    replay = build_apply_authorization_request(db, proposal_path)

    assert replay["terminal"] == "CURRENT_MEMORY_APPLY_AUTH_REQUEST_ALREADY_APPLIED"
    assert replay["apply_status"] == "ALREADY_APPLIED"
    assert replay["authority_review_required"] is False
    assert replay["r37_effectful_gate_required"] is False
    assert replay["proposal_file_sha256"] == proposal_sha
    assert hashlib.sha256(db.read_bytes()).hexdigest() == before
