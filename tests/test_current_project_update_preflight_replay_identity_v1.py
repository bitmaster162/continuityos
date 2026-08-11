from __future__ import annotations

import json
from pathlib import Path

import continuityos.operational_memory_apply as apply
from continuityos.current_claim_sync import REQUEST_SCHEMA
from continuityos.current_project_update_review import build_project_update_review_packet
from continuityos.current_project_update_preflight import preflight_project_update_packet
from continuityos.operational_memory import OperationalMemory

PROJECT = "project:r54-replay"
SEED_REF = {"sha256": "d" * 64, "locator": "evidence://r54-replay/seed"}


def _json_bytes(value) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def _seed(path: Path) -> None:
    with OperationalMemory(str(path)) as memory:
        memory.record_claim(
            subject_id=PROJECT,
            predicate="project.status",
            scope="global",
            value={"state": "OLD"},
            evidence_state="VERIFIED",
            evidence_refs=[SEED_REF],
            actor_type="DETERMINISTIC_CONTROLLER",
            actor_id="r54-replay-seed",
            valid_from="2026-08-10T05:00:00Z",
            recorded_at="2026-08-10T05:00:00Z",
        )


def _packet_auth_and_proposal(tmp_path: Path):
    db = tmp_path / "project.db"
    _seed(db)
    evidence = tmp_path / "evidence.json"
    evidence.write_bytes(_json_bytes({"status": "PASS", "frontier": "r54-replay"}))
    request = {
        "schema": REQUEST_SCHEMA,
        "project_id": PROJECT,
        "evidence": [{"evidence_id": "fresh", "locator": str(evidence)}],
        "claims": [{
            "predicate": "project.status",
            "scope": "global",
            "value": {"state": "UPDATED"},
            "evidence_state": "VERIFIED",
            "evidence_ids": ["fresh"],
            "valid_from": "2026-08-10T08:00:00Z",
        }],
        "rationale": "R54 replay identity regression",
    }
    packet = build_project_update_review_packet(db, request)
    assert packet["terminal"] == "CURRENT_PROJECT_UPDATE_REVIEW_PASS", packet
    auth_a = dict(packet["authorization_review"]["authorization_skeleton"])
    auth_a.update({
        "decision": apply.AUTH_DECISION,
        "authority_class": "DETERMINISTIC_CONTROLLER",
        "authority_id": "R54_AUTH_A",
        "authority_ref": "test://r54/auth-a",
        "apply_recorded_at": "2026-08-10T09:00:00Z",
        "rationale": "first exact authorization",
    })
    auth_b = dict(auth_a)
    auth_b.update({
        "authority_id": "R54_AUTH_B",
        "authority_ref": "test://r54/auth-b",
        "rationale": "different authorization bytes for same proposal",
    })
    proposal_path = tmp_path / "proposal.json"
    proposal_path.write_bytes(packet["proposal"]["proposal_canonical_json"].encode("utf-8"))
    auth_a_path = tmp_path / "auth-a.json"
    auth_a_bytes = _json_bytes(auth_a)
    auth_a_path.write_bytes(auth_a_bytes)
    auth_b_bytes = _json_bytes(auth_b)
    return db, packet, proposal_path, auth_a_path, auth_a_bytes, auth_b_bytes


def test_exact_original_authorization_replay_reports_already_applied(tmp_path):
    db, packet, proposal_path, auth_a_path, auth_a_bytes, _ = _packet_auth_and_proposal(tmp_path)
    applied = apply.apply_authorized_memory_delta(db, proposal_path, auth_a_path)
    assert applied["terminal"] == "CURRENT_MEMORY_APPLY_PASS", applied

    result = preflight_project_update_packet(db, packet, auth_a_bytes)

    assert result["terminal"] == "CURRENT_PROJECT_UPDATE_PREFLIGHT_ALREADY_APPLIED", result
    assert result["apply_status"] == "ALREADY_APPLIED"
    assert result["authorization_file_sha256"] == applied["authorization_file_sha256"]


def test_different_valid_authorization_cannot_relabel_durable_replay(tmp_path):
    db, packet, proposal_path, auth_a_path, _, auth_b_bytes = _packet_auth_and_proposal(tmp_path)
    applied = apply.apply_authorized_memory_delta(db, proposal_path, auth_a_path)
    assert applied["terminal"] == "CURRENT_MEMORY_APPLY_PASS", applied

    result = preflight_project_update_packet(db, packet, auth_b_bytes)

    assert result["terminal"] == "CURRENT_PROJECT_UPDATE_PREFLIGHT_REVISE", result
    assert result["reason"] == "REPLAY_AUTHORIZATION_IDENTITY_MISMATCH"
    assert result["apply_ready"] is False
    assert result["durable_authorization_file_sha256"] == applied["authorization_file_sha256"]
    assert result["presented_authorization_file_sha256"] != applied["authorization_file_sha256"]
    assert result["execution_authorized"] is False
