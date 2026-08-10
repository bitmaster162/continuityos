from __future__ import annotations

import hashlib
import json
from pathlib import Path

import continuityos.operational_memory_apply as apply
from continuityos.current_claim_sync import REQUEST_SCHEMA
from continuityos.current_project_update_review import build_project_update_review_packet
from continuityos.current_project_update_preflight import preflight_project_update_packet
from continuityos.operational_memory import OperationalMemory

PROJECT = "project:r54-preflight"
SEED_REF = {"sha256": "d" * 64, "locator": "evidence://r54/seed"}


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
            actor_id="r54-seed",
            valid_from="2026-08-10T05:00:00Z",
            recorded_at="2026-08-10T05:00:00Z",
        )
        assert memory.verify()["ok"] is True


def _request(evidence: Path):
    return {
        "schema": REQUEST_SCHEMA,
        "project_id": PROJECT,
        "evidence": [{
            "evidence_id": "fresh",
            "locator": str(evidence),
            "kind": "PROVIDER_READBACK",
            "scope": PROJECT,
        }],
        "claims": [{
            "predicate": "project.status",
            "scope": "global",
            "value": {"state": "UPDATED"},
            "evidence_state": "VERIFIED",
            "evidence_ids": ["fresh"],
            "valid_from": "2026-08-10T08:00:00Z",
        }],
        "rationale": "R54 packet-aware preflight",
    }


def _packet_and_auth(tmp_path: Path):
    db = tmp_path / "project.db"
    _seed(db)
    evidence = tmp_path / "evidence.json"
    evidence.write_bytes(_json_bytes({"status": "PASS", "frontier": "r54"}))
    packet = build_project_update_review_packet(db, _request(evidence))
    assert packet["terminal"] == "CURRENT_PROJECT_UPDATE_REVIEW_PASS", packet
    auth = dict(packet["authorization_review"]["authorization_skeleton"])
    auth.update({
        "decision": apply.AUTH_DECISION,
        "authority_class": "DETERMINISTIC_CONTROLLER",
        "authority_id": "R54_TEST_CONTROLLER",
        "authority_ref": "test://r54/authority",
        "apply_recorded_at": "2026-08-10T09:00:00Z",
        "rationale": "separate authority decision for R54 regression",
    })
    return db, packet, _json_bytes(auth)


def test_packet_plus_completed_authority_is_ready_without_materializing_proposal(tmp_path):
    db, packet, auth_bytes = _packet_and_auth(tmp_path)
    before = hashlib.sha256(db.read_bytes()).hexdigest()

    result = preflight_project_update_packet(db, packet, auth_bytes)

    assert result["terminal"] == "CURRENT_PROJECT_UPDATE_PREFLIGHT_READY", result
    assert result["packet_valid"] is True
    assert result["authorization_record_valid"] is True
    assert result["authorization_identity_authenticated"] is False
    assert result["apply_ready"] is True
    assert result["apply_status"] == "NOT_APPLIED"
    assert result["execution_authorized"] is False
    assert result["effects"]["filesystem_write"] is False
    assert result["effects"]["operational_memory_write"] is False
    assert result["proposal_file_sha256"] == packet["proposal"]["proposal_file_sha256"]
    assert result["authorization_file_sha256"] == hashlib.sha256(auth_bytes).hexdigest()
    assert result["next_gate"]["current_session_must_not_run_r37"] is True
    assert hashlib.sha256(db.read_bytes()).hexdigest() == before


def test_packet_tamper_is_rejected_before_memory_preflight(tmp_path):
    db, packet, auth_bytes = _packet_and_auth(tmp_path)
    packet = json.loads(json.dumps(packet))
    packet["proposal"]["proposal_file_sha256"] = "0" * 64

    result = preflight_project_update_packet(db, packet, auth_bytes)

    assert result["terminal"] == "CURRENT_PROJECT_UPDATE_PREFLIGHT_REVISE"
    assert result["reason"] == "PACKET_OR_AUTHORIZATION_INVALID"
    assert result["packet_valid"] is False
    assert result["apply_ready"] is False


def test_wrong_authority_binding_is_rejected(tmp_path):
    db, packet, auth_bytes = _packet_and_auth(tmp_path)
    auth = json.loads(auth_bytes)
    auth["proposal_file_sha256"] = "f" * 64

    result = preflight_project_update_packet(db, packet, _json_bytes(auth))

    assert result["terminal"] == "CURRENT_PROJECT_UPDATE_PREFLIGHT_REVISE"
    assert result["reason"] == "PACKET_OR_AUTHORIZATION_INVALID"
    assert result["apply_ready"] is False


def test_memory_drift_after_r52_packet_is_stale(tmp_path):
    db, packet, auth_bytes = _packet_and_auth(tmp_path)
    with OperationalMemory(str(db)) as memory:
        memory.record_claim(
            subject_id="project:other",
            predicate="other.noise",
            scope="global",
            value={"changed": True},
            evidence_state="UNKNOWN",
            evidence_refs=[],
            actor_type="DETERMINISTIC_CONTROLLER",
            actor_id="r54-drift",
            valid_from="2026-08-10T08:30:00Z",
            recorded_at="2026-08-10T08:30:00Z",
        )
        assert memory.verify()["ok"] is True

    result = preflight_project_update_packet(db, packet, auth_bytes)

    assert result["terminal"] == "CURRENT_PROJECT_UPDATE_PREFLIGHT_REVISE"
    assert result["reason"] == "STALE_OPERATIONAL_MEMORY_BASE"
    assert result["packet_valid"] is True
    assert result["authorization_record_valid"] is True
    assert result["apply_ready"] is False


def test_byte_identical_clone_is_not_authorized_target(tmp_path):
    db, packet, auth_bytes = _packet_and_auth(tmp_path)
    clone = tmp_path / "clone.db"
    clone.write_bytes(db.read_bytes())

    result = preflight_project_update_packet(clone, packet, auth_bytes)

    assert result["terminal"] == "CURRENT_PROJECT_UPDATE_PREFLIGHT_REVISE"
    assert result["reason"] == "PACKET_OR_AUTHORIZATION_INVALID"
    assert any("target" in item.lower() for item in result["errors"])
    assert result["apply_ready"] is False
