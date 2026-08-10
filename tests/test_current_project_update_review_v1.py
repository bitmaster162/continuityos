from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

import continuityos.operational_memory_apply as apply
from continuityos.current_claim_sync import REQUEST_SCHEMA
from continuityos.current_project_update_review import build_project_update_review_packet
from continuityos.operational_memory import OperationalMemory, strict_json_loads

PROJECT = "project:r52-review"
SEED_REF = {"sha256": "d" * 64, "locator": "evidence://r52/seed"}


def write_json(path: Path, value) -> str:
    payload = (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    path.write_bytes(payload)
    return hashlib.sha256(payload).hexdigest()


def seed_db(path: Path):
    with OperationalMemory(str(path)) as memory:
        memory.record_claim(
            subject_id=PROJECT,
            predicate="project.status",
            scope="global",
            value={"state": "OLD"},
            evidence_state="VERIFIED",
            evidence_refs=[SEED_REF],
            actor_type="DETERMINISTIC_CONTROLLER",
            actor_id="r52-seed",
            valid_from="2026-08-10T05:00:00Z",
            recorded_at="2026-08-10T05:00:00Z",
        )
        assert memory.verify()["ok"] is True


def request(evidence: Path):
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
        "rationale": "review exact project update before separate authority decision",
    }


def test_review_packet_composes_current_work_target_bound_proposal_and_incomplete_auth(tmp_path):
    db = tmp_path / "project.db"
    seed_db(db)
    evidence = tmp_path / "evidence.json"
    write_json(evidence, {"status": "PASS", "frontier": "r52"})
    before = db.read_bytes()

    result = build_project_update_review_packet(db, request(evidence))

    assert result["terminal"] == "CURRENT_PROJECT_UPDATE_REVIEW_PASS", result
    assert result["reason"] == "TARGET_BOUND_CLAIM_UPDATE_READY_FOR_SEPARATE_AUTHORITY_REVIEW"
    assert result["project_id"] == PROJECT
    assert result["current_work"]["project_id"] == PROJECT
    assert result["claim_sync_plan"]["terminal"] == "CURRENT_CLAIM_SYNC_PLAN_PASS"
    assert result["claim_sync_plan"]["selector_resolutions"][0]["resolution"] == "SUPERSEDE_CURRENT"
    proposal = result["claim_sync_plan"]["delta_proposal"]
    assert proposal["operational_memory"]["path"] == str(db.absolute())
    assert result["proposal"]["operational_memory_target"]["path"] == str(db.absolute())
    canonical = result["proposal"]["proposal_canonical_json"]
    assert strict_json_loads(canonical) == proposal
    expected_sha = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    assert result["proposal"]["proposal_file_sha256"] == expected_sha
    assert result["proposal"]["proposal_file_size_bytes"] == len(canonical.encode("utf-8"))

    review = result["authorization_review"]
    skeleton = review["authorization_skeleton"]
    assert skeleton["proposal_file_sha256"] == expected_sha
    assert skeleton["proposal_id"] == proposal["proposal_id"]
    assert skeleton["decision"] is None
    assert skeleton["authority_class"] is None
    assert skeleton["authority_id"] is None
    assert skeleton["apply_recorded_at"] is None
    assert review["authorization_skeleton_is_r37_valid"] is False
    assert result["authorization_granted"] is False
    assert result["execution_authorized"] is False
    assert result["effects"]["filesystem_write"] is False
    assert result["effects"]["operational_memory_write"] is False
    with pytest.raises(Exception):
        apply._validate_authorization(
            skeleton,
            proposal=proposal,
            proposal_file_sha256=expected_sha,
        )
    assert db.read_bytes() == before


def test_review_packet_is_deterministic_and_does_not_write(tmp_path):
    db = tmp_path / "project.db"
    seed_db(db)
    evidence = tmp_path / "evidence.json"
    write_json(evidence, {"status": "PASS", "frontier": "stable"})
    req = request(evidence)
    before_sha = hashlib.sha256(db.read_bytes()).hexdigest()

    first = build_project_update_review_packet(db, req)
    second = build_project_update_review_packet(db, req)

    assert first == second
    assert first["packet_id"].startswith("purp-")
    assert hashlib.sha256(db.read_bytes()).hexdigest() == before_sha


def test_packet_proposal_sha_changes_when_exact_evidence_bytes_change(tmp_path):
    db = tmp_path / "project.db"
    seed_db(db)
    evidence = tmp_path / "evidence.json"
    write_json(evidence, {"status": "PASS", "version": 1})
    first = build_project_update_review_packet(db, request(evidence))
    assert first["terminal"] == "CURRENT_PROJECT_UPDATE_REVIEW_PASS"

    write_json(evidence, {"status": "PASS", "version": 2})
    second = build_project_update_review_packet(db, request(evidence))

    assert second["terminal"] == "CURRENT_PROJECT_UPDATE_REVIEW_PASS"
    assert first["proposal"]["proposal_file_sha256"] != second["proposal"]["proposal_file_sha256"]
    assert first["packet_id"] != second["packet_id"]


def test_invalid_claim_sync_request_propagates_revise_without_writing(tmp_path):
    db = tmp_path / "project.db"
    seed_db(db)
    before = db.read_bytes()
    bad = {
        "schema": REQUEST_SCHEMA,
        "project_id": PROJECT,
        "evidence": [],
        "claims": [{
            "predicate": "project.status",
            "scope": "global",
            "value": {"state": "BAD"},
            "evidence_state": "VERIFIED",
            "evidence_ids": [],
        }],
    }

    result = build_project_update_review_packet(db, bad)

    assert result["terminal"] == "CURRENT_PROJECT_UPDATE_REVIEW_REVISE"
    assert result["reason"] == "CLAIM_SYNC_PLAN_NOT_READY"
    assert result["proposal"] is None
    assert result["authorization_review"] is None
    assert result["execution_authorized"] is False
    assert db.read_bytes() == before
