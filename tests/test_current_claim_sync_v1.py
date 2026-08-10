from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from continuityos.current_claim_sync import (
    REQUEST_SCHEMA,
    build_claim_sync_plan_from_db,
)
from continuityos.operational_memory import OperationalMemory

PROJECT = "project:r43-claim-sync"


def _write_json(path: Path, value) -> str:
    payload = (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    path.write_bytes(payload)
    return hashlib.sha256(payload).hexdigest()


def _request(evidence: Path, *, predicate="project.status", scope="global", value=None):
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
            "predicate": predicate,
            "scope": scope,
            "value": {"state": "UPDATED"} if value is None else value,
            "evidence_state": "VERIFIED",
            "evidence_ids": ["fresh"],
            "valid_from": "2026-08-10T03:00:00Z",
            "note": "logical selector only; R43 resolves storage identity",
        }],
        "rationale": "sync exact project evidence without manual claim-id lookup",
    }


def _new_db(path: Path):
    with OperationalMemory(str(path)) as memory:
        assert memory.verify()["ok"] is True


def _seed_claim(path: Path, *, predicate="project.status", scope="global", value=None, recorded_at="2026-08-10T01:00:00Z"):
    with OperationalMemory(str(path)) as memory:
        memory.record_claim(
            subject_id=PROJECT,
            predicate=predicate,
            scope=scope,
            value={"state": "OLD"} if value is None else value,
            evidence_state="UNKNOWN",
            evidence_refs=[],
            valid_from=recorded_at,
            recorded_at=recorded_at,
            actor_type="DETERMINISTIC_CONTROLLER",
            actor_id="R43_TEST_SEED",
        )
        return next(
            row for row in memory.projection()["claims"]
            if row["subject_id"] == PROJECT and row["predicate"] == predicate and row["scope"] == scope
        )


def test_missing_selector_compiles_r36_record_claim_without_writing_db(tmp_path):
    db = tmp_path / "memory.db"
    _new_db(db)
    evidence = tmp_path / "evidence.json"
    _write_json(evidence, {"status": "PASS", "frontier": "new"})
    before = hashlib.sha256(db.read_bytes()).hexdigest()

    result = build_claim_sync_plan_from_db(db, _request(evidence))

    assert result["terminal"] == "CURRENT_CLAIM_SYNC_PLAN_PASS"
    assert result["selector_resolutions"][0]["resolution"] == "RECORD_NEW"
    assert result["delta_request"]["operations"][0]["op"] == "RECORD_CLAIM"
    proposal_op = result["delta_proposal"]["operations"][0]
    assert proposal_op["op"] == "RECORD_CLAIM"
    assert proposal_op["predicate"] == "project.status"
    assert proposal_op["scope"] == "global"
    assert proposal_op["evidence_refs"][0]["sha256"] == hashlib.sha256(evidence.read_bytes()).hexdigest()
    assert result["apply_status"] == "NOT_APPLIED"
    assert result["execution_authorized"] is False
    assert result["semantic_assertions_accepted"] is False
    assert hashlib.sha256(db.read_bytes()).hexdigest() == before


def test_existing_selector_compiles_exact_r36_supersession(tmp_path):
    db = tmp_path / "memory.db"
    _new_db(db)
    current = _seed_claim(db)
    evidence = tmp_path / "evidence.json"
    _write_json(evidence, {"status": "PASS", "frontier": "updated"})
    before = hashlib.sha256(db.read_bytes()).hexdigest()

    result = build_claim_sync_plan_from_db(db, _request(evidence))

    assert result["terminal"] == "CURRENT_CLAIM_SYNC_PLAN_PASS"
    resolution = result["selector_resolutions"][0]
    assert resolution["resolution"] == "SUPERSEDE_CURRENT"
    assert resolution["current_claim_id"] == current["claim_id"]
    assert resolution["current_claim_hash"] == current["claim_hash"]
    request_op = result["delta_request"]["operations"][0]
    assert request_op["op"] == "SUPERSEDE_CLAIM"
    assert request_op["supersedes_id"] == current["claim_id"]
    proposal_op = result["delta_proposal"]["operations"][0]
    assert proposal_op["supersedes_id"] == current["claim_id"]
    assert proposal_op["superseded_hash"] == current["claim_hash"]
    assert hashlib.sha256(db.read_bytes()).hexdigest() == before


def test_competing_current_claims_fail_closed_as_ambiguous(tmp_path):
    db = tmp_path / "memory.db"
    _new_db(db)
    _seed_claim(db, value={"state": "A"}, recorded_at="2026-08-10T01:00:00Z")
    _seed_claim(db, value={"state": "B"}, recorded_at="2026-08-10T01:01:00Z")
    evidence = tmp_path / "evidence.json"
    _write_json(evidence, {"status": "PASS"})

    result = build_claim_sync_plan_from_db(db, _request(evidence))

    assert result["terminal"] == "CURRENT_CLAIM_SYNC_PLAN_REVISE"
    assert result["reason"] == "CLAIM_SELECTOR_AMBIGUOUS"
    assert any("2 current claims" in item for item in result["errors"])
    assert result["delta_proposal"] is None


def test_duplicate_logical_selector_is_rejected_before_db_read(tmp_path):
    evidence = tmp_path / "evidence.json"
    _write_json(evidence, {"status": "PASS"})
    request = _request(evidence)
    request["claims"].append(dict(request["claims"][0]))

    result = build_claim_sync_plan_from_db(tmp_path / "missing.db", request)

    assert result["terminal"] == "CURRENT_CLAIM_SYNC_PLAN_REVISE"
    assert result["reason"] == "CLAIM_SYNC_REQUEST_INVALID"
    assert any("duplicate claim selector" in item for item in result["errors"])


def test_verified_claim_requires_evidence_and_decision_fields_are_not_accepted(tmp_path):
    evidence = tmp_path / "evidence.json"
    _write_json(evidence, {"status": "PASS"})
    request = _request(evidence)
    request["claims"][0]["evidence_ids"] = []
    result = build_claim_sync_plan_from_db(tmp_path / "missing.db", request)
    assert result["reason"] == "CLAIM_SYNC_REQUEST_INVALID"
    assert any("VERIFIED requires evidence" in item for item in result["errors"])

    request = _request(evidence)
    request["claims"][0]["decision_type"] = "NEXT_ACTION"
    result = build_claim_sync_plan_from_db(tmp_path / "missing.db", request)
    assert result["reason"] == "CLAIM_SYNC_REQUEST_INVALID"
    assert any("extra=['decision_type']" in item for item in result["errors"])


def test_unknown_claim_may_have_no_evidence(tmp_path):
    db = tmp_path / "memory.db"
    _new_db(db)
    request = {
        "schema": REQUEST_SCHEMA,
        "project_id": PROJECT,
        "evidence": [],
        "claims": [{
            "predicate": "project.note",
            "scope": "global",
            "value": "unverified operator note",
            "evidence_state": "UNKNOWN",
            "evidence_ids": [],
        }],
    }

    result = build_claim_sync_plan_from_db(db, request)

    assert result["terminal"] == "CURRENT_CLAIM_SYNC_PLAN_PASS"
    assert result["delta_proposal"]["operations"][0]["evidence_state"] == "UNKNOWN"
    assert result["delta_proposal"]["operations"][0]["evidence_refs"] == []


def test_symlink_evidence_is_refused_when_supported(tmp_path):
    db = tmp_path / "memory.db"
    _new_db(db)
    real = tmp_path / "real.json"
    _write_json(real, {"status": "PASS"})
    alias = tmp_path / "alias.json"
    try:
        alias.symlink_to(real)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"symlink unavailable: {exc}")

    result = build_claim_sync_plan_from_db(db, _request(alias))

    assert result["terminal"] == "CURRENT_CLAIM_SYNC_PLAN_REVISE"
    assert result["reason"] == "CLAIM_SYNC_REQUEST_INVALID"
    assert any("symlink/reparse refused" in item for item in result["errors"])
