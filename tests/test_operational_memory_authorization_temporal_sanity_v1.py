from __future__ import annotations

from datetime import datetime, timezone
import hashlib
from pathlib import Path

import continuityos.operational_memory_apply as apply
import continuityos.operational_memory_temporal_guard as temporal_guard
from continuityos.current_memory_apply_check import check_authorized_memory_delta
from continuityos.current_bootstrap_check import check_project_memory_bootstrap
from continuityos.current_memory_delta import REQUEST_SCHEMA, build_memory_delta_proposal_from_db
from continuityos.operational_memory import OperationalMemory, _canonical_json
import continuityos.project_memory_bootstrap as bootstrap

PROJECT = "project:r46-temporal"
NOW = datetime(2026, 8, 10, 4, 30, 0, tzinfo=timezone.utc)


def _write(path: Path, value) -> None:
    path.write_text(_canonical_json(value), encoding="utf-8", newline="")


def _fixture(tmp_path: Path):
    db = tmp_path / "memory.db"
    with OperationalMemory(str(db)) as memory:
        memory.record_claim(
            subject_id=PROJECT,
            predicate="project.status",
            scope="global",
            value={"state": "READY"},
            evidence_state="UNKNOWN",
            evidence_refs=[],
            valid_from="2026-08-10T04:00:00Z",
            actor_type="DETERMINISTIC_CONTROLLER",
            actor_id="R46_TEST_SEED",
            recorded_at="2026-08-10T04:00:00Z",
        )
        assert memory.verify()["ok"] is True
    request = {
        "schema": REQUEST_SCHEMA,
        "project_id": PROJECT,
        "operations": [{
            "op": "RECORD_CLAIM",
            "predicate": "project.open_loop",
            "scope": "temporal",
            "value": {"id": "temporal", "status": "OPEN"},
            "evidence_state": "UNKNOWN",
            "evidence_refs": [],
            "valid_from": "2026-08-10T04:01:00Z",
        }],
        "rationale": "R46 temporal-sanity regression",
    }
    proposal = build_memory_delta_proposal_from_db(db, request)
    assert proposal["terminal"] == "CURRENT_MEMORY_DELTA_PROPOSAL_PASS"
    proposal_path = tmp_path / "proposal.json"
    _write(proposal_path, proposal)
    return db, proposal, proposal_path


def _authorization(proposal, proposal_path: Path, apply_recorded_at: str):
    base = proposal["base"]
    return {
        "schema": apply.AUTH_SCHEMA,
        "decision": apply.AUTH_DECISION,
        "proposal_id": proposal["proposal_id"],
        "proposal_file_sha256": apply._sha_bytes(proposal_path.read_bytes()),
        "project_id": proposal["project_id"],
        "base_projection_sha256": base["projection_sha256"],
        "base_event_cursor": base["event_cursor"],
        "base_event_chain_head": base["event_chain_head"],
        "operation_count": len(proposal["operations"]),
        "authority_class": "DETERMINISTIC_CONTROLLER",
        "authority_id": "R46_TEST_CONTROLLER",
        "authority_ref": "test://r46/temporal-sanity",
        "apply_recorded_at": apply_recorded_at,
        "rationale": "R46 temporal-sanity test authorization",
    }


def _bootstrap_fixture(tmp_path: Path, bootstrap_recorded_at: str):
    evidence = tmp_path / "bootstrap-evidence.json"
    evidence.write_text('{"status":"PASS"}', encoding="utf-8", newline="")
    evidence_sha = hashlib.sha256(evidence.read_bytes()).hexdigest()
    manifest = {
        "schema": bootstrap.MANIFEST_SCHEMA,
        "project_id": "project:r46-bootstrap-temporal",
        "evidence": [{
            "evidence_id": "proof",
            "sha256": evidence_sha,
            "locator": str(evidence),
        }],
        "claims": [{
            "predicate": "project.status",
            "scope": "global",
            "value": {"state": "BOOTSTRAPPED"},
            "evidence_state": "VERIFIED",
            "evidence_ids": ["proof"],
            "valid_from": "2026-08-10T04:00:00Z",
            "recorded_at": "2026-08-10T04:00:00Z",
        }],
        "proposed_decisions": [],
    }
    manifest_path = tmp_path / "bootstrap-manifest.json"
    _write(manifest_path, manifest)
    target = tmp_path / "bootstrap.db"
    authorization = {
        "schema": bootstrap.AUTH_SCHEMA,
        "decision": bootstrap.AUTH_DECISION,
        "manifest_file_sha256": hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
        "project_id": manifest["project_id"],
        "target_db": str(target.absolute()),
        "claim_count": 1,
        "proposed_decision_count": 0,
        "authority_class": "DETERMINISTIC_CONTROLLER",
        "authority_id": "R46_BOOTSTRAP_TEST_CONTROLLER",
        "authority_ref": "test://r46/bootstrap-temporal-sanity",
        "bootstrap_recorded_at": bootstrap_recorded_at,
        "rationale": "R46 bootstrap temporal-sanity test authorization",
    }
    auth_path = tmp_path / "bootstrap-auth.json"
    _write(auth_path, authorization)
    return target, manifest_path, auth_path


def test_far_future_authorization_is_rejected_by_r44_and_r37_before_write(monkeypatch, tmp_path):
    db, proposal, proposal_path = _fixture(tmp_path)
    auth = _authorization(proposal, proposal_path, "9999-12-31T23:59:59Z")
    auth_path = tmp_path / "future-auth.json"
    _write(auth_path, auth)
    monkeypatch.setattr(temporal_guard, "_utc_now", lambda: NOW)

    checked = check_authorized_memory_delta(db, proposal_path, auth_path)
    assert checked["terminal"] == "CURRENT_MEMORY_APPLY_CHECK_REVISE"
    assert checked["reason"] == "APPLY_ARTIFACT_INVALID"
    assert any("future clock skew" in item for item in checked["errors"])

    before = db.read_bytes()
    monkeypatch.setattr(apply, "inspect_current_session", lambda: {"mode": apply.MODE_LEGACY})
    applied = apply.apply_authorized_memory_delta(db, proposal_path, auth_path)
    assert applied["terminal"] == "CURRENT_MEMORY_APPLY_REVISE"
    assert applied["reason"] == "APPLY_ARTIFACT_INVALID"
    assert any("future clock skew" in item for item in applied["errors"])
    assert db.read_bytes() == before


def test_far_future_bootstrap_authorization_is_rejected_by_r41_and_r38_before_target_creation(monkeypatch, tmp_path):
    target, manifest_path, auth_path = _bootstrap_fixture(tmp_path, "9999-12-31T23:59:59Z")
    monkeypatch.setattr(temporal_guard, "_utc_now", lambda: NOW)

    checked = check_project_memory_bootstrap(target, manifest_path, auth_path)
    assert checked["terminal"] == "CURRENT_BOOTSTRAP_CHECK_REVISE"
    assert checked["reason"] == "BOOTSTRAP_ARTIFACT_INVALID"
    assert any("future clock skew" in item for item in checked["errors"])
    assert not target.exists()

    monkeypatch.setattr(
        bootstrap.boundary,
        "inspect_current_session",
        lambda: {"mode": bootstrap.boundary.MODE_LEGACY},
    )
    result = bootstrap.bootstrap_project_memory(target, manifest_path, auth_path)
    assert result["terminal"] == "PROJECT_MEMORY_BOOTSTRAP_REVISE"
    assert result["reason"] == "BOOTSTRAP_ARTIFACT_INVALID"
    assert any("future clock skew" in item for item in result["errors"])
    assert not target.exists()
    assert list(tmp_path.glob(f".{target.name}.bootstrap-*")) == []


def test_small_positive_clock_skew_is_accepted(monkeypatch, tmp_path):
    _, proposal, proposal_path = _fixture(tmp_path)
    auth = _authorization(proposal, proposal_path, "2026-08-10T04:35:00Z")
    monkeypatch.setattr(temporal_guard, "_utc_now", lambda: NOW)

    validated = apply._validate_authorization(
        auth,
        proposal=proposal,
        proposal_file_sha256=apply._sha_bytes(proposal_path.read_bytes()),
    )
    assert validated["apply_recorded_at"] == "2026-08-10T04:35:00.000000Z"


def test_timestamp_beyond_clock_skew_is_rejected(monkeypatch, tmp_path):
    _, proposal, proposal_path = _fixture(tmp_path)
    auth = _authorization(proposal, proposal_path, "2026-08-10T04:35:00.000001Z")
    monkeypatch.setattr(temporal_guard, "_utc_now", lambda: NOW)

    try:
        apply._validate_authorization(
            auth,
            proposal=proposal,
            proposal_file_sha256=apply._sha_bytes(proposal_path.read_bytes()),
        )
    except ValueError as exc:
        assert "future clock skew" in str(exc)
    else:
        raise AssertionError("authorization beyond future clock skew unexpectedly validated")


def test_delayed_historical_authorization_remains_valid(monkeypatch, tmp_path):
    _, proposal, proposal_path = _fixture(tmp_path)
    auth = _authorization(proposal, proposal_path, "2026-08-10T04:10:00Z")
    monkeypatch.setattr(
        temporal_guard,
        "_utc_now",
        lambda: datetime(2026, 8, 12, 0, 0, 0, tzinfo=timezone.utc),
    )

    validated = apply._validate_authorization(
        auth,
        proposal=proposal,
        proposal_file_sha256=apply._sha_bytes(proposal_path.read_bytes()),
    )
    assert validated["apply_recorded_at"] == "2026-08-10T04:10:00.000000Z"
