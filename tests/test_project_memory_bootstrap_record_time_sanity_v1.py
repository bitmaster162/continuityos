from __future__ import annotations

from datetime import datetime, timezone
import hashlib
from pathlib import Path

import continuityos.operational_memory_temporal_guard as temporal_guard
import continuityos.project_memory_bootstrap as boot
from continuityos.current_bootstrap_check import check_project_memory_bootstrap
from continuityos.operational_memory import _canonical_json

NOW = datetime(2026, 8, 10, 5, 10, 0, tzinfo=timezone.utc)
PROJECT = "project:r47-bootstrap-record-time"


def _write(path: Path, value) -> None:
    path.write_text(_canonical_json(value), encoding="utf-8", newline="")


def _artifacts(
    tmp_path: Path,
    *,
    bootstrap_recorded_at: str = "2026-08-10T05:10:00Z",
    claim_recorded_at: str = "2026-08-10T05:00:00Z",
    decision_recorded_at: str = "2026-08-10T05:05:00Z",
):
    evidence = tmp_path / "evidence.json"
    evidence.write_bytes(b'{"status":"PASS"}')
    evidence_sha = hashlib.sha256(evidence.read_bytes()).hexdigest()
    manifest = {
        "schema": boot.MANIFEST_SCHEMA,
        "project_id": PROJECT,
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
            "recorded_at": claim_recorded_at,
        }],
        "proposed_decisions": [{
            "decision_type": "NEXT_ACTION",
            "value": {"action": "review bootstrap", "priority": 10},
            "rationale": "proposal-only bootstrap decision",
            "evidence_ids": ["proof"],
            "recorded_at": decision_recorded_at,
        }],
    }
    manifest_path = tmp_path / "manifest.json"
    _write(manifest_path, manifest)
    target = tmp_path / "memory.db"
    authorization = {
        "schema": boot.AUTH_SCHEMA,
        "decision": boot.AUTH_DECISION,
        "manifest_file_sha256": hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
        "project_id": PROJECT,
        "target_db": str(target.absolute()),
        "claim_count": 1,
        "proposed_decision_count": 1,
        "authority_class": "DETERMINISTIC_CONTROLLER",
        "authority_id": "R47_TEST_CONTROLLER",
        "authority_ref": "test://r47/bootstrap-record-time",
        "bootstrap_recorded_at": bootstrap_recorded_at,
        "rationale": "R47 bootstrap record-time regression",
    }
    authorization_path = tmp_path / "authorization.json"
    _write(authorization_path, authorization)
    return target, manifest_path, authorization_path


def _legacy(monkeypatch) -> None:
    monkeypatch.setattr(
        boot.boundary,
        "inspect_current_session",
        lambda: {"mode": boot.boundary.MODE_LEGACY},
    )


def test_future_proposed_decision_is_rejected_by_r41_and_r38(monkeypatch, tmp_path):
    target, manifest_path, authorization_path = _artifacts(
        tmp_path,
        decision_recorded_at="9999-12-31T23:59:59Z",
    )
    monkeypatch.setattr(temporal_guard, "_utc_now", lambda: NOW)

    checked = check_project_memory_bootstrap(target, manifest_path, authorization_path)
    assert checked["terminal"] == "CURRENT_BOOTSTRAP_CHECK_REVISE"
    assert checked["reason"] == "BOOTSTRAP_ARTIFACT_INVALID"
    assert any("proposed_decisions[0].recorded_at exceeds bootstrap_recorded_at" in item for item in checked["errors"])
    assert not target.exists()

    _legacy(monkeypatch)
    result = boot.bootstrap_project_memory(target, manifest_path, authorization_path)
    assert result["terminal"] == "PROJECT_MEMORY_BOOTSTRAP_REVISE"
    assert result["reason"] == "BOOTSTRAP_ARTIFACT_INVALID"
    assert any("proposed_decisions[0].recorded_at exceeds bootstrap_recorded_at" in item for item in result["errors"])
    assert not target.exists()
    assert list(tmp_path.glob(f".{target.name}.bootstrap-*")) == []


def test_future_claim_record_time_is_rejected_before_target_creation(monkeypatch, tmp_path):
    target, manifest_path, authorization_path = _artifacts(
        tmp_path,
        claim_recorded_at="9999-12-31T23:59:59Z",
    )
    monkeypatch.setattr(temporal_guard, "_utc_now", lambda: NOW)

    checked = check_project_memory_bootstrap(target, manifest_path, authorization_path)
    assert checked["terminal"] == "CURRENT_BOOTSTRAP_CHECK_REVISE"
    assert any("claims[0].recorded_at exceeds bootstrap_recorded_at" in item for item in checked["errors"])
    assert not target.exists()


def test_record_time_equal_to_bootstrap_authority_is_accepted(monkeypatch, tmp_path):
    target, manifest_path, authorization_path = _artifacts(
        tmp_path,
        claim_recorded_at="2026-08-10T05:10:00Z",
        decision_recorded_at="2026-08-10T05:10:00Z",
    )
    monkeypatch.setattr(temporal_guard, "_utc_now", lambda: NOW)

    checked = check_project_memory_bootstrap(target, manifest_path, authorization_path)
    assert checked["terminal"] == "CURRENT_BOOTSTRAP_CHECK_READY"
    assert checked["reason"] == "ARTIFACTS_VALIDATED_TARGET_AVAILABLE"
    assert not target.exists()


def test_historical_manifest_record_times_remain_accepted(monkeypatch, tmp_path):
    target, manifest_path, authorization_path = _artifacts(
        tmp_path,
        bootstrap_recorded_at="2026-08-10T05:10:00Z",
        claim_recorded_at="2026-08-01T00:00:00Z",
        decision_recorded_at="2026-08-09T00:00:00Z",
    )
    monkeypatch.setattr(temporal_guard, "_utc_now", lambda: NOW)

    checked = check_project_memory_bootstrap(target, manifest_path, authorization_path)
    assert checked["terminal"] == "CURRENT_BOOTSTRAP_CHECK_READY"
    assert not target.exists()


def test_r40_r46_r47_guards_remain_composed_on_bootstrap():
    assert getattr(boot._safe_parent, "__continuityos_r40_target_path_guarded__", False) is True
    assert getattr(boot._validate_authorization, "__continuityos_r46_temporal_guarded__", False) is True
    assert getattr(
        boot._validate_authorization,
        "__continuityos_r47_bootstrap_record_time_guarded__",
        False,
    ) is True
