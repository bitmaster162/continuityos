from __future__ import annotations

from datetime import datetime, timezone
import hashlib
from pathlib import Path

import continuityos.operational_memory_temporal_guard as temporal_guard
import continuityos.project_memory_bootstrap as boot
from continuityos.current_bootstrap_check import check_project_memory_bootstrap
from continuityos.operational_memory import _canonical_json

NOW = datetime(2026, 8, 10, 5, 40, 0, tzinfo=timezone.utc)
PROJECT = "project:r49-bootstrap-valid-from"


def _write(path: Path, value) -> None:
    path.write_bytes(_canonical_json(value).encode("utf-8"))


def _artifacts(tmp_path: Path, *, valid_from: str, valid_to: str | None = None):
    evidence = tmp_path / "evidence.json"
    evidence.write_bytes(b'{"status":"PASS"}')
    evidence_sha = hashlib.sha256(evidence.read_bytes()).hexdigest()
    claim = {
        "predicate": "project.status",
        "scope": "global",
        "value": {"state": "BOOTSTRAPPED"},
        "evidence_state": "VERIFIED",
        "evidence_ids": ["proof"],
        "valid_from": valid_from,
        "recorded_at": "2026-08-10T05:39:00Z",
    }
    if valid_to is not None:
        claim["valid_to"] = valid_to
    manifest = {
        "schema": boot.MANIFEST_SCHEMA,
        "project_id": PROJECT,
        "evidence": [{
            "evidence_id": "proof",
            "sha256": evidence_sha,
            "locator": str(evidence),
        }],
        "claims": [claim],
        "proposed_decisions": [],
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
        "proposed_decision_count": 0,
        "authority_class": "DETERMINISTIC_CONTROLLER",
        "authority_id": "R49_TEST_CONTROLLER",
        "authority_ref": "test://r49/bootstrap-valid-from",
        "bootstrap_recorded_at": "2026-08-10T05:40:00Z",
        "rationale": "R49 bootstrap valid_from regression",
    }
    auth_path = tmp_path / "authorization.json"
    _write(auth_path, authorization)
    return target, manifest_path, auth_path


def test_future_valid_from_is_rejected_by_r41_and_r38_before_target_creation(monkeypatch, tmp_path):
    target, manifest_path, auth_path = _artifacts(
        tmp_path,
        valid_from="9999-12-31T23:59:59Z",
    )
    monkeypatch.setattr(temporal_guard, "_utc_now", lambda: NOW)

    checked = check_project_memory_bootstrap(target, manifest_path, auth_path)
    assert checked["terminal"] == "CURRENT_BOOTSTRAP_CHECK_REVISE"
    assert checked["reason"] == "BOOTSTRAP_ARTIFACT_INVALID"
    assert any("claims[0].valid_from exceeds bootstrap_recorded_at" in item for item in checked["errors"])
    assert not target.exists()

    monkeypatch.setattr(
        boot.boundary,
        "inspect_current_session",
        lambda: {"mode": boot.boundary.MODE_LEGACY},
    )
    result = boot.bootstrap_project_memory(target, manifest_path, auth_path)
    assert result["terminal"] == "PROJECT_MEMORY_BOOTSTRAP_REVISE"
    assert result["reason"] == "BOOTSTRAP_ARTIFACT_INVALID"
    assert any("claims[0].valid_from exceeds bootstrap_recorded_at" in item for item in result["errors"])
    assert not target.exists()
    assert list(tmp_path.glob(f".{target.name}.bootstrap-*")) == []


def test_valid_from_equal_to_bootstrap_authority_is_accepted(monkeypatch, tmp_path):
    target, manifest_path, auth_path = _artifacts(
        tmp_path,
        valid_from="2026-08-10T05:40:00Z",
    )
    monkeypatch.setattr(temporal_guard, "_utc_now", lambda: NOW)

    checked = check_project_memory_bootstrap(target, manifest_path, auth_path)
    assert checked["terminal"] == "CURRENT_BOOTSTRAP_CHECK_READY"
    assert checked["reason"] == "ARTIFACTS_VALIDATED_TARGET_AVAILABLE"
    assert not target.exists()


def test_historical_valid_from_with_future_valid_to_remains_accepted(monkeypatch, tmp_path):
    target, manifest_path, auth_path = _artifacts(
        tmp_path,
        valid_from="2026-08-01T00:00:00Z",
        valid_to="2027-08-01T00:00:00Z",
    )
    monkeypatch.setattr(temporal_guard, "_utc_now", lambda: NOW)

    checked = check_project_memory_bootstrap(target, manifest_path, auth_path)
    assert checked["terminal"] == "CURRENT_BOOTSTRAP_CHECK_READY"
    assert not target.exists()


def test_r40_r46_r47_r49_guards_remain_composed_on_bootstrap():
    assert getattr(boot._safe_parent, "__continuityos_r40_target_path_guarded__", False) is True
    assert getattr(boot._validate_authorization, "__continuityos_r46_temporal_guarded__", False) is True
    assert getattr(
        boot._validate_authorization,
        "__continuityos_r47_bootstrap_record_time_guarded__",
        False,
    ) is True
    assert getattr(
        boot._validate_authorization,
        "__continuityos_r49_bootstrap_valid_from_guarded__",
        False,
    ) is True
