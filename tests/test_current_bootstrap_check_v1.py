from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

import continuityos.current_effect_boundary as boundary
import continuityos.project_memory_bootstrap as boot
from continuityos.current_bootstrap_check import check_project_memory_bootstrap

PROJECT = "project:r41-bootstrap-check"


def _write_json(path: Path, value) -> str:
    payload = (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    path.write_bytes(payload)
    return hashlib.sha256(payload).hexdigest()


def _clear_current(monkeypatch) -> None:
    for name in (boundary.ENV_CHALLENGE, boundary.ENV_CHALLENGE_SHA, boundary.ENV_ACK, boundary.ENV_REQUIRED):
        monkeypatch.delenv(name, raising=False)


def _artifacts(tmp_path: Path, target: Path):
    evidence = tmp_path / "evidence.json"
    evidence_sha = _write_json(evidence, {"status": "PASS", "kind": "r41-check"})
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
            "value": {"state": "READY"},
            "evidence_state": "VERIFIED",
            "evidence_ids": ["proof"],
            "valid_from": "2026-08-10T00:00:00Z",
            "recorded_at": "2026-08-10T00:00:00Z",
        }],
        "proposed_decisions": [],
    }
    manifest_path = tmp_path / "manifest.json"
    manifest_sha = _write_json(manifest_path, manifest)
    authorization = {
        "schema": boot.AUTH_SCHEMA,
        "decision": boot.AUTH_DECISION,
        "manifest_file_sha256": manifest_sha,
        "project_id": PROJECT,
        "target_db": str(target.absolute()),
        "claim_count": 1,
        "proposed_decision_count": 0,
        "authority_class": "DETERMINISTIC_CONTROLLER",
        "authority_id": "R41_CHECK_TEST",
        "authority_ref": "test://r41/bootstrap-check",
        "bootstrap_recorded_at": "2026-08-10T00:01:00Z",
        "rationale": "validate before separate effectful bootstrap",
    }
    authorization_path = tmp_path / "authorization.json"
    auth_sha = _write_json(authorization_path, authorization)
    return evidence, manifest_path, authorization_path, manifest_sha, auth_sha


def test_ready_preflight_reuses_r38_validation_without_writes(monkeypatch, tmp_path):
    _clear_current(monkeypatch)
    target = tmp_path / "project.db"
    _, manifest_path, authorization_path, manifest_sha, auth_sha = _artifacts(tmp_path, target)
    before = {path.name: path.read_bytes() for path in tmp_path.iterdir() if path.is_file()}

    result = check_project_memory_bootstrap(target, manifest_path, authorization_path)

    after = {path.name: path.read_bytes() for path in tmp_path.iterdir() if path.is_file()}
    assert result["terminal"] == "CURRENT_BOOTSTRAP_CHECK_READY"
    assert result["manifest_file_sha256"] == manifest_sha
    assert result["authorization_file_sha256"] == auth_sha
    assert result["authorization_record_valid"] is True
    assert result["authorization_identity_authenticated"] is False
    assert result["bootstrap_status"] == "NOT_APPLIED"
    assert result["bootstrap_ready"] is True
    assert result["effectful_gate_required"] is True
    assert result["r38_revalidation_required"] is True
    assert result["execution_authorized"] is False
    assert result["effects"]["filesystem_write"] is False
    assert not target.exists()
    assert after == before


def test_preflight_detects_exact_already_created_without_mutation(monkeypatch, tmp_path):
    _clear_current(monkeypatch)
    target = tmp_path / "project.db"
    _, manifest_path, authorization_path, _, _ = _artifacts(tmp_path, target)
    created = boot.bootstrap_project_memory(target, manifest_path, authorization_path)
    assert created["terminal"] == "PROJECT_MEMORY_BOOTSTRAP_PASS"
    before = target.read_bytes()

    result = check_project_memory_bootstrap(target, manifest_path, authorization_path)

    assert result["terminal"] == "CURRENT_BOOTSTRAP_CHECK_ALREADY_CREATED"
    assert result["bootstrap_status"] == "ALREADY_CREATED"
    assert result["effectful_gate_required"] is False
    assert result["r38_revalidation_required"] is False
    assert result["execution_authorized"] is False
    assert target.read_bytes() == before


def test_preflight_rejects_authorization_target_mismatch(monkeypatch, tmp_path):
    _clear_current(monkeypatch)
    target = tmp_path / "project.db"
    _, manifest_path, authorization_path, _, _ = _artifacts(tmp_path, target)
    auth = json.loads(authorization_path.read_text(encoding="utf-8"))
    auth["target_db"] = str((tmp_path / "other.db").absolute())
    _write_json(authorization_path, auth)

    result = check_project_memory_bootstrap(target, manifest_path, authorization_path)

    assert result["terminal"] == "CURRENT_BOOTSTRAP_CHECK_REVISE"
    assert result["reason"] == "BOOTSTRAP_ARTIFACT_INVALID"
    assert any("authorization target_db mismatch" in item for item in result["errors"])
    assert not target.exists()


def test_preflight_rejects_evidence_drift(monkeypatch, tmp_path):
    _clear_current(monkeypatch)
    target = tmp_path / "project.db"
    evidence, manifest_path, authorization_path, _, _ = _artifacts(tmp_path, target)
    evidence.write_bytes(b'{"status":"CHANGED"}\n')

    result = check_project_memory_bootstrap(target, manifest_path, authorization_path)

    assert result["terminal"] == "CURRENT_BOOTSTRAP_CHECK_REVISE"
    assert any("evidence SHA mismatch" in item for item in result["errors"])
    assert not target.exists()


def test_preflight_reuses_r40_symlinked_ancestor_rejection(monkeypatch, tmp_path):
    _clear_current(monkeypatch)
    physical = tmp_path / "physical"
    nested = physical / "nested"
    nested.mkdir(parents=True)
    alias = tmp_path / "authorized-alias"
    try:
        alias.symlink_to(physical, target_is_directory=True)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"directory symlink unavailable: {exc}")
    target = alias / "nested" / "project.db"
    _, manifest_path, authorization_path, _, _ = _artifacts(tmp_path, target)

    result = check_project_memory_bootstrap(target, manifest_path, authorization_path)

    assert result["terminal"] == "CURRENT_BOOTSTRAP_CHECK_REVISE"
    assert any("target parent path traverses symlink/reparse ancestor" in item for item in result["errors"])
    assert not target.exists()
    assert not (nested / "project.db").exists()
