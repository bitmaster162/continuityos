from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

import continuityos.current_effect_boundary as boundary
import continuityos.project_memory_bootstrap as boot


def _write_json(path: Path, value) -> str:
    payload = (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    path.write_bytes(payload)
    return hashlib.sha256(payload).hexdigest()


def _clear_current(monkeypatch) -> None:
    for name in (boundary.ENV_CHALLENGE, boundary.ENV_CHALLENGE_SHA, boundary.ENV_ACK, boundary.ENV_REQUIRED):
        monkeypatch.delenv(name, raising=False)


def test_bootstrap_refuses_symlinked_target_ancestor_before_any_publish(monkeypatch, tmp_path):
    _clear_current(monkeypatch)
    physical = tmp_path / "physical"
    nested = physical / "nested"
    nested.mkdir(parents=True)
    alias = tmp_path / "authorized-alias"
    try:
        alias.symlink_to(physical, target_is_directory=True)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"directory symlink unavailable: {exc}")

    evidence = tmp_path / "evidence.json"
    evidence_sha = _write_json(evidence, {"status": "PASS", "kind": "target-path-regression"})
    target = alias / "nested" / "project.db"
    manifest = {
        "schema": boot.MANIFEST_SCHEMA,
        "project_id": "project:r40-target-path",
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
        "project_id": "project:r40-target-path",
        "target_db": str(target.absolute()),
        "claim_count": 1,
        "proposed_decision_count": 0,
        "authority_class": "DETERMINISTIC_CONTROLLER",
        "authority_id": "R40_TARGET_PATH_TEST",
        "authority_ref": "test://r40/target-path",
        "bootstrap_recorded_at": "2026-08-10T00:01:00Z",
        "rationale": "authorization must not traverse a different physical parent",
    }
    authorization_path = tmp_path / "authorization.json"
    _write_json(authorization_path, authorization)

    result = boot.bootstrap_project_memory(target, manifest_path, authorization_path)

    assert result["terminal"] == "PROJECT_MEMORY_BOOTSTRAP_REVISE"
    assert result["reason"] == "BOOTSTRAP_ARTIFACT_INVALID"
    assert any("target parent path traverses symlink/reparse ancestor" in item for item in result["errors"])
    assert not target.exists()
    assert not (nested / "project.db").exists()
    assert list(nested.glob(".project.db.bootstrap-*")) == []


def test_safe_parent_remains_lexically_and_physically_identical(tmp_path):
    parent = tmp_path / "plain" / "nested"
    parent.mkdir(parents=True)
    target = parent / "project.db"

    safe = boot._safe_parent(target.absolute())

    assert safe == parent.absolute()
    assert safe == parent.resolve(strict=True)
