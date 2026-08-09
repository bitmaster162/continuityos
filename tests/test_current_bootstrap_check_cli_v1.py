from __future__ import annotations

import hashlib
import json
from pathlib import Path

import continuityos.current_bootstrap_check_cli as cli
import continuityos.current_effect_boundary as boundary
import continuityos.project_memory_bootstrap as boot


def _write_json(path: Path, value) -> str:
    payload = (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    path.write_bytes(payload)
    return hashlib.sha256(payload).hexdigest()


def _artifacts(tmp_path: Path):
    target = tmp_path / "project.db"
    evidence = tmp_path / "evidence.json"
    evidence_sha = _write_json(evidence, {"status": "PASS"})
    manifest = {
        "schema": boot.MANIFEST_SCHEMA,
        "project_id": "project:r41-cli",
        "evidence": [{"evidence_id": "proof", "sha256": evidence_sha, "locator": str(evidence)}],
        "claims": [{
            "predicate": "project.status",
            "scope": "global",
            "value": "READY",
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
        "project_id": "project:r41-cli",
        "target_db": str(target.absolute()),
        "claim_count": 1,
        "proposed_decision_count": 0,
        "authority_class": "DETERMINISTIC_CONTROLLER",
        "authority_id": "R41_CLI_TEST",
        "authority_ref": "test://r41/cli",
        "bootstrap_recorded_at": "2026-08-10T00:01:00Z",
        "rationale": "preflight",
    }
    authorization_path = tmp_path / "authorization.json"
    _write_json(authorization_path, authorization)
    return target, manifest_path, authorization_path


def _current_state():
    return {
        "mode": boundary.MODE_CURRENT,
        "binding_verified": True,
        "authority_generation": "R64",
        "challenge_id": "b" * 64,
        "challenge_sha256": "a" * 64,
        "session_effect_ceiling": "READ_ONLY",
        "authority_ceiling": "NO_FURTHER_AGENT_WORK",
    }


def test_cli_requires_verified_current_session_before_reading_inputs(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(cli, "inspect_current_session", lambda: {"mode": boundary.MODE_LEGACY, "binding_verified": False})

    rc = cli.main([
        "--db", str(tmp_path / "missing.db"),
        "--manifest", str(tmp_path / "missing-manifest.json"),
        "--authorization", str(tmp_path / "missing-auth.json"),
    ])
    result = json.loads(capsys.readouterr().out)

    assert rc == 2
    assert result["reason"] == "VERIFIED_CURRENT_SESSION_REQUIRED"
    assert result["legacy_fallback"] is False
    assert result["execution_authorized"] is False
    assert result["effects"]["filesystem_write"] is False


def test_cli_ready_is_read_only_and_binds_current_identity(monkeypatch, tmp_path, capsys):
    target, manifest_path, authorization_path = _artifacts(tmp_path)
    before = {path.name: path.read_bytes() for path in tmp_path.iterdir() if path.is_file()}
    monkeypatch.setattr(cli, "inspect_current_session", _current_state)

    rc = cli.main([
        "--db", str(target),
        "--manifest", str(manifest_path),
        "--authorization", str(authorization_path),
    ])
    result = json.loads(capsys.readouterr().out)
    after = {path.name: path.read_bytes() for path in tmp_path.iterdir() if path.is_file()}

    assert rc == 0
    assert result["terminal"] == "CURRENT_BOOTSTRAP_CHECK_READY"
    assert result["current_session"]["binding_verified"] is True
    assert result["current_session"]["authority_generation"] == "R64"
    assert result["current_session"]["session_effect_ceiling"] == "READ_ONLY"
    assert result["authorization_record_valid"] is True
    assert result["authorization_identity_authenticated"] is False
    assert result["bootstrap_status"] == "NOT_APPLIED"
    assert result["effectful_gate_required"] is True
    assert result["r38_revalidation_required"] is True
    assert result["execution_authorized"] is False
    assert not target.exists()
    assert after == before
