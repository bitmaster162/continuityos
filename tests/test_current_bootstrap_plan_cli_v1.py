from __future__ import annotations

import json
from pathlib import Path

import continuityos.current_bootstrap_plan_cli as cli
import continuityos.current_effect_boundary as boundary
from continuityos.current_bootstrap_plan import REQUEST_SCHEMA


def _write_json(path: Path, value) -> None:
    payload = (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    path.write_bytes(payload)


def _request(tmp_path: Path) -> Path:
    evidence = tmp_path / "evidence.json"
    evidence.write_bytes(b'{"status":"PASS"}\r\n')
    request = {
        "schema": REQUEST_SCHEMA,
        "project_id": "project:continuityos",
        "evidence": [{"evidence_id": "proof", "locator": str(evidence)}],
        "claims": [{
            "predicate": "project.status",
            "scope": "global",
            "value": {"state": "ACTIVE"},
            "evidence_state": "VERIFIED",
            "evidence_ids": ["proof"],
            "valid_from": "2026-08-09T18:00:00Z",
            "recorded_at": "2026-08-09T18:00:00Z",
        }],
        "proposed_decisions": [],
    }
    path = tmp_path / "request.json"
    _write_json(path, request)
    return path


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


def test_cli_requires_verified_current_session(monkeypatch, tmp_path, capsys):
    request = _request(tmp_path)
    monkeypatch.setattr(cli, "inspect_current_session", lambda: {"mode": boundary.MODE_LEGACY, "binding_verified": False})

    rc = cli.main(["--request", str(request)])
    result = json.loads(capsys.readouterr().out)

    assert rc == 2
    assert result["reason"] == "VERIFIED_CURRENT_SESSION_REQUIRED"
    assert result["legacy_fallback"] is False
    assert result["effects"]["filesystem_write"] is False


def test_cli_pass_is_read_only_and_binds_current_identity(monkeypatch, tmp_path, capsys):
    request = _request(tmp_path)
    before = {path.name: path.read_bytes() for path in tmp_path.iterdir()}
    monkeypatch.setattr(cli, "inspect_current_session", _current_state)

    rc = cli.main(["--request", str(request)])
    result = json.loads(capsys.readouterr().out)
    after = {path.name: path.read_bytes() for path in tmp_path.iterdir()}

    assert rc == 0
    assert result["terminal"] == "CURRENT_BOOTSTRAP_PLAN_PASS"
    assert result["current_session"]["binding_verified"] is True
    assert result["current_session"]["authority_generation"] == "R64"
    assert result["current_session"]["session_effect_ceiling"] == "READ_ONLY"
    assert result["request_input"]["schema"] == REQUEST_SCHEMA
    assert result["authorization_required"] is True
    assert result["semantic_assertions_accepted"] is False
    assert result["execution_authorized"] is False
    assert after == before


def test_cli_duplicate_json_key_revises_without_builder(monkeypatch, tmp_path, capsys):
    request = tmp_path / "request.json"
    request.write_bytes(b'{"schema":"x","schema":"y"}')
    monkeypatch.setattr(cli, "inspect_current_session", _current_state)

    rc = cli.main(["--request", str(request)])
    result = json.loads(capsys.readouterr().out)

    assert rc == 2
    assert result["reason"] == "BOOTSTRAP_PLAN_REQUEST_UNREADABLE"
    assert "duplicate JSON key" in result["error"]


def test_cli_missing_request_revises_fail_closed(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(cli, "inspect_current_session", _current_state)

    rc = cli.main(["--request", str(tmp_path / "missing.json")])
    result = json.loads(capsys.readouterr().out)

    assert rc == 2
    assert result["reason"] == "BOOTSTRAP_PLAN_REQUEST_UNREADABLE"
    assert result["execution_authorized"] is False
