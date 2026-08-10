from __future__ import annotations

import hashlib
import json

import continuityos.current_claim_sync_cli as cli
from continuityos.current_claim_sync import REQUEST_SCHEMA
from continuityos.operational_memory import OperationalMemory

PROJECT = "project:r43-cli"


def _write_json(path, value):
    payload = (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    path.write_bytes(payload)
    return hashlib.sha256(payload).hexdigest()


def _request(path):
    evidence = path / "evidence.json"
    _write_json(evidence, {"status": "PASS", "frontier": "r43"})
    request = {
        "schema": REQUEST_SCHEMA,
        "project_id": PROJECT,
        "evidence": [{"evidence_id": "proof", "locator": str(evidence)}],
        "claims": [{
            "predicate": "project.status",
            "scope": "global",
            "value": {"state": "R43"},
            "evidence_state": "VERIFIED",
            "evidence_ids": ["proof"],
        }],
    }
    request_path = path / "request.json"
    request_sha = _write_json(request_path, request)
    return request_path, request_sha


def _current_state():
    return {
        "mode": "CURRENT",
        "binding_verified": True,
        "authority_generation": "R64",
        "challenge_id": "b" * 64,
        "challenge_sha256": "a" * 64,
        "session_effect_ceiling": "READ_ONLY",
        "authority_ceiling": "NO_FURTHER_AGENT_WORK",
    }


def test_cli_requires_verified_current_session(monkeypatch, tmp_path, capsys):
    request_path, _ = _request(tmp_path)
    db = tmp_path / "memory.db"
    with OperationalMemory(str(db)):
        pass
    monkeypatch.setattr(cli, "inspect_current_session", lambda: {"mode": "LEGACY", "binding_verified": False})

    code = cli.main(["--operational-db", str(db), "--request", str(request_path)])
    result = json.loads(capsys.readouterr().out)

    assert code == 2
    assert result["reason"] == "VERIFIED_CURRENT_SESSION_REQUIRED"
    assert result["legacy_fallback"] is False
    assert result["execution_authorized"] is False


def test_cli_success_is_read_only_and_reports_exact_request_hash(monkeypatch, tmp_path, capsys):
    request_path, request_sha = _request(tmp_path)
    db = tmp_path / "memory.db"
    with OperationalMemory(str(db)) as memory:
        assert memory.verify()["ok"] is True
    before = hashlib.sha256(db.read_bytes()).hexdigest()
    monkeypatch.setattr(cli, "inspect_current_session", _current_state)

    code = cli.main(["--operational-db", str(db), "--request", str(request_path)])
    result = json.loads(capsys.readouterr().out)

    assert code == 0
    assert result["terminal"] == "CURRENT_CLAIM_SYNC_PLAN_PASS"
    assert result["current_session"]["binding_verified"] is True
    assert result["current_session"]["authority_generation"] == "R64"
    assert result["request_input"]["sha256"] == request_sha
    assert result["effects"]["operational_memory_write"] is False
    assert result["effects"]["filesystem_write"] is False
    assert result["execution_authorized"] is False
    assert hashlib.sha256(db.read_bytes()).hexdigest() == before


def test_cli_refuses_symlink_request_when_supported(monkeypatch, tmp_path, capsys):
    request_path, _ = _request(tmp_path)
    alias = tmp_path / "request-alias.json"
    try:
        alias.symlink_to(request_path)
    except (OSError, NotImplementedError):
        return
    db = tmp_path / "memory.db"
    with OperationalMemory(str(db)):
        pass
    monkeypatch.setattr(cli, "inspect_current_session", _current_state)

    code = cli.main(["--operational-db", str(db), "--request", str(alias)])
    result = json.loads(capsys.readouterr().out)

    assert code == 2
    assert result["reason"] == "CLAIM_SYNC_REQUEST_UNREADABLE"
    assert "symlink/reparse refused" in result["error"]
