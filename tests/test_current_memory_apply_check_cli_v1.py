from __future__ import annotations

import json

import continuityos.current_memory_apply_check_cli as cli


def test_cli_requires_verified_current_session(monkeypatch, capsys):
    monkeypatch.setattr(cli, "inspect_current_session", lambda: {"mode": "LEGACY", "binding_verified": False})

    code = cli.main([
        "--operational-db", "missing.db",
        "--proposal", "missing-proposal.json",
        "--authorization", "missing-auth.json",
    ])
    result = json.loads(capsys.readouterr().out)

    assert code == 2
    assert result["reason"] == "VERIFIED_CURRENT_SESSION_REQUIRED"
    assert result["legacy_fallback"] is False
    assert result["apply_ready"] is False
    assert result["execution_authorized"] is False


def test_cli_delegates_only_after_verified_current_session(monkeypatch, capsys):
    monkeypatch.setattr(cli, "inspect_current_session", lambda: {
        "mode": "CURRENT",
        "binding_verified": True,
        "authority_generation": "R64",
        "challenge_id": "b" * 64,
        "challenge_sha256": "a" * 64,
        "session_effect_ceiling": "READ_ONLY",
        "authority_ceiling": "NO_FURTHER_AGENT_WORK",
    })
    monkeypatch.setattr(cli, "check_authorized_memory_delta", lambda *args: {
        "schema": cli.CHECK_SCHEMA,
        "terminal": "CURRENT_MEMORY_APPLY_CHECK_READY",
        "reason": "ARTIFACTS_BASE_AND_OPERATION_TARGETS_VALIDATED",
        "apply_status": "NOT_APPLIED",
        "apply_ready": True,
        "execution_decision": "HOLD",
        "execution_authorized": False,
        "effects": {"operational_memory_write": False, "filesystem_write": False},
    })

    code = cli.main([
        "--operational-db", "memory.db",
        "--proposal", "proposal.json",
        "--authorization", "auth.json",
    ])
    result = json.loads(capsys.readouterr().out)

    assert code == 0
    assert result["terminal"] == "CURRENT_MEMORY_APPLY_CHECK_READY"
    assert result["current_session"]["binding_verified"] is True
    assert result["current_session"]["authority_generation"] == "R64"
    assert result["legacy_fallback"] is False
    assert result["execution_authorized"] is False
