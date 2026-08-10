from __future__ import annotations

import json

import continuityos.current_memory_apply_auth_request_cli as cli


def test_cli_requires_verified_current_session(monkeypatch, capsys):
    monkeypatch.setattr(cli, "inspect_current_session", lambda: {"mode": "LEGACY", "binding_verified": False})

    code = cli.main(["--operational-db", "memory.db", "--proposal", "proposal.json"])
    result = json.loads(capsys.readouterr().out)

    assert code == 2
    assert result["reason"] == "VERIFIED_CURRENT_SESSION_REQUIRED"
    assert result["authorization_artifact_created"] is False
    assert result["authorization_granted"] is False
    assert result["execution_authorized"] is False
    assert result["legacy_fallback"] is False


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
    monkeypatch.setattr(cli, "build_apply_authorization_request", lambda *args: {
        "schema": cli.REQUEST_SCHEMA,
        "terminal": "CURRENT_MEMORY_APPLY_AUTH_REQUEST_PASS",
        "reason": "EXACT_PROPOSAL_AND_BASE_BOUND_FOR_AUTHORITY_REVIEW",
        "authorization_artifact_created": False,
        "authorization_granted": False,
        "authorization_identity_authenticated": False,
        "apply_status": "NOT_APPLIED",
        "execution_decision": "HOLD",
        "execution_authorized": False,
        "effects": {"operational_memory_write": False, "filesystem_write": False},
    })

    code = cli.main(["--operational-db", "memory.db", "--proposal", "proposal.json"])
    result = json.loads(capsys.readouterr().out)

    assert code == 0
    assert result["current_session"]["binding_verified"] is True
    assert result["current_session"]["authority_generation"] == "R64"
    assert result["authorization_granted"] is False
    assert result["execution_authorized"] is False
    assert result["legacy_fallback"] is False
