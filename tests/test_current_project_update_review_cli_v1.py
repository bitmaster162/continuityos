from __future__ import annotations

import json

import continuityos.current_project_update_review_cli as cli


def test_cli_requires_verified_current_session(monkeypatch, tmp_path, capsys):
    request = tmp_path / "request.json"
    request.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(
        cli,
        "inspect_current_session",
        lambda: {"mode": "LEGACY", "binding_verified": False, "reason": "unbound"},
    )

    rc = cli.main(["--db", str(tmp_path / "missing.db"), "--request", str(request)])

    result = json.loads(capsys.readouterr().out)
    assert rc == 2
    assert result["terminal"] == "CURRENT_PROJECT_UPDATE_REVIEW_REVISE"
    assert result["reason"] == "VERIFIED_CURRENT_SESSION_REQUIRED"
    assert result["legacy_fallback"] is False
    assert result["execution_authorized"] is False


def test_cli_emits_packet_and_current_binding_without_writes(monkeypatch, tmp_path, capsys):
    request = tmp_path / "request.json"
    request.write_text('{"project_id":"project:test"}', encoding="utf-8")
    monkeypatch.setattr(
        cli,
        "inspect_current_session",
        lambda: {
            "mode": cli.MODE_CURRENT,
            "binding_verified": True,
            "authority_generation": "R64",
            "challenge_id": "c" * 64,
            "challenge_sha256": "d" * 64,
            "session_effect_ceiling": "READ_ONLY",
            "authority_ceiling": "NO_FURTHER_AGENT_WORK",
        },
    )
    monkeypatch.setattr(
        cli,
        "build_project_update_review_packet",
        lambda db, value: {
            "schema": cli.PACKET_SCHEMA,
            "terminal": "CURRENT_PROJECT_UPDATE_REVIEW_PASS",
            "reason": "test",
            "project_id": value["project_id"],
            "apply_status": "NOT_APPLIED",
            "authorization_granted": False,
            "execution_authorized": False,
            "effects": {"filesystem_write": False, "operational_memory_write": False},
        },
    )

    rc = cli.main(["--db", str(tmp_path / "memory.db"), "--request", str(request)])

    result = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert result["terminal"] == "CURRENT_PROJECT_UPDATE_REVIEW_PASS"
    assert result["current_session"]["binding_verified"] is True
    assert result["current_session"]["authority_generation"] == "R64"
    assert result["request_input"]["size_bytes"] == len(request.read_bytes())
    assert result["execution_authorized"] is False
