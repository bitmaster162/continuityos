from __future__ import annotations

import json

import continuityos.current_effect_boundary as boundary
import continuityos.current_work_cli as cli


def clear_binding(monkeypatch):
    for name in (
        boundary.ENV_CHALLENGE,
        boundary.ENV_CHALLENGE_SHA,
        boundary.ENV_ACK,
        boundary.ENV_REQUIRED,
    ):
        monkeypatch.delenv(name, raising=False)


def set_current(monkeypatch):
    monkeypatch.setenv(boundary.ENV_CHALLENGE, "challenge.json")
    monkeypatch.setenv(boundary.ENV_CHALLENGE_SHA, "a" * 64)
    monkeypatch.setenv(boundary.ENV_ACK, "ack.json")
    monkeypatch.setenv(boundary.ENV_REQUIRED, "1")
    monkeypatch.setattr(
        boundary,
        "verify_current_runtime_binding",
        lambda *args, **kwargs: {
            "terminal": "CURRENT_RUNTIME_BINDING_PASS",
            "binding_verified": True,
            "authority_generation": "R64",
            "challenge_id": "b" * 64,
            "challenge_sha256": "a" * 64,
            "ack_sha256": "c" * 64,
        },
    )


def test_cli_requires_verified_current_session_and_never_falls_back(monkeypatch, capsys):
    clear_binding(monkeypatch)
    called = []
    monkeypatch.setattr(cli, "build_current_work_from_db", lambda *args, **kwargs: called.append(args))

    code = cli.main(["--project", "project:x", "--operational-db", "missing.db"])

    assert code == 2
    assert called == []
    payload = json.loads(capsys.readouterr().out)
    assert payload["terminal"] == "CURRENT_WORK_REVISE"
    assert payload["reason"] == "VERIFIED_CURRENT_SESSION_REQUIRED"
    assert payload["legacy_fallback"] is False
    assert payload["execution_authorized"] is False


def test_cli_emits_pass_capsule_with_current_identity(monkeypatch, capsys):
    set_current(monkeypatch)
    monkeypatch.setattr(
        cli,
        "build_current_work_from_db",
        lambda db, project: {
            "schema": "continuityos.current_work.project_capsule/v1",
            "terminal": "CURRENT_WORK_PASS",
            "reason": "PROPOSED_NEXT_ACTION_SELECTED",
            "project_id": project,
            "next_action": {"action": "run tests"},
            "execution_decision": "HOLD",
            "execution_authorized": False,
            "effects": {"can_trade": False, "capital_permission": "DENY"},
        },
    )

    code = cli.main(["--project", "project:x", "--operational-db", "memory.db"])

    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["terminal"] == "CURRENT_WORK_PASS"
    assert payload["current_session"]["binding_verified"] is True
    assert payload["current_session"]["authority_generation"] == "R64"
    assert payload["current_session"]["session_effect_ceiling"] == "READ_ONLY"
    assert payload["execution_authorized"] is False


def test_cli_hold_returns_three(monkeypatch, capsys):
    set_current(monkeypatch)
    monkeypatch.setattr(
        cli,
        "build_current_work_from_db",
        lambda *args, **kwargs: {
            "schema": "continuityos.current_work.project_capsule/v1",
            "terminal": "CURRENT_WORK_HOLD",
            "reason": "NEXT_ACTION_HOLD",
            "project_id": "project:x",
            "next_action": None,
            "execution_decision": "HOLD",
            "execution_authorized": False,
            "effects": {"can_trade": False, "capital_permission": "DENY"},
        },
    )

    assert cli.main(["--project", "project:x", "--operational-db", "memory.db"]) == 3
    assert json.loads(capsys.readouterr().out)["terminal"] == "CURRENT_WORK_HOLD"


def test_cli_revise_returns_two(monkeypatch, capsys):
    set_current(monkeypatch)
    monkeypatch.setattr(
        cli,
        "build_current_work_from_db",
        lambda *args, **kwargs: {
            "schema": "continuityos.current_work.project_capsule/v1",
            "terminal": "CURRENT_WORK_REVISE",
            "reason": "OPERATIONAL_MEMORY_MISSING",
            "project_id": "project:x",
            "next_action": None,
            "execution_decision": "HOLD",
            "execution_authorized": False,
            "effects": {"can_trade": False, "capital_permission": "DENY"},
        },
    )

    assert cli.main(["--project", "project:x", "--operational-db", "missing.db"]) == 2
    assert json.loads(capsys.readouterr().out)["reason"] == "OPERATIONAL_MEMORY_MISSING"
