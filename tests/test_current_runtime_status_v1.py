from __future__ import annotations

import json

import continuityos.current_runtime_cli as cli


def clear_binding(monkeypatch):
    for name in (cli.ENV_CHALLENGE, cli.ENV_CHALLENGE_SHA, cli.ENV_ACK, cli.ENV_REQUIRED):
        monkeypatch.delenv(name, raising=False)


def set_binding(monkeypatch):
    monkeypatch.setenv(cli.ENV_CHALLENGE, "challenge.json")
    monkeypatch.setenv(cli.ENV_CHALLENGE_SHA, "a" * 64)
    monkeypatch.setenv(cli.ENV_ACK, "ack.json")


def test_current_status_reports_unbound_without_legacy_dispatch(monkeypatch, capsys):
    clear_binding(monkeypatch)
    monkeypatch.setattr(
        cli,
        "r23_safe_main",
        lambda argv: (_ for _ in ()).throw(AssertionError("status must not enter legacy CLI")),
    )

    code = cli.main(["current-status"])
    result = json.loads(capsys.readouterr().out)
    assert code == 0
    assert result["terminal"] == "CURRENT_RUNTIME_STATUS_UNBOUND"
    assert result["mode"] == "LEGACY_UNBOUND"
    assert result["current_session_declared"] is False
    assert result["binding_verified"] is False
    assert result["legacy_fallback"] is True
    assert result["capabilities"]["current_binding_verification"] == "NOT_ACTIVE"
    assert result["effects"]["execution_attempted"] is False


def test_current_status_partial_binding_is_revise_and_never_falls_back(monkeypatch, capsys):
    clear_binding(monkeypatch)
    monkeypatch.setenv(cli.ENV_CHALLENGE, "challenge.json")
    monkeypatch.setattr(
        cli,
        "r23_safe_main",
        lambda argv: (_ for _ in ()).throw(AssertionError("partial status must not fall back")),
    )

    code = cli.main(["current-status"])
    result = json.loads(capsys.readouterr().out)
    assert code == 2
    assert result["terminal"] == "CURRENT_RUNTIME_STATUS_REVISE"
    assert result["reason"] == "CURRENT_SESSION_BINDING_INCOMPLETE"
    assert result["current_session_declared"] is True
    assert result["binding_complete"] is False
    assert cli.ENV_CHALLENGE_SHA in result["missing"]
    assert cli.ENV_ACK in result["missing"]
    assert result["legacy_fallback"] is False
    assert result["execution_decision"] == "HOLD"


def test_required_session_without_pins_is_visible_as_invalid_current(monkeypatch, capsys):
    clear_binding(monkeypatch)
    monkeypatch.setenv(cli.ENV_REQUIRED, "true")
    code = cli.main(["current-status"])
    result = json.loads(capsys.readouterr().out)
    assert code == 2
    assert result["terminal"] == "CURRENT_RUNTIME_STATUS_REVISE"
    assert result["current_session_declared"] is True
    assert len(result["missing"]) == 3


def test_current_status_verified_binding_reports_exact_runtime_ceiling(monkeypatch, capsys):
    clear_binding(monkeypatch)
    set_binding(monkeypatch)
    captured = {}

    def verify(challenge, ack, **kwargs):
        captured.update({"challenge": challenge, "ack": ack, **kwargs})
        return {
            "terminal": "CURRENT_RUNTIME_BINDING_PASS",
            "binding_verified": True,
            "authority_generation": "R64",
            "challenge_id": "challenge-1",
            "challenge_sha256": "a" * 64,
            "ack_sha256": "b" * 64,
        }

    monkeypatch.setattr(cli, "verify_current_runtime_binding", verify)
    code = cli.main(["current-status"])
    result = json.loads(capsys.readouterr().out)
    assert code == 0
    assert result["terminal"] == "CURRENT_RUNTIME_STATUS_PASS"
    assert result["mode"] == "CURRENT_BOUND_READ_ONLY"
    assert result["binding_complete"] is True
    assert result["binding_verified"] is True
    assert result["authority_generation"] == "R64"
    assert result["challenge_id"] == "challenge-1"
    assert result["challenge_sha256"] == "a" * 64
    assert result["ack_sha256"] == "b" * 64
    assert result["session_effect_ceiling"] == "READ_ONLY"
    assert result["authority_ceiling"] == "NO_FURTHER_AGENT_WORK"
    assert result["execution_decision"] == "HOLD"
    assert result["execution_authorized"] is False
    assert result["legacy_fallback"] is False
    assert result["capabilities"]["read_only_inspection"] == "ALLOW"
    assert result["capabilities"]["effectful_continuityos_calls"] == "HOLD"
    assert captured["expected_challenge_sha256"] == "a" * 64


def test_current_status_unverified_ack_is_revise(monkeypatch, capsys):
    clear_binding(monkeypatch)
    set_binding(monkeypatch)
    monkeypatch.setattr(
        cli,
        "verify_current_runtime_binding",
        lambda *args, **kwargs: {
            "terminal": "CURRENT_RUNTIME_BINDING_REVISE",
            "binding_verified": False,
            "reason": "CURRENT_COLD_START_ACK_NOT_VERIFIED",
        },
    )

    code = cli.main(["current-status"])
    result = json.loads(capsys.readouterr().out)
    assert code == 2
    assert result["terminal"] == "CURRENT_RUNTIME_STATUS_REVISE"
    assert result["reason"] == "CURRENT_COLD_START_ACK_NOT_VERIFIED"
    assert result["binding_complete"] is True
    assert result["binding_verified"] is False
    assert result["execution_decision"] == "HOLD"


def test_current_status_verification_exception_is_fail_closed(monkeypatch, capsys):
    clear_binding(monkeypatch)
    set_binding(monkeypatch)
    monkeypatch.setattr(
        cli,
        "verify_current_runtime_binding",
        lambda *args, **kwargs: (_ for _ in ()).throw(ValueError("bad ack")),
    )

    code = cli.main(["current-status"])
    result = json.loads(capsys.readouterr().out)
    assert code == 2
    assert result["terminal"] == "CURRENT_RUNTIME_STATUS_REVISE"
    assert result["reason"] == "CURRENT_SESSION_BINDING_INVALID"
    assert result["error_type"] == "ValueError"
    assert result["legacy_fallback"] is False
    assert result["execution_decision"] == "HOLD"


def test_db_prefix_does_not_hide_current_status(monkeypatch, capsys):
    clear_binding(monkeypatch)
    set_binding(monkeypatch)
    monkeypatch.setattr(
        cli,
        "verify_current_runtime_binding",
        lambda *args, **kwargs: {
            "binding_verified": True,
            "authority_generation": "R64",
            "challenge_id": "challenge-1",
            "challenge_sha256": "a" * 64,
            "ack_sha256": "b" * 64,
        },
    )
    assert cli.main(["--db", "legacy.db", "current-status"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["terminal"] == "CURRENT_RUNTIME_STATUS_PASS"


def test_current_status_rejects_arguments_instead_of_delegating(monkeypatch, capsys):
    clear_binding(monkeypatch)
    assert cli.main(["current-status", "unexpected"]) == 2
    result = json.loads(capsys.readouterr().out)
    assert result["terminal"] == "CURRENT_RUNTIME_STATUS_REVISE"
    assert result["reason"] == "CURRENT_STATUS_TAKES_NO_ARGUMENTS"
    assert result["legacy_fallback"] is False
