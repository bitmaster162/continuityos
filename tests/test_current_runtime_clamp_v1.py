from __future__ import annotations

import json
import os
from pathlib import Path
import tomllib

import continuityos.current_runtime as runtime
import continuityos.current_runtime_cli as cli


def passing_verdict():
    return {
        "outcome": "PASS",
        "status": "CURRENT_COLD_START_PASS",
        "challenge_id": "challenge-1",
        "challenge_sha256": "a" * 64,
        "ack_sha256": "b" * 64,
        "authority_generation": "R64",
    }


def test_runtime_preflight_verifies_context_but_never_grants_execution(monkeypatch):
    monkeypatch.setattr(runtime, "verify_current_cold_start_ack", lambda *args, **kwargs: passing_verdict())
    result = runtime.evaluate_current_preflight(
        Path("challenge.json"),
        Path("ack.json"),
        expected_challenge_sha256="a" * 64,
        tool="shell",
        command="git status",
        cwd="/repo",
    )
    assert result["terminal"] == "CURRENT_RUNTIME_PREFLIGHT_PASS"
    assert result["binding_verified"] is True
    assert result["authority_generation"] == "R64"
    assert result["session_effect_ceiling"] == "READ_ONLY"
    assert result["authority_ceiling"] == "NO_FURTHER_AGENT_WORK"
    assert result["execution_decision"] == "HOLD"
    assert result["execution_authorized"] is False
    assert result["legacy_decision_evaluated"] is False
    assert result["effects"]["legacy_ledger_write"] is False
    assert result["effects"]["execution_attempted"] is False


def test_runtime_run_is_held_before_legacy_or_execution(monkeypatch):
    monkeypatch.setattr(runtime, "verify_current_cold_start_ack", lambda *args, **kwargs: passing_verdict())
    result = runtime.block_current_run(
        Path("challenge.json"),
        Path("ack.json"),
        expected_challenge_sha256="a" * 64,
        tool="exec",
        argv=["git", "status"],
    )
    assert result["terminal"] == "CURRENT_RUNTIME_RUN_HOLD"
    assert result["decision"] == "HOLD"
    assert result["legacy_engine_called"] is False
    assert result["legacy_ledger_write"] is False
    assert result["execution_attempted"] is False
    assert result["executed"] is False


def test_unverified_ack_revises_fail_closed(monkeypatch):
    monkeypatch.setattr(
        runtime,
        "verify_current_cold_start_ack",
        lambda *args, **kwargs: {
            "outcome": "FAIL",
            "status": "CURRENT_COLD_START_FAIL",
            "challenge_id": "challenge-1",
        },
    )
    result = runtime.block_current_run(
        Path("challenge.json"),
        Path("ack.json"),
        expected_challenge_sha256="a" * 64,
        tool="exec",
        argv=["git", "status"],
    )
    assert result["terminal"] == "CURRENT_RUNTIME_RUN_REVISE"
    assert result["decision"] == "HOLD"
    assert result["effects"]["execution_attempted"] is False


def clear_binding(monkeypatch):
    for name in (cli.ENV_CHALLENGE, cli.ENV_CHALLENGE_SHA, cli.ENV_ACK, cli.ENV_REQUIRED):
        monkeypatch.delenv(name, raising=False)


def set_binding(monkeypatch):
    monkeypatch.setenv(cli.ENV_CHALLENGE, "challenge.json")
    monkeypatch.setenv(cli.ENV_CHALLENGE_SHA, "a" * 64)
    monkeypatch.setenv(cli.ENV_ACK, "ack.json")


def test_no_current_binding_preserves_r23_legacy_compatibility(monkeypatch):
    clear_binding(monkeypatch)
    calls = []
    monkeypatch.setattr(cli, "r23_safe_main", lambda argv: calls.append(list(argv)) or 19)
    assert cli.main(["run", "exec", "--", "echo", "hello"]) == 19
    assert calls == [["run", "exec", "--", "echo", "hello"]]


def test_partial_current_binding_never_falls_back_to_legacy(monkeypatch, capsys):
    clear_binding(monkeypatch)
    monkeypatch.setenv(cli.ENV_CHALLENGE, "challenge.json")
    monkeypatch.setattr(
        cli,
        "r23_safe_main",
        lambda argv: (_ for _ in ()).throw(AssertionError("legacy fallback must not happen")),
    )
    code = cli.main(["run", "exec", "--", "git", "status"])
    result = json.loads(capsys.readouterr().out)
    assert code == 2
    assert result["terminal"] == "CURRENT_RUNTIME_BINDING_REVISE"
    assert cli.ENV_CHALLENGE_SHA in result["missing"]
    assert cli.ENV_ACK in result["missing"]
    assert result["legacy_fallback"] is False


def test_required_current_session_without_binding_fails_closed(monkeypatch, capsys):
    clear_binding(monkeypatch)
    monkeypatch.setenv(cli.ENV_REQUIRED, "true")
    monkeypatch.setattr(
        cli,
        "r23_safe_main",
        lambda argv: (_ for _ in ()).throw(AssertionError("legacy fallback must not happen")),
    )
    code = cli.main(["preflight", "shell", "git status", "--json"])
    result = json.loads(capsys.readouterr().out)
    assert code == 2
    assert result["terminal"] == "CURRENT_RUNTIME_BINDING_REVISE"
    assert len(result["missing"]) == 3


def test_bound_current_preflight_is_pure_and_does_not_call_legacy(monkeypatch, capsys):
    clear_binding(monkeypatch)
    set_binding(monkeypatch)
    captured = {}

    def evaluate(challenge, ack, **kwargs):
        captured.update({"challenge": challenge, "ack": ack, **kwargs})
        return {
            "terminal": "CURRENT_RUNTIME_PREFLIGHT_PASS",
            "execution_decision": "HOLD",
            "execution_authorized": False,
            "effects": {"legacy_ledger_write": False, "execution_attempted": False},
        }

    monkeypatch.setattr(cli, "evaluate_current_preflight", evaluate)
    monkeypatch.setattr(
        cli,
        "r23_safe_main",
        lambda argv: (_ for _ in ()).throw(AssertionError("legacy preflight must not run")),
    )
    code = cli.main(["preflight", "shell", "git status", "--cwd", "/repo", "--json"])
    result = json.loads(capsys.readouterr().out)
    assert code == 0
    assert result["terminal"] == "CURRENT_RUNTIME_PREFLIGHT_PASS"
    assert result["execution_decision"] == "HOLD"
    assert captured["challenge"] == Path("challenge.json")
    assert captured["expected_challenge_sha256"] == "a" * 64
    assert captured["tool"] == "shell"
    assert captured["command"] == "git status"
    assert captured["cwd"] == "/repo"


def test_bound_current_run_holds_before_legacy(monkeypatch, capsys):
    clear_binding(monkeypatch)
    set_binding(monkeypatch)
    captured = {}

    def block(challenge, ack, **kwargs):
        captured.update({"challenge": challenge, "ack": ack, **kwargs})
        return {
            "terminal": "CURRENT_RUNTIME_RUN_HOLD",
            "decision": "HOLD",
            "legacy_engine_called": False,
            "legacy_ledger_write": False,
            "execution_attempted": False,
            "executed": False,
        }

    monkeypatch.setattr(cli, "block_current_run", block)
    monkeypatch.setattr(
        cli,
        "r23_safe_main",
        lambda argv: (_ for _ in ()).throw(AssertionError("legacy run must not run")),
    )
    code = cli.main(["run", "exec", "--", "git", "status"])
    result = json.loads(capsys.readouterr().out)
    assert code == 3
    assert result["terminal"] == "CURRENT_RUNTIME_RUN_HOLD"
    assert result["executed"] is False
    assert captured["tool"] == "exec"
    assert captured["argv"] == ["git", "status"]


def test_db_prefix_cannot_bypass_current_runtime_clamp(monkeypatch):
    clear_binding(monkeypatch)
    set_binding(monkeypatch)
    calls = []
    monkeypatch.setattr(
        cli,
        "block_current_run",
        lambda *args, **kwargs: calls.append((args, kwargs)) or {
            "terminal": "CURRENT_RUNTIME_RUN_HOLD",
            "decision": "HOLD",
        },
    )
    monkeypatch.setattr(
        cli,
        "r23_safe_main",
        lambda argv: (_ for _ in ()).throw(AssertionError("--db must not bypass clamp")),
    )
    assert cli.main(["--db", "memory.db", "run", "exec", "--", "git", "status"]) == 3
    assert len(calls) == 1


def test_current_binding_does_not_intercept_non_runtime_commands(monkeypatch):
    clear_binding(monkeypatch)
    set_binding(monkeypatch)
    calls = []
    monkeypatch.setattr(cli, "r23_safe_main", lambda argv: calls.append(list(argv)) or 7)
    assert cli.main(["cold-start", "verify", "--help"]) == 7
    assert calls == [["cold-start", "verify", "--help"]]


def test_packaged_continuity_entrypoint_points_at_runtime_dispatcher():
    root = Path(__file__).resolve().parents[1]
    data = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    assert data["project"]["scripts"]["continuity"] == "continuityos.current_runtime_cli:main"
