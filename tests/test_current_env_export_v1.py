from __future__ import annotations

import json
import os
from pathlib import Path

import continuityos.current_env as envmod
import continuityos.current_runtime_cli as cli


def pass_verdict(challenge_sha: str = "a" * 64):
    return {
        "terminal": "CURRENT_RUNTIME_BINDING_PASS",
        "binding_verified": True,
        "authority_generation": "R64",
        "challenge_id": "c" * 64,
        "challenge_sha256": challenge_sha,
        "ack_sha256": "b" * 64,
    }


def test_json_export_verifies_exact_binding_and_never_mutates_environment(monkeypatch, tmp_path):
    challenge = tmp_path / "challenge.json"
    ack = tmp_path / "ack.json"
    seen = []
    monkeypatch.setattr(
        envmod,
        "verify_current_runtime_binding",
        lambda challenge_path, ack_path, expected_challenge_sha256: seen.append(
            (challenge_path, ack_path, expected_challenge_sha256)
        ) or pass_verdict(expected_challenge_sha256),
    )
    before = {name: os.environ.get(name) for name in (
        envmod.ENV_CHALLENGE,
        envmod.ENV_CHALLENGE_SHA,
        envmod.ENV_ACK,
        envmod.ENV_REQUIRED,
    )}

    result = envmod.build_current_env_export(
        str(challenge),
        "A" * 64,
        str(ack),
        output_format="json",
    )

    assert result["terminal"] == "CURRENT_ENV_EXPORT_PASS"
    assert result["authority_generation"] == "R64"
    assert result["output_format"] == "json"
    assert result["rendered"] is None
    assert result["environment"][envmod.ENV_CHALLENGE] == os.path.abspath(str(challenge))
    assert result["environment"][envmod.ENV_ACK] == os.path.abspath(str(ack))
    assert result["environment"][envmod.ENV_CHALLENGE_SHA] == "a" * 64
    assert result["environment"][envmod.ENV_REQUIRED] == "1"
    assert result["effects"]["environment_mutated"] is False
    assert seen == [(challenge, ack, "a" * 64)]
    after = {name: os.environ.get(name) for name in before}
    assert after == before


def test_powershell_export_quotes_single_quote_without_execution(monkeypatch, tmp_path):
    challenge = tmp_path / "challenge's file.json"
    ack = tmp_path / "ack file.json"
    monkeypatch.setattr(
        envmod,
        "verify_current_runtime_binding",
        lambda *args, **kwargs: pass_verdict(),
    )

    result = envmod.build_current_env_export(
        str(challenge), "a" * 64, str(ack), output_format="powershell"
    )

    assert result["terminal"] == "CURRENT_ENV_EXPORT_PASS"
    rendered = result["rendered"]
    assert "$env:CONTINUITYOS_CURRENT_CHALLENGE = '" in rendered
    assert "challenge''s file.json" in rendered
    assert "$env:CONTINUITYOS_CURRENT_SESSION_REQUIRED = '1'" in rendered
    assert rendered.endswith("\n")


def test_posix_export_shell_quotes_spaces(monkeypatch, tmp_path):
    challenge = tmp_path / "challenge file.json"
    ack = tmp_path / "ack file.json"
    monkeypatch.setattr(
        envmod,
        "verify_current_runtime_binding",
        lambda *args, **kwargs: pass_verdict(),
    )

    result = envmod.build_current_env_export(
        str(challenge), "a" * 64, str(ack), output_format="posix"
    )

    assert result["terminal"] == "CURRENT_ENV_EXPORT_PASS"
    rendered = result["rendered"]
    assert "export CONTINUITYOS_CURRENT_CHALLENGE='" in rendered
    assert "challenge file.json'" in rendered
    assert "export CONTINUITYOS_CURRENT_SESSION_REQUIRED=1" in rendered


def test_invalid_binding_returns_revise_without_shell_text(monkeypatch, tmp_path):
    monkeypatch.setattr(
        envmod,
        "verify_current_runtime_binding",
        lambda *args, **kwargs: (_ for _ in ()).throw(ValueError("bad ack")),
    )
    result = envmod.build_current_env_export(
        str(tmp_path / "challenge.json"),
        "a" * 64,
        str(tmp_path / "ack.json"),
        output_format="powershell",
    )
    assert result["terminal"] == "CURRENT_ENV_EXPORT_REVISE"
    assert result["reason"] == "CURRENT_SESSION_BINDING_INVALID"
    assert "rendered" not in result
    assert result["effects"]["environment_mutated"] is False


def test_unverified_ack_returns_revise(monkeypatch, tmp_path):
    monkeypatch.setattr(
        envmod,
        "verify_current_runtime_binding",
        lambda *args, **kwargs: {
            "terminal": "CURRENT_RUNTIME_BINDING_REVISE",
            "binding_verified": False,
        },
    )
    result = envmod.build_current_env_export(
        str(tmp_path / "challenge.json"),
        "a" * 64,
        str(tmp_path / "ack.json"),
    )
    assert result["terminal"] == "CURRENT_ENV_EXPORT_REVISE"
    assert result["reason"] == "CURRENT_COLD_START_ACK_NOT_VERIFIED"


def test_newline_path_fails_before_verifier(monkeypatch, tmp_path):
    monkeypatch.setattr(
        envmod,
        "verify_current_runtime_binding",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("unsafe path must fail before verification")
        ),
    )
    result = envmod.build_current_env_export(
        "bad\nchallenge.json",
        "a" * 64,
        str(tmp_path / "ack.json"),
        output_format="powershell",
    )
    assert result["terminal"] == "CURRENT_ENV_EXPORT_REVISE"
    assert result["reason"] == "CURRENT_SESSION_BINDING_INVALID"


def test_cli_current_env_is_recovery_surface_even_with_partial_ambient_binding(monkeypatch, capsys):
    monkeypatch.setenv(cli.ENV_CHALLENGE, "stale-partial.json")
    monkeypatch.delenv(cli.ENV_CHALLENGE_SHA, raising=False)
    monkeypatch.delenv(cli.ENV_ACK, raising=False)
    calls = []
    monkeypatch.setattr(
        cli,
        "build_current_env_export",
        lambda challenge, sha, ack, output_format: calls.append(
            (challenge, sha, ack, output_format)
        ) or {
            "terminal": "CURRENT_ENV_EXPORT_PASS",
            "rendered": "$env:X = '1'\n",
        },
    )
    monkeypatch.setattr(
        cli,
        "r23_safe_main",
        lambda argv: (_ for _ in ()).throw(AssertionError("legacy dispatcher must not run")),
    )

    code = cli.main([
        "current-env",
        "--challenge", "fresh-challenge.json",
        "--challenge-sha256", "a" * 64,
        "--ack", "fresh-ack.json",
        "--format", "powershell",
    ])
    assert code == 0
    assert capsys.readouterr().out == "$env:X = '1'\n"
    assert calls == [("fresh-challenge.json", "a" * 64, "fresh-ack.json", "powershell")]


def test_cli_current_env_json_pass_is_machine_readable(monkeypatch, capsys):
    monkeypatch.setattr(
        cli,
        "build_current_env_export",
        lambda *args, **kwargs: {
            "schema": envmod.SCHEMA,
            "terminal": "CURRENT_ENV_EXPORT_PASS",
            "output_format": "json",
            "environment": {envmod.ENV_REQUIRED: "1"},
            "rendered": None,
            "effects": {"environment_mutated": False},
        },
    )
    code = cli.main([
        "current-env",
        "--challenge", "challenge.json",
        "--challenge-sha256", "a" * 64,
        "--ack", "ack.json",
    ])
    result = json.loads(capsys.readouterr().out)
    assert code == 0
    assert result["terminal"] == "CURRENT_ENV_EXPORT_PASS"
    assert result["environment"][envmod.ENV_REQUIRED] == "1"


def test_cli_current_env_failure_is_json_revise(monkeypatch, capsys):
    monkeypatch.setattr(
        cli,
        "build_current_env_export",
        lambda *args, **kwargs: {
            "schema": envmod.SCHEMA,
            "terminal": "CURRENT_ENV_EXPORT_REVISE",
            "reason": "CURRENT_SESSION_BINDING_INVALID",
            "effects": {"environment_mutated": False},
        },
    )
    code = cli.main([
        "current-env",
        "--challenge", "challenge.json",
        "--challenge-sha256", "a" * 64,
        "--ack", "ack.json",
        "--format", "posix",
    ])
    result = json.loads(capsys.readouterr().out)
    assert code == 2
    assert result["terminal"] == "CURRENT_ENV_EXPORT_REVISE"
