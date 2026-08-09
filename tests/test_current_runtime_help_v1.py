from __future__ import annotations

import pytest

import continuityos.current_runtime_cli as cli


PROJECT_MEMORY_COMMANDS = (
    "continuity-work",
    "continuity-memory-delta",
    "continuity-memory-apply",
    "continuity-memory-bootstrap-plan",
    "continuity-memory-bootstrap-check",
    "continuity-memory-bootstrap",
)


def clear_binding(monkeypatch):
    for name in (cli.ENV_CHALLENGE, cli.ENV_CHALLENGE_SHA, cli.ENV_ACK, cli.ENV_REQUIRED):
        monkeypatch.delenv(name, raising=False)


def test_top_level_help_preserves_legacy_output_and_appends_current_runtime(monkeypatch, capsys):
    clear_binding(monkeypatch)
    calls = []

    def legacy_help(argv):
        calls.append(list(argv))
        print("LEGACY HELP")
        raise SystemExit(0)

    monkeypatch.setattr(cli, "r23_safe_main", legacy_help)
    assert cli.main(["--help"]) == 0
    out = capsys.readouterr().out
    assert calls == [["--help"]]
    assert "LEGACY HELP" in out
    assert "Current runtime:" in out
    assert "current-status" in out
    assert "current-env" in out
    assert "Project memory (separate console scripts):" in out
    assert "Verified current READ_ONLY:" in out
    assert "Separate effectful gates (current session must not be bound):" in out
    assert "READY / proposal results never grant execution" in out
    for command in PROJECT_MEMORY_COMMANDS:
        assert command in out
    assert "CONTINUITYOS_CURRENT_CHALLENGE_SHA256" in out


def test_short_top_level_help_is_discoverable(monkeypatch, capsys):
    clear_binding(monkeypatch)

    def legacy_help(argv):
        print("legacy -h")
        raise SystemExit(0)

    monkeypatch.setattr(cli, "r23_safe_main", legacy_help)
    assert cli.main(["-h"]) == 0
    out = capsys.readouterr().out
    assert "legacy -h" in out
    assert "current-status" in out
    assert "current-env" in out
    for command in PROJECT_MEMORY_COMMANDS:
        assert command in out


def test_db_prefix_top_level_help_keeps_exact_legacy_argv(monkeypatch, capsys):
    clear_binding(monkeypatch)
    calls = []

    def legacy_help(argv):
        calls.append(list(argv))
        print("legacy db help")
        raise SystemExit(0)

    monkeypatch.setattr(cli, "r23_safe_main", legacy_help)
    argv = ["--db", "memory.db", "--help"]
    assert cli.main(argv) == 0
    assert calls == [argv]
    out = capsys.readouterr().out
    assert "current-status" in out
    assert "current-env" in out
    for command in PROJECT_MEMORY_COMMANDS:
        assert command in out


def test_nested_help_remains_owned_by_safe_legacy_dispatch(monkeypatch, capsys):
    clear_binding(monkeypatch)
    calls = []

    def nested(argv):
        calls.append(list(argv))
        print("NESTED HELP")
        return 7

    monkeypatch.setattr(cli, "r23_safe_main", nested)
    argv = ["cold-start", "verify", "--help"]
    assert cli.main(argv) == 7
    out = capsys.readouterr().out
    assert calls == [argv]
    assert out.strip() == "NESTED HELP"
    assert "Current runtime:" not in out
    assert "Project memory" not in out


def test_bound_session_help_is_pure_and_does_not_verify_binding(monkeypatch, capsys):
    monkeypatch.setenv(cli.ENV_CHALLENGE, "challenge.json")
    monkeypatch.setenv(cli.ENV_CHALLENGE_SHA, "a" * 64)
    monkeypatch.setenv(cli.ENV_ACK, "ack.json")
    monkeypatch.setattr(
        cli,
        "verify_current_runtime_binding",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("help must not verify current binding")
        ),
    )

    def legacy_help(argv):
        print("LEGACY HELP")
        raise SystemExit(0)

    monkeypatch.setattr(cli, "r23_safe_main", legacy_help)
    assert cli.main(["--help"]) == 0
    out = capsys.readouterr().out
    assert "Current runtime:" in out
    assert "current-status" in out
    assert "current-env" in out
    for command in PROJECT_MEMORY_COMMANDS:
        assert command in out


def test_nonzero_legacy_help_exit_is_not_swallowed(monkeypatch):
    clear_binding(monkeypatch)

    def broken(argv):
        raise SystemExit(2)

    monkeypatch.setattr(cli, "r23_safe_main", broken)
    with pytest.raises(SystemExit) as exc:
        cli.main(["--help"])
    assert exc.value.code == 2
