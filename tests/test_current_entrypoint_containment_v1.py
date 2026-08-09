from __future__ import annotations

from importlib import metadata
import json
from pathlib import Path
import tomllib

import continuityos.current_entrypoints as guard


def clear_binding(monkeypatch):
    for name in (
        "CONTINUITYOS_CURRENT_CHALLENGE",
        "CONTINUITYOS_CURRENT_CHALLENGE_SHA256",
        "CONTINUITYOS_CURRENT_ACK",
        "CONTINUITYOS_CURRENT_SESSION_REQUIRED",
    ):
        monkeypatch.delenv(name, raising=False)


def set_binding(monkeypatch):
    monkeypatch.setenv("CONTINUITYOS_CURRENT_CHALLENGE", "challenge.json")
    monkeypatch.setenv("CONTINUITYOS_CURRENT_CHALLENGE_SHA256", "a" * 64)
    monkeypatch.setenv("CONTINUITYOS_CURRENT_ACK", "ack.json")


def passing_binding(*args, **kwargs):
    return {
        "schema": "continuityos.current_runtime.monotonic_clamp/v1",
        "terminal": "CURRENT_RUNTIME_BINDING_PASS",
        "binding_verified": True,
        "authority_generation": "R64",
        "challenge_id": "c" * 64,
        "challenge_sha256": "a" * 64,
        "ack_sha256": "b" * 64,
    }


def loader(calls, result=17):
    def load():
        def legacy(argv=None):
            calls.append(list(argv or []))
            return result
        return legacy
    return load


def test_absent_current_binding_preserves_legacy_surface(monkeypatch):
    clear_binding(monkeypatch)
    calls = []
    code = guard._dispatch("cos", ["recall", "btc"], loader(calls))
    assert code == 17
    assert calls == [["recall", "btc"]]


def test_partial_current_binding_never_falls_back(monkeypatch, capsys):
    clear_binding(monkeypatch)
    monkeypatch.setenv("CONTINUITYOS_CURRENT_CHALLENGE", "challenge.json")
    calls = []
    code = guard._dispatch("cos", ["serve"], loader(calls))
    result = json.loads(capsys.readouterr().out)
    assert code == 2
    assert calls == []
    assert result["terminal"] == "CURRENT_ENTRYPOINT_BINDING_REVISE"
    assert result["legacy_fallback"] is False


def test_required_current_session_without_binding_fails_closed(monkeypatch, capsys):
    clear_binding(monkeypatch)
    monkeypatch.setenv("CONTINUITYOS_CURRENT_SESSION_REQUIRED", "true")
    calls = []
    code = guard._dispatch("continuity-memory", ["status"], loader(calls))
    result = json.loads(capsys.readouterr().out)
    assert code == 2
    assert calls == []
    assert result["reason"] == "CURRENT_SESSION_BINDING_INCOMPLETE"


def test_invalid_current_binding_blocks_before_legacy(monkeypatch, capsys):
    clear_binding(monkeypatch)
    set_binding(monkeypatch)
    monkeypatch.setattr(
        guard,
        "verify_current_runtime_binding",
        lambda *args, **kwargs: {
            "terminal": "CURRENT_RUNTIME_BINDING_REVISE",
            "binding_verified": False,
        },
    )
    calls = []
    code = guard._dispatch("continuity-context", ["prepare"], loader(calls))
    result = json.loads(capsys.readouterr().out)
    assert code == 2
    assert calls == []
    assert result["reason"] == "CURRENT_SESSION_ACK_NOT_VERIFIED"


def test_verified_current_session_holds_all_non_state_surfaces(monkeypatch, capsys):
    clear_binding(monkeypatch)
    set_binding(monkeypatch)
    monkeypatch.setattr(guard, "verify_current_runtime_binding", passing_binding)
    for surface, argv in (
        ("cos", ["serve"]),
        ("continuity-memory", ["event", "--stream", "x"]),
        ("continuity-context", ["verify"]),
        ("continuity-session", ["verify"]),
    ):
        calls = []
        assert guard._dispatch(surface, argv, loader(calls)) == 3
        result = json.loads(capsys.readouterr().out)
        assert calls == []
        assert result["terminal"] == "CURRENT_ENTRYPOINT_HOLD"
        assert result["authority_generation"] == "R64"
        assert result["effects"]["filesystem_write"] is False
        assert result["effects"]["server_started"] is False


def test_verified_current_session_allows_only_state_evaluate(monkeypatch):
    clear_binding(monkeypatch)
    set_binding(monkeypatch)
    monkeypatch.setattr(guard, "verify_current_runtime_binding", passing_binding)
    calls = []
    code = guard._dispatch(
        "continuity-state",
        ["evaluate", "--input", "bundle.json"],
        loader(calls, result=9),
        allow_state_evaluate=True,
    )
    assert code == 9
    assert calls == [["evaluate", "--input", "bundle.json"]]


def test_verified_current_session_blocks_historical_state_prepare(monkeypatch, capsys):
    clear_binding(monkeypatch)
    set_binding(monkeypatch)
    monkeypatch.setattr(guard, "verify_current_runtime_binding", passing_binding)
    calls = []
    code = guard._dispatch(
        "continuity-state",
        ["prepare-cold-start", "--input", "bundle.json"],
        loader(calls),
        allow_state_evaluate=True,
    )
    result = json.loads(capsys.readouterr().out)
    assert code == 3
    assert calls == []
    assert result["command"] == "prepare-cold-start"
    assert result["legacy_fallback"] is False


def test_current_cos_db_prefix_still_identifies_command(monkeypatch, capsys):
    clear_binding(monkeypatch)
    set_binding(monkeypatch)
    monkeypatch.setattr(guard, "verify_current_runtime_binding", passing_binding)
    calls = []
    code = guard._dispatch("cos", ["--db", "memory.db", "update", "--yes"], loader(calls))
    result = json.loads(capsys.readouterr().out)
    assert code == 3
    assert calls == []
    assert result["command"] == "update"
    assert result["effects"]["self_update"] is False


def test_packaged_entrypoints_use_current_containment():
    expected = {
        "cos": "continuityos.current_entrypoints:cos_main",
        "continuity": "continuityos.current_runtime_cli:main",
        "continuity-state": "continuityos.current_entrypoints:state_main",
        "continuity-memory": "continuityos.current_entrypoints:operational_memory_main",
        "continuity-context": "continuityos.current_entrypoints:operational_context_main",
        "continuity-session": "continuityos.current_entrypoints:session_input_main",
    }
    try:
        dist = metadata.distribution("continuityos")
    except metadata.PackageNotFoundError:
        root = Path(__file__).resolve().parents[1]
        data = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
        observed = data["project"]["scripts"]
    else:
        observed = {
            ep.name: ep.value
            for ep in dist.entry_points
            if ep.group == "console_scripts" and ep.name in expected
        }
    for name, target in expected.items():
        assert observed[name] == target
