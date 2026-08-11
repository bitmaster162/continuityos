from __future__ import annotations

import json

from continuityos import current_entrypoints
from continuityos import embedders
from continuityos import wizard
import continuityos.cli as legacy_cli


def _unbound(monkeypatch) -> None:
    monkeypatch.setattr(current_entrypoints, "current_binding_from_env", lambda env: (None, []))


def _isolated_setup_paths(monkeypatch, tmp_path):
    home = tmp_path / "home"
    monkeypatch.setattr(wizard, "HOME", home)
    monkeypatch.setattr(wizard, "STATE_FILE", home / "setup_state.json")
    monkeypatch.setattr(wizard, "ENV_FILE", home / ".env")
    monkeypatch.setattr(wizard, "DASH_FILE", home / "continuityos_dashboard.html")
    monkeypatch.setattr(wizard, "_INTERACTIVE", False)
    return home


def test_cos_setup_default_never_constructs_fastembed(monkeypatch, tmp_path, capsys):
    _unbound(monkeypatch)
    home = _isolated_setup_paths(monkeypatch, tmp_path)
    monkeypatch.delenv("CONTINUITYOS_EMBEDDER", raising=False)
    calls = []

    class ForbiddenFastEmbed:
        def __init__(self, *args, **kwargs):
            calls.append((args, kwargs))
            raise AssertionError("FastEmbed must not be constructed by default setup")

    monkeypatch.setattr(embedders, "FastEmbedEmbedder", ForbiddenFastEmbed)
    db = tmp_path / "memory.db"

    rc = current_entrypoints.cos_main(["--db", str(db), "setup", "--quick"])

    assert rc == 0
    assert calls == []
    assert db.exists()
    assert (home / "setup_state.json").exists()
    assert (home / "continuityos_dashboard.html").exists()
    out = capsys.readouterr().out
    assert "HashingEmbedder (local, offline)" in out
    assert "cos import <export-path> --extract" in out


def test_cos_setup_fastembed_requires_explicit_opt_in(monkeypatch, tmp_path):
    _unbound(monkeypatch)
    _isolated_setup_paths(monkeypatch, tmp_path)
    monkeypatch.setenv("CONTINUITYOS_EMBEDDER", "fast")
    calls = []

    class FakeFastEmbed:
        def __init__(self, *args, **kwargs):
            calls.append((args, kwargs))

        def __call__(self, text):
            return [1.0, 0.0, 0.0]

    monkeypatch.setattr(embedders, "FastEmbedEmbedder", FakeFastEmbed)
    db = tmp_path / "fast.db"

    rc = current_entrypoints.cos_main(["--db", str(db), "setup", "--quick"])

    assert rc == 0
    assert len(calls) == 1
    assert db.exists()


def test_cos_setup_unknown_embedder_holds_before_legacy_cli_or_setup_writes(monkeypatch, tmp_path, capsys):
    _unbound(monkeypatch)
    home = _isolated_setup_paths(monkeypatch, tmp_path)
    monkeypatch.setenv("CONTINUITYOS_EMBEDDER", "surprise-provider")
    monkeypatch.setattr(
        legacy_cli,
        "main",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("legacy CLI must not run")),
    )
    db = tmp_path / "must-not-exist.db"

    rc = current_entrypoints.cos_main(["--db", str(db), "setup", "--quick"])

    assert rc == 2
    assert not db.exists()
    assert not home.exists()
    value = json.loads(capsys.readouterr().out)
    assert value["terminal"] == "COS_EMBEDDER_POLICY_HOLD"
    assert value["reason"] == "UNSUPPORTED_EMBEDDER_MODE"
    assert value["command"] == "setup"
    assert value["requested"] == "surprise-provider"
    assert value["effects"]["legacy_entrypoint_called"] is False
    assert value["effects"]["network_effect"] is False
    assert value["effects"]["filesystem_write"] is False
    assert value["effects"]["memory_write"] is False


def test_cos_setup_surface_drops_legacy_internal_onboarding(monkeypatch, tmp_path, capsys):
    _unbound(monkeypatch)
    home = _isolated_setup_paths(monkeypatch, tmp_path)
    monkeypatch.delenv("CONTINUITYOS_EMBEDDER", raising=False)
    db = tmp_path / "clean.db"

    rc = current_entrypoints.cos_main(["--db", str(db), "setup", "--quick"])

    assert rc == 0
    out = capsys.readouterr().out
    dashboard = (home / "continuityos_dashboard.html").read_text(encoding="utf-8")
    combined = out + "\n" + dashboard
    for stale in (
        "OpenRouter",
        "Nemotron",
        "Hermes",
        "Antigravity",
        "Trade/HANDOFF",
        "monetization map",
        "thread is now immortal",
        "runs tasks 24/7",
    ):
        assert stale not in combined


def test_cos_setup_dashboard_only_is_offline_by_default(monkeypatch, tmp_path):
    _unbound(monkeypatch)
    home = _isolated_setup_paths(monkeypatch, tmp_path)
    monkeypatch.delenv("CONTINUITYOS_EMBEDDER", raising=False)
    calls = []

    class ForbiddenFastEmbed:
        def __init__(self, *args, **kwargs):
            calls.append((args, kwargs))
            raise AssertionError("FastEmbed must not be constructed by dashboard-only setup")

    monkeypatch.setattr(embedders, "FastEmbedEmbedder", ForbiddenFastEmbed)
    db = tmp_path / "dashboard.db"

    rc = current_entrypoints.cos_main(["--db", str(db), "setup", "--dashboard-only"])

    assert rc == 0
    assert calls == []
    assert (home / "continuityos_dashboard.html").exists()
