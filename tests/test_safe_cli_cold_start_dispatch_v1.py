from __future__ import annotations

import json

import continuityos.safe_cli as safe


def test_non_cold_start_command_delegates_unchanged(monkeypatch):
    calls = []

    def legacy(argv):
        calls.append(list(argv))
        return 17

    monkeypatch.setattr(safe, "legacy_main", legacy)
    monkeypatch.setattr(
        safe,
        "state_main",
        lambda argv: (_ for _ in ()).throw(AssertionError("state path must not run")),
    )

    assert safe.main(["audit", "-n", "3"]) == 17
    assert calls == [["audit", "-n", "3"]]


def test_cold_start_prepare_without_mode_holds_before_any_preparer(monkeypatch, capsys):
    monkeypatch.setattr(
        safe,
        "legacy_main",
        lambda argv: (_ for _ in ()).throw(AssertionError("legacy path must not run")),
    )
    monkeypatch.setattr(
        safe,
        "state_main",
        lambda argv: (_ for _ in ()).throw(AssertionError("state path must not run")),
    )

    code = safe.main([
        "cold-start", "prepare",
        "--boot-receipt", "boot.json",
        "--spec", "spec.json",
        "--output", "out",
    ])
    receipt = json.loads(capsys.readouterr().out)

    assert code == 3
    assert receipt["terminal"] == "CURRENT_COLD_START_HOLD"
    assert receipt["reason"] == "STATE_BUNDLE_REQUIRED"
    assert receipt["legacy_r63_unbound_executed"] is False
    assert receipt["state_bound_executed"] is False
    assert receipt["effects"]["can_trade"] is False
    assert receipt["effects"]["capital_permission"] == "DENY"


def test_state_bundle_routes_to_guarded_current_path(monkeypatch):
    state_calls = []

    def state(argv):
        state_calls.append(list(argv))
        return 0

    monkeypatch.setattr(safe, "state_main", state)
    monkeypatch.setattr(
        safe,
        "legacy_main",
        lambda argv: (_ for _ in ()).throw(AssertionError("legacy path must not run")),
    )

    code = safe.main([
        "cold-start", "prepare",
        "--state-bundle", "state.json",
        "--boot-receipt", "boot.json",
        "--spec", "spec.json",
        "--output", "out",
    ])

    assert code == 0
    assert state_calls == [[
        "prepare-cold-start",
        "--input", "state.json",
        "--boot-receipt", "boot.json",
        "--spec", "spec.json",
        "--output", "out",
    ]]


def test_db_global_prefix_does_not_bypass_state_dispatch(monkeypatch):
    state_calls = []

    monkeypatch.setattr(
        safe, "state_main", lambda argv: state_calls.append(list(argv)) or 0
    )
    monkeypatch.setattr(
        safe,
        "legacy_main",
        lambda argv: (_ for _ in ()).throw(AssertionError("legacy path must not run")),
    )

    code = safe.main([
        "--db", "memory.db",
        "cold-start", "prepare",
        "--state-bundle", "state.json",
        "--boot-receipt", "boot.json",
        "--spec", "spec.json",
        "--output", "out",
    ])

    assert code == 0
    assert state_calls and state_calls[0][0] == "prepare-cold-start"


def test_legacy_r63_path_requires_explicit_override(monkeypatch, capsys):
    legacy_calls = []

    def legacy(argv):
        legacy_calls.append(list(argv))
        return 0

    monkeypatch.setattr(safe, "legacy_main", legacy)
    monkeypatch.setattr(
        safe,
        "state_main",
        lambda argv: (_ for _ in ()).throw(AssertionError("state path must not run")),
    )

    code = safe.main([
        "--db=memory.db",
        "cold-start", "prepare",
        "--legacy-r63-unbound",
        "--boot-receipt", "boot.json",
        "--spec", "spec.json",
        "--output", "out",
    ])
    captured = capsys.readouterr()

    assert code == 0
    assert "LEGACY R63 UNBOUND" in captured.err
    assert legacy_calls == [[
        "--db=memory.db",
        "cold-start", "prepare",
        "--boot-receipt", "boot.json",
        "--spec", "spec.json",
        "--output", "out",
    ]]


def test_state_bundle_and_legacy_override_are_mutually_exclusive(monkeypatch):
    monkeypatch.setattr(
        safe,
        "legacy_main",
        lambda argv: (_ for _ in ()).throw(AssertionError("legacy path must not run")),
    )
    monkeypatch.setattr(
        safe,
        "state_main",
        lambda argv: (_ for _ in ()).throw(AssertionError("state path must not run")),
    )

    code = safe.main([
        "cold-start", "prepare",
        "--state-bundle", "state.json",
        "--legacy-r63-unbound",
        "--boot-receipt", "boot.json",
        "--spec", "spec.json",
        "--output", "out",
    ])

    assert code == 2


def test_prepare_help_is_available_without_selecting_a_mode(monkeypatch):
    monkeypatch.setattr(
        safe,
        "legacy_main",
        lambda argv: (_ for _ in ()).throw(AssertionError("legacy path must not run")),
    )
    assert safe.main(["cold-start", "prepare", "--help"]) == 0
