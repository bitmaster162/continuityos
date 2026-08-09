from __future__ import annotations

import json
from pathlib import Path

import continuityos.safe_cli as safe


def test_non_cold_start_command_delegates_unchanged(monkeypatch):
    calls = []

    def legacy(argv):
        calls.append(list(argv))
        return 17

    monkeypatch.setattr(safe, "legacy_main", legacy)
    monkeypatch.setattr(
        safe,
        "prepare_current_cold_start",
        lambda **kwargs: (_ for _ in ()).throw(AssertionError("current path must not run")),
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
        "prepare_current_cold_start",
        lambda **kwargs: (_ for _ in ()).throw(AssertionError("current path must not run")),
    )

    code = safe.main([
        "cold-start", "prepare",
        "--spec", "spec.json",
        "--output", "out",
    ])
    receipt = json.loads(capsys.readouterr().out)

    assert code == 3
    assert receipt["terminal"] == "CURRENT_COLD_START_HOLD"
    assert receipt["reason"] == "STATE_BUNDLE_REQUIRED"
    assert receipt["legacy_r63_unbound_executed"] is False
    assert receipt["current_authority_executed"] is False
    assert receipt["effects"]["can_trade"] is False


def test_state_bundle_requires_exact_current_authority_inputs(monkeypatch, capsys):
    monkeypatch.setattr(
        safe,
        "prepare_current_cold_start",
        lambda **kwargs: (_ for _ in ()).throw(AssertionError("current path must not run")),
    )
    code = safe.main([
        "cold-start", "prepare",
        "--state-bundle", "state.json",
        "--spec", "spec.json",
        "--output", "out",
    ])
    receipt = json.loads(capsys.readouterr().out)
    assert code == 3
    assert receipt["reason"] == "CURRENT_AUTHORITY_INPUTS_REQUIRED"
    assert "--authority-pointer" in receipt["detail"]
    assert "--current-state" in receipt["detail"]


def test_current_prepare_routes_without_legacy_boot(monkeypatch, capsys):
    calls = []

    def current_prepare(**kwargs):
        calls.append(kwargs)
        return {
            "schema": "CONTINUITYOS_CURRENT_COLD_START_PREPARE_RECEIPT_V1",
            "terminal": "CURRENT_COLD_START_PASS",
            "effects": {"can_trade": False, "capital_permission": "DENY"},
        }

    monkeypatch.setattr(safe, "prepare_current_cold_start", current_prepare)
    monkeypatch.setattr(
        safe,
        "legacy_main",
        lambda argv: (_ for _ in ()).throw(AssertionError("legacy path must not run")),
    )

    code = safe.main([
        "cold-start", "prepare",
        "--state-bundle", "state.json",
        "--authority-pointer", "CURRENT_POINTER.json",
        "--authority-pointer-sha256", "a" * 64,
        "--current-state", "CURRENT_STATE.json",
        "--role-index", "ROLE_INDEX.json",
        "--role-views", "ROLE_VIEWS.json",
        "--spec", "spec.json",
        "--output", "out",
    ])
    receipt = json.loads(capsys.readouterr().out)

    assert code == 0
    assert receipt["terminal"] == "CURRENT_COLD_START_PASS"
    assert len(calls) == 1
    assert calls[0]["authority_pointer_path"] == Path("CURRENT_POINTER.json")
    assert calls[0]["expected_authority_pointer_sha256"] == "a" * 64
    assert calls[0]["state_bundle_path"] == Path("state.json")


def test_current_prepare_rejects_legacy_boot_receipt(monkeypatch, capsys):
    monkeypatch.setattr(
        safe,
        "prepare_current_cold_start",
        lambda **kwargs: (_ for _ in ()).throw(AssertionError("current path must not run")),
    )
    code = safe.main([
        "cold-start", "prepare",
        "--state-bundle", "state.json",
        "--authority-pointer", "CURRENT_POINTER.json",
        "--authority-pointer-sha256", "a" * 64,
        "--current-state", "CURRENT_STATE.json",
        "--role-index", "ROLE_INDEX.json",
        "--role-views", "ROLE_VIEWS.json",
        "--boot-receipt", "R63_BOOT.json",
        "--spec", "spec.json",
        "--output", "out",
    ])
    receipt = json.loads(capsys.readouterr().out)
    assert code == 3
    assert receipt["reason"] == "LEGACY_BOOT_RECEIPT_NOT_USED_BY_CURRENT_PROTOCOL"


def test_db_global_prefix_does_not_bypass_current_dispatch(monkeypatch):
    calls = []

    monkeypatch.setattr(
        safe,
        "prepare_current_cold_start",
        lambda **kwargs: calls.append(kwargs) or {"terminal": "CURRENT_COLD_START_PASS"},
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
        "--authority-pointer", "CURRENT_POINTER.json",
        "--authority-pointer-sha256", "a" * 64,
        "--current-state", "CURRENT_STATE.json",
        "--role-index", "ROLE_INDEX.json",
        "--role-views", "ROLE_VIEWS.json",
        "--spec", "spec.json",
        "--output", "out",
    ])
    assert code == 0
    assert len(calls) == 1


def test_legacy_r63_path_requires_explicit_override(monkeypatch, capsys):
    legacy_calls = []

    def legacy(argv):
        legacy_calls.append(list(argv))
        return 0

    monkeypatch.setattr(safe, "legacy_main", legacy)

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
    code = safe.main([
        "cold-start", "prepare",
        "--state-bundle", "state.json",
        "--legacy-r63-unbound",
        "--spec", "spec.json",
        "--output", "out",
    ])
    assert code == 2


def test_current_verify_schema_routes_to_current_verifier(monkeypatch, tmp_path, capsys):
    challenge = tmp_path / "challenge.json"
    challenge.write_text(json.dumps({"schema": safe.CURRENT_CHALLENGE_SCHEMA}), encoding="utf-8")
    ack = tmp_path / "ack.json"
    ack.write_text("{}", encoding="utf-8")
    calls = []

    monkeypatch.setattr(safe, "peek_challenge_schema", lambda path: safe.CURRENT_CHALLENGE_SCHEMA)
    monkeypatch.setattr(
        safe,
        "verify_current_cold_start_ack",
        lambda challenge_path, ack_path, expected_challenge_sha256: calls.append(
            (challenge_path, ack_path, expected_challenge_sha256)
        ) or {"outcome": "PASS", "status": "CURRENT_COLD_START_PASS"},
    )
    monkeypatch.setattr(
        safe,
        "legacy_main",
        lambda argv: (_ for _ in ()).throw(AssertionError("legacy verify must not run")),
    )

    code = safe.main([
        "cold-start", "verify",
        "--challenge", str(challenge),
        "--challenge-sha256", "b" * 64,
        "--ack", str(ack),
    ])
    result = json.loads(capsys.readouterr().out)
    assert code == 0
    assert result["outcome"] == "PASS"
    assert calls and calls[0][2] == "b" * 64


def test_legacy_verify_delegates_unchanged(monkeypatch, tmp_path):
    challenge = tmp_path / "challenge.json"
    challenge.write_text(json.dumps({"schema": "ANTI_AMNESIA_COLD_START_CHALLENGE_V1"}), encoding="utf-8")
    legacy_calls = []
    monkeypatch.setattr(
        safe, "peek_challenge_schema", lambda path: "ANTI_AMNESIA_COLD_START_CHALLENGE_V1"
    )
    monkeypatch.setattr(safe, "legacy_main", lambda argv: legacy_calls.append(list(argv)) or 9)

    code = safe.main([
        "cold-start", "verify",
        "--challenge", str(challenge),
        "--challenge-sha256", "c" * 64,
        "--ack", "ack.json",
    ])
    assert code == 9
    assert legacy_calls and legacy_calls[0][:2] == ["cold-start", "verify"]


def test_prepare_help_is_available_without_selecting_a_mode(monkeypatch):
    monkeypatch.setattr(
        safe,
        "legacy_main",
        lambda argv: (_ for _ in ()).throw(AssertionError("legacy path must not run")),
    )
    assert safe.main(["cold-start", "prepare", "--help"]) == 0
