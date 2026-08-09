from __future__ import annotations

import json
from pathlib import Path

import pytest

import continuityos.current_authority_root as rootmod
import continuityos.safe_cli as safe


def make_root(tmp_path: Path) -> Path:
    for name in rootmod.CANONICAL_FILES.values():
        (tmp_path / name).write_text("{}", encoding="utf-8")
    return tmp_path


def test_resolver_uses_only_exact_canonical_filenames(tmp_path):
    root = make_root(tmp_path)
    (root / "CURRENT_POINTER_R99_ACTIVE.json").write_text("{}", encoding="utf-8")
    paths = rootmod.resolve_current_authority_root(root)
    assert {key: path.name for key, path in paths.items()} == rootmod.CANONICAL_FILES
    assert "CURRENT_POINTER_R99_ACTIVE.json" not in {path.name for path in paths.values()}


def test_resolver_missing_canonical_file_fails_instead_of_guessing(tmp_path):
    root = make_root(tmp_path)
    (root / "CURRENT_POINTER.json").unlink()
    (root / "CURRENT_POINTER_R64_ACTIVE.json").write_text("{}", encoding="utf-8")
    with pytest.raises(rootmod.CurrentColdStartError, match="MISSING_CANONICAL_FILE"):
        rootmod.resolve_current_authority_root(root)


def test_inspector_reuses_current_pointer_and_root_validators(monkeypatch, tmp_path):
    root = make_root(tmp_path)
    seen = []

    values = {
        "CURRENT_POINTER.json": ({"pointer": True}, "1" * 64),
        "CURRENT_STATE.json": ({"state": True}, "2" * 64),
        "ROLE_INDEX.json": ({"index": True}, "3" * 64),
        "ROLE_VIEWS.json": ({"views": True}, "4" * 64),
    }

    def read(path, label):
        seen.append((path.name, label))
        return values[path.name]

    monkeypatch.setattr(rootmod, "_read_json_with_sha", read)
    monkeypatch.setattr(
        rootmod,
        "_validate_pointer",
        lambda value, actual_sha256, expected_sha256: {
            "generation": "R64",
            "accepted_manifest_sha256": "5" * 64,
            "activation_status": "ACTIVE",
            "activation_decision": "ACCEPT_R64_POINTER_PROMOTION",
            "human_sovereign": "ROBERT",
            "effect_ceiling": {"NO_FURTHER_AGENT_WORK": True, "can_trade": False},
            "root_bindings": {
                "current_state": "2" * 64,
                "role_index": "3" * 64,
                "role_views": "4" * 64,
            },
        },
    )
    monkeypatch.setattr(
        rootmod,
        "_validate_stable_roots",
        lambda pointer, current_state_value, current_state_sha, role_index_value, role_index_sha, role_views_value, role_views_sha: {
            "current_state": {"canonicality_activation": "CANDIDATE_NOT_ACTIVE_PENDING_ROBERT"},
            "sha256": {
                "current_state": current_state_sha,
                "role_index": role_index_sha,
                "role_views": role_views_sha,
            },
        },
    )

    result = rootmod.inspect_current_authority_root(
        root,
        expected_authority_pointer_sha256="1" * 64,
    )
    assert result["terminal"] == "CURRENT_AUTHORITY_ROOT_INSPECT_PASS"
    assert result["selection_mode"] == "EXACT_CANONICAL_FILENAMES_ONLY"
    assert result["authority_generation"] == "R64"
    assert result["activation_status"] == "ACTIVE"
    assert result["human_sovereign"] == "ROBERT"
    assert result["writes_performed"] == []
    assert result["effects"]["filesystem_write"] is False
    assert [name for name, _ in seen] == [
        "CURRENT_POINTER.json",
        "CURRENT_STATE.json",
        "ROLE_INDEX.json",
        "ROLE_VIEWS.json",
    ]


def test_cli_inspect_root_routes_without_legacy_dispatch(monkeypatch, tmp_path, capsys):
    root = make_root(tmp_path)
    calls = []
    monkeypatch.setattr(
        safe,
        "inspect_current_authority_root",
        lambda authority_root, expected_authority_pointer_sha256: calls.append(
            (authority_root, expected_authority_pointer_sha256)
        ) or {
            "schema": rootmod.SCHEMA,
            "terminal": "CURRENT_AUTHORITY_ROOT_INSPECT_PASS",
            "authority_generation": "R64",
            "writes_performed": [],
        },
    )
    monkeypatch.setattr(
        safe,
        "legacy_main",
        lambda argv: (_ for _ in ()).throw(AssertionError("legacy path must not run")),
    )

    code = safe.main([
        "cold-start",
        "inspect-root",
        "--authority-root",
        str(root),
        "--authority-pointer-sha256",
        "a" * 64,
    ])
    result = json.loads(capsys.readouterr().out)
    assert code == 0
    assert result["terminal"] == "CURRENT_AUTHORITY_ROOT_INSPECT_PASS"
    assert calls == [(root, "a" * 64)]


def test_cli_inspect_root_failure_is_read_only_revise(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(
        safe,
        "inspect_current_authority_root",
        lambda *args, **kwargs: (_ for _ in ()).throw(ValueError("bad root")),
    )
    code = safe.main([
        "cold-start",
        "inspect-root",
        "--authority-root",
        str(tmp_path),
        "--authority-pointer-sha256",
        "a" * 64,
    ])
    result = json.loads(capsys.readouterr().out)
    assert code == 2
    assert result["terminal"] == "CURRENT_AUTHORITY_ROOT_INSPECT_REVISE"
    assert result["reason"] == "CURRENT_AUTHORITY_ROOT_INVALID"
    assert result["writes_performed"] == []
    assert result["effects"]["can_trade"] is False


def test_prepare_authority_root_expands_exact_paths(monkeypatch, tmp_path, capsys):
    root = make_root(tmp_path)
    calls = []
    monkeypatch.setattr(
        safe,
        "prepare_current_cold_start",
        lambda **kwargs: calls.append(kwargs) or {
            "terminal": "CURRENT_COLD_START_PASS",
            "effects": {"can_trade": False, "capital_permission": "DENY"},
        },
    )
    monkeypatch.setattr(
        safe,
        "legacy_main",
        lambda argv: (_ for _ in ()).throw(AssertionError("legacy path must not run")),
    )

    code = safe.main([
        "cold-start", "prepare",
        "--state-bundle", "state.json",
        "--authority-root", str(root),
        "--authority-pointer-sha256", "a" * 64,
        "--spec", "spec.json",
        "--output", "out",
    ])
    json.loads(capsys.readouterr().out)
    assert code == 0
    assert len(calls) == 1
    assert calls[0]["authority_pointer_path"] == root / "CURRENT_POINTER.json"
    assert calls[0]["current_state_path"] == root / "CURRENT_STATE.json"
    assert calls[0]["role_index_path"] == root / "ROLE_INDEX.json"
    assert calls[0]["role_views_path"] == root / "ROLE_VIEWS.json"


def test_prepare_rejects_mixed_root_and_individual_paths(monkeypatch, tmp_path, capsys):
    root = make_root(tmp_path)
    monkeypatch.setattr(
        safe,
        "prepare_current_cold_start",
        lambda **kwargs: (_ for _ in ()).throw(AssertionError("preparer must not run")),
    )
    code = safe.main([
        "cold-start", "prepare",
        "--state-bundle", "state.json",
        "--authority-root", str(root),
        "--authority-pointer", "other.json",
        "--authority-pointer-sha256", "a" * 64,
        "--spec", "spec.json",
        "--output", "out",
    ])
    result = json.loads(capsys.readouterr().out)
    assert code == 3
    assert result["reason"] == "AUTHORITY_ROOT_INPUTS_MIXED"


def test_prepare_authority_root_still_requires_controller_pinned_pointer_sha(tmp_path, capsys):
    root = make_root(tmp_path)
    code = safe.main([
        "cold-start", "prepare",
        "--state-bundle", "state.json",
        "--authority-root", str(root),
        "--spec", "spec.json",
        "--output", "out",
    ])
    result = json.loads(capsys.readouterr().out)
    assert code == 3
    assert result["reason"] == "CURRENT_AUTHORITY_INPUTS_REQUIRED"
    assert "--authority-pointer-sha256" in result["detail"]


def test_legacy_override_rejects_authority_root(monkeypatch, tmp_path, capsys):
    root = make_root(tmp_path)
    monkeypatch.setattr(
        safe,
        "legacy_main",
        lambda argv: (_ for _ in ()).throw(AssertionError("legacy must not run on mixed inputs")),
    )
    code = safe.main([
        "cold-start", "prepare",
        "--legacy-r63-unbound",
        "--authority-root", str(root),
        "--boot-receipt", "boot.json",
        "--spec", "spec.json",
        "--output", "out",
    ])
    result = json.loads(capsys.readouterr().out)
    assert code == 3
    assert result["reason"] == "LEGACY_AND_CURRENT_INPUTS_MIXED"
