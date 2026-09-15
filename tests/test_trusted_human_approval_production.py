from __future__ import annotations

import ast
import inspect
from pathlib import Path

import pytest

import continuityos.trusted_human_approval_production as production
from continuityos.durable_approval_replay import (
    DurableApprovalReplayError,
    SQLiteApprovalReplayGuard,
)
from continuityos.trusted_human_approval import HumanApprovalResult

APPROVAL_ID = "hap_" + "a" * 64
OTHER_APPROVAL_ID = "hap_" + "b" * 64


def _call(db: Path):
    return production.verify_and_consume_human_approval_production(
        replay_db_path=db,
        request_receipt={"request": True},
        approval_envelope={"approval": True},
        trusted_key_registry={"registry": True},
        pinned_registry_sha256="c" * 64,
        repository="bitmaster162/continuityos",
        current_base_sha="d" * 40,
        current_head_sha="e" * 40,
        current_tree_sha="f" * 40,
        now_unix=2_000_000_000,
    )


def test_factory_is_file_backed_and_persistent_across_instances(tmp_path: Path):
    db = tmp_path / "approval-replay.sqlite3"
    first = production.build_production_replay_guard(replay_db_path=db)
    assert type(first) is SQLiteApprovalReplayGuard
    assert first.consume_once(APPROVAL_ID) is True

    restarted = production.build_production_replay_guard(replay_db_path=db)
    assert restarted.consume_once(APPROVAL_ID) is False
    assert restarted.contains(APPROVAL_ID) is True
    assert restarted.consume_once(OTHER_APPROVAL_ID) is True


def test_production_wrapper_delegates_with_exact_sqlite_guard(monkeypatch, tmp_path: Path):
    seen = {}

    def fake_verify(**kwargs):
        seen.update(kwargs)
        return HumanApprovalResult({"receipt_id": "hme_test"}, APPROVAL_ID)

    monkeypatch.setattr(production, "verify_and_consume_human_approval", fake_verify)
    db = tmp_path / "binding.sqlite3"
    result = _call(db)

    assert result.approval_id == APPROVAL_ID
    assert type(seen["replay_guard"]) is SQLiteApprovalReplayGuard
    assert Path(seen["replay_guard"].path) == db.resolve()
    assert seen["repository"] == "bitmaster162/continuityos"


def test_fresh_binding_instances_share_durable_replay_state(monkeypatch, tmp_path: Path):
    def fake_verify(**kwargs):
        guard = kwargs["replay_guard"]
        if guard.consume_once(APPROVAL_ID) is not True:
            raise ValueError("trusted human approval: approval replay detected")
        return HumanApprovalResult({"receipt_id": "hme_test"}, APPROVAL_ID)

    monkeypatch.setattr(production, "verify_and_consume_human_approval", fake_verify)
    db = tmp_path / "replay.sqlite3"

    assert _call(db).approval_id == APPROVAL_ID
    with pytest.raises(ValueError, match="approval replay detected"):
        _call(db)


def test_storage_failure_stops_before_verifier(monkeypatch, tmp_path: Path):
    called = False

    def should_not_run(**kwargs):
        nonlocal called
        called = True
        raise AssertionError("verifier must not run")

    monkeypatch.setattr(production, "verify_and_consume_human_approval", should_not_run)
    bad_path = tmp_path / "directory-not-db"
    bad_path.mkdir()
    with pytest.raises(DurableApprovalReplayError, match="storage initialization failed"):
        _call(bad_path)
    assert called is False


def test_production_api_has_no_replay_guard_override_or_implicit_path():
    signature = inspect.signature(production.verify_and_consume_human_approval_production)
    assert "replay_guard" not in signature.parameters
    replay_path = signature.parameters["replay_db_path"]
    assert replay_path.default is inspect.Parameter.empty

    with pytest.raises(ValueError, match="file-backed path required"):
        production.build_production_replay_guard(replay_db_path=":memory:")
    with pytest.raises(ValueError, match="invalid busy_timeout_ms"):
        production.build_production_replay_guard(
            replay_db_path="replay.sqlite3",
            busy_timeout_ms=0,
        )


def test_module_has_no_implicit_fallback_or_execution_surface():
    source = Path(production.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])

    banned_imports = {
        "subprocess",
        "socket",
        "requests",
        "urllib",
        "http",
        "tempfile",
    }
    assert not (banned_imports & imported)
    assert "InMemoryApprovalReplayGuard" not in source
    assert "os.environ" not in source
    assert "getenv(" not in source
    assert "merge_pull_request" not in source
    assert "deployment" not in source.lower()
    assert "can_trade" not in source
    assert "capital_permission" not in source
