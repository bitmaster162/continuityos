from __future__ import annotations

import ast
import sqlite3
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

import continuityos.durable_approval_replay as durable_replay_module
from continuityos.durable_approval_replay import (
    SCHEMA,
    DurableApprovalReplayError,
    SQLiteApprovalReplayGuard,
)

APPROVAL_ID = "hap_" + "a" * 64
OTHER_APPROVAL_ID = "hap_" + "b" * 64
ROOT = Path(__file__).resolve().parents[1]


def test_first_consume_succeeds_and_restart_replay_fails(tmp_path: Path):
    db = tmp_path / "replay.sqlite3"
    first = SQLiteApprovalReplayGuard(db)
    assert first.consume_once(APPROVAL_ID) is True
    assert first.contains(APPROVAL_ID) is True

    restarted = SQLiteApprovalReplayGuard(db)
    assert restarted.consume_once(APPROVAL_ID) is False
    assert restarted.consume_once(OTHER_APPROVAL_ID) is True


def test_thread_race_allows_exactly_one_consumer(tmp_path: Path):
    guard = SQLiteApprovalReplayGuard(tmp_path / "thread-race.sqlite3")

    def consume(_: int) -> bool:
        return guard.consume_once(APPROVAL_ID)

    with ThreadPoolExecutor(max_workers=16) as pool:
        outcomes = list(pool.map(consume, range(32)))

    assert outcomes.count(True) == 1
    assert outcomes.count(False) == 31


def test_process_race_allows_exactly_one_consumer(tmp_path: Path):
    db = tmp_path / "process-race.sqlite3"
    SQLiteApprovalReplayGuard(db)
    code = (
        "from continuityos.durable_approval_replay import SQLiteApprovalReplayGuard;"
        f"g=SQLiteApprovalReplayGuard({str(db)!r});"
        f"print('1' if g.consume_once({APPROVAL_ID!r}) else '0')"
    )
    processes = [
        subprocess.Popen(
            [sys.executable, "-c", code],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        for _ in range(8)
    ]
    outputs = []
    for process in processes:
        stdout, stderr = process.communicate(timeout=30)
        assert process.returncode == 0, stderr
        outputs.append(stdout.strip())

    assert outputs.count("1") == 1
    assert outputs.count("0") == 7


def test_schema_identity_tamper_fails_closed(tmp_path: Path):
    db = tmp_path / "schema.sqlite3"
    SQLiteApprovalReplayGuard(db)
    con = sqlite3.connect(db)
    try:
        con.execute("UPDATE replay_meta SET value='wrong' WHERE key='schema'")
        con.commit()
    finally:
        con.close()

    with pytest.raises(DurableApprovalReplayError, match="schema identity mismatch"):
        SQLiteApprovalReplayGuard(db)


def test_file_backing_and_configuration_are_strict(tmp_path: Path):
    with pytest.raises(ValueError, match="file-backed path required"):
        SQLiteApprovalReplayGuard(":memory:")
    with pytest.raises(ValueError, match="invalid busy_timeout_ms"):
        SQLiteApprovalReplayGuard(tmp_path / "x.sqlite3", busy_timeout_ms=0)
    with pytest.raises(ValueError, match="invalid approval_id"):
        SQLiteApprovalReplayGuard(tmp_path / "y.sqlite3").consume_once("bad")


def test_storage_open_failure_fails_closed(tmp_path: Path):
    directory = tmp_path / "not-a-db"
    directory.mkdir()
    with pytest.raises(DurableApprovalReplayError, match="storage initialization failed"):
        SQLiteApprovalReplayGuard(directory)


def test_sqlite_durability_profile_is_wal_and_full(tmp_path: Path):
    db = tmp_path / "profile.sqlite3"
    SQLiteApprovalReplayGuard(db)
    con = sqlite3.connect(db)
    try:
        assert str(con.execute("PRAGMA journal_mode").fetchone()[0]).lower() == "wal"
        assert con.execute("PRAGMA synchronous").fetchone()[0] == 2
        assert con.execute(
            "SELECT value FROM replay_meta WHERE key='schema'"
        ).fetchone() == (SCHEMA,)
    finally:
        con.close()


def test_missing_consumption_table_fails_closed(tmp_path: Path):
    db = tmp_path / "broken.sqlite3"
    guard = SQLiteApprovalReplayGuard(db)
    con = sqlite3.connect(db)
    try:
        con.execute("DROP TABLE consumed_approvals")
        con.commit()
    finally:
        con.close()

    with pytest.raises(DurableApprovalReplayError, match="storage consume failed"):
        guard.consume_once(APPROVAL_ID)


def test_module_has_no_network_or_execution_surface():
    source = Path(durable_replay_module.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])

    banned = {
        "subprocess",
        "socket",
        "requests",
        "urllib",
        "http",
        "github",
        "git",
    }
    assert not (banned & imported)
    assert "merge_pull_request" not in source
    assert "Ed25519PrivateKey" not in source
    assert "can_trade" not in source
    assert "capital_permission" not in source


def test_live_schema_drift_fails_closed(tmp_path: Path):
    db = tmp_path / "live-schema.sqlite3"
    guard = SQLiteApprovalReplayGuard(db)
    con = sqlite3.connect(db)
    try:
        con.execute("UPDATE replay_meta SET value='wrong' WHERE key='schema'")
        con.commit()
    finally:
        con.close()

    with pytest.raises(DurableApprovalReplayError, match="schema identity mismatch"):
        guard.consume_once(APPROVAL_ID)


def test_live_journal_mode_drift_fails_closed(tmp_path: Path):
    db = tmp_path / "journal.sqlite3"
    guard = SQLiteApprovalReplayGuard(db)
    con = sqlite3.connect(db)
    try:
        mode = con.execute("PRAGMA journal_mode=DELETE").fetchone()[0]
        assert str(mode).lower() == "delete"
    finally:
        con.close()

    with pytest.raises(DurableApprovalReplayError, match="journal mode drift"):
        guard.consume_once(APPROVAL_ID)
