import os
import sqlite3
import sys
import threading

import pytest

from continuityos import Continuity, Memory
from continuityos.db import (
    CONTEXT_DIGEST_SCHEME,
    context_fingerprint,
    context_identity,
    context_read_snapshot,
    resolve_memory_db,
)


def test_db_resolution_precedence_and_memory_sentinel(tmp_path):
    explicit = str(tmp_path / "explicit.db")
    environment = str(tmp_path / "environment.db")
    fallback = str(tmp_path / "fallback.db")
    assert resolve_memory_db(
        explicit,
        environ={"CONTINUITYOS_DB": environment},
        default=fallback,
    )["path"] == os.path.normcase(os.path.abspath(explicit))
    env_result = resolve_memory_db(
        None,
        environ={"CONTINUITYOS_DB": environment},
        default=fallback,
    )
    assert env_result["path"] == os.path.normcase(os.path.abspath(environment))
    assert env_result["source"] == "environment"
    default_result = resolve_memory_db(None, environ={}, default=fallback)
    assert default_result["path"] == os.path.normcase(os.path.abspath(fallback))
    assert default_result["source"] == "default"
    assert resolve_memory_db(":memory:", environ={})["path"] == ":memory:"


def test_default_home_is_expanded_at_call_time(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    result = resolve_memory_db(None, environ={})
    assert result["path"] == os.path.normcase(os.path.abspath(
        str(tmp_path / ".continuityos" / "memory.db")
    ))


def test_logical_context_digest_is_stable_and_scoped(tmp_path):
    path = str(tmp_path / "context with space #1.db")
    memory = Memory(path)
    try:
        first = context_fingerprint(path)
        second = context_fingerprint(path)
        assert first == second
        assert first["scheme"] == CONTEXT_DIGEST_SCHEME
        assert first["row_count"] == 0

        memory.remember("ordinary note", namespace="notes")
        notes_only = context_fingerprint(path)
        assert notes_only["context_sha256"] == first["context_sha256"]

        memory.remember("Never bypass the broker.", namespace="canon")
        canon = context_fingerprint(path)
        assert canon["context_sha256"] != first["context_sha256"]
        assert canon["row_count"] == 1

        memory.remember("Require a receipt.", namespace="rules")
        rules = context_fingerprint(path)
        assert rules["context_sha256"] != canon["context_sha256"]
        assert rules["row_count"] == 2
    finally:
        memory.store.con.close()


def test_context_fingerprint_reads_committed_wal_state(tmp_path):
    path = str(tmp_path / "wal.db")
    memory = Memory(path)
    try:
        memory.store.con.execute("PRAGMA wal_autocheckpoint=0")
        memory.remember("WAL-visible canon", namespace="canon")
        identity = context_fingerprint(path)
        assert identity["row_count"] == 1
    finally:
        memory.store.con.close()


def test_context_fingerprint_rejects_incomplete_schema(tmp_path):
    path = str(tmp_path / "old.db")
    with sqlite3.connect(path) as con:
        con.execute(
            "CREATE TABLE items(id INTEGER PRIMARY KEY, namespace TEXT, text TEXT)"
        )
    with pytest.raises(ValueError, match="items schema is missing"):
        context_fingerprint(path)


def test_live_in_memory_context_has_deterministic_identity():
    context = Continuity(db=":memory:")
    try:
        before = context_identity(context)
        context.add_canon("Never execute without a bound preflight.")
        after = context_identity(context)
        assert before["path"] == ":memory:"
        assert after["row_count"] == 1
        assert before["context_sha256"] != after["context_sha256"]
    finally:
        context.m.store.con.close()


def test_live_context_identity_uses_connection_path_after_cwd_change(
    tmp_path, monkeypatch
):
    opened_from = tmp_path / "opened-from"
    later_cwd = tmp_path / "later-cwd"
    opened_from.mkdir()
    later_cwd.mkdir()
    monkeypatch.chdir(opened_from)
    context = Continuity(db="relative.db")
    try:
        monkeypatch.chdir(later_cwd)
        identity = context_identity(context)
        assert identity["path"] == os.path.normcase(
            os.path.abspath(str(opened_from / "relative.db"))
        )
        assert identity["path_sha256"]
    finally:
        context.m.store.con.close()


def test_cos_serve_does_not_relabel_env_or_default_db_as_explicit(
    tmp_path, monkeypatch
):
    import continuityos.cli as cli
    import continuityos.mcp_server as mcp

    calls = []
    monkeypatch.setattr(mcp, "main", lambda: calls.append(list(sys.argv)) or 0)
    monkeypatch.setattr(sys, "argv", ["pytest"])
    monkeypatch.delenv("CONTINUITYOS_DB", raising=False)
    assert cli.main(["serve"]) == 0
    assert calls[-1] == ["mcp"]

    monkeypatch.setenv("CONTINUITYOS_DB", str(tmp_path / "env.db"))
    assert cli.main(["serve"]) == 0
    assert calls[-1] == ["mcp"]

    explicit = str(tmp_path / "explicit.db")
    assert cli.main(["--db", explicit, "serve"]) == 0
    assert calls[-1] == ["mcp", "--db", explicit]


def test_context_snapshot_blocks_same_store_mutation(tmp_path):
    context = Continuity(db=str(tmp_path / "snapshot.db"))
    item_id = context.add_canon("Never mutate evaluated context mid-decision.")
    started = threading.Event()
    finished = threading.Event()

    def forget():
        started.set()
        context.m.forget(item_id)
        finished.set()

    worker = threading.Thread(target=forget)
    try:
        with context_read_snapshot(context):
            worker.start()
            assert started.wait(2)
            assert not finished.wait(0.1)
            assert context_identity(context)["row_count"] == 1
        worker.join(2)
        assert finished.is_set()
        assert context_identity(context)["row_count"] == 0
    finally:
        context.m.store.con.close()
