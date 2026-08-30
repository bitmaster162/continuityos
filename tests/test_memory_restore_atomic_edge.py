from __future__ import annotations

import hashlib
import os
from pathlib import Path
import sqlite3

import pytest

import continuityos.memory_backup as backup
import continuityos.memory_restore as restore


def _seed_memory(path: Path, text: str) -> None:
    con = sqlite3.connect(path)
    try:
        con.execute("PRAGMA journal_mode=DELETE")
        con.execute(
            """CREATE TABLE items(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                namespace TEXT NOT NULL DEFAULT 'default',
                text TEXT NOT NULL,
                tags TEXT NOT NULL DEFAULT '[]',
                meta TEXT NOT NULL DEFAULT '{}',
                vec BLOB,
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL,
                key TEXT,
                version INTEGER NOT NULL DEFAULT 0
            )"""
        )
        con.execute(
            "INSERT INTO items(namespace,text,tags,meta,created_at,updated_at,key,version) "
            "VALUES(?,?,?,?,?,?,?,?)",
            ("facts", text, "[]", "{}", 1.0, 1.0, text, 1),
        )
        con.commit()
    finally:
        con.close()


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _fixture(monkeypatch, tmp_path: Path):
    home = tmp_path / "home"
    home.mkdir()
    root = home / ".continuityos" / "backups"
    monkeypatch.setattr(backup, "_backup_root", lambda: root)
    monkeypatch.setattr(restore, "_backup_root", lambda: root)

    source = tmp_path / "source.db"
    target = tmp_path / "target.db"
    _seed_memory(source, "restore-source")
    _seed_memory(target, "restore-target")
    receipt = backup.create_quiescent_backup(source)
    return source, target, receipt


def test_p5a_restore_compatibility_schema_is_literal_v1():
    assert restore.P5A_BACKUP_SCHEMA == "continuityos.memory_backup/v1"
    assert restore.P5A_COMPATIBILITY_SCHEMA == (
        "continuityos.memory_restore.p5a_v1_compatibility/v1"
    )


def test_atomic_helper_error_after_replace_rolls_back_byte_exact(monkeypatch, tmp_path):
    source, target, receipt = _fixture(monkeypatch, tmp_path)
    target_before = target.read_bytes()
    target_before_sha = _sha(target)
    candidate_sha = _sha(source)
    calls = 0

    def first_switch_reports_error(temp: Path, destination: Path) -> None:
        nonlocal calls
        calls += 1
        os.replace(temp, destination)
        if calls == 1:
            assert _sha(destination) == candidate_sha
            raise OSError("synthetic post-switch durability failure")

    monkeypatch.setattr(restore, "_replace_file_atomic", first_switch_reports_error)

    with pytest.raises(restore.RestoreHold) as exc:
        restore.restore_quiescent_backup(
            Path(str(receipt["backup_path"])).name,
            target,
            target_before_sha,
            confirmed=True,
            allow_p5a_v1_compatibility=True,
        )

    assert exc.value.reason == "ATOMIC_REPLACE_FAILED_ROLLED_BACK"
    assert calls == 2
    assert target.read_bytes() == target_before
    assert _sha(target) == target_before_sha
    for suffix in restore.SIDE_SUFFIXES:
        assert not Path(str(target) + suffix).exists()
