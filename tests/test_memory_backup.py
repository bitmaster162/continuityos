from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sqlite3
import zipfile

import pytest

import continuityos.current_entrypoints as guard
import continuityos.memory_backup as backup


def _seed_memory(path: Path) -> None:
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
            (
                "facts",
                "bounded backup fixture",
                "[]",
                "{}",
                1.0,
                1.0,
                "fixture",
                1,
            ),
        )
        con.commit()
    finally:
        con.close()


def _fixed_root(monkeypatch, tmp_path: Path) -> Path:
    home = tmp_path / "home"
    home.mkdir()
    root = home / ".continuityos" / "backups"
    monkeypatch.setattr(backup, "_backup_root", lambda: root)
    return root


def _published(root: Path) -> list[Path]:
    return list(root.glob("*.cosbackup")) if root.exists() else []


def test_quiescent_snapshot_is_byte_exact_and_manifested(monkeypatch, tmp_path):
    source = tmp_path / "memory.db"
    _seed_memory(source)
    source_before = source.read_bytes()
    source_sha = hashlib.sha256(source_before).hexdigest()
    root = _fixed_root(monkeypatch, tmp_path)

    receipt = backup.create_quiescent_backup(source)

    assert receipt["terminal"] == "COS_BACKUP_PASS"
    assert receipt["mode"] == "QUIESCENT_SNAPSHOT"
    assert receipt["source"]["sha256"] == source_sha
    assert receipt["backup"]["memory_sha256"] == source_sha
    assert receipt["backup"]["integrity_check"] == "ok"
    assert receipt["backup"]["restore_available"] is False
    assert receipt["governance"] == {
        "execution_authority": "NONE",
        "can_execute": False,
        "can_trade": False,
        "capital_permission": "DENY",
    }
    assert source.read_bytes() == source_before
    for suffix in ("-wal", "-shm", "-journal"):
        assert not Path(str(source) + suffix).exists()

    bundle = Path(receipt["backup_path"])
    assert bundle.parent == root.resolve()
    with zipfile.ZipFile(bundle, "r") as archive:
        assert sorted(archive.namelist()) == ["manifest.json", "memory.db"]
        assert archive.read("memory.db") == source_before
        manifest = json.loads(archive.read("manifest.json").decode("utf-8"))
    assert manifest["backup"]["bundle_filename"] == bundle.name
    assert manifest["source"]["path_sha256"] == hashlib.sha256(
        str(source.resolve()).encode("utf-8")
    ).hexdigest()
    assert "backup_path" not in manifest


def test_nonempty_wal_holds_before_backup_root_write(monkeypatch, tmp_path):
    source = tmp_path / "memory.db"
    _seed_memory(source)
    wal = Path(str(source) + "-wal")
    wal.write_bytes(b"active-wal")
    source_before = source.read_bytes()
    wal_before = wal.read_bytes()
    root = _fixed_root(monkeypatch, tmp_path)

    with pytest.raises(backup.BackupHold) as exc:
        backup.create_quiescent_backup(source)

    assert exc.value.reason == "SOURCE_WAL_ACTIVE"
    assert not root.exists()
    assert source.read_bytes() == source_before
    assert wal.read_bytes() == wal_before


def test_nonempty_rollback_journal_holds_before_backup_root_write(
    monkeypatch,
    tmp_path,
):
    source = tmp_path / "memory.db"
    _seed_memory(source)
    journal = Path(str(source) + "-journal")
    journal.write_bytes(b"active-journal")
    root = _fixed_root(monkeypatch, tmp_path)

    with pytest.raises(backup.BackupHold) as exc:
        backup.create_quiescent_backup(source)

    assert exc.value.reason == "SOURCE_ROLLBACK_JOURNAL_ACTIVE"
    assert not root.exists()


def test_source_change_during_copy_holds_without_published_bundle(
    monkeypatch,
    tmp_path,
):
    source = tmp_path / "memory.db"
    _seed_memory(source)
    root = _fixed_root(monkeypatch, tmp_path)
    original = backup._copy_source

    def copy_then_mutate(src: Path, dst: Path) -> None:
        original(src, dst)
        with src.open("ab") as handle:
            handle.write(b"drift")

    monkeypatch.setattr(backup, "_copy_source", copy_then_mutate)
    with pytest.raises(backup.BackupHold) as exc:
        backup.create_quiescent_backup(source)

    assert exc.value.reason == "SOURCE_CHANGED_DURING_BACKUP"
    assert _published(root) == []
    assert list(root.glob(".p5a-memory-backup-*")) == []


def test_sidecar_change_during_copy_holds_without_published_bundle(
    monkeypatch,
    tmp_path,
):
    source = tmp_path / "memory.db"
    _seed_memory(source)
    root = _fixed_root(monkeypatch, tmp_path)
    original = backup._copy_source

    def copy_then_create_shm(src: Path, dst: Path) -> None:
        original(src, dst)
        Path(str(src) + "-shm").write_bytes(b"new-sidecar")

    monkeypatch.setattr(backup, "_copy_source", copy_then_create_shm)
    with pytest.raises(backup.BackupHold) as exc:
        backup.create_quiescent_backup(source)

    assert exc.value.reason == "SIDECAR_CHANGED_DURING_BACKUP"
    assert _published(root) == []


def test_invalid_sqlite_schema_holds_without_published_bundle(
    monkeypatch,
    tmp_path,
):
    source = tmp_path / "memory.db"
    con = sqlite3.connect(source)
    con.execute("CREATE TABLE unrelated(id INTEGER PRIMARY KEY)")
    con.commit()
    con.close()
    root = _fixed_root(monkeypatch, tmp_path)

    with pytest.raises(backup.BackupHold) as exc:
        backup.create_quiescent_backup(source)

    assert exc.value.reason == "BACKUP_VALIDATION_FAILED"
    assert _published(root) == []
    assert list(root.glob(".p5a-memory-backup-*")) == []


def test_backup_root_symlink_escape_holds(monkeypatch, tmp_path):
    source = tmp_path / "memory.db"
    _seed_memory(source)
    root = _fixed_root(monkeypatch, tmp_path)
    root.parent.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    try:
        root.symlink_to(outside, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("directory symlink creation unavailable")

    with pytest.raises(backup.BackupHold) as exc:
        backup.create_quiescent_backup(source)

    assert exc.value.reason == "BACKUP_ROOT_UNSAFE"
    assert list(outside.iterdir()) == []


def test_cli_has_no_arbitrary_destination_or_restore_flags(tmp_path):
    source = tmp_path / "memory.db"
    _seed_memory(source)
    with pytest.raises(SystemExit) as exc:
        backup.main(
            ["--db", str(source), "--out", str(tmp_path / "elsewhere")]
        )
    assert exc.value.code == 2
    with pytest.raises(SystemExit) as exc:
        backup.main(["--db", str(source), "--restore"])
    assert exc.value.code == 2


def test_cos_backup_routes_before_legacy_memory_construction(monkeypatch, tmp_path):
    source = tmp_path / "memory.db"
    _seed_memory(source)
    calls: list[list[str]] = []

    monkeypatch.setattr(guard, "current_binding_from_env", lambda env: (None, []))
    monkeypatch.setattr(
        backup,
        "main",
        lambda argv=None: calls.append(list(argv or [])) or 0,
    )

    def forbidden_legacy(command):
        raise AssertionError(f"legacy loader must not handle backup: {command}")

    monkeypatch.setattr(guard, "_legacy_cos_loader", forbidden_legacy)
    code = guard.cos_main(["--db", str(source), "backup", "--json"])

    assert code == 0
    assert calls == [["--db", str(source), "--json"]]


def test_verified_current_read_only_session_holds_backup_before_write(
    monkeypatch,
    capsys,
):
    binding = {
        "challenge": "challenge.json",
        "challenge_sha256": "a" * 64,
        "ack": "ack.json",
    }
    monkeypatch.setattr(
        guard,
        "current_binding_from_env",
        lambda env: (binding, []),
    )
    monkeypatch.setattr(
        guard,
        "verify_current_runtime_binding",
        lambda *args, **kwargs: {
            "binding_verified": True,
            "authority_generation": "R64",
            "challenge_id": "c" * 64,
            "challenge_sha256": "a" * 64,
        },
    )

    def forbidden_backup(argv=None):
        raise AssertionError("backup implementation must not run inside current HOLD")

    monkeypatch.setattr(backup, "main", forbidden_backup)
    assert guard.cos_main(["backup", "--json"]) == 3
    result = json.loads(capsys.readouterr().out)
    assert result["terminal"] == "CURRENT_ENTRYPOINT_HOLD"
    assert result["command"] == "backup"
    assert result["effects"]["filesystem_write"] is False
    assert result["effects"]["memory_write"] is False


def test_product_help_exposes_backup_without_restore():
    assert "backup" in guard.PRODUCT_HELP
    assert "no restore" in guard.PRODUCT_HELP
