from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sqlite3
import zipfile

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


def _roots(monkeypatch, tmp_path: Path) -> tuple[Path, Path]:
    home = tmp_path / "home"
    home.mkdir()
    root = home / ".continuityos" / "backups"
    monkeypatch.setattr(backup, "_backup_root", lambda: root)
    monkeypatch.setattr(restore, "_backup_root", lambda: root)
    return root, root.parent / "restore-transactions"


def _fixture_backup(monkeypatch, tmp_path: Path) -> tuple[Path, Path, dict[str, object], Path]:
    root, txn_root = _roots(monkeypatch, tmp_path)
    candidate = tmp_path / "candidate.db"
    target = tmp_path / "target.db"
    _seed_memory(candidate, "candidate-state")
    _seed_memory(target, "target-state")
    receipt = backup.create_quiescent_backup(candidate)
    return candidate, target, receipt, txn_root


def _restore(
    receipt: dict[str, object],
    target: Path,
    *,
    expected: str | None = None,
    allow: bool = True,
):
    return restore.restore_quiescent_backup(
        Path(str(receipt["backup_path"])).name,
        target,
        expected or _sha(target),
        confirmed=True,
        allow_p5a_v1_compatibility=allow,
    )


def test_p5a_v1_requires_explicit_compatibility_acknowledgement(monkeypatch, tmp_path):
    _, target, receipt, txn_root = _fixture_backup(monkeypatch, tmp_path)
    before = target.read_bytes()

    with pytest.raises(restore.RestoreHold) as exc:
        _restore(receipt, target, allow=False)

    assert exc.value.reason == "BACKUP_NOT_RESTORE_COMPATIBLE"
    assert target.read_bytes() == before
    assert not txn_root.exists()


def test_restore_is_atomic_byte_exact_and_retains_preimage(monkeypatch, tmp_path):
    candidate, target, receipt, txn_root = _fixture_backup(monkeypatch, tmp_path)
    before = target.read_bytes()
    before_sha = _sha(target)
    candidate_sha = _sha(candidate)

    result = _restore(receipt, target)

    assert result["terminal"] == "COS_RESTORE_PASS"
    assert result["mode"] == "QUIESCENT_ATOMIC_RESTORE"
    assert result["target"]["before_sha256"] == before_sha
    assert result["target"]["after_sha256"] == candidate_sha
    assert target.read_bytes() == candidate.read_bytes()
    assert result["restore_performed"] is True
    assert result["rollback_performed"] is False
    assert result["governance"] == {
        "execution_authority": "NONE",
        "can_execute": False,
        "can_trade": False,
        "capital_permission": "DENY",
    }
    compatibility = result["backup"]["compatibility"]
    assert compatibility["schema"] == restore.P5A_COMPATIBILITY_SCHEMA
    assert compatibility["manifest_restore_available"] is False
    assert compatibility["explicit_acknowledgement"] is True

    preimage = Path(result["preimage"]["path"])
    assert preimage.read_bytes() == before
    assert _sha(preimage) == before_sha
    assert preimage.parent.parent == txn_root.resolve()
    assert (preimage.parent / "intent.json").is_file()
    assert (preimage.parent / "result.json").is_file()
    for suffix in restore.SIDE_SUFFIXES:
        assert not Path(str(target) + suffix).exists()


def test_expected_current_sha_mismatch_holds_before_transaction_write(monkeypatch, tmp_path):
    _, target, receipt, txn_root = _fixture_backup(monkeypatch, tmp_path)
    before = target.read_bytes()

    with pytest.raises(restore.RestoreHold) as exc:
        _restore(receipt, target, expected="0" * 64)

    assert exc.value.reason == "EXPECTED_CURRENT_SHA256_MISMATCH"
    assert target.read_bytes() == before
    assert not txn_root.exists()


@pytest.mark.parametrize("suffix", ["-wal", "-shm", "-journal"])
def test_any_target_sqlite_sidecar_holds_before_transaction_write(
    monkeypatch,
    tmp_path,
    suffix,
):
    _, target, receipt, txn_root = _fixture_backup(monkeypatch, tmp_path)
    before = target.read_bytes()
    Path(str(target) + suffix).write_bytes(b"")

    with pytest.raises(restore.RestoreHold) as exc:
        _restore(receipt, target)

    assert exc.value.reason == "TARGET_NOT_QUIESCENT"
    assert target.read_bytes() == before
    assert not txn_root.exists()


def test_target_drift_during_preimage_custody_holds_before_switch(monkeypatch, tmp_path):
    candidate, target, receipt, _ = _fixture_backup(monkeypatch, tmp_path)
    before = target.read_bytes()
    candidate_bytes = candidate.read_bytes()
    original = restore._copy_fsync

    def copy_then_touch(source: Path, destination: Path) -> None:
        original(source, destination)
        if source == target.resolve() and destination.name == "before.memory.db":
            stat = target.stat()
            os.utime(target, ns=(stat.st_atime_ns, stat.st_mtime_ns + 1_000_000))

    monkeypatch.setattr(restore, "_copy_fsync", copy_then_touch)
    with pytest.raises(restore.RestoreHold) as exc:
        _restore(receipt, target)

    assert exc.value.reason == "TARGET_CHANGED_DURING_RESTORE"
    assert target.read_bytes() == before
    assert target.read_bytes() != candidate_bytes


def test_post_switch_validation_failure_rolls_back_byte_exact(monkeypatch, tmp_path):
    candidate, target, receipt, txn_root = _fixture_backup(monkeypatch, tmp_path)
    before = target.read_bytes()
    before_sha = _sha(target)
    candidate_sha = _sha(candidate)
    original = restore._validate_sqlite

    def fail_only_after_switch(path: Path):
        if path.resolve() == target.resolve() and _sha(target) == candidate_sha:
            raise restore.RestoreHold("INJECTED_POST_SWITCH_FAILURE", "synthetic")
        return original(path)

    monkeypatch.setattr(restore, "_validate_sqlite", fail_only_after_switch)
    with pytest.raises(restore.RestoreHold) as exc:
        _restore(receipt, target)

    assert exc.value.reason == "POST_RESTORE_TRANSACTION_FAILED_ROLLED_BACK"
    assert target.read_bytes() == before
    assert _sha(target) == before_sha
    results = list(txn_root.rglob("result.json"))
    assert len(results) == 1
    result = json.loads(results[0].read_text(encoding="utf-8"))
    assert result["restore_performed"] is True
    assert result["rollback_performed"] is True
    assert result["rollback"]["target_sha256"] == before_sha


def test_tampered_embedded_memory_holds_without_target_mutation(monkeypatch, tmp_path):
    _, target, receipt, txn_root = _fixture_backup(monkeypatch, tmp_path)
    before = target.read_bytes()
    bundle = Path(str(receipt["backup_path"]))
    with zipfile.ZipFile(bundle, "r") as archive:
        manifest = archive.read("manifest.json")
        memory = archive.read("memory.db")
    with zipfile.ZipFile(bundle, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("memory.db", b"X" + memory[1:])
        archive.writestr("manifest.json", manifest)

    with pytest.raises(restore.RestoreHold) as exc:
        _restore(receipt, target)

    assert exc.value.reason == "BACKUP_HASH_MISMATCH"
    assert target.read_bytes() == before
    assert not txn_root.exists()


def test_backup_path_escape_is_rejected(monkeypatch, tmp_path):
    _, target, _, txn_root = _fixture_backup(monkeypatch, tmp_path)
    before = target.read_bytes()

    with pytest.raises(restore.RestoreHold) as exc:
        restore.restore_quiescent_backup(
            "../outside.cosbackup",
            target,
            _sha(target),
            confirmed=True,
            allow_p5a_v1_compatibility=True,
        )

    assert exc.value.reason == "BACKUP_NAME_INVALID"
    assert target.read_bytes() == before
    assert not txn_root.exists()


def test_current_effect_boundary_holds_before_bundle_or_target_access(monkeypatch, tmp_path):
    def held(effect: str):
        raise restore.CurrentEffectBoundaryError(
            effect,
            {"mode": "CURRENT", "reason": "EXACT_CURRENT_SESSION_VERIFIED"},
        )

    monkeypatch.setattr(restore, "assert_current_effect_allowed", held)
    with pytest.raises(restore.RestoreHold) as exc:
        restore.restore_quiescent_backup(
            "missing.cosbackup",
            tmp_path / "missing.db",
            "0" * 64,
            confirmed=True,
            allow_p5a_v1_compatibility=True,
        )

    assert exc.value.reason == "CURRENT_EFFECT_HOLD"


def test_cli_requires_explicit_byte_replace_confirmation(monkeypatch, tmp_path, capsys):
    _, target, receipt, _ = _fixture_backup(monkeypatch, tmp_path)
    before = target.read_bytes()

    code = restore.main(
        [
            "--db",
            str(target),
            "--backup",
            Path(str(receipt["backup_path"])).name,
            "--expected-current-sha256",
            _sha(target),
            "--allow-p5a-v1-compatibility",
            "--json",
        ]
    )

    assert code == 2
    result = json.loads(capsys.readouterr().out)
    assert result["terminal"] == "COS_RESTORE_HOLD"
    assert result["reason"] == "EXPLICIT_CONFIRMATION_REQUIRED"
    assert result["restore_performed"] is False
    assert target.read_bytes() == before
