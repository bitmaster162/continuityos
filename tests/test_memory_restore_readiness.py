from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sqlite3

import pytest

import continuityos.memory_backup as backup
import continuityos.memory_restore as restore
import continuityos.memory_restore_readiness as readiness


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
    backup_root = home / ".continuityos" / "backups"
    monkeypatch.setattr(backup, "_backup_root", lambda: backup_root)
    monkeypatch.setattr(restore, "_backup_root", lambda: backup_root)

    source = tmp_path / "backup-source.db"
    target = tmp_path / "active-memory.db"
    _seed_memory(source, "backup-state")
    _seed_memory(target, "active-state")
    backup_receipt = backup.create_quiescent_backup(source)

    runtime_root = tmp_path / "runtime"
    runtime_root.mkdir()
    manifest = runtime_root / "runtime-source.json"
    manifest.write_text(json.dumps({"memory_db": str(target.resolve())}), encoding="utf-8")
    return runtime_root, manifest, source, target, backup_receipt, backup_root


def _inspect(runtime_root: Path, receipt: dict[str, object], **kwargs):
    return readiness.inspect_restore_readiness(
        Path(str(receipt["backup_path"])).name,
        runtime_root=runtime_root,
        allow_p5a_v1_compatibility=True,
        acknowledge_byte_exact_replace=True,
        env={},
        **kwargs,
    )


def test_readiness_pass_is_read_only_and_emits_exact_pins(monkeypatch, tmp_path):
    runtime_root, manifest, source, target, receipt, backup_root = _fixture(monkeypatch, tmp_path)
    target_before = target.read_bytes()
    bundle = Path(str(receipt["backup_path"]))
    bundle_before = bundle.read_bytes()
    manifest_before = manifest.read_bytes()

    result = _inspect(runtime_root, receipt)

    assert result["terminal"] == "COS_RESTORE_READINESS_PASS"
    assert result["mode"] == "READ_ONLY_PREFLIGHT"
    assert result["read_only"] is True
    assert result["restore_authorized"] is False
    assert result["restore_performed"] is False
    assert result["rollback_performed"] is False
    assert result["current_effect"]["mode"] == "LEGACY"
    assert result["current_effect"]["restore_effect_allowed"] is True
    assert result["target"]["path"] == str(target.resolve())
    assert result["target"]["current_sha256"] == _sha(target)
    assert result["target"]["sidecars_absent"] is True
    assert result["target"]["validation"]["integrity_check"] == "ok"
    assert result["backup"]["candidate_sha256"] == _sha(source)
    assert result["backup"]["compatibility"]["explicit_acknowledgement"] is True
    assert result["requirements"]["cos_restore_routing_available"] is False
    assert result["requirements"]["separate_live_restore_gate_required"] is True
    assert result["pins"]["expected_current_sha256"] == _sha(target)
    assert result["pins"]["expected_target_path_sha256"] == hashlib.sha256(
        str(target.resolve()).encode("utf-8")
    ).hexdigest()
    assert target.read_bytes() == target_before
    assert bundle.read_bytes() == bundle_before
    assert manifest.read_bytes() == manifest_before
    assert not (backup_root.parent / "restore-transactions").exists()
    for suffix in restore.SIDE_SUFFIXES:
        assert not Path(str(target) + suffix).exists()


def test_acknowledgements_hold_before_runtime_access(tmp_path):
    with pytest.raises(readiness.RestoreReadinessHold) as exc:
        readiness.inspect_restore_readiness(
            "missing.cosbackup",
            runtime_root=tmp_path / "missing",
        )
    assert exc.value.reason == "P5A_V1_COMPATIBILITY_ACK_REQUIRED"

    with pytest.raises(readiness.RestoreReadinessHold) as exc:
        readiness.inspect_restore_readiness(
            "missing.cosbackup",
            runtime_root=tmp_path / "missing",
            allow_p5a_v1_compatibility=True,
        )
    assert exc.value.reason == "BYTE_EXACT_REPLACE_ACK_REQUIRED"


def test_runtime_manifest_conflicting_memory_bindings_fail_closed(monkeypatch, tmp_path):
    runtime_root, manifest, _, target, receipt, backup_root = _fixture(monkeypatch, tmp_path)
    other = tmp_path / "other.db"
    _seed_memory(other, "other")
    manifest.write_text(
        json.dumps({"memory_db": str(target.resolve()), "db": str(other.resolve())}),
        encoding="utf-8",
    )
    before = target.read_bytes()

    with pytest.raises(readiness.RestoreReadinessHold) as exc:
        _inspect(runtime_root, receipt)

    assert exc.value.reason == "RUNTIME_MEMORY_BINDING_CONFLICT"
    assert target.read_bytes() == before
    assert not (backup_root.parent / "restore-transactions").exists()


def test_expected_target_path_and_current_hash_are_fail_closed(monkeypatch, tmp_path):
    runtime_root, _, _, target, receipt, backup_root = _fixture(monkeypatch, tmp_path)
    before = target.read_bytes()

    with pytest.raises(readiness.RestoreReadinessHold) as exc:
        _inspect(runtime_root, receipt, expected_target_path_sha256="0" * 64)
    assert exc.value.reason == "EXPECTED_TARGET_PATH_SHA256_MISMATCH"

    with pytest.raises(readiness.RestoreReadinessHold) as exc:
        _inspect(runtime_root, receipt, expected_current_sha256="0" * 64)
    assert exc.value.reason == "EXPECTED_CURRENT_SHA256_MISMATCH"
    assert target.read_bytes() == before
    assert not (backup_root.parent / "restore-transactions").exists()


@pytest.mark.parametrize("suffix", ["-wal", "-shm", "-journal"])
def test_any_target_sidecar_holds_without_cleanup_or_transaction(
    monkeypatch,
    tmp_path,
    suffix,
):
    runtime_root, _, _, target, receipt, backup_root = _fixture(monkeypatch, tmp_path)
    sidecar = Path(str(target) + suffix)
    sidecar.write_bytes(b"")
    target_before = target.read_bytes()
    sidecar_before = sidecar.read_bytes()

    with pytest.raises(readiness.RestoreReadinessHold) as exc:
        _inspect(runtime_root, receipt)

    assert exc.value.reason == "TARGET_NOT_QUIESCENT"
    assert target.read_bytes() == target_before
    assert sidecar.read_bytes() == sidecar_before
    assert not (backup_root.parent / "restore-transactions").exists()


def test_verified_current_session_reports_effect_hold_without_restore(monkeypatch, tmp_path):
    runtime_root, _, _, target, receipt, backup_root = _fixture(monkeypatch, tmp_path)
    before = target.read_bytes()
    monkeypatch.setattr(
        readiness,
        "inspect_current_session",
        lambda env=None: {
            "mode": "CURRENT",
            "binding_verified": True,
            "reason": "EXACT_CURRENT_SESSION_VERIFIED",
            "session_effect_ceiling": "READ_ONLY",
            "authority_ceiling": "NO_FURTHER_AGENT_WORK",
        },
    )

    result = _inspect(runtime_root, receipt)

    assert result["terminal"] == "COS_RESTORE_READINESS_HOLD"
    assert result["reason"] == "CURRENT_EFFECT_HOLD"
    assert result["current_effect"]["restore_effect_allowed"] is False
    assert result["restore_authorized"] is False
    assert result["restore_performed"] is False
    assert target.read_bytes() == before
    assert not (backup_root.parent / "restore-transactions").exists()


def test_invalid_declared_current_session_reports_revise(monkeypatch, tmp_path):
    runtime_root, _, _, target, receipt, backup_root = _fixture(monkeypatch, tmp_path)
    before = target.read_bytes()
    monkeypatch.setattr(
        readiness,
        "inspect_current_session",
        lambda env=None: {
            "mode": "REVISE",
            "binding_verified": False,
            "reason": "CURRENT_SESSION_BINDING_INCOMPLETE",
        },
    )

    result = _inspect(runtime_root, receipt)

    assert result["terminal"] == "COS_RESTORE_READINESS_HOLD"
    assert result["reason"] == "CURRENT_EFFECT_REVISE"
    assert result["current_effect"]["restore_effect_allowed"] is False
    assert target.read_bytes() == before
    assert not (backup_root.parent / "restore-transactions").exists()


def test_cli_is_preflight_only_and_never_routes_cos_restore(monkeypatch, tmp_path, capsys):
    runtime_root, _, _, target, receipt, backup_root = _fixture(monkeypatch, tmp_path)
    before = target.read_bytes()
    code = readiness.main(
        [
            "--runtime-root",
            str(runtime_root),
            "--backup",
            Path(str(receipt["backup_path"])).name,
            "--allow-p5a-v1-compatibility",
            "--acknowledge-byte-exact-replace",
            "--expected-current-sha256",
            _sha(target),
            "--json",
        ]
    )

    assert code == 0
    result = json.loads(capsys.readouterr().out)
    assert result["terminal"] == "COS_RESTORE_READINESS_PASS"
    assert result["requirements"]["cos_restore_routing_available"] is False
    assert result["restore_authorized"] is False
    assert result["restore_performed"] is False
    assert target.read_bytes() == before
    assert not (backup_root.parent / "restore-transactions").exists()
