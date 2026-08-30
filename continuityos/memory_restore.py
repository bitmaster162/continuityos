"""Fail-closed transactional restore for ContinuityOS memory backups.

P5B intentionally exposes only a separately-authorized transaction primitive. It
never treats P5A's ``restore_available=false`` as implicit permission: a P5A/v1
bundle is accepted only through the explicit compatibility acknowledgement below.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import stat
from typing import Any, Mapping, Sequence
import uuid
import zipfile

from .current_effect_boundary import CurrentEffectBoundaryError, assert_current_effect_allowed
from .db import resolve_memory_db
from .memory_backup import (
    BackupHold,
    MANIFEST_MEMBER,
    MEMORY_MEMBER,
    REQUIRED_ITEMS_COLUMNS,
    SCHEMA as P5A_BACKUP_SCHEMA,
    _backup_root,
    _governance,
    _hash_file,
    _validate_sqlite_copy,
)
from .windows_product_transaction import _replace_file_atomic

SCHEMA = "continuityos.memory_restore/v1"
MODE = "QUIESCENT_ATOMIC_RESTORE"
P5A_COMPATIBILITY_SCHEMA = "continuityos.memory_restore.p5a_v1_compatibility/v1"
SIDE_SUFFIXES = ("-wal", "-shm", "-journal")


class RestoreHold(RuntimeError):
    def __init__(self, reason: str, detail: str = ""):
        super().__init__(detail or reason)
        self.reason = reason
        self.detail = detail or reason


class RestoreRollbackError(RuntimeError):
    reason = "ROLLBACK_VERIFICATION_FAILED"

    def __init__(self, detail: str):
        super().__init__(detail)
        self.detail = detail


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _require_sha256(value: str, label: str) -> str:
    text = str(value or "").lower()
    if len(text) != 64 or any(c not in "0123456789abcdef" for c in text):
        raise RestoreHold("INVALID_SHA256", f"{label} must be SHA-256 hex")
    return text


def _require_regular_file(path: Path, label: str) -> None:
    try:
        info = path.lstat()
    except OSError as exc:
        raise RestoreHold(f"{label}_UNAVAILABLE", f"{label.lower()} unavailable") from exc
    attrs = int(getattr(info, "st_file_attributes", 0))
    reparse = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    if path.is_symlink() or attrs & reparse or not stat.S_ISREG(info.st_mode):
        raise RestoreHold(f"{label}_UNSAFE", f"{label.lower()} is not a regular direct file")


def _resolve_bundle(filename: str) -> Path:
    name = str(filename or "")
    if not name or Path(name).name != name or "/" in name or "\\" in name or not name.endswith(".cosbackup"):
        raise RestoreHold(
            "BACKUP_NAME_INVALID",
            "restore accepts only a .cosbackup filename from the fixed backup root",
        )
    root = _backup_root()
    if root.is_symlink() or not root.is_dir():
        raise RestoreHold("BACKUP_ROOT_UNSAFE", "fixed backup root is unavailable or unsafe")
    root = root.resolve(strict=True)
    bundle = root / name
    _require_regular_file(bundle, "BACKUP_BUNDLE")
    bundle = bundle.resolve(strict=True)
    if bundle.parent != root:
        raise RestoreHold("BACKUP_BUNDLE_UNSAFE", "backup bundle escapes fixed backup root")
    return bundle


def _compatibility_receipt(manifest: Mapping[str, Any], bundle_name: str, allow: bool) -> dict[str, Any]:
    if manifest.get("schema") != P5A_BACKUP_SCHEMA:
        raise RestoreHold("BACKUP_SCHEMA_UNSUPPORTED", "backup schema is unsupported")
    if manifest.get("terminal") != "COS_BACKUP_PASS" or manifest.get("mode") != "QUIESCENT_SNAPSHOT":
        raise RestoreHold("BACKUP_MANIFEST_INVALID", "backup terminal/mode mismatch")
    if manifest.get("governance") != _governance():
        raise RestoreHold("BACKUP_MANIFEST_INVALID", "backup governance mismatch")
    backup = manifest.get("backup")
    source = manifest.get("source")
    if not isinstance(backup, Mapping) or not isinstance(source, Mapping):
        raise RestoreHold("BACKUP_MANIFEST_INVALID", "backup/source section missing")
    if backup.get("bundle_filename") != bundle_name:
        raise RestoreHold("BACKUP_MANIFEST_INVALID", "bundle filename binding mismatch")
    if backup.get("memory_member") != MEMORY_MEMBER or backup.get("manifest_member") != MANIFEST_MEMBER:
        raise RestoreHold("BACKUP_MANIFEST_INVALID", "bundle member binding mismatch")
    if backup.get("restore_available") is not False:
        raise RestoreHold("BACKUP_MANIFEST_INVALID", "P5A/v1 must carry restore_available=false")
    if not allow:
        raise RestoreHold(
            "BACKUP_NOT_RESTORE_COMPATIBLE",
            "P5A/v1 requires explicit --allow-p5a-v1-compatibility acknowledgement",
        )
    if backup.get("integrity_check") != "ok" or backup.get("required_items_columns") != sorted(REQUIRED_ITEMS_COLUMNS):
        raise RestoreHold("BACKUP_MANIFEST_INVALID", "backup integrity/schema receipt mismatch")
    memory_sha = _require_sha256(str(backup.get("memory_sha256") or ""), "backup.memory_sha256")
    if str(source.get("sha256") or "").lower() != memory_sha:
        raise RestoreHold("BACKUP_MANIFEST_INVALID", "source/backup SHA binding mismatch")
    size = backup.get("memory_size_bytes")
    if not isinstance(size, int) or isinstance(size, bool) or size <= 0 or source.get("size_bytes") != size:
        raise RestoreHold("BACKUP_MANIFEST_INVALID", "source/backup size binding mismatch")
    pre = source.get("sidecars_pre")
    post = source.get("sidecars_post")
    if not isinstance(pre, Mapping) or post != pre:
        raise RestoreHold("BACKUP_MANIFEST_INVALID", "P5A sidecar custody mismatch")
    for suffix in ("-wal", "-journal"):
        item = pre.get(suffix)
        if not isinstance(item, Mapping) or int(item.get("size") or 0) != 0:
            raise RestoreHold("BACKUP_MANIFEST_INVALID", f"P5A source was not quiescent at {suffix}")
    return {
        "memory_sha256": memory_sha,
        "memory_size_bytes": size,
        "compatibility": {
            "schema": P5A_COMPATIBILITY_SCHEMA,
            "source_backup_schema": P5A_BACKUP_SCHEMA,
            "manifest_restore_available": False,
            "explicit_acknowledgement": True,
        },
    }


def _read_bundle(bundle: Path, *, allow_p5a_v1_compatibility: bool) -> dict[str, Any]:
    try:
        with zipfile.ZipFile(bundle, "r") as archive:
            infos = archive.infolist()
            if sorted(i.filename for i in infos) != [MANIFEST_MEMBER, MEMORY_MEMBER] or any(i.is_dir() for i in infos):
                raise RestoreHold("BACKUP_BUNDLE_INVALID", "backup bundle members are not exact")
            manifest = json.loads(archive.read(MANIFEST_MEMBER).decode("utf-8"))
            if not isinstance(manifest, dict):
                raise RestoreHold("BACKUP_MANIFEST_INVALID", "manifest root must be an object")
            verdict = _compatibility_receipt(manifest, bundle.name, allow_p5a_v1_compatibility)
            if archive.getinfo(MEMORY_MEMBER).file_size != verdict["memory_size_bytes"]:
                raise RestoreHold("BACKUP_BUNDLE_INVALID", "embedded memory size mismatch")
            return verdict
    except RestoreHold:
        raise
    except (OSError, zipfile.BadZipFile, KeyError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RestoreHold("BACKUP_BUNDLE_INVALID", f"backup bundle read failed: {type(exc).__name__}") from exc


def _require_no_sidecars(target: Path, reason: str = "TARGET_NOT_QUIESCENT") -> None:
    for suffix in SIDE_SUFFIXES:
        if Path(str(target) + suffix).exists():
            raise RestoreHold(reason, f"quiescent restore requires absent SQLite sidecar: {suffix}")


def _target_state(target: Path) -> dict[str, Any]:
    _require_regular_file(target, "TARGET_MEMORY")
    _require_no_sidecars(target)
    info = target.stat()
    return {
        "size": int(info.st_size),
        "mtime_ns": int(info.st_mtime_ns),
        "device": int(getattr(info, "st_dev", 0)),
        "inode": int(getattr(info, "st_ino", 0)),
        "sha256": _hash_file(target),
    }


def _validate_sqlite(path: Path) -> dict[str, object]:
    try:
        return dict(_validate_sqlite_copy(path))
    except BackupHold as exc:
        raise RestoreHold("CANDIDATE_VALIDATION_FAILED", exc.detail) from exc


def _extract_candidate(bundle: Path, destination: Path, expected_sha: str, expected_size: int) -> None:
    digest = hashlib.sha256()
    size = 0
    try:
        with zipfile.ZipFile(bundle, "r") as archive, archive.open(MEMORY_MEMBER, "r") as src, destination.open("xb") as dst:
            for chunk in iter(lambda: src.read(1024 * 1024), b""):
                size += len(chunk)
                digest.update(chunk)
                dst.write(chunk)
            dst.flush()
            os.fsync(dst.fileno())
    except (OSError, zipfile.BadZipFile, KeyError) as exc:
        raise RestoreHold("BACKUP_BUNDLE_INVALID", "failed to stage embedded memory") from exc
    if size != expected_size or digest.hexdigest() != expected_sha:
        raise RestoreHold("BACKUP_HASH_MISMATCH", "staged candidate does not match manifest")


def _copy_fsync(source: Path, destination: Path) -> None:
    with source.open("rb") as src, destination.open("xb") as dst:
        shutil.copyfileobj(src, dst, length=1024 * 1024)
        dst.flush()
        os.fsync(dst.fileno())


def _transaction_dir() -> Path:
    state = _backup_root().parent
    if state.is_symlink() or not state.is_dir():
        raise RestoreHold("TRANSACTION_ROOT_UNSAFE", "ContinuityOS state directory is unsafe")
    root = state / "restore-transactions"
    if root.exists():
        if root.is_symlink() or not root.is_dir():
            raise RestoreHold("TRANSACTION_ROOT_UNSAFE", "restore transaction root is unsafe")
    else:
        root.mkdir(mode=0o700)
    root = root.resolve(strict=True)
    txn = root / (datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ") + "-" + uuid.uuid4().hex)
    txn.mkdir(mode=0o700)
    return txn


def _write_json(path: Path, value: Mapping[str, Any]) -> None:
    data = (json.dumps(dict(value), ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    with path.open("xb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())


def _cleanup(path: Path) -> None:
    try:
        path.unlink()
    except (FileNotFoundError, OSError):
        pass


def _rollback(target: Path, preimage: Path, candidate_sha: str, preimage_sha: str) -> dict[str, object]:
    if _hash_file(target) != candidate_sha:
        raise RestoreRollbackError("rollback refuses target drift after candidate switch")
    try:
        _require_no_sidecars(target, "ROLLBACK_TARGET_NOT_QUIESCENT")
    except RestoreHold as exc:
        raise RestoreRollbackError(exc.detail) from exc
    temp = target.parent / f".{target.name}.p5b-rollback-{uuid.uuid4().hex}.tmp"
    try:
        _copy_fsync(preimage, temp)
        if _hash_file(temp) != preimage_sha:
            raise RestoreRollbackError("rollback staging hash mismatch")
        _validate_sqlite(temp)
        _replace_file_atomic(temp, target)
        if _hash_file(target) != preimage_sha:
            raise RestoreRollbackError("rollback readback hash mismatch")
        _validate_sqlite(target)
        _require_no_sidecars(target, "ROLLBACK_TARGET_NOT_QUIESCENT")
        return {"ok": True, "rollback_performed": True, "target_sha256": preimage_sha}
    except RestoreRollbackError:
        raise
    except Exception as exc:
        raise RestoreRollbackError(f"rollback failed: {type(exc).__name__}: {exc}") from exc
    finally:
        _cleanup(temp)


def restore_quiescent_backup(
    backup_filename: str,
    target_path: str | Path,
    expected_current_sha256: str,
    *,
    confirmed: bool = False,
    allow_p5a_v1_compatibility: bool = False,
) -> dict[str, object]:
    try:
        assert_current_effect_allowed("memory.restore")
    except CurrentEffectBoundaryError as exc:
        raise RestoreHold("CURRENT_EFFECT_HOLD", str(exc)) from exc
    if not confirmed:
        raise RestoreHold("EXPLICIT_CONFIRMATION_REQUIRED", "restore requires explicit byte-replace confirmation")

    expected_current = _require_sha256(expected_current_sha256, "expected_current_sha256")
    bundle = _resolve_bundle(backup_filename)
    bundle_sha = _hash_file(bundle)
    bundle_state = _read_bundle(bundle, allow_p5a_v1_compatibility=allow_p5a_v1_compatibility)
    if str(target_path) == ":memory:":
        raise RestoreHold("IN_MEMORY_TARGET_UNSUPPORTED", "in-memory target cannot be restored")
    raw_target = Path(target_path).expanduser()
    if raw_target.is_symlink():
        raise RestoreHold("TARGET_MEMORY_UNSAFE", "target memory is a symlink")
    try:
        target = raw_target.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise RestoreHold("TARGET_MEMORY_UNAVAILABLE", "target memory is unavailable") from exc

    initial = _target_state(target)
    if initial["sha256"] != expected_current:
        raise RestoreHold("EXPECTED_CURRENT_SHA256_MISMATCH", "target does not match the pinned current SHA-256")

    candidate = target.parent / f".{target.name}.p5b-candidate-{uuid.uuid4().hex}.tmp"
    switched = False
    txn: Path | None = None
    preimage: Path | None = None
    try:
        _extract_candidate(bundle, candidate, str(bundle_state["memory_sha256"]), int(bundle_state["memory_size_bytes"]))
        candidate_sha = _hash_file(candidate)
        candidate_validation = _validate_sqlite(candidate)
        if _target_state(target) != initial:
            raise RestoreHold("TARGET_CHANGED_DURING_RESTORE", "target changed before pre-image custody")

        txn = _transaction_dir()
        preimage = txn / "before.memory.db"
        _copy_fsync(target, preimage)
        if _hash_file(preimage) != expected_current:
            raise RestoreHold("PREIMAGE_HASH_MISMATCH", "pre-image does not match pinned current SHA-256")
        _validate_sqlite(preimage)
        if _target_state(target) != initial:
            raise RestoreHold("TARGET_CHANGED_DURING_RESTORE", "target changed during pre-image custody")

        intent = {
            "schema": SCHEMA,
            "mode": MODE,
            "transaction_id": txn.name,
            "target": {
                "filename": target.name,
                "path_sha256": _sha256_bytes(str(target).encode("utf-8")),
                "expected_current_sha256": expected_current,
            },
            "backup": {
                "bundle_filename": bundle.name,
                "bundle_sha256": bundle_sha,
                "candidate_sha256": candidate_sha,
                "compatibility": bundle_state["compatibility"],
            },
            "preimage": {"filename": preimage.name, "sha256": expected_current, "retained": True},
            "governance": _governance(),
        }
        _write_json(txn / "intent.json", intent)
        if _target_state(target) != initial or _hash_file(candidate) != candidate_sha:
            raise RestoreHold("TARGET_OR_CANDIDATE_DRIFT", "target or candidate changed before atomic replace")

        _replace_file_atomic(candidate, target)
        switched = True
        try:
            if _hash_file(target) != candidate_sha:
                raise RestoreHold("RESTORE_READBACK_MISMATCH", "restored target hash mismatch")
            post_validation = _validate_sqlite(target)
            _require_no_sidecars(target)
            result = {
                "schema": SCHEMA,
                "terminal": "COS_RESTORE_PASS",
                "mode": MODE,
                "transaction_id": txn.name,
                "transaction_dir": str(txn),
                "target": {
                    "filename": target.name,
                    "path_sha256": _sha256_bytes(str(target).encode("utf-8")),
                    "before_sha256": expected_current,
                    "after_sha256": candidate_sha,
                },
                "backup": intent["backup"],
                "preimage": {"path": str(preimage), "sha256": expected_current, "retained": True},
                "candidate_validation": candidate_validation,
                "post_validation": post_validation,
                "restore_performed": True,
                "rollback_performed": False,
                "governance": _governance(),
            }
            _write_json(txn / "result.json", result)
            return result
        except Exception as exc:
            assert preimage is not None
            rollback = _rollback(target, preimage, candidate_sha, expected_current)
            try:
                _write_json(
                    txn / "result.json",
                    {
                        "schema": SCHEMA,
                        "terminal": "COS_RESTORE_HOLD",
                        "mode": MODE,
                        "reason": "POST_RESTORE_TRANSACTION_FAILED",
                        "error": f"{type(exc).__name__}: {exc}",
                        "rollback": rollback,
                        "restore_performed": True,
                        "rollback_performed": True,
                        "governance": _governance(),
                    },
                )
            except OSError:
                pass
            raise RestoreHold(
                "POST_RESTORE_TRANSACTION_FAILED_ROLLED_BACK",
                "post-switch transaction failed and byte-exact pre-image was restored",
            ) from exc
    except RestoreRollbackError:
        raise
    except RestoreHold:
        raise
    except Exception as exc:
        if switched:
            raise RestoreRollbackError(f"unexpected failure after switch: {type(exc).__name__}: {exc}") from exc
        raise RestoreHold("RESTORE_FAILED", f"restore failed closed before switch: {type(exc).__name__}") from exc
    finally:
        _cleanup(candidate)


def _receipt(terminal: str, reason: str, detail: str = "") -> dict[str, object]:
    return {
        "schema": SCHEMA,
        "terminal": terminal,
        "mode": MODE,
        "reason": reason,
        "detail": detail or reason,
        "restore_performed": False,
        "rollback_performed": False,
        "governance": _governance(),
    }


def _emit(value: Mapping[str, object], as_json: bool) -> None:
    if as_json:
        print(json.dumps(dict(value), ensure_ascii=False, sort_keys=True, separators=(",", ":")))
    else:
        print(f"{value.get('terminal')}: {value.get('reason', value.get('mode', ''))}")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m continuityos.memory_restore")
    parser.add_argument("--db", default=None)
    parser.add_argument("--backup", required=True)
    parser.add_argument("--expected-current-sha256", required=True)
    parser.add_argument("--allow-p5a-v1-compatibility", action="store_true")
    parser.add_argument("--confirm-byte-exact-replace", action="store_true")
    parser.add_argument("--json", dest="as_json", action="store_true")
    args = parser.parse_args(list(argv) if argv is not None else None)
    if not args.confirm_byte_exact_replace:
        _emit(_receipt("COS_RESTORE_HOLD", "EXPLICIT_CONFIRMATION_REQUIRED"), args.as_json)
        return 2
    try:
        resolved = resolve_memory_db(args.db)
        result = restore_quiescent_backup(
            args.backup,
            resolved["path"],
            args.expected_current_sha256,
            confirmed=True,
            allow_p5a_v1_compatibility=args.allow_p5a_v1_compatibility,
        )
    except RestoreHold as exc:
        _emit(_receipt("COS_RESTORE_HOLD", exc.reason, exc.detail), args.as_json)
        return 2
    except RestoreRollbackError as exc:
        _emit(_receipt("COS_RESTORE_REVISE", exc.reason, exc.detail), args.as_json)
        return 4
    except Exception as exc:
        _emit(_receipt("COS_RESTORE_HOLD", "MEMORY_DB_RESOLUTION_FAILED", f"{type(exc).__name__}: {exc}"), args.as_json)
        return 2
    _emit(result, args.as_json)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
