"""Fail-closed quiescent snapshots for the local ContinuityOS memory database."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import sqlite3
import tempfile
from typing import Any, Mapping, Sequence
import zipfile

from .db import resolve_memory_db

SCHEMA = "continuityos.memory_backup/v1"
MODE = "QUIESCENT_SNAPSHOT"
MEMORY_MEMBER = "memory.db"
MANIFEST_MEMBER = "manifest.json"
REQUIRED_ITEMS_COLUMNS = {
    "id",
    "namespace",
    "text",
    "tags",
    "meta",
    "vec",
    "created_at",
    "updated_at",
    "key",
    "version",
}


class BackupHold(RuntimeError):
    def __init__(self, reason: str, detail: str = ""):
        super().__init__(detail or reason)
        self.reason = reason
        self.detail = detail or reason


def _governance() -> dict[str, object]:
    return {
        "execution_authority": "NONE",
        "can_execute": False,
        "can_trade": False,
        "capital_permission": "DENY",
    }


def _backup_root() -> Path:
    return Path.home() / ".continuityos" / "backups"


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _stat_identity(path: Path) -> dict[str, int]:
    stat = path.stat()
    return {
        "size": int(stat.st_size),
        "mtime_ns": int(stat.st_mtime_ns),
        "device": int(getattr(stat, "st_dev", 0)),
        "inode": int(getattr(stat, "st_ino", 0)),
    }


def _sidecar_state(source: Path) -> dict[str, dict[str, object]]:
    result: dict[str, dict[str, object]] = {}
    for suffix in ("-wal", "-shm", "-journal"):
        path = Path(str(source) + suffix)
        if not path.exists():
            result[suffix] = {
                "exists": False,
                "size": 0,
                "sha256": None,
                "mtime_ns": None,
            }
            continue
        if not path.is_file():
            raise BackupHold(
                "SOURCE_SIDECAR_UNSAFE",
                f"sidecar is not a regular file: {suffix}",
            )
        stat = path.stat()
        result[suffix] = {
            "exists": True,
            "size": int(stat.st_size),
            "sha256": _hash_file(path),
            "mtime_ns": int(stat.st_mtime_ns),
        }
    return result


def _preflight_source(
    source: Path,
) -> tuple[dict[str, int], str, dict[str, dict[str, object]]]:
    if not source.is_file():
        raise BackupHold("SOURCE_UNAVAILABLE", "memory database is unavailable")
    sidecars = _sidecar_state(source)
    if int(sidecars["-wal"]["size"]) > 0:
        raise BackupHold(
            "SOURCE_WAL_ACTIVE",
            "memory database has a non-empty WAL",
        )
    if int(sidecars["-journal"]["size"]) > 0:
        raise BackupHold(
            "SOURCE_ROLLBACK_JOURNAL_ACTIVE",
            "memory database has a non-empty rollback journal",
        )
    identity = _stat_identity(source)
    digest = _hash_file(source)
    return identity, digest, sidecars


def _safe_backup_root() -> Path:
    root = _backup_root()
    state_dir = root.parent
    home_dir = state_dir.parent
    try:
        if home_dir.is_symlink():
            raise BackupHold("BACKUP_ROOT_UNSAFE", "home directory is a symlink")
        home_resolved = home_dir.resolve(strict=True)
        if state_dir.exists():
            if state_dir.is_symlink() or not state_dir.is_dir():
                raise BackupHold(
                    "BACKUP_ROOT_UNSAFE",
                    "state directory is not a safe directory",
                )
        else:
            state_dir.mkdir(mode=0o700)
        state_resolved = state_dir.resolve(strict=True)
        if state_resolved.parent != home_resolved:
            raise BackupHold(
                "BACKUP_ROOT_UNSAFE",
                "state directory escapes its fixed parent",
            )
        if root.exists():
            if root.is_symlink() or not root.is_dir():
                raise BackupHold(
                    "BACKUP_ROOT_UNSAFE",
                    "backup directory is not a safe directory",
                )
        else:
            root.mkdir(mode=0o700)
        root_resolved = root.resolve(strict=True)
        if root_resolved.parent != state_resolved:
            raise BackupHold(
                "BACKUP_ROOT_UNSAFE",
                "backup directory escapes the fixed state directory",
            )
        return root_resolved
    except BackupHold:
        raise
    except OSError as exc:
        raise BackupHold(
            "BACKUP_ROOT_UNSAFE",
            f"backup root setup failed: {type(exc).__name__}",
        ) from exc


def _copy_source(source: Path, destination: Path) -> None:
    with source.open("rb") as src, destination.open("xb") as dst:
        shutil.copyfileobj(src, dst, length=1024 * 1024)
        dst.flush()
        os.fsync(dst.fileno())


def _validate_sqlite_copy(path: Path) -> dict[str, object]:
    try:
        uri = path.resolve(strict=True).as_uri() + "?mode=ro&immutable=1"
        con = sqlite3.connect(uri, uri=True)
        try:
            con.execute("PRAGMA query_only=ON")
            con.execute("PRAGMA temp_store=MEMORY")
            integrity_rows = [
                str(row[0]) for row in con.execute("PRAGMA integrity_check").fetchall()
            ]
            if integrity_rows != ["ok"]:
                raise BackupHold(
                    "BACKUP_VALIDATION_FAILED",
                    "SQLite integrity_check did not return ok",
                )
            table = con.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='items'"
            ).fetchone()
            if table is None:
                raise BackupHold(
                    "BACKUP_VALIDATION_FAILED",
                    "backup has no items table",
                )
            columns = {
                str(row[1])
                for row in con.execute("PRAGMA table_info(items)").fetchall()
            }
            missing = REQUIRED_ITEMS_COLUMNS - columns
            if missing:
                raise BackupHold(
                    "BACKUP_VALIDATION_FAILED",
                    "backup items schema is missing: " + ", ".join(sorted(missing)),
                )
        finally:
            con.close()
    except BackupHold:
        raise
    except (OSError, sqlite3.Error, ValueError) as exc:
        raise BackupHold(
            "BACKUP_VALIDATION_FAILED",
            f"backup SQLite validation failed: {type(exc).__name__}",
        ) from exc
    for suffix in ("-wal", "-shm", "-journal"):
        if Path(str(path) + suffix).exists():
            raise BackupHold(
                "BACKUP_VALIDATION_FAILED",
                f"backup validation created unexpected sidecar: {suffix}",
            )
    return {
        "integrity_check": "ok",
        "required_items_columns": sorted(REQUIRED_ITEMS_COLUMNS),
    }


def _write_bundle(
    bundle_tmp: Path,
    copied_db: Path,
    manifest: Mapping[str, Any],
) -> None:
    manifest_bytes = (
        json.dumps(dict(manifest), ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    with bundle_tmp.open("xb") as raw:
        with zipfile.ZipFile(raw, mode="w", compression=zipfile.ZIP_STORED) as archive:
            archive.write(copied_db, MEMORY_MEMBER)
            archive.writestr(MANIFEST_MEMBER, manifest_bytes)
        raw.flush()
        os.fsync(raw.fileno())


def _verify_bundle(
    bundle_tmp: Path,
    expected_db_sha: str,
    expected_manifest: Mapping[str, Any],
) -> None:
    try:
        with zipfile.ZipFile(bundle_tmp, mode="r") as archive:
            if sorted(archive.namelist()) != [MANIFEST_MEMBER, MEMORY_MEMBER]:
                raise BackupHold(
                    "BACKUP_VALIDATION_FAILED",
                    "backup bundle contains unexpected members",
                )
            digest = hashlib.sha256()
            with archive.open(MEMORY_MEMBER, "r") as member:
                for chunk in iter(lambda: member.read(1024 * 1024), b""):
                    digest.update(chunk)
            if digest.hexdigest() != expected_db_sha:
                raise BackupHold(
                    "BACKUP_HASH_MISMATCH",
                    "embedded memory hash differs from source",
                )
            parsed = json.loads(archive.read(MANIFEST_MEMBER).decode("utf-8"))
            if parsed != dict(expected_manifest):
                raise BackupHold(
                    "BACKUP_VALIDATION_FAILED",
                    "embedded manifest readback mismatch",
                )
    except BackupHold:
        raise
    except (
        OSError,
        zipfile.BadZipFile,
        KeyError,
        UnicodeDecodeError,
        json.JSONDecodeError,
    ) as exc:
        raise BackupHold(
            "BACKUP_VALIDATION_FAILED",
            f"backup bundle validation failed: {type(exc).__name__}",
        ) from exc


def _cleanup_path(path: Path) -> None:
    try:
        if path.is_dir() and not path.is_symlink():
            shutil.rmtree(path)
        else:
            path.unlink()
    except FileNotFoundError:
        pass
    except OSError:
        pass


def create_quiescent_backup(source_path: str | Path) -> dict[str, object]:
    if str(source_path) == ":memory:":
        raise BackupHold(
            "IN_MEMORY_SOURCE_UNSUPPORTED",
            "an in-memory database cannot be backed up",
        )
    try:
        source = Path(source_path).expanduser().resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise BackupHold(
            "SOURCE_UNAVAILABLE",
            "memory database is unavailable",
        ) from exc
    if not source.is_file():
        raise BackupHold(
            "SOURCE_NOT_REGULAR_FILE",
            "memory database is not a regular file",
        )

    pre_identity, pre_sha, pre_sidecars = _preflight_source(source)
    root = _safe_backup_root()
    staging = Path(
        tempfile.mkdtemp(prefix=".p5a-memory-backup-", dir=str(root))
    )
    copied = staging / MEMORY_MEMBER
    bundle_tmp = root / (
        ".p5a-memory-backup-" + secrets.token_hex(12) + ".tmp"
    )
    published: Path | None = None
    try:
        _copy_source(source, copied)
        copied_sha = _hash_file(copied)
        if copied_sha != pre_sha:
            raise BackupHold(
                "BACKUP_HASH_MISMATCH",
                "copied memory hash differs from source preflight",
            )
        validation = _validate_sqlite_copy(copied)

        post_identity = _stat_identity(source)
        post_sha = _hash_file(source)
        post_sidecars = _sidecar_state(source)
        if post_identity != pre_identity or post_sha != pre_sha:
            raise BackupHold(
                "SOURCE_CHANGED_DURING_BACKUP",
                "memory database changed during backup",
            )
        if post_sidecars != pre_sidecars:
            raise BackupHold(
                "SIDECAR_CHANGED_DURING_BACKUP",
                "memory sidecar state changed during backup",
            )

        created_at = datetime.now(timezone.utc).isoformat()
        token = secrets.token_hex(4)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        final_name = f"memory-{stamp}-{pre_sha[:12]}-{token}.cosbackup"
        final_path = root / final_name
        manifest: dict[str, object] = {
            "schema": SCHEMA,
            "terminal": "COS_BACKUP_PASS",
            "mode": MODE,
            "created_at": created_at,
            "source": {
                "filename": source.name,
                "path_sha256": _sha256_bytes(str(source).encode("utf-8")),
                "sha256": pre_sha,
                "size_bytes": pre_identity["size"],
                "sidecars_pre": pre_sidecars,
                "sidecars_post": post_sidecars,
            },
            "backup": {
                "bundle_filename": final_name,
                "memory_member": MEMORY_MEMBER,
                "manifest_member": MANIFEST_MEMBER,
                "memory_sha256": copied_sha,
                "memory_size_bytes": copied.stat().st_size,
                "integrity_check": validation["integrity_check"],
                "required_items_columns": validation["required_items_columns"],
                "restore_available": False,
            },
            "governance": _governance(),
        }
        _write_bundle(bundle_tmp, copied, manifest)
        _verify_bundle(bundle_tmp, pre_sha, manifest)
        try:
            os.link(bundle_tmp, final_path)
        except FileExistsError as exc:
            raise BackupHold(
                "BACKUP_NAME_COLLISION",
                "backup bundle name already exists",
            ) from exc
        except OSError as exc:
            raise BackupHold(
                "ATOMIC_PUBLISH_UNAVAILABLE",
                f"atomic non-overwrite publish failed: {type(exc).__name__}",
            ) from exc
        published = final_path
        if _hash_file(published) != _hash_file(bundle_tmp):
            raise BackupHold(
                "BACKUP_VALIDATION_FAILED",
                "published bundle readback mismatch",
            )
        return {
            **manifest,
            "backup_path": str(published),
            "bundle_sha256": _hash_file(published),
        }
    except BackupHold:
        if published is not None:
            _cleanup_path(published)
        raise
    except Exception as exc:
        if published is not None:
            _cleanup_path(published)
        raise BackupHold(
            "BACKUP_FAILED",
            f"backup failed closed: {type(exc).__name__}",
        ) from exc
    finally:
        _cleanup_path(bundle_tmp)
        _cleanup_path(staging)


def _hold_receipt(reason: str, detail: str = "") -> dict[str, object]:
    return {
        "schema": SCHEMA,
        "terminal": "COS_BACKUP_HOLD",
        "mode": MODE,
        "reason": reason,
        "detail": detail or reason,
        "governance": _governance(),
    }


def _emit(receipt: Mapping[str, object], as_json: bool) -> None:
    if as_json:
        print(
            json.dumps(
                dict(receipt),
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return
    print(
        f"{receipt.get('terminal')}: "
        f"{receipt.get('reason', receipt.get('mode', ''))}"
    )
    if receipt.get("backup_path"):
        print(f"backup: {receipt['backup_path']}")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="cos backup",
        description=(
            "Create one local quiescent snapshot of the resolved "
            "ContinuityOS memory database."
        ),
    )
    parser.add_argument("--db", default=None)
    parser.add_argument("--json", dest="as_json", action="store_true")
    args = parser.parse_args(list(argv) if argv is not None else None)
    try:
        resolved = resolve_memory_db(args.db)
    except Exception as exc:
        receipt = _hold_receipt(
            "MEMORY_DB_RESOLUTION_FAILED",
            f"{type(exc).__name__}: {exc}",
        )
        _emit(receipt, args.as_json)
        return 2
    try:
        receipt = create_quiescent_backup(resolved["path"])
    except BackupHold as exc:
        receipt = _hold_receipt(exc.reason, exc.detail)
        _emit(receipt, args.as_json)
        return 2
    _emit(receipt, args.as_json)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
