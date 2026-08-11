"""Best-effort local rollback with explicit, verifiable outcomes.

The module snapshots files, directories, symlinks, and the absence of a target.
SQLite files use the backup API so WAL-backed committed state is included. It still
cannot reverse external side effects or close the preflight-to-execution TOCTOU gap.
"""
from __future__ import annotations

import hashlib
import glob
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import tempfile
import time
from typing import Any, Dict, List

SNAP_ROOT = os.path.expanduser("~/.continuityos/snapshots")
_SID = re.compile(r"^[0-9a-f]{16}$")


def _sha256(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _is_sqlite(path: str) -> bool:
    try:
        with open(path, "rb") as f:
            return f.read(16) == b"SQLite format 3\x00"
    except OSError:
        return False


def _sqlite_backup(source: str, target: str) -> None:
    src = sqlite3.connect(Path(source).resolve().as_uri() + "?mode=ro", uri=True)
    dst = sqlite3.connect(target)
    try:
        src.backup(dst)
    finally:
        dst.close()
        src.close()
    shutil.copystat(source, target)


def snapshot(paths: List[str], allow_missing_files: bool = False) -> Dict[str, Any]:
    raw_paths = list(paths or [])
    if any(glob.has_magic(path) for path in raw_paths):
        raise ValueError("snapshot targets must be materialized paths, not globs")
    requested = list(dict.fromkeys(os.path.abspath(os.path.expanduser(p)) for p in raw_paths))
    sid = hashlib.sha256(
        (f"{time.time_ns()}|{os.getpid()}|" + "\0".join(requested)).encode("utf-8")
    ).hexdigest()[:16]
    directory = os.path.join(SNAP_ROOT, sid)
    os.makedirs(directory, exist_ok=False)

    items: List[Dict[str, Any]] = []
    errors: List[Dict[str, str]] = []
    saved = 0
    for index, original in enumerate(requested):
        item: Dict[str, Any] = {"original": original}
        try:
            if os.path.islink(original):
                raise OSError("symlink rollback is not supported in v1")
            elif os.path.isdir(original):
                raise OSError("directory rollback is not supported in v1")
            elif os.path.isfile(original):
                target = os.path.join(directory, f"{index}_file")
                kind = "sqlite" if _is_sqlite(original) else "file"
                if kind == "sqlite":
                    _sqlite_backup(original, target)
                else:
                    shutil.copy2(original, target)
                item.update({"kind": kind, "snapshot": target, "sha256": _sha256(target)})
                saved += 1
            elif not os.path.lexists(original):
                if not allow_missing_files:
                    raise OSError("missing target type is not bound as a supported file")
                # Restoring this state means deleting a regular file created later.
                item.update({"kind": "missing_file"})
            else:
                raise OSError("unsupported filesystem object")
            items.append(item)
        except Exception as exc:
            errors.append({"path": original, "error": f"{type(exc).__name__}: {exc}"})

    manifest = {
        "version": 1,
        "id": sid,
        "ts": time.time(),
        "items": items,
        "errors": errors,
    }
    manifest_path = os.path.join(directory, "manifest.json")
    temp_path = manifest_path + ".tmp"
    with open(temp_path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(manifest, f, ensure_ascii=False, indent=2, sort_keys=True)
        f.flush()
        os.fsync(f.fileno())
    os.replace(temp_path, manifest_path)
    restorable = bool(requested) and len(items) == len(requested) and not errors
    return {"id": sid, "saved": saved, "restorable": restorable, "errors": errors}


def _snapshot_path(directory: str, value: str) -> str:
    path = os.path.realpath(value)
    if os.path.commonpath((path, os.path.realpath(directory))) != os.path.realpath(directory):
        raise ValueError("snapshot payload escapes its snapshot directory")
    return path


def _atomic_restore_file(source: str, original: str, expected: str = "", sqlite: bool = False) -> None:
    parent = os.path.dirname(original)
    os.makedirs(parent, exist_ok=True)
    if os.path.isdir(original) and not os.path.islink(original):
        raise OSError("refusing to replace a directory with a file")
    fd, staged = tempfile.mkstemp(prefix=".continuity-restore-", dir=parent)
    os.close(fd)
    sidecars: List[tuple[str, str]] = []
    replaced = False
    try:
        shutil.copy2(source, staged)
        if expected and _sha256(staged) != expected:
            raise ValueError("snapshot checksum mismatch")
        if sqlite:
            # A stale WAL can replay over a restored main DB. Move sidecars out of
            # the way before the atomic replacement; fail without touching the DB
            # if the platform cannot move an active sidecar.
            for suffix in ("-wal", "-shm"):
                sidecar = original + suffix
                if os.path.lexists(sidecar):
                    parked = staged + suffix
                    os.replace(sidecar, parked)
                    sidecars.append((sidecar, parked))
        os.replace(staged, original)
        replaced = True
        for _, parked in sidecars:
            if os.path.lexists(parked):
                os.unlink(parked)
    except Exception:
        if not replaced:
            for sidecar, parked in reversed(sidecars):
                if os.path.lexists(parked) and not os.path.lexists(sidecar):
                    os.replace(parked, sidecar)
        raise
    finally:
        if os.path.lexists(staged):
            os.unlink(staged)


def restore(sid: str) -> Dict[str, Any]:
    if not _SID.fullmatch(sid or ""):
        return {"ok": False, "error": "invalid snapshot id", "id": sid}
    directory = os.path.realpath(os.path.join(SNAP_ROOT, sid))
    try:
        if os.path.commonpath((directory, os.path.realpath(SNAP_ROOT))) != os.path.realpath(SNAP_ROOT):
            return {"ok": False, "error": "invalid snapshot path", "id": sid}
    except ValueError:
        return {"ok": False, "error": "invalid snapshot path", "id": sid}
    manifest_path = os.path.join(directory, "manifest.json")
    if not os.path.isfile(manifest_path):
        return {"ok": False, "error": "snapshot not found", "id": sid}

    try:
        with open(manifest_path, "r", encoding="utf-8") as f:
            manifest = json.load(f)
    except Exception as exc:
        return {"ok": False, "error": f"invalid manifest: {exc}", "id": sid}

    # Read pre-v1 manifests so existing snapshots remain usable.
    items = manifest.get("items")
    if items is None:
        items = [
            {"kind": "file", "original": item["orig"], "snapshot": item["snap"]}
            for item in manifest.get("files", [])
        ]

    if not isinstance(items, list) or not items:
        return {"ok": False, "error": "manifest contains no restorable items", "id": sid}

    restored = 0
    errors: List[Dict[str, str]] = []
    for item in items:
        raw_original = item.get("original")
        if not isinstance(raw_original, str) or not raw_original:
            errors.append({"path": "", "error": "manifest item has no original path"})
            continue
        if not os.path.isabs(os.path.expanduser(raw_original)):
            errors.append({"path": raw_original, "error": "manifest original path must be absolute"})
            continue
        original = os.path.abspath(os.path.expanduser(raw_original))
        kind = item.get("kind")
        try:
            if kind == "missing_file":
                if os.path.isdir(original) and not os.path.islink(original):
                    raise OSError("refusing to remove a created directory in v1 rollback")
                if os.path.lexists(original):
                    os.unlink(original)
            elif kind in ("file", "sqlite"):
                source = _snapshot_path(directory, item["snapshot"])
                expected = item.get("sha256")
                if expected and _sha256(source) != expected:
                    raise ValueError("snapshot checksum mismatch")
                _atomic_restore_file(source, original, expected or "", sqlite=(kind == "sqlite"))
            else:
                raise ValueError(f"unsupported manifest kind: {kind!r}")
            restored += 1
        except Exception as exc:
            errors.append({"path": original, "error": f"{type(exc).__name__}: {exc}"})
    return {"ok": not errors, "restored": restored, "errors": errors, "id": sid}
