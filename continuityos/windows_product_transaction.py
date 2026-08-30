"""Windows product transaction primitives for Sovereign Twin P1.

P1A/P1B expose read-only staging and immutable payload validation. P1C adds one
bounded write path for an *existing* valid runtime-source/v3 binding: atomically
switch that pointer to a staged runtime, prove the new binding from a fresh
packaged process, and restore the previous pointer byte-for-byte on any
post-switch failure. Memory is never mutated by this module.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import sys
import time
import uuid
from typing import Any, Iterable

RUNTIME_PACKAGE_SCHEMA = "sovereign-twin.runtime-package/v1"
RUNTIME_SOURCE_SCHEMA = "sovereign-twin.windows-runtime-source/v3"
RUNTIME_MODULE_REL = Path("Lib") / "site-packages" / "continuityos" / "sovereign_twin_runtime.py"
LAUNCHER_REL = Path("Scripts") / "sovereign-twin.exe"
PACKAGE_MANIFEST = "runtime-package.json"
SUMS_FILE = "SHA256SUMS"
TREE_EXCLUDES = frozenset({PACKAGE_MANIFEST, SUMS_FILE})
SQLITE_AUX_SUFFIXES = ("-wal", "-shm", "-journal")
TRANSACTION_SCHEMA = "sovereign-twin.windows-product-transaction/v1"
POSTBIND_SCHEMA = "sovereign-twin.windows-product-postbind/v1"
ROLLBACK_SCHEMA = "sovereign-twin.windows-product-rollback/v1"

RUNTIME_SOURCE_FIELDS = (
    "schema",
    "repository",
    "source_sha",
    "installed_at_utc",
    "python",
    "twin_executable",
    "memory_db",
    "admission_queue",
    "llm_server",
    "ui",
    "fast_model",
    "deep_model",
    "embedding_model",
    "execution_authority",
    "can_execute",
    "memory_activated_at_utc",
    "memory_manifest",
    "memory_embedding_dimension",
)
RUNTIME_SOURCE_STRING_FIELDS = tuple(
    field for field in RUNTIME_SOURCE_FIELDS
    if field not in {"can_execute", "memory_embedding_dimension"}
)
EXPECTED_EMBEDDING_CONTRACT = {
    "document_task_prefix": "search_document",
    "query_task_prefix": "search_query",
}
_LOOPBACK_RE = re.compile(r"^https?://(?:127\.0\.0\.1|localhost):([0-9]+)(?:/)?$")


def _norm_rel(path: Path) -> str:
    return path.as_posix()


def _sha256_file_windows_shared(path: Path) -> str:
    """Hash a Windows file while coexisting with SQLite's live shared handles."""
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create_file = kernel32.CreateFileW
    create_file.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    )
    create_file.restype = wintypes.HANDLE
    read_file = kernel32.ReadFile
    read_file.argtypes = (
        wintypes.HANDLE,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        wintypes.LPVOID,
    )
    read_file.restype = wintypes.BOOL
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = (wintypes.HANDLE,)
    close_handle.restype = wintypes.BOOL

    GENERIC_READ = 0x80000000
    FILE_SHARE_READ = 0x00000001
    FILE_SHARE_WRITE = 0x00000002
    FILE_SHARE_DELETE = 0x00000004
    OPEN_EXISTING = 3
    FILE_ATTRIBUTE_NORMAL = 0x00000080
    FILE_FLAG_SEQUENTIAL_SCAN = 0x08000000
    invalid_handle = ctypes.c_void_p(-1).value

    handle = create_file(
        str(path),
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        None,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
        None,
    )
    if handle in (None, invalid_handle):
        err = ctypes.get_last_error()
        raise OSError(err, f"CreateFileW shared-read failed for {path}")

    h = hashlib.sha256()
    buf = ctypes.create_string_buffer(1024 * 1024)
    got = wintypes.DWORD(0)
    try:
        while True:
            if not read_file(handle, buf, len(buf), ctypes.byref(got), None):
                err = ctypes.get_last_error()
                raise OSError(err, f"ReadFile shared-read failed for {path}")
            if got.value == 0:
                break
            h.update(buf.raw[: got.value])
    finally:
        close_handle(handle)
    return h.hexdigest()


def sha256_file(path: str | os.PathLike[str]) -> str:
    resolved = Path(path)
    if os.name == "nt":
        return _sha256_file_windows_shared(resolved)
    h = hashlib.sha256()
    with open(resolved, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def iter_payload_files(root: str | os.PathLike[str]) -> Iterable[Path]:
    base = Path(root).resolve()
    for path in sorted(base.rglob("*"), key=lambda p: _norm_rel(p.relative_to(base))):
        if path.is_symlink():
            raise ValueError(f"runtime payload contains symlink: {path}")
        if not path.is_file():
            continue
        rel = _norm_rel(path.relative_to(base))
        if rel in TREE_EXCLUDES:
            continue
        yield path


def canonical_tree_lines(root: str | os.PathLike[str]) -> list[str]:
    base = Path(root).resolve()
    return [
        f"{sha256_file(path)}  {path.stat().st_size}  {_norm_rel(path.relative_to(base))}"
        for path in iter_payload_files(base)
    ]


def canonical_tree_sha256(root: str | os.PathLike[str]) -> str:
    data = ("\n".join(canonical_tree_lines(root)) + "\n").encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def _reject_duplicate_object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise ValueError(f"duplicate JSON key: {key}")
        out[key] = value
    return out


def _load_json(path: Path) -> dict[str, Any]:
    raw = path.read_text(encoding="utf-8-sig")
    value = json.loads(raw, object_pairs_hook=_reject_duplicate_object_pairs)
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def _require_sha256(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be SHA-256 hex string")
    text = value.lower()
    if len(text) != 64 or any(c not in "0123456789abcdef" for c in text):
        raise ValueError(f"{field} must be SHA-256 hex")
    return text


def _require_source_sha(value: Any) -> str:
    if not isinstance(value, str):
        raise ValueError("source_sha must be exact 40-character Git SHA string")
    if len(value) != 40 or any(c not in "0123456789abcdefABCDEF" for c in value):
        raise ValueError("source_sha must be exact 40-character Git SHA")
    return value


def _require_none_false(obj: dict[str, Any], context: str) -> None:
    if obj.get("execution_authority") != "NONE":
        raise ValueError(f"{context} execution_authority must be NONE")
    if obj.get("can_execute") is not False:
        raise ValueError(f"{context} can_execute must be false")


def _full_path(value: Any, field: str) -> Path:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} missing")
    return Path(value).expanduser().resolve()


def _require_exact_runtime_source_shape(pointer: dict[str, Any]) -> None:
    expected = set(RUNTIME_SOURCE_FIELDS)
    actual = set(pointer)
    missing = sorted(expected - actual)
    unexpected = sorted(actual - expected)
    if missing or unexpected:
        detail: list[str] = []
        if missing:
            detail.append("missing=" + ",".join(missing))
        if unexpected:
            detail.append("unexpected=" + ",".join(unexpected))
        raise ValueError(
            "live runtime-source must contain exactly 18 v3 fields: " + " ".join(detail)
        )
    for field in RUNTIME_SOURCE_STRING_FIELDS:
        value = pointer[field]
        if not isinstance(value, str) or not value:
            raise ValueError(f"live runtime-source {field} must be a non-empty JSON string")
    if pointer["can_execute"] is not False:
        raise ValueError("live runtime-source can_execute must be false")
    dimension = pointer["memory_embedding_dimension"]
    if not isinstance(dimension, int) or isinstance(dimension, bool) or dimension <= 0:
        raise ValueError("live runtime-source memory_embedding_dimension invalid")


def _require_loopback_url(value: str, field: str) -> int:
    match = _LOOPBACK_RE.fullmatch(value)
    if match is None:
        raise ValueError(
            f"live runtime-source {field} must be exact loopback http(s) URL with port"
        )
    port = int(match.group(1))
    if port <= 0 or port > 65535:
        raise ValueError(f"live runtime-source {field} port invalid")
    return port


def _same_runtime_root(python_exe: Path, twin_exe: Path) -> bool:
    python_root = python_exe.parent
    twin_root = twin_exe.parent.parent
    return str(python_root).casefold() == str(twin_root).casefold()


def _fingerprint_file(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"present": False}
    if not path.is_file():
        raise ValueError(f"expected file for fingerprint: {path}")
    st = path.stat()
    return {
        "present": True,
        "size": int(st.st_size),
        "mtime_ns": int(st.st_mtime_ns),
        "sha256": sha256_file(path),
    }


def _sqlite_physical_fingerprints(path: Path) -> dict[str, dict[str, Any]]:
    paths = [path, *(Path(str(path) + suffix) for suffix in SQLITE_AUX_SUFFIXES)]
    return {str(p): _fingerprint_file(p) for p in paths}


def sqlite_physical_fingerprints(path: str | os.PathLike[str]) -> dict[str, dict[str, Any]]:
    return _sqlite_physical_fingerprints(Path(path).resolve())


def _reject_pending_sqlite_state(before: dict[str, dict[str, Any]], path: Path) -> None:
    for suffix in ("-wal", "-journal"):
        fp = before[str(Path(str(path) + suffix))]
        if fp.get("present") and int(fp.get("size") or 0) > 0:
            raise ValueError(
                f"zero-write memory preflight refuses pending SQLite {suffix} content; "
                "quiesce/checkpoint the memory DB first"
            )


def _sqlite_memory_audit_zero_write(path: Path, dimension: int) -> dict[str, Any]:
    before = _sqlite_physical_fingerprints(path)
    _reject_pending_sqlite_state(before, path)

    uri = path.as_uri() + "?mode=ro&immutable=1"
    con = sqlite3.connect(uri, uri=True, timeout=5.0)
    try:
        con.execute("PRAGMA query_only=ON")
        row = con.execute("PRAGMA quick_check").fetchone()
        quick = str(row[0]) if row else ""
        if quick.lower() != "ok":
            raise ValueError(f"live memory quick_check failed: {quick}")
        items = con.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='items'"
        ).fetchone()
        if items is None:
            raise ValueError("live memory items table missing")
        expected_bytes = dimension * 4
        row = con.execute(
            """
            SELECT
                COUNT(*) AS item_count,
                SUM(CASE WHEN vec IS NOT NULL THEN 1 ELSE 0 END) AS vector_count,
                SUM(CASE WHEN vec IS NULL THEN 1 ELSE 0 END) AS vectorless_count,
                SUM(
                    CASE
                        WHEN vec IS NOT NULL
                         AND (typeof(vec) <> 'blob' OR length(vec) <> ?)
                        THEN 1 ELSE 0
                    END
                ) AS bad_vector_count
            FROM items
            """,
            (expected_bytes,),
        ).fetchone()
        assert row is not None
        item_count = int(row[0] or 0)
        vector_count = int(row[1] or 0)
        vectorless_count = int(row[2] or 0)
        bad_vector_count = int(row[3] or 0)
        if bad_vector_count:
            raise ValueError(
                "live memory vector width/type mismatch: "
                f"{bad_vector_count} row(s) are not {expected_bytes}-byte float32 blobs"
            )
    finally:
        con.close()

    after = _sqlite_physical_fingerprints(path)
    if after != before:
        raise ValueError("SQLite physical files changed during zero-write preflight")
    return {
        "memory_quick_check": quick,
        "item_count": item_count,
        "vector_count": vector_count,
        "vectorless_count": vectorless_count,
        "bad_vector_count": bad_vector_count,
        "expected_vector_bytes": expected_bytes,
        "sqlite_open_mode": "mode=ro&immutable=1",
        "sqlite_physical_fingerprints": before,
        "sqlite_physical_files_unchanged": True,
    }


def _validate_memory_manifest(
    manifest_path: Path,
    memory_db: Path,
    embedding_model: str,
    dimension: int,
) -> dict[str, Any]:
    manifest = _load_json(manifest_path)
    manifest_db = _full_path(manifest.get("db"), "memory manifest db")
    if manifest_db != memory_db:
        raise ValueError("memory manifest db path does not bind live memory_db")
    if manifest.get("embedding_model") != embedding_model:
        raise ValueError("memory manifest embedding_model does not bind live embedding_model")
    manifest_dimension = manifest.get("embedding_dimension")
    if (
        not isinstance(manifest_dimension, int)
        or isinstance(manifest_dimension, bool)
        or manifest_dimension != dimension
    ):
        raise ValueError(
            "memory manifest embedding_dimension does not bind live memory_embedding_dimension"
        )
    if manifest.get("embedding_contract") != EXPECTED_EMBEDDING_CONTRACT:
        raise ValueError(
            "memory manifest embedding_contract does not bind Nomic task-prefix contract"
        )
    return {
        "path": str(manifest_path),
        "sha256": sha256_file(manifest_path),
        "schema": manifest.get("schema"),
        "db": str(manifest_db),
        "embedding_model": embedding_model,
        "embedding_dimension": dimension,
        "embedding_contract": dict(EXPECTED_EMBEDDING_CONTRACT),
        "bound": True,
    }


def _expected_sums_text(root: Path) -> str:
    return "\n".join(canonical_tree_lines(root)) + "\n"


def validate_runtime_package(runtime_root: str | os.PathLike[str]) -> dict[str, Any]:
    root = Path(runtime_root).resolve()
    if not root.is_dir():
        raise ValueError(f"runtime root missing: {root}")

    manifest_path = root / PACKAGE_MANIFEST
    sums_path = root / SUMS_FILE
    if not manifest_path.is_file():
        raise ValueError(f"runtime package manifest missing: {manifest_path}")
    if not sums_path.is_file():
        raise ValueError(f"runtime package SHA256SUMS missing: {sums_path}")
    package = _load_json(manifest_path)

    if package.get("schema") != RUNTIME_PACKAGE_SCHEMA:
        raise ValueError("runtime package schema mismatch")
    _require_none_false(package, "runtime package")
    _require_source_sha(package.get("source_sha"))

    build_id = str(package.get("build_id") or "")
    if not build_id or build_id != root.name:
        raise ValueError("runtime package build_id must equal runtime directory name")
    if package.get("architecture") != "win-x64":
        raise ValueError("P1A supports only win-x64 runtime packages")

    supported = package.get("runtime_source_schema_supported")
    if not isinstance(supported, list) or RUNTIME_SOURCE_SCHEMA not in supported:
        raise ValueError("runtime package does not support runtime-source/v3")
    dims = package.get("memory_embedding_dimensions_supported")
    if not isinstance(dims, list) or not dims or not all(
        isinstance(x, int) and not isinstance(x, bool) and x > 0 for x in dims
    ):
        raise ValueError("runtime package has invalid embedding dimension support list")

    python_exe = root / "python.exe"
    python_dlls = list(root.glob("python3*.dll"))
    launcher = root / LAUNCHER_REL
    runtime_module = root / RUNTIME_MODULE_REL
    for required in (python_exe, launcher, runtime_module):
        if not required.is_file():
            raise ValueError(f"runtime package required file missing: {required}")
    if not python_dlls:
        raise ValueError("runtime package Python DLL missing")

    path_config = package.get("python_path_config")
    if path_config is not None:
        if (
            not isinstance(path_config, str)
            or not path_config
            or Path(path_config).name != path_config
        ):
            raise ValueError("runtime package python_path_config invalid")
        pth = root / path_config
        if not pth.is_file():
            raise ValueError("runtime package python_path_config missing")
        pth_lines = {
            line.strip().lower().replace("/", "\\")
            for line in pth.read_text(encoding="utf-8-sig").splitlines()
        }
        if "lib\\site-packages" not in pth_lines or "import site" not in pth_lines:
            raise ValueError(
                "runtime package python_path_config does not enable bundled site-packages"
            )

    launcher_sha = sha256_file(launcher)
    module_sha = sha256_file(runtime_module)
    tree_sha = canonical_tree_sha256(root)
    if launcher_sha != _require_sha256(package.get("launcher_sha256"), "launcher_sha256"):
        raise ValueError("runtime package launcher SHA mismatch")
    if module_sha != _require_sha256(
        package.get("runtime_module_sha256"), "runtime_module_sha256"
    ):
        raise ValueError("runtime package module SHA mismatch")
    if tree_sha != _require_sha256(package.get("runtime_tree_sha256"), "runtime_tree_sha256"):
        raise ValueError("runtime package tree SHA mismatch")

    expected_sums = _expected_sums_text(root).encode("utf-8")
    actual_sums = sums_path.read_bytes()
    if actual_sums != expected_sums:
        raise ValueError("runtime package SHA256SUMS content mismatch")

    return {
        "ok": True,
        "schema": package["schema"],
        "runtime_root": str(root),
        "build_id": build_id,
        "package_version": str(package.get("package_version") or ""),
        "source_sha": package["source_sha"],
        "architecture": package["architecture"],
        "python": str(python_exe),
        "launcher": str(launcher),
        "runtime_module": str(runtime_module),
        "runtime_tree_sha256": tree_sha,
        "sha256sums_sha256": hashlib.sha256(actual_sums).hexdigest(),
        "launcher_sha256": launcher_sha,
        "runtime_module_sha256": module_sha,
        "memory_embedding_dimensions_supported": dims,
        "execution_authority": "NONE",
        "can_execute": False,
    }


def validate_live_pointer(pointer_path: str | os.PathLike[str]) -> dict[str, Any]:
    path = Path(pointer_path).resolve()
    if not path.exists():
        return {"present": False, "path": str(path)}

    pointer = _load_json(path)
    _require_exact_runtime_source_shape(pointer)
    if pointer["schema"] != RUNTIME_SOURCE_SCHEMA:
        raise ValueError("live runtime-source schema mismatch")
    _require_none_false(pointer, "live runtime-source")
    _require_source_sha(pointer["source_sha"])
    _require_loopback_url(pointer["llm_server"], "llm_server")
    _require_loopback_url(pointer["ui"], "ui")

    python_exe = _full_path(pointer["python"], "python")
    twin_exe = _full_path(pointer["twin_executable"], "twin_executable")
    memory_db = _full_path(pointer["memory_db"], "memory_db")
    memory_manifest = _full_path(pointer["memory_manifest"], "memory_manifest")
    for field, required_path in (
        ("python", python_exe),
        ("twin_executable", twin_exe),
        ("memory_db", memory_db),
        ("memory_manifest", memory_manifest),
    ):
        if not required_path.is_file():
            raise ValueError(
                f"live runtime-source {field} missing on disk: {required_path}"
            )

    if python_exe.name.casefold() != "python.exe":
        raise ValueError("live runtime-source python basename must be python.exe")
    if twin_exe.name.casefold() != "sovereign-twin.exe":
        raise ValueError(
            "live runtime-source twin_executable basename must be sovereign-twin.exe"
        )
    if not _same_runtime_root(python_exe, twin_exe):
        raise ValueError(
            "live runtime-source python and twin_executable must bind the same runtime root"
        )

    dimension = pointer["memory_embedding_dimension"]
    memory_audit = _sqlite_memory_audit_zero_write(memory_db, dimension)
    manifest_binding = _validate_memory_manifest(
        memory_manifest,
        memory_db,
        pointer["embedding_model"],
        dimension,
    )
    return {
        "present": True,
        "path": str(path),
        "sha256": sha256_file(path),
        "source_sha": pointer["source_sha"],
        "python": str(python_exe),
        "twin_executable": str(twin_exe),
        "memory_db": str(memory_db),
        "memory_db_sha256": sha256_file(memory_db),
        "memory_manifest": str(memory_manifest),
        "memory_manifest_binding": manifest_binding,
        "memory_manifest_bound": True,
        "memory_embedding_dimension": dimension,
        **memory_audit,
        "execution_authority": "NONE",
        "can_execute": False,
    }


def stage_validate(
    runtime_root: str | os.PathLike[str],
    pointer_path: str | os.PathLike[str],
) -> dict[str, Any]:
    package = validate_runtime_package(runtime_root)
    live = validate_live_pointer(pointer_path)
    if live.get("present"):
        active_twin = Path(str(live["twin_executable"])).resolve()
        staged_root = Path(runtime_root).resolve()
        try:
            active_twin.relative_to(staged_root)
        except ValueError:
            pass
        else:
            raise ValueError("staged runtime is already referenced by the active pointer")
        dim = live["memory_embedding_dimension"]
        if dim not in package["memory_embedding_dimensions_supported"]:
            raise ValueError(
                "staged runtime does not declare support for active memory embedding dimension"
            )
    return {
        "schema": "sovereign-twin.windows-product-stage-validation/v1",
        "ok": True,
        "effect": "READ_ONLY_ZERO_EXTERNAL_EFFECTS",
        "runtime_package": package,
        "live": live,
        "activation_performed": False,
        "pointer_switch_performed": False,
        "memory_mutated": False,
        "execution_authority": "NONE",
        "can_execute": False,
    }


def _pointer_bytes(obj: dict[str, Any]) -> bytes:
    _require_exact_runtime_source_shape(obj)
    _require_none_false(obj, "candidate runtime-source")
    return (
        json.dumps(
            {field: obj[field] for field in RUNTIME_SOURCE_FIELDS},
            ensure_ascii=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")


def _candidate_pointer(
    live_pointer: dict[str, Any],
    package: dict[str, Any],
    runtime_root: Path,
) -> dict[str, Any]:
    candidate = dict(live_pointer)
    candidate["source_sha"] = package["source_sha"]
    candidate["installed_at_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    candidate["python"] = str((runtime_root / "python.exe").resolve())
    candidate["twin_executable"] = str((runtime_root / LAUNCHER_REL).resolve())
    candidate["execution_authority"] = "NONE"
    candidate["can_execute"] = False
    _require_exact_runtime_source_shape(candidate)
    return candidate


def _write_exclusive_fsync(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "xb") as fh:
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())


def _write_temp_fsync(target: Path, data: bytes) -> Path:
    target.parent.mkdir(parents=True, exist_ok=True)
    temp = target.parent / f".{target.name}.p1c-{uuid.uuid4().hex}.tmp"
    with open(temp, "xb") as fh:
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())
    return temp


def _replace_file_atomic(temp: Path, target: Path) -> None:
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes

        MOVEFILE_REPLACE_EXISTING = 0x1
        MOVEFILE_WRITE_THROUGH = 0x8
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        move = kernel32.MoveFileExW
        move.argtypes = (wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD)
        move.restype = wintypes.BOOL
        ok = move(
            str(temp),
            str(target),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
        if not ok:
            err = ctypes.get_last_error()
            raise OSError(err, f"MoveFileExW atomic pointer replace failed: {target}")
    else:
        os.replace(temp, target)
        try:
            fd = os.open(str(target.parent), os.O_RDONLY)
        except OSError:
            return
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def _atomic_write_bytes(target: Path, data: bytes) -> None:
    temp = _write_temp_fsync(target, data)
    try:
        _replace_file_atomic(temp, target)
    finally:
        if temp.exists():
            temp.unlink()


def _memory_state_from_live(live: dict[str, Any]) -> dict[str, Any]:
    return {
        "memory_db": live["memory_db"],
        "memory_db_sha256": live["memory_db_sha256"],
        "sqlite_physical_fingerprints": live["sqlite_physical_fingerprints"],
        "memory_manifest": live["memory_manifest"],
        "memory_manifest_sha256": live["memory_manifest_binding"]["sha256"],
    }


def _transaction_memory_state_for_compare(state: dict[str, Any]) -> dict[str, Any]:
    """Normalize only SQLite's volatile WAL shared-memory state for cross-process compare."""
    comparable = dict(state)
    physical = dict(comparable["sqlite_physical_fingerprints"])
    shm_path = str(Path(str(comparable["memory_db"]) + "-shm"))
    physical.pop(shm_path, None)
    comparable["sqlite_physical_fingerprints"] = physical
    return comparable


def _assert_memory_state_unchanged(before: dict[str, Any], after: dict[str, Any]) -> None:
    # A read-only SQLite process may create/update -shm WAL coordination state.
    # Keep -shm in receipts and each zero-write open audit, but do not treat that
    # cross-process coordination churn as logical memory mutation. DB, WAL,
    # journal, manifest and their content fingerprints remain exact invariants.
    after_state = _memory_state_from_live(after)
    if _transaction_memory_state_for_compare(after_state) != _transaction_memory_state_for_compare(before):
        raise ValueError("memory physical state changed during runtime pointer transaction")


def _run_starter_status(starter: Path, *, timeout: float = 30.0) -> dict[str, Any]:
    if not starter.is_file():
        raise ValueError(f"stable starter missing: {starter}")
    proc = subprocess.run(
        [str(starter), "--status"],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    stdout = proc.stdout.strip()
    stderr = proc.stderr.strip()
    if proc.returncode != 0:
        raise ValueError(
            f"stable starter --status failed rc={proc.returncode} stdout={stdout!r} stderr={stderr!r}"
        )
    try:
        status = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise ValueError(f"stable starter --status returned non-JSON output: {stdout!r}") from exc
    if not isinstance(status, dict) or status.get("ok") is not True:
        raise ValueError(f"stable starter --status did not report ok=true: {status!r}")
    if status.get("execution_authority") != "NONE" or status.get("can_execute") is not False:
        raise ValueError("stable starter --status authority boundary changed")
    return status


def postbind(
    runtime_root: str | os.PathLike[str],
    pointer_path: str | os.PathLike[str],
    starter_path: str | os.PathLike[str],
) -> dict[str, Any]:
    package = validate_runtime_package(runtime_root)
    live = validate_live_pointer(pointer_path)
    if not live.get("present"):
        raise ValueError("postbind requires an existing runtime-source pointer")
    runtime = Path(runtime_root).resolve()
    if Path(live["python"]).resolve() != (runtime / "python.exe").resolve():
        raise ValueError("postbind pointer python does not bind staged runtime")
    if Path(live["twin_executable"]).resolve() != (runtime / LAUNCHER_REL).resolve():
        raise ValueError("postbind pointer twin_executable does not bind staged runtime")
    if live["source_sha"].lower() != str(package["source_sha"]).lower():
        raise ValueError("postbind pointer source_sha does not bind staged runtime")
    status = _run_starter_status(Path(starter_path).resolve())
    return {
        "schema": POSTBIND_SCHEMA,
        "ok": True,
        "effect": "READ_ONLY_POSTBIND",
        "runtime_root": str(runtime),
        "pointer_sha256": live["sha256"],
        "source_sha": live["source_sha"],
        "starter_status": status,
        "memory": _memory_state_from_live(live),
        "execution_authority": "NONE",
        "can_execute": False,
    }


def _fresh_postbind(
    package: dict[str, Any],
    runtime_root: Path,
    pointer: Path,
    starter: Path,
    timeout: float,
) -> dict[str, Any]:
    cmd = [
        package["python"],
        "-B",
        "-I",
        "-m",
        "continuityos.windows_product_transaction",
        "--p1c-write",
        "postbind",
        "--runtime-root",
        str(runtime_root),
        "--pointer",
        str(pointer),
        "--starter",
        str(starter),
    ]
    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if proc.returncode != 0:
        raise ValueError(
            "fresh-process postbind failed "
            f"rc={proc.returncode} stdout={proc.stdout.strip()!r} stderr={proc.stderr.strip()!r}"
        )
    try:
        receipt = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise ValueError("fresh-process postbind returned invalid JSON") from exc
    if not isinstance(receipt, dict) or receipt.get("ok") is not True:
        raise ValueError(f"fresh-process postbind did not report ok=true: {receipt!r}")
    return receipt


def _rollback_bytes(
    pointer: Path,
    backup_bytes: bytes,
    expected_current_sha256: str,
    starter: Path | None,
) -> dict[str, Any]:
    if sha256_file(pointer) != expected_current_sha256.lower():
        raise ValueError("rollback refuses pointer drift from expected current SHA-256")
    _atomic_write_bytes(pointer, backup_bytes)
    restored_sha = hashlib.sha256(backup_bytes).hexdigest()
    if sha256_file(pointer) != restored_sha:
        raise ValueError("rollback pointer readback SHA-256 mismatch")
    live = validate_live_pointer(pointer)
    status = _run_starter_status(starter) if starter is not None else None
    return {
        "schema": ROLLBACK_SCHEMA,
        "ok": True,
        "pointer_sha256": restored_sha,
        "live_source_sha": live["source_sha"],
        "starter_status": status,
        "memory": _memory_state_from_live(live),
        "execution_authority": "NONE",
        "can_execute": False,
    }


def rollback(
    pointer_path: str | os.PathLike[str],
    backup_path: str | os.PathLike[str],
    expected_current_sha256: str,
    starter_path: str | os.PathLike[str] | None = None,
) -> dict[str, Any]:
    pointer = Path(pointer_path).resolve()
    backup = Path(backup_path).resolve()
    if not pointer.is_file():
        raise ValueError("rollback requires current pointer file")
    if not backup.is_file():
        raise ValueError("rollback backup missing")
    _require_sha256(expected_current_sha256, "expected_current_sha256")
    backup_bytes = backup.read_bytes()

    probe = pointer.parent / f".runtime-source.rollback-probe-{uuid.uuid4().hex}.json"
    _write_exclusive_fsync(probe, backup_bytes)
    try:
        previous = validate_live_pointer(probe)
        if not previous.get("present"):
            raise ValueError("rollback backup does not contain valid runtime-source")
    finally:
        probe.unlink(missing_ok=True)

    starter = Path(starter_path).resolve() if starter_path else None
    return _rollback_bytes(
        pointer,
        backup_bytes,
        expected_current_sha256.lower(),
        starter,
    )


def activate(
    runtime_root: str | os.PathLike[str],
    pointer_path: str | os.PathLike[str],
    starter_path: str | os.PathLike[str],
    *,
    postbind_timeout: float = 45.0,
) -> dict[str, Any]:
    runtime = Path(runtime_root).resolve()
    pointer = Path(pointer_path).resolve()
    starter = Path(starter_path).resolve()

    staged = stage_validate(runtime, pointer)
    if not staged["live"].get("present"):
        raise ValueError("P1C activation requires an existing valid runtime-source pointer")
    if not starter.is_file():
        raise ValueError(f"stable starter missing: {starter}")

    package = staged["runtime_package"]
    old_live = staged["live"]
    old_bytes = pointer.read_bytes()
    old_sha = hashlib.sha256(old_bytes).hexdigest()
    memory_before = _memory_state_from_live(old_live)
    live_obj = _load_json(pointer)
    candidate_obj = _candidate_pointer(live_obj, package, runtime)
    candidate_bytes = _pointer_bytes(candidate_obj)
    candidate_sha = hashlib.sha256(candidate_bytes).hexdigest()

    txn_root = pointer.parent / "transactions"
    txn_id = f"{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}-{uuid.uuid4().hex}"
    txn_dir = txn_root / txn_id
    txn_dir.mkdir(parents=True, exist_ok=False)
    backup = txn_dir / "before.runtime-source.json"
    candidate_receipt = txn_dir / "candidate.runtime-source.json"
    result_path = txn_dir / "result.json"
    _write_exclusive_fsync(backup, old_bytes)
    _write_exclusive_fsync(candidate_receipt, candidate_bytes)

    switched = False
    rollback_receipt = None
    try:
        package_now = validate_runtime_package(runtime)
        live_now = validate_live_pointer(pointer)
        if live_now.get("sha256") != old_sha or pointer.read_bytes() != old_bytes:
            raise ValueError("activation refuses live pointer drift since preflight")
        if package_now["runtime_tree_sha256"] != package["runtime_tree_sha256"]:
            raise ValueError("activation refuses staged runtime drift since preflight")
        _assert_memory_state_unchanged(memory_before, live_now)

        candidate_probe = txn_dir / "candidate.validate.json"
        _write_exclusive_fsync(candidate_probe, candidate_bytes)
        try:
            candidate_live = validate_live_pointer(candidate_probe)
            _assert_memory_state_unchanged(memory_before, candidate_live)
        finally:
            candidate_probe.unlink(missing_ok=True)

        _atomic_write_bytes(pointer, candidate_bytes)
        switched = True
        if sha256_file(pointer) != candidate_sha:
            raise ValueError("candidate pointer readback SHA-256 mismatch")

        post = _fresh_postbind(
            package,
            runtime,
            pointer,
            starter,
            postbind_timeout,
        )
        live_after = validate_live_pointer(pointer)
        if live_after["sha256"] != candidate_sha:
            raise ValueError("postbind pointer drift detected")
        _assert_memory_state_unchanged(memory_before, live_after)

        result = {
            "schema": TRANSACTION_SCHEMA,
            "ok": True,
            "effect": "ATOMIC_EXISTING_BINDING_UPDATE",
            "transaction_id": txn_id,
            "transaction_dir": str(txn_dir),
            "backup_path": str(backup),
            "candidate_receipt_path": str(candidate_receipt),
            "old_pointer_sha256": old_sha,
            "new_pointer_sha256": candidate_sha,
            "old_source_sha": old_live["source_sha"],
            "new_source_sha": package["source_sha"],
            "postbind": post,
            "rollback_performed": False,
            "memory_mutated": False,
            "execution_authority": "NONE",
            "can_execute": False,
        }
        _write_exclusive_fsync(
            result_path,
            (json.dumps(result, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8"),
        )
        return result
    except Exception as exc:
        rollback_error = None
        if switched:
            try:
                rollback_receipt = _rollback_bytes(
                    pointer,
                    old_bytes,
                    candidate_sha,
                    starter,
                )
                live_rolled_back = validate_live_pointer(pointer)
                _assert_memory_state_unchanged(memory_before, live_rolled_back)
            except Exception as rb_exc:
                rollback_error = f"{type(rb_exc).__name__}: {rb_exc}"

        failure = {
            "schema": TRANSACTION_SCHEMA,
            "ok": False,
            "effect": "ATOMIC_EXISTING_BINDING_UPDATE",
            "transaction_id": txn_id,
            "transaction_dir": str(txn_dir),
            "backup_path": str(backup),
            "candidate_receipt_path": str(candidate_receipt),
            "old_pointer_sha256": old_sha,
            "candidate_pointer_sha256": candidate_sha,
            "error_class": type(exc).__name__,
            "error": str(exc),
            "pointer_switch_performed": switched,
            "rollback_performed": rollback_receipt is not None,
            "rollback": rollback_receipt,
            "rollback_error": rollback_error,
            "memory_mutated": False,
            "execution_authority": "NONE",
            "can_execute": False,
        }
        _write_exclusive_fsync(
            result_path,
            (json.dumps(failure, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8"),
        )
        if rollback_error:
            raise RuntimeError(
                f"activation failed and rollback verification also failed: {failure}"
            ) from exc
        raise ValueError(
            "activation failed after bounded transaction; "
            f"rollback_performed={failure['rollback_performed']}: {exc}"
        ) from exc


def build_parser() -> argparse.ArgumentParser:
    """Default P1A/P1B surface remains read-only."""
    p = argparse.ArgumentParser(prog="python -m continuityos.windows_product_transaction")
    sub = p.add_subparsers(dest="cmd", required=True)
    stage = sub.add_parser("stage-validate", help="read-only staged runtime validation")
    stage.add_argument("--runtime-root", required=True)
    stage.add_argument("--pointer", required=True)
    return p


def _build_p1c_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="python -m continuityos.windows_product_transaction --p1c-write",
        description="Explicit P1C existing-binding transaction capability.",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    act = sub.add_parser("activate", help="atomically update an existing runtime binding")
    act.add_argument("--runtime-root", required=True)
    act.add_argument("--pointer", required=True)
    act.add_argument("--starter", required=True)
    act.add_argument("--postbind-timeout", type=float, default=45.0)

    post = sub.add_parser("postbind", help="read-only fresh-process binding verification")
    post.add_argument("--runtime-root", required=True)
    post.add_argument("--pointer", required=True)
    post.add_argument("--starter", required=True)

    rb = sub.add_parser("rollback", help="restore a byte-exact validated pointer backup")
    rb.add_argument("--pointer", required=True)
    rb.add_argument("--backup", required=True)
    rb.add_argument("--expected-current-sha256", required=True)
    rb.add_argument("--starter")
    return p


def _failure_schema(cmd: str) -> tuple[str, str]:
    if cmd == "postbind":
        return POSTBIND_SCHEMA, "READ_ONLY_POSTBIND"
    if cmd == "rollback":
        return ROLLBACK_SCHEMA, "ATOMIC_POINTER_ROLLBACK"
    if cmd == "activate":
        return TRANSACTION_SCHEMA, "ATOMIC_EXISTING_BINDING_UPDATE"
    return "sovereign-twin.windows-product-stage-validation/v1", "READ_ONLY_ZERO_EXTERNAL_EFFECTS"


def main(argv: list[str] | None = None) -> int:
    raw = list(sys.argv[1:] if argv is None else argv)
    p1c_write = bool(raw and raw[0] == "--p1c-write")
    if p1c_write:
        args = _build_p1c_parser().parse_args(raw[1:])
    else:
        args = build_parser().parse_args(raw)

    try:
        if not p1c_write:
            result = stage_validate(args.runtime_root, args.pointer)
        elif args.cmd == "activate":
            result = activate(
                args.runtime_root,
                args.pointer,
                args.starter,
                postbind_timeout=args.postbind_timeout,
            )
        elif args.cmd == "postbind":
            result = postbind(args.runtime_root, args.pointer, args.starter)
        elif args.cmd == "rollback":
            result = rollback(
                args.pointer,
                args.backup,
                args.expected_current_sha256,
                args.starter,
            )
        else:
            raise ValueError(f"unsupported command: {args.cmd}")
        print(json.dumps(result, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
        return 0
    except (
        OSError,
        ValueError,
        RuntimeError,
        sqlite3.DatabaseError,
        json.JSONDecodeError,
        subprocess.SubprocessError,
    ) as exc:
        schema, effect = _failure_schema(args.cmd if p1c_write else "stage-validate")
        print(
            json.dumps(
                {
                    "schema": schema,
                    "ok": False,
                    "effect": effect,
                    "error_class": type(exc).__name__,
                    "error": str(exc),
                    "memory_mutated": False,
                    "execution_authority": "NONE",
                    "can_execute": False,
                },
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())