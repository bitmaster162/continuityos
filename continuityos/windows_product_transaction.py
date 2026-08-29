"""Read-only Windows product transaction preflight primitives for Sovereign Twin P1A.

P1A intentionally implements *no activation writes*. It validates an immutable,
side-by-side runtime package against the existing runtime-source pointer and memory
container. Atomic pointer replacement, rollback, repair and uninstall are later P1
slices and must not be smuggled into this foundation module.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
from typing import Any, Iterable

RUNTIME_PACKAGE_SCHEMA = "sovereign-twin.runtime-package/v1"
RUNTIME_SOURCE_SCHEMA = "sovereign-twin.windows-runtime-source/v3"
RUNTIME_MODULE_REL = Path("Lib") / "site-packages" / "continuityos" / "sovereign_twin_runtime.py"
LAUNCHER_REL = Path("Scripts") / "sovereign-twin.exe"
PACKAGE_MANIFEST = "runtime-package.json"
SUMS_FILE = "SHA256SUMS"
TREE_EXCLUDES = frozenset({PACKAGE_MANIFEST, SUMS_FILE})
SQLITE_AUX_SUFFIXES = ("-wal", "-shm", "-journal")

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
    lines: list[str] = []
    for path in iter_payload_files(base):
        rel = _norm_rel(path.relative_to(base))
        lines.append(f"{sha256_file(path)}  {path.stat().st_size}  {rel}")
    return lines


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
        raise ValueError("live runtime-source must contain exactly 18 v3 fields: " + " ".join(detail))

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
        raise ValueError(f"live runtime-source {field} must be exact loopback http(s) URL with port")
    port = int(match.group(1))
    if port <= 0 or port > 65535:
        raise ValueError(f"live runtime-source {field} port invalid")
    return port


def _same_runtime_root(python_exe: Path, twin_exe: Path) -> bool:
    """Mirror native starter layout: <root>/python.exe + <root>/*/sovereign-twin.exe."""
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
    """Public read-only helper used by CI/installer custody checks."""
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
    """Verify quick_check and exact physical vector width without modifying SQLite files."""
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
        raise ValueError("memory manifest embedding_dimension does not bind live memory_embedding_dimension")
    if manifest.get("embedding_contract") != EXPECTED_EMBEDDING_CONTRACT:
        raise ValueError("memory manifest embedding_contract does not bind Nomic task-prefix contract")

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
        if not isinstance(path_config, str) or not path_config or Path(path_config).name != path_config:
            raise ValueError("runtime package python_path_config invalid")
        pth = root / path_config
        if not pth.is_file():
            raise ValueError("runtime package python_path_config missing")
        pth_lines = {
            line.strip().lower().replace("/", "\\")
            for line in pth.read_text(encoding="utf-8-sig").splitlines()
        }
        if "lib\\site-packages" not in pth_lines or "import site" not in pth_lines:
            raise ValueError("runtime package python_path_config does not enable bundled site-packages")

    launcher_sha = sha256_file(launcher)
    module_sha = sha256_file(runtime_module)
    tree_sha = canonical_tree_sha256(root)
    if launcher_sha != _require_sha256(package.get("launcher_sha256"), "launcher_sha256"):
        raise ValueError("runtime package launcher SHA mismatch")
    if module_sha != _require_sha256(package.get("runtime_module_sha256"), "runtime_module_sha256"):
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
            raise ValueError(f"live runtime-source {field} missing on disk: {required_path}")

    if python_exe.name.casefold() != "python.exe":
        raise ValueError("live runtime-source python basename must be python.exe")
    if twin_exe.name.casefold() != "sovereign-twin.exe":
        raise ValueError("live runtime-source twin_executable basename must be sovereign-twin.exe")
    if not _same_runtime_root(python_exe, twin_exe):
        raise ValueError("live runtime-source python and twin_executable must bind the same runtime root")

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


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="python -m continuityos.windows_product_transaction")
    sub = p.add_subparsers(dest="cmd", required=True)
    stage = sub.add_parser("stage-validate", help="read-only staged runtime validation")
    stage.add_argument("--runtime-root", required=True)
    stage.add_argument("--pointer", required=True)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.cmd == "stage-validate":
            result = stage_validate(args.runtime_root, args.pointer)
        else:  # pragma: no cover - argparse prevents this
            raise ValueError(f"unsupported command: {args.cmd}")
        print(json.dumps(result, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
        return 0
    except (OSError, ValueError, sqlite3.DatabaseError, json.JSONDecodeError) as exc:
        print(
            json.dumps(
                {
                    "schema": "sovereign-twin.windows-product-stage-validation/v1",
                    "ok": False,
                    "effect": "READ_ONLY_ZERO_EXTERNAL_EFFECTS",
                    "error_class": type(exc).__name__,
                    "error": str(exc),
                    "activation_performed": False,
                    "pointer_switch_performed": False,
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
