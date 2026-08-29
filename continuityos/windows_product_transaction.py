"""Read-only Windows product transaction preflight primitives for Sovereign Twin P1A.

P1A intentionally implements *no activation writes*.  It validates an immutable,
side-by-side runtime package against the existing runtime-source pointer and memory
container.  Atomic pointer replacement, rollback, repair and uninstall are later P1
slices and must not be smuggled into this foundation module.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import sqlite3
from typing import Any, Iterable

RUNTIME_PACKAGE_SCHEMA = "sovereign-twin.runtime-package/v1"
RUNTIME_SOURCE_SCHEMA = "sovereign-twin.windows-runtime-source/v3"
RUNTIME_MODULE_REL = Path("Lib") / "site-packages" / "continuityos" / "sovereign_twin_runtime.py"
LAUNCHER_REL = Path("Scripts") / "sovereign-twin.exe"
PACKAGE_MANIFEST = "runtime-package.json"
SUMS_FILE = "SHA256SUMS"
TREE_EXCLUDES = frozenset({PACKAGE_MANIFEST, SUMS_FILE})


def _norm_rel(path: Path) -> str:
    return path.as_posix()


def sha256_file(path: str | os.PathLike[str]) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
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


def _load_json(path: Path) -> dict[str, Any]:
    raw = path.read_text(encoding="utf-8")
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def _require_sha256(value: Any, field: str) -> str:
    text = str(value or "").lower()
    if len(text) != 64 or any(c not in "0123456789abcdef" for c in text):
        raise ValueError(f"{field} must be lowercase SHA-256 hex")
    return text


def _require_source_sha(value: Any) -> str:
    text = str(value or "").lower()
    if len(text) != 40 or any(c not in "0123456789abcdef" for c in text):
        raise ValueError("source_sha must be exact 40-character Git SHA")
    return text


def _require_none_false(obj: dict[str, Any], context: str) -> None:
    if obj.get("execution_authority") != "NONE":
        raise ValueError(f"{context} execution_authority must be NONE")
    if obj.get("can_execute") is not False:
        raise ValueError(f"{context} can_execute must be false")


def _full_path(value: Any, field: str) -> Path:
    text = str(value or "").strip()
    if not text:
        raise ValueError(f"{field} missing")
    return Path(text).expanduser().resolve()


def _sqlite_quick_check_read_only(path: Path) -> str:
    # URI mode=ro prevents accidental DB creation or journal mutation by this preflight.
    uri = path.as_uri() + "?mode=ro"
    con = sqlite3.connect(uri, uri=True, timeout=5.0)
    try:
        row = con.execute("PRAGMA quick_check").fetchone()
        return str(row[0]) if row else ""
    finally:
        con.close()


def validate_runtime_package(runtime_root: str | os.PathLike[str]) -> dict[str, Any]:
    root = Path(runtime_root).resolve()
    if not root.is_dir():
        raise ValueError(f"runtime root missing: {root}")

    manifest_path = root / PACKAGE_MANIFEST
    if not manifest_path.is_file():
        raise ValueError(f"runtime package manifest missing: {manifest_path}")
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
    if not isinstance(dims, list) or not dims or not all(isinstance(x, int) and x > 0 for x in dims):
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
        pth_lines = {line.strip().lower().replace("/", "\\") for line in pth.read_text(encoding="utf-8-sig").splitlines()}
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
    if pointer.get("schema") != RUNTIME_SOURCE_SCHEMA:
        raise ValueError("live runtime-source schema mismatch")
    _require_none_false(pointer, "live runtime-source")

    required = (
        "repository",
        "source_sha",
        "python",
        "twin_executable",
        "memory_db",
        "admission_queue",
        "llm_server",
        "ui",
        "fast_model",
        "deep_model",
        "embedding_model",
    )
    for field in required:
        if not str(pointer.get(field) or "").strip():
            raise ValueError(f"live runtime-source field missing: {field}")
    _require_source_sha(pointer["source_sha"])

    python_exe = _full_path(pointer["python"], "python")
    twin_exe = _full_path(pointer["twin_executable"], "twin_executable")
    memory_db = _full_path(pointer["memory_db"], "memory_db")
    for field, required_path in (("python", python_exe), ("twin_executable", twin_exe), ("memory_db", memory_db)):
        if not required_path.is_file():
            raise ValueError(f"live runtime-source {field} missing on disk: {required_path}")

    memory_manifest_value = str(pointer.get("memory_manifest") or "").strip()
    memory_manifest = None
    if memory_manifest_value:
        memory_manifest = _full_path(memory_manifest_value, "memory_manifest")
        if not memory_manifest.is_file():
            raise ValueError(f"live runtime-source memory_manifest missing on disk: {memory_manifest}")

    dimension = pointer.get("memory_embedding_dimension")
    if dimension is not None and (not isinstance(dimension, int) or dimension <= 0):
        raise ValueError("live runtime-source memory_embedding_dimension invalid")

    quick = _sqlite_quick_check_read_only(memory_db)
    if quick.lower() != "ok":
        raise ValueError(f"live memory quick_check failed: {quick}")

    return {
        "present": True,
        "path": str(path),
        "sha256": sha256_file(path),
        "source_sha": pointer["source_sha"],
        "python": str(python_exe),
        "twin_executable": str(twin_exe),
        "memory_db": str(memory_db),
        "memory_db_sha256": sha256_file(memory_db),
        "memory_manifest": str(memory_manifest) if memory_manifest else None,
        "memory_embedding_dimension": dimension,
        "memory_quick_check": quick,
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

        dim = live.get("memory_embedding_dimension")
        if dim is not None and dim not in package["memory_embedding_dimensions_supported"]:
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
