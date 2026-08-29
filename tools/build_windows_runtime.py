"""Build an offline, immutable Sovereign Twin Windows runtime payload.

Inputs are prepared artifacts only: a CPython Windows runtime directory, an exact
ContinuityOS wheel, and a prebuilt location-relative launcher executable.  This tool
never downloads source, invokes pip, or mutates an active installation.
"""
from __future__ import annotations

import argparse
from email.parser import Parser
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import zipfile

PACKAGE_SCHEMA = "sovereign-twin.runtime-package/v1"
RUNTIME_SOURCE_SCHEMA = "sovereign-twin.windows-runtime-source/v3"
RUNTIME_MODULE_REL = Path("Lib") / "site-packages" / "continuityos" / "sovereign_twin_runtime.py"
LAUNCHER_REL = Path("Scripts") / "sovereign-twin.exe"
PACKAGE_MANIFEST = "runtime-package.json"
SUMS_FILE = "SHA256SUMS"
TREE_EXCLUDES = frozenset({PACKAGE_MANIFEST, SUMS_FILE})


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _safe_rel(name: str) -> Path:
    rel = Path(name.replace("\\", "/"))
    if rel.is_absolute() or ".." in rel.parts:
        raise ValueError(f"wheel contains unsafe path: {name}")
    return rel


def _copy_tree_exact(source: Path, target: Path) -> None:
    if not source.is_dir():
        raise ValueError(f"Python runtime directory missing: {source}")
    for src in sorted(source.rglob("*"), key=lambda p: p.as_posix()):
        rel = src.relative_to(source)
        dst = target / rel
        if src.is_symlink():
            raise ValueError(f"Python runtime contains unsupported symlink: {src}")
        if src.is_dir():
            dst.mkdir(parents=True, exist_ok=True)
        elif src.is_file():
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(src, dst)
        else:
            raise ValueError(f"unsupported Python runtime entry: {src}")


def _extract_wheel_exact(wheel: Path, site_packages: Path) -> tuple[str, str]:
    if not wheel.is_file() or wheel.suffix.lower() != ".whl":
        raise ValueError(f"wheel missing or invalid: {wheel}")
    metadata_text = None
    site_packages.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(wheel, "r") as zf:
        for info in sorted(zf.infolist(), key=lambda i: i.filename):
            if info.is_dir():
                continue
            rel = _safe_rel(info.filename)
            # Wheels may carry executable permission bits; P1A copies bytes only and lets
            # Windows executable semantics come from file extension/PE format.
            unix_mode = (info.external_attr >> 16) & 0xFFFF
            if stat.S_ISLNK(unix_mode):
                raise ValueError(f"wheel contains unsupported symlink: {info.filename}")
            data = zf.read(info)
            dst = site_packages / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            dst.write_bytes(data)
            if rel.name == "METADATA" and rel.parent.name.endswith(".dist-info"):
                if metadata_text is not None:
                    raise ValueError("wheel contains multiple METADATA files")
                metadata_text = data.decode("utf-8")
    if metadata_text is None:
        raise ValueError("wheel METADATA not found")
    meta = Parser().parsestr(metadata_text)
    name = str(meta.get("Name") or "").strip().lower().replace("_", "-")
    version = str(meta.get("Version") or "").strip()
    if name != "continuityos" or not version:
        raise ValueError("wheel metadata does not identify continuityos with a version")
    return name, version


def _iter_payload_files(root: Path):
    for path in sorted(root.rglob("*"), key=lambda p: p.relative_to(root).as_posix()):
        if path.is_symlink():
            raise ValueError(f"runtime payload contains symlink: {path}")
        if not path.is_file():
            continue
        rel = path.relative_to(root).as_posix()
        if rel in TREE_EXCLUDES:
            continue
        yield path


def canonical_tree_lines(root: Path) -> list[str]:
    return [
        f"{sha256_file(path)}  {path.stat().st_size}  {path.relative_to(root).as_posix()}"
        for path in _iter_payload_files(root)
    ]


def canonical_tree_sha256(root: Path) -> str:
    payload = ("\n".join(canonical_tree_lines(root)) + "\n").encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _require_source_sha(value: str) -> str:
    value = value.lower()
    if len(value) != 40 or any(c not in "0123456789abcdef" for c in value):
        raise ValueError("--source-sha must be an exact 40-character Git SHA")
    return value


def _write_json(path: Path, obj: dict) -> None:
    path.write_text(
        json.dumps(obj, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def build_runtime(
    *,
    python_runtime: str | os.PathLike[str],
    wheel: str | os.PathLike[str],
    launcher: str | os.PathLike[str],
    output_root: str | os.PathLike[str],
    source_sha: str,
    architecture: str = "win-x64",
    supported_dimensions: tuple[int, ...] = (768,),
) -> dict:
    source_sha = _require_source_sha(source_sha)
    if architecture != "win-x64":
        raise ValueError("P1A builder supports only win-x64")
    if not supported_dimensions or any(not isinstance(x, int) or x <= 0 for x in supported_dimensions):
        raise ValueError("supported_dimensions must contain positive integers")

    py_src = Path(python_runtime).resolve()
    wheel_path = Path(wheel).resolve()
    launcher_path = Path(launcher).resolve()
    out_base = Path(output_root).resolve()
    if not launcher_path.is_file():
        raise ValueError(f"launcher missing: {launcher_path}")

    wheel_sha = sha256_file(wheel_path)

    # Read version before fixing the output directory name.  Extract into a private
    # preparation directory under output_root, then rename once validation succeeds.
    out_base.mkdir(parents=True, exist_ok=True)
    prep = out_base / f".p1a-prep-{source_sha[:12]}"
    if prep.exists():
        raise ValueError(f"preparation directory already exists: {prep}")
    prep.mkdir()
    try:
        _copy_tree_exact(py_src, prep)
        if not (prep / "python.exe").is_file():
            raise ValueError("bundled Python runtime has no python.exe")
        if not list(prep.glob("python3*.dll")):
            raise ValueError("bundled Python runtime has no python3*.dll")

        _, version = _extract_wheel_exact(wheel_path, prep / "Lib" / "site-packages")
        runtime_module = prep / RUNTIME_MODULE_REL
        if not runtime_module.is_file():
            raise ValueError(f"wheel missing required runtime module: {RUNTIME_MODULE_REL.as_posix()}")

        launcher_dst = prep / LAUNCHER_REL
        launcher_dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(launcher_path, launcher_dst)

        build_id = f"{version}+{source_sha[:12]}-{architecture}"
        final_root = out_base / build_id
        if final_root.exists():
            raise ValueError(f"runtime build already exists: {final_root}")

        launcher_sha = sha256_file(launcher_dst)
        runtime_module_sha = sha256_file(runtime_module)
        tree_sha = canonical_tree_sha256(prep)
        package = {
            "schema": PACKAGE_SCHEMA,
            "build_id": build_id,
            "package_version": version,
            "source_sha": source_sha,
            "architecture": architecture,
            "wheel_sha256": wheel_sha,
            "runtime_tree_sha256": tree_sha,
            "runtime_module_sha256": runtime_module_sha,
            "launcher_sha256": launcher_sha,
            "runtime_source_schema_supported": [RUNTIME_SOURCE_SCHEMA],
            "memory_embedding_dimensions_supported": list(supported_dimensions),
            "execution_authority": "NONE",
            "can_execute": False,
        }
        _write_json(prep / PACKAGE_MANIFEST, package)

        sums = canonical_tree_lines(prep)
        (prep / SUMS_FILE).write_text("\n".join(sums) + "\n", encoding="utf-8", newline="\n")

        # Rename is the only admission into the output namespace.  The builder never
        # overwrites an existing versioned runtime directory.
        prep.rename(final_root)
        return {
            "schema": "sovereign-twin.windows-runtime-build/v1",
            "ok": True,
            "runtime_root": str(final_root),
            "build_id": build_id,
            "package_manifest": str(final_root / PACKAGE_MANIFEST),
            "runtime_tree_sha256": tree_sha,
            "wheel_sha256": wheel_sha,
            "execution_authority": "NONE",
            "can_execute": False,
        }
    except Exception:
        if prep.exists():
            shutil.rmtree(prep)
        raise


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="python -m tools.build_windows_runtime")
    p.add_argument("--python-runtime", required=True)
    p.add_argument("--wheel", required=True)
    p.add_argument("--launcher", required=True)
    p.add_argument("--output-root", required=True)
    p.add_argument("--source-sha", required=True)
    p.add_argument("--architecture", default="win-x64")
    p.add_argument("--embedding-dimension", type=int, action="append", default=[])
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        result = build_runtime(
            python_runtime=args.python_runtime,
            wheel=args.wheel,
            launcher=args.launcher,
            output_root=args.output_root,
            source_sha=args.source_sha,
            architecture=args.architecture,
            supported_dimensions=tuple(args.embedding_dimension or [768]),
        )
        print(json.dumps(result, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
        return 0
    except (OSError, ValueError, zipfile.BadZipFile) as exc:
        print(
            json.dumps(
                {
                    "schema": "sovereign-twin.windows-runtime-build/v1",
                    "ok": False,
                    "error_class": type(exc).__name__,
                    "error": str(exc),
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
