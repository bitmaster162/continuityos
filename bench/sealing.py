"""Stdlib-only benchmark identity and receipt helpers.

This module does not grant runtime, merge, deployment, provider, trading, or
capital authority.  It only records reproducibility evidence for benchmark
runs.
"""
from __future__ import annotations

import hashlib
import importlib.metadata
import json
import platform
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


SCHEMA = "continuityos-benchmark-manifest-v1"
_SHA256_HEX = set("0123456789abcdef")


def canonical_json_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_sha256(value: Any) -> str:
    return sha256_bytes(canonical_json_bytes(value))


def normalize_sha256(value: str, *, field: str) -> str:
    normalized = value.strip().lower()
    if len(normalized) != 64 or any(ch not in _SHA256_HEX for ch in normalized):
        raise ValueError(f"{field} must be exactly 64 hexadecimal SHA-256 characters")
    return normalized


def write_json(path: str | Path, payload: Any) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def _git(root: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", *args],
        cwd=str(root),
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    return completed.stdout.strip()


def git_identity(start: str | Path | None = None) -> dict[str, Any]:
    """Return exact Git HEAD/tree when available, without mutating the repository."""
    root_hint = Path(start or Path.cwd()).resolve()
    try:
        root = Path(_git(root_hint, "rev-parse", "--show-toplevel")).resolve()
        head = _git(root, "rev-parse", "HEAD")
        tree = _git(root, "rev-parse", "HEAD^{tree}")
        status = _git(root, "status", "--porcelain=v1", "--untracked-files=all")
    except (OSError, subprocess.CalledProcessError, ValueError):
        return {
            "status": "UNAVAILABLE",
            "head": None,
            "tree": None,
            "working_tree_clean": None,
        }
    return {
        "status": "AVAILABLE",
        "head": head,
        "tree": tree,
        "working_tree_clean": not bool(status),
    }


def package_versions(names: Iterable[str]) -> dict[str, str | None]:
    versions: dict[str, str | None] = {}
    for name in names:
        try:
            versions[name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            versions[name] = None
    return versions


def source_identity(path: str | Path) -> dict[str, Any]:
    target = Path(path).resolve()
    return {
        "path": target.name,
        "sha256": sha256_file(target),
        "size_bytes": target.stat().st_size,
    }


def model_identity(
    *,
    embedder: str,
    model_name: str | None,
    model_revision: str | None,
    model_sha256: str | None,
    package_name: str | None,
) -> dict[str, Any]:
    if embedder == "hashing":
        return {
            "embedder": "hashing",
            "model_name": None,
            "model_revision": None,
            "model_sha256": None,
            "package": None,
            "package_version": None,
            "identity_assurance": "TRACKED_CODE_ONLY",
        }

    digest = (
        normalize_sha256(model_sha256, field="model_sha256")
        if model_sha256 is not None
        else None
    )
    version = package_versions([package_name]).get(package_name) if package_name else None
    assurance = "MODEL_BYTES_BOUND" if model_revision and digest else "NAME_ONLY"
    return {
        "embedder": embedder,
        "model_name": model_name,
        "model_revision": model_revision,
        "model_sha256": digest,
        "package": package_name,
        "package_version": version,
        "identity_assurance": assurance,
    }


def require_sealed_model(identity: dict[str, Any]) -> None:
    if identity["embedder"] == "hashing":
        return
    if identity.get("identity_assurance") != "MODEL_BYTES_BOUND":
        raise ValueError(
            "sealed benchmark requires --model-revision and --model-sha256 "
            "for non-hashing embedders"
        )


def build_manifest(
    *,
    benchmark_name: str,
    benchmark_source: str | Path,
    argv: list[str],
    result_path: str | Path,
    dataset: dict[str, Any],
    model: dict[str, Any],
    extra_packages: Iterable[str] = (),
) -> dict[str, Any]:
    result = Path(result_path).resolve()
    repo = git_identity(Path(benchmark_source).resolve().parent)
    packages = package_versions(
        ["continuityos", *extra_packages]
    )
    return {
        "schema": SCHEMA,
        "generated_at_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "benchmark": {
            "name": benchmark_name,
            "source": source_identity(benchmark_source),
        },
        "repo": repo,
        "dataset": dataset,
        "model": model,
        "environment": {
            "python": sys.version,
            "platform": platform.platform(),
            "packages": packages,
        },
        "argv": list(argv),
        "result": {
            "path": result.name,
            "sha256": sha256_file(result),
            "size_bytes": result.stat().st_size,
        },
        "authority": {
            "execution_authority": "NONE",
            "can_execute": False,
            "can_trade": False,
            "capital_permission": "DENY",
            "deploy_permission": "DENY",
            "provider_effects": False,
        },
    }
