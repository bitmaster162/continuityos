"""Shared fail-closed primitives for evidence-bound control-plane gates."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any
import hashlib
import json
import re
import subprocess
import zipfile

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
OID_RE = re.compile(r"^[0-9a-f]{40}$")
REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
MAX_JSON_BYTES = 4 * 1024 * 1024
MAX_ZIP_MEMBERS = 4096
MAX_UNCOMPRESSED_BYTES = 512 * 1024 * 1024

FORBIDDEN_EFFECTS = (
    "force_push",
    "merge",
    "pull_request_merge",
    "auto_merge",
    "deployment",
    "registry_apply",
    "current_state_apply",
    "r63_apply",
    "trading",
    "wallet_access",
    "order_execution",
    "external_message",
    "self_application",
)


def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def canonical_json_text(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def load_json(path: Path, label: str) -> dict[str, Any]:
    path = Path(path)
    if path.is_symlink():
        raise ValueError(f"{label} path may not be a symlink")
    if not path.is_file():
        raise FileNotFoundError(f"{label} file is missing")
    if path.stat().st_size > MAX_JSON_BYTES:
        raise ValueError(f"{label} exceeds {MAX_JSON_BYTES} bytes")
    try:
        value = json.loads(path.read_text(encoding="utf-8-sig"))
    except Exception as exc:
        raise ValueError(f"{label} is not valid UTF-8 JSON: {type(exc).__name__}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    return value


def require_dict(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    return value


def require_list(value: Any, label: str, maximum: int) -> list[Any]:
    if not isinstance(value, list) or len(value) > maximum:
        raise ValueError(f"{label} must be a list with at most {maximum} entries")
    return value


def require_str(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} must be a non-empty string")
    return value


def require_bool(value: Any, label: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{label} must be boolean")
    return value


def require_sha(value: Any, label: str) -> str:
    text = require_str(value, label)
    if not SHA256_RE.fullmatch(text):
        raise ValueError(f"{label} must be lowercase SHA-256")
    return text


def require_oid(value: Any, label: str) -> str:
    text = require_str(value, label)
    if not OID_RE.fullmatch(text):
        raise ValueError(f"{label} must be lowercase 40-hex Git object ID")
    return text


def require_repo(value: Any, label: str = "repository") -> str:
    text = require_str(value, label).lower()
    if not REPO_RE.fullmatch(text):
        raise ValueError(f"{label} must be owner/name")
    return text


def fixed_effects(*, merge: bool = False) -> dict[str, Any]:
    return {
        "force_push": False,
        "merge": merge,
        "pull_request_merge": merge,
        "auto_merge": False,
        "deployment": False,
        "registry_apply": False,
        "current_state_apply": False,
        "r63_apply": False,
        "trading": False,
        "wallet_access": False,
        "order_execution": False,
        "external_message": False,
        "self_application": False,
        "can_trade": False,
        "capital_permission": "DENY",
        "deploy_permission": "DENY",
    }


def validate_effects(value: Any, label: str, *, merge: bool = False) -> None:
    obj = require_dict(value, label)
    for key in FORBIDDEN_EFFECTS:
        expected = merge if key in {"merge", "pull_request_merge"} else False
        if obj.get(key) is not expected:
            raise ValueError(f"{label}.{key} must be {str(expected).lower()}")
    if obj.get("can_trade") is not False:
        raise ValueError(f"{label}.can_trade must be false")
    if obj.get("capital_permission") != "DENY":
        raise ValueError(f"{label}.capital_permission must be DENY")
    if obj.get("deploy_permission") != "DENY":
        raise ValueError(f"{label}.deploy_permission must be DENY")


def safe_zip_member(name: str) -> bool:
    if "\\" in name or re.match(r"^[A-Za-z]:", name):
        return False
    path = PurePosixPath(name)
    return not path.is_absolute() and all(part not in {"", ".", ".."} for part in path.parts)


def verify_zip(path: Path) -> list[str]:
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise ValueError("ZIP is missing or symlinked")
    with zipfile.ZipFile(path, "r") as archive:
        infos = archive.infolist()
        if len(infos) > MAX_ZIP_MEMBERS:
            raise ValueError("ZIP has too many members")
        if sum(item.file_size for item in infos) > MAX_UNCOMPRESSED_BYTES:
            raise ValueError("ZIP uncompressed size exceeds limit")
        raw_names = [getattr(item, "orig_filename", item.filename) for item in infos]
        normalized_names = [item.filename for item in infos]
        if any(not safe_zip_member(name) for name in raw_names):
            raise ValueError("ZIP contains unsafe raw member path")
        if any(not safe_zip_member(name) for name in normalized_names):
            raise ValueError("ZIP contains unsafe normalized member path")
        if len(normalized_names) != len(set(normalized_names)):
            raise ValueError("ZIP contains duplicate paths")
        if len(normalized_names) != len({name.casefold() for name in normalized_names}):
            raise ValueError("ZIP contains case-colliding paths")
        if archive.testzip() is not None:
            raise ValueError("ZIP CRC failure")
        return normalized_names


def verify_manifest(archive: zipfile.ZipFile, manifest_name: str) -> int:
    manifest = json.loads(archive.read(manifest_name).decode("utf-8"))
    entries = manifest.get("files")
    if not isinstance(entries, list) or len(entries) > MAX_ZIP_MEMBERS:
        raise ValueError("manifest.files is invalid")
    names = archive.namelist()
    root = PurePosixPath(manifest_name).parent
    seen: set[str] = set()
    for index, raw in enumerate(entries):
        row = require_dict(raw, f"manifest.files[{index}]")
        rel = require_str(row.get("path") or row.get("file"), f"manifest.files[{index}].path")
        if rel in seen:
            raise ValueError("manifest contains duplicate path")
        seen.add(rel)
        member = next((candidate for candidate in (str(root / rel), rel) if candidate in names), None)
        if member is None:
            raise ValueError(f"manifest member missing: {rel}")
        data = archive.read(member)
        if sha256_bytes(data) != require_sha(row.get("sha256"), f"manifest.files[{index}].sha256"):
            raise ValueError(f"manifest SHA mismatch: {rel}")
        size = row.get("bytes", row.get("size_bytes"))
        if size is not None and (not isinstance(size, int) or isinstance(size, bool) or size != len(data)):
            raise ValueError(f"manifest size mismatch: {rel}")
    return len(entries)


def sidecar_sha(path: Path) -> str:
    text = Path(path).read_text(encoding="utf-8", errors="strict")
    match = re.search(r"\b([0-9a-f]{64})\b", text)
    if not match:
        raise ValueError("sidecar has no lowercase SHA-256")
    return match.group(1)


def git(repo: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo), *args],
        text=True,
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        raise ValueError(f"git {' '.join(args)} failed: {proc.stderr.strip()}")
    return proc.stdout.strip()


def add_check(
    checks: list[dict[str, Any]],
    check_id: str,
    status: str,
    detail: str,
    **evidence: Any,
) -> None:
    row: dict[str, Any] = {"id": check_id, "status": status, "detail": detail}
    if evidence:
        row["evidence"] = evidence
    checks.append(row)
