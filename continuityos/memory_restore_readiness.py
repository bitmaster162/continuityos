"""Read-only restore-readiness preflight for a future bounded memory restore.

P5C does not expose ``cos restore`` and does not perform a restore. It binds one
fixed runtime-source manifest to one canonical memory database, validates one P5A
backup bundle, records exact hashes/quiescence, and reports whether the current
effect boundary would permit a separately authorized restore transaction.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
from typing import Mapping, Sequence

from .control_center import default_runtime_root
from .current_effect_boundary import MODE_CURRENT, MODE_LEGACY, inspect_current_session
from .memory_backup import BackupHold, _governance, _validate_sqlite_copy
from . import memory_restore as restore

SCHEMA = "continuityos.memory_restore_readiness/v1"
MODE = "READ_ONLY_PREFLIGHT"
_RUNTIME_MEMORY_KEYS = ("memory_db", "db", "database")


class RestoreReadinessHold(RuntimeError):
    def __init__(self, reason: str, detail: str = ""):
        super().__init__(detail or reason)
        self.reason = reason
        self.detail = detail or reason


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _require_sha256(value: str | None, label: str) -> str | None:
    if value is None:
        return None
    text = str(value).strip().lower()
    if len(text) != 64 or any(c not in "0123456789abcdef" for c in text):
        raise RestoreReadinessHold("INVALID_SHA256", f"{label} must be SHA-256 hex")
    return text


def _safe_runtime_root(runtime_root: str | Path | None) -> Path:
    raw = default_runtime_root() if runtime_root is None else Path(runtime_root).expanduser()
    try:
        info = raw.lstat()
    except OSError as exc:
        raise RestoreReadinessHold(
            "RUNTIME_ROOT_UNAVAILABLE",
            "runtime root is unavailable",
        ) from exc
    attrs = int(getattr(info, "st_file_attributes", 0))
    reparse = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    if raw.is_symlink() or attrs & reparse or not stat.S_ISDIR(info.st_mode):
        raise RestoreReadinessHold(
            "RUNTIME_ROOT_UNSAFE",
            "runtime root must be a direct directory",
        )
    try:
        return raw.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise RestoreReadinessHold(
            "RUNTIME_ROOT_UNAVAILABLE",
            "runtime root cannot be resolved",
        ) from exc


def _runtime_binding(runtime_root: Path) -> tuple[Path, str, Path]:
    manifest_path = runtime_root / "runtime-source.json"
    try:
        restore._require_regular_file(manifest_path, "RUNTIME_SOURCE")
        raw = manifest_path.read_bytes()
        manifest = json.loads(raw.decode("utf-8"))
    except restore.RestoreHold as exc:
        raise RestoreReadinessHold(exc.reason, exc.detail) from exc
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RestoreReadinessHold(
            "RUNTIME_SOURCE_INVALID",
            f"runtime-source.json read failed: {type(exc).__name__}",
        ) from exc
    if not isinstance(manifest, dict):
        raise RestoreReadinessHold(
            "RUNTIME_SOURCE_INVALID",
            "runtime-source.json root must be an object",
        )

    supplied: list[tuple[str, Path]] = []
    for key in _RUNTIME_MEMORY_KEYS:
        value = manifest.get(key)
        if isinstance(value, str) and value.strip():
            candidate = Path(value).expanduser()
            if not candidate.is_absolute():
                raise RestoreReadinessHold(
                    "RUNTIME_MEMORY_BINDING_UNSAFE",
                    f"{key} must be an absolute path",
                )
            try:
                restore._require_regular_file(candidate, "TARGET_MEMORY")
                supplied.append((key, candidate.resolve(strict=True)))
            except restore.RestoreHold as exc:
                raise RestoreReadinessHold(exc.reason, exc.detail) from exc
            except (OSError, RuntimeError) as exc:
                raise RestoreReadinessHold(
                    "TARGET_MEMORY_UNAVAILABLE",
                    f"{key} target is unavailable",
                ) from exc
    if not supplied:
        raise RestoreReadinessHold(
            "RUNTIME_MEMORY_BINDING_MISSING",
            "runtime-source.json has no canonical memory binding",
        )
    canonical = supplied[0][1]
    if any(path != canonical for _, path in supplied[1:]):
        raise RestoreReadinessHold(
            "RUNTIME_MEMORY_BINDING_CONFLICT",
            "runtime-source.json contains conflicting memory bindings",
        )
    try:
        restore._require_regular_file(canonical, "TARGET_MEMORY")
    except restore.RestoreHold as exc:
        raise RestoreReadinessHold(exc.reason, exc.detail) from exc
    return manifest_path, hashlib.sha256(raw).hexdigest(), canonical


def _requirements() -> dict[str, object]:
    return {
        "p5a_v1_compatibility_acknowledgement": True,
        "byte_exact_replace_acknowledgement": True,
        "expected_current_sha256_required_for_restore": True,
        "target_path_sha256_required_for_restore": True,
        "fresh_pre_switch_recheck_required": True,
        "separate_live_restore_gate_required": True,
        "cos_restore_routing_available": False,
    }


def _base_receipt(terminal: str, reason: str = "") -> dict[str, object]:
    return {
        "schema": SCHEMA,
        "terminal": terminal,
        "mode": MODE,
        "reason": reason or None,
        "read_only": True,
        "restore_authorized": False,
        "restore_performed": False,
        "rollback_performed": False,
        "requirements": _requirements(),
        "governance": _governance(),
    }


def inspect_restore_readiness(
    backup_filename: str,
    *,
    runtime_root: str | Path | None = None,
    allow_p5a_v1_compatibility: bool = False,
    acknowledge_byte_exact_replace: bool = False,
    expected_current_sha256: str | None = None,
    expected_target_path_sha256: str | None = None,
    env: Mapping[str, str] | None = None,
) -> dict[str, object]:
    """Inspect one restore candidate without creating transaction or target writes."""
    if not allow_p5a_v1_compatibility:
        raise RestoreReadinessHold(
            "P5A_V1_COMPATIBILITY_ACK_REQUIRED",
            "readiness requires explicit P5A/v1 compatibility acknowledgement",
        )
    if not acknowledge_byte_exact_replace:
        raise RestoreReadinessHold(
            "BYTE_EXACT_REPLACE_ACK_REQUIRED",
            "readiness requires explicit acknowledgement of byte-exact target replacement",
        )
    expected_current = _require_sha256(expected_current_sha256, "expected_current_sha256")
    expected_path = _require_sha256(expected_target_path_sha256, "expected_target_path_sha256")

    root = _safe_runtime_root(runtime_root)
    manifest_path, manifest_sha, target = _runtime_binding(root)
    target_path_sha = _sha256_text(str(target))

    if expected_path is not None and target_path_sha != expected_path:
        raise RestoreReadinessHold(
            "EXPECTED_TARGET_PATH_SHA256_MISMATCH",
            "runtime-bound target path does not match the pinned path SHA-256",
        )

    try:
        target_state = restore._target_state(target)
        try:
            target_validation = dict(_validate_sqlite_copy(target))
        except BackupHold as exc:
            raise RestoreReadinessHold("TARGET_VALIDATION_FAILED", exc.detail) from exc
        bundle = restore._resolve_bundle(backup_filename)
        bundle_sha = restore._hash_file(bundle)
        bundle_state = restore._read_bundle(
            bundle,
            allow_p5a_v1_compatibility=True,
        )
    except restore.RestoreHold as exc:
        raise RestoreReadinessHold(exc.reason, exc.detail) from exc

    current_sha = str(target_state["sha256"])
    if expected_current is not None and current_sha != expected_current:
        raise RestoreReadinessHold(
            "EXPECTED_CURRENT_SHA256_MISMATCH",
            "runtime-bound target does not match the pinned current SHA-256",
        )

    try:
        if _sha256_file(manifest_path) != manifest_sha:
            raise RestoreReadinessHold(
                "RUNTIME_SOURCE_CHANGED_DURING_PREFLIGHT",
                "runtime-source.json changed during readiness inspection",
            )
        if restore._target_state(target) != target_state:
            raise RestoreReadinessHold(
                "TARGET_CHANGED_DURING_PREFLIGHT",
                "runtime-bound target changed during readiness inspection",
            )
        if restore._hash_file(bundle) != bundle_sha:
            raise RestoreReadinessHold(
                "BACKUP_CHANGED_DURING_PREFLIGHT",
                "backup bundle changed during readiness inspection",
            )
    except restore.RestoreHold as exc:
        raise RestoreReadinessHold(exc.reason, exc.detail) from exc
    except OSError as exc:
        raise RestoreReadinessHold(
            "READINESS_INPUT_UNAVAILABLE",
            f"readiness input became unavailable: {type(exc).__name__}",
        ) from exc

    effect_state = inspect_current_session(os.environ if env is None else env)
    effect_allowed = effect_state.get("mode") == MODE_LEGACY
    receipt = _base_receipt(
        "COS_RESTORE_READINESS_PASS" if effect_allowed else "COS_RESTORE_READINESS_HOLD",
        "" if effect_allowed else (
            "CURRENT_EFFECT_HOLD"
            if effect_state.get("mode") == MODE_CURRENT
            else "CURRENT_EFFECT_REVISE"
        ),
    )
    receipt.update(
        {
            "runtime_source": {
                "path": str(manifest_path),
                "path_sha256": _sha256_text(str(manifest_path)),
                "sha256": manifest_sha,
            },
            "target": {
                "path": str(target),
                "path_sha256": target_path_sha,
                "current_sha256": current_sha,
                "size_bytes": int(target_state["size"]),
                "mtime_ns": int(target_state["mtime_ns"]),
                "device": int(target_state["device"]),
                "inode": int(target_state["inode"]),
                "sidecars_absent": True,
                "validation": target_validation,
            },
            "backup": {
                "bundle_filename": bundle.name,
                "bundle_sha256": bundle_sha,
                "candidate_sha256": str(bundle_state["memory_sha256"]),
                "candidate_size_bytes": int(bundle_state["memory_size_bytes"]),
                "compatibility": bundle_state["compatibility"],
            },
            "current_effect": {
                "mode": effect_state.get("mode"),
                "binding_verified": bool(effect_state.get("binding_verified")),
                "reason": effect_state.get("reason"),
                "restore_effect_allowed": effect_allowed,
                "session_effect_ceiling": effect_state.get("session_effect_ceiling"),
                "authority_ceiling": effect_state.get("authority_ceiling"),
            },
            "pins": {
                "expected_current_sha256": current_sha,
                "expected_target_path_sha256": target_path_sha,
                "runtime_source_sha256": manifest_sha,
                "bundle_sha256": bundle_sha,
            },
        }
    )
    return receipt


def _hold_receipt(reason: str, detail: str = "") -> dict[str, object]:
    receipt = _base_receipt("COS_RESTORE_READINESS_HOLD", reason)
    receipt["detail"] = detail or reason
    return receipt


def _emit(value: Mapping[str, object], as_json: bool) -> None:
    if as_json:
        print(json.dumps(dict(value), ensure_ascii=False, sort_keys=True, separators=(",", ":")))
    else:
        print(f"{value.get('terminal')}: {value.get('reason') or MODE}")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m continuityos.memory_restore_readiness")
    parser.add_argument("--runtime-root", default=None)
    parser.add_argument("--backup", required=True)
    parser.add_argument("--allow-p5a-v1-compatibility", action="store_true")
    parser.add_argument("--acknowledge-byte-exact-replace", action="store_true")
    parser.add_argument("--expected-current-sha256", default=None)
    parser.add_argument("--expected-target-path-sha256", default=None)
    parser.add_argument("--json", dest="as_json", action="store_true")
    args = parser.parse_args(list(argv) if argv is not None else None)

    try:
        receipt = inspect_restore_readiness(
            args.backup,
            runtime_root=args.runtime_root,
            allow_p5a_v1_compatibility=args.allow_p5a_v1_compatibility,
            acknowledge_byte_exact_replace=args.acknowledge_byte_exact_replace,
            expected_current_sha256=args.expected_current_sha256,
            expected_target_path_sha256=args.expected_target_path_sha256,
        )
    except RestoreReadinessHold as exc:
        receipt = _hold_receipt(exc.reason, exc.detail)
        _emit(receipt, args.as_json)
        return 2
    _emit(receipt, args.as_json)
    return 0 if receipt["terminal"] == "COS_RESTORE_READINESS_PASS" else 3


if __name__ == "__main__":
    raise SystemExit(main())
