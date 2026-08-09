"""Deterministic read-only inspection of one current-authority stable-root directory.

The existing current cold-start verifier already validates ACTIVE pointer semantics,
root hashes/generations, and deny ceilings.  This module removes only operator path
boilerplate: one directory is expanded to the four exact canonical filenames.

There is deliberately no globbing, generation guessing, mtime ordering, fallback,
or "latest" selection.  Missing or differently named files fail closed.
"""
from __future__ import annotations

import os
from pathlib import Path
import stat
from typing import Any

from .current_cold_start import (
    CurrentColdStartError,
    _read_json_with_sha,
    _validate_pointer,
    _validate_stable_roots,
)

SCHEMA = "CONTINUITYOS_CURRENT_AUTHORITY_ROOT_INSPECT_V1"
CANONICAL_FILES = {
    "authority_pointer": "CURRENT_POINTER.json",
    "current_state": "CURRENT_STATE.json",
    "role_index": "ROLE_INDEX.json",
    "role_views": "ROLE_VIEWS.json",
}


def _effects() -> dict[str, Any]:
    return {
        "filesystem_write": False,
        "network_effect": False,
        "subprocess": False,
        "deployment": False,
        "current_state_apply": False,
        "canonical_mutation": False,
        "agent_dispatch": False,
        "external_message": False,
        "trading": False,
        "wallet_access": False,
        "can_trade": False,
        "capital_permission": "DENY",
        "deploy_permission": "DENY",
    }


def resolve_current_authority_root(authority_root: Path) -> dict[str, Path]:
    root = Path(authority_root).expanduser().absolute()
    if not root.exists() or not root.is_dir():
        raise CurrentColdStartError("current.authority_root:MISSING_DIRECTORY")
    info = root.lstat()
    if stat.S_ISLNK(info.st_mode):
        raise CurrentColdStartError("current.authority_root:SYMLINK_REFUSED")
    attrs = getattr(info, "st_file_attributes", 0)
    if attrs & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400):
        raise CurrentColdStartError("current.authority_root:REPARSE_REFUSED")

    resolved_root = root.resolve()
    result: dict[str, Path] = {}
    for key, filename in CANONICAL_FILES.items():
        path = resolved_root / filename
        if not path.exists() or not path.is_file():
            raise CurrentColdStartError(
                f"current.authority_root:{filename}:MISSING_CANONICAL_FILE"
            )
        # The cold-start stable reader performs the full per-file symlink/reparse,
        # size and read-drift checks.  Resolve only after existence is confirmed.
        result[key] = path
    return result


def inspect_current_authority_root(
    authority_root: Path,
    *,
    expected_authority_pointer_sha256: str,
) -> dict[str, Any]:
    paths = resolve_current_authority_root(authority_root)

    pointer_value, pointer_sha = _read_json_with_sha(
        paths["authority_pointer"], "current.pointer"
    )
    pointer = _validate_pointer(
        pointer_value,
        actual_sha256=pointer_sha,
        expected_sha256=expected_authority_pointer_sha256,
    )

    current_state_value, current_state_sha = _read_json_with_sha(
        paths["current_state"], "current.current_state"
    )
    role_index_value, role_index_sha = _read_json_with_sha(
        paths["role_index"], "current.role_index"
    )
    role_views_value, role_views_sha = _read_json_with_sha(
        paths["role_views"], "current.role_views"
    )
    roots = _validate_stable_roots(
        pointer,
        current_state_value,
        current_state_sha,
        role_index_value,
        role_index_sha,
        role_views_value,
        role_views_sha,
    )

    root_path = os.path.normcase(str(Path(authority_root).expanduser().absolute().resolve()))
    return {
        "schema": SCHEMA,
        "terminal": "CURRENT_AUTHORITY_ROOT_INSPECT_PASS",
        "authority_root": root_path,
        "selection_mode": "EXACT_CANONICAL_FILENAMES_ONLY",
        "authority_generation": pointer["generation"],
        "authority_pointer_sha256": pointer_sha,
        "accepted_manifest_sha256": pointer["accepted_manifest_sha256"],
        "activation_status": pointer["activation_status"],
        "activation_decision": pointer["activation_decision"],
        "human_sovereign": pointer["human_sovereign"],
        "canonical_files": {
            key: {
                "name": CANONICAL_FILES[key],
                "path": str(paths[key]),
                "sha256": (
                    pointer_sha if key == "authority_pointer" else roots["sha256"][key]
                ),
            }
            for key in CANONICAL_FILES
        },
        "compiled_current_state_marker": roots["current_state"].get(
            "canonicality_activation"
        ),
        "effect_ceiling": dict(pointer["effect_ceiling"]),
        "writes_performed": [],
        "effects": _effects(),
    }
