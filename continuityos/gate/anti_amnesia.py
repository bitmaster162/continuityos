"""Deterministic, read-only ANTI_AMNESIA_GATE v1.

The gate binds the current R63 control plane and a fixed ContinuityOS
canon/runtime snapshot without invoking recovery, locking, ledgers, network,
or mutation code.  It is advisory shadow infrastructure only.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple
import unicodedata
import zipfile


GATE = "ANTI_AMNESIA_GATE_V1"
MODE = "SHADOW"
EXPECTED_AUTHORITY_GENERATION = "R63"
RETURN_ENVELOPE_NAME = "ANTI_AMNESIA_RETURN_V1.json"

EXIT_PASS = 0
EXIT_WARN = 1
EXIT_HOLD = 2
EXIT_INTERNAL = 4

MAX_INPUT_FILE_BYTES = 16 * 1024 * 1024
MAX_RETURN_BYTES = 64 * 1024 * 1024
MAX_RETURN_FILES = 512
MAX_ZIP_MEMBER_BYTES = 16 * 1024 * 1024
MAX_ZIP_RATIO = 100

DEFAULT_CONTROL_ROOT = (
    Path.home() / "My Drive" / "Control canter" / "00_CONTROL_CURRENT"
)

WORKSPACE_INPUTS: Tuple[Tuple[str, str], ...] = (
    ("00_CANON/HUMAN_CANON.md", "text"),
    ("00_CANON/INVARIANTS.md", "text"),
    ("00_CANON/INTERNAL_AGENTS.md", "text"),
    ("01_RUNTIME/state.json", "json"),
    ("01_RUNTIME/projects.json", "json"),
    ("01_RUNTIME/open_loops.json", "json"),
    ("01_RUNTIME/checkpoints.jsonl", "jsonl"),
)

AUTHORITY_DESCRIPTORS: Tuple[str, ...] = (
    "manifest",
    "current_state",
    "role_index",
    "role_views",
    "generation_ledger",
    "packet_manifest",
)

AUTHORITY_DOCUMENT_SCHEMAS: Mapping[str, str] = {
    "current_state": "CONTROL_CURRENT_STATE_R63",
    "role_index": "CONTROL_ROLE_INDEX_R63",
    "role_views": "CONTROL_ROLE_VIEWS_R63",
    "generation_ledger": "control_canter.generation_ledger.v1",
}

ROLE_RE = re.compile(r"^[A-Z][A-Z0-9-]{0,63}$")
CASE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
WINDOWS_RESERVED_NAMES = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *(f"COM{index}" for index in range(1, 10)),
    *(f"LPT{index}" for index in range(1, 10)),
}


class AntiAmnesiaError(ValueError):
    """The shadow contract or one of its inputs is invalid."""


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def canonical_json_text(value: Any) -> str:
    return canonical_json_bytes(value).decode("utf-8")


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def sha256_canonical(value: Any) -> str:
    return sha256_bytes(canonical_json_bytes(value))


def _reject_duplicate_keys(pairs: Sequence[Tuple[str, Any]]) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise AntiAmnesiaError(f"DUPLICATE_JSON_KEY:{key}")
        result[key] = value
    return result


def _reject_non_finite(value: str) -> None:
    raise AntiAmnesiaError(f"NON_FINITE_JSON_NUMBER:{value}")


def strict_json_loads(payload: bytes, label: str) -> Any:
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise AntiAmnesiaError(f"INVALID_UTF8:{label}") from exc
    try:
        return json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_non_finite,
        )
    except AntiAmnesiaError:
        raise
    except (json.JSONDecodeError, TypeError, ValueError) as exc:
        raise AntiAmnesiaError(f"INVALID_JSON:{label}") from exc


def _is_reparse(path: Path) -> bool:
    try:
        attrs = getattr(path.lstat(), "st_file_attributes", 0)
    except OSError:
        return False
    flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(attrs & flag)


def stable_read_bytes(
    path: Path,
    *,
    label: str,
    max_bytes: int = MAX_INPUT_FILE_BYTES,
) -> bytes:
    """Read a regular file twice and fail if identity or bytes change."""
    path = Path(path)
    if path.is_symlink() or _is_reparse(path):
        raise AntiAmnesiaError(f"REPARSE_INPUT_REFUSED:{label}")
    try:
        before = path.stat()
    except OSError as exc:
        raise AntiAmnesiaError(f"INPUT_MISSING:{label}") from exc
    if not stat.S_ISREG(before.st_mode):
        raise AntiAmnesiaError(f"INPUT_NOT_REGULAR_FILE:{label}")
    if before.st_size > max_bytes:
        raise AntiAmnesiaError(f"INPUT_TOO_LARGE:{label}")
    try:
        first = path.read_bytes()
        middle = path.stat()
        second = path.read_bytes()
        after = path.stat()
    except OSError as exc:
        raise AntiAmnesiaError(f"INPUT_READ_FAILED:{label}") from exc
    identities = (
        (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns),
        (middle.st_dev, middle.st_ino, middle.st_size, middle.st_mtime_ns),
        (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns),
    )
    if len(set(identities)) != 1 or first != second or len(first) != before.st_size:
        raise AntiAmnesiaError(f"INPUT_CHANGED_DURING_READ:{label}")
    return first


def _safe_relative_path(root: Path, raw: Any, label: str) -> Tuple[str, Path]:
    if not isinstance(raw, str) or not raw:
        raise AntiAmnesiaError(f"INVALID_RELATIVE_PATH:{label}")
    if "\\" in raw:
        raise AntiAmnesiaError(f"AMBIGUOUS_BACKSLASH_PATH:{label}")
    pure = PurePosixPath(raw)
    if pure.is_absolute() or not pure.parts or any(part in {"", ".", ".."} for part in pure.parts):
        raise AntiAmnesiaError(f"UNSAFE_RELATIVE_PATH:{label}")
    if ":" in pure.parts[0]:
        raise AntiAmnesiaError(f"DRIVE_QUALIFIED_PATH:{label}")
    root_resolved = root.resolve()
    target = (root_resolved / Path(*pure.parts)).resolve()
    try:
        target.relative_to(root_resolved)
    except ValueError as exc:
        raise AntiAmnesiaError(f"PATH_ESCAPES_ROOT:{label}") from exc
    cursor = root_resolved
    for part in pure.parts:
        cursor = cursor / part
        if cursor.exists() and (cursor.is_symlink() or _is_reparse(cursor)):
            raise AntiAmnesiaError(f"REPARSE_PATH_REFUSED:{label}")
    return pure.as_posix(), target


def _record(
    checks: List[Dict[str, str]],
    errors: List[str],
    warnings: List[str],
    check_id: str,
    status_value: str,
    code: str,
) -> None:
    checks.append({"check_id": check_id, "status": status_value, "code": code})
    if status_value == "FAIL":
        errors.append(code)
    elif status_value == "WARN":
        warnings.append(code)


def _effect_ceiling_valid(value: Any, *, require_self_application: bool) -> bool:
    if not isinstance(value, dict):
        return False
    required_false = ["auto_dispatch", "auto_accept", "can_trade"]
    if require_self_application:
        required_false.append("self_application")
    if any(value.get(field) is not False for field in required_false):
        return False
    if value.get("push") != "DENY" or value.get("deploy") != "DENY":
        return False
    return value.get("capital_permission") == "DENY"


def _descriptor_binding(
    control_root: Path,
    pointer: Mapping[str, Any],
    name: str,
    docs: Dict[str, Any],
    checks: List[Dict[str, str]],
    errors: List[str],
    warnings: List[str],
) -> Dict[str, Any]:
    descriptor = pointer.get(name)
    binding: Dict[str, Any] = {
        "name": name,
        "logical_path": None,
        "size_bytes": None,
        "sha256": None,
        "verified": False,
    }
    if not isinstance(descriptor, dict):
        _record(checks, errors, warnings, f"r63.descriptor.{name}", "FAIL", f"R63_DESCRIPTOR_MISSING:{name}")
        return binding
    try:
        logical, path = _safe_relative_path(control_root, descriptor.get("path"), name)
        payload = stable_read_bytes(path, label=f"r63.{name}")
    except AntiAmnesiaError as exc:
        _record(checks, errors, warnings, f"r63.descriptor.{name}", "FAIL", str(exc))
        return binding
    digest = sha256_bytes(payload)
    binding.update(
        {
            "logical_path": logical,
            "size_bytes": len(payload),
            "sha256": digest,
        }
    )
    declared_size = descriptor.get("size_bytes")
    declared_hash = descriptor.get("sha256")
    if (
        not isinstance(declared_size, int)
        or declared_size != len(payload)
        or not isinstance(declared_hash, str)
        or declared_hash.lower() != digest
    ):
        _record(checks, errors, warnings, f"r63.descriptor.{name}", "FAIL", f"R63_DESCRIPTOR_MISMATCH:{name}")
        return binding
    try:
        docs[name] = strict_json_loads(payload, f"r63.{name}")
    except AntiAmnesiaError as exc:
        _record(checks, errors, warnings, f"r63.descriptor.{name}", "FAIL", str(exc))
        return binding
    binding["verified"] = True
    _record(checks, errors, warnings, f"r63.descriptor.{name}", "PASS", "VERIFIED")
    return binding


def bind_r63_authority(
    control_root: Optional[Path] = None,
) -> Tuple[Dict[str, Any], Dict[str, Any], List[Dict[str, str]], List[str], List[str]]:
    root = Path(control_root) if control_root is not None else DEFAULT_CONTROL_ROOT
    checks: List[Dict[str, str]] = []
    errors: List[str] = []
    warnings: List[str] = []
    docs: Dict[str, Any] = {}
    pointer_binding: Dict[str, Any] = {
        "logical_path": "CURRENT_POINTER.json",
        "size_bytes": None,
        "sha256": None,
        "verified": False,
    }
    pointer: Dict[str, Any] = {}
    try:
        payload = stable_read_bytes(root / "CURRENT_POINTER.json", label="r63.pointer")
        pointer_binding.update(
            {
                "size_bytes": len(payload),
                "sha256": sha256_bytes(payload),
            }
        )
        parsed = strict_json_loads(payload, "r63.pointer")
        if not isinstance(parsed, dict):
            raise AntiAmnesiaError("R63_POINTER_NOT_OBJECT")
        pointer = parsed
        pointer_binding["verified"] = True
        _record(checks, errors, warnings, "r63.pointer.bytes", "PASS", "VERIFIED")
    except AntiAmnesiaError as exc:
        _record(checks, errors, warnings, "r63.pointer.bytes", "FAIL", str(exc))

    generation = pointer.get("generation")
    pointer_contract_ok = (
        pointer.get("schema") == "CONTROL_CURRENT_POINTER_R63"
        and generation == EXPECTED_AUTHORITY_GENERATION
    )
    _record(
        checks,
        errors,
        warnings,
        "r63.pointer.contract",
        "PASS" if pointer_contract_ok else "FAIL",
        "VERIFIED" if pointer_contract_ok else "R63_POINTER_CONTRACT_MISMATCH",
    )

    bindings = [
        _descriptor_binding(root, pointer, name, docs, checks, errors, warnings)
        for name in AUTHORITY_DESCRIPTORS
    ]

    ready_binding: Dict[str, Any] = {
        "logical_path": None,
        "size_bytes": None,
        "sha256": None,
        "status": None,
        "verified": False,
    }
    ready_protocol = pointer.get("ready_protocol")
    if isinstance(ready_protocol, dict):
        try:
            logical, ready_path = _safe_relative_path(
                root, ready_protocol.get("marker"), "ready"
            )
            ready_payload = stable_read_bytes(ready_path, label="r63.ready")
            ready_doc = strict_json_loads(ready_payload, "r63.ready")
            if not isinstance(ready_doc, dict):
                raise AntiAmnesiaError("R63_READY_NOT_OBJECT")
            ready_ok = (
                ready_doc.get("schema") == "CONTROL_CANTER_R63_READY"
                and ready_doc.get("generation") == EXPECTED_AUTHORITY_GENERATION
                and ready_doc.get("created_last") is True
                and ready_doc.get("pointer_sha256") == pointer_binding.get("sha256")
                and ready_doc.get("pointer_size_bytes") == pointer_binding.get("size_bytes")
                and ready_doc.get("can_trade") is False
                and ready_doc.get("capital_permission") == "DENY"
            )
            ready_binding.update(
                {
                    "logical_path": logical,
                    "size_bytes": len(ready_payload),
                    "sha256": sha256_bytes(ready_payload),
                    "status": ready_doc.get("status"),
                    "verified": ready_ok,
                }
            )
            if not ready_ok:
                raise AntiAmnesiaError("R63_READY_BINDING_MISMATCH")
            docs["ready"] = ready_doc
            _record(checks, errors, warnings, "r63.ready", "PASS", "VERIFIED")
        except AntiAmnesiaError as exc:
            _record(checks, errors, warnings, "r63.ready", "FAIL", str(exc))
    else:
        _record(checks, errors, warnings, "r63.ready", "FAIL", "R63_READY_PROTOCOL_MISSING")
    if (
        isinstance(ready_protocol, dict)
        and ready_protocol.get("raw_provider_readback_required") is True
    ):
        _record(
            checks,
            errors,
            warnings,
            "r63.provider_readback",
            "WARN",
            "R63_RAW_PROVIDER_READBACK_OUTSIDE_SHADOW_PROOF",
        )

    state = docs.get("current_state")
    views = docs.get("role_views")
    index = docs.get("role_index")
    ledger = docs.get("generation_ledger")
    for document_name, expected_schema in AUTHORITY_DOCUMENT_SCHEMAS.items():
        document = docs.get(document_name)
        contract_ok = (
            isinstance(document, dict)
            and document.get("schema") == expected_schema
            and document.get("generation") == EXPECTED_AUTHORITY_GENERATION
        )
        _record(
            checks,
            errors,
            warnings,
            f"r63.document_contract.{document_name}",
            "PASS" if contract_ok else "FAIL",
            "VERIFIED"
            if contract_ok
            else f"R63_DOCUMENT_CONTRACT_MISMATCH:{document_name}",
        )
    cross_generation_ok = all(
        isinstance(document, dict)
        and document.get("generation") == EXPECTED_AUTHORITY_GENERATION
        for document in (state, views, index, ledger)
    )
    _record(
        checks,
        errors,
        warnings,
        "r63.cross_generation",
        "PASS" if cross_generation_ok else "FAIL",
        "VERIFIED" if cross_generation_ok else "R63_GENERATION_DISAGREEMENT",
    )

    pointer_effect = pointer.get("effect_ceiling")
    state_effect = state.get("global_effect_ceiling") if isinstance(state, dict) else None
    views_effect = views.get("global_effect_ceiling") if isinstance(views, dict) else None
    effect_ok = (
        _effect_ceiling_valid(pointer_effect, require_self_application=False)
        and _effect_ceiling_valid(state_effect, require_self_application=True)
        and _effect_ceiling_valid(views_effect, require_self_application=True)
    )
    _record(
        checks,
        errors,
        warnings,
        "r63.effect_ceiling",
        "PASS" if effect_ok else "FAIL",
        "VERIFIED" if effect_ok else "R63_EFFECT_CEILING_CONFLICT",
    )

    ledger_current = False
    if isinstance(ledger, dict):
        for row in ledger.get("generations", []):
            if (
                isinstance(row, dict)
                and row.get("generation") == EXPECTED_AUTHORITY_GENERATION
                and row.get("plane") == "AUTHORITY"
                and row.get("status") == "CURRENT_AUTHORITY_PLANE"
            ):
                ledger_current = True
                break
    _record(
        checks,
        errors,
        warnings,
        "r63.ledger_current_authority",
        "PASS" if ledger_current else "FAIL",
        "VERIFIED" if ledger_current else "R63_NOT_CURRENT_IN_GENERATION_LEDGER",
    )

    authority = {
        "generation": generation,
        "relation": "ADVISORY_ONLY_R63_REMAINS_AUTHORITATIVE",
        "pointer": pointer_binding,
        "descriptors": sorted(bindings, key=lambda row: row["name"]),
        "ready": ready_binding,
        "effect_ceiling": {
            "auto_dispatch": False,
            "auto_accept": False,
            "self_application": False,
            "push": "DENY",
            "deploy": "DENY",
            "external_messages": "DENY_WITHOUT_EXPLICIT_HUMAN_REVIEW_AND_SEND_AUTHORITY",
            "can_trade": False,
            "capital_permission": "DENY",
        },
    }
    return authority, docs, sorted(checks, key=lambda row: row["check_id"]), sorted(set(errors)), sorted(set(warnings))


def _parse_jsonl(payload: bytes, label: str) -> List[Dict[str, Any]]:
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise AntiAmnesiaError(f"INVALID_UTF8:{label}") from exc
    rows: List[Dict[str, Any]] = []
    for line_no, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        row = strict_json_loads(line.encode("utf-8"), f"{label}:{line_no}")
        if not isinstance(row, dict):
            raise AntiAmnesiaError(f"JSONL_ROW_NOT_OBJECT:{label}:{line_no}")
        rows.append(row)
    if not rows:
        raise AntiAmnesiaError(f"EMPTY_JSONL:{label}")
    return rows


def bind_workspace(
    workspace_root: Optional[Path] = None,
) -> Tuple[Dict[str, Any], Dict[str, Any], List[Dict[str, str]], List[str], List[str]]:
    root = Path(workspace_root) if workspace_root is not None else Path.cwd()
    checks: List[Dict[str, str]] = []
    errors: List[str] = []
    warnings: List[str] = []
    docs: Dict[str, Any] = {}
    runtime = root / "01_RUNTIME"
    journal = runtime / ".runtime_txn.json"
    journal_before = journal.exists()
    _record(
        checks,
        errors,
        warnings,
        "workspace.transaction_journal_absent_before",
        "PASS" if not journal_before else "FAIL",
        "VERIFIED" if not journal_before else "LIVE_TRANSACTION_JOURNAL_PRESENT",
    )

    first_pass: Dict[str, bytes] = {}
    for logical, kind in WORKSPACE_INPUTS:
        try:
            _, path = _safe_relative_path(root, logical, f"workspace.{logical}")
            first_pass[logical] = stable_read_bytes(path, label=f"workspace.{logical}")
        except AntiAmnesiaError as exc:
            _record(checks, errors, warnings, f"workspace.file.{logical}", "FAIL", str(exc))
            continue
        _record(checks, errors, warnings, f"workspace.file.{logical}", "PASS", "VERIFIED")
        try:
            if kind == "json":
                docs[logical] = strict_json_loads(first_pass[logical], logical)
            elif kind == "jsonl":
                docs[logical] = _parse_jsonl(first_pass[logical], logical)
            else:
                first_pass[logical].decode("utf-8")
        except (AntiAmnesiaError, UnicodeDecodeError) as exc:
            code = str(exc) if isinstance(exc, AntiAmnesiaError) else f"INVALID_UTF8:{logical}"
            _record(checks, errors, warnings, f"workspace.parse.{logical}", "FAIL", code)
        else:
            _record(checks, errors, warnings, f"workspace.parse.{logical}", "PASS", "VERIFIED")

    second_pass: Dict[str, bytes] = {}
    if len(first_pass) == len(WORKSPACE_INPUTS):
        for logical, _kind in WORKSPACE_INPUTS:
            try:
                _, path = _safe_relative_path(root, logical, f"workspace.{logical}")
                second_pass[logical] = stable_read_bytes(path, label=f"workspace.recheck.{logical}")
            except AntiAmnesiaError as exc:
                _record(checks, errors, warnings, f"workspace.stability.{logical}", "FAIL", str(exc))
                continue
            same = second_pass[logical] == first_pass[logical]
            _record(
                checks,
                errors,
                warnings,
                f"workspace.stability.{logical}",
                "PASS" if same else "FAIL",
                "VERIFIED" if same else f"WORKSPACE_INPUT_CHANGED:{logical}",
            )

    state = docs.get("01_RUNTIME/state.json")
    projects = docs.get("01_RUNTIME/projects.json")
    loops = docs.get("01_RUNTIME/open_loops.json")
    checkpoints = docs.get("01_RUNTIME/checkpoints.jsonl")
    state_shape_ok = (
        isinstance(state, dict)
        and isinstance(state.get("last_checkpoint_id"), str)
        and bool(state.get("last_checkpoint_id"))
    )
    _record(
        checks,
        errors,
        warnings,
        "workspace.semantic.state",
        "PASS" if state_shape_ok else "FAIL",
        "VERIFIED" if state_shape_ok else "STATE_MINIMAL_CONTRACT_MISMATCH",
    )
    projects_shape_ok = (
        isinstance(projects, dict)
        and all(isinstance(item, dict) for item in projects.values())
    )
    _record(
        checks,
        errors,
        warnings,
        "workspace.semantic.projects",
        "PASS" if projects_shape_ok else "FAIL",
        "VERIFIED"
        if projects_shape_ok
        else "PROJECTS_MINIMAL_CONTRACT_MISMATCH",
    )
    def loop_identity(item: Mapping[str, Any]) -> Any:
        identity = item.get("id")
        return identity if isinstance(identity, str) else item.get("loop_id")

    loops_shape_ok = (
        isinstance(loops, list)
        and all(
            isinstance(item, dict)
            and isinstance(item.get("status"), str)
            and bool(item.get("status"))
            and isinstance(item.get("title"), str)
            and bool(item.get("title"))
            and isinstance(loop_identity(item), str)
            and bool(loop_identity(item))
            and (
                item.get("next_action") is None
                or isinstance(item.get("next_action"), str)
            )
            for item in loops
        )
    )
    _record(
        checks,
        errors,
        warnings,
        "workspace.semantic.open_loops",
        "PASS" if loops_shape_ok else "FAIL",
        "VERIFIED"
        if loops_shape_ok
        else "OPEN_LOOPS_MINIMAL_CONTRACT_MISMATCH",
    )
    all_loop_ids = (
        [loop_identity(item) for item in loops] if loops_shape_ok else []
    )
    loop_ids_unique = (
        loops_shape_ok and len(all_loop_ids) == len(set(all_loop_ids))
    )
    _record(
        checks,
        errors,
        warnings,
        "workspace.semantic.open_loop_ids",
        "PASS" if loop_ids_unique else "FAIL",
        "VERIFIED" if loop_ids_unique else "OPEN_LOOPS_DUPLICATE_ID",
    )
    latest_checkpoint_id = None
    if isinstance(checkpoints, list) and checkpoints:
        latest_checkpoint_id = checkpoints[-1].get("checkpoint_id")
    checkpoint_match = (
        isinstance(state, dict)
        and isinstance(latest_checkpoint_id, str)
        and state.get("last_checkpoint_id") == latest_checkpoint_id
    )
    _record(
        checks,
        errors,
        warnings,
        "workspace.checkpoint_identity",
        "PASS" if checkpoint_match else "FAIL",
        "VERIFIED" if checkpoint_match else "STATE_CHECKPOINT_ID_MISMATCH",
    )

    journal_after = journal.exists()
    _record(
        checks,
        errors,
        warnings,
        "workspace.transaction_journal_absent_after",
        "PASS" if not journal_after else "FAIL",
        "VERIFIED" if not journal_after else "LIVE_TRANSACTION_JOURNAL_PRESENT",
    )

    file_bindings = [
        {
            "logical_path": logical,
            "size_bytes": len(first_pass[logical]),
            "sha256": sha256_bytes(first_pass[logical]),
        }
        for logical, _kind in WORKSPACE_INPUTS
        if logical in first_pass
    ]
    project_count = len(projects) if isinstance(projects, dict) else None
    loop_rows = list(loops.values()) if isinstance(loops, dict) else loops
    open_loop_count = None
    active_open_loop_ids: List[str] = []
    active_open_loops: List[Dict[str, Any]] = []
    if isinstance(loop_rows, list) and loops_shape_ok and loop_ids_unique:
        for item in loop_rows:
            if item.get("status", "open") not in {"closed", "parked"}:
                active_open_loops.append(
                    {
                        "id": loop_identity(item),
                        "title": item["title"],
                        "status": item["status"],
                        "next_action": item.get("next_action"),
                    }
                )
        active_open_loops.sort(key=lambda item: item["id"])
        active_open_loop_ids = [item["id"] for item in active_open_loops]
        open_loop_count = len(active_open_loop_ids)
    active_open_loops_digest = sha256_canonical(active_open_loops)
    digest_input = {
        "files": file_bindings,
        "latest_checkpoint_id": latest_checkpoint_id,
        "project_count": project_count,
        "open_loop_count": open_loop_count,
        "active_open_loop_ids": active_open_loop_ids,
        "active_open_loops": active_open_loops,
        "active_open_loops_digest": active_open_loops_digest,
    }
    workspace = {
        "read_order": [logical for logical, _kind in WORKSPACE_INPUTS],
        "files": file_bindings,
        "latest_checkpoint_id": latest_checkpoint_id,
        "state_checkpoint_match": checkpoint_match,
        "project_count": project_count,
        "open_loop_count": open_loop_count,
        "active_open_loop_ids": active_open_loop_ids,
        "active_open_loops": active_open_loops,
        "active_open_loops_digest": active_open_loops_digest,
        "transaction_journal_present": journal_before or journal_after,
        "context_digest": sha256_canonical(digest_input),
    }
    return workspace, docs, sorted(checks, key=lambda row: row["check_id"]), sorted(set(errors)), sorted(set(warnings))


def validate_role(role: Any) -> str:
    if not isinstance(role, str) or not ROLE_RE.fullmatch(role):
        raise AntiAmnesiaError("INVALID_ROLE_ID")
    return role


def validate_case_id(case_id: Any) -> Optional[str]:
    if case_id is None:
        return None
    if not isinstance(case_id, str) or not CASE_RE.fullmatch(case_id):
        raise AntiAmnesiaError("INVALID_CASE_ID")
    return case_id


def _resolve_json_pointer(document: Any, pointer: str) -> Any:
    if not isinstance(pointer, str) or not pointer.startswith("/"):
        raise AntiAmnesiaError("INVALID_ROLE_JSON_POINTER")
    node = document
    for part in pointer[1:].split("/"):
        key = part.replace("~1", "/").replace("~0", "~")
        if isinstance(node, dict) and key in node:
            node = node[key]
        else:
            raise AntiAmnesiaError("ROLE_JSON_POINTER_NOT_FOUND")
    return node


def build_boot_receipt(
    role: Any,
    case_id: Any = None,
    *,
    control_root: Optional[Path] = None,
    workspace_root: Optional[Path] = None,
) -> Dict[str, Any]:
    authority, authority_docs, authority_checks, authority_errors, authority_warnings = bind_r63_authority(control_root)
    workspace, _workspace_docs, workspace_checks, workspace_errors, workspace_warnings = bind_workspace(workspace_root)
    checks = [*authority_checks, *workspace_checks]
    errors = [*authority_errors, *workspace_errors]
    warnings = [*authority_warnings, *workspace_warnings]

    role_value: Optional[str] = None
    role_binding: Dict[str, Any] = {
        "id": None,
        "json_pointer": None,
        "record_sha256": None,
        "state": None,
        "lane": None,
        "authority_status": "UNRESOLVED",
    }
    resolved_role_record: Mapping[str, Any] = {}
    try:
        role_value = validate_role(role)
    except AntiAmnesiaError as exc:
        _record(checks, errors, warnings, "boot.role.syntax", "FAIL", str(exc))
    else:
        _record(checks, errors, warnings, "boot.role.syntax", "PASS", "VERIFIED")
        index = authority_docs.get("role_index")
        views = authority_docs.get("role_views")
        descriptor = None
        if isinstance(index, dict):
            role_map = index.get("role_views")
            if isinstance(role_map, dict):
                descriptor = role_map.get(role_value)
        try:
            if not isinstance(descriptor, dict):
                raise AntiAmnesiaError("ROLE_NOT_IN_R63_INDEX")
            expected_path = next(
                (
                    item["logical_path"]
                    for item in authority["descriptors"]
                    if item["name"] == "role_views"
                ),
                None,
            )
            if descriptor.get("path") != expected_path:
                raise AntiAmnesiaError("ROLE_VIEW_PATH_MISMATCH")
            expected_pointer = f"/roles/{role_value}"
            if descriptor.get("json_pointer") != expected_pointer:
                raise AntiAmnesiaError("ROLE_JSON_POINTER_IDENTITY_MISMATCH")
            record = _resolve_json_pointer(views, descriptor.get("json_pointer"))
            if not isinstance(record, dict):
                raise AntiAmnesiaError("ROLE_RECORD_NOT_OBJECT")
        except AntiAmnesiaError as exc:
            _record(checks, errors, warnings, "boot.role.r63_binding", "FAIL", str(exc))
        else:
            resolved_role_record = record
            role_binding.update(
                {
                    "id": role_value,
                    "json_pointer": descriptor.get("json_pointer"),
                    "record_sha256": sha256_canonical(record),
                    "state": record.get("state"),
                    "lane": record.get("lane"),
                    "authority_status": "EXACT_R63_ROLE",
                }
            )
            _record(checks, errors, warnings, "boot.role.r63_binding", "PASS", "VERIFIED")

    case_value: Optional[str] = None
    case_binding = {
        "requested": case_id,
        "status": "NOT_REQUESTED",
        "authoritative": False,
        "matched_field": None,
    }
    try:
        case_value = validate_case_id(case_id)
    except AntiAmnesiaError as exc:
        _record(checks, errors, warnings, "boot.case.syntax", "FAIL", str(exc))
    else:
        _record(checks, errors, warnings, "boot.case.syntax", "PASS", "VERIFIED")
        if case_value is not None:
            structured = [
                (field, resolved_role_record.get(field))
                for field in ("case_id", "work_order_id", "work_order", "current_case")
                if isinstance(resolved_role_record.get(field), str)
            ]
            exact = next((field for field, value in structured if value == case_value), None)
            if exact is not None:
                case_binding.update(
                    {
                        "requested": case_value,
                        "status": "EXACT_STRUCTURED_MATCH",
                        "authoritative": True,
                        "matched_field": exact,
                    }
                )
                _record(checks, errors, warnings, "boot.case.r63_binding", "PASS", "VERIFIED")
            elif structured:
                case_binding.update(
                    {
                        "requested": case_value,
                        "status": "CONFLICT",
                        "authoritative": False,
                    }
                )
                _record(checks, errors, warnings, "boot.case.r63_binding", "FAIL", "CASE_CONFLICTS_WITH_R63")
            else:
                case_binding.update(
                    {
                        "requested": case_value,
                        "status": "CLI_ASSERTED_NON_AUTHORITY",
                        "authoritative": False,
                    }
                )
                _record(
                    checks,
                    errors,
                    warnings,
                    "boot.case.r63_binding",
                    "FAIL",
                    "CASE_NOT_STRUCTURED_IN_R63",
                )

    authority_recheck, authority_docs_recheck, authority_checks_recheck, authority_errors_recheck, authority_warnings_recheck = bind_r63_authority(control_root)
    workspace_recheck, _workspace_docs_recheck, workspace_checks_recheck, workspace_errors_recheck, workspace_warnings_recheck = bind_workspace(workspace_root)
    snapshot_stable = (
        authority_recheck == authority
        and authority_docs_recheck == authority_docs
        and authority_checks_recheck == authority_checks
        and authority_errors_recheck == authority_errors
        and authority_warnings_recheck == authority_warnings
        and workspace_recheck == workspace
        and workspace_checks_recheck == workspace_checks
        and workspace_errors_recheck == workspace_errors
        and workspace_warnings_recheck == workspace_warnings
    )
    _record(
        checks,
        errors,
        warnings,
        "boot.input_snapshot_stability",
        "PASS" if snapshot_stable else "FAIL",
        "VERIFIED" if snapshot_stable else "BOOT_INPUT_SNAPSHOT_CHANGED",
    )

    checks = sorted(checks, key=lambda row: row["check_id"])
    errors = sorted(set(errors))
    warnings = sorted(set(warnings))
    if errors:
        outcome = "WOULD_HOLD"
        status_value = "SHADOW_HOLD"
    elif warnings:
        outcome = "WOULD_ALLOW_WITH_WARNINGS"
        status_value = "SHADOW_READY_WITH_WARNINGS"
    else:
        outcome = "WOULD_ALLOW"
        status_value = "SHADOW_READY"
    receipt = {
        "schema": "ANTI_AMNESIA_BOOT_RECEIPT_V1",
        "gate": GATE,
        "mode": MODE,
        "command": {
            "name": "boot",
            "role": role,
            "case_id": case_id,
        },
        "authority": authority,
        "workspace": workspace,
        "binding": {
            "role": role_binding,
            "case": case_binding,
        },
        "checks": checks,
        "errors": errors,
        "warnings": warnings,
        "outcome": outcome,
        "status": status_value,
        "enforced": False,
        "live_state_reads_via_runtime_api": False,
        "live_state_modified": False,
        "r63_authority_replaced": False,
        "writes_performed": [],
        "can_trade": False,
        "capital_permission": "DENY",
    }
    validate_boot_receipt(receipt)
    return receipt


def _require_exact_keys(value: Any, expected: Iterable[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise AntiAmnesiaError(f"{label}:NOT_OBJECT")
    expected_set = set(expected)
    actual_set = set(value)
    if actual_set != expected_set:
        missing = sorted(expected_set - actual_set)
        extra = sorted(actual_set - expected_set)
        raise AntiAmnesiaError(f"{label}:KEYS:missing={missing}:extra={extra}")
    return value


def _require_bool(value: Any, expected: bool, label: str) -> None:
    if value is not expected:
        raise AntiAmnesiaError(f"{label}:EXPECTED_{str(expected).upper()}")


def _require_sha(value: Any, label: str) -> str:
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        raise AntiAmnesiaError(f"{label}:INVALID_SHA256")
    return value


def _require_bool_type(value: Any, label: str) -> bool:
    if not isinstance(value, bool):
        raise AntiAmnesiaError(f"{label}:NOT_BOOLEAN")
    return value


def _validate_nullable_hash_binding(
    value: Any,
    label: str,
    *,
    ready: bool = False,
) -> Mapping[str, Any]:
    keys = {"logical_path", "size_bytes", "sha256", "verified"}
    if ready:
        keys.add("status")
    row = _require_exact_keys(value, keys, label)
    if row["logical_path"] is not None and not isinstance(
        row["logical_path"], str
    ):
        raise AntiAmnesiaError(f"{label}:INVALID_LOGICAL_PATH")
    if row["size_bytes"] is not None and (
        not isinstance(row["size_bytes"], int)
        or isinstance(row["size_bytes"], bool)
        or row["size_bytes"] < 0
    ):
        raise AntiAmnesiaError(f"{label}:INVALID_SIZE")
    if row["sha256"] is not None:
        _require_sha(row["sha256"], f"{label}.sha256")
    _require_bool_type(row["verified"], f"{label}.verified")
    if ready and row["status"] is not None and not isinstance(
        row["status"], str
    ):
        raise AntiAmnesiaError(f"{label}:INVALID_STATUS")
    if row["verified"] and (
        row["logical_path"] is None
        or row["size_bytes"] is None
        or row["sha256"] is None
    ):
        raise AntiAmnesiaError(f"{label}:VERIFIED_WITHOUT_IDENTITY")
    return row


def _validate_authority_receipt(
    value: Any,
    label: str,
    *,
    require_verified: bool,
) -> Mapping[str, Any]:
    authority = _require_exact_keys(
        value,
        {
            "generation",
            "relation",
            "pointer",
            "descriptors",
            "ready",
            "effect_ceiling",
        },
        label,
    )
    if authority["generation"] is not None and not isinstance(
        authority["generation"], str
    ):
        raise AntiAmnesiaError(f"{label}:INVALID_GENERATION")
    if (
        authority["relation"]
        != "ADVISORY_ONLY_R63_REMAINS_AUTHORITATIVE"
    ):
        raise AntiAmnesiaError(f"{label}:R63_RELATION_MISMATCH")
    pointer = _validate_nullable_hash_binding(
        authority["pointer"], f"{label}.pointer"
    )
    descriptors = authority["descriptors"]
    if not isinstance(descriptors, list):
        raise AntiAmnesiaError(f"{label}:DESCRIPTORS_NOT_ARRAY")
    descriptor_names: List[str] = []
    descriptor_rows: List[Mapping[str, Any]] = []
    for index, descriptor in enumerate(descriptors):
        row = _require_exact_keys(
            descriptor,
            {
                "name",
                "logical_path",
                "size_bytes",
                "sha256",
                "verified",
            },
            f"{label}.descriptors[{index}]",
        )
        if not isinstance(row["name"], str):
            raise AntiAmnesiaError(f"{label}:INVALID_DESCRIPTOR_NAME")
        descriptor_names.append(row["name"])
        binding = {
            key: row[key]
            for key in ("logical_path", "size_bytes", "sha256", "verified")
        }
        _validate_nullable_hash_binding(
            binding, f"{label}.descriptors[{index}]"
        )
        descriptor_rows.append(row)
    expected_names = sorted(AUTHORITY_DESCRIPTORS)
    if descriptor_names != expected_names:
        raise AntiAmnesiaError(f"{label}:DESCRIPTOR_SET_OR_ORDER_MISMATCH")
    ready = _validate_nullable_hash_binding(
        authority["ready"], f"{label}.ready", ready=True
    )
    _require_exact_keys(
        authority["effect_ceiling"],
        {
            "auto_dispatch",
            "auto_accept",
            "self_application",
            "push",
            "deploy",
            "external_messages",
            "can_trade",
            "capital_permission",
        },
        f"{label}.effect_ceiling",
    )
    if not _effect_ceiling_valid(
        authority["effect_ceiling"], require_self_application=True
    ):
        raise AntiAmnesiaError(f"{label}:R63_EFFECT_CEILING_MISMATCH")
    if require_verified and (
        authority["generation"] != EXPECTED_AUTHORITY_GENERATION
        or not pointer["verified"]
        or not ready["verified"]
        or any(not row["verified"] for row in descriptor_rows)
    ):
        raise AntiAmnesiaError(f"{label}:UNVERIFIED_AUTHORITY_ON_READY_RECEIPT")
    return authority


def _validate_workspace_receipt(
    value: Any,
    label: str,
    *,
    require_verified: bool,
) -> Mapping[str, Any]:
    workspace = _require_exact_keys(
        value,
        {
            "read_order",
            "files",
            "latest_checkpoint_id",
            "state_checkpoint_match",
            "project_count",
            "open_loop_count",
            "active_open_loop_ids",
            "active_open_loops",
            "active_open_loops_digest",
            "transaction_journal_present",
            "context_digest",
        },
        label,
    )
    expected_paths = [logical for logical, _kind in WORKSPACE_INPUTS]
    if workspace["read_order"] != expected_paths:
        raise AntiAmnesiaError(f"{label}:READ_ORDER_MISMATCH")
    files = workspace["files"]
    if not isinstance(files, list):
        raise AntiAmnesiaError(f"{label}:FILES_NOT_ARRAY")
    actual_paths: List[str] = []
    for index, file_row in enumerate(files):
        row = _require_exact_keys(
            file_row,
            {"logical_path", "size_bytes", "sha256"},
            f"{label}.files[{index}]",
        )
        if not isinstance(row["logical_path"], str):
            raise AntiAmnesiaError(f"{label}:INVALID_FILE_PATH")
        if (
            not isinstance(row["size_bytes"], int)
            or isinstance(row["size_bytes"], bool)
            or row["size_bytes"] < 0
        ):
            raise AntiAmnesiaError(f"{label}:INVALID_FILE_SIZE")
        _require_sha(row["sha256"], f"{label}.files[{index}].sha256")
        actual_paths.append(row["logical_path"])
    expected_subset_order = [
        path for path in expected_paths if path in set(actual_paths)
    ]
    if actual_paths != expected_subset_order or len(actual_paths) != len(
        set(actual_paths)
    ):
        raise AntiAmnesiaError(f"{label}:FILE_SET_OR_ORDER_MISMATCH")
    if any(path not in expected_paths for path in actual_paths):
        raise AntiAmnesiaError(f"{label}:UNEXPECTED_FILE")
    if workspace["latest_checkpoint_id"] is not None and not isinstance(
        workspace["latest_checkpoint_id"], str
    ):
        raise AntiAmnesiaError(f"{label}:INVALID_CHECKPOINT_ID")
    _require_bool_type(
        workspace["state_checkpoint_match"],
        f"{label}.state_checkpoint_match",
    )
    for field in ("project_count", "open_loop_count"):
        if workspace[field] is not None and (
            not isinstance(workspace[field], int)
            or isinstance(workspace[field], bool)
            or workspace[field] < 0
        ):
            raise AntiAmnesiaError(f"{label}:INVALID_{field.upper()}")
    active_ids = workspace["active_open_loop_ids"]
    if (
        not isinstance(active_ids, list)
        or not all(isinstance(item, str) and item for item in active_ids)
        or active_ids != sorted(set(active_ids))
    ):
        raise AntiAmnesiaError(f"{label}:INVALID_ACTIVE_OPEN_LOOP_IDS")
    active_loops = workspace["active_open_loops"]
    if not isinstance(active_loops, list):
        raise AntiAmnesiaError(f"{label}:ACTIVE_OPEN_LOOPS_NOT_ARRAY")
    normalized_loops: List[Dict[str, Any]] = []
    for index, loop in enumerate(active_loops):
        row = _require_exact_keys(
            loop,
            {"id", "title", "status", "next_action"},
            f"{label}.active_open_loops[{index}]",
        )
        if (
            not isinstance(row["id"], str)
            or not row["id"]
            or not isinstance(row["title"], str)
            or not row["title"]
            or not isinstance(row["status"], str)
            or not row["status"]
            or (
                row["next_action"] is not None
                and not isinstance(row["next_action"], str)
            )
        ):
            raise AntiAmnesiaError(
                f"{label}:INVALID_ACTIVE_OPEN_LOOP_RECORD"
            )
        normalized_loops.append(dict(row))
    normalized_ids = [row["id"] for row in normalized_loops]
    if normalized_ids != sorted(set(normalized_ids)):
        raise AntiAmnesiaError(
            f"{label}:ACTIVE_OPEN_LOOP_ORDER_OR_DUPLICATE"
        )
    if active_ids != normalized_ids:
        raise AntiAmnesiaError(f"{label}:ACTIVE_OPEN_LOOP_ID_SET_MISMATCH")
    _require_sha(
        workspace["active_open_loops_digest"],
        f"{label}.active_open_loops_digest",
    )
    if workspace["active_open_loops_digest"] != sha256_canonical(
        normalized_loops
    ):
        raise AntiAmnesiaError(f"{label}:ACTIVE_OPEN_LOOP_DIGEST_MISMATCH")
    _require_bool_type(
        workspace["transaction_journal_present"],
        f"{label}.transaction_journal_present",
    )
    _require_sha(workspace["context_digest"], f"{label}.context_digest")
    digest_input = {
        "files": files,
        "latest_checkpoint_id": workspace["latest_checkpoint_id"],
        "project_count": workspace["project_count"],
        "open_loop_count": workspace["open_loop_count"],
        "active_open_loop_ids": active_ids,
        "active_open_loops": normalized_loops,
        "active_open_loops_digest": workspace["active_open_loops_digest"],
    }
    if workspace["context_digest"] != sha256_canonical(digest_input):
        raise AntiAmnesiaError(f"{label}:CONTEXT_DIGEST_MISMATCH")
    if require_verified and (
        actual_paths != expected_paths
        or not workspace["state_checkpoint_match"]
        or workspace["transaction_journal_present"]
        or workspace["project_count"] is None
        or workspace["open_loop_count"] != len(active_ids)
    ):
        raise AntiAmnesiaError(f"{label}:UNVERIFIED_WORKSPACE_ON_READY_RECEIPT")
    return workspace


def _validate_diagnostics(
    root: Mapping[str, Any],
    label: str,
    outcomes: Mapping[str, str],
) -> None:
    checks = root["checks"]
    if not isinstance(checks, list):
        raise AntiAmnesiaError(f"{label}:CHECKS_NOT_ARRAY")
    check_ids: List[str] = []
    derived_errors: List[str] = []
    derived_warnings: List[str] = []
    for index, check in enumerate(checks):
        row = _require_exact_keys(
            check,
            {"check_id", "status", "code"},
            f"{label}.checks[{index}]",
        )
        if not isinstance(row["check_id"], str) or not row["check_id"]:
            raise AntiAmnesiaError(f"{label}:INVALID_CHECK_ID")
        if row["status"] not in {"PASS", "WARN", "FAIL"}:
            raise AntiAmnesiaError(f"{label}:INVALID_CHECK_STATUS")
        if not isinstance(row["code"], str) or not row["code"]:
            raise AntiAmnesiaError(f"{label}:INVALID_CHECK_CODE")
        check_ids.append(row["check_id"])
        if row["status"] == "FAIL":
            derived_errors.append(row["code"])
        elif row["status"] == "WARN":
            derived_warnings.append(row["code"])
    if check_ids != sorted(check_ids) or len(check_ids) != len(set(check_ids)):
        raise AntiAmnesiaError(f"{label}:CHECK_SET_OR_ORDER_MISMATCH")
    errors = root["errors"]
    warnings = root["warnings"]
    if (
        not isinstance(errors, list)
        or not all(isinstance(item, str) for item in errors)
        or errors != sorted(set(derived_errors))
    ):
        raise AntiAmnesiaError(f"{label}:ERROR_DERIVATION_MISMATCH")
    if (
        not isinstance(warnings, list)
        or not all(isinstance(item, str) for item in warnings)
        or warnings != sorted(set(derived_warnings))
    ):
        raise AntiAmnesiaError(f"{label}:WARNING_DERIVATION_MISMATCH")
    expected_outcome = (
        "hold" if errors else "warning" if warnings else "pass"
    )
    expected_status = outcomes[expected_outcome]
    expected_outcome_name = {
        "boot": {
            "pass": "WOULD_ALLOW",
            "warning": "WOULD_ALLOW_WITH_WARNINGS",
            "hold": "WOULD_HOLD",
        },
        "close": {
            "pass": "WOULD_ACCEPT",
            "warning": "WOULD_ACCEPT_WITH_WARNINGS",
            "hold": "WOULD_HOLD",
        },
    }[label][expected_outcome]
    if (
        root["outcome"] != expected_outcome_name
        or root["status"] != expected_status
    ):
        raise AntiAmnesiaError(f"{label}:OUTCOME_DERIVATION_MISMATCH")


def validate_boot_receipt(receipt: Any) -> None:
    root = _require_exact_keys(
        receipt,
        {
            "schema", "gate", "mode", "command", "authority", "workspace",
            "binding", "checks", "errors", "warnings", "outcome", "status",
            "enforced", "live_state_reads_via_runtime_api", "live_state_modified",
            "r63_authority_replaced", "writes_performed", "can_trade",
            "capital_permission",
        },
        "boot",
    )
    if root["schema"] != "ANTI_AMNESIA_BOOT_RECEIPT_V1" or root["gate"] != GATE or root["mode"] != MODE:
        raise AntiAmnesiaError("boot:IDENTITY_MISMATCH")
    command = _require_exact_keys(root["command"], {"name", "role", "case_id"}, "boot.command")
    if command["name"] != "boot":
        raise AntiAmnesiaError("boot.command:NAME_MISMATCH")
    if not isinstance(command["role"], str):
        raise AntiAmnesiaError("boot.command:ROLE_NOT_STRING")
    if command["case_id"] is not None and not isinstance(command["case_id"], str):
        raise AntiAmnesiaError("boot.command:CASE_NOT_STRING_OR_NULL")
    _require_bool(root["enforced"], False, "boot.enforced")
    _require_bool(root["live_state_reads_via_runtime_api"], False, "boot.live_state_reads_via_runtime_api")
    _require_bool(root["live_state_modified"], False, "boot.live_state_modified")
    _require_bool(root["r63_authority_replaced"], False, "boot.r63_authority_replaced")
    _require_bool(root["can_trade"], False, "boot.can_trade")
    if root["capital_permission"] != "DENY" or root["writes_performed"] != []:
        raise AntiAmnesiaError("boot:EFFECT_CEILING_MISMATCH")
    _validate_diagnostics(
        root,
        "boot",
        {
            "pass": "SHADOW_READY",
            "warning": "SHADOW_READY_WITH_WARNINGS",
            "hold": "SHADOW_HOLD",
        },
    )
    usable = root["outcome"] != "WOULD_HOLD"
    _validate_authority_receipt(
        root["authority"], "boot.authority", require_verified=usable
    )
    _validate_workspace_receipt(
        root["workspace"], "boot.workspace", require_verified=usable
    )
    binding = _require_exact_keys(
        root["binding"], {"role", "case"}, "boot.binding"
    )
    role = _require_exact_keys(
        binding["role"],
        {
            "id",
            "json_pointer",
            "record_sha256",
            "state",
            "lane",
            "authority_status",
        },
        "boot.binding.role",
    )
    for field in ("id", "json_pointer", "state", "lane"):
        if role[field] is not None and not isinstance(role[field], str):
            raise AntiAmnesiaError(f"boot.binding.role:INVALID_{field.upper()}")
    if role["record_sha256"] is not None:
        _require_sha(
            role["record_sha256"], "boot.binding.role.record_sha256"
        )
    if role["authority_status"] not in {"UNRESOLVED", "EXACT_R63_ROLE"}:
        raise AntiAmnesiaError("boot.binding.role:INVALID_AUTHORITY_STATUS")
    case = _require_exact_keys(
        binding["case"],
        {"requested", "status", "authoritative", "matched_field"},
        "boot.binding.case",
    )
    if case["requested"] is not None and not isinstance(
        case["requested"], str
    ):
        raise AntiAmnesiaError("boot.binding.case:INVALID_REQUESTED")
    if case["status"] not in {
        "NOT_REQUESTED",
        "EXACT_STRUCTURED_MATCH",
        "CLI_ASSERTED_NON_AUTHORITY",
        "CONFLICT",
    }:
        raise AntiAmnesiaError("boot.binding.case:INVALID_STATUS")
    _require_bool_type(
        case["authoritative"], "boot.binding.case.authoritative"
    )
    if case["matched_field"] is not None and not isinstance(
        case["matched_field"], str
    ):
        raise AntiAmnesiaError("boot.binding.case:INVALID_MATCHED_FIELD")
    if case["authoritative"] is not (
        case["status"] == "EXACT_STRUCTURED_MATCH"
    ):
        raise AntiAmnesiaError("boot.binding.case:AUTHORITY_STATUS_MISMATCH")
    if usable:
        validate_role(command["role"])
        validate_case_id(command["case_id"])
        if (
            role["id"] != command["role"]
            or role["json_pointer"] != f"/roles/{command['role']}"
            or role["record_sha256"] is None
            or role["authority_status"] != "EXACT_R63_ROLE"
        ):
            raise AntiAmnesiaError("boot.binding.role:USABLE_BINDING_MISMATCH")
        if case["requested"] != command["case_id"]:
            raise AntiAmnesiaError("boot.binding.case:COMMAND_MISMATCH")
        if command["case_id"] is None:
            if (
                case["status"] != "NOT_REQUESTED"
                or case["matched_field"] is not None
            ):
                raise AntiAmnesiaError(
                    "boot.binding.case:NOT_REQUESTED_MISMATCH"
                )
        elif case["status"] == "EXACT_STRUCTURED_MATCH":
            if case["matched_field"] not in {
                "case_id",
                "work_order_id",
                "work_order",
                "current_case",
            }:
                raise AntiAmnesiaError(
                    "boot.binding.case:INVALID_MATCHED_FIELD"
                )
        elif (
            case["status"] != "CLI_ASSERTED_NON_AUTHORITY"
            or case["matched_field"] is not None
        ):
            raise AntiAmnesiaError("boot.binding.case:USABLE_BINDING_MISMATCH")


def validate_return_envelope(envelope: Any) -> None:
    root = _require_exact_keys(
        envelope,
        {
            "schema", "gate", "mode", "boot_receipt", "boot_binding", "terminal_state",
            "continuity_capsule", "work_delta", "product_delta", "effects",
            "artifacts", "tests",
        },
        "return",
    )
    if root["schema"] != "ANTI_AMNESIA_RETURN_V1" or root["gate"] != GATE or root["mode"] != MODE:
        raise AntiAmnesiaError("return:IDENTITY_MISMATCH")
    boot_receipt = _require_exact_keys(
        root["boot_receipt"],
        {"path", "sha256"},
        "return.boot_receipt",
    )
    _validate_return_names([boot_receipt["path"]])
    if boot_receipt["path"] == RETURN_ENVELOPE_NAME:
        raise AntiAmnesiaError("return.boot_receipt:ENVELOPE_SELF_REFERENCE")
    _require_sha(boot_receipt["sha256"], "return.boot_receipt.sha256")
    boot = _require_exact_keys(
        root["boot_binding"],
        {"context_digest", "r63_pointer_sha256", "role", "case_id", "case_binding"},
        "return.boot_binding",
    )
    _require_sha(boot["context_digest"], "return.boot_binding.context_digest")
    _require_sha(boot["r63_pointer_sha256"], "return.boot_binding.r63_pointer_sha256")
    validate_role(boot["role"])
    validate_case_id(boot["case_id"])
    if boot["case_binding"] not in {
        "NOT_REQUESTED", "EXACT_STRUCTURED_MATCH", "CLI_ASSERTED_NON_AUTHORITY"
    }:
        raise AntiAmnesiaError("return.boot_binding:INVALID_CASE_BINDING")
    if not isinstance(root["terminal_state"], str) or not root["terminal_state"].strip():
        raise AntiAmnesiaError("return:EMPTY_TERMINAL_STATE")
    capsule = _require_exact_keys(
        root["continuity_capsule"],
        {
            "state_digest", "drift_risks", "top_open_loops",
            "next_irreversible_action", "checkpoint_delta",
        },
        "return.continuity_capsule",
    )
    if not isinstance(capsule["state_digest"], list) or not capsule["state_digest"]:
        raise AntiAmnesiaError("return.continuity_capsule:EMPTY_STATE_DIGEST")
    if not all(isinstance(item, str) and item for item in capsule["state_digest"]):
        raise AntiAmnesiaError("return.continuity_capsule:INVALID_STATE_DIGEST")
    if not isinstance(capsule["drift_risks"], list) or not all(
        isinstance(item, str) for item in capsule["drift_risks"]
    ):
        raise AntiAmnesiaError("return.continuity_capsule:INVALID_DRIFT_RISKS")
    if not isinstance(capsule["top_open_loops"], list):
        raise AntiAmnesiaError("return.continuity_capsule:TOP_OPEN_LOOPS_NOT_ARRAY")
    reported_loop_ids: List[str] = []
    for index, loop in enumerate(capsule["top_open_loops"]):
        row = _require_exact_keys(
            loop,
            {"id", "title", "status", "next_action"},
            f"return.continuity_capsule.top_open_loops[{index}]",
        )
        for field in ("id", "title", "status"):
            if not isinstance(row[field], str) or not row[field]:
                raise AntiAmnesiaError(
                    f"return.continuity_capsule.top_open_loops[{index}]:"
                    f"INVALID_{field.upper()}"
                )
        if row["next_action"] is not None and not isinstance(
            row["next_action"], str
        ):
            raise AntiAmnesiaError(
                f"return.continuity_capsule.top_open_loops[{index}]:"
                "INVALID_NEXT_ACTION"
            )
        reported_loop_ids.append(row["id"])
    if (
        reported_loop_ids != sorted(reported_loop_ids)
        or len(reported_loop_ids) != len(set(reported_loop_ids))
    ):
        raise AntiAmnesiaError(
            "return.continuity_capsule:OPEN_LOOP_ORDER_OR_DUPLICATE"
        )
    if not isinstance(capsule["next_irreversible_action"], str) or not capsule["next_irreversible_action"].strip():
        raise AntiAmnesiaError("return.continuity_capsule:EMPTY_NEXT_ACTION")
    checkpoint = _require_exact_keys(
        capsule["checkpoint_delta"], {"action", "reference", "reason"},
        "return.continuity_capsule.checkpoint_delta",
    )
    if checkpoint["action"] not in {"NONE", "PROPOSED", "COMPLETED"}:
        raise AntiAmnesiaError("return.continuity_capsule:INVALID_CHECKPOINT_ACTION")
    if checkpoint["reference"] is not None and not isinstance(checkpoint["reference"], str):
        raise AntiAmnesiaError("return.continuity_capsule:INVALID_CHECKPOINT_REFERENCE")
    if not isinstance(checkpoint["reason"], str) or not checkpoint["reason"]:
        raise AntiAmnesiaError("return.continuity_capsule:EMPTY_CHECKPOINT_REASON")
    work = _require_exact_keys(
        root["work_delta"],
        {"summary", "state_changes", "source_changes", "unknowns"},
        "return.work_delta",
    )
    if not isinstance(work["summary"], str) or not work["summary"].strip():
        raise AntiAmnesiaError("return.work_delta:EMPTY_SUMMARY")
    for field in ("state_changes", "source_changes", "unknowns"):
        if not isinstance(work[field], list) or not all(isinstance(item, str) for item in work[field]):
            raise AntiAmnesiaError(f"return.work_delta:INVALID_{field.upper()}")
    product = _require_exact_keys(root["product_delta"], {"status", "evidence"}, "return.product_delta")
    if (
        product["status"] not in {"ZERO", "NONZERO", "UNKNOWN"}
        or not isinstance(product["evidence"], list)
        or not all(isinstance(item, str) for item in product["evidence"])
    ):
        raise AntiAmnesiaError("return.product_delta:INVALID")
    effects = _require_exact_keys(
        root["effects"],
        {
            "live_state_applied", "r63_authority_replaced", "return_registry_mutated",
            "checkpoint_created", "push", "deploy", "external_messages",
            "can_trade", "capital_permission",
        },
        "return.effects",
    )
    for field in (
        "live_state_applied", "r63_authority_replaced", "return_registry_mutated",
        "checkpoint_created", "push", "deploy", "external_messages", "can_trade",
    ):
        _require_bool(effects[field], False, f"return.effects.{field}")
    if effects["capital_permission"] != "DENY":
        raise AntiAmnesiaError("return.effects:CAPITAL_PERMISSION")
    if not isinstance(root["artifacts"], list) or not root["artifacts"]:
        raise AntiAmnesiaError("return:ARTIFACTS_NOT_ARRAY")
    artifact_paths: List[str] = []
    for index, artifact in enumerate(root["artifacts"]):
        row = _require_exact_keys(
            artifact, {"path", "size_bytes", "sha256"}, f"return.artifacts[{index}]"
        )
        if not isinstance(row["path"], str):
            raise AntiAmnesiaError(f"return.artifacts[{index}]:UNSAFE_PATH")
        if (
            not isinstance(row["size_bytes"], int)
            or isinstance(row["size_bytes"], bool)
            or row["size_bytes"] < 0
        ):
            raise AntiAmnesiaError(f"return.artifacts[{index}]:INVALID_SIZE")
        _require_sha(row["sha256"], f"return.artifacts[{index}].sha256")
        artifact_paths.append(row["path"])
    _validate_return_names(artifact_paths)
    if artifact_paths != sorted(artifact_paths):
        raise AntiAmnesiaError("return:ARTIFACT_ORDER_OR_DUPLICATE")
    if boot_receipt["path"] not in artifact_paths:
        raise AntiAmnesiaError("return:BOOT_RECEIPT_NOT_IN_ARTIFACTS")
    if not isinstance(root["tests"], list) or not root["tests"]:
        raise AntiAmnesiaError("return:TESTS_NOT_ARRAY")
    evidenced_pass_count = 0
    for index, test in enumerate(root["tests"]):
        row = _require_exact_keys(
            test,
            {"name", "result", "passed", "failed", "skipped", "evidence"},
            f"return.tests[{index}]",
        )
        if not isinstance(row["name"], str) or not row["name"]:
            raise AntiAmnesiaError(f"return.tests[{index}]:INVALID_NAME")
        if row["result"] not in {"PASS", "FAIL", "SKIP"}:
            raise AntiAmnesiaError(f"return.tests[{index}]:INVALID_RESULT")
        for field in ("passed", "failed", "skipped"):
            if not isinstance(row[field], int) or isinstance(row[field], bool) or row[field] < 0:
                raise AntiAmnesiaError(f"return.tests[{index}]:INVALID_{field.upper()}")
        if row["evidence"] is not None and not isinstance(row["evidence"], str):
            raise AntiAmnesiaError(f"return.tests[{index}]:INVALID_EVIDENCE")
        if (
            isinstance(row["evidence"], str)
            and row["evidence"] not in artifact_paths
        ):
            raise AntiAmnesiaError(
                f"return.tests[{index}]:EVIDENCE_NOT_IN_ARTIFACTS"
            )
        if row["result"] == "PASS" and (row["failed"] != 0 or row["passed"] < 1):
            raise AntiAmnesiaError(f"return.tests[{index}]:PASS_TALLY_MISMATCH")
        if row["result"] == "PASS":
            if not isinstance(row["evidence"], str):
                raise AntiAmnesiaError(
                    f"return.tests[{index}]:PASS_REQUIRES_EVIDENCE"
                )
            evidenced_pass_count += 1
        if row["result"] == "FAIL" and row["failed"] < 1:
            raise AntiAmnesiaError(f"return.tests[{index}]:FAIL_TALLY_MISMATCH")
        if row["result"] == "SKIP" and (
            row["passed"] != 0 or row["failed"] != 0 or row["skipped"] < 1
        ):
            raise AntiAmnesiaError(f"return.tests[{index}]:SKIP_TALLY_MISMATCH")
    if evidenced_pass_count < 1:
        raise AntiAmnesiaError("return:NO_EVIDENCED_PASS")


def _zip_member_is_symlink(info: zipfile.ZipInfo) -> bool:
    mode = (info.external_attr >> 16) & 0xFFFF
    return stat.S_ISLNK(mode)


def _validate_return_names(names: Sequence[str]) -> None:
    if len(names) > MAX_RETURN_FILES:
        raise AntiAmnesiaError("RETURN_FILE_COUNT_LIMIT")
    if len(names) != len(set(names)):
        raise AntiAmnesiaError("RETURN_DUPLICATE_PATH")
    normalized: List[str] = []
    for name in names:
        if not isinstance(name, str) or not name:
            raise AntiAmnesiaError("RETURN_UNSAFE_PATH")
        pure = PurePosixPath(name)
        canonical = pure.as_posix()
        unsafe_component = any(
            ":" in part
            or part.endswith((".", " "))
            or part.split(".", 1)[0].upper() in WINDOWS_RESERVED_NAMES
            for part in pure.parts
        )
        if (
            pure.is_absolute()
            or not pure.parts
            or any(part in {"", ".", ".."} for part in pure.parts)
            or "\\" in name
            or unsafe_component
            or name not in {canonical, canonical + "/"}
        ):
            raise AntiAmnesiaError("RETURN_UNSAFE_PATH")
        normalized.append(unicodedata.normalize("NFC", canonical).casefold())
    if len(normalized) != len(set(normalized)):
        raise AntiAmnesiaError("RETURN_CASEFOLD_COLLISION")


def _read_zip_return(path: Path) -> Tuple[Dict[str, bytes], Dict[str, Any]]:
    payload = stable_read_bytes(path, label="return.zip", max_bytes=MAX_RETURN_BYTES)
    files: Dict[str, bytes] = {}
    try:
        with zipfile.ZipFile(io.BytesIO(payload), "r") as archive:
            all_infos = archive.infolist()
            _validate_return_names([info.filename for info in all_infos])
            for info in all_infos:
                if info.flag_bits & 0x1:
                    raise AntiAmnesiaError("RETURN_ENCRYPTED_MEMBER")
                if _zip_member_is_symlink(info):
                    raise AntiAmnesiaError("RETURN_SYMLINK_MEMBER")
                unix_mode = (info.external_attr >> 16) & 0xFFFF
                file_type = stat.S_IFMT(unix_mode)
                if file_type and not (
                    stat.S_ISREG(unix_mode) or stat.S_ISDIR(unix_mode)
                ):
                    raise AntiAmnesiaError("RETURN_SPECIAL_FILE_MEMBER")
            infos = [info for info in all_infos if not info.is_dir()]
            names = [info.filename for info in infos]
            total = 0
            for info in infos:
                if info.file_size > MAX_ZIP_MEMBER_BYTES:
                    raise AntiAmnesiaError("RETURN_MEMBER_SIZE_LIMIT")
                total += info.file_size
                if total > MAX_RETURN_BYTES:
                    raise AntiAmnesiaError("RETURN_UNCOMPRESSED_SIZE_LIMIT")
                if info.file_size and (
                    info.compress_size == 0
                    or info.file_size / max(info.compress_size, 1) > MAX_ZIP_RATIO
                ):
                    raise AntiAmnesiaError("RETURN_COMPRESSION_RATIO_LIMIT")
            bad = archive.testzip()
            if bad is not None:
                raise AntiAmnesiaError("RETURN_ZIP_CRC_FAILURE")
            files = {info.filename: archive.read(info.filename) for info in infos}
    except AntiAmnesiaError:
        raise
    except (OSError, zipfile.BadZipFile, RuntimeError) as exc:
        raise AntiAmnesiaError("RETURN_INVALID_ZIP") from exc
    return files, {
        "kind": "ZIP",
        "content_sha256": sha256_bytes(payload),
        "size_bytes": len(payload),
        "entry_count": len(files),
    }


def _read_directory_return(path: Path) -> Tuple[Dict[str, bytes], Dict[str, Any]]:
    if path.is_symlink() or _is_reparse(path):
        raise AntiAmnesiaError("RETURN_REPARSE_DIRECTORY")
    try:
        root = path.resolve(strict=True)
    except OSError as exc:
        raise AntiAmnesiaError("RETURN_DIRECTORY_MISSING") from exc
    if not root.is_dir():
        raise AntiAmnesiaError("RETURN_NOT_DIRECTORY")

    def enumerate_members() -> List[Path]:
        members: List[Path] = []
        for current, directory_names, file_names in os.walk(
            root, topdown=True, followlinks=False
        ):
            current_path = Path(current)
            if current_path != root and (
                current_path.is_symlink() or _is_reparse(current_path)
            ):
                raise AntiAmnesiaError("RETURN_REPARSE_MEMBER")
            directory_names.sort()
            file_names.sort()
            for directory_name in directory_names:
                directory = current_path / directory_name
                if directory.is_symlink() or _is_reparse(directory):
                    raise AntiAmnesiaError("RETURN_REPARSE_MEMBER")
            for file_name in file_names:
                member = current_path / file_name
                if member.is_symlink() or _is_reparse(member):
                    raise AntiAmnesiaError("RETURN_REPARSE_MEMBER")
                if not member.is_file():
                    raise AntiAmnesiaError("RETURN_NON_REGULAR_MEMBER")
                if member.stat().st_nlink != 1:
                    raise AntiAmnesiaError("RETURN_HARDLINK_MEMBER")
                members.append(member)
        return sorted(
            members, key=lambda item: item.relative_to(root).as_posix()
        )

    paths = enumerate_members()
    names = [item.relative_to(root).as_posix() for item in paths]
    _validate_return_names(names)
    files: Dict[str, bytes] = {}
    total = 0
    for name, item in zip(names, paths):
        if item.is_symlink() or _is_reparse(item):
            raise AntiAmnesiaError("RETURN_REPARSE_MEMBER")
        payload = stable_read_bytes(item, label=f"return.{name}", max_bytes=MAX_ZIP_MEMBER_BYTES)
        total += len(payload)
        if total > MAX_RETURN_BYTES:
            raise AntiAmnesiaError("RETURN_SIZE_LIMIT")
        files[name] = payload
    after_paths = enumerate_members()
    after_names = [item.relative_to(root).as_posix() for item in after_paths]
    if after_names != names:
        raise AntiAmnesiaError("RETURN_DIRECTORY_CHANGED_DURING_READ")
    for name, item in zip(after_names, after_paths):
        second_payload = stable_read_bytes(
            item,
            label=f"return.recheck.{name}",
            max_bytes=MAX_ZIP_MEMBER_BYTES,
        )
        if second_payload != files[name]:
            raise AntiAmnesiaError("RETURN_DIRECTORY_CHANGED_DURING_READ")
    inventory = [
        {"path": name, "size_bytes": len(files[name]), "sha256": sha256_bytes(files[name])}
        for name in names
    ]
    return files, {
        "kind": "DIRECTORY",
        "content_sha256": sha256_canonical(inventory),
        "size_bytes": total,
        "entry_count": len(files),
    }


def _validate_artifact_inventory(files: Mapping[str, bytes], envelope: Mapping[str, Any]) -> None:
    actual_names = sorted(name for name in files if name != RETURN_ENVELOPE_NAME)
    declared_rows = envelope["artifacts"]
    declared_names = [row["path"] for row in declared_rows]
    if actual_names != declared_names:
        raise AntiAmnesiaError("RETURN_ARTIFACT_INVENTORY_MISMATCH")
    for row in declared_rows:
        payload = files[row["path"]]
        if len(payload) != row["size_bytes"] or sha256_bytes(payload) != row["sha256"]:
            raise AntiAmnesiaError(f"RETURN_ARTIFACT_HASH_MISMATCH:{row['path']}")


def _validate_boot_receipt_artifact(
    files: Mapping[str, bytes],
    envelope: Mapping[str, Any],
    authority_docs: Mapping[str, Any],
    current_authority: Mapping[str, Any],
    current_workspace: Mapping[str, Any],
    expected_boot_receipt: Mapping[str, Any],
) -> Mapping[str, Any]:
    descriptor = envelope["boot_receipt"]
    path = descriptor["path"]
    payload = files.get(path)
    if payload is None:
        raise AntiAmnesiaError("BOOT_RECEIPT_ARTIFACT_MISSING")
    if sha256_bytes(payload) != descriptor["sha256"]:
        raise AntiAmnesiaError("BOOT_RECEIPT_ARTIFACT_HASH_MISMATCH")
    artifact_rows = {
        row["path"]: row for row in envelope["artifacts"]
    }
    artifact = artifact_rows.get(path)
    if artifact is None or artifact["sha256"] != descriptor["sha256"]:
        raise AntiAmnesiaError("BOOT_RECEIPT_ARTIFACT_BINDING_MISMATCH")
    parsed = strict_json_loads(payload, path)
    validate_boot_receipt(parsed)
    if (
        parsed["outcome"] == "WOULD_HOLD"
        or parsed["binding"]["role"]["authority_status"] != "EXACT_R63_ROLE"
    ):
        raise AntiAmnesiaError("BOOT_RECEIPT_NOT_USABLE")
    expected_binding = {
        "context_digest": parsed["workspace"]["context_digest"],
        "r63_pointer_sha256": parsed["authority"]["pointer"]["sha256"],
        "role": parsed["command"]["role"],
        "case_id": parsed["command"]["case_id"],
        "case_binding": parsed["binding"]["case"]["status"],
    }
    if envelope["boot_binding"] != expected_binding:
        raise AntiAmnesiaError("BOOT_RECEIPT_DECLARATION_MISMATCH")
    if parsed["authority"] != current_authority:
        raise AntiAmnesiaError("BOOT_RECEIPT_AUTHORITY_STALE")
    if parsed["workspace"] != current_workspace:
        raise AntiAmnesiaError("BOOT_RECEIPT_WORKSPACE_STALE")
    reported_loops = envelope["continuity_capsule"]["top_open_loops"]
    reported_loop_ids = [row["id"] for row in reported_loops]
    if reported_loop_ids != parsed["workspace"]["active_open_loop_ids"]:
        raise AntiAmnesiaError("RETURN_OPEN_LOOP_SET_MISMATCH")
    if reported_loops != parsed["workspace"]["active_open_loops"]:
        raise AntiAmnesiaError("RETURN_OPEN_LOOP_SEMANTICS_MISMATCH")
    views = authority_docs.get("role_views")
    current_record = None
    if (
        isinstance(views, dict)
        and isinstance(views.get("roles"), dict)
    ):
        current_record = views["roles"].get(parsed["command"]["role"])
    if (
        not isinstance(current_record, dict)
        or sha256_canonical(current_record)
        != parsed["binding"]["role"]["record_sha256"]
    ):
        raise AntiAmnesiaError("BOOT_RECEIPT_ROLE_RECORD_STALE")
    requested_case = parsed["command"]["case_id"]
    case_binding = parsed["binding"]["case"]
    structured_cases = {
        field: current_record.get(field)
        for field in (
            "case_id",
            "work_order_id",
            "work_order",
            "current_case",
        )
        if isinstance(current_record.get(field), str)
    }
    if requested_case is None:
        case_current = case_binding["status"] == "NOT_REQUESTED"
    elif case_binding["status"] == "EXACT_STRUCTURED_MATCH":
        case_current = (
            case_binding["matched_field"] in structured_cases
            and structured_cases[case_binding["matched_field"]]
            == requested_case
        )
    else:
        case_current = (
            case_binding["status"] == "CLI_ASSERTED_NON_AUTHORITY"
            and not structured_cases
        )
    if not case_current:
        raise AntiAmnesiaError("BOOT_RECEIPT_CASE_BINDING_NOT_CURRENT")
    if parsed != expected_boot_receipt:
        raise AntiAmnesiaError("BOOT_RECEIPT_NOT_CURRENT_EXACT")
    return parsed


def build_close_receipt(
    return_path: Any,
    dry_run: Any,
    *,
    control_root: Optional[Path] = None,
    workspace_root: Optional[Path] = None,
) -> Dict[str, Any]:
    authority, authority_docs, authority_checks, authority_errors, authority_warnings = bind_r63_authority(control_root)
    workspace, _workspace_docs, workspace_checks, workspace_errors, workspace_warnings = bind_workspace(workspace_root)
    checks = [*authority_checks, *workspace_checks]
    errors = [*authority_errors, *workspace_errors]
    warnings = [*authority_warnings, *workspace_warnings]
    candidate = {
        "kind": None,
        "content_sha256": None,
        "size_bytes": None,
        "entry_count": None,
        "envelope_sha256": None,
    }

    if dry_run is not True:
        _record(checks, errors, warnings, "close.dry_run", "FAIL", "CLOSE_REQUIRES_DRY_RUN")
    else:
        _record(checks, errors, warnings, "close.dry_run", "PASS", "VERIFIED")

    files: Dict[str, bytes] = {}
    envelope: Optional[Mapping[str, Any]] = None
    if not isinstance(return_path, (str, os.PathLike)) or not str(return_path):
        _record(checks, errors, warnings, "close.return_path", "FAIL", "INVALID_RETURN_PATH")
    else:
        path = Path(return_path).expanduser()
        try:
            if path.is_dir():
                files, metadata = _read_directory_return(path)
            elif path.is_file():
                if path.suffix.lower() != ".zip":
                    raise AntiAmnesiaError("RETURN_FILE_MUST_BE_ZIP")
                files, metadata = _read_zip_return(path)
            else:
                raise AntiAmnesiaError("RETURN_PATH_MISSING")
            candidate.update(metadata)
            _record(checks, errors, warnings, "close.return_path", "PASS", "VERIFIED")
        except AntiAmnesiaError as exc:
            _record(checks, errors, warnings, "close.return_path", "FAIL", str(exc))

    if files:
        try:
            payload = files.get(RETURN_ENVELOPE_NAME)
            if payload is None:
                raise AntiAmnesiaError("RETURN_ENVELOPE_MISSING")
            parsed = strict_json_loads(payload, RETURN_ENVELOPE_NAME)
            validate_return_envelope(parsed)
            envelope = parsed
            candidate["envelope_sha256"] = sha256_bytes(payload)
            _validate_artifact_inventory(files, envelope)
        except AntiAmnesiaError as exc:
            _record(checks, errors, warnings, "close.return_envelope", "FAIL", str(exc))
        else:
            _record(checks, errors, warnings, "close.return_envelope", "PASS", "VERIFIED")
    else:
        _record(
            checks,
            errors,
            warnings,
            "close.return_envelope",
            "FAIL",
            "RETURN_ENVELOPE_MISSING",
        )

    if envelope is not None:
        boot = envelope["boot_binding"]
        expected_boot_receipt = build_boot_receipt(
            boot["role"],
            boot["case_id"],
            control_root=control_root,
            workspace_root=workspace_root,
        )
        close_snapshot_stable = (
            expected_boot_receipt["authority"] == authority
            and expected_boot_receipt["workspace"] == workspace
        )
        _record(
            checks,
            errors,
            warnings,
            "close.input_snapshot_stability",
            "PASS" if close_snapshot_stable else "FAIL",
            "VERIFIED"
            if close_snapshot_stable
            else "CLOSE_INPUT_SNAPSHOT_CHANGED",
        )
        try:
            _validate_boot_receipt_artifact(
                files,
                envelope,
                authority_docs,
                authority,
                workspace,
                expected_boot_receipt,
            )
        except AntiAmnesiaError as exc:
            _record(
                checks,
                errors,
                warnings,
                "close.boot_receipt",
                "FAIL",
                str(exc),
            )
        else:
            _record(
                checks,
                errors,
                warnings,
                "close.boot_receipt",
                "PASS",
                "VERIFIED",
            )
        pointer_sha = authority.get("pointer", {}).get("sha256")
        current_binding_ok = (
            boot["context_digest"] == workspace.get("context_digest")
            and boot["r63_pointer_sha256"] == pointer_sha
        )
        _record(
            checks,
            errors,
            warnings,
            "close.current_binding",
            "PASS" if current_binding_ok else "FAIL",
            "VERIFIED" if current_binding_ok else "RETURN_BOOT_BINDING_STALE",
        )
        role = boot["role"]
        views = authority_docs.get("role_views")
        role_exists = (
            isinstance(views, dict)
            and isinstance(views.get("roles"), dict)
            and isinstance(views["roles"].get(role), dict)
        )
        _record(
            checks,
            errors,
            warnings,
            "close.role_current",
            "PASS" if role_exists else "FAIL",
            "VERIFIED" if role_exists else "RETURN_ROLE_NOT_IN_CURRENT_R63",
        )
        if boot["case_binding"] == "CLI_ASSERTED_NON_AUTHORITY":
            _record(
                checks,
                errors,
                warnings,
                "close.case_authority",
                "WARN",
                "CASE_REMAINS_NON_AUTHORITATIVE",
            )
        else:
            _record(checks, errors, warnings, "close.case_authority", "PASS", "VERIFIED")
        failed_tests = any(
            isinstance(row, dict) and row.get("result") == "FAIL"
            for row in envelope["tests"]
        )
        _record(
            checks,
            errors,
            warnings,
            "close.technical_tests",
            "WARN" if failed_tests else "PASS",
            "RETURN_CONTAINS_FAILED_TESTS" if failed_tests else "VERIFIED",
        )

    checks = sorted(checks, key=lambda row: row["check_id"])
    errors = sorted(set(errors))
    warnings = sorted(set(warnings))
    if errors:
        outcome = "WOULD_HOLD"
        status_value = "SHADOW_HOLD"
    elif warnings:
        outcome = "WOULD_ACCEPT_WITH_WARNINGS"
        status_value = "SHADOW_ACCEPTABLE_WITH_WARNINGS"
    else:
        outcome = "WOULD_ACCEPT"
        status_value = "SHADOW_ACCEPTABLE"
    receipt = {
        "schema": "ANTI_AMNESIA_CLOSE_RECEIPT_V1",
        "gate": GATE,
        "mode": MODE,
        "command": {
            "name": "close",
            "dry_run": dry_run is True,
        },
        "authority": authority,
        "workspace": workspace,
        "candidate": candidate,
        "checks": checks,
        "errors": errors,
        "warnings": warnings,
        "outcome": outcome,
        "status": status_value,
        "closed": False,
        "enforced": False,
        "live_state_reads_via_runtime_api": False,
        "live_state_modified": False,
        "r63_authority_replaced": False,
        "writes_performed": [],
        "can_trade": False,
        "capital_permission": "DENY",
    }
    validate_close_receipt(receipt)
    return receipt


def validate_close_receipt(receipt: Any) -> None:
    root = _require_exact_keys(
        receipt,
        {
            "schema", "gate", "mode", "command", "authority", "workspace",
            "candidate", "checks", "errors", "warnings", "outcome", "status",
            "closed", "enforced", "live_state_reads_via_runtime_api",
            "live_state_modified", "r63_authority_replaced", "writes_performed",
            "can_trade", "capital_permission",
        },
        "close",
    )
    if root["schema"] != "ANTI_AMNESIA_CLOSE_RECEIPT_V1" or root["gate"] != GATE or root["mode"] != MODE:
        raise AntiAmnesiaError("close:IDENTITY_MISMATCH")
    command = _require_exact_keys(root["command"], {"name", "dry_run"}, "close.command")
    if command["name"] != "close" or not isinstance(command["dry_run"], bool):
        raise AntiAmnesiaError("close.command:INVALID")
    for field in (
        "closed", "enforced", "live_state_reads_via_runtime_api",
        "live_state_modified", "r63_authority_replaced", "can_trade",
    ):
        _require_bool(root[field], False, f"close.{field}")
    if root["capital_permission"] != "DENY" or root["writes_performed"] != []:
        raise AntiAmnesiaError("close:EFFECT_CEILING_MISMATCH")
    _validate_diagnostics(
        root,
        "close",
        {
            "pass": "SHADOW_ACCEPTABLE",
            "warning": "SHADOW_ACCEPTABLE_WITH_WARNINGS",
            "hold": "SHADOW_HOLD",
        },
    )
    usable = root["outcome"] != "WOULD_HOLD"
    _validate_authority_receipt(
        root["authority"], "close.authority", require_verified=usable
    )
    _validate_workspace_receipt(
        root["workspace"], "close.workspace", require_verified=usable
    )
    candidate = _require_exact_keys(
        root["candidate"],
        {
            "kind",
            "content_sha256",
            "size_bytes",
            "entry_count",
            "envelope_sha256",
        },
        "close.candidate",
    )
    if candidate["kind"] not in {None, "ZIP", "DIRECTORY"}:
        raise AntiAmnesiaError("close.candidate:INVALID_KIND")
    for field in ("content_sha256", "envelope_sha256"):
        if candidate[field] is not None:
            _require_sha(candidate[field], f"close.candidate.{field}")
    for field in ("size_bytes", "entry_count"):
        if candidate[field] is not None and (
            not isinstance(candidate[field], int)
            or isinstance(candidate[field], bool)
            or candidate[field] < 0
        ):
            raise AntiAmnesiaError(
                f"close.candidate:INVALID_{field.upper()}"
            )
    identity_fields = (
        candidate["content_sha256"],
        candidate["size_bytes"],
        candidate["entry_count"],
        candidate["envelope_sha256"],
    )
    if candidate["kind"] is None and any(
        item is not None for item in identity_fields
    ):
        raise AntiAmnesiaError("close.candidate:PARTIAL_IDENTITY")
    if usable:
        if command["dry_run"] is not True:
            raise AntiAmnesiaError("close.command:READY_WITHOUT_DRY_RUN")
        if (
            candidate["kind"] not in {"ZIP", "DIRECTORY"}
            or candidate["content_sha256"] is None
            or candidate["envelope_sha256"] is None
            or candidate["size_bytes"] is None
            or candidate["entry_count"] is None
            or candidate["entry_count"] < 2
        ):
            raise AntiAmnesiaError("close.candidate:UNVERIFIED_READY_CANDIDATE")
        checks_by_id = {
            row["check_id"]: row for row in root["checks"]
        }
        for required_check in (
            "close.return_path",
            "close.return_envelope",
            "close.boot_receipt",
            "close.current_binding",
            "close.role_current",
            "close.dry_run",
            "close.input_snapshot_stability",
        ):
            if checks_by_id.get(required_check, {}).get("status") != "PASS":
                raise AntiAmnesiaError(
                    f"close:READY_WITHOUT_{required_check.upper()}"
                )
        if checks_by_id.get("close.technical_tests", {}).get(
            "status"
        ) not in {"PASS", "WARN"}:
            raise AntiAmnesiaError(
                "close:READY_WITHOUT_CLOSE.TECHNICAL_TESTS"
            )


def build_internal_error_receipt(command: Any, error: BaseException) -> Dict[str, Any]:
    receipt = {
        "schema": "ANTI_AMNESIA_CLI_INTERNAL_ERROR_V1",
        "gate": GATE,
        "mode": MODE,
        "command": command if command in {"boot", "close"} else "unknown",
        "error_type": type(error).__name__,
        "outcome": "WOULD_HOLD",
        "enforced": False,
        "live_state_modified": False,
        "r63_authority_replaced": False,
        "writes_performed": [],
        "can_trade": False,
        "capital_permission": "DENY",
    }
    validate_internal_error_receipt(receipt)
    return receipt


def validate_internal_error_receipt(receipt: Any) -> None:
    root = _require_exact_keys(
        receipt,
        {
            "schema",
            "gate",
            "mode",
            "command",
            "error_type",
            "outcome",
            "enforced",
            "live_state_modified",
            "r63_authority_replaced",
            "writes_performed",
            "can_trade",
            "capital_permission",
        },
        "internal_error",
    )
    if (
        root["schema"] != "ANTI_AMNESIA_CLI_INTERNAL_ERROR_V1"
        or root["gate"] != GATE
        or root["mode"] != MODE
        or root["command"] not in {"boot", "close", "unknown"}
        or root["outcome"] != "WOULD_HOLD"
        or not isinstance(root["error_type"], str)
        or not root["error_type"]
    ):
        raise AntiAmnesiaError("internal_error:IDENTITY_MISMATCH")
    for field in (
        "enforced",
        "live_state_modified",
        "r63_authority_replaced",
        "can_trade",
    ):
        _require_bool(root[field], False, f"internal_error.{field}")
    if root["writes_performed"] != [] or root["capital_permission"] != "DENY":
        raise AntiAmnesiaError("internal_error:EFFECT_CEILING_MISMATCH")


def exit_code_for_receipt(receipt: Mapping[str, Any]) -> int:
    outcome = receipt.get("outcome")
    if outcome in {"WOULD_ALLOW", "WOULD_ACCEPT"}:
        return EXIT_PASS
    if outcome in {"WOULD_ALLOW_WITH_WARNINGS", "WOULD_ACCEPT_WITH_WARNINGS"}:
        return EXIT_WARN
    return EXIT_HOLD


def emit_receipt(receipt: Mapping[str, Any], stream: Any = None) -> None:
    target = stream if stream is not None else os.sys.stdout
    target.write(canonical_json_text(receipt))
    target.write("\n")
