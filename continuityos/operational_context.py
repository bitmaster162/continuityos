"""Deterministic, bounded context projection from Common Operational Memory.

The bridge exports a controller-authored, evidence-bound context pack for one
ANTI_AMNESIA session capsule. It is read-only by construction:

* the operational database is opened with SQLite ``mode=ro&immutable=1``;
* the whole database is verified before projection;
* a named checkpoint fixes the event cursor;
* exact subjects, evidence classes, decision states and byte budgets come from a
  controller-authored spec;
* overflow fails closed rather than silently truncating material state;
* broker custody is summarized without copying arbitrary source values;
* the output is canonically serialized and hash-bound to the session capsule,
  checkpoint and memory projection.

This module does not accept content, apply state, update R63, dispatch agents,
deploy, trade or grant capital permission.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
import uuid
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from .operational_memory import (
    DECISION_STATES,
    EVIDENCE_STATES,
    OperationalMemory,
    PolicyViolation,
    _canonical_json,
    _normalize_time,
    _sha256_text,
    resolve_operational_db,
    strict_json_loads,
)

SCHEMA_SPEC = "CONTINUITYOS_OPERATIONAL_CONTEXT_SPEC_V1"
SCHEMA_PACK = "CONTINUITYOS_OPERATIONAL_CONTEXT_PACK_V1"
SCHEMA_PREPARE_RECEIPT = "CONTINUITYOS_OPERATIONAL_CONTEXT_PREPARE_RECEIPT_V1"
SCHEMA_VERIFY_RECEIPT = "CONTINUITYOS_OPERATIONAL_CONTEXT_VERIFY_RECEIPT_V1"
SCHEMA_SESSION_CAPSULE = "ANTI_AMNESIA_SESSION_CAPSULE_V1"
AUTHORITY_GENERATION = "R63"
MAX_INPUT_BYTES = 4 * 1024 * 1024
ABSOLUTE_MAX_OUTPUT_BYTES = 1024 * 1024
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_GIT_OBJECT_RE = re.compile(r"^[0-9a-f]{40,64}$")
_WORK_ORDER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,191}$")

_CAPSULE_KEYS = {
    "schema",
    "challenge_id",
    "authority_generation",
    "role",
    "active_case",
    "case_binding",
    "work_order_id",
    "role_state",
    "role_lane",
    "workspace_context_digest",
    "current_pointer_sha256",
    "latest_checkpoint_id",
    "active_open_loop_ids",
    "goal",
    "accepted_decisions",
    "rejected_alternatives",
    "allowed_changes",
    "forbidden_actions",
    "immutable_decisions",
    "git_baseline",
    "next_action",
    "terminal_condition",
    "effect_ceiling",
    "may_dispatch_codex",
    "can_trade",
    "capital_permission",
    "boot_status",
    "boot_outcome",
    "boot_warnings",
}

_PACK_KEYS = {
    "schema",
    "authority_generation",
    "role",
    "active_case",
    "work_order_id",
    "session_binding",
    "memory_binding",
    "selection",
    "claims",
    "decisions",
    "broker_custody_summary",
    "ceilings",
    "context_sha256",
}

_SPEC_KEYS = {
    "schema",
    "checkpoint_id",
    "subjects",
    "claim_predicates",
    "evidence_states",
    "decision_states",
    "include_broker_summary",
    "max_claims",
    "max_decisions",
    "max_output_bytes",
    "valid_at",
}


class OperationalContextError(RuntimeError):
    """Context input, selection or verification failed."""


def _canonical_bytes(value: Any) -> bytes:
    return _canonical_json(value).encode("utf-8")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _exact_keys(value: Any, expected: Iterable[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise OperationalContextError(f"{label}:NOT_OBJECT")
    want = set(expected)
    got = set(value)
    if want != got:
        raise OperationalContextError(
            f"{label}:KEYS:missing={sorted(want - got)}:extra={sorted(got - want)}"
        )
    return value


def _nonempty(value: Any, label: str, *, max_length: int = 4096) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > max_length:
        raise OperationalContextError(f"{label}:INVALID_STRING")
    return value.strip()


def _string_list(
    value: Any,
    label: str,
    *,
    min_items: int = 0,
    max_items: int = 256,
) -> List[str]:
    if not isinstance(value, list) or not (min_items <= len(value) <= max_items):
        raise OperationalContextError(f"{label}:INVALID_LIST")
    out = [_nonempty(item, f"{label}[{idx}]", max_length=512) for idx, item in enumerate(value)]
    if len(out) != len(set(out)):
        raise OperationalContextError(f"{label}:DUPLICATE_ITEMS")
    return out


def _bounded_int(value: Any, label: str, *, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not (minimum <= value <= maximum):
        raise OperationalContextError(f"{label}:OUT_OF_RANGE")
    return value


def _safe_regular_file(
    path: Path,
    label: str,
    *,
    max_bytes: Optional[int] = MAX_INPUT_BYTES,
) -> Path:
    p = Path(path).expanduser().absolute()
    if not p.exists() or not p.is_file():
        raise OperationalContextError(f"{label}:MISSING_FILE")
    info = p.lstat()
    if stat.S_ISLNK(info.st_mode):
        raise OperationalContextError(f"{label}:SYMLINK_REFUSED")
    attrs = getattr(info, "st_file_attributes", 0)
    if attrs & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400):
        raise OperationalContextError(f"{label}:REPARSE_REFUSED")
    if max_bytes is not None and info.st_size > max_bytes:
        raise OperationalContextError(f"{label}:TOO_LARGE")
    return p


def _stable_read(path: Path, label: str) -> Tuple[bytes, str]:
    p = _safe_regular_file(path, label)
    first_stat = p.stat()
    first = p.read_bytes()
    second = p.read_bytes()
    second_stat = p.stat()
    if first != second or (
        first_stat.st_size,
        first_stat.st_mtime_ns,
        first_stat.st_ino,
    ) != (
        second_stat.st_size,
        second_stat.st_mtime_ns,
        second_stat.st_ino,
    ):
        raise OperationalContextError(f"{label}:DRIFT_DURING_READ")
    return first, _sha256_bytes(first)


def _file_identity(path: Path) -> Optional[Tuple[int, int, int]]:
    if not path.exists():
        return None
    st = path.stat()
    return (st.st_size, st.st_mtime_ns, st.st_ino)


def _database_identity(
    path: str,
) -> Tuple[str, Tuple[Tuple[int, int, int], Optional[Tuple[int, int, int]], Optional[Tuple[int, int, int]]]]:
    resolved = resolve_operational_db(path)
    p = _safe_regular_file(Path(resolved), "operational_db", max_bytes=None)
    wal = Path(str(p) + "-wal")
    shm = Path(str(p) + "-shm")
    if wal.exists() and wal.stat().st_size > 0:
        raise OperationalContextError("operational_db:DATABASE_NOT_QUIESCENT")
    main_identity = _file_identity(p)
    if main_identity is None:  # defensive; _safe_regular_file already checked
        raise OperationalContextError("operational_db:MISSING_FILE")
    return str(p), (main_identity, _file_identity(wal), _file_identity(shm))


def _assert_database_unchanged(
    path: str,
    identity: Tuple[Tuple[int, int, int], Optional[Tuple[int, int, int]], Optional[Tuple[int, int, int]]],
) -> None:
    p = _safe_regular_file(Path(path), "operational_db", max_bytes=None)
    current = (
        _file_identity(p),
        _file_identity(Path(str(p) + "-wal")),
        _file_identity(Path(str(p) + "-shm")),
    )
    if current != identity:
        raise OperationalContextError("operational_db:DRIFT_DURING_CONTEXT_BUILD")


def _validate_sha(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
        raise OperationalContextError(f"{label}:INVALID_SHA256")
    return value


def _validate_capsule(value: Any) -> Dict[str, Any]:
    row = _exact_keys(value, _CAPSULE_KEYS, "session_capsule")
    if row["schema"] != SCHEMA_SESSION_CAPSULE:
        raise OperationalContextError("session_capsule.schema:UNSUPPORTED")
    if row["authority_generation"] != AUTHORITY_GENERATION:
        raise OperationalContextError("session_capsule.authority_generation:NOT_R63")
    _validate_sha(row["challenge_id"], "session_capsule.challenge_id")
    _validate_sha(row["workspace_context_digest"], "session_capsule.workspace_context_digest")
    _validate_sha(row["current_pointer_sha256"], "session_capsule.current_pointer_sha256")
    role = _nonempty(row["role"], "session_capsule.role", max_length=128)
    case_id = row["active_case"]
    if case_id is not None:
        case_id = _nonempty(case_id, "session_capsule.active_case", max_length=192)
    if row["case_binding"] not in {"NOT_REQUESTED", "EXACT_STRUCTURED_MATCH"}:
        raise OperationalContextError("session_capsule.case_binding:INVALID")
    if case_id is None and row["case_binding"] != "NOT_REQUESTED":
        raise OperationalContextError("session_capsule.case_binding:CASE_MISMATCH")
    if case_id is not None and row["case_binding"] != "EXACT_STRUCTURED_MATCH":
        raise OperationalContextError("session_capsule.case_binding:CASE_NOT_EXACT")
    work_order_id = row["work_order_id"]
    if not isinstance(work_order_id, str) or not _WORK_ORDER_RE.fullmatch(work_order_id):
        raise OperationalContextError("session_capsule.work_order_id:INVALID")
    for field in (
        "active_open_loop_ids",
        "accepted_decisions",
        "rejected_alternatives",
        "allowed_changes",
        "forbidden_actions",
        "immutable_decisions",
        "boot_warnings",
    ):
        _string_list(row[field], f"session_capsule.{field}")
    for field in ("role_state", "role_lane", "goal", "next_action", "terminal_condition"):
        _nonempty(row[field], f"session_capsule.{field}")
    if row["effect_ceiling"] != "READ_ONLY":
        raise OperationalContextError("session_capsule.effect_ceiling:MUST_BE_READ_ONLY")
    required_immutable = {
        "can_trade=false",
        "capital_permission=DENY",
        "deploy_permission=DENY",
        "self_application=false",
    }
    if not required_immutable.issubset(set(row["immutable_decisions"])):
        raise OperationalContextError("session_capsule.immutable_decisions:MISSING_DENY_CEILING")
    baseline = _exact_keys(
        row["git_baseline"],
        {"repository", "branch", "head", "tree", "porcelain"},
        "session_capsule.git_baseline",
    )
    _nonempty(baseline["repository"], "session_capsule.git_baseline.repository")
    _nonempty(baseline["branch"], "session_capsule.git_baseline.branch", max_length=255)
    for field in ("head", "tree"):
        if not isinstance(baseline[field], str) or not _GIT_OBJECT_RE.fullmatch(baseline[field]):
            raise OperationalContextError(f"session_capsule.git_baseline.{field}:INVALID")
    if baseline["porcelain"] != "":
        raise OperationalContextError("session_capsule.git_baseline:DIRTY")
    if row["may_dispatch_codex"] is not False:
        raise OperationalContextError("session_capsule.may_dispatch_codex:MUST_BE_FALSE")
    if row["can_trade"] is not False or row["capital_permission"] != "DENY":
        raise OperationalContextError("session_capsule:PERMISSION_CEILING_VIOLATION")
    if row["boot_status"] not in {"SHADOW_READY", "SHADOW_READY_WITH_WARNINGS"}:
        raise OperationalContextError("session_capsule.boot_status:INVALID")
    if row["boot_outcome"] not in {"WOULD_ALLOW", "WOULD_ALLOW_WITH_WARNINGS"}:
        raise OperationalContextError("session_capsule.boot_outcome:INVALID")
    return dict(row)


def validate_context_spec(value: Any) -> Dict[str, Any]:
    row = _exact_keys(value, _SPEC_KEYS, "context_spec")
    if row["schema"] != SCHEMA_SPEC:
        raise OperationalContextError("context_spec.schema:UNSUPPORTED")
    checkpoint_id = _nonempty(row["checkpoint_id"], "context_spec.checkpoint_id", max_length=192)
    subjects = _string_list(row["subjects"], "context_spec.subjects", min_items=1, max_items=128)
    predicates = _string_list(row["claim_predicates"], "context_spec.claim_predicates", max_items=128)
    evidence_states = _string_list(row["evidence_states"], "context_spec.evidence_states", min_items=1)
    if not set(evidence_states).issubset(EVIDENCE_STATES):
        raise OperationalContextError("context_spec.evidence_states:INVALID")
    decision_states = _string_list(row["decision_states"], "context_spec.decision_states", min_items=1)
    if not set(decision_states).issubset(DECISION_STATES):
        raise OperationalContextError("context_spec.decision_states:INVALID")
    if not isinstance(row["include_broker_summary"], bool):
        raise OperationalContextError("context_spec.include_broker_summary:INVALID_BOOL")
    max_claims = _bounded_int(row["max_claims"], "context_spec.max_claims", minimum=0, maximum=1024)
    max_decisions = _bounded_int(row["max_decisions"], "context_spec.max_decisions", minimum=0, maximum=1024)
    max_output_bytes = _bounded_int(
        row["max_output_bytes"],
        "context_spec.max_output_bytes",
        minimum=4096,
        maximum=ABSOLUTE_MAX_OUTPUT_BYTES,
    )
    valid_at = None
    if row["valid_at"] is not None:
        try:
            valid_at = _normalize_time(row["valid_at"], field="context_spec.valid_at")
        except ValueError as exc:
            raise OperationalContextError(str(exc)) from exc
    return {
        "schema": SCHEMA_SPEC,
        "checkpoint_id": checkpoint_id,
        "subjects": sorted(subjects),
        "claim_predicates": sorted(predicates),
        "evidence_states": sorted(evidence_states),
        "decision_states": sorted(decision_states),
        "include_broker_summary": row["include_broker_summary"],
        "max_claims": max_claims,
        "max_decisions": max_decisions,
        "max_output_bytes": max_output_bytes,
        "valid_at": valid_at,
    }



def validate_session_capsule(value: Any) -> Dict[str, Any]:
    """Validate one strict ANTI_AMNESIA_SESSION_CAPSULE_V1 object.

    This public wrapper is intentionally read-only.  It exists so adjacent
    lifecycle components can bind a context pack to the exact capsule without
    duplicating or weakening the capsule contract.
    """

    return _validate_capsule(value)


def validate_context_pack_structure(value: Any) -> Dict[str, Any]:
    """Validate a context pack without reopening its source database.

    The full ``verify_context_pack`` function remains the authoritative
    database-backed replay check.  This structural validator is used when a
    previously verified pack is handed to the Anti-Amnesia session lifecycle.
    It proves strict shape, self-hash integrity, R63/session identity and the
    non-effecting ceilings; it never upgrades content acceptance.
    """

    row = _exact_keys(value, _PACK_KEYS, "context_pack")
    if row["schema"] != SCHEMA_PACK:
        raise OperationalContextError("context_pack.schema:UNSUPPORTED")
    if row["authority_generation"] != AUTHORITY_GENERATION:
        raise OperationalContextError("context_pack.authority_generation:NOT_R63")
    role = _nonempty(row["role"], "context_pack.role", max_length=128)
    active_case = row["active_case"]
    if active_case is not None:
        active_case = _nonempty(active_case, "context_pack.active_case", max_length=192)
    work_order_id = row["work_order_id"]
    if not isinstance(work_order_id, str) or not _WORK_ORDER_RE.fullmatch(work_order_id):
        raise OperationalContextError("context_pack.work_order_id:INVALID")

    session = _exact_keys(
        row["session_binding"],
        {
            "session_capsule_sha256",
            "challenge_id",
            "current_pointer_sha256",
            "workspace_context_digest",
        },
        "context_pack.session_binding",
    )
    for field in (
        "session_capsule_sha256",
        "challenge_id",
        "current_pointer_sha256",
        "workspace_context_digest",
    ):
        _validate_sha(session[field], f"context_pack.session_binding.{field}")

    memory = _exact_keys(
        row["memory_binding"],
        {
            "schema_name",
            "schema_version",
            "mode",
            "database_identity_sha256",
            "checkpoint",
            "context_event_cursor",
            "context_event_chain_head",
            "context_valid_at",
            "context_projection_sha256",
        },
        "context_pack.memory_binding",
    )
    if memory["schema_name"] != "continuityos.common_operational_memory.v1":
        raise OperationalContextError("context_pack.memory_binding.schema_name:INVALID")
    if memory["schema_version"] != 1 or memory["mode"] != "SHADOW_ONLY":
        raise OperationalContextError("context_pack.memory_binding:UNSUPPORTED_VERSION_OR_MODE")
    _validate_sha(
        memory["database_identity_sha256"],
        "context_pack.memory_binding.database_identity_sha256",
    )
    if isinstance(memory["context_event_cursor"], bool) or not isinstance(
        memory["context_event_cursor"], int
    ) or memory["context_event_cursor"] < 0:
        raise OperationalContextError("context_pack.memory_binding.context_event_cursor:INVALID")
    chain_head = memory["context_event_chain_head"]
    if chain_head is not None:
        _validate_sha(chain_head, "context_pack.memory_binding.context_event_chain_head")
    if memory["context_valid_at"] is not None:
        try:
            _normalize_time(
                memory["context_valid_at"],
                field="context_pack.memory_binding.context_valid_at",
            )
        except ValueError as exc:
            raise OperationalContextError(str(exc)) from exc
    _validate_sha(
        memory["context_projection_sha256"],
        "context_pack.memory_binding.context_projection_sha256",
    )

    checkpoint = _exact_keys(
        memory["checkpoint"],
        {
            "checkpoint_id",
            "label",
            "event_sequence",
            "projection_sha256",
            "recorded_at",
            "evidence_refs",
            "metadata_keys",
            "checkpoint_hash",
        },
        "context_pack.memory_binding.checkpoint",
    )
    checkpoint_id = _nonempty(
        checkpoint["checkpoint_id"],
        "context_pack.memory_binding.checkpoint.checkpoint_id",
        max_length=192,
    )
    _nonempty(
        checkpoint["label"],
        "context_pack.memory_binding.checkpoint.label",
        max_length=1024,
    )
    if isinstance(checkpoint["event_sequence"], bool) or not isinstance(
        checkpoint["event_sequence"], int
    ) or checkpoint["event_sequence"] < 0:
        raise OperationalContextError("context_pack.memory_binding.checkpoint.event_sequence:INVALID")
    if checkpoint["event_sequence"] != memory["context_event_cursor"]:
        raise OperationalContextError("context_pack.memory_binding:CHECKPOINT_CURSOR_MISMATCH")
    _validate_sha(
        checkpoint["projection_sha256"],
        "context_pack.memory_binding.checkpoint.projection_sha256",
    )
    try:
        _normalize_time(
            checkpoint["recorded_at"],
            field="context_pack.memory_binding.checkpoint.recorded_at",
        )
    except ValueError as exc:
        raise OperationalContextError(str(exc)) from exc
    if not isinstance(checkpoint["evidence_refs"], list):
        raise OperationalContextError("context_pack.memory_binding.checkpoint.evidence_refs:INVALID")
    _string_list(
        checkpoint["metadata_keys"],
        "context_pack.memory_binding.checkpoint.metadata_keys",
        max_items=1024,
    )
    _validate_sha(
        checkpoint["checkpoint_hash"],
        "context_pack.memory_binding.checkpoint.checkpoint_hash",
    )

    selection = dict(row["selection"]) if isinstance(row["selection"], dict) else None
    if selection is None or "spec_sha256" not in selection:
        raise OperationalContextError("context_pack.selection:INVALID")
    spec_sha256 = selection.pop("spec_sha256")
    _validate_sha(spec_sha256, "context_pack.selection.spec_sha256")
    normalized_spec = validate_context_spec(selection)
    if normalized_spec["checkpoint_id"] != checkpoint_id:
        raise OperationalContextError("context_pack.selection:CHECKPOINT_MISMATCH")

    if not isinstance(row["claims"], list) or not isinstance(row["decisions"], list):
        raise OperationalContextError("context_pack:CLAIMS_OR_DECISIONS_INVALID")
    if len(row["claims"]) > normalized_spec["max_claims"]:
        raise OperationalContextError("context_pack.claims:BUDGET_EXCEEDED")
    if len(row["decisions"]) > normalized_spec["max_decisions"]:
        raise OperationalContextError("context_pack.decisions:BUDGET_EXCEEDED")

    broker = row["broker_custody_summary"]
    if normalized_spec["include_broker_summary"] is False and broker is not None:
        raise OperationalContextError("context_pack.broker_custody_summary:UNEXPECTED")
    if broker is not None:
        broker_row = _exact_keys(
            broker,
            {
                "total",
                "by_physical_status",
                "by_generation_slot",
                "source_registry_sha256",
                "all_content_unreviewed",
                "all_state_not_applied",
            },
            "context_pack.broker_custody_summary",
        )
        if isinstance(broker_row["total"], bool) or not isinstance(broker_row["total"], int) or broker_row["total"] < 0:
            raise OperationalContextError("context_pack.broker_custody_summary.total:INVALID")
        if not isinstance(broker_row["by_physical_status"], dict) or not isinstance(
            broker_row["by_generation_slot"], dict
        ):
            raise OperationalContextError("context_pack.broker_custody_summary:INVALID_COUNTS")
        registries = _string_list(
            broker_row["source_registry_sha256"],
            "context_pack.broker_custody_summary.source_registry_sha256",
            max_items=1024,
        )
        for index, digest in enumerate(registries):
            _validate_sha(
                digest,
                f"context_pack.broker_custody_summary.source_registry_sha256[{index}]",
            )
        if broker_row["all_content_unreviewed"] is not True:
            raise OperationalContextError("context_pack.broker_custody_summary:CONTENT_CEILING_VIOLATION")
        if broker_row["all_state_not_applied"] is not True:
            raise OperationalContextError("context_pack.broker_custody_summary:APPLY_CEILING_VIOLATION")

    ceilings = _exact_keys(
        row["ceilings"],
        {
            "accepted_truth_owner",
            "context_is_projection_only",
            "content_acceptance",
            "state_apply",
            "may_dispatch_codex",
            "can_trade",
            "capital_permission",
            "deploy_permission",
            "self_application",
        },
        "context_pack.ceilings",
    )
    expected_ceilings = {
        "accepted_truth_owner": "CONTROL_CENTER",
        "context_is_projection_only": True,
        "content_acceptance": "NOT_PERFORMED",
        "state_apply": "DISABLED",
        "may_dispatch_codex": False,
        "can_trade": False,
        "capital_permission": "DENY",
        "deploy_permission": "DENY",
        "self_application": False,
    }
    if dict(ceilings) != expected_ceilings:
        raise OperationalContextError("context_pack.ceilings:VIOLATION")

    context_sha256 = _validate_sha(row["context_sha256"], "context_pack.context_sha256")
    body = dict(row)
    body.pop("context_sha256")
    expected_context_sha = _sha256_text(_canonical_json(body))
    if context_sha256 != expected_context_sha:
        raise OperationalContextError("context_pack.context_sha256:MISMATCH")

    return {
        **dict(row),
        "role": role,
        "active_case": active_case,
        "work_order_id": work_order_id,
        "selection": {**normalized_spec, "spec_sha256": spec_sha256},
    }

def _checkpoint(memory: OperationalMemory, checkpoint_id: str) -> Dict[str, Any]:
    row = memory.con.execute(
        "SELECT * FROM checkpoints WHERE checkpoint_id=?", (checkpoint_id,)
    ).fetchone()
    if row is None:
        raise OperationalContextError("checkpoint:NOT_FOUND")
    try:
        refs = strict_json_loads(row["evidence_refs_json"])
        metadata = strict_json_loads(row["metadata_json"])
    except Exception as exc:
        raise OperationalContextError("checkpoint:INVALID_JSON") from exc
    return {
        "checkpoint_id": row["checkpoint_id"],
        "label": row["label"],
        "event_sequence": int(row["event_sequence"]),
        "projection_sha256": row["projection_sha256"],
        "recorded_at": row["recorded_at"],
        "evidence_refs": refs,
        "metadata_keys": sorted(str(key) for key in metadata.keys()) if isinstance(metadata, dict) else [],
        "checkpoint_hash": row["checkpoint_hash"],
    }


def _broker_summary(rows: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    by_status: Dict[str, int] = {}
    by_slot: Dict[str, int] = {}
    registries = set()
    all_unreviewed = True
    all_not_applied = True
    for row in rows:
        status = str(row["physical_status"])
        by_status[status] = by_status.get(status, 0) + 1
        slot_key = f"{row.get('generation') or 'UNKNOWN'}:{row.get('slot') or 'UNKNOWN'}"
        by_slot[slot_key] = by_slot.get(slot_key, 0) + 1
        registries.add(str(row["source_registry_sha256"]))
        all_unreviewed = all_unreviewed and row["content_status"] == "UNREVIEWED"
        all_not_applied = all_not_applied and row["apply_status"] == "NOT_APPLIED"
    return {
        "total": len(rows),
        "by_physical_status": dict(sorted(by_status.items())),
        "by_generation_slot": dict(sorted(by_slot.items())),
        "source_registry_sha256": sorted(registries),
        "all_content_unreviewed": all_unreviewed,
        "all_state_not_applied": all_not_applied,
    }


def build_context_pack(
    memory: OperationalMemory,
    *,
    capsule: Mapping[str, Any],
    capsule_sha256: str,
    spec: Mapping[str, Any],
    spec_sha256: str,
) -> Dict[str, Any]:
    if not memory.read_only:
        raise PolicyViolation("operational context requires a read-only memory handle")
    _validate_sha(capsule_sha256, "session_capsule_sha256")
    _validate_sha(spec_sha256, "context_spec_sha256")
    capsule = _validate_capsule(capsule)
    spec = validate_context_spec(spec)
    verification = memory.verify()
    if not verification.get("ok"):
        raise OperationalContextError("operational_memory:VERIFY_FAILED")
    checkpoint = _checkpoint(memory, spec["checkpoint_id"])
    projection = memory.projection(
        event_sequence=checkpoint["event_sequence"],
        valid_at=spec["valid_at"],
    )
    subject_set = set(spec["subjects"])
    predicate_set = set(spec["claim_predicates"])
    evidence_set = set(spec["evidence_states"])
    decision_set = set(spec["decision_states"])
    claims = [
        row
        for row in projection["claims"]
        if row["subject_id"] in subject_set
        and (not predicate_set or row["predicate"] in predicate_set)
        and row["evidence_state"] in evidence_set
    ]
    decisions = [
        row
        for row in projection["decisions"]
        if row["subject_id"] in subject_set and row["state"] in decision_set
    ]
    if len(claims) > spec["max_claims"]:
        raise OperationalContextError(
            f"context:CLAIM_BUDGET_EXCEEDED:{len(claims)}>{spec['max_claims']}"
        )
    if len(decisions) > spec["max_decisions"]:
        raise OperationalContextError(
            f"context:DECISION_BUDGET_EXCEEDED:{len(decisions)}>{spec['max_decisions']}"
        )
    broker = _broker_summary(projection["broker_custody"]) if spec["include_broker_summary"] else None
    metadata = memory.metadata()
    memory_identity = _sha256_text(
        _canonical_json(
            {
                "schema_name": metadata.get("schema_name"),
                "schema_version": metadata.get("schema_version"),
                "checkpoint_id": checkpoint["checkpoint_id"],
                "checkpoint_hash": checkpoint["checkpoint_hash"],
                "projection_sha256": projection["projection_sha256"],
            }
        )
    )
    body = {
        "schema": SCHEMA_PACK,
        "authority_generation": AUTHORITY_GENERATION,
        "role": capsule["role"],
        "active_case": capsule["active_case"],
        "work_order_id": capsule["work_order_id"],
        "session_binding": {
            "session_capsule_sha256": capsule_sha256,
            "challenge_id": capsule["challenge_id"],
            "current_pointer_sha256": capsule["current_pointer_sha256"],
            "workspace_context_digest": capsule["workspace_context_digest"],
        },
        "memory_binding": {
            "schema_name": metadata.get("schema_name"),
            "schema_version": int(metadata.get("schema_version", "0")),
            "mode": metadata.get("mode"),
            "database_identity_sha256": memory_identity,
            "checkpoint": checkpoint,
            "context_event_cursor": projection["event_cursor"],
            "context_event_chain_head": projection["event_chain_head"],
            "context_valid_at": projection["valid_at"],
            "context_projection_sha256": projection["projection_sha256"],
        },
        "selection": {
            **spec,
            "spec_sha256": spec_sha256,
        },
        "claims": claims,
        "decisions": decisions,
        "broker_custody_summary": broker,
        "ceilings": {
            "accepted_truth_owner": "CONTROL_CENTER",
            "context_is_projection_only": True,
            "content_acceptance": "NOT_PERFORMED",
            "state_apply": "DISABLED",
            "may_dispatch_codex": False,
            "can_trade": False,
            "capital_permission": "DENY",
            "deploy_permission": "DENY",
            "self_application": False,
        },
    }
    context_sha = _sha256_text(_canonical_json(body))
    pack = {**body, "context_sha256": context_sha}
    payload = _canonical_bytes(pack)
    if len(payload) > spec["max_output_bytes"]:
        raise OperationalContextError(
            f"context:OUTPUT_BUDGET_EXCEEDED:{len(payload)}>{spec['max_output_bytes']}"
        )
    return pack


def _atomic_write_new(path: Path, payload: bytes) -> None:
    target = Path(path).expanduser().absolute()
    if target.exists():
        raise OperationalContextError("output:TARGET_ALREADY_EXISTS")
    target.parent.mkdir(parents=True, exist_ok=True)
    temp = target.with_name(f".{target.name}.tmp-{os.getpid()}-{uuid.uuid4().hex}")
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        fd = os.open(temp, flags, 0o600)
        try:
            view = memoryview(payload)
            offset = 0
            while offset < len(view):
                written = os.write(fd, view[offset:])
                if written <= 0:
                    raise OperationalContextError("output:SHORT_WRITE")
                offset += written
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(temp, target)
        if os.name != "nt":
            dfd = os.open(target.parent, os.O_RDONLY)
            try:
                os.fsync(dfd)
            finally:
                os.close(dfd)
    except Exception:
        try:
            temp.unlink()
        except FileNotFoundError:
            pass
        raise


def prepare_context_pack(
    *,
    db_path: str,
    capsule_path: Path,
    spec_path: Path,
    output_path: Path,
) -> Dict[str, Any]:
    capsule_payload, capsule_sha = _stable_read(Path(capsule_path), "session_capsule")
    spec_payload, spec_sha = _stable_read(Path(spec_path), "context_spec")
    capsule = strict_json_loads(capsule_payload.decode("utf-8-sig"))
    spec = strict_json_loads(spec_payload.decode("utf-8-sig"))
    resolved_db, db_identity = _database_identity(db_path)
    with OperationalMemory(resolved_db, read_only=True, immutable=True) as memory:
        pack = validate_context_pack_structure(
            build_context_pack(
                memory,
                capsule=capsule,
                capsule_sha256=capsule_sha,
                spec=spec,
                spec_sha256=spec_sha,
            )
        )
    _assert_database_unchanged(resolved_db, db_identity)
    payload = _canonical_bytes(pack)
    _atomic_write_new(Path(output_path), payload)
    readback, output_sha = _stable_read(Path(output_path), "context_output")
    if readback != payload:
        raise OperationalContextError("output:READBACK_MISMATCH")
    return {
        "schema": SCHEMA_PREPARE_RECEIPT,
        "status": "OPERATIONAL_CONTEXT_PACK_READY",
        "output": str(Path(output_path).expanduser().absolute()),
        "output_sha256": output_sha,
        "context_sha256": pack["context_sha256"],
        "checkpoint_id": pack["memory_binding"]["checkpoint"]["checkpoint_id"],
        "event_cursor": pack["memory_binding"]["context_event_cursor"],
        "claim_count": len(pack["claims"]),
        "decision_count": len(pack["decisions"]),
        "broker_summary_included": pack["broker_custody_summary"] is not None,
        "live_state_modified": False,
        "writes_performed": [str(Path(output_path).expanduser().absolute())],
        "can_trade": False,
        "capital_permission": "DENY",
        "deploy_permission": "DENY",
        "self_application": False,
    }


def verify_context_pack(
    *,
    db_path: str,
    capsule_path: Path,
    spec_path: Path,
    context_path: Path,
) -> Dict[str, Any]:
    capsule_payload, capsule_sha = _stable_read(Path(capsule_path), "session_capsule")
    spec_payload, spec_sha = _stable_read(Path(spec_path), "context_spec")
    context_payload, context_file_sha = _stable_read(Path(context_path), "context_pack")
    capsule = strict_json_loads(capsule_payload.decode("utf-8-sig"))
    spec = strict_json_loads(spec_payload.decode("utf-8-sig"))
    context = strict_json_loads(context_payload.decode("utf-8-sig"))
    _exact_keys(context, _PACK_KEYS, "context_pack")
    if context.get("schema") != SCHEMA_PACK:
        raise OperationalContextError("context_pack.schema:UNSUPPORTED")
    resolved_db, db_identity = _database_identity(db_path)
    with OperationalMemory(resolved_db, read_only=True, immutable=True) as memory:
        expected = build_context_pack(
            memory,
            capsule=capsule,
            capsule_sha256=capsule_sha,
            spec=spec,
            spec_sha256=spec_sha,
        )
    _assert_database_unchanged(resolved_db, db_identity)
    expected_payload = _canonical_bytes(expected)
    exact = context_payload == expected_payload
    context_hash_ok = context.get("context_sha256") == expected.get("context_sha256")
    return {
        "schema": SCHEMA_VERIFY_RECEIPT,
        "status": "OPERATIONAL_CONTEXT_VERIFY_PASS" if exact and context_hash_ok else "OPERATIONAL_CONTEXT_VERIFY_FAIL",
        "ok": exact and context_hash_ok,
        "context_file_sha256": context_file_sha,
        "expected_file_sha256": _sha256_bytes(expected_payload),
        "context_sha256": context.get("context_sha256"),
        "expected_context_sha256": expected.get("context_sha256"),
        "exact_bytes": exact,
        "live_state_modified": False,
        "can_trade": False,
        "capital_permission": "DENY",
        "deploy_permission": "DENY",
        "self_application": False,
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="continuity-context",
        description="Prepare or verify a bounded Common Operational Memory context pack",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)
    for name in ("prepare", "verify"):
        p = sub.add_parser(name)
        p.add_argument("--db", required=True, help="local Common Operational Memory SQLite database")
        p.add_argument("--capsule", required=True, help="ANTI_AMNESIA_SESSION_CAPSULE_V1 JSON")
        p.add_argument("--spec", required=True, help="controller-authored operational context spec")
        if name == "prepare":
            p.add_argument("--out", required=True, help="new output path for the context pack")
        else:
            p.add_argument("--context", required=True, help="context pack to verify")
    args = parser.parse_args(argv)
    try:
        if args.cmd == "prepare":
            out = prepare_context_pack(
                db_path=args.db,
                capsule_path=Path(args.capsule),
                spec_path=Path(args.spec),
                output_path=Path(args.out),
            )
        else:
            out = verify_context_pack(
                db_path=args.db,
                capsule_path=Path(args.capsule),
                spec_path=Path(args.spec),
                context_path=Path(args.context),
            )
        print(json.dumps(out, ensure_ascii=False, indent=2))
        return 0 if out.get("ok", True) else 1
    except Exception as exc:
        print(
            json.dumps(
                {
                    "schema": "CONTINUITYOS_OPERATIONAL_CONTEXT_ERROR_V1",
                    "error": type(exc).__name__,
                    "message": str(exc),
                    "live_state_modified": False,
                    "can_trade": False,
                    "capital_permission": "DENY",
                    "deploy_permission": "DENY",
                    "self_application": False,
                },
                ensure_ascii=False,
                indent=2,
            ),
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
