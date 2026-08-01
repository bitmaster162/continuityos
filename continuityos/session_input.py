"""Deterministic session-input manifest for Anti-Amnesia + operational memory.

This module binds one verified Anti-Amnesia session capsule to one bounded
Common Operational Memory context pack and its controller-authored selection
spec.  It produces a single canonical manifest that can be pinned by SHA-256 and
later cited by a return/close contract.

The implementation is intentionally shadow-only:

* it reads existing artifacts twice and rejects drift;
* it validates the capsule, context pack, context self-hash, context-spec hash,
  checkpoint binding and all deny ceilings;
* it creates one new manifest file and never overwrites an existing path;
* it does not open or mutate the operational-memory database;
* it does not update R63, current state, checkpoints or accepted truth;
* it does not dispatch agents, deploy, trade or grant capital permission.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import uuid
from typing import Any, Dict, Iterable, Mapping, Optional, Sequence, Tuple

from .operational_context import (
    AUTHORITY_GENERATION,
    SCHEMA_PACK as CONTEXT_PACK_SCHEMA,
    SCHEMA_VERIFY_RECEIPT as CONTEXT_VERIFY_RECEIPT_SCHEMA,
    _PACK_KEYS,
    _canonical_bytes,
    _validate_capsule,
    validate_context_spec,
)
from .operational_memory import _canonical_json, _sha256_text, strict_json_loads

SCHEMA_MANIFEST = "ANTI_AMNESIA_SESSION_INPUT_MANIFEST_V1"
SCHEMA_PREPARE_RECEIPT = "ANTI_AMNESIA_SESSION_INPUT_PREPARE_RECEIPT_V1"
SCHEMA_VERIFY_RECEIPT = "ANTI_AMNESIA_SESSION_INPUT_VERIFY_RECEIPT_V1"
MAX_INPUT_BYTES = 4 * 1024 * 1024
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_GIT_OBJECT_RE = re.compile(r"^[0-9a-f]{40,64}$")

_MANIFEST_KEYS = {
    "schema",
    "authority_generation",
    "session_binding",
    "artifact_binding",
    "memory_binding",
    "ceilings",
    "manifest_sha256",
}


class SessionInputError(RuntimeError):
    """A capsule/context/spec/manifest binding is invalid."""


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _exact_keys(value: Any, expected: Iterable[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise SessionInputError(f"{label}:NOT_OBJECT")
    want = set(expected)
    got = set(value)
    if want != got:
        raise SessionInputError(
            f"{label}:KEYS:missing={sorted(want - got)}:extra={sorted(got - want)}"
        )
    return value


def _nonempty(value: Any, label: str, *, max_length: int = 4096) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > max_length:
        raise SessionInputError(f"{label}:INVALID_STRING")
    return value


def _sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
        raise SessionInputError(f"{label}:INVALID_SHA256")
    return value


def _git_oid(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _GIT_OBJECT_RE.fullmatch(value):
        raise SessionInputError(f"{label}:INVALID_GIT_OBJECT")
    return value


def _safe_file(path: Path, label: str) -> Path:
    p = Path(path).expanduser().absolute()
    if not p.exists() or not p.is_file():
        raise SessionInputError(f"{label}:MISSING_FILE")
    info = p.lstat()
    if stat.S_ISLNK(info.st_mode):
        raise SessionInputError(f"{label}:SYMLINK_REFUSED")
    attrs = getattr(info, "st_file_attributes", 0)
    if attrs & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400):
        raise SessionInputError(f"{label}:REPARSE_REFUSED")
    if info.st_size > MAX_INPUT_BYTES:
        raise SessionInputError(f"{label}:TOO_LARGE")
    return p


def _stable_read(path: Path, label: str) -> Tuple[bytes, str]:
    p = _safe_file(path, label)
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
        raise SessionInputError(f"{label}:DRIFT_DURING_READ")
    return first, _sha256_bytes(first)


def _parse_canonical_json(payload: bytes, label: str) -> Mapping[str, Any]:
    try:
        value = strict_json_loads(payload.decode("utf-8-sig"))
    except Exception as exc:
        raise SessionInputError(f"{label}:INVALID_JSON") from exc
    canonical = _canonical_bytes(value)
    if payload != canonical:
        raise SessionInputError(f"{label}:NON_CANONICAL_JSON")
    if not isinstance(value, dict):
        raise SessionInputError(f"{label}:NOT_OBJECT")
    return value


def _validate_context_pack(
    value: Any,
    *,
    capsule: Mapping[str, Any],
    capsule_sha256: str,
    spec: Mapping[str, Any],
    spec_sha256: str,
) -> Dict[str, Any]:
    row = _exact_keys(value, _PACK_KEYS, "operational_context")
    if row["schema"] != CONTEXT_PACK_SCHEMA:
        raise SessionInputError("operational_context.schema:UNSUPPORTED")
    if row["authority_generation"] != AUTHORITY_GENERATION:
        raise SessionInputError("operational_context.authority_generation:NOT_R63")
    if row["role"] != capsule["role"]:
        raise SessionInputError("operational_context.role:CAPSULE_MISMATCH")
    if row["active_case"] != capsule["active_case"]:
        raise SessionInputError("operational_context.active_case:CAPSULE_MISMATCH")
    if row["work_order_id"] != capsule["work_order_id"]:
        raise SessionInputError("operational_context.work_order_id:CAPSULE_MISMATCH")

    session = _exact_keys(
        row["session_binding"],
        {
            "session_capsule_sha256",
            "challenge_id",
            "current_pointer_sha256",
            "workspace_context_digest",
        },
        "operational_context.session_binding",
    )
    expected_session = {
        "session_capsule_sha256": capsule_sha256,
        "challenge_id": capsule["challenge_id"],
        "current_pointer_sha256": capsule["current_pointer_sha256"],
        "workspace_context_digest": capsule["workspace_context_digest"],
    }
    if dict(session) != expected_session:
        raise SessionInputError("operational_context.session_binding:MISMATCH")

    selection = _exact_keys(
        row["selection"],
        {
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
            "spec_sha256",
        },
        "operational_context.selection",
    )
    if selection["spec_sha256"] != spec_sha256:
        raise SessionInputError("operational_context.selection:SPEC_SHA256_MISMATCH")
    normalized_selection = {key: selection[key] for key in spec}
    if normalized_selection != dict(spec):
        raise SessionInputError("operational_context.selection:SPEC_MISMATCH")

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
        "operational_context.memory_binding",
    )
    _nonempty(memory["schema_name"], "operational_context.memory_binding.schema_name")
    if isinstance(memory["schema_version"], bool) or not isinstance(memory["schema_version"], int) or memory["schema_version"] < 1:
        raise SessionInputError("operational_context.memory_binding.schema_version:INVALID")
    _nonempty(memory["mode"], "operational_context.memory_binding.mode")
    _sha256(memory["database_identity_sha256"], "operational_context.memory_binding.database_identity_sha256")
    if isinstance(memory["context_event_cursor"], bool) or not isinstance(memory["context_event_cursor"], int) or memory["context_event_cursor"] < 0:
        raise SessionInputError("operational_context.memory_binding.context_event_cursor:INVALID")
    if memory["context_event_chain_head"] is not None:
        _sha256(memory["context_event_chain_head"], "operational_context.memory_binding.context_event_chain_head")
    if memory["context_valid_at"] is not None:
        _nonempty(memory["context_valid_at"], "operational_context.memory_binding.context_valid_at")
    _sha256(memory["context_projection_sha256"], "operational_context.memory_binding.context_projection_sha256")

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
        "operational_context.memory_binding.checkpoint",
    )
    _nonempty(checkpoint["checkpoint_id"], "operational_context.memory_binding.checkpoint.checkpoint_id")
    _nonempty(checkpoint["label"], "operational_context.memory_binding.checkpoint.label")
    if isinstance(checkpoint["event_sequence"], bool) or not isinstance(checkpoint["event_sequence"], int) or checkpoint["event_sequence"] < 0:
        raise SessionInputError("operational_context.memory_binding.checkpoint.event_sequence:INVALID")
    _sha256(checkpoint["projection_sha256"], "operational_context.memory_binding.checkpoint.projection_sha256")
    _nonempty(checkpoint["recorded_at"], "operational_context.memory_binding.checkpoint.recorded_at")
    if not isinstance(checkpoint["evidence_refs"], list):
        raise SessionInputError("operational_context.memory_binding.checkpoint.evidence_refs:INVALID")
    if not isinstance(checkpoint["metadata_keys"], list) or not all(isinstance(item, str) for item in checkpoint["metadata_keys"]):
        raise SessionInputError("operational_context.memory_binding.checkpoint.metadata_keys:INVALID")
    _sha256(checkpoint["checkpoint_hash"], "operational_context.memory_binding.checkpoint.checkpoint_hash")
    if checkpoint["checkpoint_id"] != spec["checkpoint_id"]:
        raise SessionInputError("operational_context.memory_binding.checkpoint:SPEC_MISMATCH")
    if memory["context_event_cursor"] != checkpoint["event_sequence"]:
        raise SessionInputError("operational_context.memory_binding:EVENT_CURSOR_MISMATCH")

    if not isinstance(row["claims"], list) or not isinstance(row["decisions"], list):
        raise SessionInputError("operational_context:CLAIMS_OR_DECISIONS_INVALID")
    if row["broker_custody_summary"] is not None and not isinstance(row["broker_custody_summary"], dict):
        raise SessionInputError("operational_context.broker_custody_summary:INVALID")

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
        "operational_context.ceilings",
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
        raise SessionInputError("operational_context.ceilings:VIOLATION")

    context_sha = _sha256(row["context_sha256"], "operational_context.context_sha256")
    body = {key: row[key] for key in row if key != "context_sha256"}
    expected_context_sha = _sha256_text(_canonical_json(body))
    if context_sha != expected_context_sha:
        raise SessionInputError("operational_context.context_sha256:SELF_HASH_MISMATCH")
    return dict(row)


def _manifest_body(
    *,
    capsule: Mapping[str, Any],
    capsule_sha256: str,
    context: Mapping[str, Any],
    context_file_sha256: str,
    spec_sha256: str,
    context_verification_sha256: str,
) -> Dict[str, Any]:
    baseline = capsule["git_baseline"]
    memory = context["memory_binding"]
    checkpoint = memory["checkpoint"]
    return {
        "schema": SCHEMA_MANIFEST,
        "authority_generation": AUTHORITY_GENERATION,
        "session_binding": {
            "challenge_id": capsule["challenge_id"],
            "current_pointer_sha256": capsule["current_pointer_sha256"],
            "workspace_context_digest": capsule["workspace_context_digest"],
            "role": capsule["role"],
            "active_case": capsule["active_case"],
            "case_binding": capsule["case_binding"],
            "work_order_id": capsule["work_order_id"],
            "git_repository": baseline["repository"],
            "git_branch": baseline["branch"],
            "git_head": baseline["head"],
            "git_tree": baseline["tree"],
        },
        "artifact_binding": {
            "session_capsule": {
                "logical_name": "SESSION_CAPSULE.json",
                "sha256": capsule_sha256,
            },
            "operational_context": {
                "logical_name": "OPERATIONAL_CONTEXT.json",
                "file_sha256": context_file_sha256,
                "context_sha256": context["context_sha256"],
            },
            "context_spec": {
                "logical_name": "OPERATIONAL_CONTEXT_SPEC.json",
                "sha256": spec_sha256,
            },
            "context_verification": {
                "logical_name": "OPERATIONAL_CONTEXT_VERIFY_RECEIPT.json",
                "sha256": context_verification_sha256,
            },
        },
        "memory_binding": {
            "database_identity_sha256": memory["database_identity_sha256"],
            "checkpoint_id": checkpoint["checkpoint_id"],
            "checkpoint_hash": checkpoint["checkpoint_hash"],
            "event_cursor": memory["context_event_cursor"],
            "event_chain_head": memory["context_event_chain_head"],
            "projection_sha256": memory["context_projection_sha256"],
            "valid_at": memory["context_valid_at"],
        },
        "ceilings": {
            "effect_ceiling": capsule["effect_ceiling"],
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


def validate_session_input_manifest(value: Any) -> Dict[str, Any]:
    row = _exact_keys(value, _MANIFEST_KEYS, "session_input_manifest")
    if row["schema"] != SCHEMA_MANIFEST:
        raise SessionInputError("session_input_manifest.schema:UNSUPPORTED")
    if row["authority_generation"] != AUTHORITY_GENERATION:
        raise SessionInputError("session_input_manifest.authority_generation:NOT_R63")

    session = _exact_keys(
        row["session_binding"],
        {
            "challenge_id",
            "current_pointer_sha256",
            "workspace_context_digest",
            "role",
            "active_case",
            "case_binding",
            "work_order_id",
            "git_repository",
            "git_branch",
            "git_head",
            "git_tree",
        },
        "session_input_manifest.session_binding",
    )
    for field in ("challenge_id", "current_pointer_sha256", "workspace_context_digest"):
        _sha256(session[field], f"session_input_manifest.session_binding.{field}")
    for field in ("role", "work_order_id", "git_repository", "git_branch"):
        _nonempty(session[field], f"session_input_manifest.session_binding.{field}")
    if session["active_case"] is not None:
        _nonempty(session["active_case"], "session_input_manifest.session_binding.active_case")
    if session["case_binding"] not in {"NOT_REQUESTED", "EXACT_STRUCTURED_MATCH"}:
        raise SessionInputError("session_input_manifest.session_binding.case_binding:INVALID")
    if (session["active_case"] is None) != (session["case_binding"] == "NOT_REQUESTED"):
        raise SessionInputError("session_input_manifest.session_binding:CASE_MISMATCH")
    _git_oid(session["git_head"], "session_input_manifest.session_binding.git_head")
    _git_oid(session["git_tree"], "session_input_manifest.session_binding.git_tree")

    artifacts = _exact_keys(
        row["artifact_binding"],
        {"session_capsule", "operational_context", "context_spec", "context_verification"},
        "session_input_manifest.artifact_binding",
    )
    capsule_artifact = _exact_keys(
        artifacts["session_capsule"],
        {"logical_name", "sha256"},
        "session_input_manifest.artifact_binding.session_capsule",
    )
    if capsule_artifact["logical_name"] != "SESSION_CAPSULE.json":
        raise SessionInputError("session_input_manifest.artifact_binding.session_capsule:LOGICAL_NAME")
    _sha256(capsule_artifact["sha256"], "session_input_manifest.artifact_binding.session_capsule.sha256")
    context_artifact = _exact_keys(
        artifacts["operational_context"],
        {"logical_name", "file_sha256", "context_sha256"},
        "session_input_manifest.artifact_binding.operational_context",
    )
    if context_artifact["logical_name"] != "OPERATIONAL_CONTEXT.json":
        raise SessionInputError("session_input_manifest.artifact_binding.operational_context:LOGICAL_NAME")
    _sha256(context_artifact["file_sha256"], "session_input_manifest.artifact_binding.operational_context.file_sha256")
    _sha256(context_artifact["context_sha256"], "session_input_manifest.artifact_binding.operational_context.context_sha256")
    spec_artifact = _exact_keys(
        artifacts["context_spec"],
        {"logical_name", "sha256"},
        "session_input_manifest.artifact_binding.context_spec",
    )
    if spec_artifact["logical_name"] != "OPERATIONAL_CONTEXT_SPEC.json":
        raise SessionInputError("session_input_manifest.artifact_binding.context_spec:LOGICAL_NAME")
    _sha256(spec_artifact["sha256"], "session_input_manifest.artifact_binding.context_spec.sha256")

    verify_artifact = _exact_keys(
        artifacts["context_verification"],
        {"logical_name", "sha256"},
        "session_input_manifest.artifact_binding.context_verification",
    )
    if verify_artifact["logical_name"] != "OPERATIONAL_CONTEXT_VERIFY_RECEIPT.json":
        raise SessionInputError("session_input_manifest.artifact_binding.context_verification:LOGICAL_NAME")
    _sha256(verify_artifact["sha256"], "session_input_manifest.artifact_binding.context_verification.sha256")

    memory = _exact_keys(
        row["memory_binding"],
        {
            "database_identity_sha256",
            "checkpoint_id",
            "checkpoint_hash",
            "event_cursor",
            "event_chain_head",
            "projection_sha256",
            "valid_at",
        },
        "session_input_manifest.memory_binding",
    )
    for field in ("database_identity_sha256", "checkpoint_hash", "projection_sha256"):
        _sha256(memory[field], f"session_input_manifest.memory_binding.{field}")
    _nonempty(memory["checkpoint_id"], "session_input_manifest.memory_binding.checkpoint_id")
    if isinstance(memory["event_cursor"], bool) or not isinstance(memory["event_cursor"], int) or memory["event_cursor"] < 0:
        raise SessionInputError("session_input_manifest.memory_binding.event_cursor:INVALID")
    if memory["event_chain_head"] is not None:
        _sha256(memory["event_chain_head"], "session_input_manifest.memory_binding.event_chain_head")
    if memory["valid_at"] is not None:
        _nonempty(memory["valid_at"], "session_input_manifest.memory_binding.valid_at")

    ceilings = _exact_keys(
        row["ceilings"],
        {
            "effect_ceiling",
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
        "session_input_manifest.ceilings",
    )
    expected_ceilings = {
        "effect_ceiling": "READ_ONLY",
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
        raise SessionInputError("session_input_manifest.ceilings:VIOLATION")

    manifest_sha = _sha256(row["manifest_sha256"], "session_input_manifest.manifest_sha256")
    body = {key: row[key] for key in row if key != "manifest_sha256"}
    expected_sha = _sha256_text(_canonical_json(body))
    if manifest_sha != expected_sha:
        raise SessionInputError("session_input_manifest.manifest_sha256:SELF_HASH_MISMATCH")
    return dict(row)


def build_session_input_manifest(
    *,
    capsule: Mapping[str, Any],
    capsule_sha256: str,
    context: Mapping[str, Any],
    context_file_sha256: str,
    spec: Mapping[str, Any],
    spec_sha256: str,
    context_verification: Mapping[str, Any],
    context_verification_sha256: str,
) -> Dict[str, Any]:
    _sha256(capsule_sha256, "session_capsule_sha256")
    _sha256(context_file_sha256, "operational_context_file_sha256")
    _sha256(spec_sha256, "context_spec_sha256")
    _sha256(context_verification_sha256, "context_verification_sha256")
    normalized_capsule = _validate_capsule(capsule)
    normalized_spec = validate_context_spec(spec)
    normalized_context = _validate_context_pack(
        context,
        capsule=normalized_capsule,
        capsule_sha256=capsule_sha256,
        spec=normalized_spec,
        spec_sha256=spec_sha256,
    )
    verify_row = _exact_keys(
        context_verification,
        {
            "schema",
            "status",
            "ok",
            "context_file_sha256",
            "expected_file_sha256",
            "context_sha256",
            "expected_context_sha256",
            "exact_bytes",
            "live_state_modified",
            "can_trade",
            "capital_permission",
            "deploy_permission",
            "self_application",
        },
        "context_verification",
    )
    expected_verify = {
        "schema": CONTEXT_VERIFY_RECEIPT_SCHEMA,
        "status": "OPERATIONAL_CONTEXT_VERIFY_PASS",
        "ok": True,
        "context_file_sha256": context_file_sha256,
        "expected_file_sha256": context_file_sha256,
        "context_sha256": normalized_context["context_sha256"],
        "expected_context_sha256": normalized_context["context_sha256"],
        "exact_bytes": True,
        "live_state_modified": False,
        "can_trade": False,
        "capital_permission": "DENY",
        "deploy_permission": "DENY",
        "self_application": False,
    }
    if dict(verify_row) != expected_verify:
        raise SessionInputError("context_verification:NOT_EXACT_PASS")
    body = _manifest_body(
        capsule=normalized_capsule,
        capsule_sha256=capsule_sha256,
        context=normalized_context,
        context_file_sha256=context_file_sha256,
        spec_sha256=spec_sha256,
        context_verification_sha256=context_verification_sha256,
    )
    manifest = {**body, "manifest_sha256": _sha256_text(_canonical_json(body))}
    validate_session_input_manifest(manifest)
    return manifest


def _atomic_write_new(path: Path, payload: bytes) -> None:
    target = Path(path).expanduser().absolute()
    if target.exists():
        raise SessionInputError("output:TARGET_ALREADY_EXISTS")
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
                    raise SessionInputError("output:SHORT_WRITE")
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


def _load_bound_inputs(
    *,
    capsule_path: Path,
    context_path: Path,
    spec_path: Path,
    context_verification_path: Path,
) -> Tuple[Dict[str, Any], bytes, str]:
    capsule_payload, capsule_sha = _stable_read(Path(capsule_path), "session_capsule")
    context_payload, context_file_sha = _stable_read(Path(context_path), "operational_context")
    spec_payload, spec_sha = _stable_read(Path(spec_path), "context_spec")
    verify_payload, verify_sha = _stable_read(Path(context_verification_path), "context_verification")
    capsule = _parse_canonical_json(capsule_payload, "session_capsule")
    context = _parse_canonical_json(context_payload, "operational_context")
    spec = _parse_canonical_json(spec_payload, "context_spec")
    context_verification = _parse_canonical_json(verify_payload, "context_verification")
    manifest = build_session_input_manifest(
        capsule=capsule,
        capsule_sha256=capsule_sha,
        context=context,
        context_file_sha256=context_file_sha,
        spec=spec,
        spec_sha256=spec_sha,
        context_verification=context_verification,
        context_verification_sha256=verify_sha,
    )
    payload = _canonical_bytes(manifest)
    return manifest, payload, _sha256_bytes(payload)


def prepare_session_input_manifest(
    *,
    capsule_path: Path,
    context_path: Path,
    spec_path: Path,
    context_verification_path: Path,
    output_path: Path,
) -> Dict[str, Any]:
    manifest, payload, file_sha = _load_bound_inputs(
        capsule_path=capsule_path,
        context_path=context_path,
        spec_path=spec_path,
        context_verification_path=context_verification_path,
    )
    _atomic_write_new(Path(output_path), payload)
    readback, readback_sha = _stable_read(Path(output_path), "session_input_manifest")
    if readback != payload or readback_sha != file_sha:
        raise SessionInputError("output:READBACK_MISMATCH")
    return {
        "schema": SCHEMA_PREPARE_RECEIPT,
        "status": "SESSION_INPUT_MANIFEST_READY",
        "output": str(Path(output_path).expanduser().absolute()),
        "output_sha256": readback_sha,
        "manifest_sha256": manifest["manifest_sha256"],
        "challenge_id": manifest["session_binding"]["challenge_id"],
        "work_order_id": manifest["session_binding"]["work_order_id"],
        "checkpoint_id": manifest["memory_binding"]["checkpoint_id"],
        "context_sha256": manifest["artifact_binding"]["operational_context"]["context_sha256"],
        "live_state_modified": False,
        "writes_performed": [str(Path(output_path).expanduser().absolute())],
        "can_trade": False,
        "capital_permission": "DENY",
        "deploy_permission": "DENY",
        "self_application": False,
    }


def verify_session_input_manifest(
    *,
    capsule_path: Path,
    context_path: Path,
    spec_path: Path,
    context_verification_path: Path,
    manifest_path: Path,
    expected_manifest_file_sha256: str,
) -> Dict[str, Any]:
    _sha256(expected_manifest_file_sha256, "expected_manifest_file_sha256")
    manifest_payload, manifest_file_sha = _stable_read(Path(manifest_path), "session_input_manifest")
    if manifest_file_sha != expected_manifest_file_sha256:
        raise SessionInputError("session_input_manifest:PINNED_SHA256_MISMATCH")
    parsed_manifest = _parse_canonical_json(manifest_payload, "session_input_manifest")
    validate_session_input_manifest(parsed_manifest)
    expected, expected_payload, expected_file_sha = _load_bound_inputs(
        capsule_path=capsule_path,
        context_path=context_path,
        spec_path=spec_path,
        context_verification_path=context_verification_path,
    )
    exact = manifest_payload == expected_payload
    self_hash_match = parsed_manifest["manifest_sha256"] == expected["manifest_sha256"]
    return {
        "schema": SCHEMA_VERIFY_RECEIPT,
        "status": "SESSION_INPUT_VERIFY_PASS" if exact and self_hash_match else "SESSION_INPUT_VERIFY_FAIL",
        "ok": exact and self_hash_match,
        "manifest_file_sha256": manifest_file_sha,
        "expected_file_sha256": expected_file_sha,
        "manifest_sha256": parsed_manifest["manifest_sha256"],
        "expected_manifest_sha256": expected["manifest_sha256"],
        "exact_bytes": exact,
        "live_state_modified": False,
        "can_trade": False,
        "capital_permission": "DENY",
        "deploy_permission": "DENY",
        "self_application": False,
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="continuity-session",
        description="Prepare or verify a hash-pinned session input manifest",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)
    prepare = sub.add_parser("prepare")
    verify = sub.add_parser("verify")
    for command in (prepare, verify):
        command.add_argument("--capsule", required=True, help="canonical ANTI_AMNESIA_SESSION_CAPSULE_V1 JSON")
        command.add_argument("--context", required=True, help="canonical CONTINUITYOS_OPERATIONAL_CONTEXT_PACK_V1 JSON")
        command.add_argument("--spec", required=True, help="canonical controller-authored context spec JSON")
        command.add_argument("--context-verification", required=True, help="canonical OPERATIONAL_CONTEXT_VERIFY_PASS receipt")
    prepare.add_argument("--out", required=True, help="new SESSION_INPUT_MANIFEST.json path")
    verify.add_argument("--manifest", required=True, help="existing session input manifest")
    verify.add_argument("--manifest-sha256", required=True, help="controller-pinned manifest file SHA-256")
    args = parser.parse_args(argv)
    try:
        if args.cmd == "prepare":
            receipt = prepare_session_input_manifest(
                capsule_path=Path(args.capsule),
                context_path=Path(args.context),
                spec_path=Path(args.spec),
                context_verification_path=Path(args.context_verification),
                output_path=Path(args.out),
            )
        else:
            receipt = verify_session_input_manifest(
                capsule_path=Path(args.capsule),
                context_path=Path(args.context),
                spec_path=Path(args.spec),
                context_verification_path=Path(args.context_verification),
                manifest_path=Path(args.manifest),
                expected_manifest_file_sha256=args.manifest_sha256,
            )
        print(json.dumps(receipt, ensure_ascii=False, indent=2, sort_keys=True))
        return 0 if receipt.get("ok", True) else 1
    except Exception as exc:
        print(
            json.dumps(
                {
                    "schema": "ANTI_AMNESIA_SESSION_INPUT_ERROR_V1",
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
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
