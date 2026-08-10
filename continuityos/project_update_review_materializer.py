"""Materialize exact R52 review artifacts without granting authority.

R54 is intentionally a filesystem-only handoff step. It validates one R52 packet,
rechecks the exact nested R37 proposal bytes/hash and deterministic authorization
skeleton, proves that skeleton is still rejected by R37, then writes a fresh
no-clobber review directory. It never fills authority fields or touches
OperationalMemory.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import shutil
from typing import Any, Mapping

from .current_effect_boundary import MODE_LEGACY, inspect_current_session
from . import operational_memory_apply as apply
from .current_project_update_review import PACKET_SCHEMA, _authorization_skeleton
from .operational_memory import strict_json_loads
from .project_memory_bootstrap import MAX_ARTIFACT_BYTES, _safe_parent, _stable_read

RECEIPT_SCHEMA = "continuityos.operational_memory.project_update_materialization/v1"
PROPOSAL_NAME = "OPERATIONAL_MEMORY_DELTA_PROPOSAL.json"
SKELETON_NAME = "OPERATIONAL_MEMORY_APPLY_AUTHORIZATION_SKELETON.json"
RECEIPT_NAME = "MATERIALIZATION_RECEIPT.json"
SUMS_NAME = "SHA256SUMS.txt"

_PACKET_BODY_KEYS = {
    "schema", "terminal", "reason", "project_id", "current_work",
    "claim_sync_plan", "proposal", "authorization_review", "next_gate",
    "apply_status", "authorization_granted", "authorization_identity_authenticated",
    "semantic_assertions_accepted", "execution_decision", "execution_authorized",
    "effects",
}
_PACKET_ALLOWED_KEYS = _PACKET_BODY_KEYS | {"packet_id", "current_session", "request_input"}


def _sha(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _canonical_bytes(value: Any) -> bytes:
    return apply._canonical_json(value).encode("utf-8")


def _effects(*, wrote: bool = False) -> dict[str, Any]:
    return {
        "operational_memory_write": False,
        "filesystem_write": bool(wrote),
        "network_effect": False,
        "subprocess_execution": False,
        "agent_dispatch": False,
        "external_message": False,
        "deployment": False,
        "current_state_apply": False,
        "canonical_mutation": False,
        "accepted_truth_modified": False,
        "trading": False,
        "wallet_access": False,
        "order_execution": False,
        "can_trade": False,
        "capital_permission": "DENY",
        "deploy_permission": "DENY",
    }


def _receipt(terminal: str, reason: str, *, errors=None, wrote=False, **extra: Any) -> dict[str, Any]:
    return {
        "schema": RECEIPT_SCHEMA,
        "terminal": terminal,
        "reason": reason,
        "errors": list(errors or []),
        "materialized": bool(wrote),
        "authorization_granted": False,
        "authorization_identity_authenticated": False,
        "apply_status": "NOT_APPLIED",
        "execution_decision": "HOLD",
        "execution_authorized": False,
        "effects": _effects(wrote=wrote),
        **extra,
    }


def _validate_packet(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError("R52 packet root must be an object")
    missing = (_PACKET_BODY_KEYS | {"packet_id"}) - set(value)
    extra = set(value) - _PACKET_ALLOWED_KEYS
    if missing or extra:
        raise ValueError(f"R52 packet keys mismatch missing={sorted(missing)} extra={sorted(extra)}")
    if value.get("schema") != PACKET_SCHEMA or value.get("terminal") != "CURRENT_PROJECT_UPDATE_REVIEW_PASS":
        raise ValueError("R52 packet is not PASS")
    if value.get("apply_status") != "NOT_APPLIED":
        raise ValueError("R52 packet apply_status must be NOT_APPLIED")
    if value.get("authorization_granted") is not False:
        raise ValueError("R52 packet unexpectedly grants authorization")
    if value.get("authorization_identity_authenticated") is not False:
        raise ValueError("R52 packet unexpectedly authenticates authority identity")
    if value.get("execution_authorized") is not False or value.get("execution_decision") != "HOLD":
        raise ValueError("R52 packet execution ceiling mismatch")

    body = {key: value[key] for key in _PACKET_BODY_KEYS}
    expected_packet_id = "purp-" + hashlib.sha256(_canonical_bytes(body)).hexdigest()[:40]
    if value.get("packet_id") != expected_packet_id:
        raise ValueError("R52 packet_id integrity mismatch")

    proposal_meta = value.get("proposal")
    if not isinstance(proposal_meta, Mapping):
        raise ValueError("R52 proposal handoff missing")
    proposal_text = proposal_meta.get("proposal_canonical_json")
    if not isinstance(proposal_text, str) or not proposal_text:
        raise ValueError("R52 proposal canonical JSON missing")
    proposal_bytes = proposal_text.encode("utf-8")
    proposal_sha = _sha(proposal_bytes)
    if proposal_meta.get("proposal_file_sha256") != proposal_sha:
        raise ValueError("R52 proposal file SHA mismatch")
    if proposal_meta.get("proposal_file_size_bytes") != len(proposal_bytes):
        raise ValueError("R52 proposal file size mismatch")
    proposal_value = strict_json_loads(proposal_text)
    normalized = apply._validate_proposal(proposal_value)
    if apply._canonical_json(normalized) != proposal_text:
        raise ValueError("R52 proposal text is not canonical validated R37 proposal bytes")
    if proposal_meta.get("proposal_id") != normalized.get("proposal_id"):
        raise ValueError("R52 proposal_id mismatch")

    review = value.get("authorization_review")
    if not isinstance(review, Mapping):
        raise ValueError("R52 authorization review missing")
    skeleton = review.get("authorization_skeleton")
    if not isinstance(skeleton, Mapping):
        raise ValueError("R52 authorization skeleton missing")
    expected_skeleton = _authorization_skeleton(normalized, proposal_sha)
    if dict(skeleton) != expected_skeleton:
        raise ValueError("R52 authorization skeleton is not deterministic for proposal bytes")
    if review.get("authorization_skeleton_is_r37_valid") is not False:
        raise ValueError("R52 skeleton unexpectedly marked R37-valid")
    if review.get("authorization_granted") is not False:
        raise ValueError("R52 authorization review unexpectedly grants authority")
    if review.get("authorization_identity_authenticated") is not False:
        raise ValueError("R52 authorization review unexpectedly authenticates identity")
    try:
        apply._validate_authorization(
            skeleton,
            proposal=normalized,
            proposal_file_sha256=proposal_sha,
        )
    except Exception:
        pass
    else:
        raise ValueError("R52 incomplete authorization skeleton unexpectedly validates at R37")

    return {
        "packet": dict(value),
        "proposal": normalized,
        "proposal_bytes": proposal_bytes,
        "proposal_sha256": proposal_sha,
        "skeleton": dict(skeleton),
        "skeleton_bytes": _canonical_bytes(skeleton),
    }


def _write_exclusive(path: Path, payload: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(path, flags, 0o600)
    try:
        with os.fdopen(fd, "wb", closefd=True) as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        raise


def materialize_project_update_review(packet_path: str | Path, output_dir: str | Path) -> dict[str, Any]:
    """Write exact proposal + invalid auth skeleton into one fresh review directory."""
    state = inspect_current_session()
    if state.get("mode") != MODE_LEGACY:
        return _receipt(
            "PROJECT_UPDATE_MATERIALIZATION_HOLD" if state.get("binding_verified") else "PROJECT_UPDATE_MATERIALIZATION_REVISE",
            "CURRENT_SESSION_FILESYSTEM_EFFECT_FORBIDDEN",
            errors=[str(state.get("reason") or state.get("mode"))],
            current_session=state,
        )

    out = Path(output_dir).expanduser().absolute()
    packet_file = Path(packet_path).expanduser().absolute()
    try:
        packet_bytes = _stable_read(packet_file, "R52 review packet", max_bytes=MAX_ARTIFACT_BYTES)
        packet = strict_json_loads(packet_bytes.decode("utf-8-sig"))
        validated = _validate_packet(packet)
        if out.exists() or out.is_symlink():
            raise FileExistsError("output directory already exists")
        # Reuse the composed R40 target-parent invariant: the lexical output parent
        # must be the physical parent, with no symlink/junction/alias ancestor.
        canonical_parent = _safe_parent(out / ".r54-path-probe")
        if canonical_parent != out.parent:
            raise ValueError("output parent is not canonical")
    except Exception as exc:
        return _receipt(
            "PROJECT_UPDATE_MATERIALIZATION_REVISE",
            "MATERIALIZATION_INPUT_INVALID",
            errors=[f"{type(exc).__name__}: {exc}"],
            packet_path=str(packet_file),
            output_dir=str(out),
        )

    created = False
    try:
        out.mkdir(mode=0o700)
        created = True
        proposal_bytes = validated["proposal_bytes"]
        skeleton_bytes = validated["skeleton_bytes"]
        proposal_sha = validated["proposal_sha256"]
        skeleton_sha = _sha(skeleton_bytes)
        packet_sha = _sha(packet_bytes)

        _write_exclusive(out / PROPOSAL_NAME, proposal_bytes)
        _write_exclusive(out / SKELETON_NAME, skeleton_bytes)

        receipt = _receipt(
            "PROJECT_UPDATE_MATERIALIZATION_PASS",
            "EXACT_NON_AUTHORIZING_REVIEW_ARTIFACTS_WRITTEN",
            wrote=True,
            packet_file_sha256=packet_sha,
            packet_id=validated["packet"]["packet_id"],
            project_id=validated["packet"]["project_id"],
            output_dir=str(out),
            proposal_file={
                "name": PROPOSAL_NAME,
                "sha256": proposal_sha,
                "size_bytes": len(proposal_bytes),
            },
            authorization_skeleton_file={
                "name": SKELETON_NAME,
                "sha256": skeleton_sha,
                "size_bytes": len(skeleton_bytes),
                "r37_valid": False,
            },
            next_gate="SEPARATE_HUMAN_OR_DETERMINISTIC_CONTROLLER_DECISION_THEN_R44",
            r44_preflight_required=True,
            r37_effectful_gate_required_after_r44_ready=True,
        )
        receipt_bytes = _canonical_bytes(receipt)
        _write_exclusive(out / RECEIPT_NAME, receipt_bytes)
        sums = (
            f"{proposal_sha}  {PROPOSAL_NAME}\n"
            f"{skeleton_sha}  {SKELETON_NAME}\n"
            f"{_sha(receipt_bytes)}  {RECEIPT_NAME}\n"
        ).encode("ascii")
        _write_exclusive(out / SUMS_NAME, sums)
        return receipt
    except Exception as exc:
        if created:
            shutil.rmtree(out, ignore_errors=True)
        return _receipt(
            "PROJECT_UPDATE_MATERIALIZATION_REVISE",
            "MATERIALIZATION_ROLLED_BACK",
            errors=[f"{type(exc).__name__}: {exc}"],
            packet_path=str(packet_file),
            output_dir=str(out),
        )
