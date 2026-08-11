"""Read-only authorization-request packet for an exact R36 memory proposal.

R45 removes manual copying of proposal/base/count fields before authority review.
It validates the proposal and the current immutable OperationalMemory base, then
emits an intentionally incomplete R37 authorization skeleton. The skeleton cannot
pass R37 until a HUMAN or DETERMINISTIC_CONTROLLER explicitly supplies the approval
decision and authority-specific fields.

This module never grants authority, authenticates an identity, writes memory, or
runs the effectful R37 gate.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import stat
from typing import Any

from . import operational_memory_apply as apply

REQUEST_SCHEMA = "continuityos.operational_memory.apply_authorization_request/v1"


def _effects() -> dict[str, Any]:
    return {
        "operational_memory_write": False,
        "filesystem_write": False,
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


def _result(terminal: str, reason: str, *, project_id: str | None = None, errors=None, **extra: Any) -> dict[str, Any]:
    return {
        "schema": REQUEST_SCHEMA,
        "terminal": terminal,
        "reason": reason,
        "project_id": project_id,
        "errors": list(errors or []),
        "authorization_artifact_created": False,
        "authorization_granted": False,
        "authorization_identity_authenticated": False,
        "apply_status": "NOT_APPLIED",
        "execution_decision": "HOLD",
        "execution_authorized": False,
        "accepted_truth_modified": False,
        "effects": _effects(),
        **extra,
    }


def build_apply_authorization_request(db_path: str | Path, proposal_path: str | Path) -> dict[str, Any]:
    """Bind exact proposal/base fields for review without creating authorization."""
    try:
        proposal_bytes = apply._stable_read(Path(proposal_path), "proposal")
        proposal_sha = apply._sha_bytes(proposal_bytes)
        proposal = apply._validate_proposal(apply._load_object(proposal_bytes, "proposal"))
    except Exception as exc:
        return _result(
            "CURRENT_MEMORY_APPLY_AUTH_REQUEST_REVISE",
            "PROPOSAL_INVALID",
            errors=[f"{type(exc).__name__}: {exc}"],
        )

    project_id = str(proposal["project_id"])
    db = Path(db_path).expanduser().absolute()
    if not db.is_file() or db.is_symlink():
        return _result(
            "CURRENT_MEMORY_APPLY_AUTH_REQUEST_REVISE",
            "OPERATIONAL_MEMORY_MISSING_OR_UNSAFE",
            project_id=project_id,
            errors=[str(db)],
        )
    attrs = getattr(db.lstat(), "st_file_attributes", 0)
    if attrs & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400):
        return _result(
            "CURRENT_MEMORY_APPLY_AUTH_REQUEST_REVISE",
            "OPERATIONAL_MEMORY_REPARSE_REFUSED",
            project_id=project_id,
            errors=[str(db)],
        )

    try:
        with apply.OperationalMemory(str(db), read_only=True, immutable=True) as memory:
            verification = memory.verify()
            if verification.get("ok") is not True:
                raise ValueError("operational memory verification failed")
            prior = apply._find_prior_apply(memory, proposal["proposal_id"], proposal_sha)
            if prior is not None:
                projection = memory.projection()
                return _result(
                    "CURRENT_MEMORY_APPLY_AUTH_REQUEST_ALREADY_APPLIED",
                    "EXACT_PROPOSAL_ALREADY_APPLIED",
                    project_id=project_id,
                    proposal_id=proposal["proposal_id"],
                    proposal_file_sha256=proposal_sha,
                    apply_status="ALREADY_APPLIED",
                    authority_review_required=False,
                    r44_preflight_required=False,
                    r37_effectful_gate_required=False,
                    durable_apply_event=prior,
                    current_projection_sha256=projection.get("projection_sha256"),
                )
            projection = memory.projection()
            actual_base = apply._base_identity(projection, project_id)
            expected_base = apply._expected_base(proposal)
            if actual_base != expected_base:
                return _result(
                    "CURRENT_MEMORY_APPLY_AUTH_REQUEST_REVISE",
                    "STALE_OPERATIONAL_MEMORY_BASE",
                    project_id=project_id,
                    proposal_id=proposal["proposal_id"],
                    proposal_file_sha256=proposal_sha,
                    expected_base=expected_base,
                    current_base=actual_base,
                    errors=[f"expected={expected_base}", f"actual={actual_base}"],
                )
    except Exception as exc:
        return _result(
            "CURRENT_MEMORY_APPLY_AUTH_REQUEST_REVISE",
            "OPERATIONAL_MEMORY_PREFLIGHT_FAILED",
            project_id=project_id,
            proposal_id=proposal.get("proposal_id"),
            proposal_file_sha256=proposal_sha,
            errors=[f"{type(exc).__name__}: {exc}"],
        )

    base = proposal["base"]
    skeleton = {
        "schema": apply.AUTH_SCHEMA,
        "decision": None,
        "proposal_id": proposal["proposal_id"],
        "proposal_file_sha256": proposal_sha,
        "project_id": project_id,
        "base_projection_sha256": base["projection_sha256"],
        "base_event_cursor": base["event_cursor"],
        "base_event_chain_head": base["event_chain_head"],
        "operation_count": len(proposal["operations"]),
        "authority_class": None,
        "authority_id": None,
        "authority_ref": None,
        "apply_recorded_at": None,
        "rationale": None,
    }
    request_body = {
        "proposal_id": proposal["proposal_id"],
        "proposal_file_sha256": proposal_sha,
        "project_id": project_id,
        "base": apply._expected_base(proposal),
        "operation_count": len(proposal["operations"]),
    }
    request_id = "omar-" + hashlib.sha256(apply._canonical_json(request_body).encode("utf-8")).hexdigest()[:40]
    return _result(
        "CURRENT_MEMORY_APPLY_AUTH_REQUEST_PASS",
        "EXACT_PROPOSAL_AND_BASE_BOUND_FOR_AUTHORITY_REVIEW",
        project_id=project_id,
        request_id=request_id,
        proposal_id=proposal["proposal_id"],
        proposal_file_sha256=proposal_sha,
        expected_base=apply._expected_base(proposal),
        operation_count=len(proposal["operations"]),
        authorization_schema=apply.AUTH_SCHEMA,
        approval_value_if_authorized=apply.AUTH_DECISION,
        accepted_authority_classes=["HUMAN", "DETERMINISTIC_CONTROLLER"],
        authorization_skeleton=skeleton,
        authority_fields_required=[
            "decision", "authority_class", "authority_id", "authority_ref",
            "apply_recorded_at", "rationale",
        ],
        authority_review_required=True,
        authorization_skeleton_is_r37_valid=False,
        r44_preflight_required_after_authorization=True,
        r37_effectful_gate_required_after_r44_ready=True,
        temporal_and_target_revalidation_deferred_to_r44_and_r37=True,
    )
