"""One read-only operator packet for existing project-memory claim updates.

R52 composes the already-merged R43 claim-sync planner, R51 target-bound R36
proposal, R35 current-work view and R45 authorization-review contract into one
deterministic JSON packet. It removes manual claim-id/hash and proposal-file SHA
copying while deliberately stopping before authority or effects.

The packet contains exact proposal bytes/hash plus an intentionally incomplete R37
authorization skeleton. A HUMAN or DETERMINISTIC_CONTROLLER must still make a
separate decision, materialize exact artifacts, run R44 preflight, and invoke R37
from an unbound process. This module never writes files or OperationalMemory.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Mapping

from . import current_claim_sync as claim_sync
from . import operational_memory_apply as apply
from .current_memory_apply_auth_request import REQUEST_SCHEMA as AUTH_REQUEST_SCHEMA
from .current_work import build_current_work_from_db
from .operational_memory import OperationalMemory
from .operational_memory_target_binding_guard import _validate_bound_target

PACKET_SCHEMA = "continuityos.operational_memory.project_update_review/v1"


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


def _revise(
    reason: str,
    errors: list[str],
    *,
    project_id: str | None = None,
    claim_sync_plan: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "schema": PACKET_SCHEMA,
        "terminal": "CURRENT_PROJECT_UPDATE_REVIEW_REVISE",
        "reason": reason,
        "project_id": project_id,
        "errors": list(errors),
        "packet_id": None,
        "current_work": None,
        "claim_sync_plan": dict(claim_sync_plan) if isinstance(claim_sync_plan, Mapping) else None,
        "proposal": None,
        "authorization_review": None,
        "next_gate": None,
        "apply_status": "NOT_APPLIED",
        "authorization_granted": False,
        "authorization_identity_authenticated": False,
        "semantic_assertions_accepted": False,
        "execution_decision": "HOLD",
        "execution_authorized": False,
        "effects": _effects(),
    }


def _authorization_skeleton(proposal: Mapping[str, Any], proposal_sha: str) -> dict[str, Any]:
    base = proposal["base"]
    return {
        "schema": apply.AUTH_SCHEMA,
        "decision": None,
        "proposal_id": proposal["proposal_id"],
        "proposal_file_sha256": proposal_sha,
        "project_id": proposal["project_id"],
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


def build_project_update_review_packet(
    db_path: str | Path,
    claim_sync_request: Mapping[str, Any],
) -> dict[str, Any]:
    """Compile one deterministic review packet without writing or authorizing."""
    project_id = (
        str(claim_sync_request.get("project_id") or "")
        if isinstance(claim_sync_request, Mapping)
        else ""
    )
    plan = claim_sync.build_claim_sync_plan_from_db(db_path, claim_sync_request)
    if not isinstance(plan, Mapping) or plan.get("terminal") != "CURRENT_CLAIM_SYNC_PLAN_PASS":
        return _revise(
            "CLAIM_SYNC_PLAN_NOT_READY",
            list(plan.get("errors") or [str(plan.get("reason") or "claim-sync rejected")])
            if isinstance(plan, Mapping)
            else ["claim-sync returned non-object"],
            project_id=project_id or None,
            claim_sync_plan=plan if isinstance(plan, Mapping) else None,
        )

    project_id = str(plan["project_id"])
    proposal = plan.get("delta_proposal")
    if not isinstance(proposal, Mapping):
        return _revise(
            "TARGET_BOUND_PROPOSAL_MISSING",
            ["claim-sync plan has no nested R36 proposal"],
            project_id=project_id,
            claim_sync_plan=plan,
        )

    try:
        normalized = apply._validate_proposal(proposal)
        target = _validate_bound_target(normalized, db_path)
        current_work = build_current_work_from_db(db_path, project_id)
        if current_work.get("terminal") == "CURRENT_WORK_REVISE":
            raise ValueError("current-work is REVISE: " + "; ".join(current_work.get("errors") or []))
        expected_work_sha = normalized["base"].get("current_work_capsule_sha256")
        if current_work.get("capsule_sha256") != expected_work_sha:
            raise ValueError(
                "current-work changed after claim-sync projection: "
                f"expected={expected_work_sha} actual={current_work.get('capsule_sha256')}"
            )

        # R53: the work capsule is project-scoped, while R36/R37 bind the proposal to
        # the entire OperationalMemory projection. An unrelated subject can therefore
        # move projection/cursor/chain without changing this project's work capsule.
        # Re-read the full immutable DB snapshot and require the exact R37 base identity
        # before presenting a packet as ready for authority review.
        target_path = target.get("path") if isinstance(target, Mapping) else None
        if not isinstance(target_path, str) or not target_path:
            raise ValueError("target binding returned no canonical path")
        with OperationalMemory(target_path, read_only=True) as memory:
            verification = memory.verify()
            if verification.get("ok") is not True:
                raise ValueError(
                    "operational memory verification failed after claim-sync: "
                    + "; ".join(verification.get("errors") or [])
                )
            current_projection = memory.projection()
        expected_base = apply._expected_base(normalized)
        actual_base = apply._base_identity(current_projection, project_id)
        if actual_base != expected_base:
            raise ValueError(
                "operational-memory base changed after claim-sync projection: "
                f"expected={expected_base} actual={actual_base}"
            )

        proposal_canonical_json = apply._canonical_json(normalized)
        proposal_bytes = proposal_canonical_json.encode("utf-8")
        proposal_sha = hashlib.sha256(proposal_bytes).hexdigest()
        skeleton = _authorization_skeleton(normalized, proposal_sha)
        # Prove the emitted skeleton is intentionally non-authorizing. If this ever
        # becomes valid without explicit authority fields, fail closed.
        try:
            apply._validate_authorization(
                skeleton,
                proposal=normalized,
                proposal_file_sha256=proposal_sha,
            )
        except Exception:
            pass
        else:  # pragma: no cover - hard invariant
            raise RuntimeError("incomplete authorization skeleton unexpectedly validates")
    except Exception as exc:
        return _revise(
            "REVIEW_PACKET_BINDING_FAILED",
            [f"{type(exc).__name__}: {exc}"],
            project_id=project_id,
            claim_sync_plan=plan,
        )

    authorization_review = {
        "schema": AUTH_REQUEST_SCHEMA,
        "authorization_schema": apply.AUTH_SCHEMA,
        "approval_value_if_authorized": apply.AUTH_DECISION,
        "accepted_authority_classes": ["HUMAN", "DETERMINISTIC_CONTROLLER"],
        "authorization_skeleton": skeleton,
        "authority_fields_required": [
            "decision",
            "authority_class",
            "authority_id",
            "authority_ref",
            "apply_recorded_at",
            "rationale",
        ],
        "authorization_skeleton_is_r37_valid": False,
        "authorization_granted": False,
        "authorization_identity_authenticated": False,
    }
    proposal_packet = {
        "proposal_id": normalized["proposal_id"],
        "proposal_file_sha256": proposal_sha,
        "proposal_file_size_bytes": len(proposal_bytes),
        "proposal_canonical_json": proposal_canonical_json,
        "operational_memory_target": target,
        "apply_status": "NOT_APPLIED",
    }
    body = {
        "schema": PACKET_SCHEMA,
        "terminal": "CURRENT_PROJECT_UPDATE_REVIEW_PASS",
        "reason": "TARGET_BOUND_CLAIM_UPDATE_READY_FOR_SEPARATE_AUTHORITY_REVIEW",
        "project_id": project_id,
        "current_work": current_work,
        "claim_sync_plan": plan,
        "proposal": proposal_packet,
        "authorization_review": authorization_review,
        "next_gate": {
            "step": "SEPARATE_AUTHORITY_DECISION_THEN_R44_PREFLIGHT",
            "materialize_exact_proposal_bytes": True,
            "fill_authority_fields": True,
            "r44_preflight_required": True,
            "r37_effectful_gate_required_after_r44_ready": True,
            "current_session_must_not_run_r37": True,
        },
        "apply_status": "NOT_APPLIED",
        "authorization_granted": False,
        "authorization_identity_authenticated": False,
        "semantic_assertions_accepted": False,
        "execution_decision": "HOLD",
        "execution_authorized": False,
        "effects": _effects(),
    }
    packet_id = "purp-" + hashlib.sha256(apply._canonical_json(body).encode("utf-8")).hexdigest()[:40]
    return {**body, "packet_id": packet_id}
