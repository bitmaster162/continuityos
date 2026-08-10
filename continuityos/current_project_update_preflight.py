"""Packet-aware read-only preflight after R52 authority review.

R54 accepts an exact R52 review packet plus separately completed raw R37
authorization bytes. It validates the packet/proposal transport in memory and
reuses the R37 validators plus R44 operation-target checker against an immutable
OperationalMemory snapshot. It never materializes proposal bytes, writes memory,
or grants execution. R37 remains the separate unbound effectful gate and must
re-read exact materialized proposal/authorization artifacts before commit.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Mapping

from . import current_memory_apply_check as r44
from . import operational_memory_apply as apply
from .current_project_update_review import PACKET_SCHEMA
from .operational_memory import _canonical_json, strict_json_loads
from .operational_memory_target_binding_guard import _validate_bound_target

PREFLIGHT_SCHEMA = "continuityos.operational_memory.project_update_packet_preflight/v1"

_PACKET_BODY_KEYS = {
    "schema", "terminal", "reason", "project_id", "current_work",
    "claim_sync_plan", "proposal", "authorization_review", "next_gate",
    "apply_status", "authorization_granted", "authorization_identity_authenticated",
    "semantic_assertions_accepted", "execution_decision", "execution_authorized",
    "effects",
}


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


def _result(terminal: str, reason: str, *, errors=None, project_id=None, **extra: Any) -> dict[str, Any]:
    return {
        "schema": PREFLIGHT_SCHEMA,
        "terminal": terminal,
        "reason": reason,
        "project_id": project_id,
        "errors": list(errors or []),
        "point_in_time": True,
        "packet_valid": False,
        "authorization_record_valid": False,
        "authorization_identity_authenticated": False,
        "apply_status": "NOT_APPLIED",
        "apply_ready": False,
        "execution_decision": "HOLD",
        "execution_authorized": False,
        "accepted_truth_modified": False,
        "effects": _effects(),
        **extra,
    }


def _validate_packet(value: Any) -> tuple[dict[str, Any], dict[str, Any], bytes, str]:
    if not isinstance(value, Mapping):
        raise ValueError("packet root must be an object")
    required = _PACKET_BODY_KEYS | {"packet_id"}
    missing = required - set(value)
    if missing:
        raise ValueError(f"packet missing required keys: {sorted(missing)}")
    if value.get("schema") != PACKET_SCHEMA:
        raise ValueError("packet schema mismatch")
    if value.get("terminal") != "CURRENT_PROJECT_UPDATE_REVIEW_PASS":
        raise ValueError("packet is not PASS")
    if value.get("apply_status") != "NOT_APPLIED":
        raise ValueError("packet apply ceiling mismatch")
    if value.get("authorization_granted") is not False:
        raise ValueError("packet unexpectedly grants authorization")
    if value.get("execution_authorized") is not False or value.get("execution_decision") != "HOLD":
        raise ValueError("packet execution ceiling mismatch")

    body = {key: value[key] for key in _PACKET_BODY_KEYS}
    expected_packet_id = "purp-" + hashlib.sha256(_canonical_json(body).encode("utf-8")).hexdigest()[:40]
    if value.get("packet_id") != expected_packet_id:
        raise ValueError("packet_id integrity mismatch")

    proposal_packet = value.get("proposal")
    if not isinstance(proposal_packet, Mapping):
        raise ValueError("packet proposal missing")
    canonical = proposal_packet.get("proposal_canonical_json")
    if not isinstance(canonical, str) or not canonical:
        raise ValueError("packet proposal_canonical_json missing")
    proposal_bytes = canonical.encode("utf-8")
    proposal_sha = hashlib.sha256(proposal_bytes).hexdigest()
    if proposal_packet.get("proposal_file_sha256") != proposal_sha:
        raise ValueError("embedded proposal SHA mismatch")
    if proposal_packet.get("proposal_file_size_bytes") != len(proposal_bytes):
        raise ValueError("embedded proposal size mismatch")
    try:
        proposal_raw = strict_json_loads(canonical)
    except Exception as exc:
        raise ValueError(f"embedded proposal invalid JSON: {exc}") from exc
    proposal = apply._validate_proposal(proposal_raw)
    if _canonical_json(proposal) != canonical:
        raise ValueError("embedded proposal bytes are not canonical exact proposal bytes")
    if proposal.get("proposal_id") != proposal_packet.get("proposal_id"):
        raise ValueError("packet proposal_id mismatch")
    if proposal.get("project_id") != value.get("project_id"):
        raise ValueError("packet project/proposal mismatch")
    return dict(value), proposal, proposal_bytes, proposal_sha


def preflight_project_update_packet(
    db_path: str | Path,
    packet: Mapping[str, Any],
    authorization_bytes: bytes,
) -> dict[str, Any]:
    """Validate an R52 packet + completed authorization against immutable memory."""
    try:
        if not isinstance(authorization_bytes, bytes) or not authorization_bytes:
            raise ValueError("authorization bytes must be non-empty bytes")
        authorization_file_sha256 = hashlib.sha256(authorization_bytes).hexdigest()
        try:
            authorization_raw = strict_json_loads(authorization_bytes.decode("utf-8-sig"))
        except Exception as exc:
            raise ValueError(f"authorization invalid JSON: {exc}") from exc
        if not isinstance(authorization_raw, Mapping):
            raise ValueError("authorization root must be an object")

        packet_value, proposal, proposal_bytes, proposal_sha = _validate_packet(packet)
        auth = apply._validate_authorization(
            authorization_raw,
            proposal=proposal,
            proposal_file_sha256=proposal_sha,
        )
        target = _validate_bound_target(proposal, db_path)
        packet_target = packet_value["proposal"].get("operational_memory_target")
        if packet_target != target:
            raise ValueError("packet operational-memory target metadata mismatch")
    except Exception as exc:
        return _result(
            "CURRENT_PROJECT_UPDATE_PREFLIGHT_REVISE",
            "PACKET_OR_AUTHORIZATION_INVALID",
            errors=[f"{type(exc).__name__}: {exc}"],
        )

    project_id = proposal["project_id"]
    common = {
        "packet_id": packet_value["packet_id"],
        "packet_valid": True,
        "proposal_id": proposal["proposal_id"],
        "proposal_file_sha256": proposal_sha,
        "proposal_file_size_bytes": len(proposal_bytes),
        "authorization_file_sha256": authorization_file_sha256,
        "authorization_record_valid": True,
        "authorization": {
            "class": auth["authority_class"],
            "id": auth["authority_id"],
            "ref": auth["authority_ref"],
        },
        "operational_memory_target": target,
    }
    try:
        db = Path(target["path"])
        with apply.OperationalMemory(str(db), read_only=True, immutable=True) as memory:
            verification = memory.verify()
            if verification.get("ok") is not True:
                raise ValueError("operational memory verification failed")
            prior = apply._find_prior_apply(memory, proposal["proposal_id"], proposal_sha)
            if prior is not None:
                durable_auth_sha = prior.get("payload", {}).get("authorization_file_sha256")
                if durable_auth_sha != authorization_file_sha256:
                    return _result(
                        "CURRENT_PROJECT_UPDATE_PREFLIGHT_REVISE",
                        "REPLAY_AUTHORIZATION_IDENTITY_MISMATCH",
                        project_id=project_id,
                        errors=[
                            f"durable_authorization_file_sha256={durable_auth_sha}",
                            f"presented_authorization_file_sha256={authorization_file_sha256}",
                        ],
                        durable_apply_event=prior,
                        durable_authorization_file_sha256=durable_auth_sha,
                        presented_authorization_file_sha256=authorization_file_sha256,
                        effectful_gate_required=False,
                        r37_revalidation_required=False,
                        **common,
                    )
                projection = memory.projection()
                return _result(
                    "CURRENT_PROJECT_UPDATE_PREFLIGHT_ALREADY_APPLIED",
                    "EXACT_PROPOSAL_ALREADY_APPLIED",
                    project_id=project_id,
                    apply_status="ALREADY_APPLIED",
                    effectful_gate_required=False,
                    r37_revalidation_required=False,
                    durable_apply_event=prior,
                    current_projection_sha256=projection.get("projection_sha256"),
                    **common,
                )
            projection = memory.projection()
            actual_base = apply._base_identity(projection, project_id)
            expected_base = apply._expected_base(proposal)
            if actual_base != expected_base:
                return _result(
                    "CURRENT_PROJECT_UPDATE_PREFLIGHT_REVISE",
                    "STALE_OPERATIONAL_MEMORY_BASE",
                    project_id=project_id,
                    errors=[f"expected={expected_base}", f"actual={actual_base}"],
                    current_base=actual_base,
                    expected_base=expected_base,
                    effectful_gate_required=True,
                    r37_revalidation_required=True,
                    **common,
                )
            checked = r44._check_operation_targets(memory, proposal, auth)
    except Exception as exc:
        return _result(
            "CURRENT_PROJECT_UPDATE_PREFLIGHT_REVISE",
            "OPERATIONAL_MEMORY_PREFLIGHT_FAILED",
            project_id=project_id,
            errors=[f"{type(exc).__name__}: {exc}"],
            effectful_gate_required=True,
            r37_revalidation_required=True,
            **common,
        )

    return _result(
        "CURRENT_PROJECT_UPDATE_PREFLIGHT_READY",
        "PACKET_AUTHORIZATION_BASE_AND_TARGETS_VALIDATED",
        project_id=project_id,
        apply_ready=True,
        expected_base=apply._expected_base(proposal),
        operation_targets=checked,
        next_gate={
            "step": "MATERIALIZE_EXACT_PROPOSAL_AND_RUN_R37_UNBOUND",
            "proposal_canonical_json": packet_value["proposal"]["proposal_canonical_json"],
            "proposal_file_sha256": proposal_sha,
            "authorization_file_sha256": authorization_file_sha256,
            "r37_must_revalidate": True,
            "current_session_must_not_run_r37": True,
        },
        effectful_gate_required=True,
        r37_revalidation_required=True,
        **common,
    )
