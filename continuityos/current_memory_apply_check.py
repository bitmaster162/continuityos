"""Read-only point-in-time preflight for R37 shadow-memory apply.

R44 validates the exact R36 proposal, R37 authorization, current immutable memory
base, replay identity, and operation targets while the verified current session
remains READ_ONLY. It never starts a write transaction or applies the proposal.
R37 remains the separate effectful gate and revalidates everything under its own
write lock before commit.
"""
from __future__ import annotations

from pathlib import Path
import stat
from typing import Any, Mapping

from . import operational_memory_apply as apply

CHECK_SCHEMA = "continuityos.operational_memory.apply_check/v1"


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
        "schema": CHECK_SCHEMA,
        "terminal": terminal,
        "reason": reason,
        "project_id": project_id,
        "errors": list(errors or []),
        "point_in_time": True,
        "authorization_identity_authenticated": False,
        "apply_status": "NOT_APPLIED",
        "apply_ready": False,
        "execution_decision": "HOLD",
        "execution_authorized": False,
        "accepted_truth_modified": False,
        "effects": _effects(),
        **extra,
    }


def _check_operation_targets(
    memory: Any,
    proposal: Mapping[str, Any],
    authorization: Mapping[str, Any],
) -> list[dict[str, Any]]:
    con = memory.con
    project_id = proposal["project_id"]
    rec = authorization["apply_recorded_at"]
    checked: list[dict[str, Any]] = []
    for op in proposal["operations"]:
        kind = op["op"]
        if kind in {"RECORD_CLAIM", "SUPERSEDE_CLAIM"}:
            predicate = apply._nonempty(op.get("predicate"), field="predicate")
            scope = apply._nonempty(op.get("scope"), field="scope")
            state = apply._nonempty(op.get("evidence_state"), field="evidence_state").upper()
            if state not in apply.EVIDENCE_STATES:
                raise ValueError("invalid claim evidence_state")
            refs = apply.normalize_evidence_refs(op.get("evidence_refs"))
            if state != "UNKNOWN" and not refs:
                raise apply.PolicyViolation(f"{state} claim requires immutable evidence")
            # Mirror R37 exactly: an omitted valid_from means apply_recorded_at.
            vf = apply._normalize_time(op.get("valid_from") or rec, field="valid_from")
            vt = apply._normalize_time(op.get("valid_to"), field="valid_to") if op.get("valid_to") is not None else None
            if vt is not None and vt <= vf:
                raise ValueError("valid_to must be later than valid_from")
            target_id = op.get("supersedes_id")
            if target_id:
                row = con.execute("SELECT * FROM claims WHERE claim_id=?", (target_id,)).fetchone()
                if row is None:
                    raise ValueError(f"supersedes claim missing: {target_id}")
                if row["claim_hash"] != op.get("superseded_hash"):
                    raise apply.IdentityConflict(f"superseded claim hash drift: {target_id}")
                if (row["subject_id"], row["predicate"], row["scope"]) != (project_id, predicate, scope):
                    raise apply.PolicyViolation("supersede claim identity mismatch")
                if con.execute("SELECT 1 FROM claims WHERE supersedes_id=?", (target_id,)).fetchone() is not None:
                    raise apply.PolicyViolation(f"claim already superseded: {target_id}")
            elif apply._current_claim_rows(con, project_id, predicate, scope):
                raise apply.PolicyViolation(
                    f"RECORD_CLAIM would create competing current claim for {predicate}/{scope}"
                )
            checked.append({"operation_index": op["operation_index"], "op": kind, "target": target_id})
            continue

        decision_type = apply._nonempty(op.get("decision_type"), field="decision_type")
        state = apply._nonempty(op.get("state"), field="state").upper()
        if state not in apply.DECISION_STATES:
            raise ValueError("invalid decision state")
        if kind == "RECORD_DECISION" and state == "SUPERSEDED":
            raise apply.PolicyViolation("RECORD_DECISION cannot create standalone SUPERSEDED state")
        refs = apply.normalize_evidence_refs(op.get("evidence_refs"))
        if state in apply.TERMINAL_DECISIONS and not refs:
            raise apply.PolicyViolation(f"{state} decision requires immutable evidence")
        apply._nonempty(op.get("rationale"), field="rationale")
        target_id = op.get("supersedes_id")
        if target_id:
            row = con.execute("SELECT * FROM decisions WHERE decision_id=?", (target_id,)).fetchone()
            if row is None:
                raise ValueError(f"supersedes decision missing: {target_id}")
            if row["decision_hash"] != op.get("superseded_hash"):
                raise apply.IdentityConflict(f"superseded decision hash drift: {target_id}")
            if (row["subject_id"], row["decision_type"]) != (project_id, decision_type):
                raise apply.PolicyViolation("supersede decision identity mismatch")
            if con.execute("SELECT 1 FROM decisions WHERE supersedes_id=?", (target_id,)).fetchone() is not None:
                raise apply.PolicyViolation(f"decision already superseded: {target_id}")
        elif state in apply.TERMINAL_DECISIONS:
            current = apply._current_decision_rows(con, project_id, decision_type)
            if any(row["state"] in apply.TERMINAL_DECISIONS for row in current):
                raise apply.PolicyViolation(f"terminal RECORD_DECISION would compete with current {decision_type}")
        checked.append({"operation_index": op["operation_index"], "op": kind, "target": target_id})
    return checked


def check_authorized_memory_delta(db_path: str | Path, proposal_path: str | Path, authorization_path: str | Path) -> dict[str, Any]:
    """Validate R37 readiness against an immutable snapshot; never write."""
    try:
        proposal_bytes = apply._stable_read(Path(proposal_path), "proposal")
        auth_bytes = apply._stable_read(Path(authorization_path), "authorization")
        proposal_sha = apply._sha_bytes(proposal_bytes)
        auth_sha = apply._sha_bytes(auth_bytes)
        proposal = apply._validate_proposal(apply._load_object(proposal_bytes, "proposal"))
        authorization = apply._validate_authorization(
            apply._load_object(auth_bytes, "authorization"),
            proposal=proposal,
            proposal_file_sha256=proposal_sha,
        )
    except Exception as exc:
        return _result(
            "CURRENT_MEMORY_APPLY_CHECK_REVISE", "APPLY_ARTIFACT_INVALID",
            errors=[f"{type(exc).__name__}: {exc}"],
            r37_revalidation_required=True,
        )

    project_id = proposal["project_id"]
    db = Path(db_path).expanduser().absolute()
    if not db.is_file() or db.is_symlink():
        return _result(
            "CURRENT_MEMORY_APPLY_CHECK_REVISE", "OPERATIONAL_MEMORY_MISSING_OR_UNSAFE",
            project_id=project_id, errors=[str(db)], r37_revalidation_required=True,
        )
    attrs = getattr(db.lstat(), "st_file_attributes", 0)
    if attrs & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400):
        return _result(
            "CURRENT_MEMORY_APPLY_CHECK_REVISE", "OPERATIONAL_MEMORY_REPARSE_REFUSED",
            project_id=project_id, errors=[str(db)], r37_revalidation_required=True,
        )

    common = {
        "proposal_id": proposal["proposal_id"],
        "proposal_file_sha256": proposal_sha,
        "authorization_file_sha256": auth_sha,
        "authorization_record_valid": True,
        "authorization": {
            "class": authorization["authority_class"],
            "id": authorization["authority_id"],
            "ref": authorization["authority_ref"],
        },
    }
    try:
        with apply.OperationalMemory(str(db), read_only=True, immutable=True) as memory:
            verification = memory.verify()
            if verification.get("ok") is not True:
                raise ValueError("operational memory verification failed")
            prior = apply._find_prior_apply(memory, proposal["proposal_id"], proposal_sha)
            if prior is not None:
                projection = memory.projection()
                return _result(
                    "CURRENT_MEMORY_APPLY_CHECK_ALREADY_APPLIED",
                    "EXACT_PROPOSAL_ALREADY_APPLIED",
                    project_id=project_id,
                    apply_status="ALREADY_APPLIED",
                    apply_ready=False,
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
                    "CURRENT_MEMORY_APPLY_CHECK_REVISE",
                    "STALE_OPERATIONAL_MEMORY_BASE",
                    project_id=project_id,
                    errors=[f"expected={expected_base}", f"actual={actual_base}"],
                    current_base=actual_base,
                    expected_base=expected_base,
                    effectful_gate_required=True,
                    r37_revalidation_required=True,
                    **common,
                )
            checked = _check_operation_targets(memory, proposal, authorization)
    except Exception as exc:
        return _result(
            "CURRENT_MEMORY_APPLY_CHECK_REVISE",
            "OPERATIONAL_MEMORY_PREFLIGHT_FAILED",
            project_id=project_id,
            errors=[f"{type(exc).__name__}: {exc}"],
            effectful_gate_required=True,
            r37_revalidation_required=True,
            **common,
        )

    return _result(
        "CURRENT_MEMORY_APPLY_CHECK_READY",
        "ARTIFACTS_BASE_AND_OPERATION_TARGETS_VALIDATED",
        project_id=project_id,
        apply_ready=True,
        expected_base=apply._expected_base(proposal),
        operation_targets=checked,
        effectful_gate_required=True,
        r37_revalidation_required=True,
        **common,
    )
