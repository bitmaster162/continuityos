"""Proposal-only, base-bound OperationalMemory delta compiler.

A verified current session is deliberately unable to mutate OperationalMemory. This
module provides the missing handoff: it validates a requested set of claim/decision
changes against one exact read-only projection and emits a deterministic proposal
artifact. It never applies the proposal.

The proposal is bound to projection SHA/event cursor/chain head and to the R35
current-work capsule. Any future applier must prove those bases still match before
writing. This module does not implement that applier.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Mapping, Sequence

from .current_work import build_current_work_from_db

REQUEST_SCHEMA = "continuityos.operational_memory.delta_request/v1"
PROPOSAL_SCHEMA = "continuityos.operational_memory.delta_proposal/v1"
PROJECTION_SCHEMA = "continuityos.common_operational_memory.projection.v1"

CLAIM_OPS = {"RECORD_CLAIM", "SUPERSEDE_CLAIM"}
DECISION_OPS = {"RECORD_DECISION", "SUPERSEDE_DECISION"}
OPS = CLAIM_OPS | DECISION_OPS
EVIDENCE_STATES = {
    "VERIFIED", "SOURCE_BACKED", "INFERENCE", "ASSUMPTION", "HYPOTHESIS", "UNKNOWN"
}
DECISION_STATES = {"PROPOSED", "ACCEPTED", "REJECTED", "HOLD", "SUPERSEDED"}
TERMINAL_DECISION_STATES = {"ACCEPTED", "REJECTED", "HOLD", "SUPERSEDED"}


def _canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def _sha(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _effects() -> dict[str, Any]:
    return {
        "operational_memory_write": False,
        "filesystem_write": False,
        "legacy_ledger_write": False,
        "network_effect": False,
        "subprocess_execution": False,
        "agent_dispatch": False,
        "external_message": False,
        "deployment": False,
        "current_state_apply": False,
        "canonical_mutation": False,
        "trading": False,
        "wallet_access": False,
        "order_execution": False,
        "can_trade": False,
        "capital_permission": "DENY",
        "deploy_permission": "DENY",
    }


def _revise(reason: str, errors: Sequence[str], *, project_id: str | None = None) -> dict[str, Any]:
    return {
        "schema": PROPOSAL_SCHEMA,
        "terminal": "CURRENT_MEMORY_DELTA_PROPOSAL_REVISE",
        "reason": reason,
        "project_id": project_id,
        "errors": list(errors),
        "proposal_id": None,
        "apply_status": "NOT_APPLIED",
        "apply_implemented": False,
        "execution_decision": "HOLD",
        "execution_authorized": False,
        "effects": _effects(),
    }


def _nonempty(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be a non-empty string")
    return value.strip()


def _exact_keys(value: Any, allowed: set[str], required: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{label} must be an object")
    extra = set(value) - allowed
    missing = required - set(value)
    if extra or missing:
        raise ValueError(f"{label} keys mismatch: missing={sorted(missing)} extra={sorted(extra)}")
    return value


def _normalize_refs(value: Any, label: str) -> list[dict[str, Any]]:
    # Reuse the exact OperationalMemory evidence contract without opening storage.
    from .operational_memory import normalize_evidence_refs

    if value is None:
        value = []
    if not isinstance(value, list):
        raise ValueError(f"{label} must be an array")
    return normalize_evidence_refs(value)


def _normalize_claim_operation(
    raw: Mapping[str, Any],
    *,
    project_id: str,
    current_claims: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    op = str(raw.get("op") or "").upper()
    allowed = {
        "op", "predicate", "scope", "value", "evidence_state", "evidence_refs",
        "valid_from", "valid_to", "supersedes_id", "note",
    }
    required = {"op", "value", "evidence_state"}
    if op == "RECORD_CLAIM":
        required |= {"predicate", "scope"}
    else:
        required |= {"supersedes_id"}
    _exact_keys(raw, allowed, required, f"operation[{op}]")

    state = _nonempty(raw.get("evidence_state"), "evidence_state").upper()
    if state not in EVIDENCE_STATES:
        raise ValueError(f"unsupported evidence_state: {state}")
    refs = _normalize_refs(raw.get("evidence_refs"), "evidence_refs")
    if state != "UNKNOWN" and not refs:
        raise ValueError(f"{state} claim proposal requires immutable evidence_refs")

    supersedes_id = None
    superseded_hash = None
    if op == "SUPERSEDE_CLAIM":
        supersedes_id = _nonempty(raw.get("supersedes_id"), "supersedes_id")
        target = current_claims.get(supersedes_id)
        if target is None:
            raise ValueError(f"supersedes_id is not a current project claim: {supersedes_id}")
        predicate = str(target.get("predicate"))
        scope = str(target.get("scope"))
        if raw.get("predicate") is not None and _nonempty(raw.get("predicate"), "predicate") != predicate:
            raise ValueError("supersede predicate differs from current target")
        if raw.get("scope") is not None and _nonempty(raw.get("scope"), "scope") != scope:
            raise ValueError("supersede scope differs from current target")
        superseded_hash = target.get("claim_hash")
    else:
        predicate = _nonempty(raw.get("predicate"), "predicate")
        scope = _nonempty(raw.get("scope"), "scope")

    valid_from = raw.get("valid_from")
    valid_to = raw.get("valid_to")
    if valid_from is not None:
        valid_from = _nonempty(valid_from, "valid_from")
    if valid_to is not None:
        valid_to = _nonempty(valid_to, "valid_to")
    note = raw.get("note")
    if note is not None:
        note = _nonempty(note, "note")

    return {
        "op": op,
        "subject_id": project_id,
        "predicate": predicate,
        "scope": scope,
        "value": raw.get("value"),
        "evidence_state": state,
        "evidence_refs": refs,
        "valid_from": valid_from,
        "valid_to": valid_to,
        "supersedes_id": supersedes_id,
        "superseded_hash": superseded_hash,
        "required_authority": "DETERMINISTIC_CONTROLLER_OR_HUMAN_REVIEW",
        "note": note,
    }


def _normalize_decision_operation(
    raw: Mapping[str, Any],
    *,
    project_id: str,
    current_decisions: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    op = str(raw.get("op") or "").upper()
    allowed = {
        "op", "decision_type", "state", "value", "rationale", "evidence_refs",
        "supersedes_id", "note",
    }
    required = {"op", "state", "value", "rationale"}
    if op == "RECORD_DECISION":
        required |= {"decision_type"}
    else:
        required |= {"supersedes_id"}
    _exact_keys(raw, allowed, required, f"operation[{op}]")

    state = _nonempty(raw.get("state"), "state").upper()
    if state not in DECISION_STATES:
        raise ValueError(f"unsupported decision state: {state}")
    rationale = _nonempty(raw.get("rationale"), "rationale")
    refs = _normalize_refs(raw.get("evidence_refs"), "evidence_refs")
    if state in TERMINAL_DECISION_STATES and not refs:
        raise ValueError(f"{state} decision proposal requires immutable evidence_refs")

    supersedes_id = None
    superseded_hash = None
    if op == "SUPERSEDE_DECISION":
        supersedes_id = _nonempty(raw.get("supersedes_id"), "supersedes_id")
        target = current_decisions.get(supersedes_id)
        if target is None:
            raise ValueError(f"supersedes_id is not a current project decision: {supersedes_id}")
        decision_type = str(target.get("decision_type"))
        if raw.get("decision_type") is not None and _nonempty(raw.get("decision_type"), "decision_type") != decision_type:
            raise ValueError("supersede decision_type differs from current target")
        superseded_hash = target.get("decision_hash")
    else:
        decision_type = _nonempty(raw.get("decision_type"), "decision_type")

    note = raw.get("note")
    if note is not None:
        note = _nonempty(note, "note")
    return {
        "op": op,
        "subject_id": project_id,
        "decision_type": decision_type,
        "state": state,
        "value": raw.get("value"),
        "rationale": rationale,
        "evidence_refs": refs,
        "supersedes_id": supersedes_id,
        "superseded_hash": superseded_hash,
        "required_authority": (
            "HUMAN_OR_DETERMINISTIC_CONTROLLER"
            if state in TERMINAL_DECISION_STATES
            else "PROPOSAL_REVIEW"
        ),
        "note": note,
    }


def compile_memory_delta_proposal(
    projection: Mapping[str, Any],
    current_work: Mapping[str, Any],
    request: Mapping[str, Any],
) -> dict[str, Any]:
    """Compile one deterministic NOT_APPLIED proposal against exact current bytes."""
    try:
        _exact_keys(request, {"schema", "project_id", "operations", "rationale"}, {"schema", "project_id", "operations"}, "request")
        if request.get("schema") != REQUEST_SCHEMA:
            raise ValueError("unexpected request schema")
        project_id = _nonempty(request.get("project_id"), "project_id")
        operations_raw = request.get("operations")
        if not isinstance(operations_raw, list) or not operations_raw:
            raise ValueError("operations must be a non-empty array")
        if len(operations_raw) > 64:
            raise ValueError("operations exceeds maximum of 64")
        rationale = request.get("rationale")
        if rationale is not None:
            rationale = _nonempty(rationale, "rationale")
    except Exception as exc:
        return _revise("DELTA_REQUEST_INVALID", [str(exc)], project_id=str(request.get("project_id") or "") if isinstance(request, Mapping) else None)

    if not isinstance(projection, Mapping) or projection.get("schema") != PROJECTION_SCHEMA:
        return _revise("OPERATIONAL_PROJECTION_INVALID", ["unexpected projection schema"], project_id=project_id)
    if not isinstance(current_work, Mapping) or current_work.get("project_id") != project_id:
        return _revise("CURRENT_WORK_BINDING_INVALID", ["current-work capsule does not bind requested project"], project_id=project_id)
    if current_work.get("terminal") == "CURRENT_WORK_REVISE":
        return _revise("CURRENT_WORK_NOT_USABLE", list(current_work.get("errors") or ["current-work REVISE"]), project_id=project_id)

    current_claims = {
        str(row.get("claim_id")): row
        for row in list(projection.get("claims") or [])
        if row.get("subject_id") == project_id and row.get("claim_id")
    }
    current_decisions = {
        str(row.get("decision_id")): row
        for row in list(projection.get("decisions") or [])
        if row.get("subject_id") == project_id and row.get("decision_id")
    }

    operations: list[dict[str, Any]] = []
    errors: list[str] = []
    superseded_claims: set[str] = set()
    superseded_decisions: set[str] = set()
    for index, raw in enumerate(operations_raw):
        try:
            if not isinstance(raw, Mapping):
                raise ValueError("operation must be an object")
            op = _nonempty(raw.get("op"), "op").upper()
            if op not in OPS:
                raise ValueError(f"unsupported op: {op}")
            if op in CLAIM_OPS:
                normalized = _normalize_claim_operation(raw, project_id=project_id, current_claims=current_claims)
                target = normalized.get("supersedes_id")
                if target:
                    if target in superseded_claims:
                        raise ValueError(f"claim is superseded twice in one proposal: {target}")
                    superseded_claims.add(str(target))
            else:
                normalized = _normalize_decision_operation(raw, project_id=project_id, current_decisions=current_decisions)
                target = normalized.get("supersedes_id")
                if target:
                    if target in superseded_decisions:
                        raise ValueError(f"decision is superseded twice in one proposal: {target}")
                    superseded_decisions.add(str(target))
            normalized["operation_index"] = index
            operations.append(normalized)
        except Exception as exc:
            errors.append(f"operations[{index}]: {exc}")
    if errors:
        return _revise("DELTA_OPERATION_INVALID", errors, project_id=project_id)

    base = {
        "projection_sha256": projection.get("projection_sha256"),
        "event_cursor": projection.get("event_cursor"),
        "event_chain_head": projection.get("event_chain_head"),
        "valid_at": projection.get("valid_at"),
        "current_work_capsule_sha256": current_work.get("capsule_sha256"),
    }
    if not all(base.get(field) for field in ("projection_sha256", "event_chain_head", "current_work_capsule_sha256")):
        return _revise("DELTA_BASE_IDENTITY_INCOMPLETE", ["projection/work capsule lacks hash identity"], project_id=project_id)

    normalized_request = {
        "schema": REQUEST_SCHEMA,
        "project_id": project_id,
        "operations": operations,
        "rationale": rationale,
    }
    request_sha = _sha(normalized_request)
    body = {
        "schema": PROPOSAL_SCHEMA,
        "terminal": "CURRENT_MEMORY_DELTA_PROPOSAL_PASS",
        "reason": "EXACT_OPERATIONAL_MEMORY_BASE_BOUND",
        "project_id": project_id,
        "request_sha256": request_sha,
        "base": base,
        "operations": operations,
        "rationale": rationale,
        "requirements": {
            "base_projection_must_match_at_apply": True,
            "event_chain_head_must_match_at_apply": True,
            "superseded_record_hashes_must_match_at_apply": True,
            "human_or_controller_review_required": True,
            "apply_is_separate_effectful_operation": True,
        },
        "apply_status": "NOT_APPLIED",
        "apply_implemented": False,
        "execution_decision": "HOLD",
        "execution_authorized": False,
        "effects": _effects(),
    }
    return {**body, "proposal_id": "omdp-" + _sha(body)[:40]}


def build_memory_delta_proposal_from_db(
    db_path: str | Path,
    request: Mapping[str, Any],
) -> dict[str, Any]:
    """Read and verify one existing OperationalMemory DB; never create or mutate it."""
    project_id = str(request.get("project_id") or "") if isinstance(request, Mapping) else ""
    path = Path(db_path).expanduser().absolute()
    if not path.is_file():
        return _revise("OPERATIONAL_MEMORY_MISSING", [str(path)], project_id=project_id)
    try:
        from .operational_memory import OperationalMemory

        with OperationalMemory(str(path), read_only=True) as memory:
            verification = memory.verify()
            if verification.get("ok") is not True:
                return _revise(
                    "OPERATIONAL_MEMORY_VERIFY_FAILED",
                    list(verification.get("errors") or ["verification failed"]),
                    project_id=project_id,
                )
            projection = memory.projection()
        current_work = build_current_work_from_db(path, project_id)
        result = compile_memory_delta_proposal(projection, current_work, request)
        result["operational_memory"] = {
            "path": str(path),
            "verified": True,
            "projection_sha256": projection.get("projection_sha256"),
            "event_cursor": projection.get("event_cursor"),
            "event_chain_head": projection.get("event_chain_head"),
        }
        return result
    except Exception as exc:
        return _revise(
            "OPERATIONAL_MEMORY_READ_FAILED",
            [f"{type(exc).__name__}: {exc}"],
            project_id=project_id,
        )
