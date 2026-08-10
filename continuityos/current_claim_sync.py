"""Read-only claim-sync planner over existing R36 OperationalMemory deltas.

R43 removes manual claim-id/hash lookup when new evidence updates project facts.
A verified caller declares logical claim selectors (predicate + scope), desired
values, and local evidence locators. This module stable-reads and hashes the exact
evidence bytes, resolves each selector against one verified shadow-memory
projection, chooses RECORD_CLAIM or SUPERSEDE_CLAIM, and delegates proposal
construction to the existing R36 compiler.

It does not infer semantic truth, modify memory, create terminal decisions, apply a
proposal, mutate canonical state, or grant execution authority.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

from .current_memory_delta import (
    EVIDENCE_STATES,
    PROPOSAL_SCHEMA,
    REQUEST_SCHEMA as DELTA_REQUEST_SCHEMA,
    compile_memory_delta_proposal,
)
from .current_work import build_current_work_from_db
from .operational_memory import OperationalMemory, normalize_evidence_refs
from .project_memory_bootstrap import MAX_ARTIFACT_BYTES, _stable_read

REQUEST_SCHEMA = "continuityos.operational_memory.claim_sync_plan_request/v1"
PLAN_SCHEMA = "continuityos.operational_memory.claim_sync_plan/v1"
MAX_EVIDENCE_FILES = 256
MAX_CLAIMS = 64


def _canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _sha(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


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


def _revise(reason: str, errors: list[str], *, project_id: str | None = None) -> dict[str, Any]:
    return {
        "schema": PLAN_SCHEMA,
        "terminal": "CURRENT_CLAIM_SYNC_PLAN_REVISE",
        "reason": reason,
        "project_id": project_id,
        "errors": list(errors),
        "plan_id": None,
        "selector_resolutions": [],
        "delta_request": None,
        "delta_proposal": None,
        "apply_status": "NOT_APPLIED",
        "semantic_assertions_accepted": False,
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
    missing = required - set(value)
    extra = set(value) - allowed
    if missing or extra:
        raise ValueError(f"{label} keys mismatch: missing={sorted(missing)} extra={sorted(extra)}")
    return value


def _normalize_request(request: Mapping[str, Any]) -> dict[str, Any]:
    _exact_keys(
        request,
        {"schema", "project_id", "evidence", "claims", "rationale"},
        {"schema", "project_id", "evidence", "claims"},
        "request",
    )
    if request.get("schema") != REQUEST_SCHEMA:
        raise ValueError("request schema mismatch")
    project_id = _nonempty(request.get("project_id"), "project_id")

    evidence_raw = request.get("evidence")
    if not isinstance(evidence_raw, list) or len(evidence_raw) > MAX_EVIDENCE_FILES:
        raise ValueError(f"evidence must be an array of at most {MAX_EVIDENCE_FILES} rows")
    evidence: list[dict[str, Any]] = []
    evidence_ids: set[str] = set()
    for index, row in enumerate(evidence_raw):
        _exact_keys(
            row,
            {"evidence_id", "locator", "kind", "scope"},
            {"evidence_id", "locator"},
            f"evidence[{index}]",
        )
        evidence_id = _nonempty(row.get("evidence_id"), f"evidence[{index}].evidence_id")
        if evidence_id in evidence_ids:
            raise ValueError(f"duplicate evidence_id: {evidence_id}")
        evidence_ids.add(evidence_id)
        locator = _nonempty(row.get("locator"), f"evidence[{index}].locator")
        item: dict[str, Any] = {"evidence_id": evidence_id, "locator": locator}
        for optional in ("kind", "scope"):
            if row.get(optional) is not None:
                item[optional] = _nonempty(row.get(optional), f"evidence[{index}].{optional}")
        evidence.append(item)

    claims_raw = request.get("claims")
    if not isinstance(claims_raw, list) or not 1 <= len(claims_raw) <= MAX_CLAIMS:
        raise ValueError(f"claims must contain 1..{MAX_CLAIMS} rows")
    claims: list[dict[str, Any]] = []
    selectors: set[tuple[str, str]] = set()
    for index, row in enumerate(claims_raw):
        _exact_keys(
            row,
            {
                "predicate", "scope", "value", "evidence_state", "evidence_ids",
                "valid_from", "valid_to", "note",
            },
            {"predicate", "scope", "value", "evidence_state", "evidence_ids"},
            f"claims[{index}]",
        )
        predicate = _nonempty(row.get("predicate"), f"claims[{index}].predicate")
        scope = _nonempty(row.get("scope"), f"claims[{index}].scope")
        selector = (predicate, scope)
        if selector in selectors:
            raise ValueError(f"duplicate claim selector: {predicate}/{scope}")
        selectors.add(selector)
        state = _nonempty(row.get("evidence_state"), f"claims[{index}].evidence_state").upper()
        if state not in EVIDENCE_STATES:
            raise ValueError(f"claims[{index}] unsupported evidence_state: {state}")
        ids = row.get("evidence_ids")
        if not isinstance(ids, list) or not all(isinstance(item, str) and item.strip() for item in ids):
            raise ValueError(f"claims[{index}].evidence_ids must be an array of non-empty strings")
        ids = list(dict.fromkeys(item.strip() for item in ids))
        if any(item not in evidence_ids for item in ids):
            raise ValueError(f"claims[{index}] references unknown evidence_id")
        if state != "UNKNOWN" and not ids:
            raise ValueError(f"claims[{index}] {state} requires evidence")
        claim: dict[str, Any] = {
            "predicate": predicate,
            "scope": scope,
            "value": row.get("value"),
            "evidence_state": state,
            "evidence_ids": ids,
        }
        for optional in ("valid_from", "valid_to", "note"):
            if row.get(optional) is not None:
                claim[optional] = _nonempty(row.get(optional), f"claims[{index}].{optional}")
        claims.append(claim)

    rationale = request.get("rationale")
    if rationale is not None:
        rationale = _nonempty(rationale, "rationale")
    return {
        "schema": REQUEST_SCHEMA,
        "project_id": project_id,
        "evidence": evidence,
        "claims": claims,
        "rationale": rationale,
    }


def _rehash_evidence(rows: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]]]:
    verified: list[dict[str, Any]] = []
    by_id: dict[str, dict[str, Any]] = {}
    for row in rows:
        path = Path(row["locator"]).expanduser().absolute()
        payload = _stable_read(path, f"claim-sync evidence:{row['evidence_id']}", max_bytes=MAX_ARTIFACT_BYTES)
        ref: dict[str, Any] = {
            "sha256": hashlib.sha256(payload).hexdigest(),
            "locator": str(path),
        }
        for optional in ("kind", "scope"):
            if row.get(optional) is not None:
                ref[optional] = row[optional]
        normalized = normalize_evidence_refs([ref])[0]
        item = {"evidence_id": row["evidence_id"], **normalized, "size_bytes": len(payload)}
        verified.append(item)
        by_id[row["evidence_id"]] = normalized
    verified.sort(key=lambda item: item["evidence_id"])
    return verified, by_id


def compile_claim_sync_plan(
    projection: Mapping[str, Any],
    current_work: Mapping[str, Any],
    request: Mapping[str, Any],
    *,
    evidence_rows: list[dict[str, Any]],
    evidence_by_id: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    """Resolve logical claim selectors and delegate the proposal to R36."""
    project_id = str(request["project_id"])
    current_claims = [
        row for row in list(projection.get("claims") or [])
        if row.get("subject_id") == project_id
    ]
    operations: list[dict[str, Any]] = []
    resolutions: list[dict[str, Any]] = []
    errors: list[str] = []

    for index, claim in enumerate(request["claims"]):
        predicate = claim["predicate"]
        scope = claim["scope"]
        matches = [
            row for row in current_claims
            if row.get("predicate") == predicate and row.get("scope") == scope
        ]
        if len(matches) > 1:
            errors.append(
                f"claims[{index}] ambiguous current selector {predicate}/{scope}: {len(matches)} current claims"
            )
            continue
        refs = [dict(evidence_by_id[item]) for item in claim["evidence_ids"]]
        operation: dict[str, Any] = {
            "op": "SUPERSEDE_CLAIM" if matches else "RECORD_CLAIM",
            "value": claim["value"],
            "evidence_state": claim["evidence_state"],
            "evidence_refs": refs,
        }
        if matches:
            operation["supersedes_id"] = matches[0]["claim_id"]
        else:
            operation["predicate"] = predicate
            operation["scope"] = scope
        for optional in ("valid_from", "valid_to", "note"):
            if claim.get(optional) is not None:
                operation[optional] = claim[optional]
        operations.append(operation)
        resolutions.append({
            "claim_index": index,
            "predicate": predicate,
            "scope": scope,
            "resolution": "SUPERSEDE_CURRENT" if matches else "RECORD_NEW",
            "current_claim_id": matches[0].get("claim_id") if matches else None,
            "current_claim_hash": matches[0].get("claim_hash") if matches else None,
        })

    if errors:
        return _revise("CLAIM_SELECTOR_AMBIGUOUS", errors, project_id=project_id)

    delta_request = {
        "schema": DELTA_REQUEST_SCHEMA,
        "project_id": project_id,
        "operations": operations,
        "rationale": request.get("rationale"),
    }
    proposal = compile_memory_delta_proposal(projection, current_work, delta_request)
    if proposal.get("schema") != PROPOSAL_SCHEMA or proposal.get("terminal") != "CURRENT_MEMORY_DELTA_PROPOSAL_PASS":
        return _revise(
            "R36_DELTA_PROPOSAL_REJECTED",
            list(proposal.get("errors") or [str(proposal.get("reason") or "R36 proposal rejected")]),
            project_id=project_id,
        )

    body = {
        "schema": PLAN_SCHEMA,
        "terminal": "CURRENT_CLAIM_SYNC_PLAN_PASS",
        "reason": "LOGICAL_CLAIM_SELECTORS_RESOLVED_TO_R36_PROPOSAL",
        "project_id": project_id,
        "evidence": evidence_rows,
        "selector_resolutions": resolutions,
        "delta_request": delta_request,
        "delta_proposal": proposal,
        "apply_status": "NOT_APPLIED",
        "semantic_assertions_accepted": False,
        "execution_decision": "HOLD",
        "execution_authorized": False,
        "effects": _effects(),
    }
    return {**body, "plan_id": "csp-" + _sha(body)[:40]}


def build_claim_sync_plan_from_db(db_path: str | Path, raw_request: Mapping[str, Any]) -> dict[str, Any]:
    """Read one existing shadow DB and exact evidence; never create or mutate it."""
    project_id: str | None = None
    try:
        request = _normalize_request(raw_request)
        project_id = request["project_id"]
        evidence_rows, evidence_by_id = _rehash_evidence(request["evidence"])
    except Exception as exc:
        return _revise("CLAIM_SYNC_REQUEST_INVALID", [f"{type(exc).__name__}: {exc}"], project_id=project_id)

    path = Path(db_path).expanduser().absolute()
    if not path.is_file():
        return _revise("OPERATIONAL_MEMORY_MISSING", [str(path)], project_id=project_id)
    try:
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
        result = compile_claim_sync_plan(
            projection,
            current_work,
            request,
            evidence_rows=evidence_rows,
            evidence_by_id=evidence_by_id,
        )
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
