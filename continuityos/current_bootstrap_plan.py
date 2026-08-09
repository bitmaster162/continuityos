"""Proposal-only compiler for deterministic project-memory bootstrap manifests.

R39 removes the remaining cryptographic/manual glue before R38. A caller declares
project semantics and local evidence locators; this module stable-reads and hashes
the exact evidence bytes, canonicalizes the request through the *same* R38 manifest
validator, and returns a deterministic NOT_APPLIED manifest proposal.

It does not authorize bootstrap, create a database, mutate OperationalMemory, or
promote the caller's semantic assertions to accepted truth.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Mapping

from .operational_memory import _canonical_json, _nonempty
from .project_memory_bootstrap import (
    AUTH_DECISION,
    AUTH_SCHEMA,
    MANIFEST_SCHEMA,
    MAX_ARTIFACT_BYTES,
    _sha_bytes,
    _stable_read,
    _validate_manifest,
)

REQUEST_SCHEMA = "continuityos.operational_memory.project_bootstrap_plan_request/v1"
PLAN_SCHEMA = "continuityos.operational_memory.project_bootstrap_plan/v1"
MAX_EVIDENCE_FILES = 256


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
        "trading": False,
        "wallet_access": False,
        "order_execution": False,
        "can_trade": False,
        "capital_permission": "DENY",
        "deploy_permission": "DENY",
    }


def _revise(reason: str, *, project_id: str | None = None, errors: list[str] | None = None) -> dict[str, Any]:
    return {
        "schema": PLAN_SCHEMA,
        "terminal": "CURRENT_BOOTSTRAP_PLAN_REVISE",
        "reason": reason,
        "project_id": project_id,
        "errors": list(errors or []),
        "manifest": None,
        "manifest_sha256": None,
        "authorization_required": True,
        "authorization_schema": AUTH_SCHEMA,
        "authorization_decision": AUTH_DECISION,
        "apply_status": "NOT_APPLIED",
        "semantic_assertions_accepted": False,
        "evidence_bytes_verified": False,
        "execution_decision": "HOLD",
        "execution_authorized": False,
        "effects": _effects(),
    }


def _exact_request(value: Any) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError("request root must be an object")
    allowed = {"schema", "project_id", "evidence", "claims", "proposed_decisions", "rationale"}
    required = {"schema", "project_id", "evidence", "claims", "proposed_decisions"}
    missing = required - set(value)
    extra = set(value) - allowed
    if missing or extra:
        raise ValueError(f"request keys mismatch missing={sorted(missing)} extra={sorted(extra)}")
    if value.get("schema") != REQUEST_SCHEMA:
        raise ValueError("request schema mismatch")
    return value


def build_bootstrap_plan(request: Mapping[str, Any]) -> dict[str, Any]:
    """Compile a deterministic R38 manifest proposal without writing anything."""
    project_id: str | None = None
    try:
        value = _exact_request(request)
        project_id = _nonempty(value.get("project_id"), field="project_id")
        evidence_rows = value.get("evidence")
        if not isinstance(evidence_rows, list) or len(evidence_rows) > MAX_EVIDENCE_FILES:
            raise ValueError(f"evidence must be an array of at most {MAX_EVIDENCE_FILES} rows")

        manifest_evidence: list[dict[str, Any]] = []
        verified_evidence: list[dict[str, Any]] = []
        seen_ids: set[str] = set()
        for index, row in enumerate(evidence_rows):
            if not isinstance(row, Mapping):
                raise ValueError(f"evidence[{index}] must be an object")
            allowed = {"evidence_id", "locator", "kind", "scope"}
            required = {"evidence_id", "locator"}
            missing = required - set(row)
            extra = set(row) - allowed
            if missing or extra:
                raise ValueError(
                    f"evidence[{index}] keys mismatch missing={sorted(missing)} extra={sorted(extra)}"
                )
            evidence_id = _nonempty(row.get("evidence_id"), field=f"evidence[{index}].evidence_id")
            if evidence_id in seen_ids:
                raise ValueError(f"duplicate evidence_id: {evidence_id}")
            seen_ids.add(evidence_id)
            locator = _nonempty(row.get("locator"), field=f"evidence[{index}].locator")
            path = Path(locator).expanduser().absolute()
            payload = _stable_read(path, f"evidence:{evidence_id}", max_bytes=MAX_ARTIFACT_BYTES)
            sha256 = _sha_bytes(payload)
            item: dict[str, Any] = {
                "evidence_id": evidence_id,
                "sha256": sha256,
                "locator": str(path),
            }
            for optional in ("kind", "scope"):
                if row.get(optional) is not None:
                    item[optional] = _nonempty(row.get(optional), field=f"evidence[{index}].{optional}")
            manifest_evidence.append(item)
            verified_evidence.append({**item, "size_bytes": len(payload)})

        manifest_input: dict[str, Any] = {
            "schema": MANIFEST_SCHEMA,
            "project_id": project_id,
            "evidence": manifest_evidence,
            "claims": value.get("claims"),
            "proposed_decisions": value.get("proposed_decisions"),
        }
        if value.get("rationale") is not None:
            manifest_input["rationale"] = value.get("rationale")

        normalized = _validate_manifest(manifest_input)
        manifest: dict[str, Any] = {
            "schema": MANIFEST_SCHEMA,
            "project_id": normalized["project_id"],
            "evidence": normalized["evidence"],
            "claims": normalized["claims"],
            "proposed_decisions": normalized["proposed_decisions"],
        }
        if normalized.get("rationale") is not None:
            manifest["rationale"] = normalized["rationale"]
        # Revalidate the exact emitted shape, not merely the pre-normalized request.
        _validate_manifest(manifest)
        manifest_sha = hashlib.sha256(_canonical_json(manifest).encode("utf-8")).hexdigest()
        plan_id = "pbp-" + manifest_sha[:32]
        verified_evidence.sort(key=lambda item: item["evidence_id"])
        return {
            "schema": PLAN_SCHEMA,
            "terminal": "CURRENT_BOOTSTRAP_PLAN_PASS",
            "reason": "CANONICAL_MANIFEST_PROPOSAL_COMPILED",
            "plan_id": plan_id,
            "project_id": project_id,
            "manifest": manifest,
            "manifest_sha256": manifest_sha,
            "evidence": verified_evidence,
            "authorization_required": True,
            "authorization_schema": AUTH_SCHEMA,
            "authorization_decision": AUTH_DECISION,
            "authorization_requirements": {
                "must_bind_exact_manifest_sha256": manifest_sha,
                "must_bind_target_db": True,
                "must_bind_claim_count": len(manifest["claims"]),
                "must_bind_proposed_decision_count": len(manifest["proposed_decisions"]),
                "accepted_authority_classes": ["HUMAN", "DETERMINISTIC_CONTROLLER"],
            },
            "apply_status": "NOT_APPLIED",
            "semantic_assertions_accepted": False,
            "evidence_bytes_verified": True,
            "execution_decision": "HOLD",
            "execution_authorized": False,
            "effects": _effects(),
        }
    except Exception as exc:
        return _revise(
            "BOOTSTRAP_PLAN_REQUEST_INVALID",
            project_id=project_id,
            errors=[f"{type(exc).__name__}: {exc}"],
        )
