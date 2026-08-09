"""Deterministic read-only project work projection over Common Operational Memory v1.

The projector does not invent facts, write memory, select an executor, or grant
execution. It compiles one project's current claims/decisions/open loops into a
compact operator capsule and chooses at most one deterministic *next action*.

Selection is monotonic:
1. one current ACCEPTED NEXT_ACTION decision wins, unless an active blocker holds it;
2. current HOLD/REJECTED NEXT_ACTION decisions hold the project;
3. without a terminal decision, PROPOSED decisions / project.next_action claims /
   open-loop next actions are candidates only;
4. active blockers can remove candidates, never grant permission;
5. every result keeps execution_authorized=false.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Mapping, Sequence

SCHEMA = "continuityos.current_work.project_capsule/v1"
PROJECTION_SCHEMA = "continuityos.common_operational_memory.projection.v1"

_EVIDENCE_RANK = {
    "VERIFIED": 6,
    "SOURCE_BACKED": 5,
    "INFERENCE": 4,
    "ASSUMPTION": 3,
    "HYPOTHESIS": 2,
    "UNKNOWN": 1,
}
_CLOSED = {"CLOSED", "DONE", "RESOLVED", "PARKED", "SUPERSEDED"}


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


def _revise(project_id: str, reason: str, errors: Sequence[str]) -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "terminal": "CURRENT_WORK_REVISE",
        "reason": reason,
        "project_id": project_id,
        "errors": list(errors),
        "next_action": None,
        "execution_decision": "HOLD",
        "execution_authorized": False,
        "effects": _effects(),
    }


def _nonempty(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be a non-empty string")
    return value.strip()


def _priority(value: Any, *, label: str) -> int:
    if value is None:
        return 0
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= 100:
        raise ValueError(f"{label} must be an integer between 0 and 100")
    return int(value)


def _string_list(value: Any, *, label: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(item, str) and item.strip() for item in value):
        raise ValueError(f"{label} must be an array of non-empty strings")
    return sorted(set(item.strip() for item in value))


def _normalize_action(value: Any, *, source_id: str) -> dict[str, Any]:
    if isinstance(value, str):
        action = _nonempty(value, label="action")
        return {
            "id": source_id,
            "action": action,
            "priority": 0,
            "blocked_by": [],
            "owner": None,
            "value": value,
        }
    if not isinstance(value, Mapping):
        raise ValueError("next-action value must be a string or object")
    action = _nonempty(value.get("action"), label="action")
    identifier = value.get("id")
    if identifier is None:
        identifier = source_id
    identifier = _nonempty(identifier, label="action.id")
    owner = value.get("owner")
    if owner is not None:
        owner = _nonempty(owner, label="action.owner")
    return {
        "id": identifier,
        "action": action,
        "priority": _priority(value.get("priority"), label="action.priority"),
        "blocked_by": _string_list(value.get("blocked_by"), label="action.blocked_by"),
        "owner": owner,
        "value": dict(value),
    }


def _normalize_loop(claim: Mapping[str, Any]) -> dict[str, Any]:
    value = claim.get("value")
    if not isinstance(value, Mapping):
        raise ValueError(f"open loop {claim.get('claim_id')} value must be an object")
    scope = _nonempty(claim.get("scope"), label="open_loop.scope")
    loop_id = _nonempty(value.get("id") or scope, label="open_loop.id")
    title = _nonempty(value.get("title"), label="open_loop.title")
    status = str(value.get("status") or "OPEN").strip().upper()
    if not status:
        raise ValueError("open_loop.status must be non-empty")
    next_action = value.get("next_action")
    if next_action is not None:
        next_action = _nonempty(next_action, label="open_loop.next_action")
    return {
        "id": loop_id,
        "title": title,
        "status": status,
        "next_action": next_action,
        "priority": _priority(value.get("priority"), label="open_loop.priority"),
        "blocked_by": _string_list(value.get("blocked_by"), label="open_loop.blocked_by"),
        "claim_id": claim.get("claim_id"),
        "evidence_state": claim.get("evidence_state"),
        "evidence_refs": list(claim.get("evidence_refs") or []),
    }


def _normalize_blocker(claim: Mapping[str, Any]) -> dict[str, Any]:
    value = claim.get("value")
    scope = _nonempty(claim.get("scope"), label="blocker.scope")
    if isinstance(value, str):
        return {
            "id": scope,
            "title": _nonempty(value, label="blocker.title"),
            "status": "OPEN",
            "severity": 50,
            "blocks": [],
            "claim_id": claim.get("claim_id"),
            "evidence_state": claim.get("evidence_state"),
            "evidence_refs": list(claim.get("evidence_refs") or []),
        }
    if not isinstance(value, Mapping):
        raise ValueError(f"blocker {claim.get('claim_id')} value must be a string or object")
    status = str(value.get("status") or "OPEN").strip().upper()
    if not status:
        raise ValueError("blocker.status must be non-empty")
    return {
        "id": _nonempty(value.get("id") or scope, label="blocker.id"),
        "title": _nonempty(value.get("title"), label="blocker.title"),
        "status": status,
        "severity": _priority(value.get("severity", 50), label="blocker.severity"),
        "blocks": _string_list(value.get("blocks"), label="blocker.blocks"),
        "claim_id": claim.get("claim_id"),
        "evidence_state": claim.get("evidence_state"),
        "evidence_refs": list(claim.get("evidence_refs") or []),
    }


def _is_blocked(action: Mapping[str, Any], blockers: Sequence[Mapping[str, Any]]) -> tuple[bool, list[str]]:
    active_ids = {str(item["id"]) for item in blockers}
    explicit = set(action.get("blocked_by") or []) & active_ids
    indirect = {
        str(item["id"])
        for item in blockers
        if "*" in set(item.get("blocks") or [])
        or str(action.get("id")) in set(item.get("blocks") or [])
    }
    reasons = sorted(explicit | indirect)
    return bool(reasons), reasons


def _singleton(claims: Sequence[Mapping[str, Any]], predicate: str) -> tuple[Any, list[str]]:
    rows = [row for row in claims if row.get("predicate") == predicate and row.get("scope") == "global"]
    if len(rows) > 1:
        return None, [f"multiple current {predicate} claims in global scope"]
    if not rows:
        return None, []
    return rows[0].get("value"), []


def compile_project_work(projection: Mapping[str, Any], project_id: str) -> dict[str, Any]:
    """Compile one project capsule from a verified OperationalMemory projection."""
    try:
        project_id = _nonempty(project_id, label="project_id")
    except Exception as exc:
        return _revise(str(project_id or ""), "PROJECT_ID_INVALID", [str(exc)])
    if not isinstance(projection, Mapping) or projection.get("schema") != PROJECTION_SCHEMA:
        return _revise(project_id, "OPERATIONAL_PROJECTION_INVALID", ["unexpected projection schema"])

    claims = [row for row in list(projection.get("claims") or []) if row.get("subject_id") == project_id]
    decisions = [row for row in list(projection.get("decisions") or []) if row.get("subject_id") == project_id]
    errors: list[str] = []

    goal, singleton_errors = _singleton(claims, "project.goal")
    errors.extend(singleton_errors)
    status, singleton_errors = _singleton(claims, "project.status")
    errors.extend(singleton_errors)

    open_loops: list[dict[str, Any]] = []
    blockers: list[dict[str, Any]] = []
    action_claims: list[dict[str, Any]] = []
    for claim in claims:
        predicate = claim.get("predicate")
        try:
            if predicate == "project.open_loop":
                loop = _normalize_loop(claim)
                if loop["status"] not in _CLOSED:
                    open_loops.append(loop)
            elif predicate == "project.blocker":
                blocker = _normalize_blocker(claim)
                if blocker["status"] not in _CLOSED:
                    blockers.append(blocker)
            elif predicate == "project.next_action":
                action = _normalize_action(claim.get("value"), source_id=str(claim.get("claim_id") or claim.get("scope") or "claim"))
                action.update({
                    "source": "CLAIM",
                    "source_id": claim.get("claim_id"),
                    "authority_status": "PROPOSED_FROM_CLAIM",
                    "evidence_state": claim.get("evidence_state"),
                    "evidence_refs": list(claim.get("evidence_refs") or []),
                    "source_rank": 2,
                })
                action_claims.append(action)
        except Exception as exc:
            errors.append(f"{predicate}:{claim.get('claim_id')}: {exc}")

    open_loops.sort(key=lambda row: (-row["priority"], row["id"]))
    blockers.sort(key=lambda row: (-row["severity"], row["id"]))

    next_decisions = [row for row in decisions if str(row.get("decision_type") or "").upper() == "NEXT_ACTION"]
    terminal_decisions = [row for row in next_decisions if str(row.get("state") or "").upper() in {"ACCEPTED", "HOLD", "REJECTED"}]
    if len(terminal_decisions) > 1:
        errors.append("multiple current terminal NEXT_ACTION decisions")

    if errors:
        return _revise(project_id, "PROJECT_MEMORY_CONFLICT", sorted(errors))

    common = {
        "schema": SCHEMA,
        "project_id": project_id,
        "projection_identity": {
            "projection_sha256": projection.get("projection_sha256"),
            "event_cursor": projection.get("event_cursor"),
            "event_chain_head": projection.get("event_chain_head"),
            "valid_at": projection.get("valid_at"),
        },
        "goal": goal,
        "status": status,
        "open_loops": open_loops,
        "blockers": blockers,
        "decisions": sorted(
            decisions,
            key=lambda row: (
                str(row.get("decision_type") or ""),
                str(row.get("recorded_at") or ""),
                str(row.get("decision_id") or ""),
            ),
        ),
        "memory_ceilings": dict(projection.get("ceilings") or {}),
        "execution_decision": "HOLD",
        "execution_authorized": False,
        "effects": _effects(),
    }

    if terminal_decisions:
        decision = terminal_decisions[0]
        state = str(decision.get("state") or "").upper()
        if state in {"HOLD", "REJECTED"}:
            body = {
                **common,
                "terminal": "CURRENT_WORK_HOLD",
                "reason": f"NEXT_ACTION_{state}",
                "next_action": None,
                "decision_needed": True,
            }
            return {**body, "capsule_sha256": _sha(body)}
        try:
            action = _normalize_action(decision.get("value"), source_id=str(decision.get("decision_id") or "decision"))
        except Exception as exc:
            return _revise(project_id, "ACCEPTED_NEXT_ACTION_INVALID", [str(exc)])
        action.update({
            "source": "DECISION",
            "source_id": decision.get("decision_id"),
            "authority_status": "ACCEPTED_OPERATIONAL_DECISION",
            "authority_class": decision.get("authority_class"),
            "authority_id": decision.get("authority_id"),
            "authority_ref": decision.get("authority_ref"),
            "evidence_refs": list(decision.get("evidence_refs") or []),
        })
        blocked, blocker_ids = _is_blocked(action, blockers)
        if blocked:
            action["blocked_by_active"] = blocker_ids
            body = {
                **common,
                "terminal": "CURRENT_WORK_HOLD",
                "reason": "ACCEPTED_NEXT_ACTION_BLOCKED",
                "next_action": action,
                "decision_needed": True,
            }
            return {**body, "capsule_sha256": _sha(body)}
        action["blocked_by_active"] = []
        body = {
            **common,
            "terminal": "CURRENT_WORK_PASS",
            "reason": "ACCEPTED_NEXT_ACTION_SELECTED",
            "next_action": action,
            "decision_needed": False,
        }
        return {**body, "capsule_sha256": _sha(body)}

    candidates: list[dict[str, Any]] = []
    for decision in next_decisions:
        if str(decision.get("state") or "").upper() != "PROPOSED":
            continue
        try:
            action = _normalize_action(decision.get("value"), source_id=str(decision.get("decision_id") or "decision"))
        except Exception as exc:
            return _revise(project_id, "PROPOSED_NEXT_ACTION_INVALID", [str(exc)])
        action.update({
            "source": "DECISION",
            "source_id": decision.get("decision_id"),
            "authority_status": "PROPOSED_DECISION",
            "authority_class": decision.get("authority_class"),
            "authority_id": decision.get("authority_id"),
            "authority_ref": decision.get("authority_ref"),
            "evidence_refs": list(decision.get("evidence_refs") or []),
            "evidence_state": None,
            "source_rank": 3,
        })
        candidates.append(action)
    candidates.extend(action_claims)
    for loop in open_loops:
        if loop["status"] == "BLOCKED" or not loop.get("next_action"):
            continue
        candidates.append({
            "id": loop["id"],
            "action": loop["next_action"],
            "priority": loop["priority"],
            "blocked_by": list(loop["blocked_by"]),
            "owner": None,
            "value": {"loop_id": loop["id"], "next_action": loop["next_action"]},
            "source": "OPEN_LOOP",
            "source_id": loop["claim_id"],
            "authority_status": "PROPOSED_FROM_OPEN_LOOP",
            "evidence_state": loop.get("evidence_state"),
            "evidence_refs": list(loop.get("evidence_refs") or []),
            "source_rank": 1,
        })

    for action in candidates:
        blocked, blocker_ids = _is_blocked(action, blockers)
        action["blocked_by_active"] = blocker_ids if blocked else []
        action["evidence_rank"] = _EVIDENCE_RANK.get(str(action.get("evidence_state") or "UNKNOWN").upper(), 0)
    unblocked = [action for action in candidates if not action["blocked_by_active"]]
    unblocked.sort(
        key=lambda row: (
            -row["priority"],
            -row.get("source_rank", 0),
            -row.get("evidence_rank", 0),
            str(row.get("source_id") or row.get("id") or ""),
        )
    )

    if unblocked:
        selected = dict(unblocked[0])
        selected.pop("source_rank", None)
        selected.pop("evidence_rank", None)
        body = {
            **common,
            "terminal": "CURRENT_WORK_PASS",
            "reason": "PROPOSED_NEXT_ACTION_SELECTED",
            "next_action": selected,
            "decision_needed": True,
            "candidate_count": len(candidates),
        }
        return {**body, "capsule_sha256": _sha(body)}

    if candidates:
        body = {
            **common,
            "terminal": "CURRENT_WORK_HOLD",
            "reason": "ALL_NEXT_ACTION_CANDIDATES_BLOCKED",
            "next_action": None,
            "decision_needed": True,
            "candidate_count": len(candidates),
        }
        return {**body, "capsule_sha256": _sha(body)}

    body = {
        **common,
        "terminal": "CURRENT_WORK_PASS",
        "reason": "NO_NEXT_ACTION_RECORDED",
        "next_action": None,
        "decision_needed": True,
        "candidate_count": 0,
    }
    return {**body, "capsule_sha256": _sha(body)}


def build_current_work_from_db(db_path: str | Path, project_id: str) -> dict[str, Any]:
    """Open an existing OperationalMemory database read-only and compile one project."""
    path = Path(db_path).expanduser().absolute()
    if not path.is_file():
        return _revise(str(project_id or ""), "OPERATIONAL_MEMORY_MISSING", [str(path)])
    try:
        # Lazy import preserves normal `continuity` startup and lets the installed
        # current direct-surface guard force/verify read-only semantics as well.
        from .operational_memory import OperationalMemory

        with OperationalMemory(str(path), read_only=True) as memory:
            verification = memory.verify()
            if verification.get("ok") is not True:
                return _revise(
                    str(project_id or ""),
                    "OPERATIONAL_MEMORY_VERIFY_FAILED",
                    list(verification.get("errors") or ["verification failed"]),
                )
            projection = memory.projection()
        result = compile_project_work(projection, project_id)
        result["operational_memory"] = {
            "path": str(path),
            "verified": True,
            "projection_sha256": projection.get("projection_sha256"),
            "event_chain_head": projection.get("event_chain_head"),
            "event_cursor": projection.get("event_cursor"),
        }
        return result
    except Exception as exc:
        return _revise(
            str(project_id or ""),
            "OPERATIONAL_MEMORY_READ_FAILED",
            [f"{type(exc).__name__}: {exc}"],
        )
