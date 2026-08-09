"""Fail-closed resolution of competing ContinuityOS state/evidence artifacts.

The resolver separates *authority precedence* from *fresh factual contradiction*.
A stale template or lower-authority return can never override a later accepted
human/controller decision merely because it is still present on disk. Conversely,
a fresh provider/audit observation can block use of an older decision when it
explicitly reports a current contradiction.

This module is pure/read-only: it performs no filesystem, network, Git, provider,
deployment, registry, state, trading, wallet, messaging, or self-application effect.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Iterable
import hashlib
import json
import re

CANDIDATE_SCHEMA = "continuityos.state_resolution.candidate/v1"
RESULT_SCHEMA = "continuityos.state_resolution.result/v1"

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

KIND_RANK = {
    "TEMPLATE": 10,
    "REMEDIATION_RETURN": 20,
    "AUDIT": 30,
    "PROVIDER_READBACK": 40,
    "CONTROLLER_ADJUDICATION": 50,
    "HUMAN_DECISION": 60,
}

ALLOWED_STATUS = {
    "OPEN",
    "PARTIAL",
    "PASS",
    "PASS_WITH_CONDITIONS",
    "REVISE",
    "HOLD",
    "REJECT",
}

BLOCKING_FRESH_STATUS = {"OPEN", "REVISE", "REJECT"}


def _fixed_effects() -> dict[str, Any]:
    return {
        "force_push": False,
        "merge": False,
        "pull_request_merge": False,
        "auto_merge": False,
        "deployment": False,
        "registry_apply": False,
        "current_state_apply": False,
        "r63_apply": False,
        "trading": False,
        "wallet_access": False,
        "order_execution": False,
        "external_message": False,
        "self_application": False,
        "can_trade": False,
        "capital_permission": "DENY",
        "deploy_permission": "DENY",
    }


def canonical_json_text(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"


def candidate_sha256(candidate: dict[str, Any]) -> str:
    """Return a deterministic identity for a normalized candidate."""
    return hashlib.sha256(canonical_json_text(candidate).encode("utf-8")).hexdigest()


def _parse_time(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} must be a non-empty RFC3339 string")
    text = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise ValueError(f"{label} is not RFC3339") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{label} must include timezone")
    return parsed.astimezone(timezone.utc)


def _require_str(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} must be a non-empty string")
    return value


def _normalize_candidate(raw: Any, index: int) -> dict[str, Any]:
    label = f"candidates[{index}]"
    if not isinstance(raw, dict):
        raise ValueError(f"{label} must be an object")
    if raw.get("schema") != CANDIDATE_SCHEMA:
        raise ValueError(f"{label}.schema mismatch")

    kind = _require_str(raw.get("kind"), f"{label}.kind")
    if kind not in KIND_RANK:
        raise ValueError(f"{label}.kind is unsupported")

    status = _require_str(raw.get("status"), f"{label}.status")
    if status not in ALLOWED_STATUS:
        raise ValueError(f"{label}.status is unsupported")

    subject = _require_str(raw.get("subject"), f"{label}.subject")
    artifact_id = _require_str(raw.get("artifact_id"), f"{label}.artifact_id")
    observed = _parse_time(raw.get("observed_at_utc"), f"{label}.observed_at_utc")

    production_qualified = raw.get("production_qualified", False)
    evidence_debt = raw.get("evidence_debt", False)
    current_observation = raw.get("current_observation", False)
    if not isinstance(production_qualified, bool):
        raise ValueError(f"{label}.production_qualified must be boolean")
    if not isinstance(evidence_debt, bool):
        raise ValueError(f"{label}.evidence_debt must be boolean")
    if not isinstance(current_observation, bool):
        raise ValueError(f"{label}.current_observation must be boolean")

    explicit_sha = raw.get("artifact_sha256")
    if explicit_sha is not None:
        if not isinstance(explicit_sha, str) or not SHA256_RE.fullmatch(explicit_sha):
            raise ValueError(f"{label}.artifact_sha256 must be lowercase SHA-256")

    normalized = {
        "schema": CANDIDATE_SCHEMA,
        "subject": subject,
        "artifact_id": artifact_id,
        "kind": kind,
        "status": status,
        "observed_at_utc": observed.isoformat().replace("+00:00", "Z"),
        "production_qualified": production_qualified,
        "evidence_debt": evidence_debt,
        "current_observation": current_observation,
    }
    normalized["artifact_sha256"] = explicit_sha or candidate_sha256(normalized)
    return normalized


def _operational_state(status: str) -> str:
    return {
        "PASS": "ACCEPTED",
        "PASS_WITH_CONDITIONS": "ACCEPTED_WITH_CONDITIONS",
        "OPEN": "OPEN",
        "PARTIAL": "PARTIAL",
        "REVISE": "REVISE",
        "HOLD": "HOLD",
        "REJECT": "REJECT",
    }[status]


def _result(status: str, **payload: Any) -> dict[str, Any]:
    result = {
        "schema": RESULT_SCHEMA,
        "terminal": status,
        "effects": _fixed_effects(),
    }
    result.update(payload)
    return result


def resolve_state(candidates: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """Resolve one subject's current state without allowing stale evidence rollback.

    Authority precedence is:
    TEMPLATE < REMEDIATION_RETURN < AUDIT < PROVIDER_READBACK
    < CONTROLLER_ADJUDICATION < HUMAN_DECISION.

    Within one authority kind, the latest observation wins. Equal-rank/equal-time
    conflicting states are ambiguous and HOLD. A later *current* AUDIT or
    PROVIDER_READBACK reporting OPEN/REVISE/REJECT does not silently override a
    higher-authority decision; instead it creates a fresh-contradiction HOLD.
    """
    try:
        rows = [_normalize_candidate(raw, i) for i, raw in enumerate(candidates)]
    except Exception as exc:
        return _result(
            "STATE_RESOLUTION_REVISE",
            error_type=type(exc).__name__,
            error=str(exc),
            selected=None,
            stale=[],
        )

    if not rows:
        return _result(
            "STATE_RESOLUTION_HOLD",
            reason="NO_EVIDENCE",
            selected=None,
            stale=[],
        )

    subjects = {row["subject"] for row in rows}
    if len(subjects) != 1:
        return _result(
            "STATE_RESOLUTION_REVISE",
            reason="MULTIPLE_SUBJECTS",
            selected=None,
            stale=[],
        )

    for row in rows:
        row["_rank"] = KIND_RANK[row["kind"]]
        row["_time"] = _parse_time(row["observed_at_utc"], "observed_at_utc")

    highest_rank = max(row["_rank"] for row in rows)
    same_rank = [row for row in rows if row["_rank"] == highest_rank]
    latest_time = max(row["_time"] for row in same_rank)
    finalists = [row for row in same_rank if row["_time"] == latest_time]

    finalist_states = {
        (row["status"], row["production_qualified"], row["evidence_debt"])
        for row in finalists
    }
    if len(finalist_states) != 1:
        return _result(
            "STATE_RESOLUTION_HOLD",
            reason="EQUAL_AUTHORITY_CONTRADICTION",
            subject=next(iter(subjects)),
            selected=None,
            contradictions=[
                {k: v for k, v in row.items() if not k.startswith("_")}
                for row in finalists
            ],
            stale=[],
        )

    # Deterministic identity choice when equivalent duplicates exist.
    selected = sorted(finalists, key=lambda row: row["artifact_sha256"])[-1]

    # A fresh current observation can block reliance on an older accepted decision,
    # but cannot itself acquire higher authority.
    fresh_contradictions = [
        row
        for row in rows
        if row["kind"] in {"AUDIT", "PROVIDER_READBACK"}
        and row["current_observation"] is True
        and row["_time"] > selected["_time"]
        and row["status"] in BLOCKING_FRESH_STATUS
    ]
    if fresh_contradictions:
        return _result(
            "STATE_RESOLUTION_HOLD",
            reason="FRESH_CURRENT_CONTRADICTION",
            subject=selected["subject"],
            selected={k: v for k, v in selected.items() if not k.startswith("_")},
            contradictions=[
                {k: v for k, v in row.items() if not k.startswith("_")}
                for row in sorted(fresh_contradictions, key=lambda r: r["_time"])
            ],
            stale=[],
        )

    stale_rows = [row for row in rows if row is not selected]
    stale_rows.sort(key=lambda row: (row["_rank"], row["_time"], row["artifact_sha256"]))

    selected_clean = {k: v for k, v in selected.items() if not k.startswith("_")}
    production_qualified = (
        selected["status"] == "PASS"
        and selected["production_qualified"] is True
        and selected["evidence_debt"] is False
    )

    return _result(
        "STATE_RESOLUTION_PASS",
        subject=selected["subject"],
        selected=selected_clean,
        current_status=selected["status"],
        operational_state=_operational_state(selected["status"]),
        production_qualified=production_qualified,
        evidence_debt=selected["evidence_debt"],
        stale=[
            {k: v for k, v in row.items() if not k.startswith("_")}
            for row in stale_rows
        ],
        stale_count=len(stale_rows),
    )
