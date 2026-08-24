from __future__ import annotations

import copy
import hashlib
import json
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Mapping, Sequence

LIFECYCLE_SCHEMA_VERSION = "company-twin-lifecycle/1"
EXPORT_SCHEMA_VERSION = "company-twin-export/1"
RETENTION_CLASSES = {"TRANSIENT", "STANDARD", "EXTENDED", "INDEFINITE"}
RETENTION_DAYS = {
    "TRANSIENT": 30,
    "STANDARD": 365,
    "EXTENDED": 2555,
    "INDEFINITE": None,
}
OWNER_OPERATIONS = {"REQUEST_TOMBSTONE", "SET_RETENTION", "SET_HOLD", "RELEASE_HOLD"}
AGENT_FORBIDDEN_OPERATIONS = {
    "REQUEST_TOMBSTONE", "SET_RETENTION", "SET_HOLD", "RELEASE_HOLD", "PURGE",
}


class LifecycleValidationError(ValueError):
    pass


class LifecycleAuthorizationError(PermissionError):
    pass


def _canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _parse_time(value: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise LifecycleValidationError("timestamp must be a non-empty string")
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise LifecycleValidationError(f"invalid timestamp: {value}") from exc
    if parsed.tzinfo is None:
        raise LifecycleValidationError("timestamp must include timezone")
    return parsed.astimezone(timezone.utc)


def _iso_z(value: datetime) -> str:
    return value.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _require_record(record: Mapping[str, Any]) -> None:
    required = ("id", "tenant_id", "scope", "truth_class", "effective_at", "observed_at")
    missing = [field for field in required if not isinstance(record.get(field), str) or not record.get(field)]
    if missing:
        raise LifecycleValidationError(f"record missing required fields: {', '.join(sorted(missing))}")
    _parse_time(str(record["effective_at"]))
    _parse_time(str(record["observed_at"]))
    if not isinstance(record.get("deleted", False), bool):
        raise LifecycleValidationError("record.deleted must be boolean")


def _authorize_actor(actor: Mapping[str, Any], operation: str) -> None:
    actor_id = actor.get("actor_id")
    actor_kind = str(actor.get("actor_kind", "")).upper()
    authority = str(actor.get("authority_class", "")).upper()
    if not isinstance(actor_id, str) or not actor_id:
        raise LifecycleAuthorizationError("actor_id is required")
    if operation in AGENT_FORBIDDEN_OPERATIONS and actor_kind == "AGENT":
        raise LifecycleAuthorizationError(f"agents cannot perform {operation}")
    if operation in OWNER_OPERATIONS and not (actor_kind == "HUMAN" and authority == "OWNER"):
        raise LifecycleAuthorizationError(f"{operation} requires HUMAN OWNER authority")
    if operation == "EXPORT" and actor_kind == "AGENT":
        if authority not in {"READ_ONLY", "PROPOSE"}:
            raise LifecycleAuthorizationError("agent export requires READ_ONLY or PROPOSE authority")
    elif operation == "EXPORT" and actor_kind == "HUMAN":
        if authority not in {"OWNER", "WORKER", "READ_ONLY"}:
            raise LifecycleAuthorizationError("unsupported human export authority")


def retention_state(
    record: Mapping[str, Any],
    *,
    retention_class: str,
    assigned_at: str,
    assigned_by: Mapping[str, Any],
    hold: bool = False,
    hold_reason: str | None = None,
) -> dict[str, Any]:
    _require_record(record)
    _authorize_actor(assigned_by, "SET_RETENTION")
    klass = str(retention_class).upper()
    if klass not in RETENTION_CLASSES:
        raise LifecycleValidationError("unsupported retention_class")
    assigned = _parse_time(assigned_at)
    days = RETENTION_DAYS[klass]
    retention_until = None if days is None else _iso_z(assigned + timedelta(days=days))
    if hold and (not isinstance(hold_reason, str) or not hold_reason.strip()):
        raise LifecycleValidationError("hold_reason is required when hold=true")
    state = {
        "schema_version": LIFECYCLE_SCHEMA_VERSION,
        "tenant_id": str(record["tenant_id"]),
        "record_id": str(record["id"]),
        "retention_class": klass,
        "assigned_at": _iso_z(assigned),
        "assigned_by": str(assigned_by["actor_id"]),
        "retention_until": retention_until,
        "hold": bool(hold),
        "hold_reason": hold_reason.strip() if isinstance(hold_reason, str) else None,
    }
    state["state_hash"] = _sha256_text(_canonical_json(state))
    return state


def set_hold(
    lifecycle: Mapping[str, Any],
    *,
    hold: bool,
    reason: str | None,
    changed_at: str,
    changed_by: Mapping[str, Any],
) -> dict[str, Any]:
    operation = "SET_HOLD" if hold else "RELEASE_HOLD"
    _authorize_actor(changed_by, operation)
    if hold and (not isinstance(reason, str) or not reason.strip()):
        raise LifecycleValidationError("hold reason is required")
    _parse_time(changed_at)
    next_state = copy.deepcopy(dict(lifecycle))
    next_state["hold"] = bool(hold)
    next_state["hold_reason"] = reason.strip() if hold and isinstance(reason, str) else None
    next_state["hold_changed_at"] = _iso_z(_parse_time(changed_at))
    next_state["hold_changed_by"] = str(changed_by["actor_id"])
    next_state.pop("state_hash", None)
    next_state["state_hash"] = _sha256_text(_canonical_json(next_state))
    return next_state


def request_tombstone(
    records: Sequence[Mapping[str, Any]],
    *,
    tenant_id: str,
    record_id: str,
    requested_at: str,
    requested_by: Mapping[str, Any],
    reason: str,
) -> dict[str, Any]:
    _authorize_actor(requested_by, "REQUEST_TOMBSTONE")
    if not isinstance(record_id, str) or not record_id:
        raise LifecycleValidationError("exact record_id is required")
    if not isinstance(reason, str) or not reason.strip():
        raise LifecycleValidationError("reason is required")
    matches = [r for r in records if r.get("tenant_id") == tenant_id and r.get("id") == record_id]
    if len(matches) != 1:
        raise LifecycleValidationError("exact tenant-bound record_id must resolve to exactly one record")
    record = matches[0]
    _require_record(record)
    if record.get("deleted", False):
        raise LifecycleValidationError("record is already tombstoned")
    when = _iso_z(_parse_time(requested_at))
    event = {
        "schema_version": LIFECYCLE_SCHEMA_VERSION,
        "operation": "TOMBSTONE_REQUEST",
        "tenant_id": tenant_id,
        "record_id": record_id,
        "requested_at": when,
        "requested_by": str(requested_by["actor_id"]),
        "reason": reason.strip(),
        "logical_only": True,
        "physical_delete": False,
    }
    event["event_id"] = "life_" + _sha256_text(_canonical_json(event))[:24]
    return event


def build_tombstone_envelope(
    record: Mapping[str, Any],
    event: Mapping[str, Any],
    *,
    requested_by: Mapping[str, Any],
) -> dict[str, Any]:
    _require_record(record)
    _authorize_actor(requested_by, "REQUEST_TOMBSTONE")
    if event.get("operation") != "TOMBSTONE_REQUEST":
        raise LifecycleValidationError("tombstone event required")
    if event.get("tenant_id") != record.get("tenant_id") or event.get("record_id") != record.get("id"):
        raise LifecycleValidationError("event must target the exact tenant-bound record")
    required = ("connector_id", "source_system", "source_object_type", "source_object_id", "raw_ref", "source_acl")
    missing = [field for field in required if field not in record]
    if missing:
        raise LifecycleValidationError(f"record cannot produce tombstone envelope: {', '.join(sorted(missing))}")
    when = str(event["requested_at"])
    return {
        "schema_version": "company-twin-source-envelope/1",
        "tenant_id": str(record["tenant_id"]),
        "connector_id": str(record["connector_id"]),
        "source_system": str(record["source_system"]),
        "source_object_type": str(record["source_object_type"]),
        "source_object_id": str(record["source_object_id"]),
        "revision_id": "tombstone:" + str(event["event_id"]),
        "observed_at": when,
        "effective_at": when,
        "acl": copy.deepcopy(record["source_acl"]),
        "payload": {},
        "raw_ref": str(record["raw_ref"]),
        "cursor": "lifecycle:" + str(event["event_id"]),
        "actor": {
            "actor_id": str(requested_by["actor_id"]),
            "actor_kind": str(requested_by["actor_kind"]).upper(),
            "authority_class": str(requested_by["authority_class"]).upper(),
            "role": "LIFECYCLE_OWNER",
        },
        "deleted": True,
    }


def purge_eligibility(
    record: Mapping[str, Any],
    lifecycle: Mapping[str, Any],
    *,
    evaluated_at: str,
    active_reference_ids: Iterable[str] = (),
) -> dict[str, Any]:
    _require_record(record)
    if lifecycle.get("tenant_id") != record.get("tenant_id") or lifecycle.get("record_id") != record.get("id"):
        raise LifecycleValidationError("lifecycle state must match exact tenant-bound record")
    moment = _parse_time(evaluated_at)
    blockers: list[str] = []
    if not record.get("deleted", False):
        blockers.append("NOT_TOMBSTONED")
    if lifecycle.get("hold", False):
        blockers.append("HOLD_ACTIVE")
    until = lifecycle.get("retention_until")
    if until is None:
        blockers.append("RETENTION_INDEFINITE")
    elif moment < _parse_time(str(until)):
        blockers.append("RETENTION_NOT_EXPIRED")
    refs = sorted({str(ref) for ref in active_reference_ids if str(ref)})
    if refs:
        blockers.append("ACTIVE_REFERENCES")
    result = {
        "schema_version": LIFECYCLE_SCHEMA_VERSION,
        "tenant_id": str(record["tenant_id"]),
        "record_id": str(record["id"]),
        "evaluated_at": _iso_z(moment),
        "eligible": not blockers,
        "advisory_only": True,
        "physical_delete": False,
        "blockers": blockers,
        "active_reference_ids": refs,
    }
    result["eligibility_hash"] = _sha256_text(_canonical_json(result))
    return result


def _export_record(record: Mapping[str, Any]) -> dict[str, Any]:
    _require_record(record)
    fields = (
        "id", "tenant_id", "scope", "truth_class", "source_system", "source_object_type",
        "source_object_id", "revision_id", "source_envelope_id", "effective_at", "observed_at",
        "content_hash", "deleted", "supersedes", "duplicate_of", "actor_id", "actor_kind",
        "manager_actor_id", "authority_class", "payload",
    )
    return {field: copy.deepcopy(record.get(field)) for field in fields if field in record}


def build_export_bundle(
    records: Sequence[Mapping[str, Any]],
    *,
    tenant_id: str,
    authorized_scopes: Iterable[str],
    requested_at: str,
    requested_by: Mapping[str, Any],
    include_tombstones: bool = True,
) -> dict[str, Any]:
    _authorize_actor(requested_by, "EXPORT")
    if not isinstance(tenant_id, str) or not tenant_id:
        raise LifecycleValidationError("tenant_id is required")
    scopes = sorted({str(scope) for scope in authorized_scopes if str(scope)})
    if not scopes:
        raise LifecycleValidationError("at least one authorized scope is required")
    exported: list[dict[str, Any]] = []
    for record in records:
        _require_record(record)
        if record["tenant_id"] != tenant_id:
            continue
        if record["scope"] not in scopes:
            continue
        if record.get("deleted", False) and not include_tombstones:
            continue
        exported.append(_export_record(record))
    exported.sort(key=lambda item: str(item["id"]))
    requested = _iso_z(_parse_time(requested_at))
    manifest = [
        {
            "id": str(item["id"]),
            "content_hash": item.get("content_hash"),
            "truth_class": item.get("truth_class"),
            "deleted": bool(item.get("deleted", False)),
        }
        for item in exported
    ]
    manifest_hash = _sha256_text(_canonical_json(manifest))
    bundle = {
        "schema_version": EXPORT_SCHEMA_VERSION,
        "read_only": True,
        "tenant_id": tenant_id,
        "authorized_scopes": scopes,
        "requested_at": requested,
        "requested_by": str(requested_by["actor_id"]),
        "include_tombstones": bool(include_tombstones),
        "record_count": len(exported),
        "records": exported,
        "manifest_hash": manifest_hash,
    }
    bundle["receipt_hash"] = _sha256_text(_canonical_json(bundle))
    return bundle
