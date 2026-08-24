from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

TRUTH_CLASSES = {"FACT", "EVIDENCE", "INFERENCE"}
RECORD_COLLECTIONS = (
    "entities",
    "relationships",
    "evidence",
    "events",
    "decisions",
    "outcomes",
    "process_observations",
    "inferences",
)


class CompanyTwinValidationError(ValueError):
    pass


def _parse_time(value: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise CompanyTwinValidationError("timestamp must be a non-empty string")
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise CompanyTwinValidationError(f"invalid timestamp: {value}") from exc
    if parsed.tzinfo is None:
        raise CompanyTwinValidationError(f"timestamp must include timezone: {value}")
    return parsed.astimezone(timezone.utc)


def _at_or_before(value: str | None, as_of: datetime) -> bool:
    return bool(value) and _parse_time(value) <= as_of


def _first_time(record: Mapping[str, Any]) -> str | None:
    for field in (
        "occurred_at",
        "decided_at",
        "recorded_at",
        "observed_at",
        "effective_from",
        "created_at",
    ):
        value = record.get(field)
        if isinstance(value, str):
            return value
    return None


def _ids(records: Iterable[Mapping[str, Any]]) -> set[str]:
    return {str(record["id"]) for record in records}


def validate_dataset(data: Mapping[str, Any]) -> None:
    required_top = {
        "schema_version",
        "organization",
        "period",
        "source_authorities",
        "principals",
        *RECORD_COLLECTIONS,
    }
    missing = sorted(required_top.difference(data))
    if missing:
        raise CompanyTwinValidationError(f"missing top-level fields: {', '.join(missing)}")

    if data["schema_version"] != "company-twin-p2a/1":
        raise CompanyTwinValidationError("unsupported schema_version")

    organization = data["organization"]
    if not isinstance(organization, Mapping) or not organization.get("id") or not organization.get("name"):
        raise CompanyTwinValidationError("organization requires id and name")

    period = data["period"]
    start = _parse_time(period["start"])
    end = _parse_time(period["end"])
    if start > end:
        raise CompanyTwinValidationError("period start must not be after end")

    principals = data["principals"]
    if not isinstance(principals, list) or not principals:
        raise CompanyTwinValidationError("principals must be a non-empty list")
    principal_ids: set[str] = set()
    for principal in principals:
        pid = str(principal.get("id", ""))
        if not pid or pid in principal_ids:
            raise CompanyTwinValidationError("principal ids must be unique and non-empty")
        principal_ids.add(pid)
        scopes = principal.get("scopes")
        if not isinstance(scopes, list) or "company" not in scopes:
            raise CompanyTwinValidationError(f"principal {pid} must include company scope")
        if len(scopes) != len(set(scopes)):
            raise CompanyTwinValidationError(f"principal {pid} has duplicate scopes")

    source_authorities = data["source_authorities"]
    if not isinstance(source_authorities, list) or not source_authorities:
        raise CompanyTwinValidationError("source_authorities must be a non-empty list")
    source_authority_ids = _ids(source_authorities)

    seen_record_ids: set[str] = set()
    collection_ids: dict[str, set[str]] = {}
    for collection in RECORD_COLLECTIONS:
        records = data[collection]
        if not isinstance(records, list):
            raise CompanyTwinValidationError(f"{collection} must be a list")
        current: set[str] = set()
        for record in records:
            if not isinstance(record, Mapping):
                raise CompanyTwinValidationError(f"{collection} records must be objects")
            rid = str(record.get("id", ""))
            if not rid:
                raise CompanyTwinValidationError(f"{collection} record missing id")
            if rid in seen_record_ids:
                raise CompanyTwinValidationError(f"duplicate record id: {rid}")
            seen_record_ids.add(rid)
            current.add(rid)
            scope = record.get("scope")
            if not isinstance(scope, str) or not scope:
                raise CompanyTwinValidationError(f"{rid} requires scope")
            truth_class = record.get("truth_class")
            if truth_class not in TRUTH_CLASSES:
                raise CompanyTwinValidationError(f"{rid} has invalid truth_class")
            stamp = _first_time(record)
            if stamp is None:
                raise CompanyTwinValidationError(f"{rid} requires a temporal field")
            when = _parse_time(stamp)
            if when < start or when > end:
                raise CompanyTwinValidationError(f"{rid} falls outside dataset period")
        collection_ids[collection] = current

    evidence_ids = collection_ids["evidence"]
    entity_ids = collection_ids["entities"]
    decision_ids = collection_ids["decisions"]
    event_ids = collection_ids["events"]

    for evidence in data["evidence"]:
        if evidence["truth_class"] != "EVIDENCE":
            raise CompanyTwinValidationError(f"{evidence['id']} must be EVIDENCE")
        authority_id = evidence.get("source_authority_id")
        if authority_id not in source_authority_ids:
            raise CompanyTwinValidationError(f"{evidence['id']} references unknown source authority")

    for event in data["events"]:
        if event["truth_class"] != "FACT":
            raise CompanyTwinValidationError(f"{event['id']} must be FACT")
        unknown = set(event.get("evidence_ids", [])).difference(evidence_ids)
        if unknown:
            raise CompanyTwinValidationError(f"{event['id']} references unknown evidence")
        unknown_entities = set(event.get("entity_ids", [])).difference(entity_ids)
        if unknown_entities:
            raise CompanyTwinValidationError(f"{event['id']} references unknown entities")

    for decision in data["decisions"]:
        if decision["truth_class"] != "FACT":
            raise CompanyTwinValidationError(f"{decision['id']} must be FACT")
        unknown = set(decision.get("evidence_ids", [])).difference(evidence_ids)
        if unknown:
            raise CompanyTwinValidationError(f"{decision['id']} references unknown evidence")
        supersedes = decision.get("supersedes")
        if supersedes is not None and supersedes not in decision_ids:
            raise CompanyTwinValidationError(f"{decision['id']} supersedes unknown decision")

    for outcome in data["outcomes"]:
        if outcome["truth_class"] != "FACT":
            raise CompanyTwinValidationError(f"{outcome['id']} must be FACT")
        if outcome.get("decision_id") not in decision_ids:
            raise CompanyTwinValidationError(f"{outcome['id']} references unknown decision")
        unknown = set(outcome.get("evidence_ids", [])).difference(evidence_ids)
        if unknown:
            raise CompanyTwinValidationError(f"{outcome['id']} references unknown evidence")

    for relationship in data["relationships"]:
        if relationship["truth_class"] != "FACT":
            raise CompanyTwinValidationError(f"{relationship['id']} must be FACT")
        if relationship.get("from_entity_id") not in entity_ids:
            raise CompanyTwinValidationError(f"{relationship['id']} has unknown from entity")
        if relationship.get("to_entity_id") not in entity_ids:
            raise CompanyTwinValidationError(f"{relationship['id']} has unknown to entity")

    for observation in data["process_observations"]:
        if observation["truth_class"] != "FACT":
            raise CompanyTwinValidationError(f"{observation['id']} must be FACT")
        unknown = set(observation.get("evidence_ids", [])).difference(evidence_ids)
        if unknown:
            raise CompanyTwinValidationError(f"{observation['id']} references unknown evidence")

    for inference in data["inferences"]:
        if inference["truth_class"] != "INFERENCE":
            raise CompanyTwinValidationError(f"{inference['id']} must be INFERENCE")
        unknown_evidence = set(inference.get("evidence_ids", [])).difference(evidence_ids)
        unknown_events = set(inference.get("event_ids", [])).difference(event_ids)
        unknown_decisions = set(inference.get("decision_ids", [])).difference(decision_ids)
        if unknown_evidence or unknown_events or unknown_decisions:
            raise CompanyTwinValidationError(f"{inference['id']} references unknown support")
        if not (inference.get("evidence_ids") or inference.get("event_ids") or inference.get("decision_ids")):
            raise CompanyTwinValidationError(f"{inference['id']} must cite supporting records")


def load_dataset(path: str | Path) -> dict[str, Any]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    validate_dataset(data)
    return data


def principal_scopes(data: Mapping[str, Any], principal_id: str) -> frozenset[str]:
    for principal in data["principals"]:
        if principal["id"] == principal_id:
            return frozenset(principal["scopes"])
    raise KeyError(f"unknown principal: {principal_id}")


def _is_visible(record: Mapping[str, Any], scopes: frozenset[str]) -> bool:
    return str(record.get("scope")) in scopes


def _temporal_visible(record: Mapping[str, Any], as_of: datetime) -> bool:
    stamp = _first_time(record)
    if not stamp or not _at_or_before(stamp, as_of):
        return False
    effective_to = record.get("effective_to")
    if isinstance(effective_to, str) and _parse_time(effective_to) <= as_of:
        return False
    return True


def _visible_records(
    records: Iterable[Mapping[str, Any]],
    scopes: frozenset[str],
    as_of: datetime,
) -> list[dict[str, Any]]:
    return [
        dict(record)
        for record in records
        if _is_visible(record, scopes) and _temporal_visible(record, as_of)
    ]


def _decision_statuses(decisions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    superseded = {
        str(decision["supersedes"])
        for decision in decisions
        if decision.get("supersedes") is not None
    }
    result: list[dict[str, Any]] = []
    for decision in decisions:
        copy = dict(decision)
        copy["replay_status"] = "SUPERSEDED" if decision["id"] in superseded else "ACTIVE"
        result.append(copy)
    return result


def replay(
    data: Mapping[str, Any],
    *,
    principal_id: str,
    as_of: str,
) -> dict[str, Any]:
    validate_dataset(data)
    when = _parse_time(as_of)
    period_start = _parse_time(data["period"]["start"])
    period_end = _parse_time(data["period"]["end"])
    if when < period_start or when > period_end:
        raise ValueError("as_of must fall inside dataset period")

    scopes = principal_scopes(data, principal_id)
    snapshot: dict[str, Any] = {
        "schema_version": "company-twin-replay/1",
        "organization": dict(data["organization"]),
        "principal_id": principal_id,
        "authorized_scopes": sorted(scopes),
        "as_of": when.isoformat().replace("+00:00", "Z"),
        "read_only": True,
        "truth_classes": {
            "historical_records": ["FACT", "EVIDENCE"],
            "model_interpretation": ["INFERENCE"],
        },
    }

    for collection in RECORD_COLLECTIONS:
        visible = _visible_records(data[collection], scopes, when)
        snapshot[collection] = visible

    def current_ids() -> set[str]:
        return {
            record["id"]
            for collection in RECORD_COLLECTIONS
            for record in snapshot[collection]
        }

    # Fail closed on references: hide records when a referenced object is outside the
    # principal's visible scope. This avoids leaking even restricted record identifiers.
    visible_ids = current_ids()
    snapshot["relationships"] = [
        record
        for record in snapshot["relationships"]
        if record.get("from_entity_id") in visible_ids
        and record.get("to_entity_id") in visible_ids
    ]
    visible_ids = current_ids()
    snapshot["events"] = [
        record
        for record in snapshot["events"]
        if set(record.get("evidence_ids", [])).issubset(visible_ids)
        and set(record.get("entity_ids", [])).issubset(visible_ids)
    ]
    visible_ids = current_ids()
    snapshot["decisions"] = [
        record
        for record in snapshot["decisions"]
        if set(record.get("evidence_ids", [])).issubset(visible_ids)
        and (
            record.get("supersedes") is None
            or record.get("supersedes") in visible_ids
        )
    ]
    snapshot["decisions"] = _decision_statuses(snapshot["decisions"])
    visible_ids = current_ids()
    snapshot["outcomes"] = [
        record
        for record in snapshot["outcomes"]
        if record.get("decision_id") in visible_ids
        and set(record.get("evidence_ids", [])).issubset(visible_ids)
    ]
    visible_ids = current_ids()
    snapshot["process_observations"] = [
        record
        for record in snapshot["process_observations"]
        if set(record.get("evidence_ids", [])).issubset(visible_ids)
    ]
    visible_ids = current_ids()
    snapshot["inferences"] = [
        record
        for record in snapshot["inferences"]
        if set(record.get("evidence_ids", [])).issubset(visible_ids)
        and set(record.get("event_ids", [])).issubset(visible_ids)
        and set(record.get("decision_ids", [])).issubset(visible_ids)
    ]
    return snapshot


def decision_lineage(
    data: Mapping[str, Any],
    *,
    principal_id: str,
    decision_id: str,
    as_of: str,
) -> list[dict[str, Any]]:
    snapshot = replay(data, principal_id=principal_id, as_of=as_of)
    by_id = {decision["id"]: decision for decision in snapshot["decisions"]}
    if decision_id not in by_id:
        raise KeyError(f"decision not visible: {decision_id}")

    lineage: list[dict[str, Any]] = []
    current = by_id[decision_id]
    seen: set[str] = set()
    while True:
        if current["id"] in seen:
            raise CompanyTwinValidationError("decision supersession cycle detected")
        seen.add(current["id"])
        lineage.append(current)
        previous_id = current.get("supersedes")
        if previous_id is None:
            break
        previous = by_id.get(previous_id)
        if previous is None:
            break
        current = previous
    return lineage


def explorer_payload(
    data: Mapping[str, Any],
    *,
    principal_id: str,
    as_of: str,
) -> dict[str, Any]:
    snapshot = replay(data, principal_id=principal_id, as_of=as_of)
    return {
        "read_only": True,
        "organization": snapshot["organization"],
        "principal_id": principal_id,
        "authorized_scopes": snapshot["authorized_scopes"],
        "as_of": snapshot["as_of"],
        "counts": {
            collection: len(snapshot[collection])
            for collection in RECORD_COLLECTIONS
        },
        "timeline": sorted(
            [
                {
                    "id": record["id"],
                    "type": collection,
                    "at": _first_time(record),
                    "title": record.get("title") or record.get("name") or record.get("claim") or record["id"],
                    "truth_class": record["truth_class"],
                    "scope": record["scope"],
                }
                for collection in (
                    "events",
                    "decisions",
                    "outcomes",
                    "process_observations",
                    "inferences",
                )
                for record in snapshot[collection]
            ],
            key=lambda item: (item["at"] or "", item["id"]),
        ),
        "snapshot": snapshot,
    }


@dataclass(frozen=True)
class DatasetSummary:
    organization_id: str
    organization_name: str
    period_start: str
    period_end: str
    principals: int
    records: int


def summarize(data: Mapping[str, Any]) -> DatasetSummary:
    validate_dataset(data)
    return DatasetSummary(
        organization_id=str(data["organization"]["id"]),
        organization_name=str(data["organization"]["name"]),
        period_start=str(data["period"]["start"]),
        period_end=str(data["period"]["end"]),
        principals=len(data["principals"]),
        records=sum(len(data[collection]) for collection in RECORD_COLLECTIONS),
    )
