from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping, Sequence

ENVELOPE_SCHEMA_VERSION = "company-twin-source-envelope/1"
RECEIPT_SCHEMA_VERSION = "company-twin-ingest-receipt/1"
PARSER_VERSION = "company-twin-p2b/1"

ACTOR_KINDS = {"HUMAN", "AGENT", "SERVICE"}
AGENT_AUTHORITIES = {"NONE", "READ_ONLY", "PROPOSE"}
SERVICE_AUTHORITIES = {"NONE", "READ_ONLY"}
HUMAN_AUTHORITIES = {"OWNER", "WORKER", "READ_ONLY"}
ALLOWED_VISIBILITY = {"COMPANY", "TEAM", "PERSONAL", "RESTRICTED"}

SOURCE_ENVELOPE_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "https://continuityos.local/schemas/company-twin-source-envelope-p2b.json",
    "title": "Company Twin P2B Canonical Source Envelope",
    "type": "object",
    "required": [
        "schema_version", "tenant_id", "connector_id", "source_system",
        "source_object_type", "source_object_id", "revision_id", "observed_at",
        "effective_at", "acl", "payload", "raw_ref", "cursor", "actor",
    ],
}

INGEST_RECEIPT_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "https://continuityos.local/schemas/company-twin-ingest-receipt-p2b.json",
    "title": "Company Twin P2B Deterministic Ingestion Receipt",
    "type": "object",
    "required": [
        "schema_version", "tenant_id", "connector_id", "parser_version",
        "cursor_before", "cursor_after", "accepted", "idempotent",
        "quarantined", "manifest_hash", "receipt_hash",
    ],
}


class IngestValidationError(ValueError):
    pass


class IngestionBatchAborted(RuntimeError):
    pass


def _parse_time(value: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise IngestValidationError("timestamp must be a non-empty string")
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise IngestValidationError(f"invalid timestamp: {value}") from exc
    if parsed.tzinfo is None:
        raise IngestValidationError(f"timestamp must include timezone: {value}")
    return parsed.astimezone(timezone.utc)


def _canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _payload_hash(payload: Any) -> str:
    return _sha256_text(_canonical_json(payload))


def _scope_from_acl(acl: Mapping[str, Any]) -> str:
    visibility = str(acl.get("visibility", "")).upper()
    scope = acl.get("scope")
    if visibility not in ALLOWED_VISIBILITY:
        raise IngestValidationError("acl.visibility must be COMPANY/TEAM/PERSONAL/RESTRICTED")
    if not isinstance(scope, str) or not scope:
        raise IngestValidationError("acl.scope must be a non-empty string")
    if visibility == "COMPANY" and scope != "company":
        raise IngestValidationError("COMPANY visibility must use company scope")
    if visibility == "TEAM" and not scope.startswith("team:"):
        raise IngestValidationError("TEAM visibility must use team:* scope")
    if visibility == "PERSONAL" and not scope.startswith("person:"):
        raise IngestValidationError("PERSONAL visibility must use person:* scope")
    if visibility == "RESTRICTED" and not scope.startswith("restricted:"):
        raise IngestValidationError("RESTRICTED visibility must use restricted:* scope")
    return scope


def _validate_actor(actor: Mapping[str, Any]) -> None:
    actor_id = actor.get("actor_id")
    kind = str(actor.get("actor_kind", "")).upper()
    authority = str(actor.get("authority_class", "")).upper()
    if not isinstance(actor_id, str) or not actor_id:
        raise IngestValidationError("actor.actor_id is required")
    if kind not in ACTOR_KINDS:
        raise IngestValidationError("actor.actor_kind must be HUMAN/AGENT/SERVICE")
    if kind == "AGENT":
        manager = actor.get("manager_actor_id")
        if not isinstance(manager, str) or not manager:
            raise IngestValidationError("AGENT must have manager_actor_id")
        if authority not in AGENT_AUTHORITIES:
            raise IngestValidationError("AGENT authority must be NONE/READ_ONLY/PROPOSE")
    elif kind == "SERVICE":
        if authority not in SERVICE_AUTHORITIES:
            raise IngestValidationError("SERVICE authority must be NONE/READ_ONLY")
    elif authority not in HUMAN_AUTHORITIES:
        raise IngestValidationError("HUMAN authority must be OWNER/WORKER/READ_ONLY")


def validate_envelope(envelope: Mapping[str, Any]) -> None:
    missing = [f for f in SOURCE_ENVELOPE_SCHEMA["required"] if f not in envelope]
    if missing:
        raise IngestValidationError(f"missing envelope fields: {', '.join(sorted(missing))}")
    if envelope["schema_version"] != ENVELOPE_SCHEMA_VERSION:
        raise IngestValidationError("unsupported envelope schema_version")
    for field in (
        "tenant_id", "connector_id", "source_system", "source_object_type",
        "source_object_id", "revision_id", "raw_ref", "cursor",
    ):
        if not isinstance(envelope[field], str) or not envelope[field]:
            raise IngestValidationError(f"{field} must be a non-empty string")
    observed = _parse_time(envelope["observed_at"])
    effective = _parse_time(envelope["effective_at"])
    if effective > observed:
        raise IngestValidationError("effective_at must not be after observed_at")
    if not isinstance(envelope["acl"], Mapping):
        raise IngestValidationError("acl must be an object")
    _scope_from_acl(envelope["acl"])
    if not isinstance(envelope["actor"], Mapping):
        raise IngestValidationError("actor must be an object")
    _validate_actor(envelope["actor"])
    if not isinstance(envelope.get("deleted", False), bool):
        raise IngestValidationError("deleted must be boolean")
    supplied_hash = envelope.get("content_hash")
    calculated = _payload_hash(envelope["payload"])
    if supplied_hash is not None and supplied_hash != calculated:
        raise IngestValidationError("content_hash does not match canonical payload hash")


def envelope_id(envelope: Mapping[str, Any]) -> str:
    validate_envelope(envelope)
    identity = {k: envelope[k] for k in (
        "tenant_id", "connector_id", "source_system", "source_object_type",
        "source_object_id", "revision_id",
    )}
    return "src_" + _sha256_text(_canonical_json(identity))[:32]


def canonical_record_id(envelope: Mapping[str, Any]) -> str:
    identity = {k: envelope[k] for k in (
        "tenant_id", "source_system", "source_object_type", "source_object_id", "revision_id",
    )}
    return "cti_" + _sha256_text(_canonical_json(identity))[:32]


def _object_key(value: Mapping[str, Any]) -> tuple[str, str, str, str]:
    return (
        str(value["tenant_id"]), str(value["source_system"]),
        str(value["source_object_type"]), str(value["source_object_id"]),
    )


def normalize_envelope(
    envelope: Mapping[str, Any], *, duplicate_of: str | None = None,
    supersedes: str | None = None,
) -> dict[str, Any]:
    validate_envelope(envelope)
    actor = envelope["actor"]
    return {
        "id": canonical_record_id(envelope),
        "schema_version": "company-twin-ingested-record/1",
        "tenant_id": envelope["tenant_id"],
        "connector_id": envelope["connector_id"],
        "source_system": envelope["source_system"],
        "source_object_type": envelope["source_object_type"],
        "source_object_id": envelope["source_object_id"],
        "revision_id": envelope["revision_id"],
        "source_envelope_id": envelope_id(envelope),
        "observed_at": envelope["observed_at"],
        "effective_at": envelope["effective_at"],
        "scope": _scope_from_acl(envelope["acl"]),
        "visibility": str(envelope["acl"]["visibility"]).upper(),
        "source_acl": copy.deepcopy(dict(envelope["acl"])),
        "content_hash": _payload_hash(envelope["payload"]),
        "raw_ref": envelope["raw_ref"],
        "deleted": bool(envelope.get("deleted", False)),
        "cursor": envelope["cursor"],
        "parser_version": PARSER_VERSION,
        "truth_class": "EVIDENCE",
        "actor_id": actor["actor_id"],
        "actor_kind": str(actor["actor_kind"]).upper(),
        "actor_role": actor.get("role"),
        "manager_actor_id": actor.get("manager_actor_id"),
        "authority_class": str(actor["authority_class"]).upper(),
        "payload": copy.deepcopy(envelope["payload"]),
        "supersedes": supersedes,
        "duplicate_of": duplicate_of,
    }


def _quarantine_record(index: int, raw: Any, reason: str) -> dict[str, Any]:
    try:
        digest = _sha256_text(_canonical_json(raw))
    except TypeError:
        digest = _sha256_text(repr(raw))
    return {"id": f"quarantine_{digest[:24]}", "input_index": index, "reason": reason, "raw_hash": digest}


def normalize_batch(
    envelopes: Sequence[Mapping[str, Any]], *, existing_records: Sequence[Mapping[str, Any]] = (),
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[str]]:
    valid: list[Mapping[str, Any]] = []
    quarantine: list[dict[str, Any]] = []
    for index, envelope in enumerate(envelopes):
        try:
            if not isinstance(envelope, Mapping):
                raise IngestValidationError("envelope must be an object")
            validate_envelope(envelope)
            valid.append(envelope)
        except (IngestValidationError, KeyError, TypeError) as exc:
            quarantine.append(_quarantine_record(index, envelope, str(exc)))

    existing_by_id = {str(r["id"]): r for r in existing_records}
    prior_by_object: dict[tuple[str, str, str, str], list[Mapping[str, Any]]] = {}
    for record in existing_records:
        prior_by_object.setdefault(_object_key(record), []).append(record)

    unique: dict[str, Mapping[str, Any]] = {}
    idempotent: list[str] = []
    for envelope in valid:
        rid = canonical_record_id(envelope)
        if rid in existing_by_id or rid in unique:
            idempotent.append(rid)
        else:
            unique[rid] = envelope

    grouped: dict[tuple[str, str, str, str], list[Mapping[str, Any]]] = {}
    for envelope in unique.values():
        grouped.setdefault(_object_key(envelope), []).append(envelope)

    content_index: dict[tuple[str, str, str], str] = {}
    for record in existing_records:
        if not record.get("deleted", False):
            content_index.setdefault((str(record["tenant_id"]), str(record["content_hash"]), str(record["effective_at"])), str(record["id"]))

    accepted: list[dict[str, Any]] = []
    for key in sorted(grouped):
        candidates = sorted(grouped[key], key=lambda e: (_parse_time(str(e["observed_at"])), str(e["revision_id"])))
        prior = sorted(prior_by_object.get(key, ()), key=lambda r: (_parse_time(str(r["observed_at"])), str(r["revision_id"])))
        supersedes = str(prior[-1]["id"]) if prior else None
        for envelope in candidates:
            dup_key = (str(envelope["tenant_id"]), _payload_hash(envelope["payload"]), str(envelope["effective_at"]))
            record = normalize_envelope(envelope, duplicate_of=content_index.get(dup_key), supersedes=supersedes)
            accepted.append(record)
            supersedes = record["id"]
            if not record["deleted"]:
                content_index.setdefault(dup_key, record["id"])

    accepted.sort(key=lambda r: r["id"])
    quarantine.sort(key=lambda q: q["id"])
    return accepted, quarantine, sorted(set(idempotent))


def build_receipt(*, tenant_id: str, connector_id: str, cursor_before: str | None, cursor_after: str,
                  accepted: Sequence[Mapping[str, Any]], quarantined: Sequence[Mapping[str, Any]],
                  idempotent: Sequence[str]) -> dict[str, Any]:
    manifest = sorted([
        {"id": r["id"], "source_envelope_id": r["source_envelope_id"], "content_hash": r["content_hash"],
         "revision_id": r["revision_id"], "deleted": r["deleted"]}
        for r in accepted
    ], key=lambda x: x["id"])
    receipt = {
        "schema_version": RECEIPT_SCHEMA_VERSION,
        "tenant_id": tenant_id,
        "connector_id": connector_id,
        "parser_version": PARSER_VERSION,
        "cursor_before": cursor_before,
        "cursor_after": cursor_after,
        "accepted": len(accepted),
        "accepted_ids": sorted(str(r["id"]) for r in accepted),
        "idempotent": len(set(idempotent)),
        "idempotent_ids": sorted(set(idempotent)),
        "quarantined": len(quarantined),
        "quarantine_ids": sorted(str(q["id"]) for q in quarantined),
        "manifest_hash": _sha256_text(_canonical_json(manifest)),
    }
    receipt["receipt_hash"] = _sha256_text(_canonical_json(receipt))
    return receipt


@dataclass(frozen=True)
class BatchResult:
    records: tuple[dict[str, Any], ...]
    quarantine: tuple[dict[str, Any], ...]
    receipt: dict[str, Any]


class InMemoryIngestStore:
    """Transactional synthetic P2B store with no external side effects."""
    def __init__(self) -> None:
        self._records: list[dict[str, Any]] = []
        self._cursor_by_connector: dict[tuple[str, str], str] = {}

    @property
    def records(self) -> tuple[dict[str, Any], ...]:
        return tuple(copy.deepcopy(self._records))

    def cursor(self, tenant_id: str, connector_id: str) -> str | None:
        return self._cursor_by_connector.get((tenant_id, connector_id))

    def apply_batch(self, envelopes: Sequence[Mapping[str, Any]], *, tenant_id: str, connector_id: str,
                    cursor_after: str, fail_after_normalize: bool = False) -> BatchResult:
        before_records = copy.deepcopy(self._records)
        before_cursors = dict(self._cursor_by_connector)
        cursor_before = before_cursors.get((tenant_id, connector_id))
        for envelope in envelopes:
            if isinstance(envelope, Mapping):
                if envelope.get("tenant_id") not in (None, tenant_id):
                    raise IngestionBatchAborted("batch contains a different tenant_id")
                if envelope.get("connector_id") not in (None, connector_id):
                    raise IngestionBatchAborted("batch contains a different connector_id")
        accepted, quarantine, idempotent = normalize_batch(envelopes, existing_records=before_records)
        if fail_after_normalize:
            if self._records != before_records or self._cursor_by_connector != before_cursors:
                raise AssertionError("store mutated before commit point")
            raise IngestionBatchAborted("synthetic pre-commit failure")
        next_records = before_records + copy.deepcopy(accepted)
        next_records.sort(key=lambda r: r["id"])
        receipt = build_receipt(
            tenant_id=tenant_id, connector_id=connector_id, cursor_before=cursor_before,
            cursor_after=cursor_after, accepted=accepted, quarantined=quarantine, idempotent=idempotent,
        )
        self._records = next_records
        self._cursor_by_connector[(tenant_id, connector_id)] = cursor_after
        return BatchResult(tuple(copy.deepcopy(accepted)), tuple(copy.deepcopy(quarantine)), copy.deepcopy(receipt))


def replay_ingested(records: Sequence[Mapping[str, Any]], *, tenant_id: str,
                    authorized_scopes: Iterable[str], as_of: str) -> dict[str, Any]:
    moment = _parse_time(as_of)
    scopes = frozenset(str(scope) for scope in authorized_scopes)
    candidates = [r for r in records if r.get("tenant_id") == tenant_id and r.get("scope") in scopes
                  and _parse_time(str(r["effective_at"])) <= moment and _parse_time(str(r["observed_at"])) <= moment]
    grouped: dict[tuple[str, str, str, str], list[Mapping[str, Any]]] = {}
    for record in candidates:
        grouped.setdefault(_object_key(record), []).append(record)
    active: list[dict[str, Any]] = []
    tombstones: list[dict[str, Any]] = []
    for key in sorted(grouped):
        latest = sorted(grouped[key], key=lambda r: (_parse_time(str(r["observed_at"])), str(r["revision_id"])))[-1]
        public = {k: latest.get(k) for k in (
            "id", "source_system", "source_object_type", "source_object_id", "revision_id",
            "effective_at", "observed_at", "scope", "truth_class", "source_envelope_id",
            "content_hash", "actor_id", "actor_kind", "manager_actor_id", "deleted",
        )}
        if latest["deleted"]:
            tombstones.append(public)
        else:
            public["payload"] = copy.deepcopy(latest["payload"])
            active.append(public)
    return {
        "read_only": True, "tenant_id": tenant_id, "as_of": as_of,
        "authorized_scopes": sorted(scopes),
        "records": sorted(active, key=lambda r: r["id"]),
        "tombstones": sorted(tombstones, key=lambda r: r["id"]),
    }


def to_company_twin_evidence(record: Mapping[str, Any], *, source_authority_id: str) -> dict[str, Any]:
    if record.get("truth_class") != "EVIDENCE":
        raise IngestValidationError("only source evidence can project to P2A evidence")
    if record.get("deleted"):
        raise IngestValidationError("tombstones do not project to active evidence")
    return {
        "id": "ev_" + _sha256_text(str(record["id"]))[:24],
        "kind": str(record["source_object_type"]),
        "title": str(record["payload"].get("title") or record["payload"].get("subject") or record["source_object_id"]),
        "recorded_at": str(record["effective_at"]),
        "scope": str(record["scope"]),
        "truth_class": "EVIDENCE",
        "source_authority_id": source_authority_id,
        "source_ref": str(record["raw_ref"]),
        "source_envelope_ids": [str(record["source_envelope_id"])],
        "ingest_record_id": str(record["id"]),
        "content_hash": str(record["content_hash"]),
    }


def validate_agent_management(records: Sequence[Mapping[str, Any]]) -> None:
    for record in records:
        if record.get("actor_kind") == "AGENT":
            if not record.get("manager_actor_id"):
                raise IngestValidationError("AGENT record missing manager_actor_id")
            if record.get("authority_class") not in AGENT_AUTHORITIES:
                raise IngestValidationError("AGENT authority exceeds P2B ceiling")
