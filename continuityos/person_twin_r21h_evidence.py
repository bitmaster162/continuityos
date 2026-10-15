"""Optional, host-configured read boundary for one R3 CURRENT Person snapshot.

The host supplies the intent independently of a fresh R4 context provider. Neither
query text nor memory metadata supplies authority. The provider is a trusted host
integration boundary: synthetic tests do not prove live OS/session authority.
This adapter reads existing stores and grants no model egress or execution rights.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, fields
from datetime import datetime
import hashlib
import json
import math
from typing import Any, Mapping, Protocol, Sequence

from .person_twin_authority_replay import (
    PUBLIC_INPUT_KEYS,
    evaluate_person_twin_authority_replay,
)
from .person_twin_privacy_provenance import filter_person_twin_records
from .sovereign_twin_runtime_r21b import TwinEvidence


class PersonTwinEvidenceError(ValueError):
    """Fail-closed, fixed-code error containing no protected input or anchors."""


def _canonical_hash(value: Any) -> str:
    return hashlib.sha256(json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class PersonReadIntent:
    """Independent controller pins for this exact query, session and selected row."""

    query_sha256: str
    current_session_sha256: str
    request_id: str
    packet_id: str
    memory_id: int
    namespace: str
    person_record_id: str
    source_record_id: str
    principal_id: str
    scope: str
    privacy_class: str
    purpose: str

    def __post_init__(self) -> None:
        if type(self.memory_id) is not int or self.memory_id < 1:
            raise PersonTwinEvidenceError("PERSON_INTENT_MEMORY_ID_INVALID")
        for field in fields(self):
            if field.name == "memory_id":
                continue
            value = getattr(self, field.name)
            if not isinstance(value, str) or not value.strip():
                raise PersonTwinEvidenceError("PERSON_INTENT_FIELD_INVALID")
        for value in (self.query_sha256, self.current_session_sha256):
            if len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
                raise PersonTwinEvidenceError("PERSON_INTENT_HASH_INVALID")


class PersonReadContextProvider(Protocol):
    def read_context(self) -> Mapping[str, Any]:
        """Return fresh exact R4 inputs, including independent live host anchors."""
        ...


class MemoryReadStore(Protocol):
    def get(self, rid: int) -> Any: ...


def _unique_json_object(pairs: Sequence[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PersonTwinEvidenceError("PERSON_MEMORY_META_INVALID")
        result[key] = value
    return result


def _require_current_meta(raw: Any, at: str) -> None:
    if not isinstance(raw, str):
        raise PersonTwinEvidenceError("PERSON_MEMORY_META_INVALID")
    meta = json.loads(raw, object_pairs_hook=_unique_json_object)
    if not isinstance(meta, dict):
        raise PersonTwinEvidenceError("PERSON_MEMORY_META_INVALID")
    # Metadata can veto a row; it never grants READ or supplies R4 anchors.
    json.dumps(meta, allow_nan=False)
    if "superseded_by" in meta or meta.get("valid_to") is not None:
        raise PersonTwinEvidenceError("PERSON_MEMORY_NOT_CURRENT")
    if "valid_from" in meta:
        value = meta["valid_from"]
        if type(value) not in (int, float) or not math.isfinite(value):
            raise PersonTwinEvidenceError("PERSON_MEMORY_VALID_FROM_INVALID")
        current = datetime.fromisoformat(at[:-1] + "+00:00" if at.endswith("Z") else at)
        if current.tzinfo is None or value > current.timestamp():
            raise PersonTwinEvidenceError("PERSON_MEMORY_NOT_YET_CURRENT")


class PersonTwinR21HEvidenceAdapter:
    """R2 filter + R4 READ + exact existing-memory projection, without retrieval.

    A new query/session needs independently updated intent pins. Every prepare
    and prompt validation calls the provider and R4 again; ALLOW is never cached.
    The one source payload may contain the host's goal/decision/constraint/next
    step snapshot. Its exact payload.text is preserved, not generated here.
    """

    def __init__(self, intent: PersonReadIntent, provider: PersonReadContextProvider):
        if type(intent) is not PersonReadIntent or not callable(getattr(provider, "read_context", None)):
            raise PersonTwinEvidenceError("PERSON_ADAPTER_CONFIGURATION_INVALID")
        self._intent = intent
        self._provider = provider

    def _read(
        self, query: str, store: MemoryReadStore,
    ) -> tuple[tuple[TwinEvidence, ...], dict[str, str]]:
        try:
            intent = self._intent
            if not isinstance(query, str) or hashlib.sha256(query.encode("utf-8")).hexdigest() != intent.query_sha256:
                raise PersonTwinEvidenceError("PERSON_QUERY_BINDING_MISMATCH")
            try:
                raw = self._provider.read_context()
            except Exception:
                raise PersonTwinEvidenceError("PERSON_HOST_CONTEXT_READ_FAILED") from None
            try:
                if not isinstance(raw, Mapping) or set(raw) != set(PUBLIC_INPUT_KEYS):
                    raise ValueError("invalid context shape")
                # Freeze JSON inputs, preserving only the two read-store interfaces.
                stores = {name: raw[name] for name in ("admission_store", "replay_store")}
                context = json.loads(json.dumps(
                    {key: value for key, value in raw.items() if key not in stores},
                    ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False,
                ))
                context.update(stores)
            except Exception:
                raise PersonTwinEvidenceError("PERSON_HOST_CONTEXT_SHAPE_INVALID") from None
            pins = {
                "action": "READ", "principal_id": intent.principal_id,
                "requested_scope": intent.scope, "requested_privacy_class": intent.privacy_class,
                "purpose": intent.purpose,
            }
            if any(context[key] != value for key, value in pins.items()):
                raise PersonTwinEvidenceError("PERSON_READ_INTENT_MISMATCH")
            if (
                _canonical_hash(context["current_session"]) != intent.current_session_sha256
                or context["authorization_request"]["request_id"] != intent.request_id
                or context["authorization_preflight"]["packet_id"] != intent.packet_id
            ):
                raise PersonTwinEvidenceError("PERSON_SESSION_REQUEST_BINDING_MISMATCH")
            record = context["person_record"]
            source = context["source_record"]
            if record["id"] != intent.person_record_id or source["id"] != intent.source_record_id:
                raise PersonTwinEvidenceError("PERSON_RECORD_BINDING_MISMATCH")
            if record["deleted"] is not False or source["deleted"] is not False:
                raise PersonTwinEvidenceError("PERSON_DELETED_RECORD_DENIED")
            consent = context["consent_receipt"]
            filtered = filter_person_twin_records(
                [record], context["identity"], authorized_scopes=[intent.scope],
                source_records={source["id"]: source},
                consent_receipts={consent["consent_receipt_id"]: consent},
                current_revocation_ledger=context["current_revocation_ledger"],
                purpose=intent.purpose, at=context["at"],
            )
            if len(filtered) != 1 or filtered[0] != record:
                raise PersonTwinEvidenceError("PERSON_R2_RECORD_DENIED")
            decision = evaluate_person_twin_authority_replay(**context)
            if decision.get("decision") != "ALLOW" or decision.get("action") != "READ":
                raise PersonTwinEvidenceError("PERSON_R4_READ_DENIED")
            expected_binding = {
                "current_session_hash": intent.current_session_sha256,
                "request_id": intent.request_id, "packet_id": intent.packet_id,
                "person_record_id": intent.person_record_id,
                "source_record_id": intent.source_record_id,
                "principal_id": intent.principal_id, "scope": intent.scope,
                "privacy_class": intent.privacy_class, "purpose": intent.purpose,
                "action": "READ",
            }
            binding = decision.get("binding", {})
            if any(binding.get(key) != value for key, value in expected_binding.items()):
                raise PersonTwinEvidenceError("PERSON_R4_BINDING_MISMATCH")
            payload = source["payload"]
            text = payload.get("text") if isinstance(payload, dict) else None
            if not isinstance(text, str) or not text.strip():
                raise PersonTwinEvidenceError("PERSON_SOURCE_TEXT_INVALID")
            if _canonical_hash(payload) != source["content_hash"] or record["payload"] != payload:
                raise PersonTwinEvidenceError("PERSON_SOURCE_PAYLOAD_MISMATCH")
            # No bulk recall, embeddings, metadata-derived authority, or hidden-store creation.
            try:
                selected = store.get(intent.memory_id)
                row = None if selected is None else {
                    key: selected[key] for key in ("id", "namespace", "text", "meta")
                }
            except Exception:
                raise PersonTwinEvidenceError("PERSON_MEMORY_READ_FAILED") from None
            if row is None or type(row["id"]) is not int or row["id"] != intent.memory_id:
                raise PersonTwinEvidenceError("PERSON_MEMORY_ID_MISMATCH")
            if row["namespace"] != intent.namespace or row["text"] != text:
                raise PersonTwinEvidenceError("PERSON_MEMORY_SOURCE_BINDING_MISMATCH")
            _require_current_meta(row["meta"], context["at"])
            evidence = (TwinEvidence(
                id=intent.memory_id, namespace=intent.namespace, text=text,
                # Exact row selection marker, not a measured confidence score.
                score=1.0, why="R2_PROVENANCE_AND_R4_READ_CURRENT",
            ),)
            return evidence, {
                "intent_sha256": _canonical_hash(asdict(intent)),
                "r4_receipt_hash": decision["receipt_hash"],
                "evidence_sha256": _canonical_hash([asdict(row) for row in evidence]),
            }
        except PersonTwinEvidenceError:
            raise
        except Exception:
            # R2/R4/provider/store errors can contain protected data or identifiers.
            raise PersonTwinEvidenceError("PERSON_EVIDENCE_VALIDATION_FAILED") from None

    def prepare(self, query: str, store: MemoryReadStore) -> tuple[TwinEvidence, ...]:
        evidence, _ = self._read(query, store)
        return evidence

    def validate_for_prompt(
        self, query: str, store: MemoryReadStore, evidence: Sequence[TwinEvidence],
    ) -> dict[str, Any]:
        if type(evidence) is not tuple or len(evidence) != 1 or type(evidence[0]) is not TwinEvidence:
            raise PersonTwinEvidenceError("PERSON_PROMPT_EVIDENCE_SHAPE_INVALID")
        current, commitments = self._read(query, store)
        if evidence != current:
            raise PersonTwinEvidenceError("PERSON_PROMPT_EVIDENCE_CHANGED")
        receipt = {
            "schema": "continuityos.person-twin.r21h-evidence/v1",
            "decision": "ALLOW", "action": "READ", "evidence_count": 1,
            "memory_refs": [f"mem:{self._intent.memory_id}"],
            "prompt_boundary_revalidated": True,
            "production_admission_status": "NOT_PRODUCTION_ADMITTED",
            "execution_authority": "NONE", "can_execute": False,
            "can_trade": False, "capital_permission": "DENY",
            **commitments,
        }
        receipt["receipt_hash"] = _canonical_hash(receipt)
        return receipt
