from __future__ import annotations

import copy
import hashlib
import json
from typing import Any, Iterable, Mapping, Sequence

from .company_twin_lifecycle import build_export_bundle
from .person_twin_admission_contracts import (
    NOT_PRODUCTION_ADMITTED,
    PersonTwinContractError,
    evaluate_consent,
    validate_person_twin_identity,
    validate_source_consent_receipt,
)

PRIVACY_PROVENANCE_SCHEMA_VERSION = "continuityos.person-twin.privacy-provenance/v1"
EXPORT_ADAPTER_SCHEMA_VERSION = "continuityos.person-twin.export-adapter/v1"
LIFECYCLE_TARGET_SCHEMA_VERSION = "continuityos.person-twin.lifecycle-target/v1"

PERSON_PRIVATE = "PERSON_PRIVATE"
PERSON_SHARED = "PERSON_SHARED"
TEAM = "TEAM"
COMPANY = "COMPANY"
RESTRICTED = "RESTRICTED"
PRIVACY_CLASSES = {PERSON_PRIVATE, PERSON_SHARED, TEAM, COMPANY, RESTRICTED}

class PersonTwinPrivacyProvenanceError(ValueError):
    pass

def _canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))

def _canonical_hash(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()

def _non_empty(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise PersonTwinPrivacyProvenanceError(f"{field} must be a non-empty string")
    return value

def _sha256(value: Any, field: str) -> str:
    text = _non_empty(value, field)
    if len(text) != 64 or any(ch not in "0123456789abcdef" for ch in text):
        raise PersonTwinPrivacyProvenanceError(f"{field} must be a lowercase sha256 hex digest")
    return text

def _canonical_scopes(scopes: Iterable[str]) -> list[str]:
    if isinstance(scopes, (str, bytes)):
        raise PersonTwinPrivacyProvenanceError("authorized_scopes must be a collection")
    result = sorted({_non_empty(scope, "authorized_scope") for scope in scopes})
    if not result:
        raise PersonTwinPrivacyProvenanceError("at least one authorized scope is required")
    if any("*" in scope for scope in result):
        raise PersonTwinPrivacyProvenanceError("wildcard scopes are not allowed")
    return result

def canonical_person_private_scope(twin_id: str) -> str:
    return f"person:{_non_empty(twin_id, 'twin_id')}:private"

def canonical_person_shared_scope(twin_id: str, share_id: str) -> str:
    share = _non_empty(share_id, "share_id")
    if "*" in share or ":" in share:
        raise PersonTwinPrivacyProvenanceError("share_id must not contain wildcard or colon")
    return f"person:{_non_empty(twin_id, 'twin_id')}:shared:{share}"

def validate_privacy_scope(*, twin_id: str, privacy_class: str, scope: str) -> None:
    twin = _non_empty(twin_id, "twin_id")
    privacy = _non_empty(privacy_class, "privacy_class")
    value = _non_empty(scope, "scope")
    if privacy not in PRIVACY_CLASSES:
        raise PersonTwinPrivacyProvenanceError("unsupported privacy_class")
    if "*" in value:
        raise PersonTwinPrivacyProvenanceError("wildcard scope is not allowed")
    if privacy == PERSON_PRIVATE:
        if value != canonical_person_private_scope(twin):
            raise PersonTwinPrivacyProvenanceError("PERSON_PRIVATE scope must bind the exact twin_id")
    elif privacy == PERSON_SHARED:
        prefix = f"person:{twin}:shared:"
        share_id = value[len(prefix):] if value.startswith(prefix) else ""
        if not share_id or ":" in share_id:
            raise PersonTwinPrivacyProvenanceError(
                "PERSON_SHARED scope must bind exact twin_id and one explicit share_id"
            )
    elif privacy == TEAM:
        if not value.startswith("team:") or value == "team:":
            raise PersonTwinPrivacyProvenanceError("TEAM scope must use team:<id>")
    elif privacy == COMPANY:
        if value != "company":
            raise PersonTwinPrivacyProvenanceError("COMPANY scope must be exactly company")
    elif privacy == RESTRICTED:
        if not value.startswith("restricted:") or value == "restricted:":
            raise PersonTwinPrivacyProvenanceError("RESTRICTED scope must use restricted:<id>")

def infer_privacy_class(source_record: Mapping[str, Any], *, twin_id: str) -> str:
    visibility = _non_empty(source_record.get("visibility"), "visibility").upper()
    scope = _non_empty(source_record.get("scope"), "scope")
    if visibility == "PERSONAL":
        private_scope = canonical_person_private_scope(twin_id)
        shared_prefix = f"person:{twin_id}:shared:"
        if scope == private_scope:
            privacy_class = PERSON_PRIVATE
        elif scope.startswith(shared_prefix) and scope[len(shared_prefix):] and ":" not in scope[len(shared_prefix):]:
            privacy_class = PERSON_SHARED
        else:
            raise PersonTwinPrivacyProvenanceError(
                "PERSONAL source scope must be an exact Person Twin private/shared scope"
            )
    elif visibility == "TEAM":
        privacy_class = TEAM
    elif visibility == "COMPANY":
        privacy_class = COMPANY
    elif visibility == "RESTRICTED":
        privacy_class = RESTRICTED
    else:
        raise PersonTwinPrivacyProvenanceError("unsupported source visibility")
    validate_privacy_scope(twin_id=twin_id, privacy_class=privacy_class, scope=scope)
    return privacy_class

def validate_no_implicit_scope_promotion(
    source_record: Mapping[str, Any],
    *,
    twin_id: str,
    target_privacy_class: str,
    target_scope: str,
) -> None:
    source_class = infer_privacy_class(source_record, twin_id=twin_id)
    validate_privacy_scope(twin_id=twin_id, privacy_class=target_privacy_class, scope=target_scope)
    if target_privacy_class != source_class or target_scope != source_record.get("scope"):
        raise PersonTwinPrivacyProvenanceError(
            "implicit privacy/scope promotion is forbidden in P3-P1 R2"
        )

def deterministic_source_identity_hash(source_record: Mapping[str, Any]) -> str:
    identity = {
        "tenant_id": _non_empty(source_record.get("tenant_id"), "tenant_id"),
        "connector_id": _non_empty(source_record.get("connector_id"), "connector_id"),
        "source_system": _non_empty(source_record.get("source_system"), "source_system"),
    }
    return _canonical_hash(identity)

def _validate_source_record(source_record: Mapping[str, Any]) -> None:
    required = (
        "id", "schema_version", "tenant_id", "connector_id", "source_system",
        "source_object_type", "source_object_id", "revision_id", "source_envelope_id",
        "observed_at", "effective_at", "scope", "visibility", "source_acl", "content_hash",
        "deleted", "truth_class", "actor_id", "actor_kind", "authority_class", "payload",
        "supersedes", "duplicate_of",
    )
    missing = [field for field in required if field not in source_record]
    if missing:
        raise PersonTwinPrivacyProvenanceError(
            f"source record missing required P2 fields: {', '.join(sorted(missing))}"
        )
    if source_record["schema_version"] != "company-twin-ingested-record/1":
        raise PersonTwinPrivacyProvenanceError("unsupported P2 source record schema_version")
    if source_record["truth_class"] != "EVIDENCE":
        raise PersonTwinPrivacyProvenanceError("Person Twin provenance source must be EVIDENCE")
    _sha256(source_record["content_hash"], "content_hash")
    expected_content_hash = _canonical_hash(source_record["payload"])
    if source_record["content_hash"] != expected_content_hash:
        raise PersonTwinPrivacyProvenanceError("source content_hash does not match payload")
    acl = source_record["source_acl"]
    if not isinstance(acl, Mapping):
        raise PersonTwinPrivacyProvenanceError("source_acl must be a mapping")
    if acl.get("scope") != source_record["scope"]:
        raise PersonTwinPrivacyProvenanceError("source ACL scope mismatch")
    if str(acl.get("visibility", "")).upper() != str(source_record["visibility"]).upper():
        raise PersonTwinPrivacyProvenanceError("source ACL visibility mismatch")

def _binding_body(source_record: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "source_record_id": source_record["id"],
        "tenant_id": source_record["tenant_id"],
        "connector_id": source_record["connector_id"],
        "source_system": source_record["source_system"],
        "source_object_type": source_record["source_object_type"],
        "source_object_id": source_record["source_object_id"],
        "revision_id": source_record["revision_id"],
        "source_envelope_id": source_record["source_envelope_id"],
        "observed_at": source_record["observed_at"],
        "effective_at": source_record["effective_at"],
        "content_hash": source_record["content_hash"],
        "scope": source_record["scope"],
        "visibility": str(source_record["visibility"]).upper(),
        "actor_id": source_record["actor_id"],
        "actor_kind": source_record["actor_kind"],
        "authority_class": source_record["authority_class"],
        "supersedes": source_record.get("supersedes"),
        "duplicate_of": source_record.get("duplicate_of"),
        "deleted": bool(source_record.get("deleted", False)),
    }

def build_person_twin_provenance(
    identity: Mapping[str, Any],
    consent_receipt: Mapping[str, Any],
    revocation_ledger: Mapping[str, Any],
    source_record: Mapping[str, Any],
    *,
    admission_session_id: str,
    purpose: str,
    at: str,
) -> dict[str, Any]:
    try:
        validate_person_twin_identity(identity)
        validate_source_consent_receipt(identity, consent_receipt)
    except PersonTwinContractError as exc:
        raise PersonTwinPrivacyProvenanceError(str(exc)) from exc
    _validate_source_record(source_record)
    if source_record["tenant_id"] != identity["tenant_id"]:
        raise PersonTwinPrivacyProvenanceError("source tenant_id does not match Person Twin identity")

    privacy_class = infer_privacy_class(source_record, twin_id=str(identity["twin_id"]))
    scope = str(source_record["scope"])
    source_identity_hash = deterministic_source_identity_hash(source_record)
    if consent_receipt["source_system"] != source_record["source_system"]:
        raise PersonTwinPrivacyProvenanceError("consent source_system does not match source record")
    if consent_receipt["source_identity_hash"] != source_identity_hash:
        raise PersonTwinPrivacyProvenanceError("consent source_identity_hash does not match source record")

    decision = evaluate_consent(
        identity,
        consent_receipt,
        revocation_ledger=revocation_ledger,
        at=at,
        requested_object_type=str(source_record["source_object_type"]),
        requested_scope=scope,
        purpose=purpose,
        require_source_read=False,
        require_memory_admission=True,
    )
    if decision.get("decision") != "ALLOW":
        raise PersonTwinPrivacyProvenanceError(
            f"consent denied at Person Twin provenance boundary: {decision.get('reason', 'UNKNOWN')}"
        )

    admission = _non_empty(admission_session_id, "admission_session_id")
    body: dict[str, Any] = {
        "schema_version": PRIVACY_PROVENANCE_SCHEMA_VERSION,
        "id": f"ptp_{_canonical_hash({'twin_id': identity['twin_id'], 'source_record_id': source_record['id'], 'admission_session_id': admission})[:32]}",
        "tenant_id": identity["tenant_id"],
        "twin_id": identity["twin_id"],
        "identity_fingerprint": identity["identity_fingerprint"],
        "privacy_class": privacy_class,
        "scope": scope,
        "source_identity_hash": source_identity_hash,
        **_binding_body(source_record),
        "consent_receipt_id": consent_receipt["consent_receipt_id"],
        "consent_receipt_hash": consent_receipt["receipt_hash"],
        "revocation_ledger_hash": decision["revocation_ledger_hash"],
        "admission_session_id": admission,
        "truth_class": "EVIDENCE",
        "payload": copy.deepcopy(source_record["payload"]),
        "production_admission_status": NOT_PRODUCTION_ADMITTED,
        "execution_authority": "NONE",
        "can_execute": False,
    }
    body["provenance_hash"] = _canonical_hash(body)
    validate_person_twin_record(body)
    validate_person_twin_provenance_binding(identity, consent_receipt, source_record, body)
    return body

def validate_person_twin_record(record: Mapping[str, Any]) -> None:
    required = {
        "schema_version", "id", "tenant_id", "twin_id", "identity_fingerprint",
        "privacy_class", "scope", "source_identity_hash", "source_record_id", "connector_id",
        "source_system", "source_object_type", "source_object_id", "revision_id",
        "source_envelope_id", "observed_at", "effective_at", "content_hash", "visibility",
        "actor_id", "actor_kind", "authority_class", "supersedes", "duplicate_of", "deleted",
        "consent_receipt_id", "consent_receipt_hash", "revocation_ledger_hash",
        "admission_session_id", "truth_class", "payload", "production_admission_status",
        "execution_authority", "can_execute", "provenance_hash",
    }
    if set(record) != required:
        raise PersonTwinPrivacyProvenanceError("Person Twin provenance fields do not match R2 contract")
    if record["schema_version"] != PRIVACY_PROVENANCE_SCHEMA_VERSION:
        raise PersonTwinPrivacyProvenanceError("unsupported Person Twin provenance schema_version")
    _non_empty(record["id"], "id")
    _non_empty(record["tenant_id"], "tenant_id")
    _non_empty(record["twin_id"], "twin_id")
    _sha256(record["identity_fingerprint"], "identity_fingerprint")
    validate_privacy_scope(twin_id=str(record["twin_id"]), privacy_class=str(record["privacy_class"]), scope=str(record["scope"]))
    _sha256(record["source_identity_hash"], "source_identity_hash")
    _sha256(record["content_hash"], "content_hash")
    _sha256(record["consent_receipt_hash"], "consent_receipt_hash")
    _sha256(record["revocation_ledger_hash"], "revocation_ledger_hash")
    if record["truth_class"] != "EVIDENCE":
        raise PersonTwinPrivacyProvenanceError("truth_class must remain EVIDENCE")
    if record["production_admission_status"] != NOT_PRODUCTION_ADMITTED:
        raise PersonTwinPrivacyProvenanceError("R2 cannot claim production admission")
    if record["execution_authority"] != "NONE" or record["can_execute"] is not False:
        raise PersonTwinPrivacyProvenanceError("R2 record cannot carry execution authority")
    if record["content_hash"] != _canonical_hash(record["payload"]):
        raise PersonTwinPrivacyProvenanceError("content_hash does not match payload")
    provenance_hash = _sha256(record["provenance_hash"], "provenance_hash")
    body = dict(record)
    body.pop("provenance_hash")
    if provenance_hash != _canonical_hash(body):
        raise PersonTwinPrivacyProvenanceError("provenance_hash mismatch")

def validate_person_twin_provenance_binding(
    identity: Mapping[str, Any],
    consent_receipt: Mapping[str, Any],
    source_record: Mapping[str, Any],
    person_record: Mapping[str, Any],
) -> None:
    try:
        validate_person_twin_identity(identity)
        validate_source_consent_receipt(identity, consent_receipt)
    except PersonTwinContractError as exc:
        raise PersonTwinPrivacyProvenanceError(str(exc)) from exc
    _validate_source_record(source_record)
    validate_person_twin_record(person_record)
    expected = _binding_body(source_record)
    for field, value in expected.items():
        if person_record[field] != value:
            raise PersonTwinPrivacyProvenanceError(f"source provenance binding mismatch: {field}")
    if person_record["tenant_id"] != identity["tenant_id"]:
        raise PersonTwinPrivacyProvenanceError("Person Twin tenant binding mismatch")
    if person_record["twin_id"] != identity["twin_id"]:
        raise PersonTwinPrivacyProvenanceError("Person Twin twin_id binding mismatch")
    if person_record["identity_fingerprint"] != identity["identity_fingerprint"]:
        raise PersonTwinPrivacyProvenanceError("Person Twin identity fingerprint mismatch")
    if person_record["consent_receipt_id"] != consent_receipt["consent_receipt_id"]:
        raise PersonTwinPrivacyProvenanceError("Person Twin consent receipt identity mismatch")
    if person_record["consent_receipt_hash"] != consent_receipt["receipt_hash"]:
        raise PersonTwinPrivacyProvenanceError("Person Twin consent receipt hash mismatch")
    if person_record["source_identity_hash"] != deterministic_source_identity_hash(source_record):
        raise PersonTwinPrivacyProvenanceError("Person Twin source identity mismatch")
    expected_privacy = infer_privacy_class(source_record, twin_id=str(identity["twin_id"]))
    if person_record["privacy_class"] != expected_privacy:
        raise PersonTwinPrivacyProvenanceError("Person Twin privacy class mismatch")

def filter_person_twin_records(
    records: Sequence[Mapping[str, Any]],
    identity: Mapping[str, Any],
    *,
    authorized_scopes: Iterable[str],
) -> list[dict[str, Any]]:
    try:
        validate_person_twin_identity(identity)
    except PersonTwinContractError as exc:
        raise PersonTwinPrivacyProvenanceError(str(exc)) from exc
    scopes = set(_canonical_scopes(authorized_scopes))
    validated: list[Mapping[str, Any]] = []
    for record in records:
        validate_person_twin_record(record)
        validated.append(record)
    candidates = [
        record for record in validated
        if record["tenant_id"] == identity["tenant_id"]
        and record["twin_id"] == identity["twin_id"]
        and record["identity_fingerprint"] == identity["identity_fingerprint"]
        and record["scope"] in scopes
    ]
    visible_source_ids = {str(record["source_record_id"]) for record in candidates}
    result: list[dict[str, Any]] = []
    for record in candidates:
        lineage = [str(record[field]) for field in ("supersedes", "duplicate_of") if record.get(field) is not None]
        if any(ref not in visible_source_ids for ref in lineage):
            continue
        result.append(copy.deepcopy(dict(record)))
    result.sort(key=lambda item: str(item["id"]))
    return result

def build_person_twin_export_bundle(
    records: Sequence[Mapping[str, Any]],
    identity: Mapping[str, Any],
    *,
    authorized_scopes: Iterable[str],
    requested_at: str,
    requested_by: Mapping[str, Any],
    include_tombstones: bool = True,
) -> dict[str, Any]:
    scopes = _canonical_scopes(authorized_scopes)
    visible = filter_person_twin_records(records, identity, authorized_scopes=scopes)
    p2_bundle = build_export_bundle(
        visible,
        tenant_id=str(identity["tenant_id"]),
        authorized_scopes=scopes,
        requested_at=requested_at,
        requested_by=requested_by,
        include_tombstones=include_tombstones,
    )
    person_manifest = [
        {
            "id": record["id"],
            "twin_id": record["twin_id"],
            "identity_fingerprint": record["identity_fingerprint"],
            "privacy_class": record["privacy_class"],
            "scope": record["scope"],
            "consent_receipt_id": record["consent_receipt_id"],
            "consent_receipt_hash": record["consent_receipt_hash"],
            "admission_session_id": record["admission_session_id"],
            "provenance_hash": record["provenance_hash"],
        }
        for record in visible
        if include_tombstones or not record["deleted"]
    ]
    body: dict[str, Any] = {
        "schema_version": EXPORT_ADAPTER_SCHEMA_VERSION,
        "read_only": True,
        "tenant_id": identity["tenant_id"],
        "twin_id": identity["twin_id"],
        "identity_fingerprint": identity["identity_fingerprint"],
        "authorized_scopes": scopes,
        "p2_export": p2_bundle,
        "person_provenance": person_manifest,
        "production_admission_status": NOT_PRODUCTION_ADMITTED,
        "execution_authority": "NONE",
        "can_execute": False,
    }
    body["bundle_hash"] = _canonical_hash(body)
    return body

def bind_person_twin_lifecycle_target(
    records: Sequence[Mapping[str, Any]],
    identity: Mapping[str, Any],
    *,
    record_id: str,
    scope: str,
) -> dict[str, Any]:
    rid = _non_empty(record_id, "record_id")
    requested_scope = _non_empty(scope, "scope")
    visible = filter_person_twin_records(records, identity, authorized_scopes=[requested_scope])
    matches = [record for record in visible if record["id"] == rid]
    if len(matches) != 1:
        raise PersonTwinPrivacyProvenanceError(
            "lifecycle target requires one exact twin-bound record_id and scope"
        )
    record = matches[0]
    body: dict[str, Any] = {
        "schema_version": LIFECYCLE_TARGET_SCHEMA_VERSION,
        "read_only": True,
        "tenant_id": identity["tenant_id"],
        "twin_id": identity["twin_id"],
        "identity_fingerprint": identity["identity_fingerprint"],
        "record_id": rid,
        "scope": requested_scope,
        "privacy_class": record["privacy_class"],
        "provenance_hash": record["provenance_hash"],
        "consent_receipt_id": record["consent_receipt_id"],
        "physical_delete": False,
        "production_admission_status": NOT_PRODUCTION_ADMITTED,
        "execution_authority": "NONE",
        "can_execute": False,
    }
    body["binding_hash"] = _canonical_hash(body)
    return body
