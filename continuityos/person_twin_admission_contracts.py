from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping

IDENTITY_SCHEMA_VERSION = "continuityos.person-twin.identity/v1"
CONSENT_SCHEMA_VERSION = "continuityos.person-twin.source-consent-receipt/v1"
TWIN_CLASS = "PERSON"
CONTROLLER_KINDS = {"HUMAN", "ORGANIZATION"}
AUTHORIZING_PRINCIPAL_KINDS = {"HUMAN", "ORGANIZATION"}
NOT_PRODUCTION_ADMITTED = "NOT_PRODUCTION_ADMITTED"


class PersonTwinContractError(ValueError):
    pass


def _canonical_hash(payload: Mapping[str, Any]) -> str:
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _parse_time(value: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise PersonTwinContractError("timestamp must be a non-empty string")
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise PersonTwinContractError(f"invalid timestamp: {value}") from exc
    if parsed.tzinfo is None:
        raise PersonTwinContractError(f"timestamp must include timezone: {value}")
    return parsed.astimezone(timezone.utc)


def _non_empty_string(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise PersonTwinContractError(f"{field} must be a non-empty string")
    return value


def _normalized_strings(values: Iterable[str], field: str, *, allow_empty: bool = False) -> list[str]:
    if isinstance(values, (str, bytes)):
        raise PersonTwinContractError(f"{field} must be a collection of strings")
    normalized: list[str] = []
    for value in values:
        normalized.append(_non_empty_string(value, field))
    result = sorted(set(normalized))
    if not allow_empty and not result:
        raise PersonTwinContractError(f"{field} must not be empty")
    return result


def _validate_sha256(value: Any, field: str) -> str:
    text = _non_empty_string(value, field)
    if len(text) != 64:
        raise PersonTwinContractError(f"{field} must be a lowercase sha256 hex digest")
    if any(ch not in "0123456789abcdef" for ch in text):
        raise PersonTwinContractError(f"{field} must be a lowercase sha256 hex digest")
    return text


def deterministic_person_twin_id(*, tenant_id: str, subject_id: str) -> str:
    tenant = _non_empty_string(tenant_id, "tenant_id")
    subject = _non_empty_string(subject_id, "subject_id")
    digest = _canonical_hash({"tenant_id": tenant, "subject_id": subject, "twin_class": TWIN_CLASS})
    return f"person_twin_{digest[:32]}"


def build_person_twin_identity(
    *,
    tenant_id: str,
    subject_id: str,
    owner_id: str,
    controller_id: str,
    controller_kind: str,
    ownership_epoch: int,
    created_at: str,
    twin_id: str | None = None,
    recovery_authorities: Iterable[str] = (),
    delegated_admins: Iterable[str] = (),
) -> dict[str, Any]:
    tenant = _non_empty_string(tenant_id, "tenant_id")
    subject = _non_empty_string(subject_id, "subject_id")
    owner = _non_empty_string(owner_id, "owner_id")
    controller = _non_empty_string(controller_id, "controller_id")
    kind = _non_empty_string(controller_kind, "controller_kind")
    if kind not in CONTROLLER_KINDS:
        raise PersonTwinContractError("controller_kind must be HUMAN or ORGANIZATION")
    if not isinstance(ownership_epoch, int) or isinstance(ownership_epoch, bool) or ownership_epoch < 1:
        raise PersonTwinContractError("ownership_epoch must be a positive integer")
    _parse_time(created_at)

    expected_twin_id = deterministic_person_twin_id(tenant_id=tenant, subject_id=subject)
    chosen_twin_id = expected_twin_id if twin_id is None else _non_empty_string(twin_id, "twin_id")
    if chosen_twin_id != expected_twin_id:
        raise PersonTwinContractError("twin_id does not match deterministic Person Twin identity")

    body: dict[str, Any] = {
        "schema_version": IDENTITY_SCHEMA_VERSION,
        "twin_id": chosen_twin_id,
        "twin_class": TWIN_CLASS,
        "tenant_id": tenant,
        "subject_id": subject,
        "owner_id": owner,
        "controller_id": controller,
        "controller_kind": kind,
        "ownership_epoch": ownership_epoch,
        "created_at": created_at,
        "recovery_authorities": _normalized_strings(
            recovery_authorities, "recovery_authorities", allow_empty=True
        ),
        "delegated_admins": _normalized_strings(
            delegated_admins, "delegated_admins", allow_empty=True
        ),
        "production_admission_status": NOT_PRODUCTION_ADMITTED,
    }
    body["identity_fingerprint"] = _canonical_hash(body)
    validate_person_twin_identity(body)
    return body


def validate_person_twin_identity(identity: Mapping[str, Any]) -> None:
    required = {
        "schema_version",
        "twin_id",
        "twin_class",
        "tenant_id",
        "subject_id",
        "owner_id",
        "controller_id",
        "controller_kind",
        "ownership_epoch",
        "created_at",
        "recovery_authorities",
        "delegated_admins",
        "production_admission_status",
        "identity_fingerprint",
    }
    if set(identity) != required:
        raise PersonTwinContractError("identity fields do not match the v1 contract")
    if identity["schema_version"] != IDENTITY_SCHEMA_VERSION:
        raise PersonTwinContractError("unsupported identity schema_version")
    if identity["twin_class"] != TWIN_CLASS:
        raise PersonTwinContractError("twin_class must be PERSON")

    tenant = _non_empty_string(identity["tenant_id"], "tenant_id")
    subject = _non_empty_string(identity["subject_id"], "subject_id")
    expected_twin_id = deterministic_person_twin_id(tenant_id=tenant, subject_id=subject)
    if identity["twin_id"] != expected_twin_id:
        raise PersonTwinContractError("twin_id does not match deterministic Person Twin identity")

    _non_empty_string(identity["owner_id"], "owner_id")
    _non_empty_string(identity["controller_id"], "controller_id")
    if identity["controller_kind"] not in CONTROLLER_KINDS:
        raise PersonTwinContractError("controller_kind must be HUMAN or ORGANIZATION")

    epoch = identity["ownership_epoch"]
    if not isinstance(epoch, int) or isinstance(epoch, bool) or epoch < 1:
        raise PersonTwinContractError("ownership_epoch must be a positive integer")
    _parse_time(identity["created_at"])

    if identity["production_admission_status"] != NOT_PRODUCTION_ADMITTED:
        raise PersonTwinContractError("R1 identity cannot claim production admission")

    recovery = _normalized_strings(identity["recovery_authorities"], "recovery_authorities", allow_empty=True)
    admins = _normalized_strings(identity["delegated_admins"], "delegated_admins", allow_empty=True)
    if recovery != list(identity["recovery_authorities"]):
        raise PersonTwinContractError("recovery_authorities must be canonical sorted unique strings")
    if admins != list(identity["delegated_admins"]):
        raise PersonTwinContractError("delegated_admins must be canonical sorted unique strings")

    fingerprint = _validate_sha256(identity["identity_fingerprint"], "identity_fingerprint")
    body = dict(identity)
    body.pop("identity_fingerprint")
    if fingerprint != _canonical_hash(body):
        raise PersonTwinContractError("identity_fingerprint mismatch")


def _consent_id_body(payload: Mapping[str, Any]) -> dict[str, Any]:
    keys = (
        "schema_version",
        "twin_id",
        "tenant_id",
        "identity_fingerprint",
        "authorizing_principal",
        "authorizing_principal_kind",
        "source_system",
        "source_identity_hash",
        "allowed_object_types",
        "allowed_scopes",
        "purpose",
        "issued_at",
        "expires_at",
        "revoked_at",
        "source_read_authority",
        "memory_admission_authority",
        "policy_version",
    )
    return {key: payload[key] for key in keys}


def _authorized_consent_principals(identity: Mapping[str, Any]) -> set[str]:
    return {
        str(identity["controller_id"]),
        *[str(value) for value in identity["delegated_admins"]],
    }


def build_source_consent_receipt(
    identity: Mapping[str, Any],
    *,
    authorizing_principal: str,
    authorizing_principal_kind: str,
    source_system: str,
    source_identity_hash: str,
    allowed_object_types: Iterable[str],
    allowed_scopes: Iterable[str],
    purpose: str,
    issued_at: str,
    expires_at: str | None,
    revoked_at: str | None,
    source_read_authority: bool,
    memory_admission_authority: bool,
    policy_version: str,
) -> dict[str, Any]:
    validate_person_twin_identity(identity)
    principal = _non_empty_string(authorizing_principal, "authorizing_principal")
    principal_kind = _non_empty_string(authorizing_principal_kind, "authorizing_principal_kind")
    if principal_kind not in AUTHORIZING_PRINCIPAL_KINDS:
        raise PersonTwinContractError("only HUMAN or ORGANIZATION principals may issue consent")
    if principal not in _authorized_consent_principals(identity):
        raise PersonTwinContractError("authorizing principal is not the controller or delegated admin")

    _non_empty_string(source_system, "source_system")
    _validate_sha256(source_identity_hash, "source_identity_hash")
    object_types = _normalized_strings(allowed_object_types, "allowed_object_types")
    scopes = _normalized_strings(allowed_scopes, "allowed_scopes")
    if any("*" in scope for scope in scopes):
        raise PersonTwinContractError("wildcard consent scopes are not allowed")
    _non_empty_string(purpose, "purpose")
    _non_empty_string(policy_version, "policy_version")

    issued = _parse_time(issued_at)
    if expires_at is not None:
        expires = _parse_time(expires_at)
        if expires <= issued:
            raise PersonTwinContractError("expires_at must be after issued_at")
    if revoked_at is not None:
        revoked = _parse_time(revoked_at)
        if revoked < issued:
            raise PersonTwinContractError("revoked_at cannot be before issued_at")
    if not isinstance(source_read_authority, bool):
        raise PersonTwinContractError("source_read_authority must be boolean")
    if not isinstance(memory_admission_authority, bool):
        raise PersonTwinContractError("memory_admission_authority must be boolean")

    receipt: dict[str, Any] = {
        "schema_version": CONSENT_SCHEMA_VERSION,
        "twin_id": identity["twin_id"],
        "tenant_id": identity["tenant_id"],
        "identity_fingerprint": identity["identity_fingerprint"],
        "authorizing_principal": principal,
        "authorizing_principal_kind": principal_kind,
        "source_system": source_system,
        "source_identity_hash": source_identity_hash,
        "allowed_object_types": object_types,
        "allowed_scopes": scopes,
        "purpose": purpose,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "revoked_at": revoked_at,
        "source_read_authority": source_read_authority,
        "memory_admission_authority": memory_admission_authority,
        "policy_version": policy_version,
    }
    receipt["consent_receipt_id"] = f"consent_{_canonical_hash(_consent_id_body(receipt))[:32]}"
    receipt["receipt_hash"] = _canonical_hash(receipt)
    validate_source_consent_receipt(identity, receipt)
    return receipt


def validate_source_consent_receipt(identity: Mapping[str, Any], receipt: Mapping[str, Any]) -> None:
    validate_person_twin_identity(identity)
    required = {
        "schema_version",
        "consent_receipt_id",
        "twin_id",
        "tenant_id",
        "identity_fingerprint",
        "authorizing_principal",
        "authorizing_principal_kind",
        "source_system",
        "source_identity_hash",
        "allowed_object_types",
        "allowed_scopes",
        "purpose",
        "issued_at",
        "expires_at",
        "revoked_at",
        "source_read_authority",
        "memory_admission_authority",
        "policy_version",
        "receipt_hash",
    }
    if set(receipt) != required:
        raise PersonTwinContractError("consent receipt fields do not match the v1 contract")
    if receipt["schema_version"] != CONSENT_SCHEMA_VERSION:
        raise PersonTwinContractError("unsupported consent schema_version")
    if receipt["twin_id"] != identity["twin_id"]:
        raise PersonTwinContractError("consent twin_id mismatch")
    if receipt["tenant_id"] != identity["tenant_id"]:
        raise PersonTwinContractError("consent tenant_id mismatch")
    if receipt["identity_fingerprint"] != identity["identity_fingerprint"]:
        raise PersonTwinContractError("consent identity_fingerprint mismatch")

    principal = _non_empty_string(receipt["authorizing_principal"], "authorizing_principal")
    if receipt["authorizing_principal_kind"] not in AUTHORIZING_PRINCIPAL_KINDS:
        raise PersonTwinContractError("only HUMAN or ORGANIZATION principals may issue consent")
    if principal not in _authorized_consent_principals(identity):
        raise PersonTwinContractError("authorizing principal is not the controller or delegated admin")

    _non_empty_string(receipt["source_system"], "source_system")
    _validate_sha256(receipt["source_identity_hash"], "source_identity_hash")

    object_types = _normalized_strings(receipt["allowed_object_types"], "allowed_object_types")
    scopes = _normalized_strings(receipt["allowed_scopes"], "allowed_scopes")
    if object_types != list(receipt["allowed_object_types"]):
        raise PersonTwinContractError("allowed_object_types must be canonical sorted unique strings")
    if scopes != list(receipt["allowed_scopes"]):
        raise PersonTwinContractError("allowed_scopes must be canonical sorted unique strings")
    if any("*" in scope for scope in scopes):
        raise PersonTwinContractError("wildcard consent scopes are not allowed")

    _non_empty_string(receipt["purpose"], "purpose")
    _non_empty_string(receipt["policy_version"], "policy_version")
    issued = _parse_time(receipt["issued_at"])
    if receipt["expires_at"] is not None:
        expires = _parse_time(receipt["expires_at"])
        if expires <= issued:
            raise PersonTwinContractError("expires_at must be after issued_at")
    if receipt["revoked_at"] is not None:
        revoked = _parse_time(receipt["revoked_at"])
        if revoked < issued:
            raise PersonTwinContractError("revoked_at cannot be before issued_at")

    if not isinstance(receipt["source_read_authority"], bool):
        raise PersonTwinContractError("source_read_authority must be boolean")
    if not isinstance(receipt["memory_admission_authority"], bool):
        raise PersonTwinContractError("memory_admission_authority must be boolean")

    expected_id = f"consent_{_canonical_hash(_consent_id_body(receipt))[:32]}"
    if receipt["consent_receipt_id"] != expected_id:
        raise PersonTwinContractError("consent_receipt_id mismatch")

    receipt_hash = _validate_sha256(receipt["receipt_hash"], "receipt_hash")
    body = dict(receipt)
    body.pop("receipt_hash")
    if receipt_hash != _canonical_hash(body):
        raise PersonTwinContractError("receipt_hash mismatch")


def evaluate_consent(
    identity: Mapping[str, Any] | None,
    receipt: Mapping[str, Any] | None,
    *,
    at: str,
    requested_object_type: str,
    requested_scope: str,
    purpose: str,
    require_source_read: bool = True,
    require_memory_admission: bool = False,
    oauth_present: bool = False,
) -> dict[str, Any]:
    # oauth_present is deliberately non-authoritative: OAUTH_EXISTS != CONSENT_EXISTS.
    del oauth_present

    if identity is None:
        return {"decision": "DENY", "reason": "MISSING_IDENTITY"}
    try:
        validate_person_twin_identity(identity)
    except PersonTwinContractError:
        return {"decision": "DENY", "reason": "INVALID_IDENTITY"}

    if receipt is None:
        return {"decision": "DENY", "reason": "MISSING_CONSENT"}
    try:
        validate_source_consent_receipt(identity, receipt)
    except PersonTwinContractError:
        return {"decision": "DENY", "reason": "INVALID_CONSENT"}

    when = _parse_time(at)
    if receipt["revoked_at"] is not None and _parse_time(receipt["revoked_at"]) <= when:
        return {"decision": "DENY", "reason": "CONSENT_REVOKED"}
    if receipt["expires_at"] is not None and _parse_time(receipt["expires_at"]) <= when:
        return {"decision": "DENY", "reason": "CONSENT_EXPIRED"}

    if requested_object_type not in receipt["allowed_object_types"]:
        return {"decision": "DENY", "reason": "OBJECT_TYPE_NOT_CONSENTED"}
    if requested_scope not in receipt["allowed_scopes"]:
        return {"decision": "DENY", "reason": "SCOPE_NOT_CONSENTED"}
    if purpose != receipt["purpose"]:
        return {"decision": "DENY", "reason": "PURPOSE_MISMATCH"}
    if require_source_read and receipt["source_read_authority"] is not True:
        return {"decision": "DENY", "reason": "SOURCE_READ_NOT_AUTHORIZED"}
    if require_memory_admission and receipt["memory_admission_authority"] is not True:
        return {"decision": "DENY", "reason": "MEMORY_ADMISSION_NOT_AUTHORIZED"}

    return {
        "decision": "ALLOW",
        "reason": "CONSENT_VALID",
        "twin_id": identity["twin_id"],
        "tenant_id": identity["tenant_id"],
        "consent_receipt_id": receipt["consent_receipt_id"],
        "identity_fingerprint": identity["identity_fingerprint"],
        "receipt_hash": receipt["receipt_hash"],
        "production_admission_status": NOT_PRODUCTION_ADMITTED,
    }
