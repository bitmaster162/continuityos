from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping

IDENTITY_SCHEMA_VERSION = "continuityos.person-twin.identity/v1"
CONSENT_SCHEMA_VERSION = "continuityos.person-twin.source-consent-receipt/v1"
REVOCATION_ENTRY_SCHEMA_VERSION = "continuityos.person-twin.consent-revocation-entry/v1"
REVOCATION_LEDGER_SCHEMA_VERSION = "continuityos.person-twin.consent-revocation-ledger/v1"
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


def _normalized_delegated_admins(values: Iterable[Mapping[str, Any]]) -> list[dict[str, str]]:
    if isinstance(values, (str, bytes, Mapping)):
        raise PersonTwinContractError("delegated_admins must be a collection of principal bindings")
    normalized: list[dict[str, str]] = []
    seen: set[str] = set()
    for value in values:
        if not isinstance(value, Mapping) or set(value) != {"principal_id", "principal_kind"}:
            raise PersonTwinContractError(
                "delegated_admins entries must contain principal_id and principal_kind"
            )
        principal_id = _non_empty_string(value["principal_id"], "delegated_admins.principal_id")
        principal_kind = _non_empty_string(value["principal_kind"], "delegated_admins.principal_kind")
        if principal_kind not in AUTHORIZING_PRINCIPAL_KINDS:
            raise PersonTwinContractError(
                "delegated admin principal_kind must be HUMAN or ORGANIZATION"
            )
        if principal_id in seen:
            raise PersonTwinContractError("delegated_admin principal_id values must be unique")
        seen.add(principal_id)
        normalized.append({"principal_id": principal_id, "principal_kind": principal_kind})
    return sorted(normalized, key=lambda item: (item["principal_id"], item["principal_kind"]))


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
    delegated_admins: Iterable[Mapping[str, Any]] = (),
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
        "delegated_admins": _normalized_delegated_admins(delegated_admins),
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
    admins = _normalized_delegated_admins(identity["delegated_admins"])
    if recovery != list(identity["recovery_authorities"]):
        raise PersonTwinContractError("recovery_authorities must be canonical sorted unique strings")
    if admins != list(identity["delegated_admins"]):
        raise PersonTwinContractError("delegated_admins must be canonical sorted unique principal bindings")

    fingerprint = _validate_sha256(identity["identity_fingerprint"], "identity_fingerprint")
    body = dict(identity)
    body.pop("identity_fingerprint")
    if fingerprint != _canonical_hash(body):
        raise PersonTwinContractError("identity_fingerprint mismatch")


def _bound_principal_kind(identity: Mapping[str, Any], principal_id: str) -> str | None:
    if principal_id == identity["controller_id"]:
        return str(identity["controller_kind"])
    for admin in identity["delegated_admins"]:
        if admin["principal_id"] == principal_id:
            return str(admin["principal_kind"])
    return None


def _validate_authorizing_principal(
    identity: Mapping[str, Any],
    *,
    principal_id: Any,
    principal_kind: Any,
    field_prefix: str,
) -> tuple[str, str]:
    principal = _non_empty_string(principal_id, f"{field_prefix}_principal")
    kind = _non_empty_string(principal_kind, f"{field_prefix}_principal_kind")
    if kind not in AUTHORIZING_PRINCIPAL_KINDS:
        raise PersonTwinContractError("only HUMAN or ORGANIZATION principals may authorize consent state")
    bound_kind = _bound_principal_kind(identity, principal)
    if bound_kind is None:
        raise PersonTwinContractError("authorizing principal is not the controller or delegated admin")
    if kind != bound_kind:
        raise PersonTwinContractError("authorizing principal kind does not match identity binding")
    return principal, kind


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
    principal, principal_kind = _validate_authorizing_principal(
        identity,
        principal_id=authorizing_principal,
        principal_kind=authorizing_principal_kind,
        field_prefix="authorizing",
    )

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
        raise PersonTwinContractError(
            "revoked_at must be null in an immutable consent receipt; use the revocation ledger"
        )
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
        "revoked_at": None,
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

    _validate_authorizing_principal(
        identity,
        principal_id=receipt["authorizing_principal"],
        principal_kind=receipt["authorizing_principal_kind"],
        field_prefix="authorizing",
    )

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
        raise PersonTwinContractError(
            "revoked_at must be null in an immutable consent receipt; use the revocation ledger"
        )

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


def build_consent_revocation_entry(
    identity: Mapping[str, Any],
    receipt: Mapping[str, Any],
    *,
    revoking_principal: str,
    revoking_principal_kind: str,
    revoked_at: str,
    reason: str,
) -> dict[str, Any]:
    validate_person_twin_identity(identity)
    validate_source_consent_receipt(identity, receipt)
    principal, kind = _validate_authorizing_principal(
        identity,
        principal_id=revoking_principal,
        principal_kind=revoking_principal_kind,
        field_prefix="revoking",
    )
    revoked = _parse_time(revoked_at)
    if revoked < _parse_time(receipt["issued_at"]):
        raise PersonTwinContractError("revoked_at cannot be before issued_at")
    revocation_reason = _non_empty_string(reason, "reason")

    entry: dict[str, Any] = {
        "schema_version": REVOCATION_ENTRY_SCHEMA_VERSION,
        "consent_receipt_id": receipt["consent_receipt_id"],
        "receipt_hash": receipt["receipt_hash"],
        "twin_id": identity["twin_id"],
        "tenant_id": identity["tenant_id"],
        "identity_fingerprint": identity["identity_fingerprint"],
        "revoking_principal": principal,
        "revoking_principal_kind": kind,
        "revoked_at": revoked_at,
        "reason": revocation_reason,
    }
    entry["entry_hash"] = _canonical_hash(entry)
    validate_consent_revocation_entry(identity, receipt, entry)
    return entry


def validate_consent_revocation_entry(
    identity: Mapping[str, Any],
    receipt: Mapping[str, Any],
    entry: Mapping[str, Any],
) -> None:
    validate_person_twin_identity(identity)
    validate_source_consent_receipt(identity, receipt)
    required = {
        "schema_version",
        "consent_receipt_id",
        "receipt_hash",
        "twin_id",
        "tenant_id",
        "identity_fingerprint",
        "revoking_principal",
        "revoking_principal_kind",
        "revoked_at",
        "reason",
        "entry_hash",
    }
    if set(entry) != required:
        raise PersonTwinContractError("revocation entry fields do not match the v1 contract")
    if entry["schema_version"] != REVOCATION_ENTRY_SCHEMA_VERSION:
        raise PersonTwinContractError("unsupported revocation entry schema_version")
    if entry["consent_receipt_id"] != receipt["consent_receipt_id"]:
        raise PersonTwinContractError("revocation consent_receipt_id mismatch")
    if entry["receipt_hash"] != receipt["receipt_hash"]:
        raise PersonTwinContractError("revocation receipt_hash mismatch")
    if entry["twin_id"] != identity["twin_id"]:
        raise PersonTwinContractError("revocation twin_id mismatch")
    if entry["tenant_id"] != identity["tenant_id"]:
        raise PersonTwinContractError("revocation tenant_id mismatch")
    if entry["identity_fingerprint"] != identity["identity_fingerprint"]:
        raise PersonTwinContractError("revocation identity_fingerprint mismatch")
    _validate_authorizing_principal(
        identity,
        principal_id=entry["revoking_principal"],
        principal_kind=entry["revoking_principal_kind"],
        field_prefix="revoking",
    )
    if _parse_time(entry["revoked_at"]) < _parse_time(receipt["issued_at"]):
        raise PersonTwinContractError("revoked_at cannot be before issued_at")
    _non_empty_string(entry["reason"], "reason")
    entry_hash = _validate_sha256(entry["entry_hash"], "entry_hash")
    body = dict(entry)
    body.pop("entry_hash")
    if entry_hash != _canonical_hash(body):
        raise PersonTwinContractError("revocation entry_hash mismatch")


def build_consent_revocation_ledger(
    entries: Iterable[Mapping[str, Any]] = (),
) -> dict[str, Any]:
    if isinstance(entries, (str, bytes, Mapping)):
        raise PersonTwinContractError("revocation ledger entries must be a collection")
    normalized: list[dict[str, Any]] = []
    seen: set[str] = set()
    for entry in entries:
        if not isinstance(entry, Mapping):
            raise PersonTwinContractError("revocation ledger entries must be mappings")
        copied = dict(entry)
        receipt_id = _non_empty_string(copied.get("consent_receipt_id"), "consent_receipt_id")
        if receipt_id in seen:
            raise PersonTwinContractError("revocation ledger may contain only one entry per consent receipt")
        seen.add(receipt_id)
        normalized.append(copied)
    normalized.sort(key=lambda item: item["consent_receipt_id"])
    ledger: dict[str, Any] = {
        "schema_version": REVOCATION_LEDGER_SCHEMA_VERSION,
        "entries": normalized,
    }
    ledger["ledger_hash"] = _canonical_hash(ledger)
    validate_consent_revocation_ledger(ledger)
    return ledger


def validate_consent_revocation_ledger(ledger: Mapping[str, Any]) -> None:
    required = {"schema_version", "entries", "ledger_hash"}
    if set(ledger) != required:
        raise PersonTwinContractError("revocation ledger fields do not match the v1 contract")
    if ledger["schema_version"] != REVOCATION_LEDGER_SCHEMA_VERSION:
        raise PersonTwinContractError("unsupported revocation ledger schema_version")
    entries = ledger["entries"]
    if not isinstance(entries, list):
        raise PersonTwinContractError("revocation ledger entries must be a list")
    ids: list[str] = []
    for entry in entries:
        if not isinstance(entry, Mapping):
            raise PersonTwinContractError("revocation ledger entries must be mappings")
        ids.append(_non_empty_string(entry.get("consent_receipt_id"), "consent_receipt_id"))
        _validate_sha256(entry.get("entry_hash"), "entry_hash")
    if ids != sorted(ids) or len(ids) != len(set(ids)):
        raise PersonTwinContractError(
            "revocation ledger entries must be sorted and unique by consent_receipt_id"
        )
    ledger_hash = _validate_sha256(ledger["ledger_hash"], "ledger_hash")
    body = dict(ledger)
    body.pop("ledger_hash")
    if ledger_hash != _canonical_hash(body):
        raise PersonTwinContractError("revocation ledger_hash mismatch")


def evaluate_consent(
    identity: Mapping[str, Any] | None,
    receipt: Mapping[str, Any] | None,
    *,
    revocation_ledger: Mapping[str, Any] | None,
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

    if revocation_ledger is None:
        return {"decision": "DENY", "reason": "MISSING_REVOCATION_LEDGER"}
    try:
        validate_consent_revocation_ledger(revocation_ledger)
    except PersonTwinContractError:
        return {"decision": "DENY", "reason": "INVALID_REVOCATION_LEDGER"}

    try:
        when = _parse_time(at)
    except PersonTwinContractError:
        return {"decision": "DENY", "reason": "INVALID_EVALUATION_TIME"}
    issued = _parse_time(receipt["issued_at"])
    if when < issued:
        return {"decision": "DENY", "reason": "CONSENT_NOT_YET_VALID"}

    relevant = [
        entry
        for entry in revocation_ledger["entries"]
        if entry["consent_receipt_id"] == receipt["consent_receipt_id"]
    ]
    if relevant:
        entry = relevant[0]
        try:
            validate_consent_revocation_entry(identity, receipt, entry)
        except PersonTwinContractError:
            return {"decision": "DENY", "reason": "INVALID_REVOCATION_LEDGER"}
        if _parse_time(entry["revoked_at"]) <= when:
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
        "revocation_ledger_hash": revocation_ledger["ledger_hash"],
        "production_admission_status": NOT_PRODUCTION_ADMITTED,
    }
