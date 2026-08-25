from __future__ import annotations

import hashlib

import pytest

import continuityos.person_twin_admission_contracts as c


CREATED = "2026-08-25T00:00:00Z"
AT = "2026-08-25T01:00:00Z"
EXPIRES = "2026-08-26T00:00:00Z"
SOURCE_HASH = hashlib.sha256(b"synthetic-source-identity").hexdigest()


def identity(**overrides):
    kwargs = {
        "tenant_id": "tenant_self",
        "subject_id": "subject_self",
        "owner_id": "principal_owner",
        "controller_id": "principal_owner",
        "controller_kind": "HUMAN",
        "ownership_epoch": 1,
        "created_at": CREATED,
        "recovery_authorities": ["principal_recovery"],
        "delegated_admins": ["principal_admin"],
    }
    kwargs.update(overrides)
    return c.build_person_twin_identity(**kwargs)


def consent(ident=None, **overrides):
    ident = ident or identity()
    kwargs = {
        "authorizing_principal": "principal_owner",
        "authorizing_principal_kind": "HUMAN",
        "source_system": "synthetic_history",
        "source_identity_hash": SOURCE_HASH,
        "allowed_object_types": ["history_item", "note"],
        "allowed_scopes": ["PERSON_PRIVATE"],
        "purpose": "self_memory_import",
        "issued_at": CREATED,
        "expires_at": EXPIRES,
        "revoked_at": None,
        "source_read_authority": True,
        "memory_admission_authority": True,
        "policy_version": "p3-r0-v2.1",
    }
    kwargs.update(overrides)
    return c.build_source_consent_receipt(ident, **kwargs)


def test_identity_is_deterministic_and_not_production_admitted():
    first = identity()
    second = identity()
    assert first == second
    assert first["twin_class"] == "PERSON"
    assert first["production_admission_status"] == "NOT_PRODUCTION_ADMITTED"
    assert first["twin_id"].startswith("person_twin_")
    c.validate_person_twin_identity(first)


def test_twin_id_is_stable_across_controller_and_ownership_epoch_changes():
    first = identity()
    second = identity(
        owner_id="principal_new_owner",
        controller_id="principal_new_controller",
        ownership_epoch=2,
    )
    assert first["twin_id"] == second["twin_id"]
    assert first["identity_fingerprint"] != second["identity_fingerprint"]


def test_identity_requires_exact_deterministic_twin_id():
    with pytest.raises(c.PersonTwinContractError, match="twin_id"):
        identity(twin_id="person_twin_wrong")


def test_identity_fingerprint_detects_tampering():
    value = identity()
    value["controller_id"] = "attacker"
    with pytest.raises(c.PersonTwinContractError, match="identity_fingerprint"):
        c.validate_person_twin_identity(value)


def test_identity_cannot_claim_production_admission():
    value = identity()
    value["production_admission_status"] = "PRODUCTION_ADMITTED"
    with pytest.raises(c.PersonTwinContractError, match="production admission"):
        c.validate_person_twin_identity(value)


def test_identity_requires_supported_controller_kind():
    with pytest.raises(c.PersonTwinContractError, match="controller_kind"):
        identity(controller_kind="AGENT")


def test_consent_receipt_is_deterministic_and_identity_bound():
    ident = identity()
    first = consent(ident)
    second = consent(ident)
    assert first == second
    assert first["twin_id"] == ident["twin_id"]
    assert first["tenant_id"] == ident["tenant_id"]
    assert first["identity_fingerprint"] == ident["identity_fingerprint"]
    assert first["consent_receipt_id"].startswith("consent_")
    c.validate_source_consent_receipt(ident, first)


def test_consent_canonicalizes_object_types_and_scopes():
    receipt = consent(
        allowed_object_types=["note", "history_item", "note"],
        allowed_scopes=["PERSON_PRIVATE", "PERSON_PRIVATE"],
    )
    assert receipt["allowed_object_types"] == ["history_item", "note"]
    assert receipt["allowed_scopes"] == ["PERSON_PRIVATE"]


def test_missing_identity_fails_closed():
    decision = c.evaluate_consent(
        None,
        None,
        at=AT,
        requested_object_type="note",
        requested_scope="PERSON_PRIVATE",
        purpose="self_memory_import",
    )
    assert decision == {"decision": "DENY", "reason": "MISSING_IDENTITY"}


def test_oauth_exists_without_consent_does_not_authorize():
    decision = c.evaluate_consent(
        identity(),
        None,
        at=AT,
        requested_object_type="note",
        requested_scope="PERSON_PRIVATE",
        purpose="self_memory_import",
        oauth_present=True,
    )
    assert decision == {"decision": "DENY", "reason": "MISSING_CONSENT"}


def test_consent_for_different_twin_fails_closed():
    first = identity()
    receipt = consent(first)
    other = identity(tenant_id="tenant_self", subject_id="other_subject")
    decision = c.evaluate_consent(
        other,
        receipt,
        at=AT,
        requested_object_type="note",
        requested_scope="PERSON_PRIVATE",
        purpose="self_memory_import",
    )
    assert decision == {"decision": "DENY", "reason": "INVALID_CONSENT"}


def test_tenant_mismatch_fails_closed():
    ident = identity()
    receipt = consent(ident)
    receipt["tenant_id"] = "tenant_other"
    decision = c.evaluate_consent(
        ident,
        receipt,
        at=AT,
        requested_object_type="note",
        requested_scope="PERSON_PRIVATE",
        purpose="self_memory_import",
    )
    assert decision == {"decision": "DENY", "reason": "INVALID_CONSENT"}


def test_controller_mismatch_cannot_issue_consent():
    ident = identity()
    with pytest.raises(c.PersonTwinContractError, match="controller or delegated admin"):
        consent(ident, authorizing_principal="principal_stranger")


def test_delegated_admin_can_issue_consent_but_recovery_authority_cannot():
    ident = identity()
    admin_receipt = consent(ident, authorizing_principal="principal_admin")
    c.validate_source_consent_receipt(ident, admin_receipt)
    with pytest.raises(c.PersonTwinContractError, match="controller or delegated admin"):
        consent(ident, authorizing_principal="principal_recovery")


def test_agent_cannot_manufacture_owner_consent():
    with pytest.raises(c.PersonTwinContractError, match="HUMAN or ORGANIZATION"):
        consent(authorizing_principal_kind="AGENT")


def test_altered_receipt_hash_fails_closed():
    ident = identity()
    receipt = consent(ident)
    receipt["purpose"] = "different-purpose"
    decision = c.evaluate_consent(
        ident,
        receipt,
        at=AT,
        requested_object_type="note",
        requested_scope="PERSON_PRIVATE",
        purpose="different-purpose",
    )
    assert decision == {"decision": "DENY", "reason": "INVALID_CONSENT"}


def test_altered_receipt_id_fails_closed_even_with_rehashed_receipt():
    ident = identity()
    receipt = consent(ident)
    receipt["consent_receipt_id"] = "consent_" + ("0" * 32)
    body = dict(receipt)
    body.pop("receipt_hash")
    receipt["receipt_hash"] = c._canonical_hash(body)
    decision = c.evaluate_consent(
        ident,
        receipt,
        at=AT,
        requested_object_type="note",
        requested_scope="PERSON_PRIVATE",
        purpose="self_memory_import",
    )
    assert decision == {"decision": "DENY", "reason": "INVALID_CONSENT"}


def test_expired_consent_fails_closed():
    ident = identity()
    receipt = consent(ident, expires_at="2026-08-25T00:30:00Z")
    decision = c.evaluate_consent(
        ident,
        receipt,
        at=AT,
        requested_object_type="note",
        requested_scope="PERSON_PRIVATE",
        purpose="self_memory_import",
    )
    assert decision == {"decision": "DENY", "reason": "CONSENT_EXPIRED"}


def test_revoked_consent_fails_closed():
    ident = identity()
    receipt = consent(ident, revoked_at="2026-08-25T00:30:00Z")
    decision = c.evaluate_consent(
        ident,
        receipt,
        at=AT,
        requested_object_type="note",
        requested_scope="PERSON_PRIVATE",
        purpose="self_memory_import",
    )
    assert decision == {"decision": "DENY", "reason": "CONSENT_REVOKED"}


def test_future_revocation_does_not_revoke_early():
    ident = identity()
    receipt = consent(ident, revoked_at="2026-08-25T02:00:00Z")
    decision = c.evaluate_consent(
        ident,
        receipt,
        at=AT,
        requested_object_type="note",
        requested_scope="PERSON_PRIVATE",
        purpose="self_memory_import",
    )
    assert decision["decision"] == "ALLOW"


def test_scope_widening_is_not_implicit():
    ident = identity()
    receipt = consent(ident, allowed_scopes=["PERSON_PRIVATE"])
    decision = c.evaluate_consent(
        ident,
        receipt,
        at=AT,
        requested_object_type="note",
        requested_scope="PERSON_SHARED",
        purpose="self_memory_import",
    )
    assert decision == {"decision": "DENY", "reason": "SCOPE_NOT_CONSENTED"}


def test_wildcard_scopes_are_rejected():
    with pytest.raises(c.PersonTwinContractError, match="wildcard"):
        consent(allowed_scopes=["PERSON_*"])


def test_object_type_must_be_explicitly_consented():
    ident = identity()
    receipt = consent(ident)
    decision = c.evaluate_consent(
        ident,
        receipt,
        at=AT,
        requested_object_type="credential",
        requested_scope="PERSON_PRIVATE",
        purpose="self_memory_import",
    )
    assert decision == {"decision": "DENY", "reason": "OBJECT_TYPE_NOT_CONSENTED"}


def test_purpose_mismatch_fails_closed():
    ident = identity()
    receipt = consent(ident)
    decision = c.evaluate_consent(
        ident,
        receipt,
        at=AT,
        requested_object_type="note",
        requested_scope="PERSON_PRIVATE",
        purpose="analytics",
    )
    assert decision == {"decision": "DENY", "reason": "PURPOSE_MISMATCH"}


def test_source_read_and_memory_admission_authorities_are_separate():
    ident = identity()
    read_only = consent(
        ident,
        source_read_authority=True,
        memory_admission_authority=False,
    )
    read = c.evaluate_consent(
        ident,
        read_only,
        at=AT,
        requested_object_type="note",
        requested_scope="PERSON_PRIVATE",
        purpose="self_memory_import",
        require_source_read=True,
        require_memory_admission=False,
    )
    admit = c.evaluate_consent(
        ident,
        read_only,
        at=AT,
        requested_object_type="note",
        requested_scope="PERSON_PRIVATE",
        purpose="self_memory_import",
        require_source_read=True,
        require_memory_admission=True,
    )
    assert read["decision"] == "ALLOW"
    assert admit == {"decision": "DENY", "reason": "MEMORY_ADMISSION_NOT_AUTHORIZED"}


def test_memory_admission_does_not_imply_source_read():
    ident = identity()
    admission_only = consent(
        ident,
        source_read_authority=False,
        memory_admission_authority=True,
    )
    decision = c.evaluate_consent(
        ident,
        admission_only,
        at=AT,
        requested_object_type="note",
        requested_scope="PERSON_PRIVATE",
        purpose="self_memory_import",
        require_source_read=True,
        require_memory_admission=True,
    )
    assert decision == {"decision": "DENY", "reason": "SOURCE_READ_NOT_AUTHORIZED"}


def test_valid_consent_returns_only_non_effectful_evidence():
    ident = identity()
    receipt = consent(ident)
    decision = c.evaluate_consent(
        ident,
        receipt,
        at=AT,
        requested_object_type="note",
        requested_scope="PERSON_PRIVATE",
        purpose="self_memory_import",
        require_source_read=True,
        require_memory_admission=True,
        oauth_present=True,
    )
    assert decision["decision"] == "ALLOW"
    assert decision["reason"] == "CONSENT_VALID"
    assert decision["twin_id"] == ident["twin_id"]
    assert decision["consent_receipt_id"] == receipt["consent_receipt_id"]
    assert decision["production_admission_status"] == "NOT_PRODUCTION_ADMITTED"
    assert "can_execute" not in decision
    assert "current" not in decision
