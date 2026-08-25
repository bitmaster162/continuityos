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
        "delegated_admins": [
            {"principal_id": "principal_admin", "principal_kind": "HUMAN"},
        ],
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


def empty_ledger():
    return c.build_consent_revocation_ledger()


def evaluate(ident, receipt, **overrides):
    kwargs = {
        "revocation_ledger": empty_ledger(),
        "at": AT,
        "requested_object_type": "note",
        "requested_scope": "PERSON_PRIVATE",
        "purpose": "self_memory_import",
    }
    kwargs.update(overrides)
    return c.evaluate_consent(ident, receipt, **kwargs)


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


def test_delegated_admin_kind_is_bound_in_identity():
    ident = identity()
    assert ident["delegated_admins"] == [
        {"principal_id": "principal_admin", "principal_kind": "HUMAN"}
    ]


def test_agent_cannot_be_delegated_consent_admin():
    with pytest.raises(c.PersonTwinContractError, match="HUMAN or ORGANIZATION"):
        identity(
            delegated_admins=[
                {"principal_id": "principal_agent", "principal_kind": "AGENT"},
            ]
        )


def test_consent_receipt_is_deterministic_and_identity_bound():
    ident = identity()
    first = consent(ident)
    second = consent(ident)
    assert first == second
    assert first["twin_id"] == ident["twin_id"]
    assert first["tenant_id"] == ident["tenant_id"]
    assert first["identity_fingerprint"] == ident["identity_fingerprint"]
    assert first["consent_receipt_id"].startswith("consent_")
    assert first["revoked_at"] is None
    c.validate_source_consent_receipt(ident, first)


def test_consent_canonicalizes_object_types_and_scopes():
    receipt = consent(
        allowed_object_types=["note", "history_item", "note"],
        allowed_scopes=["PERSON_PRIVATE", "PERSON_PRIVATE"],
    )
    assert receipt["allowed_object_types"] == ["history_item", "note"]
    assert receipt["allowed_scopes"] == ["PERSON_PRIVATE"]


def test_receipt_cannot_embed_revocation_state():
    with pytest.raises(c.PersonTwinContractError, match="revocation ledger"):
        consent(revoked_at="2026-08-25T00:30:00Z")


def test_missing_identity_fails_closed():
    decision = c.evaluate_consent(
        None,
        None,
        revocation_ledger=empty_ledger(),
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
        revocation_ledger=empty_ledger(),
        at=AT,
        requested_object_type="note",
        requested_scope="PERSON_PRIVATE",
        purpose="self_memory_import",
        oauth_present=True,
    )
    assert decision == {"decision": "DENY", "reason": "MISSING_CONSENT"}


def test_missing_revocation_ledger_fails_closed():
    ident = identity()
    receipt = consent(ident)
    decision = c.evaluate_consent(
        ident,
        receipt,
        revocation_ledger=None,
        at=AT,
        requested_object_type="note",
        requested_scope="PERSON_PRIVATE",
        purpose="self_memory_import",
    )
    assert decision == {"decision": "DENY", "reason": "MISSING_REVOCATION_LEDGER"}


def test_consent_for_different_twin_fails_closed():
    first = identity()
    receipt = consent(first)
    other = identity(subject_id="other_subject")
    assert evaluate(other, receipt) == {"decision": "DENY", "reason": "INVALID_CONSENT"}


def test_tenant_mismatch_fails_closed():
    ident = identity()
    receipt = consent(ident)
    receipt["tenant_id"] = "tenant_other"
    assert evaluate(ident, receipt) == {"decision": "DENY", "reason": "INVALID_CONSENT"}


def test_controller_mismatch_cannot_issue_consent():
    ident = identity()
    with pytest.raises(c.PersonTwinContractError, match="controller or delegated admin"):
        consent(ident, authorizing_principal="principal_stranger")


def test_controller_kind_must_match_identity_binding():
    ident = identity()
    with pytest.raises(c.PersonTwinContractError, match="kind does not match"):
        consent(ident, authorizing_principal_kind="ORGANIZATION")


def test_delegated_admin_can_issue_consent_with_exact_bound_kind():
    ident = identity()
    admin_receipt = consent(
        ident,
        authorizing_principal="principal_admin",
        authorizing_principal_kind="HUMAN",
    )
    c.validate_source_consent_receipt(ident, admin_receipt)


def test_delegated_admin_kind_spoof_fails_closed():
    ident = identity(
        delegated_admins=[
            {"principal_id": "principal_admin", "principal_kind": "ORGANIZATION"},
        ]
    )
    with pytest.raises(c.PersonTwinContractError, match="kind does not match"):
        consent(
            ident,
            authorizing_principal="principal_admin",
            authorizing_principal_kind="HUMAN",
        )


def test_recovery_authority_cannot_issue_consent():
    ident = identity()
    with pytest.raises(c.PersonTwinContractError, match="controller or delegated admin"):
        consent(ident, authorizing_principal="principal_recovery")


def test_agent_cannot_manufacture_owner_consent():
    with pytest.raises(c.PersonTwinContractError, match="HUMAN or ORGANIZATION"):
        consent(authorizing_principal_kind="AGENT")


def test_altered_receipt_hash_fails_closed():
    ident = identity()
    receipt = consent(ident)
    receipt["purpose"] = "different-purpose"
    assert evaluate(ident, receipt, purpose="different-purpose") == {
        "decision": "DENY",
        "reason": "INVALID_CONSENT",
    }


def test_consent_is_not_valid_before_issued_at():
    ident = identity()
    receipt = consent(ident, issued_at="2026-08-25T02:00:00Z", expires_at="2026-08-26T00:00:00Z")
    assert evaluate(ident, receipt, at=AT) == {
        "decision": "DENY",
        "reason": "CONSENT_NOT_YET_VALID",
    }


def test_expired_consent_fails_closed():
    ident = identity()
    receipt = consent(ident, expires_at="2026-08-25T00:30:00Z")
    assert evaluate(ident, receipt) == {"decision": "DENY", "reason": "CONSENT_EXPIRED"}


def test_revocation_entry_invalidates_original_receipt_without_mutating_it():
    ident = identity()
    receipt = consent(ident)
    original = dict(receipt)
    entry = c.build_consent_revocation_entry(
        ident,
        receipt,
        revoking_principal="principal_owner",
        revoking_principal_kind="HUMAN",
        revoked_at="2026-08-25T00:30:00Z",
        reason="owner_revoked",
    )
    ledger = c.build_consent_revocation_ledger([entry])
    assert receipt == original
    assert evaluate(ident, receipt, revocation_ledger=ledger) == {
        "decision": "DENY",
        "reason": "CONSENT_REVOKED",
    }


def test_future_revocation_does_not_revoke_early():
    ident = identity()
    receipt = consent(ident)
    entry = c.build_consent_revocation_entry(
        ident,
        receipt,
        revoking_principal="principal_owner",
        revoking_principal_kind="HUMAN",
        revoked_at="2026-08-25T02:00:00Z",
        reason="scheduled_owner_revocation",
    )
    ledger = c.build_consent_revocation_ledger([entry])
    assert evaluate(ident, receipt, revocation_ledger=ledger)["decision"] == "ALLOW"


def test_revocation_before_issue_is_rejected():
    ident = identity()
    receipt = consent(ident, issued_at="2026-08-25T01:00:00Z")
    with pytest.raises(c.PersonTwinContractError, match="before issued_at"):
        c.build_consent_revocation_entry(
            ident,
            receipt,
            revoking_principal="principal_owner",
            revoking_principal_kind="HUMAN",
            revoked_at="2026-08-25T00:30:00Z",
            reason="invalid",
        )


def test_revocation_principal_kind_must_match_identity_binding():
    ident = identity()
    receipt = consent(ident)
    with pytest.raises(c.PersonTwinContractError, match="kind does not match"):
        c.build_consent_revocation_entry(
            ident,
            receipt,
            revoking_principal="principal_owner",
            revoking_principal_kind="ORGANIZATION",
            revoked_at="2026-08-25T00:30:00Z",
            reason="spoofed_kind",
        )


def test_revocation_ledger_hash_tampering_fails_closed():
    ident = identity()
    receipt = consent(ident)
    ledger = empty_ledger()
    ledger["ledger_hash"] = "0" * 64
    assert evaluate(ident, receipt, revocation_ledger=ledger) == {
        "decision": "DENY",
        "reason": "INVALID_REVOCATION_LEDGER",
    }


def test_revocation_entry_tampering_fails_closed_even_if_ledger_rehashed():
    ident = identity()
    receipt = consent(ident)
    entry = c.build_consent_revocation_entry(
        ident,
        receipt,
        revoking_principal="principal_owner",
        revoking_principal_kind="HUMAN",
        revoked_at="2026-08-25T00:30:00Z",
        reason="owner_revoked",
    )
    entry["receipt_hash"] = "0" * 64
    ledger = c.build_consent_revocation_ledger([entry])
    assert evaluate(ident, receipt, revocation_ledger=ledger) == {
        "decision": "DENY",
        "reason": "INVALID_REVOCATION_LEDGER",
    }


def test_scope_widening_is_not_implicit():
    ident = identity()
    receipt = consent(ident, allowed_scopes=["PERSON_PRIVATE"])
    assert evaluate(ident, receipt, requested_scope="PERSON_SHARED") == {
        "decision": "DENY",
        "reason": "SCOPE_NOT_CONSENTED",
    }


def test_wildcard_scopes_are_rejected():
    with pytest.raises(c.PersonTwinContractError, match="wildcard"):
        consent(allowed_scopes=["PERSON_*"])


def test_object_type_must_be_explicitly_consented():
    ident = identity()
    receipt = consent(ident)
    assert evaluate(ident, receipt, requested_object_type="credential") == {
        "decision": "DENY",
        "reason": "OBJECT_TYPE_NOT_CONSENTED",
    }


def test_purpose_mismatch_fails_closed():
    ident = identity()
    receipt = consent(ident)
    assert evaluate(ident, receipt, purpose="analytics") == {
        "decision": "DENY",
        "reason": "PURPOSE_MISMATCH",
    }


def test_source_read_and_memory_admission_authorities_are_separate():
    ident = identity()
    read_only = consent(
        ident,
        source_read_authority=True,
        memory_admission_authority=False,
    )
    read = evaluate(
        ident,
        read_only,
        require_source_read=True,
        require_memory_admission=False,
    )
    admit = evaluate(
        ident,
        read_only,
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
    assert evaluate(
        ident,
        admission_only,
        require_source_read=True,
        require_memory_admission=True,
    ) == {"decision": "DENY", "reason": "SOURCE_READ_NOT_AUTHORIZED"}


def test_valid_consent_returns_only_non_effectful_evidence():
    ident = identity()
    receipt = consent(ident)
    decision = evaluate(
        ident,
        receipt,
        require_source_read=True,
        require_memory_admission=True,
        oauth_present=True,
    )
    assert decision["decision"] == "ALLOW"
    assert decision["reason"] == "CONSENT_VALID"
    assert decision["twin_id"] == ident["twin_id"]
    assert decision["consent_receipt_id"] == receipt["consent_receipt_id"]
    assert decision["revocation_ledger_hash"] == empty_ledger()["ledger_hash"]
    assert decision["production_admission_status"] == "NOT_PRODUCTION_ADMITTED"
    assert "can_execute" not in decision
    assert "current" not in decision
