from __future__ import annotations

import copy
import inspect

import pytest

import continuityos.person_twin_privacy_provenance as pp
from continuityos.company_twin_ingest import normalize_envelope
from continuityos.person_twin_admission_contracts import (
    build_consent_revocation_entry,
    build_consent_revocation_ledger,
    build_person_twin_identity,
    build_source_consent_receipt,
)

AT = "2026-08-25T12:00:00Z"


def _identity(*, subject_id: str = "subject:owner", owner_id: str = "human:owner"):
    return build_person_twin_identity(
        tenant_id="tenant:person-pilot",
        subject_id=subject_id,
        owner_id=owner_id,
        controller_id=owner_id,
        controller_kind="HUMAN",
        ownership_epoch=1,
        created_at="2026-08-25T00:00:00Z",
    )


def _env(
    *,
    twin_id: str,
    visibility: str = "PERSONAL",
    scope: str | None = None,
    object_id: str = "doc-1",
    revision_id: str = "r1",
    source_system: str = "synthetic_drive",
    connector_id: str = "connector:synthetic-drive",
    payload=None,
):
    if scope is None:
        scope = pp.canonical_person_private_scope(twin_id)
    return {
        "schema_version": "company-twin-source-envelope/1",
        "tenant_id": "tenant:person-pilot",
        "connector_id": connector_id,
        "source_system": source_system,
        "source_object_type": "document",
        "source_object_id": object_id,
        "revision_id": revision_id,
        "observed_at": "2026-08-25T10:01:00Z",
        "effective_at": "2026-08-25T10:00:00Z",
        "acl": {"visibility": visibility, "scope": scope},
        "payload": payload if payload is not None else {
            "title": object_id,
            "text": "synthetic evidence",
        },
        "raw_ref": f"synthetic://{source_system}/{object_id}/{revision_id}",
        "cursor": f"cursor:{object_id}:{revision_id}",
        "actor": {
            "actor_id": "human:owner",
            "actor_kind": "HUMAN",
            "authority_class": "OWNER",
        },
        "deleted": False,
    }


def _receipt(
    identity,
    source_record,
    *,
    scopes=None,
    source_system=None,
    source_identity_hash=None,
    issued_at="2026-08-25T09:00:00Z",
    expires_at="2026-08-26T00:00:00Z",
):
    return build_source_consent_receipt(
        identity,
        authorizing_principal="human:owner",
        authorizing_principal_kind="HUMAN",
        source_system=source_system or source_record["source_system"],
        source_identity_hash=source_identity_hash
        or pp.deterministic_source_identity_hash(source_record),
        allowed_object_types=["document"],
        allowed_scopes=scopes or [source_record["scope"]],
        purpose="person-memory",
        issued_at=issued_at,
        expires_at=expires_at,
        revoked_at=None,
        source_read_authority=False,
        memory_admission_authority=True,
        policy_version="p3-p1-r2-test/1",
    )


def _build(
    *,
    identity=None,
    source_record=None,
    receipt=None,
    ledger=None,
    admission_session_id="admission:synthetic:r2:1",
    at=AT,
):
    identity = identity or _identity()
    if source_record is None:
        source_record = normalize_envelope(_env(twin_id=identity["twin_id"]))
    receipt = receipt or _receipt(identity, source_record)
    ledger = ledger or build_consent_revocation_ledger()
    record = pp.build_person_twin_provenance(
        identity,
        receipt,
        ledger,
        source_record,
        admission_session_id=admission_session_id,
        purpose="person-memory",
        at=at,
    )
    return identity, source_record, receipt, ledger, record


def _source_map(*sources):
    return {source["id"]: source for source in sources}


def _receipt_map(*receipts):
    return {receipt["consent_receipt_id"]: receipt for receipt in receipts}


def _filter(records, identity, sources, receipts, ledger, *, scopes=None, at=AT):
    if scopes is None:
        scopes = [records[0]["scope"]]
    return pp.filter_person_twin_records(
        records,
        identity,
        authorized_scopes=scopes,
        source_records=_source_map(*sources),
        consent_receipts=_receipt_map(*receipts),
        current_revocation_ledger=ledger,
        purpose="person-memory",
        at=at,
    )


def test_private_and_shared_scopes_are_exact_twin_bound():
    identity = _identity()
    private = pp.canonical_person_private_scope(identity["twin_id"])
    shared = pp.canonical_person_shared_scope(identity["twin_id"], "family")
    pp.validate_privacy_scope(
        twin_id=identity["twin_id"],
        privacy_class=pp.PERSON_PRIVATE,
        scope=private,
    )
    pp.validate_privacy_scope(
        twin_id=identity["twin_id"],
        privacy_class=pp.PERSON_SHARED,
        scope=shared,
    )


def test_generic_personal_scope_is_rejected():
    identity = _identity()
    source = normalize_envelope(
        _env(twin_id=identity["twin_id"], scope="person:owner")
    )
    with pytest.raises(pp.PersonTwinPrivacyProvenanceError, match="exact Person Twin"):
        pp.infer_privacy_class(source, twin_id=identity["twin_id"])


def test_other_twin_personal_scope_is_rejected():
    identity = _identity()
    other = _identity(subject_id="subject:other", owner_id="human:other")
    source = normalize_envelope(
        _env(
            twin_id=identity["twin_id"],
            scope=pp.canonical_person_private_scope(other["twin_id"]),
        )
    )
    with pytest.raises(pp.PersonTwinPrivacyProvenanceError):
        pp.infer_privacy_class(source, twin_id=identity["twin_id"])


@pytest.mark.parametrize(
    ("privacy_class", "scope"),
    [
        (pp.PERSON_SHARED, "SHARED"),
        (pp.TEAM, "team:engineering"),
        (pp.COMPANY, "company"),
        (pp.RESTRICTED, "restricted:finance"),
    ],
)
def test_private_scope_cannot_implicitly_widen(privacy_class, scope):
    identity = _identity()
    source = normalize_envelope(_env(twin_id=identity["twin_id"]))
    if scope == "SHARED":
        scope = pp.canonical_person_shared_scope(identity["twin_id"], "family")
    with pytest.raises(
        pp.PersonTwinPrivacyProvenanceError,
        match="implicit privacy/scope promotion",
    ):
        pp.validate_no_implicit_scope_promotion(
            source,
            twin_id=identity["twin_id"],
            target_privacy_class=privacy_class,
            target_scope=scope,
        )


def test_build_binds_identity_consent_source_privacy_and_admission_identity():
    identity, source, receipt, ledger, record = _build()
    assert record["tenant_id"] == identity["tenant_id"]
    assert record["twin_id"] == identity["twin_id"]
    assert record["identity_fingerprint"] == identity["identity_fingerprint"]
    assert record["privacy_class"] == pp.PERSON_PRIVATE
    assert record["scope"] == source["scope"]
    assert record["source_record_id"] == source["id"]
    assert record["source_identity_hash"] == pp.deterministic_source_identity_hash(source)
    assert record["consent_receipt_id"] == receipt["consent_receipt_id"]
    assert record["consent_receipt_hash"] == receipt["receipt_hash"]
    assert record["revocation_ledger_hash"] == ledger["ledger_hash"]
    assert record["admission_session_id"] == "admission:synthetic:r2:1"
    assert record["production_admission_status"] == "NOT_PRODUCTION_ADMITTED"
    assert record["execution_authority"] == "NONE"
    assert record["can_execute"] is False
    pp.validate_person_twin_record(
        record,
        identity=identity,
        consent_receipt=receipt,
        source_record=source,
    )


def test_provenance_is_deterministic_for_same_inputs():
    first = _build()[-1]
    second = _build()[-1]
    assert first == second


def test_consent_scope_mismatch_fails_closed():
    identity = _identity()
    source = normalize_envelope(_env(twin_id=identity["twin_id"]))
    receipt = _receipt(identity, source, scopes=["company"])
    with pytest.raises(pp.PersonTwinPrivacyProvenanceError, match="SCOPE_NOT_CONSENTED"):
        _build(identity=identity, source_record=source, receipt=receipt)


def test_consent_source_system_mismatch_fails_closed():
    identity = _identity()
    source = normalize_envelope(_env(twin_id=identity["twin_id"]))
    receipt = _receipt(identity, source, source_system="other_system")
    with pytest.raises(pp.PersonTwinPrivacyProvenanceError, match="source_system"):
        _build(identity=identity, source_record=source, receipt=receipt)


def test_consent_source_identity_mismatch_fails_closed():
    identity = _identity()
    source = normalize_envelope(_env(twin_id=identity["twin_id"]))
    receipt = _receipt(identity, source, source_identity_hash="0" * 64)
    with pytest.raises(pp.PersonTwinPrivacyProvenanceError, match="source_identity_hash"):
        _build(identity=identity, source_record=source, receipt=receipt)


def test_revoked_consent_fails_closed_at_provenance_boundary():
    identity = _identity()
    source = normalize_envelope(_env(twin_id=identity["twin_id"]))
    receipt = _receipt(identity, source)
    entry = build_consent_revocation_entry(
        identity,
        receipt,
        revoking_principal="human:owner",
        revoking_principal_kind="HUMAN",
        revoked_at="2026-08-25T11:00:00Z",
        reason="synthetic revoke",
    )
    ledger = build_consent_revocation_ledger([entry])
    with pytest.raises(pp.PersonTwinPrivacyProvenanceError, match="CONSENT_REVOKED"):
        _build(
            identity=identity,
            source_record=source,
            receipt=receipt,
            ledger=ledger,
            at=AT,
        )


def test_not_yet_valid_consent_fails_closed():
    identity = _identity()
    source = normalize_envelope(_env(twin_id=identity["twin_id"]))
    receipt = _receipt(
        identity,
        source,
        issued_at="2026-08-25T13:00:00Z",
        expires_at="2026-08-26T00:00:00Z",
    )
    with pytest.raises(pp.PersonTwinPrivacyProvenanceError, match="CONSENT_NOT_YET_VALID"):
        _build(
            identity=identity,
            source_record=source,
            receipt=receipt,
            at=AT,
        )


def test_cross_tenant_source_record_fails_closed():
    identity = _identity()
    envelope = _env(twin_id=identity["twin_id"])
    envelope["tenant_id"] = "tenant:other"
    source = normalize_envelope(envelope)
    receipt = _receipt(identity, source)
    with pytest.raises(pp.PersonTwinPrivacyProvenanceError, match="tenant_id"):
        _build(identity=identity, source_record=source, receipt=receipt)


def test_payload_tamper_breaks_provenance_hash_and_content_binding():
    identity, source, receipt, _, record = _build()
    tampered = copy.deepcopy(record)
    tampered["payload"]["text"] = "changed"
    with pytest.raises(pp.PersonTwinPrivacyProvenanceError):
        pp.validate_person_twin_record(
            tampered,
            identity=identity,
            consent_receipt=receipt,
            source_record=source,
        )


def test_rehashed_wrong_record_id_is_rejected():
    identity, source, receipt, _, record = _build()
    tampered = copy.deepcopy(record)
    tampered["id"] = "ptp_" + ("0" * 32)
    body = dict(tampered)
    body.pop("provenance_hash")
    tampered["provenance_hash"] = pp._canonical_hash(body)
    with pytest.raises(pp.PersonTwinPrivacyProvenanceError, match="not deterministic"):
        pp.validate_person_twin_record(
            tampered,
            identity=identity,
            consent_receipt=receipt,
            source_record=source,
        )


def test_rehashed_forged_source_identity_is_rejected_against_external_anchor():
    identity, source, receipt, _, record = _build()
    tampered = copy.deepcopy(record)
    tampered["source_object_id"] = "forged-object"
    body = dict(tampered)
    body.pop("provenance_hash")
    tampered["provenance_hash"] = pp._canonical_hash(body)
    with pytest.raises(
        pp.PersonTwinPrivacyProvenanceError,
        match="source provenance binding mismatch",
    ):
        pp.validate_person_twin_record(
            tampered,
            identity=identity,
            consent_receipt=receipt,
            source_record=source,
        )


def test_rehashed_forged_source_record_id_and_person_id_are_rejected():
    identity, source, receipt, _, record = _build()
    tampered = copy.deepcopy(record)
    tampered["source_record_id"] = "cti_" + ("f" * 32)
    tampered["id"] = pp._deterministic_person_record_id(
        twin_id=tampered["twin_id"],
        source_record_id=tampered["source_record_id"],
        admission_session_id=tampered["admission_session_id"],
    )
    body = dict(tampered)
    body.pop("provenance_hash")
    tampered["provenance_hash"] = pp._canonical_hash(body)
    with pytest.raises(
        pp.PersonTwinPrivacyProvenanceError,
        match="source provenance binding mismatch",
    ):
        pp.validate_person_twin_record(
            tampered,
            identity=identity,
            consent_receipt=receipt,
            source_record=source,
        )


def test_source_revision_tamper_breaks_exact_binding():
    identity, source, receipt, _, record = _build()
    tampered_source = copy.deepcopy(source)
    tampered_source["revision_id"] = "r999"
    with pytest.raises(pp.PersonTwinPrivacyProvenanceError):
        pp.validate_person_twin_provenance_binding(
            identity,
            receipt,
            tampered_source,
            record,
        )


def test_retrieval_filters_other_twin_and_exact_scope():
    identity, source, receipt, ledger, private = _build()
    other_identity = _identity(
        subject_id="subject:other",
        owner_id="human:other",
    )
    other_source = normalize_envelope(
        _env(twin_id=other_identity["twin_id"], object_id="other-doc")
    )
    other_receipt = build_source_consent_receipt(
        other_identity,
        authorizing_principal="human:other",
        authorizing_principal_kind="HUMAN",
        source_system=other_source["source_system"],
        source_identity_hash=pp.deterministic_source_identity_hash(other_source),
        allowed_object_types=["document"],
        allowed_scopes=[other_source["scope"]],
        purpose="person-memory",
        issued_at="2026-08-25T09:00:00Z",
        expires_at="2026-08-26T00:00:00Z",
        revoked_at=None,
        source_read_authority=False,
        memory_admission_authority=True,
        policy_version="p3-p1-r2-test/1",
    )
    other = pp.build_person_twin_provenance(
        other_identity,
        other_receipt,
        build_consent_revocation_ledger(),
        other_source,
        admission_session_id="admission:other",
        purpose="person-memory",
        at=AT,
    )
    visible = _filter(
        [other, private],
        identity,
        [source],
        [receipt],
        ledger,
        scopes=[private["scope"]],
    )
    assert [item["id"] for item in visible] == [private["id"]]


def test_retrieval_rejects_wildcard_authorization():
    identity, source, receipt, ledger, private = _build()
    with pytest.raises(pp.PersonTwinPrivacyProvenanceError, match="wildcard"):
        _filter(
            [private],
            identity,
            [source],
            [receipt],
            ledger,
            scopes=["person:*"],
        )


def test_cross_scope_lineage_is_hidden_to_prevent_reference_leak():
    identity = _identity()
    private_source = normalize_envelope(
        _env(
            twin_id=identity["twin_id"],
            object_id="lineage",
            revision_id="r1",
        )
    )
    private_receipt = _receipt(identity, private_source)
    private_ledger = build_consent_revocation_ledger()
    private = _build(
        identity=identity,
        source_record=private_source,
        receipt=private_receipt,
        ledger=private_ledger,
        admission_session_id="admission:r1",
    )[-1]

    shared_scope = pp.canonical_person_shared_scope(identity["twin_id"], "family")
    shared_source = normalize_envelope(
        _env(
            twin_id=identity["twin_id"],
            visibility="PERSONAL",
            scope=shared_scope,
            object_id="lineage",
            revision_id="r2",
        ),
        supersedes=private_source["id"],
    )
    shared_receipt = _receipt(identity, shared_source)
    shared_ledger = build_consent_revocation_ledger()
    shared = _build(
        identity=identity,
        source_record=shared_source,
        receipt=shared_receipt,
        ledger=shared_ledger,
        admission_session_id="admission:r2",
    )[-1]

    visible = _filter(
        [private, shared],
        identity,
        [shared_source],
        [shared_receipt],
        shared_ledger,
        scopes=[shared_scope],
    )
    assert visible == []


def test_retrieval_rechecks_current_revocation_after_record_was_built():
    identity, source, receipt, _, record = _build()
    entry = build_consent_revocation_entry(
        identity,
        receipt,
        revoking_principal="human:owner",
        revoking_principal_kind="HUMAN",
        revoked_at="2026-08-25T12:30:00Z",
        reason="revoke after admission evidence",
    )
    current_ledger = build_consent_revocation_ledger([entry])
    with pytest.raises(pp.PersonTwinPrivacyProvenanceError, match="CONSENT_REVOKED"):
        _filter(
            [record],
            identity,
            [source],
            [receipt],
            current_ledger,
            at="2026-08-25T13:00:00Z",
        )


def test_retrieval_requires_current_consent_receipt_evidence():
    identity, source, _, ledger, record = _build()
    with pytest.raises(
        pp.PersonTwinPrivacyProvenanceError,
        match="current consent receipt evidence is missing",
    ):
        _filter(
            [record],
            identity,
            [source],
            [],
            ledger,
        )


def test_retrieval_rejects_rehashed_forged_record_against_source_anchor():
    identity, source, receipt, ledger, record = _build()
    forged = copy.deepcopy(record)
    forged["source_object_id"] = "forged-at-read"
    body = dict(forged)
    body.pop("provenance_hash")
    forged["provenance_hash"] = pp._canonical_hash(body)
    with pytest.raises(
        pp.PersonTwinPrivacyProvenanceError,
        match="source provenance binding mismatch",
    ):
        _filter(
            [forged],
            identity,
            [source],
            [receipt],
            ledger,
        )


def test_export_reuses_p2_bundle_and_preserves_person_provenance_manifest():
    identity, source, receipt, ledger, record = _build()
    bundle = pp.build_person_twin_export_bundle(
        [record],
        identity,
        authorized_scopes=[record["scope"]],
        source_records=_source_map(source),
        consent_receipts=_receipt_map(receipt),
        current_revocation_ledger=ledger,
        purpose="person-memory",
        requested_at=AT,
        requested_by={
            "actor_id": "human:owner",
            "actor_kind": "HUMAN",
            "authority_class": "OWNER",
        },
    )
    assert bundle["read_only"] is True
    assert bundle["execution_authority"] == "NONE"
    assert bundle["can_execute"] is False
    assert bundle["current_revocation_ledger_hash"] == ledger["ledger_hash"]
    assert bundle["consent_purpose"] == "person-memory"
    assert bundle["consent_evaluated_at"] == AT
    assert bundle["p2_export"]["schema_version"] == "company-twin-export/1"
    assert bundle["p2_export"]["record_count"] == 1
    assert bundle["person_provenance"] == [{
        "id": record["id"],
        "twin_id": record["twin_id"],
        "identity_fingerprint": record["identity_fingerprint"],
        "privacy_class": record["privacy_class"],
        "scope": record["scope"],
        "consent_receipt_id": record["consent_receipt_id"],
        "consent_receipt_hash": record["consent_receipt_hash"],
        "admission_session_id": record["admission_session_id"],
        "provenance_hash": record["provenance_hash"],
    }]


def test_export_exact_scope_does_not_leak_company_record():
    identity, private_source, private_receipt, ledger, private = _build()
    company_source = normalize_envelope(
        _env(
            twin_id=identity["twin_id"],
            visibility="COMPANY",
            scope="company",
            object_id="company-doc",
        )
    )
    company_receipt = _receipt(identity, company_source)
    company = _build(
        identity=identity,
        source_record=company_source,
        receipt=company_receipt,
        admission_session_id="admission:company",
    )[-1]
    bundle = pp.build_person_twin_export_bundle(
        [company, private],
        identity,
        authorized_scopes=[private["scope"]],
        source_records=_source_map(private_source),
        consent_receipts=_receipt_map(private_receipt),
        current_revocation_ledger=ledger,
        purpose="person-memory",
        requested_at=AT,
        requested_by={
            "actor_id": "human:owner",
            "actor_kind": "HUMAN",
            "authority_class": "OWNER",
        },
    )
    encoded = repr(bundle)
    assert private["id"] in encoded
    assert company["id"] not in encoded


def test_export_rechecks_revocation_after_record_was_built():
    identity, source, receipt, _, record = _build()
    entry = build_consent_revocation_entry(
        identity,
        receipt,
        revoking_principal="human:owner",
        revoking_principal_kind="HUMAN",
        revoked_at="2026-08-25T12:30:00Z",
        reason="revoke before export",
    )
    current_ledger = build_consent_revocation_ledger([entry])
    with pytest.raises(pp.PersonTwinPrivacyProvenanceError, match="CONSENT_REVOKED"):
        pp.build_person_twin_export_bundle(
            [record],
            identity,
            authorized_scopes=[record["scope"]],
            source_records=_source_map(source),
            consent_receipts=_receipt_map(receipt),
            current_revocation_ledger=current_ledger,
            purpose="person-memory",
            requested_at="2026-08-25T13:00:00Z",
            requested_by={
                "actor_id": "human:owner",
                "actor_kind": "HUMAN",
                "authority_class": "OWNER",
            },
        )


def test_lifecycle_target_is_exact_read_only_and_no_physical_delete():
    identity, source, receipt, ledger, record = _build()
    target = pp.bind_person_twin_lifecycle_target(
        [record],
        identity,
        record_id=record["id"],
        scope=record["scope"],
        source_records=_source_map(source),
        consent_receipts=_receipt_map(receipt),
        current_revocation_ledger=ledger,
        purpose="person-memory",
        evaluated_at=AT,
    )
    assert target["record_id"] == record["id"]
    assert target["twin_id"] == identity["twin_id"]
    assert target["scope"] == record["scope"]
    assert target["read_only"] is True
    assert target["physical_delete"] is False
    assert target["execution_authority"] == "NONE"
    assert target["can_execute"] is False
    assert target["current_revocation_ledger_hash"] == ledger["ledger_hash"]


def test_lifecycle_wrong_scope_fails_closed():
    identity, source, receipt, ledger, record = _build()
    with pytest.raises(pp.PersonTwinPrivacyProvenanceError, match="exact twin-bound"):
        pp.bind_person_twin_lifecycle_target(
            [record],
            identity,
            record_id=record["id"],
            scope="company",
            source_records=_source_map(source),
            consent_receipts=_receipt_map(receipt),
            current_revocation_ledger=ledger,
            purpose="person-memory",
            evaluated_at=AT,
        )


def test_lifecycle_wrong_record_id_fails_closed():
    identity, source, receipt, ledger, record = _build()
    with pytest.raises(pp.PersonTwinPrivacyProvenanceError, match="exact twin-bound"):
        pp.bind_person_twin_lifecycle_target(
            [record],
            identity,
            record_id="ptp_missing",
            scope=record["scope"],
            source_records=_source_map(source),
            consent_receipts=_receipt_map(receipt),
            current_revocation_ledger=ledger,
            purpose="person-memory",
            evaluated_at=AT,
        )


def test_lifecycle_rechecks_revocation_after_record_was_built():
    identity, source, receipt, _, record = _build()
    entry = build_consent_revocation_entry(
        identity,
        receipt,
        revoking_principal="human:owner",
        revoking_principal_kind="HUMAN",
        revoked_at="2026-08-25T12:30:00Z",
        reason="revoke before lifecycle",
    )
    current_ledger = build_consent_revocation_ledger([entry])
    with pytest.raises(pp.PersonTwinPrivacyProvenanceError, match="CONSENT_REVOKED"):
        pp.bind_person_twin_lifecycle_target(
            [record],
            identity,
            record_id=record["id"],
            scope=record["scope"],
            source_records=_source_map(source),
            consent_receipts=_receipt_map(receipt),
            current_revocation_ledger=current_ledger,
            purpose="person-memory",
            evaluated_at="2026-08-25T13:00:00Z",
        )


def test_r2_module_has_no_network_connector_oauth_or_runtime_effect_surface():
    text = inspect.getsource(pp).lower()
    forbidden = (
        "urlopen(",
        "requests.",
        "httpx.",
        "socket.",
        "subprocess.",
        "oauth",
        "current_pointer",
        "deploy",
        "can_trade",
    )
    assert all(token not in text for token in forbidden)
