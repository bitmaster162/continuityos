from __future__ import annotations

import copy
import hashlib
import inspect

import pytest

import continuityos.person_twin_admission_coordinator as ac
import continuityos.person_twin_privacy_provenance as pp
from continuityos.company_twin_ingest import normalize_envelope
from continuityos.person_twin_admission_contracts import (
    build_consent_revocation_entry,
    build_consent_revocation_ledger,
    build_person_twin_identity,
    build_source_consent_receipt,
)

AT = "2026-08-25T12:00:00Z"


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _identity(*, subject_id="subject:owner", owner_id="human:owner"):
    return build_person_twin_identity(
        tenant_id="tenant:person-pilot",
        subject_id=subject_id,
        owner_id=owner_id,
        controller_id=owner_id,
        controller_kind="HUMAN",
        ownership_epoch=1,
        created_at="2026-08-25T00:00:00Z",
    )


def _env(*, twin_id: str, object_id="doc-r3", revision_id="r1", payload=None):
    return {
        "schema_version": "company-twin-source-envelope/1",
        "tenant_id": "tenant:person-pilot",
        "connector_id": "connector:synthetic-drive",
        "source_system": "synthetic_drive",
        "source_object_type": "document",
        "source_object_id": object_id,
        "revision_id": revision_id,
        "observed_at": "2026-08-25T10:01:00Z",
        "effective_at": "2026-08-25T10:00:00Z",
        "acl": {
            "visibility": "PERSONAL",
            "scope": pp.canonical_person_private_scope(twin_id),
        },
        "payload": payload or {
            "title": object_id,
            "text": "synthetic R3 evidence",
        },
        "raw_ref": f"synthetic://drive/{object_id}/{revision_id}",
        "cursor": f"cursor:{object_id}:{revision_id}",
        "actor": {
            "actor_id": "human:owner",
            "actor_kind": "HUMAN",
            "authority_class": "OWNER",
        },
        "deleted": False,
    }


def _receipt(identity, source):
    return build_source_consent_receipt(
        identity,
        authorizing_principal="human:owner",
        authorizing_principal_kind="HUMAN",
        source_system=source["source_system"],
        source_identity_hash=pp.deterministic_source_identity_hash(source),
        allowed_object_types=["document"],
        allowed_scopes=[source["scope"]],
        purpose="person-memory",
        issued_at="2026-08-25T09:00:00Z",
        expires_at="2026-08-26T00:00:00Z",
        revoked_at=None,
        source_read_authority=False,
        memory_admission_authority=True,
        policy_version="p3-p1-r3-test/1",
    )


def _fixture(*, pointer=None):
    identity = _identity()
    source = normalize_envelope(_env(twin_id=identity["twin_id"]))
    receipt = _receipt(identity, source)
    ledger = build_consent_revocation_ledger()
    record = pp.build_person_twin_provenance(
        identity,
        receipt,
        ledger,
        source,
        admission_session_id="admission:synthetic:r3:1",
        purpose="person-memory",
        at=AT,
    )
    pointer = pointer or ac.build_synthetic_current_pointer(identity)
    session = ac.begin_admission(
        identity,
        receipt,
        ledger,
        source,
        record,
        pointer,
        purpose="person-memory",
        at=AT,
    )
    return identity, source, receipt, ledger, record, pointer, session


def _to_admissible(fixture):
    identity, source, receipt, ledger, record, pointer, session = fixture
    session = ac.stage_candidate(session)
    session = ac.record_scan(
        session,
        passed=True,
        scan_evidence_hash=_sha("scan-pass"),
    )
    session = ac.classify_candidate(
        session,
        privacy_class=record["privacy_class"],
        scope=record["scope"],
        classification_evidence_hash=_sha("classification-pass"),
    )
    session = ac.mark_admissible(
        session,
        identity=identity,
        consent_receipt=receipt,
        revocation_ledger=ledger,
        source_record=source,
        person_record=record,
        purpose="person-memory",
        at=AT,
    )
    return identity, source, receipt, ledger, record, pointer, session


def _to_committed(fixture):
    identity, source, receipt, ledger, record, pointer, session = _to_admissible(
        fixture
    )
    session = ac.commit_non_current(
        session,
        pointer,
        identity=identity,
        consent_receipt=receipt,
        revocation_ledger=ledger,
        source_record=source,
        person_record=record,
        purpose="person-memory",
        at=AT,
    )
    return identity, source, receipt, ledger, record, pointer, session


def _to_verified(fixture):
    identity, source, receipt, ledger, record, pointer, session = _to_committed(
        fixture
    )
    session = ac.post_commit_verify(
        session,
        pointer,
        identity=identity,
        consent_receipt=receipt,
        revocation_ledger=ledger,
        source_record=source,
        person_record=record,
        purpose="person-memory",
        at=AT,
        observed_candidate_hash=session["candidate_hash"],
        observed_provenance_hash=session["provenance_hash"],
        observed_record_count=1,
    )
    assert session["state"] == ac.VERIFIED_NON_CURRENT
    return identity, source, receipt, ledger, record, pointer, session


def test_explicit_pipeline_stops_at_verified_non_current_before_promotion():
    *_, pointer, session = _to_verified(_fixture())
    assert session["state"] == ac.VERIFIED_NON_CURRENT
    assert pointer["current_candidate_id"] is None
    assert pointer["generation"] == 0
    assert session["production_admission_status"] == "NOT_PRODUCTION_ADMITTED"
    assert session["execution_authority"] == "NONE"
    assert session["can_execute"] is False


def test_direct_state_tamper_to_current_is_rejected():
    *_, session = _fixture()
    tampered = dict(session)
    tampered["state"] = ac.CURRENT
    with pytest.raises(ac.PersonTwinAdmissionCoordinatorError):
        ac.validate_admission_session(tampered)


def test_candidate_hash_tamper_is_rejected_even_with_rehashed_session():
    *_, session = _fixture()
    tampered = dict(session)
    tampered["candidate_hash"] = _sha("forged")
    tampered["candidate_id"] = f"ptac_{tampered['candidate_hash'][:32]}"
    body = {
        key: copy.deepcopy(value)
        for key, value in tampered.items()
        if key != "session_hash"
    }
    tampered["session_hash"] = ac._hash(body)
    with pytest.raises(
        ac.PersonTwinAdmissionCoordinatorError,
        match="candidate identity/hash",
    ):
        ac.validate_admission_session(tampered)


def test_scan_failure_quarantines_and_cannot_commit():
    identity, source, receipt, ledger, record, pointer, session = _fixture()
    session = ac.stage_candidate(session)
    session = ac.record_scan(
        session,
        passed=False,
        scan_evidence_hash=_sha("scan-fail"),
    )
    assert session["state"] == ac.QUARANTINED
    with pytest.raises(ac.PersonTwinAdmissionCoordinatorError):
        ac.commit_non_current(
            session,
            pointer,
            identity=identity,
            consent_receipt=receipt,
            revocation_ledger=ledger,
            source_record=source,
            person_record=record,
            purpose="person-memory",
            at=AT,
        )


def test_private_scope_cannot_be_reclassified_to_company():
    identity, source, receipt, ledger, record, pointer, session = _fixture()
    session = ac.stage_candidate(session)
    session = ac.record_scan(
        session,
        passed=True,
        scan_evidence_hash=_sha("scan"),
    )
    with pytest.raises(ac.PersonTwinAdmissionCoordinatorError, match="cannot widen"):
        ac.classify_candidate(
            session,
            privacy_class=pp.COMPANY,
            scope="company",
            classification_evidence_hash=_sha("classification"),
        )


def test_committed_candidate_does_not_change_current_pointer():
    *_, pointer, session = _to_committed(_fixture())
    assert session["state"] == ac.COMMITTED_NON_CURRENT
    assert session["commit_hash"]
    assert pointer["current_candidate_id"] is None
    assert pointer["generation"] == 0


def test_postverify_hash_mismatch_holds_and_preserves_a():
    identity = _identity()
    pointer = ac.build_synthetic_current_pointer(
        identity,
        current_candidate_id="candidate:A",
        current_candidate_hash=_sha("A"),
        generation=3,
    )
    identity, source, receipt, ledger, record, pointer, session = _to_committed(
        _fixture(pointer=pointer)
    )
    held = ac.post_commit_verify(
        session,
        pointer,
        identity=identity,
        consent_receipt=receipt,
        revocation_ledger=ledger,
        source_record=source,
        person_record=record,
        purpose="person-memory",
        at=AT,
        observed_candidate_hash=_sha("wrong"),
        observed_provenance_hash=session["provenance_hash"],
        observed_record_count=1,
    )
    assert held["state"] == ac.POSTVERIFY_HOLD
    assert held["postverify_reason"] == "CANDIDATE_HASH_MISMATCH"
    assert pointer["current_candidate_id"] == "candidate:A"
    assert pointer["last_known_good_candidate_id"] == "candidate:A"
    assert pointer["generation"] == 3


def test_postverify_pointer_drift_holds():
    identity, source, receipt, ledger, record, pointer, session = _to_committed(
        _fixture()
    )
    drifted = ac.build_synthetic_current_pointer(
        identity,
        current_candidate_id="candidate:other",
        current_candidate_hash=_sha("other"),
        generation=1,
    )
    held = ac.post_commit_verify(
        session,
        drifted,
        identity=identity,
        consent_receipt=receipt,
        revocation_ledger=ledger,
        source_record=source,
        person_record=record,
        purpose="person-memory",
        at=AT,
        observed_candidate_hash=session["candidate_hash"],
        observed_provenance_hash=session["provenance_hash"],
        observed_record_count=1,
    )
    assert held["state"] == ac.POSTVERIFY_HOLD
    assert held["postverify_reason"] == "CURRENT_POINTER_DRIFT"
    assert drifted["current_candidate_id"] == "candidate:other"


def test_revocation_after_staging_blocks_admissibility():
    identity, source, receipt, ledger, record, pointer, session = _fixture()
    session = ac.stage_candidate(session)
    session = ac.record_scan(
        session,
        passed=True,
        scan_evidence_hash=_sha("scan"),
    )
    session = ac.classify_candidate(
        session,
        privacy_class=record["privacy_class"],
        scope=record["scope"],
        classification_evidence_hash=_sha("classification"),
    )
    revocation = build_consent_revocation_entry(
        identity,
        receipt,
        revoking_principal="human:owner",
        revoking_principal_kind="HUMAN",
        revoked_at="2026-08-25T11:00:00Z",
        reason="synthetic revoke",
    )
    current_ledger = build_consent_revocation_ledger([revocation])
    with pytest.raises(ac.PersonTwinAdmissionCoordinatorError):
        ac.mark_admissible(
            session,
            identity=identity,
            consent_receipt=receipt,
            revocation_ledger=current_ledger,
            source_record=source,
            person_record=record,
            purpose="person-memory",
            at=AT,
        )


def test_source_or_provenance_drift_after_staging_is_denied():
    identity, source, receipt, ledger, record, pointer, session = _fixture()
    session = ac.stage_candidate(session)
    session = ac.record_scan(
        session,
        passed=True,
        scan_evidence_hash=_sha("scan"),
    )
    session = ac.classify_candidate(
        session,
        privacy_class=record["privacy_class"],
        scope=record["scope"],
        classification_evidence_hash=_sha("classification"),
    )
    tampered = copy.deepcopy(record)
    tampered["revision_id"] = "r999"
    with pytest.raises(ac.PersonTwinAdmissionCoordinatorError):
        ac.mark_admissible(
            session,
            identity=identity,
            consent_receipt=receipt,
            revocation_ledger=ledger,
            source_record=source,
            person_record=tampered,
            purpose="person-memory",
            at=AT,
        )


def test_promotion_before_postverify_is_denied():
    identity, source, receipt, ledger, record, pointer, session = _to_committed(
        _fixture()
    )
    with pytest.raises(
        ac.PersonTwinAdmissionCoordinatorError,
        match="promotion requires",
    ):
        ac.promote_verified_candidate(
            session,
            pointer,
            identity=identity,
            expected_generation=0,
            expected_current_candidate_id=None,
            expected_current_candidate_hash=None,
        )


def test_explicit_cas_promotion_moves_current_and_lkg_together():
    identity, source, receipt, ledger, record, pointer, session = _to_verified(
        _fixture()
    )
    result = ac.promote_verified_candidate(
        session,
        pointer,
        identity=identity,
        expected_generation=0,
        expected_current_candidate_id=None,
        expected_current_candidate_hash=None,
    )
    assert result["decision"] == "PROMOTED"
    assert result["candidate_state"] == ac.CURRENT
    new_pointer = result["current_pointer"]
    assert new_pointer["generation"] == 1
    assert new_pointer["current_candidate_id"] == session["candidate_id"]
    assert new_pointer["current_candidate_hash"] == session["candidate_hash"]
    assert new_pointer["last_known_good_candidate_id"] == session["candidate_id"]
    assert new_pointer["last_known_good_candidate_hash"] == session["candidate_hash"]
    assert new_pointer["real_current_pointer_mutated"] is False
    assert (
        result["current_session"]["production_admission_status"]
        == "NOT_PRODUCTION_ADMITTED"
    )


def test_stale_cas_holds_and_preserves_last_known_good_a():
    identity = _identity()
    pointer = ac.build_synthetic_current_pointer(
        identity,
        current_candidate_id="candidate:A",
        current_candidate_hash=_sha("A"),
        generation=7,
    )
    identity, source, receipt, ledger, record, pointer, session = _to_verified(
        _fixture(pointer=pointer)
    )
    result = ac.promote_verified_candidate(
        session,
        pointer,
        identity=identity,
        expected_generation=6,
        expected_current_candidate_id="candidate:A",
        expected_current_candidate_hash=_sha("A"),
    )
    assert result["decision"] == "HOLD"
    assert result["reason"] == "CAS_EXPECTATION_MISMATCH"
    assert result["candidate_state"] == ac.VERIFIED_NON_CURRENT
    assert result["current_pointer"]["current_candidate_id"] == "candidate:A"
    assert result["current_pointer"]["last_known_good_candidate_id"] == "candidate:A"
    assert result["current_pointer"]["generation"] == 7


def test_competing_verified_candidate_cannot_promote_over_changed_current():
    identity, source, receipt, ledger, record, pointer, session = _to_verified(
        _fixture()
    )
    changed = ac.build_synthetic_current_pointer(
        identity,
        current_candidate_id="candidate:other",
        current_candidate_hash=_sha("other"),
        generation=1,
    )
    result = ac.promote_verified_candidate(
        session,
        changed,
        identity=identity,
        expected_generation=1,
        expected_current_candidate_id="candidate:other",
        expected_current_candidate_hash=_sha("other"),
    )
    assert result["decision"] == "HOLD"
    assert result["reason"] == "STALE_CURRENT_POINTER"
    assert result["current_pointer"]["current_candidate_id"] == "candidate:other"


def test_wrong_twin_pointer_is_rejected():
    identity, source, receipt, ledger, record, pointer, session = _to_verified(
        _fixture()
    )
    other = _identity(subject_id="subject:other", owner_id="human:other")
    wrong = ac.build_synthetic_current_pointer(other)
    with pytest.raises(ac.PersonTwinAdmissionCoordinatorError, match="tenant/twin"):
        ac.promote_verified_candidate(
            session,
            wrong,
            identity=identity,
            expected_generation=0,
            expected_current_candidate_id=None,
            expected_current_candidate_hash=None,
        )


def test_exact_retry_is_deterministic_and_idempotent_as_evidence():
    first = _fixture()
    second = _fixture()
    assert first[-1]["candidate_id"] == second[-1]["candidate_id"]
    assert first[-1]["candidate_hash"] == second[-1]["candidate_hash"]
    assert first[-1]["session_hash"] == second[-1]["session_hash"]


def test_r3_surface_has_no_real_effect_or_production_admission_path():
    source = inspect.getsource(ac)
    for token in (
        "requests.",
        "urllib.",
        "subprocess.",
        "socket.",
        "Path(",
        "os.replace",
        "current_pointer.json",
    ):
        assert token not in source
    assert '"PRODUCTION_ADMITTED"' not in source
    assert "real_current_pointer_mutated" in source
    assert "NOT_PRODUCTION_ADMITTED" in source
    assert "execution_authority" in source
