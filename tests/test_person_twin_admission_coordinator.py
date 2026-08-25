from __future__ import annotations

import copy
import hashlib

import pytest

from continuityos.company_twin_ingest import normalize_envelope
from continuityos.person_twin_admission_contracts import (
    build_consent_revocation_entry,
    build_consent_revocation_ledger,
    build_person_twin_identity,
    build_source_consent_receipt,
)
from continuityos.person_twin_privacy_provenance import (
    build_person_twin_provenance,
    canonical_person_private_scope,
    deterministic_source_identity_hash,
)
from continuityos.person_twin_admission_coordinator import (
    COMMITTED_NOT_CURRENT,
    CURRENT,
    HOLD,
    POSTVERIFY_PASS,
    STAGED,
    VALIDATED,
    AdmissionStoreConflict,
    PersonTwinAdmissionCoordinator,
)

VALIDATE_AT = "2026-08-25T12:00:00Z"
POSTVERIFY_AT = "2026-08-25T12:30:00Z"


def _sha(payload: bytes | None) -> str | None:
    return None if payload is None else hashlib.sha256(payload).hexdigest()


class MemoryAdmissionStore:
    """Synthetic store whose promotion primitive is atomic compare-and-swap."""

    def __init__(self, pointer: bytes | None = b'{"candidate":"last-known-good"}'):
        self.pointer = pointer
        self.candidates: dict[str, bytes] = {}

    def read_current_pointer_bytes(self) -> bytes | None:
        return self.pointer

    def read_candidate_bytes(self, candidate_id: str) -> bytes | None:
        return self.candidates.get(candidate_id)

    def commit_candidate_not_current(
        self,
        candidate_id: str,
        candidate_bytes: bytes,
    ) -> None:
        prior = self.candidates.get(candidate_id)
        if prior is not None and prior != candidate_bytes:
            raise AdmissionStoreConflict("candidate identity conflict")
        self.candidates[candidate_id] = candidate_bytes

    def promote_current_pointer(
        self,
        *,
        expected_pointer_sha256: str | None,
        pointer_bytes: bytes,
    ) -> None:
        if _sha(self.pointer) != expected_pointer_sha256:
            raise AdmissionStoreConflict("stale current pointer")
        self.pointer = pointer_bytes


def _identity():
    return build_person_twin_identity(
        tenant_id="tenant:person-pilot",
        subject_id="subject:owner",
        owner_id="human:owner",
        controller_id="human:owner",
        controller_kind="HUMAN",
        ownership_epoch=1,
        created_at="2026-08-25T00:00:00Z",
    )


def _source(identity, *, revision_id="r1", payload=None):
    scope = canonical_person_private_scope(identity["twin_id"])
    envelope = {
        "schema_version": "company-twin-source-envelope/1",
        "tenant_id": "tenant:person-pilot",
        "connector_id": "connector:synthetic-drive",
        "source_system": "synthetic_drive",
        "source_object_type": "document",
        "source_object_id": "doc-1",
        "revision_id": revision_id,
        "observed_at": "2026-08-25T10:01:00Z",
        "effective_at": "2026-08-25T10:00:00Z",
        "acl": {"visibility": "PERSONAL", "scope": scope},
        "payload": payload or {"title": "doc-1", "text": "synthetic evidence"},
        "raw_ref": f"synthetic://drive/doc-1/{revision_id}",
        "cursor": f"cursor:doc-1:{revision_id}",
        "actor": {
            "actor_id": "human:owner",
            "actor_kind": "HUMAN",
            "authority_class": "OWNER",
        },
        "deleted": False,
    }
    return normalize_envelope(envelope)


def _receipt(identity, source, *, policy_version="p3-p1-r3-test/1"):
    return build_source_consent_receipt(
        identity,
        authorizing_principal="human:owner",
        authorizing_principal_kind="HUMAN",
        source_system=source["source_system"],
        source_identity_hash=deterministic_source_identity_hash(source),
        allowed_object_types=["document"],
        allowed_scopes=[source["scope"]],
        purpose="person-memory",
        issued_at="2026-08-25T09:00:00Z",
        expires_at="2026-08-26T00:00:00Z",
        revoked_at=None,
        source_read_authority=False,
        memory_admission_authority=True,
        policy_version=policy_version,
    )


def _fixture(*, admission_session_id="admission:synthetic:r3:1", policy_version="p3-p1-r3-test/1"):
    identity = _identity()
    source = _source(identity)
    receipt = _receipt(identity, source, policy_version=policy_version)
    ledger = build_consent_revocation_ledger()
    record = build_person_twin_provenance(
        identity,
        receipt,
        ledger,
        source,
        admission_session_id=admission_session_id,
        purpose="person-memory",
        at=VALIDATE_AT,
    )
    return identity, source, receipt, ledger, record


def _coordinator(store=None, *, fixture=None, session_id="r3-session-1"):
    identity, source, receipt, ledger, record = fixture or _fixture()
    store = store or MemoryAdmissionStore()
    coordinator = PersonTwinAdmissionCoordinator(
        store,
        session_id=session_id,
        identity=identity,
        consent_receipt=receipt,
        source_record=source,
        candidate_record=record,
        purpose="person-memory",
    )
    return store, coordinator, identity, source, receipt, ledger, record


def _through_commit(store=None, *, fixture=None):
    store, c, identity, source, receipt, ledger, record = _coordinator(
        store, fixture=fixture
    )
    assert c.staged()["state"] == STAGED
    assert c.validate(revocation_ledger=ledger, at=VALIDATE_AT)["state"] == VALIDATED
    assert c.commit_not_current()["state"] == COMMITTED_NOT_CURRENT
    return store, c, identity, source, receipt, ledger, record


def test_happy_path_staged_validated_committed_postverified_current():
    store, c, _, _, _, ledger, _ = _coordinator()
    prior = store.pointer

    assert c.staged()["history"] == [STAGED]
    assert c.validate(revocation_ledger=ledger, at=VALIDATE_AT)["state"] == VALIDATED
    assert c.commit_not_current()["state"] == COMMITTED_NOT_CURRENT
    assert store.pointer == prior

    verified = c.postverify(
        current_revocation_ledger=ledger,
        at=POSTVERIFY_AT,
    )
    assert verified["state"] == POSTVERIFY_PASS
    assert store.pointer == prior

    promoted = c.promote_current()
    assert promoted["state"] == CURRENT
    assert store.pointer != prior
    assert promoted["history"] == [
        STAGED,
        VALIDATED,
        COMMITTED_NOT_CURRENT,
        POSTVERIFY_PASS,
        CURRENT,
    ]


def test_validation_failure_commits_nothing_and_preserves_pointer():
    fixture = list(_fixture())
    fixture[-1] = copy.deepcopy(fixture[-1])
    fixture[-1]["can_execute"] = True
    store, c, _, _, _, ledger, _ = _coordinator(fixture=tuple(fixture))
    prior = store.pointer

    result = c.validate(revocation_ledger=ledger, at=VALIDATE_AT)

    assert result["state"] == HOLD
    assert store.pointer == prior
    assert store.candidates == {}


def test_committed_not_current_is_observable_and_prior_remains_current():
    store, c, *_ = _through_commit()
    prior_sha = c.session.expected_pointer_sha256

    assert c.session.state == COMMITTED_NOT_CURRENT
    assert _sha(store.pointer) == prior_sha
    assert store.read_candidate_bytes(c.session.candidate_id) is not None


def test_postverify_revocation_failure_holds_and_preserves_exact_prior_pointer():
    store, c, identity, _, receipt, _, _ = _through_commit()
    prior = store.pointer
    entry = build_consent_revocation_entry(
        identity,
        receipt,
        revoking_principal="human:owner",
        revoking_principal_kind="HUMAN",
        revoked_at="2026-08-25T12:15:00Z",
        reason="synthetic revoke before postverify",
    )
    revoked = build_consent_revocation_ledger([entry])

    result = c.postverify(
        current_revocation_ledger=revoked,
        at=POSTVERIFY_AT,
    )

    assert result["state"] == HOLD
    assert "CONSENT_REVOKED" in result["reason"]
    assert store.pointer == prior


def test_stale_pointer_before_postverify_holds_without_overwrite():
    store, c, *rest = _through_commit()
    externally_advanced = b'{"candidate":"external-new-current"}'
    store.pointer = externally_advanced

    result = c.postverify(
        current_revocation_ledger=rest[3],
        at=POSTVERIFY_AT,
    )

    assert result["state"] == HOLD
    assert store.pointer == externally_advanced


def test_stale_pointer_at_atomic_promotion_holds_and_preserves_external_current():
    store, c, _, _, _, ledger, _ = _through_commit()
    assert c.postverify(
        current_revocation_ledger=ledger,
        at=POSTVERIFY_AT,
    )["state"] == POSTVERIFY_PASS

    externally_advanced = b'{"candidate":"external-new-current"}'
    store.pointer = externally_advanced
    result = c.promote_current()

    assert result["state"] == HOLD
    assert "stale current pointer" in result["reason"]
    assert store.pointer == externally_advanced


def test_candidate_hash_drift_after_commit_holds_before_promotion():
    store, c, _, _, _, ledger, _ = _through_commit()
    prior = store.pointer
    store.candidates[c.session.candidate_id] += b"\n"

    result = c.postverify(
        current_revocation_ledger=ledger,
        at=POSTVERIFY_AT,
    )

    assert result["state"] == HOLD
    assert "candidate bytes drift" in result["reason"]
    assert store.pointer == prior


def test_replay_same_candidate_identity_with_different_valid_bytes_holds():
    store = MemoryAdmissionStore()

    fixture1 = _fixture(
        admission_session_id="admission:synthetic:r3:replay",
        policy_version="policy/a",
    )
    store, c1, *_ = _through_commit(store, fixture=fixture1)
    first_bytes = store.read_candidate_bytes(c1.session.candidate_id)

    fixture2 = _fixture(
        admission_session_id="admission:synthetic:r3:replay",
        policy_version="policy/b",
    )
    _, c2, _, _, _, ledger2, record2 = _coordinator(
        store,
        fixture=fixture2,
        session_id="r3-session-2",
    )
    assert record2["id"] == c1.session.candidate_id
    assert c2.session.candidate_sha256 != c1.session.candidate_sha256
    assert c2.validate(revocation_ledger=ledger2, at=VALIDATE_AT)["state"] == VALIDATED

    result = c2.commit_not_current()

    assert result["state"] == HOLD
    assert "different bytes" in result["reason"]
    assert store.read_candidate_bytes(c1.session.candidate_id) == first_bytes


def test_direct_self_promotion_request_is_fail_closed():
    store, c, *_ = _coordinator()
    prior = store.pointer

    result = c.request_state(CURRENT)

    assert result["state"] == HOLD
    assert result["reason"] == "DIRECT_STATE_PROMOTION_FORBIDDEN"
    assert store.pointer == prior
    assert store.candidates == {}


def test_postverify_does_not_accept_candidate_removed_after_commit():
    store, c, _, _, _, ledger, _ = _through_commit()
    prior = store.pointer
    del store.candidates[c.session.candidate_id]

    result = c.postverify(
        current_revocation_ledger=ledger,
        at=POSTVERIFY_AT,
    )

    assert result["state"] == HOLD
    assert "candidate missing" in result["reason"]
    assert store.pointer == prior


@pytest.mark.parametrize("failure_point", ["validation", "postverify", "promotion"])
def test_every_failure_path_preserves_or_respects_last_known_good(failure_point):
    if failure_point == "validation":
        fixture = list(_fixture())
        fixture[-1] = copy.deepcopy(fixture[-1])
        fixture[-1]["execution_authority"] = "MODEL"
        store, c, _, _, _, ledger, _ = _coordinator(fixture=tuple(fixture))
        prior = store.pointer
        result = c.validate(revocation_ledger=ledger, at=VALIDATE_AT)
        assert result["state"] == HOLD
        assert store.pointer == prior
        return

    store, c, _, _, _, ledger, _ = _through_commit()
    if failure_point == "postverify":
        prior = store.pointer
        store.candidates[c.session.candidate_id] = b"{}"
        result = c.postverify(
            current_revocation_ledger=ledger,
            at=POSTVERIFY_AT,
        )
        assert result["state"] == HOLD
        assert store.pointer == prior
        return

    assert c.postverify(
        current_revocation_ledger=ledger,
        at=POSTVERIFY_AT,
    )["state"] == POSTVERIFY_PASS
    external = b'{"candidate":"new-lkg"}'
    store.pointer = external
    result = c.promote_current()
    assert result["state"] == HOLD
    assert store.pointer == external


def test_receipts_never_escalate_p3_p1_authority():
    store, c, _, _, _, ledger, _ = _coordinator()
    receipts = [
        c.staged(),
        c.validate(revocation_ledger=ledger, at=VALIDATE_AT),
        c.commit_not_current(),
        c.postverify(current_revocation_ledger=ledger, at=POSTVERIFY_AT),
        c.promote_current(),
    ]

    for receipt in receipts:
        assert receipt["production_admission_status"] == "NOT_PRODUCTION_ADMITTED"
        assert receipt["execution_authority"] == "NONE"
        assert receipt["can_execute"] is False
        assert receipt["can_trade"] is False
        assert receipt["capital_permission"] == "DENY"
