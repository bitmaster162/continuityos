from __future__ import annotations

import copy
import hashlib
import json
from typing import Any, Mapping

from .person_twin_admission_contracts import (
    NOT_PRODUCTION_ADMITTED,
    PersonTwinContractError,
    evaluate_consent,
    validate_consent_revocation_ledger,
    validate_person_twin_identity,
    validate_source_consent_receipt,
)
from .person_twin_privacy_provenance import (
    PersonTwinPrivacyProvenanceError,
    validate_person_twin_record,
)

COORDINATOR_SCHEMA_VERSION = "continuityos.person-twin.admission-coordinator/v1"
POINTER_SCHEMA_VERSION = "continuityos.person-twin.synthetic-current-pointer/v1"
PROMOTION_RECEIPT_SCHEMA_VERSION = "continuityos.person-twin.synthetic-promotion-receipt/v1"

AUTHORIZED = "AUTHORIZED"
STAGED = "STAGED"
SCANNED = "SCANNED"
CLASSIFIED = "CLASSIFIED"
ADMISSIBLE = "ADMISSIBLE"
QUARANTINED = "QUARANTINED"
REJECTED = "REJECTED"
COMMITTED_NON_CURRENT = "COMMITTED_NON_CURRENT"
POSTVERIFY_HOLD = "POSTVERIFY_HOLD"
VERIFIED_NON_CURRENT = "VERIFIED_NON_CURRENT"
CURRENT = "CURRENT"
ALL_STATES = {
    AUTHORIZED,
    STAGED,
    SCANNED,
    CLASSIFIED,
    ADMISSIBLE,
    QUARANTINED,
    REJECTED,
    COMMITTED_NON_CURRENT,
    POSTVERIFY_HOLD,
    VERIFIED_NON_CURRENT,
    CURRENT,
}


class PersonTwinAdmissionCoordinatorError(ValueError):
    pass


def _canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _hash(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _non_empty(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise PersonTwinAdmissionCoordinatorError(f"{field} must be a non-empty string")
    return value


def _sha256(value: Any, field: str) -> str:
    text = _non_empty(value, field)
    if len(text) != 64 or any(ch not in "0123456789abcdef" for ch in text):
        raise PersonTwinAdmissionCoordinatorError(
            f"{field} must be a lowercase sha256 hex digest"
        )
    return text


def _without_hash(value: Mapping[str, Any], field: str) -> dict[str, Any]:
    return {key: copy.deepcopy(item) for key, item in value.items() if key != field}


def _rehash_session(session: Mapping[str, Any]) -> dict[str, Any]:
    result = _without_hash(session, "session_hash")
    result["session_hash"] = _hash(result)
    return result


def _rehash_pointer(pointer: Mapping[str, Any]) -> dict[str, Any]:
    result = _without_hash(pointer, "pointer_hash")
    result["pointer_hash"] = _hash(result)
    return result


def _candidate_body(session: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "tenant_id": session["tenant_id"],
        "twin_id": session["twin_id"],
        "identity_fingerprint": session["identity_fingerprint"],
        "person_record_id": session["person_record_id"],
        "provenance_hash": session["provenance_hash"],
        "consent_receipt_id": session["consent_receipt_id"],
        "consent_receipt_hash": session["consent_receipt_hash"],
        "revocation_ledger_hash": session["revocation_ledger_hash"],
        "source_record_id": session["source_record_id"],
        "privacy_class": session["privacy_class"],
        "scope": session["scope"],
        "purpose": session["purpose"],
        "admission_session_id": session["session_id"],
    }


def build_synthetic_current_pointer(
    identity: Mapping[str, Any],
    *,
    current_candidate_id: str | None = None,
    current_candidate_hash: str | None = None,
    generation: int = 0,
) -> dict[str, Any]:
    """Build an in-memory pointer fixture only; no real current pointer is touched."""
    try:
        validate_person_twin_identity(identity)
    except PersonTwinContractError as exc:
        raise PersonTwinAdmissionCoordinatorError(str(exc)) from exc
    if not isinstance(generation, int) or isinstance(generation, bool) or generation < 0:
        raise PersonTwinAdmissionCoordinatorError("generation must be a non-negative integer")
    if (current_candidate_id is None) != (current_candidate_hash is None):
        raise PersonTwinAdmissionCoordinatorError(
            "current candidate id/hash must both be present or null"
        )
    if current_candidate_id is not None:
        _non_empty(current_candidate_id, "current_candidate_id")
        _sha256(current_candidate_hash, "current_candidate_hash")
    if (generation == 0) != (current_candidate_id is None):
        raise PersonTwinAdmissionCoordinatorError(
            "generation/current candidate invariant mismatch"
        )
    pointer = {
        "schema_version": POINTER_SCHEMA_VERSION,
        "tenant_id": identity["tenant_id"],
        "twin_id": identity["twin_id"],
        "identity_fingerprint": identity["identity_fingerprint"],
        "current_candidate_id": current_candidate_id,
        "current_candidate_hash": current_candidate_hash,
        "last_known_good_candidate_id": current_candidate_id,
        "last_known_good_candidate_hash": current_candidate_hash,
        "generation": generation,
        "synthetic_only": True,
        "real_current_pointer_mutated": False,
        "production_admission_status": NOT_PRODUCTION_ADMITTED,
        "execution_authority": "NONE",
        "can_execute": False,
    }
    result = _rehash_pointer(pointer)
    validate_synthetic_current_pointer(result, identity=identity)
    return result


def validate_synthetic_current_pointer(
    pointer: Mapping[str, Any], *, identity: Mapping[str, Any]
) -> None:
    try:
        validate_person_twin_identity(identity)
    except PersonTwinContractError as exc:
        raise PersonTwinAdmissionCoordinatorError(str(exc)) from exc
    required = {
        "schema_version",
        "tenant_id",
        "twin_id",
        "identity_fingerprint",
        "current_candidate_id",
        "current_candidate_hash",
        "last_known_good_candidate_id",
        "last_known_good_candidate_hash",
        "generation",
        "synthetic_only",
        "real_current_pointer_mutated",
        "production_admission_status",
        "execution_authority",
        "can_execute",
        "pointer_hash",
    }
    if set(pointer) != required:
        raise PersonTwinAdmissionCoordinatorError("synthetic current pointer shape mismatch")
    if pointer["schema_version"] != POINTER_SCHEMA_VERSION:
        raise PersonTwinAdmissionCoordinatorError("unsupported synthetic pointer schema")
    if pointer["tenant_id"] != identity["tenant_id"] or pointer["twin_id"] != identity["twin_id"]:
        raise PersonTwinAdmissionCoordinatorError("pointer tenant/twin mismatch")
    if pointer["identity_fingerprint"] != identity["identity_fingerprint"]:
        raise PersonTwinAdmissionCoordinatorError("pointer identity fingerprint mismatch")
    generation = pointer["generation"]
    if not isinstance(generation, int) or isinstance(generation, bool) or generation < 0:
        raise PersonTwinAdmissionCoordinatorError("pointer generation invalid")
    cid = pointer["current_candidate_id"]
    chash = pointer["current_candidate_hash"]
    if (cid is None) != (chash is None):
        raise PersonTwinAdmissionCoordinatorError("pointer current id/hash mismatch")
    if cid is not None:
        _non_empty(cid, "current_candidate_id")
        _sha256(chash, "current_candidate_hash")
    if (generation == 0) != (cid is None):
        raise PersonTwinAdmissionCoordinatorError("pointer generation/current invariant mismatch")
    if (
        pointer["last_known_good_candidate_id"] != cid
        or pointer["last_known_good_candidate_hash"] != chash
    ):
        raise PersonTwinAdmissionCoordinatorError("last-known-good must equal current")
    if pointer["synthetic_only"] is not True or pointer["real_current_pointer_mutated"] is not False:
        raise PersonTwinAdmissionCoordinatorError("R3 pointer must remain synthetic-only")
    if pointer["production_admission_status"] != NOT_PRODUCTION_ADMITTED:
        raise PersonTwinAdmissionCoordinatorError("R3 pointer cannot claim production admission")
    if pointer["execution_authority"] != "NONE" or pointer["can_execute"] is not False:
        raise PersonTwinAdmissionCoordinatorError("R3 pointer cannot grant execution authority")
    if _sha256(pointer["pointer_hash"], "pointer_hash") != _hash(
        _without_hash(pointer, "pointer_hash")
    ):
        raise PersonTwinAdmissionCoordinatorError("pointer_hash mismatch")


def validate_admission_session(session: Mapping[str, Any]) -> None:
    required = {
        "schema_version",
        "session_id",
        "candidate_id",
        "candidate_hash",
        "tenant_id",
        "twin_id",
        "identity_fingerprint",
        "person_record_id",
        "provenance_hash",
        "consent_receipt_id",
        "consent_receipt_hash",
        "revocation_ledger_hash",
        "source_record_id",
        "privacy_class",
        "scope",
        "purpose",
        "state",
        "state_seq",
        "scan_evidence_hash",
        "classification_evidence_hash",
        "commit_hash",
        "postverify_observed_candidate_hash",
        "postverify_observed_provenance_hash",
        "postverify_reason",
        "base_pointer_hash",
        "base_generation",
        "base_current_candidate_id",
        "base_current_candidate_hash",
        "synthetic_only",
        "real_current_pointer_mutated",
        "production_admission_status",
        "execution_authority",
        "can_execute",
        "session_hash",
    }
    if set(session) != required:
        raise PersonTwinAdmissionCoordinatorError("admission session shape mismatch")
    if session["schema_version"] != COORDINATOR_SCHEMA_VERSION:
        raise PersonTwinAdmissionCoordinatorError("unsupported admission coordinator schema")
    for field in (
        "session_id",
        "candidate_id",
        "tenant_id",
        "twin_id",
        "person_record_id",
        "consent_receipt_id",
        "source_record_id",
        "privacy_class",
        "scope",
        "purpose",
    ):
        _non_empty(session[field], field)
    for field in (
        "candidate_hash",
        "identity_fingerprint",
        "provenance_hash",
        "consent_receipt_hash",
        "revocation_ledger_hash",
        "base_pointer_hash",
        "session_hash",
    ):
        _sha256(session[field], field)
    if session["state"] not in ALL_STATES:
        raise PersonTwinAdmissionCoordinatorError("unsupported admission state")
    if (
        not isinstance(session["state_seq"], int)
        or isinstance(session["state_seq"], bool)
        or session["state_seq"] < 1
    ):
        raise PersonTwinAdmissionCoordinatorError("state_seq invalid")
    if (
        not isinstance(session["base_generation"], int)
        or isinstance(session["base_generation"], bool)
        or session["base_generation"] < 0
    ):
        raise PersonTwinAdmissionCoordinatorError("base_generation invalid")
    if (session["base_current_candidate_id"] is None) != (
        session["base_current_candidate_hash"] is None
    ):
        raise PersonTwinAdmissionCoordinatorError("base current id/hash mismatch")
    if session["base_current_candidate_hash"] is not None:
        _sha256(session["base_current_candidate_hash"], "base_current_candidate_hash")
    for field in (
        "scan_evidence_hash",
        "classification_evidence_hash",
        "commit_hash",
        "postverify_observed_candidate_hash",
        "postverify_observed_provenance_hash",
    ):
        if session[field] is not None:
            _sha256(session[field], field)
    if session["synthetic_only"] is not True or session["real_current_pointer_mutated"] is not False:
        raise PersonTwinAdmissionCoordinatorError("R3 session must remain synthetic-only")
    if session["production_admission_status"] != NOT_PRODUCTION_ADMITTED:
        raise PersonTwinAdmissionCoordinatorError("R3 session cannot claim production admission")
    if session["execution_authority"] != "NONE" or session["can_execute"] is not False:
        raise PersonTwinAdmissionCoordinatorError("R3 session cannot grant execution authority")

    expected_hash = _hash(_candidate_body(session))
    if (
        session["candidate_hash"] != expected_hash
        or session["candidate_id"] != f"ptac_{expected_hash[:32]}"
    ):
        raise PersonTwinAdmissionCoordinatorError("candidate identity/hash mismatch")
    if session["session_hash"] != _hash(_without_hash(session, "session_hash")):
        raise PersonTwinAdmissionCoordinatorError("session_hash mismatch")

    state = session["state"]
    scan = session["scan_evidence_hash"]
    classified = session["classification_evidence_hash"]
    commit = session["commit_hash"]
    observed = (
        session["postverify_observed_candidate_hash"],
        session["postverify_observed_provenance_hash"],
    )
    if state in {AUTHORIZED, STAGED} and any(
        value is not None for value in (scan, classified, commit, *observed)
    ):
        raise PersonTwinAdmissionCoordinatorError("early state carries later-stage evidence")
    if state == SCANNED and (
        scan is None or any(value is not None for value in (classified, commit, *observed))
    ):
        raise PersonTwinAdmissionCoordinatorError("SCANNED evidence invariant mismatch")
    if state in {CLASSIFIED, ADMISSIBLE} and (
        scan is None
        or classified is None
        or commit is not None
        or any(value is not None for value in observed)
    ):
        raise PersonTwinAdmissionCoordinatorError("classified/admissible evidence invariant mismatch")
    if state == COMMITTED_NON_CURRENT and (
        scan is None
        or classified is None
        or commit is None
        or any(value is not None for value in observed)
    ):
        raise PersonTwinAdmissionCoordinatorError("commit evidence invariant mismatch")
    if state in {POSTVERIFY_HOLD, VERIFIED_NON_CURRENT, CURRENT} and (
        scan is None
        or classified is None
        or commit is None
        or any(value is None for value in observed)
    ):
        raise PersonTwinAdmissionCoordinatorError("postverify evidence invariant mismatch")


def _transition(
    session: Mapping[str, Any], expected: str, target: str, **updates: Any
) -> dict[str, Any]:
    validate_admission_session(session)
    if session["state"] != expected:
        raise PersonTwinAdmissionCoordinatorError(
            f"transition requires {expected}, got {session['state']}"
        )
    result = _without_hash(session, "session_hash")
    result.update(copy.deepcopy(updates))
    result["state"] = target
    result["state_seq"] = int(session["state_seq"]) + 1
    result = _rehash_session(result)
    validate_admission_session(result)
    return result


def _validate_live_evidence(
    session: Mapping[str, Any],
    *,
    identity: Mapping[str, Any],
    consent_receipt: Mapping[str, Any],
    revocation_ledger: Mapping[str, Any],
    source_record: Mapping[str, Any],
    person_record: Mapping[str, Any],
    purpose: str,
    at: str,
) -> None:
    try:
        validate_person_twin_identity(identity)
        validate_source_consent_receipt(identity, consent_receipt)
        validate_consent_revocation_ledger(revocation_ledger)
        validate_person_twin_record(
            person_record,
            identity=identity,
            consent_receipt=consent_receipt,
            source_record=source_record,
        )
    except (PersonTwinContractError, PersonTwinPrivacyProvenanceError) as exc:
        raise PersonTwinAdmissionCoordinatorError(str(exc)) from exc

    decision = evaluate_consent(
        identity,
        consent_receipt,
        revocation_ledger=revocation_ledger,
        at=at,
        requested_object_type=str(source_record["source_object_type"]),
        requested_scope=str(person_record["scope"]),
        purpose=purpose,
        require_source_read=False,
        require_memory_admission=True,
    )
    if decision.get("decision") != "ALLOW":
        raise PersonTwinAdmissionCoordinatorError(
            f"consent denied at admission boundary: {decision.get('reason', 'UNKNOWN')}"
        )
    if person_record["revocation_ledger_hash"] != revocation_ledger["ledger_hash"]:
        raise PersonTwinAdmissionCoordinatorError(
            "record is not bound to the current revocation ledger"
        )

    exact = {
        "tenant_id": identity["tenant_id"],
        "twin_id": identity["twin_id"],
        "identity_fingerprint": identity["identity_fingerprint"],
        "person_record_id": person_record["id"],
        "provenance_hash": person_record["provenance_hash"],
        "consent_receipt_id": consent_receipt["consent_receipt_id"],
        "consent_receipt_hash": consent_receipt["receipt_hash"],
        "revocation_ledger_hash": revocation_ledger["ledger_hash"],
        "source_record_id": source_record["id"],
        "privacy_class": person_record["privacy_class"],
        "scope": person_record["scope"],
        "purpose": purpose,
    }
    for field, value in exact.items():
        if session.get(field) != value:
            raise PersonTwinAdmissionCoordinatorError(
                f"admission evidence drift detected: {field}"
            )


def begin_admission(
    identity: Mapping[str, Any],
    consent_receipt: Mapping[str, Any],
    revocation_ledger: Mapping[str, Any],
    source_record: Mapping[str, Any],
    person_record: Mapping[str, Any],
    current_pointer: Mapping[str, Any],
    *,
    purpose: str,
    at: str,
) -> dict[str, Any]:
    validate_synthetic_current_pointer(current_pointer, identity=identity)
    purpose = _non_empty(purpose, "purpose")
    at = _non_empty(at, "at")
    seed = {
        "schema_version": COORDINATOR_SCHEMA_VERSION,
        "session_id": _non_empty(
            person_record.get("admission_session_id"), "admission_session_id"
        ),
        "candidate_id": "placeholder",
        "candidate_hash": "0" * 64,
        "tenant_id": identity.get("tenant_id"),
        "twin_id": identity.get("twin_id"),
        "identity_fingerprint": identity.get("identity_fingerprint"),
        "person_record_id": person_record.get("id"),
        "provenance_hash": person_record.get("provenance_hash"),
        "consent_receipt_id": consent_receipt.get("consent_receipt_id"),
        "consent_receipt_hash": consent_receipt.get("receipt_hash"),
        "revocation_ledger_hash": revocation_ledger.get("ledger_hash"),
        "source_record_id": source_record.get("id"),
        "privacy_class": person_record.get("privacy_class"),
        "scope": person_record.get("scope"),
        "purpose": purpose,
        "state": AUTHORIZED,
        "state_seq": 1,
        "scan_evidence_hash": None,
        "classification_evidence_hash": None,
        "commit_hash": None,
        "postverify_observed_candidate_hash": None,
        "postverify_observed_provenance_hash": None,
        "postverify_reason": None,
        "base_pointer_hash": current_pointer["pointer_hash"],
        "base_generation": current_pointer["generation"],
        "base_current_candidate_id": current_pointer["current_candidate_id"],
        "base_current_candidate_hash": current_pointer["current_candidate_hash"],
        "synthetic_only": True,
        "real_current_pointer_mutated": False,
        "production_admission_status": NOT_PRODUCTION_ADMITTED,
        "execution_authority": "NONE",
        "can_execute": False,
    }
    seed["candidate_hash"] = _hash(_candidate_body(seed))
    seed["candidate_id"] = f"ptac_{seed['candidate_hash'][:32]}"
    result = _rehash_session(seed)
    validate_admission_session(result)
    _validate_live_evidence(
        result,
        identity=identity,
        consent_receipt=consent_receipt,
        revocation_ledger=revocation_ledger,
        source_record=source_record,
        person_record=person_record,
        purpose=purpose,
        at=at,
    )
    return result


def stage_candidate(session: Mapping[str, Any]) -> dict[str, Any]:
    return _transition(session, AUTHORIZED, STAGED)


def record_scan(
    session: Mapping[str, Any], *, passed: bool, scan_evidence_hash: str
) -> dict[str, Any]:
    if not isinstance(passed, bool):
        raise PersonTwinAdmissionCoordinatorError("passed must be boolean")
    evidence = _sha256(scan_evidence_hash, "scan_evidence_hash")
    if not passed:
        return _transition(
            session,
            STAGED,
            QUARANTINED,
            scan_evidence_hash=evidence,
            postverify_reason="SCAN_FAILED",
        )
    return _transition(session, STAGED, SCANNED, scan_evidence_hash=evidence)


def classify_candidate(
    session: Mapping[str, Any],
    *,
    privacy_class: str,
    scope: str,
    classification_evidence_hash: str,
) -> dict[str, Any]:
    validate_admission_session(session)
    if privacy_class != session["privacy_class"] or scope != session["scope"]:
        raise PersonTwinAdmissionCoordinatorError(
            "classification cannot widen or alter R2 privacy/scope"
        )
    return _transition(
        session,
        SCANNED,
        CLASSIFIED,
        classification_evidence_hash=_sha256(
            classification_evidence_hash, "classification_evidence_hash"
        ),
    )


def mark_admissible(
    session: Mapping[str, Any],
    *,
    identity: Mapping[str, Any],
    consent_receipt: Mapping[str, Any],
    revocation_ledger: Mapping[str, Any],
    source_record: Mapping[str, Any],
    person_record: Mapping[str, Any],
    purpose: str,
    at: str,
) -> dict[str, Any]:
    validate_admission_session(session)
    if session["state"] != CLASSIFIED:
        raise PersonTwinAdmissionCoordinatorError(
            f"transition requires {CLASSIFIED}, got {session['state']}"
        )
    _validate_live_evidence(
        session,
        identity=identity,
        consent_receipt=consent_receipt,
        revocation_ledger=revocation_ledger,
        source_record=source_record,
        person_record=person_record,
        purpose=purpose,
        at=at,
    )
    return _transition(session, CLASSIFIED, ADMISSIBLE)


def reject_candidate(session: Mapping[str, Any], *, reason: str) -> dict[str, Any]:
    validate_admission_session(session)
    if session["state"] not in {AUTHORIZED, STAGED, SCANNED, CLASSIFIED, ADMISSIBLE}:
        raise PersonTwinAdmissionCoordinatorError("candidate can no longer be rejected")
    result = _without_hash(session, "session_hash")
    result["state"] = REJECTED
    result["state_seq"] = int(session["state_seq"]) + 1
    result["postverify_reason"] = _non_empty(reason, "reason")
    result = _rehash_session(result)
    validate_admission_session(result)
    return result


def _pointer_matches_base(
    session: Mapping[str, Any], pointer: Mapping[str, Any]
) -> bool:
    return (
        pointer["pointer_hash"] == session["base_pointer_hash"]
        and pointer["generation"] == session["base_generation"]
        and pointer["current_candidate_id"] == session["base_current_candidate_id"]
        and pointer["current_candidate_hash"] == session["base_current_candidate_hash"]
    )


def commit_non_current(
    session: Mapping[str, Any],
    current_pointer: Mapping[str, Any],
    *,
    identity: Mapping[str, Any],
    consent_receipt: Mapping[str, Any],
    revocation_ledger: Mapping[str, Any],
    source_record: Mapping[str, Any],
    person_record: Mapping[str, Any],
    purpose: str,
    at: str,
) -> dict[str, Any]:
    validate_admission_session(session)
    if session["state"] != ADMISSIBLE:
        raise PersonTwinAdmissionCoordinatorError(
            f"transition requires {ADMISSIBLE}, got {session['state']}"
        )
    validate_synthetic_current_pointer(current_pointer, identity=identity)
    if not _pointer_matches_base(session, current_pointer):
        raise PersonTwinAdmissionCoordinatorError(
            "stale synthetic current pointer at commit"
        )
    _validate_live_evidence(
        session,
        identity=identity,
        consent_receipt=consent_receipt,
        revocation_ledger=revocation_ledger,
        source_record=source_record,
        person_record=person_record,
        purpose=purpose,
        at=at,
    )
    commit_hash = _hash(
        {
            "candidate_id": session["candidate_id"],
            "candidate_hash": session["candidate_hash"],
            "provenance_hash": session["provenance_hash"],
            "base_pointer_hash": current_pointer["pointer_hash"],
            "base_generation": current_pointer["generation"],
            "state": COMMITTED_NON_CURRENT,
        }
    )
    return _transition(
        session,
        ADMISSIBLE,
        COMMITTED_NON_CURRENT,
        commit_hash=commit_hash,
    )


def post_commit_verify(
    session: Mapping[str, Any],
    current_pointer: Mapping[str, Any],
    *,
    identity: Mapping[str, Any],
    consent_receipt: Mapping[str, Any],
    revocation_ledger: Mapping[str, Any],
    source_record: Mapping[str, Any],
    person_record: Mapping[str, Any],
    purpose: str,
    at: str,
    observed_candidate_hash: str,
    observed_provenance_hash: str,
    observed_record_count: int,
) -> dict[str, Any]:
    validate_admission_session(session)
    if session["state"] != COMMITTED_NON_CURRENT:
        raise PersonTwinAdmissionCoordinatorError(
            f"transition requires {COMMITTED_NON_CURRENT}, got {session['state']}"
        )
    validate_synthetic_current_pointer(current_pointer, identity=identity)
    candidate_hash = _sha256(observed_candidate_hash, "observed_candidate_hash")
    provenance_hash = _sha256(observed_provenance_hash, "observed_provenance_hash")
    if not isinstance(observed_record_count, int) or isinstance(observed_record_count, bool):
        raise PersonTwinAdmissionCoordinatorError(
            "observed_record_count must be an integer"
        )
    updates = {
        "postverify_observed_candidate_hash": candidate_hash,
        "postverify_observed_provenance_hash": provenance_hash,
    }
    if not _pointer_matches_base(session, current_pointer):
        return _transition(
            session,
            COMMITTED_NON_CURRENT,
            POSTVERIFY_HOLD,
            postverify_reason="CURRENT_POINTER_DRIFT",
            **updates,
        )
    try:
        _validate_live_evidence(
            session,
            identity=identity,
            consent_receipt=consent_receipt,
            revocation_ledger=revocation_ledger,
            source_record=source_record,
            person_record=person_record,
            purpose=purpose,
            at=at,
        )
    except PersonTwinAdmissionCoordinatorError as exc:
        return _transition(
            session,
            COMMITTED_NON_CURRENT,
            POSTVERIFY_HOLD,
            postverify_reason=f"LIVE_EVIDENCE_INVALID:{exc}",
            **updates,
        )
    reason = None
    if candidate_hash != session["candidate_hash"]:
        reason = "CANDIDATE_HASH_MISMATCH"
    elif provenance_hash != session["provenance_hash"]:
        reason = "PROVENANCE_HASH_MISMATCH"
    elif observed_record_count != 1:
        reason = "RECORD_COUNT_MISMATCH"
    if reason:
        return _transition(
            session,
            COMMITTED_NON_CURRENT,
            POSTVERIFY_HOLD,
            postverify_reason=reason,
            **updates,
        )
    return _transition(
        session,
        COMMITTED_NON_CURRENT,
        VERIFIED_NON_CURRENT,
        postverify_reason="POST_COMMIT_VERIFY_PASS",
        **updates,
    )


def promote_verified_candidate(
    session: Mapping[str, Any],
    current_pointer: Mapping[str, Any],
    *,
    identity: Mapping[str, Any],
    expected_generation: int,
    expected_current_candidate_id: str | None,
    expected_current_candidate_hash: str | None,
) -> dict[str, Any]:
    """Pure CAS promotion: returns a replacement synthetic pointer, never performs I/O."""
    validate_admission_session(session)
    if session["state"] != VERIFIED_NON_CURRENT:
        raise PersonTwinAdmissionCoordinatorError(
            f"promotion requires {VERIFIED_NON_CURRENT}, got {session['state']}"
        )
    validate_synthetic_current_pointer(current_pointer, identity=identity)
    if (
        not isinstance(expected_generation, int)
        or isinstance(expected_generation, bool)
        or expected_generation < 0
    ):
        raise PersonTwinAdmissionCoordinatorError("expected_generation invalid")
    if (expected_current_candidate_id is None) != (
        expected_current_candidate_hash is None
    ):
        raise PersonTwinAdmissionCoordinatorError("expected current id/hash mismatch")
    if expected_current_candidate_hash is not None:
        _sha256(expected_current_candidate_hash, "expected_current_candidate_hash")

    expected = {
        "generation": expected_generation,
        "current_candidate_id": expected_current_candidate_id,
        "current_candidate_hash": expected_current_candidate_hash,
    }
    actual = {
        "generation": current_pointer["generation"],
        "current_candidate_id": current_pointer["current_candidate_id"],
        "current_candidate_hash": current_pointer["current_candidate_hash"],
    }
    base_matches = _pointer_matches_base(session, current_pointer)
    cas_matches = expected == actual
    if not base_matches or not cas_matches:
        receipt = {
            "schema_version": PROMOTION_RECEIPT_SCHEMA_VERSION,
            "decision": "HOLD",
            "reason": (
                "STALE_CURRENT_POINTER"
                if not base_matches
                else "CAS_EXPECTATION_MISMATCH"
            ),
            "candidate_id": session["candidate_id"],
            "candidate_hash": session["candidate_hash"],
            "candidate_state": VERIFIED_NON_CURRENT,
            "expected": expected,
            "actual": actual,
            "current_pointer": copy.deepcopy(dict(current_pointer)),
            "last_known_good_preserved": True,
            "real_current_pointer_mutated": False,
            "production_admission_status": NOT_PRODUCTION_ADMITTED,
            "execution_authority": "NONE",
            "can_execute": False,
        }
        receipt["receipt_hash"] = _hash(receipt)
        return receipt

    new_pointer = build_synthetic_current_pointer(
        identity,
        current_candidate_id=session["candidate_id"],
        current_candidate_hash=session["candidate_hash"],
        generation=current_pointer["generation"] + 1,
    )
    current_session = _transition(
        session,
        VERIFIED_NON_CURRENT,
        CURRENT,
        postverify_reason="EXPLICIT_CAS_PROMOTION_PASS",
    )
    receipt = {
        "schema_version": PROMOTION_RECEIPT_SCHEMA_VERSION,
        "decision": "PROMOTED",
        "reason": "EXPLICIT_CAS_PROMOTION_PASS",
        "candidate_id": session["candidate_id"],
        "candidate_hash": session["candidate_hash"],
        "candidate_state": CURRENT,
        "expected": expected,
        "actual": actual,
        "previous_current_pointer": copy.deepcopy(dict(current_pointer)),
        "current_pointer": new_pointer,
        "current_session": current_session,
        "last_known_good_preserved": True,
        "real_current_pointer_mutated": False,
        "production_admission_status": NOT_PRODUCTION_ADMITTED,
        "execution_authority": "NONE",
        "can_execute": False,
    }
    receipt["receipt_hash"] = _hash(receipt)
    return receipt
