from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Mapping, Protocol

from .person_twin_admission_contracts import (
    NOT_PRODUCTION_ADMITTED,
    evaluate_consent,
    validate_consent_revocation_ledger,
    validate_person_twin_identity,
    validate_source_consent_receipt,
)
from .person_twin_privacy_provenance import validate_person_twin_record

SCHEMA_VERSION = "continuityos.person-twin.admission-coordinator/v1"
CURRENT_POINTER_SCHEMA_VERSION = "continuityos.person-twin.current-pointer/v1"

STAGED = "STAGED"
VALIDATED = "VALIDATED"
COMMITTED_NOT_CURRENT = "COMMITTED_NOT_CURRENT"
POSTVERIFY_PASS = "POSTVERIFY_PASS"
CURRENT = "CURRENT"
HOLD = "HOLD"
TERMINAL_STATES = {CURRENT, HOLD}


class PersonTwinAdmissionError(ValueError):
    pass


class AdmissionStoreError(RuntimeError):
    pass


class AdmissionStoreConflict(AdmissionStoreError):
    pass


class AdmissionStore(Protocol):
    """Minimal byte-level storage boundary required by the R3 coordinator.

    The implementation is deliberately outside R3. `promote_current_pointer` MUST
    perform compare-and-swap atomically: on expected-pointer mismatch it must raise
    AdmissionStoreConflict and leave the prior current pointer byte-identical.
    """

    def read_current_pointer_bytes(self) -> bytes | None: ...

    def read_candidate_bytes(self, candidate_id: str) -> bytes | None: ...

    def commit_candidate_not_current(
        self,
        candidate_id: str,
        candidate_bytes: bytes,
    ) -> None: ...

    def promote_current_pointer(
        self,
        *,
        expected_pointer_sha256: str | None,
        pointer_bytes: bytes,
    ) -> None: ...


def _canonical_bytes(value: Mapping[str, Any]) -> bytes:
    return json.dumps(
        dict(value),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _pointer_sha(payload: bytes | None) -> str | None:
    return None if payload is None else _sha256(payload)


def _require_nonempty(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise PersonTwinAdmissionError(f"{field} must be a non-empty string")
    return value.strip()


def _hold(reason: str, *, session: "AdmissionSession") -> dict[str, Any]:
    session.state = HOLD
    session.reason = reason
    session.history.append(HOLD)
    return session.receipt()


def _assert_state(session: "AdmissionSession", expected: str) -> None:
    if session.state != expected:
        raise PersonTwinAdmissionError(
            f"invalid admission transition: expected {expected}, got {session.state}"
        )


def _validate_candidate_ceiling(record: Mapping[str, Any]) -> None:
    if record.get("production_admission_status") != NOT_PRODUCTION_ADMITTED:
        raise PersonTwinAdmissionError("candidate cannot claim production admission")
    if record.get("execution_authority") != "NONE":
        raise PersonTwinAdmissionError("candidate execution_authority must remain NONE")
    if record.get("can_execute") is not False:
        raise PersonTwinAdmissionError("candidate can_execute must remain false")


def _consent_decision(
    *,
    identity: Mapping[str, Any],
    consent_receipt: Mapping[str, Any],
    revocation_ledger: Mapping[str, Any],
    source_record: Mapping[str, Any],
    purpose: str,
    at: str,
) -> Mapping[str, Any]:
    validate_consent_revocation_ledger(revocation_ledger)
    decision = evaluate_consent(
        identity,
        consent_receipt,
        revocation_ledger=revocation_ledger,
        at=at,
        requested_object_type=str(source_record["source_object_type"]),
        requested_scope=str(source_record["scope"]),
        purpose=purpose,
        require_source_read=False,
        require_memory_admission=True,
    )
    if decision.get("decision") != "ALLOW":
        raise PersonTwinAdmissionError(
            "consent denied at admission boundary: "
            + str(decision.get("reason") or "UNKNOWN")
        )
    return decision


@dataclass
class AdmissionSession:
    session_id: str
    candidate_id: str
    candidate_sha256: str
    identity_fingerprint: str
    expected_pointer_sha256: str | None
    state: str = STAGED
    reason: str = "STAGED"
    history: list[str] | None = None

    def __post_init__(self) -> None:
        if self.history is None:
            self.history = [STAGED]

    def receipt(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "session_id": self.session_id,
            "candidate_id": self.candidate_id,
            "candidate_sha256": self.candidate_sha256,
            "identity_fingerprint": self.identity_fingerprint,
            "expected_pointer_sha256": self.expected_pointer_sha256,
            "state": self.state,
            "reason": self.reason,
            "history": list(self.history or []),
            "production_admission_status": NOT_PRODUCTION_ADMITTED,
            "execution_authority": "NONE",
            "can_execute": False,
            "can_trade": False,
            "capital_permission": "DENY",
        }


class PersonTwinAdmissionCoordinator:
    """Fail-closed R3 coordinator over an existing storage boundary.

    The coordinator never creates storage, connectors, OAuth, deployment, or runtime
    authority. A candidate may be committed as non-current, but the current pointer
    changes only after deterministic post-verification and atomic OCC promotion.
    """

    def __init__(
        self,
        store: AdmissionStore,
        *,
        session_id: str,
        identity: Mapping[str, Any],
        consent_receipt: Mapping[str, Any],
        source_record: Mapping[str, Any],
        candidate_record: Mapping[str, Any],
        purpose: str,
    ):
        self.store = store
        self.identity = dict(identity)
        self.consent_receipt = dict(consent_receipt)
        self.source_record = dict(source_record)
        self.candidate_record = dict(candidate_record)
        self.purpose = _require_nonempty(purpose, "purpose")
        candidate_id = _require_nonempty(candidate_record.get("id"), "candidate.id")
        candidate_bytes = _canonical_bytes(self.candidate_record)
        self._candidate_bytes = candidate_bytes
        self.session = AdmissionSession(
            session_id=_require_nonempty(session_id, "session_id"),
            candidate_id=candidate_id,
            candidate_sha256=_sha256(candidate_bytes),
            identity_fingerprint=_require_nonempty(
                identity.get("identity_fingerprint"), "identity.identity_fingerprint"
            ),
            expected_pointer_sha256=_pointer_sha(store.read_current_pointer_bytes()),
        )

    def staged(self) -> dict[str, Any]:
        return self.session.receipt()

    def validate(
        self,
        *,
        revocation_ledger: Mapping[str, Any],
        at: str,
    ) -> dict[str, Any]:
        _assert_state(self.session, STAGED)
        try:
            validate_person_twin_identity(self.identity)
            validate_source_consent_receipt(self.identity, self.consent_receipt)
            validate_person_twin_record(
                self.candidate_record,
                identity=self.identity,
                consent_receipt=self.consent_receipt,
                source_record=self.source_record,
            )
            if self.candidate_record.get("identity_fingerprint") != self.session.identity_fingerprint:
                raise PersonTwinAdmissionError("candidate identity fingerprint drift")
            _validate_candidate_ceiling(self.candidate_record)
            _consent_decision(
                identity=self.identity,
                consent_receipt=self.consent_receipt,
                revocation_ledger=revocation_ledger,
                source_record=self.source_record,
                purpose=self.purpose,
                at=at,
            )
        except Exception as exc:
            return _hold(
                f"VALIDATION_FAILED:{type(exc).__name__}:{exc}",
                session=self.session,
            )
        self.session.state = VALIDATED
        self.session.reason = "EXACT_IDENTITY_CONSENT_PROVENANCE_VALIDATED"
        self.session.history.append(VALIDATED)
        return self.session.receipt()

    def commit_not_current(self) -> dict[str, Any]:
        _assert_state(self.session, VALIDATED)
        try:
            current_before = self.store.read_current_pointer_bytes()
            if _pointer_sha(current_before) != self.session.expected_pointer_sha256:
                raise AdmissionStoreConflict("current pointer drift before candidate commit")

            existing = self.store.read_candidate_bytes(self.session.candidate_id)
            if existing is not None and existing != self._candidate_bytes:
                raise AdmissionStoreConflict(
                    "candidate identity already exists with different bytes"
                )
            self.store.commit_candidate_not_current(
                self.session.candidate_id,
                self._candidate_bytes,
            )

            committed = self.store.read_candidate_bytes(self.session.candidate_id)
            if committed != self._candidate_bytes:
                raise AdmissionStoreError("committed candidate readback mismatch")
            if _sha256(committed) != self.session.candidate_sha256:
                raise AdmissionStoreError("committed candidate hash mismatch")
            current_after = self.store.read_current_pointer_bytes()
            if current_after != current_before:
                raise AdmissionStoreError(
                    "candidate commit modified current pointer before postverify"
                )
        except Exception as exc:
            return _hold(
                f"COMMIT_HOLD:{type(exc).__name__}:{exc}",
                session=self.session,
            )

        self.session.state = COMMITTED_NOT_CURRENT
        self.session.reason = "EXACT_CANDIDATE_COMMITTED_POINTER_UNCHANGED"
        self.session.history.append(COMMITTED_NOT_CURRENT)
        return self.session.receipt()

    def postverify(
        self,
        *,
        current_revocation_ledger: Mapping[str, Any],
        at: str,
    ) -> dict[str, Any]:
        _assert_state(self.session, COMMITTED_NOT_CURRENT)
        try:
            current_pointer = self.store.read_current_pointer_bytes()
            if _pointer_sha(current_pointer) != self.session.expected_pointer_sha256:
                raise AdmissionStoreConflict("current pointer drift before postverify")

            committed = self.store.read_candidate_bytes(self.session.candidate_id)
            if committed is None:
                raise AdmissionStoreError("committed candidate missing")
            if committed != self._candidate_bytes:
                raise AdmissionStoreConflict("candidate bytes drift after commit")
            if _sha256(committed) != self.session.candidate_sha256:
                raise AdmissionStoreConflict("candidate hash drift after commit")

            decoded = json.loads(committed.decode("utf-8"))
            if not isinstance(decoded, Mapping):
                raise PersonTwinAdmissionError("candidate root must be an object")
            validate_person_twin_identity(self.identity)
            validate_source_consent_receipt(self.identity, self.consent_receipt)
            validate_person_twin_record(
                decoded,
                identity=self.identity,
                consent_receipt=self.consent_receipt,
                source_record=self.source_record,
            )
            _validate_candidate_ceiling(decoded)
            _consent_decision(
                identity=self.identity,
                consent_receipt=self.consent_receipt,
                revocation_ledger=current_revocation_ledger,
                source_record=self.source_record,
                purpose=self.purpose,
                at=at,
            )
        except Exception as exc:
            return _hold(
                f"POSTVERIFY_HOLD:{type(exc).__name__}:{exc}",
                session=self.session,
            )

        self.session.state = POSTVERIFY_PASS
        self.session.reason = "POSTVERIFY_PASS_POINTER_STILL_LAST_KNOWN_GOOD"
        self.session.history.append(POSTVERIFY_PASS)
        return self.session.receipt()

    def promote_current(self) -> dict[str, Any]:
        _assert_state(self.session, POSTVERIFY_PASS)
        try:
            committed = self.store.read_candidate_bytes(self.session.candidate_id)
            if committed != self._candidate_bytes:
                raise AdmissionStoreConflict("candidate drift before promotion")
            if _sha256(committed) != self.session.candidate_sha256:
                raise AdmissionStoreConflict("candidate hash drift before promotion")

            pointer = {
                "schema_version": CURRENT_POINTER_SCHEMA_VERSION,
                "state": CURRENT,
                "twin_id": self.candidate_record["twin_id"],
                "candidate_id": self.session.candidate_id,
                "candidate_sha256": self.session.candidate_sha256,
                "identity_fingerprint": self.session.identity_fingerprint,
                "production_admission_status": NOT_PRODUCTION_ADMITTED,
                "execution_authority": "NONE",
                "can_execute": False,
            }
            pointer_bytes = _canonical_bytes(pointer)

            self.store.promote_current_pointer(
                expected_pointer_sha256=self.session.expected_pointer_sha256,
                pointer_bytes=pointer_bytes,
            )
            readback = self.store.read_current_pointer_bytes()
            if readback != pointer_bytes:
                raise AdmissionStoreError("promoted current pointer readback mismatch")
        except Exception as exc:
            return _hold(
                f"PROMOTION_HOLD:{type(exc).__name__}:{exc}",
                session=self.session,
            )

        self.session.state = CURRENT
        self.session.reason = "EXACT_POSTVERIFIED_CANDIDATE_PROMOTED_BY_OCC"
        self.session.history.append(CURRENT)
        return self.session.receipt()

    def request_state(self, desired_state: str) -> dict[str, Any]:
        """No caller/model/agent may set a terminal state directly."""
        del desired_state
        if self.session.state in TERMINAL_STATES:
            return self.session.receipt()
        return _hold("DIRECT_STATE_PROMOTION_FORBIDDEN", session=self.session)
