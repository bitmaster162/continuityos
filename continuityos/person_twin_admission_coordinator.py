from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Mapping, Protocol

from .person_twin_admission_contracts import (
    NOT_PRODUCTION_ADMITTED,
    evaluate_consent,
    validate_consent_revocation_ledger,
    validate_person_twin_identity,
    validate_source_consent_receipt,
)
from .person_twin_privacy_provenance import validate_person_twin_record

SCHEMA_VERSION = "continuityos.person-twin.admission-coordinator/v2"
CURRENT_POINTER_SCHEMA_VERSION = "continuityos.person-twin.current-pointer/v1"

STAGED = "STAGED"
VALIDATED = "VALIDATED"
COMMITTED_NOT_CURRENT = "COMMITTED_NOT_CURRENT"
POSTVERIFY_PASS = "POSTVERIFY_PASS"
CURRENT = "CURRENT"
HOLD = "HOLD"
TERMINAL_STATES = {CURRENT, HOLD}

_ALLOWED_PREFIXES = {
    STAGED: (STAGED,),
    VALIDATED: (STAGED, VALIDATED),
    COMMITTED_NOT_CURRENT: (STAGED, VALIDATED, COMMITTED_NOT_CURRENT),
    POSTVERIFY_PASS: (STAGED, VALIDATED, COMMITTED_NOT_CURRENT, POSTVERIFY_PASS),
    CURRENT: (STAGED, VALIDATED, COMMITTED_NOT_CURRENT, POSTVERIFY_PASS, CURRENT),
}


class PersonTwinAdmissionError(ValueError):
    pass


class AdmissionStoreError(RuntimeError):
    pass


class AdmissionStoreConflict(AdmissionStoreError):
    pass


class AdmissionStore(Protocol):
    """Minimal byte-level storage boundary required by the R3 coordinator.

    `promote_current_pointer` MUST perform compare-and-swap atomically: on an
    expected-pointer mismatch it must raise AdmissionStoreConflict and leave the
    prior current pointer byte-identical.
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


@dataclass(frozen=True)
class _AdmissionState:
    state: str
    reason: str
    history: tuple[str, ...]
    proof: str


class PersonTwinAdmissionCoordinator:
    """Fail-closed Person Twin admission coordinator over a byte-level store.

    R3R1 keeps transition state private and immutable, revalidates current consent
    and the exact revocation-ledger binding at every material boundary, commits
    candidate bytes as non-current, post-verifies readback, and promotes only by
    an atomic OCC/CAS current-pointer write.
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

        self.session_id = _require_nonempty(session_id, "session_id")
        self.candidate_id = _require_nonempty(candidate_record.get("id"), "candidate.id")
        self._candidate_bytes = _canonical_bytes(self.candidate_record)
        self.candidate_sha256 = _sha256(self._candidate_bytes)
        self.identity_fingerprint = _require_nonempty(
            identity.get("identity_fingerprint"),
            "identity.identity_fingerprint",
        )
        self.expected_pointer_sha256 = _pointer_sha(store.read_current_pointer_bytes())

        secret_seed = (
            f"{self.session_id}|{self.candidate_sha256}|"
            f"{self.identity_fingerprint}|{id(self)}"
        ).encode("utf-8")
        self.__transition_secret = hashlib.sha256(secret_seed).digest()
        self.__state = self._make_state(STAGED, "STAGED", (STAGED,))

    @property
    def session(self) -> Mapping[str, Any]:
        """Read-only session view; callers cannot set state/history directly."""
        return MappingProxyType(self._receipt_dict())

    def staged(self) -> dict[str, Any]:
        self._assert_integrity()
        return self.receipt()

    def receipt(self) -> dict[str, Any]:
        self._assert_integrity()
        return self._receipt_dict()

    def _state_proof(
        self,
        state: str,
        reason: str,
        history: tuple[str, ...],
    ) -> str:
        payload = _canonical_bytes(
            {
                "session_id": self.session_id,
                "candidate_id": self.candidate_id,
                "candidate_sha256": self.candidate_sha256,
                "identity_fingerprint": self.identity_fingerprint,
                "expected_pointer_sha256": self.expected_pointer_sha256,
                "state": state,
                "reason": reason,
                "history": list(history),
            }
        )
        return hmac.new(self.__transition_secret, payload, hashlib.sha256).hexdigest()

    def _make_state(
        self,
        state: str,
        reason: str,
        history: tuple[str, ...],
    ) -> _AdmissionState:
        return _AdmissionState(
            state=state,
            reason=reason,
            history=history,
            proof=self._state_proof(state, reason, history),
        )

    def _assert_integrity(self) -> None:
        state = self.__state
        if not isinstance(state, _AdmissionState):
            raise PersonTwinAdmissionError("internal admission state type mismatch")
        expected_proof = self._state_proof(state.state, state.reason, state.history)
        if not hmac.compare_digest(state.proof, expected_proof):
            raise PersonTwinAdmissionError("internal transition proof mismatch")

        if state.state == HOLD:
            if not state.history or state.history[-1] != HOLD:
                raise PersonTwinAdmissionError("HOLD history invariant mismatch")
            prefix = state.history[:-1]
            if prefix not in set(_ALLOWED_PREFIXES.values()):
                raise PersonTwinAdmissionError("invalid history before HOLD")
            return

        expected_history = _ALLOWED_PREFIXES.get(state.state)
        if expected_history is None or state.history != expected_history:
            raise PersonTwinAdmissionError("admission transition history mismatch")

    def _assert_state(self, expected: str) -> None:
        self._assert_integrity()
        if self.__state.state != expected:
            raise PersonTwinAdmissionError(
                f"invalid admission transition: expected {expected}, "
                f"got {self.__state.state}"
            )

    def _advance(
        self,
        *,
        expected: str,
        target: str,
        reason: str,
    ) -> dict[str, Any]:
        self._assert_state(expected)
        expected_history = _ALLOWED_PREFIXES[target]
        if expected_history[:-1] != self.__state.history:
            raise PersonTwinAdmissionError("non-contiguous admission transition")
        self.__state = self._make_state(target, reason, expected_history)
        return self.receipt()

    def _hold(self, reason: str) -> dict[str, Any]:
        self._assert_integrity()
        if self.__state.state in TERMINAL_STATES:
            return self.receipt()
        history = self.__state.history + (HOLD,)
        self.__state = self._make_state(HOLD, reason, history)
        return self.receipt()

    def _receipt_dict(self) -> dict[str, Any]:
        state = self.__state
        return {
            "schema_version": SCHEMA_VERSION,
            "session_id": self.session_id,
            "candidate_id": self.candidate_id,
            "candidate_sha256": self.candidate_sha256,
            "identity_fingerprint": self.identity_fingerprint,
            "expected_pointer_sha256": self.expected_pointer_sha256,
            "state": state.state,
            "reason": state.reason,
            "history": state.history,
            "production_admission_status": NOT_PRODUCTION_ADMITTED,
            "execution_authority": "NONE",
            "can_execute": False,
            "can_trade": False,
            "capital_permission": "DENY",
        }

    def _validate_current_evidence(
        self,
        *,
        current_revocation_ledger: Mapping[str, Any],
        at: str,
        candidate_record: Mapping[str, Any] | None = None,
    ) -> Mapping[str, Any]:
        record = self.candidate_record if candidate_record is None else candidate_record
        validate_person_twin_identity(self.identity)
        validate_source_consent_receipt(self.identity, self.consent_receipt)
        validate_person_twin_record(
            record,
            identity=self.identity,
            consent_receipt=self.consent_receipt,
            source_record=self.source_record,
        )
        if record.get("identity_fingerprint") != self.identity_fingerprint:
            raise PersonTwinAdmissionError("candidate identity fingerprint drift")
        _validate_candidate_ceiling(record)

        validate_consent_revocation_ledger(current_revocation_ledger)
        current_ledger_hash = current_revocation_ledger["ledger_hash"]

        decision = _consent_decision(
            identity=self.identity,
            consent_receipt=self.consent_receipt,
            revocation_ledger=current_revocation_ledger,
            source_record=self.source_record,
            purpose=self.purpose,
            at=at,
        )
        if record.get("revocation_ledger_hash") != current_ledger_hash:
            raise PersonTwinAdmissionError("REVOCATION_LEDGER_HASH_DRIFT")
        if decision.get("revocation_ledger_hash") != current_ledger_hash:
            raise PersonTwinAdmissionError(
                "consent decision revocation ledger hash mismatch"
            )
        return decision

    def validate(
        self,
        *,
        revocation_ledger: Mapping[str, Any],
        at: str,
    ) -> dict[str, Any]:
        self._assert_state(STAGED)
        try:
            self._validate_current_evidence(
                current_revocation_ledger=revocation_ledger,
                at=at,
            )
        except Exception as exc:
            return self._hold(f"VALIDATION_FAILED:{type(exc).__name__}:{exc}")
        return self._advance(
            expected=STAGED,
            target=VALIDATED,
            reason="EXACT_IDENTITY_CONSENT_PROVENANCE_AND_LEDGER_VALIDATED",
        )

    def commit_not_current(
        self,
        *,
        current_revocation_ledger: Mapping[str, Any],
        at: str,
    ) -> dict[str, Any]:
        self._assert_state(VALIDATED)
        try:
            self._validate_current_evidence(
                current_revocation_ledger=current_revocation_ledger,
                at=at,
            )

            current_before = self.store.read_current_pointer_bytes()
            if _pointer_sha(current_before) != self.expected_pointer_sha256:
                raise AdmissionStoreConflict("current pointer drift before candidate commit")

            existing = self.store.read_candidate_bytes(self.candidate_id)
            if existing is not None and existing != self._candidate_bytes:
                raise AdmissionStoreConflict(
                    "candidate identity already exists with different bytes"
                )
            self.store.commit_candidate_not_current(
                self.candidate_id,
                self._candidate_bytes,
            )

            committed = self.store.read_candidate_bytes(self.candidate_id)
            if committed != self._candidate_bytes:
                raise AdmissionStoreError("committed candidate readback mismatch")
            if committed is None or _sha256(committed) != self.candidate_sha256:
                raise AdmissionStoreError("committed candidate hash mismatch")

            current_after = self.store.read_current_pointer_bytes()
            if current_after != current_before:
                raise AdmissionStoreError(
                    "candidate commit modified current pointer before postverify"
                )
        except Exception as exc:
            return self._hold(f"COMMIT_HOLD:{type(exc).__name__}:{exc}")

        return self._advance(
            expected=VALIDATED,
            target=COMMITTED_NOT_CURRENT,
            reason="EXACT_CANDIDATE_COMMITTED_POINTER_UNCHANGED",
        )

    def postverify(
        self,
        *,
        current_revocation_ledger: Mapping[str, Any],
        at: str,
    ) -> dict[str, Any]:
        self._assert_state(COMMITTED_NOT_CURRENT)
        try:
            current_pointer = self.store.read_current_pointer_bytes()
            if _pointer_sha(current_pointer) != self.expected_pointer_sha256:
                raise AdmissionStoreConflict("current pointer drift before postverify")

            committed = self.store.read_candidate_bytes(self.candidate_id)
            if committed is None:
                raise AdmissionStoreError("committed candidate missing")
            if committed != self._candidate_bytes:
                raise AdmissionStoreConflict("candidate bytes drift after commit")
            if _sha256(committed) != self.candidate_sha256:
                raise AdmissionStoreConflict("candidate hash drift after commit")

            decoded = json.loads(committed.decode("utf-8"))
            if not isinstance(decoded, Mapping):
                raise PersonTwinAdmissionError("candidate root must be an object")

            self._validate_current_evidence(
                current_revocation_ledger=current_revocation_ledger,
                at=at,
                candidate_record=decoded,
            )
        except Exception as exc:
            return self._hold(f"POSTVERIFY_HOLD:{type(exc).__name__}:{exc}")

        return self._advance(
            expected=COMMITTED_NOT_CURRENT,
            target=POSTVERIFY_PASS,
            reason="POSTVERIFY_PASS_POINTER_STILL_LAST_KNOWN_GOOD",
        )

    def promote_current(
        self,
        *,
        current_revocation_ledger: Mapping[str, Any],
        at: str,
    ) -> dict[str, Any]:
        self._assert_state(POSTVERIFY_PASS)
        try:
            committed = self.store.read_candidate_bytes(self.candidate_id)
            if committed is None:
                raise AdmissionStoreError("candidate missing before promotion")
            if committed != self._candidate_bytes:
                raise AdmissionStoreConflict("candidate drift before promotion")
            if _sha256(committed) != self.candidate_sha256:
                raise AdmissionStoreConflict("candidate hash drift before promotion")

            decoded = json.loads(committed.decode("utf-8"))
            if not isinstance(decoded, Mapping):
                raise PersonTwinAdmissionError("candidate root must be an object")

            self._validate_current_evidence(
                current_revocation_ledger=current_revocation_ledger,
                at=at,
                candidate_record=decoded,
            )

            pointer = {
                "schema_version": CURRENT_POINTER_SCHEMA_VERSION,
                "state": CURRENT,
                "twin_id": decoded["twin_id"],
                "candidate_id": self.candidate_id,
                "candidate_sha256": self.candidate_sha256,
                "identity_fingerprint": self.identity_fingerprint,
                "production_admission_status": NOT_PRODUCTION_ADMITTED,
                "execution_authority": "NONE",
                "can_execute": False,
                "can_trade": False,
                "capital_permission": "DENY",
            }
            pointer_bytes = _canonical_bytes(pointer)

            self.store.promote_current_pointer(
                expected_pointer_sha256=self.expected_pointer_sha256,
                pointer_bytes=pointer_bytes,
            )
            readback = self.store.read_current_pointer_bytes()
            if readback != pointer_bytes:
                raise AdmissionStoreError("promoted current pointer readback mismatch")
        except Exception as exc:
            return self._hold(f"PROMOTION_HOLD:{type(exc).__name__}:{exc}")

        return self._advance(
            expected=POSTVERIFY_PASS,
            target=CURRENT,
            reason="EXACT_POSTVERIFIED_CANDIDATE_PROMOTED_BY_OCC",
        )

    def request_state(self, desired_state: str) -> dict[str, Any]:
        """No caller/model/agent may set a terminal state directly."""
        del desired_state
        self._assert_integrity()
        if self.__state.state in TERMINAL_STATES:
            return self.receipt()
        return self._hold("DIRECT_STATE_PROMOTION_FORBIDDEN")
