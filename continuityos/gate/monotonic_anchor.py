"""Hardware-free monotonic execution-anchor protocol for R15.

The runtime authority is deliberately provider-injected.  This module contains
no TPM command execution, provisioning, reset, undefine, credential lookup, or
network access.  A future R15B provider may implement the same read/extend
contract against one separately reviewed TPM2 NV_EXTEND index.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Any

from .ledger import GENESIS

DOMAIN = "continuityos.governance.execution-anchor.v1"
COMMITMENT_SCHEMA = "continuityos.governance.execution-anchor.commitment.v1"
RECEIPT_SCHEMA = "continuityos.governance.execution-anchor.receipt.v1"
EVENT_KIND = "monotonic_anchor"
PHASE_GENESIS = "GENESIS"
PHASE_STARTED = "EXECUTION_STARTED"
PHASE_TERMINAL = "EXECUTION_TERMINAL"
_HEX = frozenset("0123456789abcdef")


class MonotonicAnchorError(RuntimeError):
    """Current local governance state cannot be trusted against the anchor."""


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, ensure_ascii=False, separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _is_sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and set(value) <= _HEX
    )


def _is_nonzero_sha256(value: Any) -> bool:
    return _is_sha256(value) and value != GENESIS


@dataclass(frozen=True)
class BoundMonotonicAnchorProfile:
    """Controller-pinned hardware identity and pre-activation TPM digest."""

    nv_public_sha256: str
    nv_name_sha256: str
    genesis_digest: str

    def __post_init__(self) -> None:
        if not _is_nonzero_sha256(self.nv_public_sha256):
            raise MonotonicAnchorError("monotonic anchor profile NV public identity is invalid")
        if not _is_nonzero_sha256(self.nv_name_sha256):
            raise MonotonicAnchorError("monotonic anchor profile NV name identity is invalid")
        if not _is_sha256(self.genesis_digest):
            raise MonotonicAnchorError("monotonic anchor profile genesis digest is invalid")


def _expected_digest(previous_digest: str, commitment_sha256: str) -> str:
    if not _is_sha256(previous_digest) or not _is_nonzero_sha256(commitment_sha256):
        raise MonotonicAnchorError("monotonic anchor digest input is invalid")
    return hashlib.sha256(
        bytes.fromhex(previous_digest) + bytes.fromhex(commitment_sha256)
    ).hexdigest()


class UnprovisionedTpm2NvExtendProvider:
    """Fail-closed placeholder. R15A never talks to real TPM hardware."""

    def read_snapshot(self) -> dict[str, str]:
        raise MonotonicAnchorError("production_tpm2_nv_extend_unprovisioned")

    def extend(
        self, *, expected_previous_digest: str, commitment_sha256: str
    ) -> dict[str, str]:
        raise MonotonicAnchorError("production_tpm2_nv_extend_unprovisioned")


def _require_snapshot(value: Any) -> dict[str, str]:
    required = {
        "provider", "nv_public_sha256", "nv_name_sha256", "observed_digest"
    }
    if not isinstance(value, dict) or set(value) != required:
        raise MonotonicAnchorError("monotonic anchor provider snapshot is invalid")
    if value["provider"] != "TPM2_NV_EXTEND":
        raise MonotonicAnchorError("monotonic anchor provider type mismatch")
    for key in ("nv_public_sha256", "nv_name_sha256"):
        if not _is_nonzero_sha256(value[key]):
            raise MonotonicAnchorError("monotonic anchor hardware identity is invalid")
    if not _is_sha256(value["observed_digest"]):
        raise MonotonicAnchorError("monotonic anchor observed digest is invalid")
    return dict(value)


class MonotonicExecutionAnchor:
    """Bind irreversible execution boundaries to a monotonic provider."""

    def __init__(self, provider: Any, *, profile: BoundMonotonicAnchorProfile):
        if provider is None:
            raise MonotonicAnchorError("monotonic anchor provider is required")
        if not isinstance(profile, BoundMonotonicAnchorProfile):
            raise MonotonicAnchorError("monotonic anchor bound profile is required")
        self.provider = provider
        self.profile = profile

    def _read_provider(self) -> dict[str, str]:
        try:
            snapshot = _require_snapshot(self.provider.read_snapshot())
        except MonotonicAnchorError:
            raise
        except Exception as exc:
            raise MonotonicAnchorError(
                f"monotonic anchor provider read failed: {type(exc).__name__}: {exc}"
            ) from exc
        if (
            snapshot["nv_public_sha256"] != self.profile.nv_public_sha256
            or snapshot["nv_name_sha256"] != self.profile.nv_name_sha256
        ):
            raise MonotonicAnchorError(
                "monotonic anchor hardware identity substitution detected against bound profile"
            )
        return snapshot

    @staticmethod
    def _event_rows(ledger):
        return ledger.con.execute(
            "SELECT id,kind,payload,hash FROM events ORDER BY id"
        ).fetchall()

    @staticmethod
    def _commitment_body(receipt: dict[str, Any]) -> dict[str, Any]:
        return {
            "schema": COMMITMENT_SCHEMA,
            "domain": DOMAIN,
            "state_id": receipt["state_id"],
            "anchor_generation": receipt["anchor_generation"],
            "phase": receipt["phase"],
            "preflight_hash": receipt["preflight_hash"],
            "binding_sha256": receipt["binding_sha256"],
            "terminal_kind": receipt["terminal_kind"],
            "ledger_event_count": receipt["ledger_event_count"],
            "ledger_event_hash": receipt["ledger_event_hash"],
            "previous_anchor_digest": receipt["previous_anchor_digest"],
            "nv_public_sha256": receipt["nv_public_sha256"],
            "nv_name_sha256": receipt["nv_name_sha256"],
        }

    @classmethod
    def _commitment_sha256(cls, receipt: dict[str, Any]) -> str:
        return hashlib.sha256(_canonical(cls._commitment_body(receipt))).hexdigest()

    @staticmethod
    def _require_receipt(payload: Any) -> dict[str, Any]:
        keys = {
            "schema", "domain", "state_id", "anchor_generation", "phase",
            "preflight_hash", "binding_sha256", "terminal_kind",
            "ledger_event_count", "ledger_event_hash", "previous_anchor_digest",
            "nv_public_sha256", "nv_name_sha256", "commitment_sha256",
            "observed_anchor_digest",
        }
        if not isinstance(payload, dict) or set(payload) != keys:
            raise MonotonicAnchorError("monotonic anchor receipt schema is not strict")
        if payload["schema"] != RECEIPT_SCHEMA or payload["domain"] != DOMAIN:
            raise MonotonicAnchorError("monotonic anchor receipt domain mismatch")
        if not _is_nonzero_sha256(payload["state_id"]):
            raise MonotonicAnchorError("monotonic anchor state_id is invalid")
        if type(payload["anchor_generation"]) is not int or payload["anchor_generation"] < 1:
            raise MonotonicAnchorError("monotonic anchor generation is invalid")
        if payload["phase"] not in {PHASE_GENESIS, PHASE_STARTED, PHASE_TERMINAL}:
            raise MonotonicAnchorError("monotonic anchor phase is invalid")
        if type(payload["ledger_event_count"]) is not int or payload["ledger_event_count"] < 0:
            raise MonotonicAnchorError("monotonic anchor ledger count is invalid")
        for key in (
            "ledger_event_hash", "previous_anchor_digest", "nv_public_sha256",
            "nv_name_sha256", "commitment_sha256", "observed_anchor_digest",
        ):
            if not _is_sha256(payload[key]):
                raise MonotonicAnchorError(f"monotonic anchor {key} is invalid")
        return dict(payload)

    @staticmethod
    def _require_phase_fields(receipt: dict[str, Any]) -> None:
        phase = receipt["phase"]
        preflight = receipt["preflight_hash"]
        binding = receipt["binding_sha256"]
        terminal_kind = receipt["terminal_kind"]
        if phase == PHASE_GENESIS:
            if preflight != GENESIS or binding != GENESIS or terminal_kind is not None:
                raise MonotonicAnchorError("monotonic anchor genesis fields are invalid")
            return
        if not _is_nonzero_sha256(preflight) or not _is_nonzero_sha256(binding):
            raise MonotonicAnchorError("monotonic anchor execution binding is invalid")
        if phase == PHASE_STARTED:
            if terminal_kind is not None:
                raise MonotonicAnchorError("started anchor cannot carry terminal kind")
            return
        if terminal_kind not in {"execution_completed", "execution_failed"}:
            raise MonotonicAnchorError("terminal anchor kind is invalid")

    @classmethod
    def _validate_receipt_crypto(cls, receipt: dict[str, Any]) -> None:
        cls._require_phase_fields(receipt)
        commitment = cls._commitment_sha256(receipt)
        if commitment != receipt["commitment_sha256"]:
            raise MonotonicAnchorError("monotonic anchor commitment mismatch")
        expected = _expected_digest(
            receipt["previous_anchor_digest"], receipt["commitment_sha256"]
        )
        if expected != receipt["observed_anchor_digest"]:
            raise MonotonicAnchorError("monotonic anchor digest chain mismatch")

    @staticmethod
    def _load_payload(blob: Any) -> dict[str, Any]:
        if not isinstance(blob, str):
            raise MonotonicAnchorError("monotonic anchor payload is not text JSON")
        def strict_object(pairs):
            value = {}
            for key, item in pairs:
                if key in value:
                    raise ValueError(f"duplicate key: {key}")
                value[key] = item
            return value
        try:
            value = json.loads(blob, object_pairs_hook=strict_object)
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise MonotonicAnchorError("monotonic anchor payload is corrupt") from exc
        if not isinstance(value, dict):
            raise MonotonicAnchorError("monotonic anchor payload is not an object")
        return value

    @staticmethod
    def _event_payload(row) -> dict[str, Any]:
        try:
            value = json.loads(row["payload"])
        except (TypeError, json.JSONDecodeError) as exc:
            raise MonotonicAnchorError("ledger event payload is corrupt") from exc
        if not isinstance(value, dict):
            raise MonotonicAnchorError("ledger event payload is not an object")
        return value

    def validate_global(
        self, ledger, *, _allow_pending_boundary: tuple[str, str] | None = None
    ) -> dict[str, Any]:
        verification = ledger.verify()
        if not verification.get("ok"):
            raise MonotonicAnchorError("ledger hash chain failed before anchor validation")
        state_id = ledger.state_id()
        if not _is_nonzero_sha256(state_id):
            raise MonotonicAnchorError("R15 requires an R14 governance state_id")
        rows = list(self._event_rows(ledger))
        receipts = []
        request_receipts: dict[str, dict[str, Any]] = {}
        previous_digest = None
        hardware_identity = None
        activation_receipt_position = None

        for position, row in enumerate(rows, start=1):
            if row["kind"] != EVENT_KIND:
                continue
            receipt = self._require_receipt(self._load_payload(row["payload"]))
            self._validate_receipt_crypto(receipt)
            if receipt["state_id"] != state_id:
                raise MonotonicAnchorError("monotonic anchor state_id mismatch")
            if (
                receipt["nv_public_sha256"] != self.profile.nv_public_sha256
                or receipt["nv_name_sha256"] != self.profile.nv_name_sha256
            ):
                raise MonotonicAnchorError(
                    "monotonic anchor receipt hardware identity differs from bound profile"
                )
            expected_generation = len(receipts) + 1
            if receipt["anchor_generation"] != expected_generation:
                raise MonotonicAnchorError("monotonic anchor generation is not contiguous")
            if receipt["ledger_event_count"] != position - 1:
                raise MonotonicAnchorError("monotonic anchor is not adjacent to bound frontier")
            bound_hash = GENESIS if position == 1 else rows[position - 2]["hash"]
            if receipt["ledger_event_hash"] != bound_hash:
                raise MonotonicAnchorError("monotonic anchor bound ledger hash mismatch")
            identity = (
                receipt["nv_public_sha256"], receipt["nv_name_sha256"]
            )
            if hardware_identity is None:
                hardware_identity = identity
                activation_receipt_position = position
                if receipt["phase"] != PHASE_GENESIS:
                    raise MonotonicAnchorError("first monotonic anchor receipt is not genesis")
                if receipt["previous_anchor_digest"] != self.profile.genesis_digest:
                    raise MonotonicAnchorError(
                        "monotonic anchor genesis receipt does not start at bound digest"
                    )
            else:
                if identity != hardware_identity:
                    raise MonotonicAnchorError("monotonic anchor hardware identity changed")
                if receipt["phase"] == PHASE_GENESIS:
                    raise MonotonicAnchorError("duplicate monotonic anchor genesis")
            if previous_digest is not None and (
                receipt["previous_anchor_digest"] != previous_digest
            ):
                raise MonotonicAnchorError("monotonic anchor previous digest mismatch")

            if receipt["phase"] == PHASE_STARTED:
                bound = rows[position - 2] if position > 1 else None
                if bound is None or bound["kind"] != "execution_started":
                    raise MonotonicAnchorError("started anchor is not bound to execution_started")
                bound_payload = self._event_payload(bound)
                if bound_payload.get("preflight_hash") != receipt["preflight_hash"]:
                    raise MonotonicAnchorError("started anchor preflight mismatch")
                state = request_receipts.setdefault(
                    receipt["preflight_hash"], {"started": None, "terminal": None}
                )
                if state["started"] is not None:
                    raise MonotonicAnchorError("duplicate started anchor for preflight")
                state["started"] = receipt
            elif receipt["phase"] == PHASE_TERMINAL:
                bound = rows[position - 2] if position > 1 else None
                if bound is None or bound["kind"] != receipt["terminal_kind"]:
                    raise MonotonicAnchorError("terminal anchor is not bound to terminal event")
                bound_payload = self._event_payload(bound)
                if bound_payload.get("preflight_hash") != receipt["preflight_hash"]:
                    raise MonotonicAnchorError("terminal anchor preflight mismatch")
                state = request_receipts.setdefault(
                    receipt["preflight_hash"], {"started": None, "terminal": None}
                )
                if state["started"] is None:
                    raise MonotonicAnchorError("terminal anchor has no started anchor")
                if state["terminal"] is not None:
                    raise MonotonicAnchorError("duplicate terminal anchor for preflight")
                if state["started"]["binding_sha256"] != receipt["binding_sha256"]:
                    raise MonotonicAnchorError("terminal anchor execution binding changed")
                state["terminal"] = receipt

            previous_digest = receipt["observed_anchor_digest"]
            receipts.append(receipt)

        if not receipts:
            raise MonotonicAnchorError("monotonic execution anchor is not bound")

        latest = receipts[-1]
        provider = self._read_provider()
        if (
            provider["nv_public_sha256"] != latest["nv_public_sha256"]
            or provider["nv_name_sha256"] != latest["nv_name_sha256"]
        ):
            raise MonotonicAnchorError(
                "monotonic anchor hardware identity substitution detected"
            )
        if provider["observed_digest"] != latest["observed_anchor_digest"]:
            raise MonotonicAnchorError(
                "local governance state differs from monotonic hardware frontier"
            )

        coverage = {receipt["ledger_event_hash"]: receipt for receipt in receipts[1:]}
        for position, row in enumerate(rows, start=1):
            if position <= activation_receipt_position:
                continue
            expected_phase = None
            event_payload = None
            if row["kind"] == "execution_started":
                expected_phase = PHASE_STARTED
                event_payload = self._event_payload(row)
            elif row["kind"] in {"execution_completed", "execution_failed"}:
                event_payload = self._event_payload(row)
                if event_payload.get("execution_started_hash") is not None:
                    expected_phase = PHASE_TERMINAL
            if expected_phase is None:
                continue
            anchored_receipt = coverage.get(row["hash"])
            if anchored_receipt is None:
                pending = (expected_phase, row["hash"])
                if _allow_pending_boundary == pending and position == len(rows):
                    continue
                label = (
                    "execution_started" if expected_phase == PHASE_STARTED
                    else "effect-bearing terminal"
                )
                raise MonotonicAnchorError(
                    f"post-activation {label} lacks monotonic receipt; "
                    "offline monotonic reconciliation required"
                )
            if anchored_receipt["phase"] != expected_phase:
                raise MonotonicAnchorError(
                    "post-activation execution boundary has wrong monotonic phase"
                )
            if anchored_receipt["preflight_hash"] != event_payload.get("preflight_hash"):
                raise MonotonicAnchorError(
                    "post-activation execution boundary anchor points at another preflight"
                )
            if (
                expected_phase == PHASE_TERMINAL
                and anchored_receipt["terminal_kind"] != row["kind"]
            ):
                raise MonotonicAnchorError(
                    "post-activation terminal anchor kind mismatch"
                )

        for preflight_hash, anchored in request_receipts.items():
            row = ledger._attempt_row(preflight_hash)
            if row is None:
                raise MonotonicAnchorError("anchored execution attempt row is missing")
            try:
                attempt = ledger._validate_attempt_row(row)
            except Exception as exc:
                raise MonotonicAnchorError(
                    f"anchored execution lifecycle is invalid: {type(exc).__name__}: {exc}"
                ) from exc
            started = anchored["started"]
            terminal = anchored["terminal"]
            if attempt["binding_sha256"] != started["binding_sha256"]:
                raise MonotonicAnchorError("anchored execution binding differs from attempt")
            if attempt.get("execution_started_hash") != started["ledger_event_hash"]:
                raise MonotonicAnchorError("started anchor receipt points at another attempt")
            if terminal is not None:
                if attempt["phase"] != "TERMINAL":
                    raise MonotonicAnchorError("terminal anchor exists for non-terminal attempt")
                if attempt.get("terminal_hash") != terminal["ledger_event_hash"]:
                    raise MonotonicAnchorError("terminal anchor receipt points at another terminal")
                if attempt.get("terminal_kind") != terminal["terminal_kind"]:
                    raise MonotonicAnchorError("terminal anchor kind differs from attempt")

        latest = receipts[-1]
        return {
            "state_id": state_id,
            "anchor_generation": latest["anchor_generation"],
            "observed_anchor_digest": latest["observed_anchor_digest"],
            "nv_public_sha256": latest["nv_public_sha256"],
            "nv_name_sha256": latest["nv_name_sha256"],
            "activation_ledger_event_count": receipts[0]["ledger_event_count"],
            "activation_ledger_event_hash": receipts[0]["ledger_event_hash"],
            "request_receipts": request_receipts,
        }

    @staticmethod
    def _frontier(ledger) -> dict[str, Any]:
        frontier = ledger.frontier()
        count = frontier.get("event_count")
        event_hash = frontier.get("event_hash")
        if type(count) is not int or count < 0 or not _is_sha256(event_hash):
            raise MonotonicAnchorError("ledger frontier is invalid")
        return {"event_count": count, "event_hash": event_hash}

    def _build_receipt(
        self, *, state_id: str, generation: int, phase: str,
        preflight_hash: str, binding_sha256: str, terminal_kind: str | None,
        frontier: dict[str, Any], previous_digest: str,
        hardware: dict[str, str],
    ) -> dict[str, Any]:
        receipt = {
            "schema": RECEIPT_SCHEMA, "domain": DOMAIN,
            "state_id": state_id, "anchor_generation": generation,
            "phase": phase, "preflight_hash": preflight_hash,
            "binding_sha256": binding_sha256, "terminal_kind": terminal_kind,
            "ledger_event_count": frontier["event_count"],
            "ledger_event_hash": frontier["event_hash"],
            "previous_anchor_digest": previous_digest,
            "nv_public_sha256": hardware["nv_public_sha256"],
            "nv_name_sha256": hardware["nv_name_sha256"],
        }
        commitment = hashlib.sha256(
            _canonical(self._commitment_body(receipt))
        ).hexdigest()
        receipt["commitment_sha256"] = commitment
        receipt["observed_anchor_digest"] = _expected_digest(
            previous_digest, commitment
        )
        self._validate_receipt_crypto(receipt)
        return receipt

    def _extend_and_persist(self, ledger, receipt: dict[str, Any]) -> str:
        before = self._read_provider()
        if (
            before["nv_public_sha256"] != receipt["nv_public_sha256"]
            or before["nv_name_sha256"] != receipt["nv_name_sha256"]
        ):
            raise MonotonicAnchorError("monotonic anchor hardware identity changed before extend")
        if before["observed_digest"] != receipt["previous_anchor_digest"]:
            raise MonotonicAnchorError("monotonic anchor moved before extend")
        try:
            returned = _require_snapshot(self.provider.extend(
                expected_previous_digest=receipt["previous_anchor_digest"],
                commitment_sha256=receipt["commitment_sha256"],
            ))
        except MonotonicAnchorError:
            raise
        except Exception as exc:
            raise MonotonicAnchorError(
                f"monotonic anchor extend failed: {type(exc).__name__}: {exc}"
            ) from exc
        expected = receipt["observed_anchor_digest"]
        if (
            returned["nv_public_sha256"] != receipt["nv_public_sha256"]
            or returned["nv_name_sha256"] != receipt["nv_name_sha256"]
            or returned["observed_digest"] != expected
        ):
            raise MonotonicAnchorError("monotonic anchor extend readback mismatch")
        fresh = self._read_provider()
        if fresh != returned:
            raise MonotonicAnchorError("monotonic anchor state changed after extend")
        # From this point the hardware may be ahead of local state.  Do not
        # auto-heal if the durable ledger receipt append fails.
        try:
            receipt_hash = ledger.append(EVENT_KIND, receipt)
        except Exception as exc:
            raise MonotonicAnchorError(
                "hardware advanced but local monotonic receipt was not durably recorded"
            ) from exc
        after_receipt = self._read_provider()
        if (
            after_receipt["nv_public_sha256"] != receipt["nv_public_sha256"]
            or after_receipt["nv_name_sha256"] != receipt["nv_name_sha256"]
            or after_receipt["observed_digest"] != expected
        ):
            raise MonotonicAnchorError(
                "monotonic hardware frontier changed after local receipt"
            )
        return receipt_hash

    @staticmethod
    def _require_r14_witness(ledger):
        witness = getattr(ledger, "witness", None)
        if witness is None:
            raise MonotonicAnchorError("R15 monotonic anchor requires an R14 witness-bound ledger")
        return witness

    def bind_genesis(self, ledger) -> dict[str, Any]:
        """Offline-only activation serialized by the R14 witness lock."""
        with self._require_r14_witness(ledger).locked():
            return self._bind_genesis_locked(ledger)

    def _bind_genesis_locked(self, ledger) -> dict[str, Any]:
        """Extend once and bind the current R14 state while authority is locked."""
        if not ledger.verify().get("ok"):
            raise MonotonicAnchorError("ledger hash chain failed before R15 activation")
        state_id = ledger.state_id()
        if not _is_nonzero_sha256(state_id):
            raise MonotonicAnchorError("R15 activation requires an R14 state_id")
        if any(row["kind"] == EVENT_KIND for row in self._event_rows(ledger)):
            raise MonotonicAnchorError("R15 monotonic anchor is already bound")
        try:
            ledger.validate_execution_lifecycle()
        except Exception as exc:
            raise MonotonicAnchorError("R15 activation requires a valid execution lifecycle") from exc
        active = ledger.con.execute(
            "SELECT preflight_hash,phase FROM execution_attempts "
            "WHERE phase != 'TERMINAL' LIMIT 1"
        ).fetchone()
        if active is not None:
            raise MonotonicAnchorError(
                "R15 activation requires no claimed or started execution attempts"
            )
        hardware = self._read_provider()
        if hardware["observed_digest"] != self.profile.genesis_digest:
            raise MonotonicAnchorError(
                "monotonic anchor hardware is not at the bound genesis digest"
            )
        frontier = self._frontier(ledger)
        receipt = self._build_receipt(
            state_id=state_id, generation=1, phase=PHASE_GENESIS,
            preflight_hash=GENESIS, binding_sha256=GENESIS,
            terminal_kind=None, frontier=frontier,
            previous_digest=hardware["observed_digest"], hardware=hardware,
        )
        receipt_hash = self._extend_and_persist(ledger, receipt)
        validated = self.validate_global(ledger)
        return {
            "receipt_hash": receipt_hash,
            "anchor_generation": validated["anchor_generation"],
            "observed_anchor_digest": validated["observed_anchor_digest"],
        }

    def record_execution_started(
        self, ledger, *, preflight_hash: str, binding_sha256: str,
        execution_started_hash: str,
    ) -> str:
        with self._require_r14_witness(ledger).locked():
            return self._record_execution_started_locked(
                ledger, preflight_hash=preflight_hash,
                binding_sha256=binding_sha256,
                execution_started_hash=execution_started_hash,
            )

    def _record_execution_started_locked(
        self, ledger, *, preflight_hash: str, binding_sha256: str,
        execution_started_hash: str,
    ) -> str:
        state = self.validate_global(
            ledger, _allow_pending_boundary=(PHASE_STARTED, execution_started_hash)
        )
        row = ledger._attempt_row(preflight_hash)
        try:
            attempt = ledger._validate_attempt_row(row)
        except Exception as exc:
            raise MonotonicAnchorError("cannot anchor invalid execution attempt") from exc
        if (
            attempt["phase"] != "ATTEMPT_STARTED"
            or attempt["binding_sha256"] != binding_sha256
            or attempt.get("execution_started_hash") != execution_started_hash
        ):
            raise MonotonicAnchorError("execution_started anchor binding mismatch")
        if state["request_receipts"].get(preflight_hash, {}).get("started") is not None:
            raise MonotonicAnchorError("execution_started is already monotonic-anchored")
        frontier = self._frontier(ledger)
        if frontier["event_hash"] != execution_started_hash:
            raise MonotonicAnchorError("execution_started is not the current ledger frontier")
        receipt = self._build_receipt(
            state_id=state["state_id"],
            generation=state["anchor_generation"] + 1,
            phase=PHASE_STARTED, preflight_hash=preflight_hash,
            binding_sha256=binding_sha256, terminal_kind=None,
            frontier=frontier,
            previous_digest=state["observed_anchor_digest"], hardware=state,
        )
        return self._extend_and_persist(ledger, receipt)

    def record_execution_terminal(
        self, ledger, *, preflight_hash: str, binding_sha256: str,
        terminal_hash: str, terminal_kind: str,
    ) -> str:
        with self._require_r14_witness(ledger).locked():
            return self._record_execution_terminal_locked(
                ledger, preflight_hash=preflight_hash,
                binding_sha256=binding_sha256, terminal_hash=terminal_hash,
                terminal_kind=terminal_kind,
            )

    def _record_execution_terminal_locked(
        self, ledger, *, preflight_hash: str, binding_sha256: str,
        terminal_hash: str, terminal_kind: str,
    ) -> str:
        state = self.validate_global(
            ledger, _allow_pending_boundary=(PHASE_TERMINAL, terminal_hash)
        )
        row = ledger._attempt_row(preflight_hash)
        try:
            attempt = ledger._validate_attempt_row(row)
        except Exception as exc:
            raise MonotonicAnchorError("cannot anchor invalid completed attempt") from exc
        if (
            attempt["phase"] != "TERMINAL"
            or attempt["binding_sha256"] != binding_sha256
            or attempt.get("terminal_hash") != terminal_hash
            or attempt.get("terminal_kind") != terminal_kind
            or not attempt.get("execution_started_hash")
        ):
            raise MonotonicAnchorError("completed anchor binding mismatch")
        anchored = state["request_receipts"].get(preflight_hash) or {}
        if anchored.get("started") is None:
            raise MonotonicAnchorError("completed anchor requires a started anchor")
        if anchored.get("terminal") is not None:
            raise MonotonicAnchorError("completed execution is already monotonic-anchored")
        frontier = self._frontier(ledger)
        if frontier["event_hash"] != terminal_hash:
            raise MonotonicAnchorError("completed event is not the current ledger frontier")
        receipt = self._build_receipt(
            state_id=state["state_id"],
            generation=state["anchor_generation"] + 1,
            phase=PHASE_TERMINAL, preflight_hash=preflight_hash,
            binding_sha256=binding_sha256, terminal_kind=terminal_kind,
            frontier=frontier,
            previous_digest=state["observed_anchor_digest"], hardware=state,
        )
        return self._extend_and_persist(ledger, receipt)

    def require_terminal_receipt(
        self, ledger, *, preflight_hash: str, binding_sha256: str, attempt: dict[str, Any]
    ) -> dict[str, Any]:
        state = self.validate_global(ledger)
        if attempt.get("phase") != "TERMINAL":
            raise MonotonicAnchorError("terminal receipt requested for non-terminal attempt")
        if attempt.get("binding_sha256") != binding_sha256:
            raise MonotonicAnchorError("terminal receipt binding mismatch")
        if not attempt.get("execution_started_hash"):
            # No subprocess boundary was crossed (for example rollback setup failed).
            return state
        anchored = state["request_receipts"].get(preflight_hash) or {}
        started = anchored.get("started")
        completed = anchored.get("terminal")
        if started is None:
            terminal_hash = attempt.get("terminal_hash")
            event_row = ledger.con.execute(
                "SELECT id FROM events WHERE hash=? LIMIT 1", (terminal_hash,)
            ).fetchone()
            if event_row is None:
                raise MonotonicAnchorError("terminal event is missing from anchored ledger")
            terminal_position = ledger.con.execute(
                "SELECT COUNT(*) FROM events WHERE id <= ?", (event_row[0],)
            ).fetchone()[0]
            if terminal_position <= state["activation_ledger_event_count"]:
                return state
            raise MonotonicAnchorError(
                "post-activation executed terminal attempt lacks started monotonic receipt"
            )
        if completed is None:
            raise MonotonicAnchorError("executed terminal attempt lacks terminal monotonic receipt")
        if completed["binding_sha256"] != binding_sha256:
            raise MonotonicAnchorError("terminal monotonic receipt binding mismatch")
        if completed["ledger_event_hash"] != attempt.get("terminal_hash"):
            raise MonotonicAnchorError("terminal monotonic receipt hash mismatch")
        if completed["terminal_kind"] != attempt.get("terminal_kind"):
            raise MonotonicAnchorError("terminal monotonic receipt kind mismatch")
        return state

    def require_runtime_consistency(self, ledger) -> dict[str, Any]:
        """Require no completed anchored attempt to be awaiting its terminal proof."""
        state = self.validate_global(ledger)
        for preflight_hash, anchored in state["request_receipts"].items():
            if anchored.get("started") is None or anchored.get("terminal") is not None:
                continue
            row = ledger._attempt_row(preflight_hash)
            if row is None:
                raise MonotonicAnchorError("anchored execution attempt row is missing")
            try:
                attempt = ledger._validate_attempt_row(row)
            except Exception as exc:
                raise MonotonicAnchorError("anchored execution lifecycle is invalid") from exc
            if attempt["phase"] == "TERMINAL":
                raise MonotonicAnchorError(
                    "terminal attempt awaits explicit offline monotonic reconciliation"
                )
            if attempt["phase"] == "ATTEMPT_STARTED":
                raise MonotonicAnchorError(
                    "started execution lacks a verified terminal outcome; "
                    "offline monotonic reconciliation required"
                )
            raise MonotonicAnchorError(
                "started monotonic receipt disagrees with execution attempt phase"
            )
        return state
