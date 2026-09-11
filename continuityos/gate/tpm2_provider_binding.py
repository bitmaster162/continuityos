"""R15B TPM2 NV_EXTEND binding and provider boundary.

This module is deliberately hardware-I/O free. It validates one reviewed TPM2
NV_EXTEND identity, derives the narrow R15A provider snapshot, and wraps an
injected backend. Provisioning, reset, clear, undefine, credentials, transport
opening, and OS/vendor TPM calls remain outside this module.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Any

from .monotonic_anchor import BoundMonotonicAnchorProfile, MonotonicAnchorError

BINDING_SCHEMA = "continuityos.governance.execution-anchor.tpm2-binding.v1"
PROVIDER_NAME = "TPM2_NV_EXTEND"
_TPM_ALG_SHA256 = 0x000B
_TPMA_NV_NT_MASK = 0x000000F0
_TPMA_NV_NT_EXTEND = 0x00000040
_TPMA_NV_ORDERLY = 0x04000000
_TPM_NV_INDEX_FIRST = 0x01000000
_TPM_NV_INDEX_LAST = 0x01FFFFFF
_HEX = frozenset("0123456789abcdef")


class Tpm2ProviderBindingError(MonotonicAnchorError):
    """The reviewed TPM2 provider binding or backend state is invalid."""


def _is_sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and set(value) <= _HEX
    )


def _is_nonzero_sha256(value: Any) -> bool:
    return _is_sha256(value) and value != "0" * 64


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


@dataclass(frozen=True)
class Tpm2NvBindingConstraints:
    """Reviewed non-identity constraints for one governance NV index."""

    nv_index: int
    tpma_nv_mask: int
    auth_policy_sha256: str | None
    backend_kind: str
    transport_identity: str

    def __post_init__(self) -> None:
        if type(self.nv_index) is not int or not (
            _TPM_NV_INDEX_FIRST <= self.nv_index <= _TPM_NV_INDEX_LAST
        ):
            raise Tpm2ProviderBindingError("R15B TPM NV index is invalid")
        if type(self.tpma_nv_mask) is not int or not 0 <= self.tpma_nv_mask <= 0xFFFFFFFF:
            raise Tpm2ProviderBindingError("R15B TPMA_NV mask is invalid")
        if (self.tpma_nv_mask & _TPMA_NV_NT_MASK) != _TPMA_NV_NT_EXTEND:
            raise Tpm2ProviderBindingError("R15B NV index is not TPM_NT_EXTEND")
        if self.tpma_nv_mask & _TPMA_NV_ORDERLY:
            raise Tpm2ProviderBindingError("R15B NV index must not be ORDERLY")
        if self.auth_policy_sha256 is not None and not _is_sha256(
            self.auth_policy_sha256
        ):
            raise Tpm2ProviderBindingError("R15B authorization policy is invalid")
        if not isinstance(self.backend_kind, str) or not self.backend_kind.strip():
            raise Tpm2ProviderBindingError("R15B backend kind is unbound")
        if not isinstance(self.transport_identity, str) or not self.transport_identity.strip():
            raise Tpm2ProviderBindingError("R15B transport identity is unbound")


@dataclass(frozen=True)
class BoundTpm2NvExtendProfile:
    """Controller-pinned R15B TPM identity plus the reviewed pre-activation digest."""

    constraints: Tpm2NvBindingConstraints
    nv_public_sha256: str
    nv_name_sha256: str
    genesis_digest: str

    def __post_init__(self) -> None:
        if not isinstance(self.constraints, Tpm2NvBindingConstraints):
            raise Tpm2ProviderBindingError("R15B binding constraints are required")
        if not _is_nonzero_sha256(self.nv_public_sha256):
            raise Tpm2ProviderBindingError("R15B NV public identity is invalid")
        if not _is_nonzero_sha256(self.nv_name_sha256):
            raise Tpm2ProviderBindingError("R15B NV Name identity is invalid")
        if not _is_sha256(self.genesis_digest):
            raise Tpm2ProviderBindingError("R15B genesis digest is invalid")

    def anchor_profile(self) -> BoundMonotonicAnchorProfile:
        return BoundMonotonicAnchorProfile(
            nv_public_sha256=self.nv_public_sha256,
            nv_name_sha256=self.nv_name_sha256,
            genesis_digest=self.genesis_digest,
        )

    def binding_document(self) -> dict[str, Any]:
        return {
            "schema": BINDING_SCHEMA,
            "provider": PROVIDER_NAME,
            "nv_index": self.constraints.nv_index,
            "tpma_nv_mask": self.constraints.tpma_nv_mask,
            "auth_policy_sha256": self.constraints.auth_policy_sha256,
            "backend_kind": self.constraints.backend_kind,
            "transport_identity": self.constraints.transport_identity,
            "nv_public_sha256": self.nv_public_sha256,
            "nv_name_sha256": self.nv_name_sha256,
            "genesis_digest": self.genesis_digest,
        }

    def binding_sha256(self) -> str:
        return hashlib.sha256(_canonical(self.binding_document())).hexdigest()


def _parse_tpms_nv_public(tpms_nv_public_marshaled: bytes) -> dict[str, Any]:
    """Parse exact inner TPMS_NV_PUBLIC bytes; a TPM2B size prefix is forbidden."""
    if type(tpms_nv_public_marshaled) is not bytes or len(tpms_nv_public_marshaled) < 14:
        raise Tpm2ProviderBindingError("R15B TPMS_NV_PUBLIC is invalid")
    raw = tpms_nv_public_marshaled
    nv_index = int.from_bytes(raw[0:4], "big")
    name_alg = int.from_bytes(raw[4:6], "big")
    attributes = int.from_bytes(raw[6:10], "big")
    policy_size = int.from_bytes(raw[10:12], "big")
    policy_end = 12 + policy_size
    if policy_end + 2 != len(raw):
        raise Tpm2ProviderBindingError("R15B TPMS_NV_PUBLIC length is invalid")
    return {
        "nv_index": nv_index,
        "name_alg": name_alg,
        "attributes": attributes,
        "auth_policy": raw[12:policy_end],
        "data_size": int.from_bytes(raw[policy_end:policy_end + 2], "big"),
    }


def _wire_identity(
    *, tpms_nv_public_marshaled: bytes, raw_tpm_name: bytes
) -> tuple[str, str]:
    parsed = _parse_tpms_nv_public(tpms_nv_public_marshaled)
    if parsed["name_alg"] != _TPM_ALG_SHA256:
        raise Tpm2ProviderBindingError("R15B NV Name algorithm is not SHA256")
    if type(raw_tpm_name) is not bytes or len(raw_tpm_name) != 34:
        raise Tpm2ProviderBindingError("R15B raw TPM Name is invalid")
    expected_name = b"\x00\x0b" + hashlib.sha256(
        tpms_nv_public_marshaled
    ).digest()
    if raw_tpm_name != expected_name:
        raise Tpm2ProviderBindingError("R15B TPM Name does not bind the public area")
    return (
        hashlib.sha256(tpms_nv_public_marshaled).hexdigest(),
        hashlib.sha256(raw_tpm_name).hexdigest(),
    )


def _require_parsed_constraints(
    *, parsed: dict[str, Any], constraints: Tpm2NvBindingConstraints
) -> None:
    if parsed["nv_index"] != constraints.nv_index:
        raise Tpm2ProviderBindingError("R15B NV index differs from reviewed binding")
    if parsed["name_alg"] != _TPM_ALG_SHA256:
        raise Tpm2ProviderBindingError("R15B NV Name algorithm is not SHA256")
    if parsed["attributes"] != constraints.tpma_nv_mask:
        raise Tpm2ProviderBindingError("R15B TPMA_NV differs from reviewed binding")
    if (parsed["attributes"] & _TPMA_NV_NT_MASK) != _TPMA_NV_NT_EXTEND:
        raise Tpm2ProviderBindingError("R15B NV public area is not TPM_NT_EXTEND")
    if parsed["attributes"] & _TPMA_NV_ORDERLY:
        raise Tpm2ProviderBindingError("R15B NV public area is ORDERLY")
    if parsed["data_size"] != 32:
        raise Tpm2ProviderBindingError("R15B NV data size is not 32 bytes")
    policy = parsed["auth_policy"]
    if constraints.auth_policy_sha256 is None:
        if policy != b"":
            raise Tpm2ProviderBindingError("R15B authPolicy must be empty")
    elif len(policy) != 32 or policy.hex() != constraints.auth_policy_sha256:
        raise Tpm2ProviderBindingError("R15B authPolicy differs from reviewed binding")


_RAW_SNAPSHOT_KEYS = frozenset({
    "nv_index", "tpma_nv_mask", "auth_policy_sha256", "backend_kind",
    "transport_identity", "nv_type", "name_alg", "data_size", "orderly",
    "tpms_nv_public_marshaled", "raw_tpm_name", "observed_nv_extend_digest",
})


def _require_raw_snapshot(
    value: Any, *, constraints: Tpm2NvBindingConstraints
) -> dict[str, Any]:
    if type(value) is not dict or set(value) != _RAW_SNAPSHOT_KEYS:
        raise Tpm2ProviderBindingError("R15B backend snapshot schema is invalid")
    snapshot = dict(value)
    if (
        snapshot["nv_index"] != constraints.nv_index
        or snapshot["tpma_nv_mask"] != constraints.tpma_nv_mask
        or snapshot["auth_policy_sha256"] != constraints.auth_policy_sha256
        or snapshot["backend_kind"] != constraints.backend_kind
        or snapshot["transport_identity"] != constraints.transport_identity
        or snapshot["nv_type"] != "TPM_NT_EXTEND"
        or snapshot["name_alg"] != "SHA256"
        or snapshot["data_size"] != 32
        or snapshot["orderly"] is not False
        or not _is_sha256(snapshot["observed_nv_extend_digest"])
    ):
        raise Tpm2ProviderBindingError("R15B backend snapshot differs from reviewed constraints")
    parsed = _parse_tpms_nv_public(snapshot["tpms_nv_public_marshaled"])
    _require_parsed_constraints(parsed=parsed, constraints=constraints)
    nv_public_sha256, nv_name_sha256 = _wire_identity(
        tpms_nv_public_marshaled=snapshot["tpms_nv_public_marshaled"],
        raw_tpm_name=snapshot["raw_tpm_name"],
    )
    snapshot["nv_public_sha256"] = nv_public_sha256
    snapshot["nv_name_sha256"] = nv_name_sha256
    return snapshot


def derive_profile_candidate(
    *, raw_snapshot: Any, constraints: Tpm2NvBindingConstraints
) -> BoundTpm2NvExtendProfile:
    """Create an enrollment candidate from one strictly verified read-only snapshot.

    The returned profile is not self-authorizing. Its binding hash must be reviewed
    and pinned by controller state outside the R14 rollback domain before activation.
    """
    snapshot = _require_raw_snapshot(raw_snapshot, constraints=constraints)
    return BoundTpm2NvExtendProfile(
        constraints=constraints,
        nv_public_sha256=snapshot["nv_public_sha256"],
        nv_name_sha256=snapshot["nv_name_sha256"],
        genesis_digest=snapshot["observed_nv_extend_digest"],
    )


def _provider_snapshot_from_raw(
    value: Any, *, profile: BoundTpm2NvExtendProfile
) -> dict[str, str]:
    snapshot = _require_raw_snapshot(value, constraints=profile.constraints)
    if (
        snapshot["nv_public_sha256"] != profile.nv_public_sha256
        or snapshot["nv_name_sha256"] != profile.nv_name_sha256
    ):
        raise Tpm2ProviderBindingError("R15B hardware identity differs from bound profile")
    return {
        "provider": PROVIDER_NAME,
        "nv_public_sha256": snapshot["nv_public_sha256"],
        "nv_name_sha256": snapshot["nv_name_sha256"],
        "observed_digest": snapshot["observed_nv_extend_digest"],
    }


def _expected_digest(previous_digest: str, commitment_sha256: str) -> str:
    if not _is_sha256(previous_digest) or not _is_nonzero_sha256(commitment_sha256):
        raise Tpm2ProviderBindingError("R15B extend digest input is invalid")
    return hashlib.sha256(
        bytes.fromhex(previous_digest) + bytes.fromhex(commitment_sha256)
    ).hexdigest()


class UnprovisionedTpm2NvBackend:
    """Fail-closed placeholder for the not-yet-authorized real TPM backend."""

    def read_snapshot(self, *, profile: BoundTpm2NvExtendProfile) -> dict[str, Any]:
        raise Tpm2ProviderBindingError("production_tpm2_nv_backend_unprovisioned")

    def extend_once(
        self,
        *,
        profile: BoundTpm2NvExtendProfile,
        expected_previous_digest: str,
        commitment_sha256: str,
    ) -> dict[str, Any]:
        raise Tpm2ProviderBindingError("production_tpm2_nv_backend_unprovisioned")


class BoundTpm2NvExtendProvider:
    """R15A provider adapter over one externally provisioned, pinned backend."""

    def __init__(self, backend: Any, *, profile: BoundTpm2NvExtendProfile) -> None:
        if backend is None:
            raise Tpm2ProviderBindingError("R15B TPM backend is required")
        if not isinstance(profile, BoundTpm2NvExtendProfile):
            raise Tpm2ProviderBindingError("R15B bound TPM profile is required")
        self.backend = backend
        self.profile = profile

    def _read_raw(self) -> dict[str, Any]:
        try:
            raw = self.backend.read_snapshot(profile=self.profile)
        except MonotonicAnchorError:
            raise
        except Exception as exc:
            raise Tpm2ProviderBindingError(
                f"R15B TPM backend read failed: {type(exc).__name__}: {exc}"
            ) from exc
        return raw

    def read_snapshot(self) -> dict[str, str]:
        return _provider_snapshot_from_raw(self._read_raw(), profile=self.profile)

    def extend(
        self, *, expected_previous_digest: str, commitment_sha256: str
    ) -> dict[str, str]:
        if not _is_sha256(expected_previous_digest):
            raise Tpm2ProviderBindingError("R15B expected previous digest is invalid")
        if not _is_nonzero_sha256(commitment_sha256):
            raise Tpm2ProviderBindingError("R15B commitment digest is invalid")
        before = self.read_snapshot()
        if before["observed_digest"] != expected_previous_digest:
            raise Tpm2ProviderBindingError("R15B TPM frontier moved before extend")
        try:
            returned_raw = self.backend.extend_once(
                profile=self.profile,
                expected_previous_digest=expected_previous_digest,
                commitment_sha256=commitment_sha256,
            )
        except MonotonicAnchorError:
            raise
        except Exception as exc:
            raise Tpm2ProviderBindingError(
                f"R15B TPM backend extend failed: {type(exc).__name__}: {exc}"
            ) from exc
        returned = _provider_snapshot_from_raw(
            returned_raw, profile=self.profile
        )
        expected = _expected_digest(expected_previous_digest, commitment_sha256)
        if returned["observed_digest"] != expected:
            raise Tpm2ProviderBindingError("R15B TPM extend readback mismatch")
        fresh = self.read_snapshot()
        if fresh != returned:
            raise Tpm2ProviderBindingError("R15B TPM state changed after extend")
        return fresh
