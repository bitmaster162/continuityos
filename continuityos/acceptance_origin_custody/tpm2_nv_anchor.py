"""Private TPM2 NV-EXTEND read/verify boundary for Acceptance Origin R1.

The production runtime provider is intentionally unprovisioned. No NV handle, TPMA_NV
mask, authPolicy, authorization mechanism, credential source, or TCTI is defaulted by
this source. Pure proof and wire-identity verification remain hardware-free.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
from typing import Any

from .. import cross_ai_ruap_acceptance_origin_signing_contract as contract

PROOF_SCHEMA = "continuityos.cross_ai_ruap_acceptance_origin_activation_anchor_proof/v1"
GENESIS_SCHEMA = "continuityos.cross_ai_ruap_acceptance_origin_activation_anchor_genesis/v1"
COMMITMENT_SCHEMA = "continuityos.cross_ai_ruap_acceptance_origin_activation_anchor_commitment/v1"

_PROOF_KEYS = frozenset({
    "schema", "producer_id", "activation_generation", "activation_manifest_sha256",
    "anchor_genesis_evidence_sha256", "previous_activation_generation",
    "previous_anchor_proof_sha256", "previous_nv_extend_digest", "commitment_sha256",
    "observed_nv_extend_digest", "nv_public_sha256", "nv_name_sha256",
})
_GENESIS_KEYS = frozenset({
    "schema", "producer_id", "activation_generation", "nv_public_sha256",
    "nv_name_sha256", "genesis_nv_extend_digest", "nv_type", "name_alg",
    "data_size", "orderly", "result",
})


@dataclass(frozen=True)
class _BoundTpmNvProfile:
    nv_index: int
    tpma_nv_mask: int
    auth_policy_sha256: str | None
    tcti_identity: str

    def __post_init__(self) -> None:
        if type(self.nv_index) is not int or self.nv_index <= 0:
            raise ValueError("production_tpm_nv_policy_unbound")
        if type(self.tpma_nv_mask) is not int or self.tpma_nv_mask < 0:
            raise ValueError("production_tpm_nv_policy_unbound")
        if self.auth_policy_sha256 is not None and not contract._is_sha256(
            self.auth_policy_sha256
        ):
            raise ValueError("production_tpm_nv_policy_unbound")
        if type(self.tcti_identity) is not str or not self.tcti_identity:
            raise ValueError("production_tpm_nv_policy_unbound")


class _RuntimeTpmReadProvider:
    def _open_authorized_nv_read_context(self) -> Any:
        raise ValueError("production_tpm_read_custody_unprovisioned")


class _UnprovisionedRuntimeTpmReadProvider(_RuntimeTpmReadProvider):
    pass


def _require_wire_identity(
    *,
    tpms_nv_public_marshaled: bytes,
    raw_tpm_name: bytes,
) -> tuple[str, str]:
    if type(tpms_nv_public_marshaled) is not bytes or not tpms_nv_public_marshaled:
        raise ValueError("production_tpm_nv_public_area_mismatch")
    if type(raw_tpm_name) is not bytes or len(raw_tpm_name) != 34:
        raise ValueError("production_tpm_nv_name_binding_invalid")
    expected_name = b"\x00\x0b" + hashlib.sha256(
        tpms_nv_public_marshaled
    ).digest()
    if raw_tpm_name != expected_name:
        raise ValueError("production_tpm_nv_name_binding_invalid")
    return (
        hashlib.sha256(tpms_nv_public_marshaled).hexdigest(),
        hashlib.sha256(raw_tpm_name).hexdigest(),
    )


class _Tpm2NvAnchorAdapter:
    __slots__ = ("_profile", "_read_provider")

    def __init__(
        self,
        *,
        profile: _BoundTpmNvProfile,
        read_provider: _RuntimeTpmReadProvider,
    ) -> None:
        self._profile = profile
        self._read_provider = read_provider

    def _read_current_nv_extend_state(self) -> dict[str, str]:
        context = self._read_provider._open_authorized_nv_read_context()
        if context is None:
            raise ValueError("production_tpm_anchor_unavailable")
        try:
            snapshot = context._read_nv_extend_snapshot(self._profile.nv_index)
        except AttributeError as exc:
            raise ValueError("production_tpm_anchor_unavailable") from exc
        expected = {
            "nv_index", "tpma_nv_mask", "auth_policy_sha256", "tcti_identity",
            "nv_type", "name_alg", "data_size", "orderly",
            "tpms_nv_public_marshaled", "raw_tpm_name", "observed_nv_extend_digest",
        }
        if type(snapshot) is not dict or set(snapshot) != expected:
            raise ValueError("production_tpm_nv_public_area_mismatch")
        if (
            snapshot["nv_index"] != self._profile.nv_index
            or snapshot["tpma_nv_mask"] != self._profile.tpma_nv_mask
            or snapshot["auth_policy_sha256"] != self._profile.auth_policy_sha256
            or snapshot["tcti_identity"] != self._profile.tcti_identity
            or snapshot["nv_type"] != "TPM_NT_EXTEND"
            or snapshot["name_alg"] != "SHA256"
            or snapshot["data_size"] != 32
            or snapshot["orderly"] is not False
            or not contract._is_sha256(snapshot["observed_nv_extend_digest"])
        ):
            raise ValueError("production_tpm_nv_public_area_mismatch")
        nv_public_sha256, nv_name_sha256 = _require_wire_identity(
            tpms_nv_public_marshaled=snapshot["tpms_nv_public_marshaled"],
            raw_tpm_name=snapshot["raw_tpm_name"],
        )
        return {
            "nv_public_sha256": nv_public_sha256,
            "nv_name_sha256": nv_name_sha256,
            "observed_nv_extend_digest": snapshot["observed_nv_extend_digest"],
        }


def _require_genesis(value: Any) -> dict[str, Any]:
    genesis = contract._require_exact_keys(
        contract._snapshot_bounded(value), _GENESIS_KEYS, "activation_anchor_genesis"
    )
    if (
        genesis["schema"] != GENESIS_SCHEMA
        or genesis["producer_id"] != contract.PRODUCER_ID
        or genesis["activation_generation"] != 0
        or not contract._is_sha256(genesis["nv_public_sha256"])
        or not contract._is_sha256(genesis["nv_name_sha256"])
        or not contract._is_sha256(genesis["genesis_nv_extend_digest"])
        or genesis["nv_type"] != "TPM_NT_EXTEND"
        or genesis["name_alg"] != "SHA256"
        or genesis["data_size"] != 32
        or genesis["orderly"] is not False
        or genesis["result"] != "GENESIS_READY"
    ):
        raise ValueError("production_tpm_genesis_evidence_invalid")
    return genesis


def _require_proof_shape(value: Any) -> dict[str, Any]:
    proof = contract._require_exact_keys(
        contract._snapshot_bounded(value), _PROOF_KEYS, "activation_anchor_proof"
    )
    if (
        proof["schema"] != PROOF_SCHEMA
        or proof["producer_id"] != contract.PRODUCER_ID
        or type(proof["activation_generation"]) is not int
        or not 1 <= proof["activation_generation"] <= contract.MAX_INTEGER_ABS
        or type(proof["previous_activation_generation"]) is not int
    ):
        raise ValueError("production_tpm_anchor_proof_invalid")
    for key in (
        "activation_manifest_sha256", "anchor_genesis_evidence_sha256",
        "previous_anchor_proof_sha256", "previous_nv_extend_digest",
        "commitment_sha256", "observed_nv_extend_digest",
        "nv_public_sha256", "nv_name_sha256",
    ):
        if not contract._is_sha256(proof[key]):
            raise ValueError("production_tpm_anchor_proof_invalid")
    return proof


def _commitment_sha256(proof: dict[str, Any]) -> str:
    return contract._canonical_sha256({
        "schema": COMMITMENT_SCHEMA,
        "producer_id": contract.PRODUCER_ID,
        "activation_generation": proof["activation_generation"],
        "activation_manifest_sha256": proof["activation_manifest_sha256"],
        "anchor_genesis_evidence_sha256": proof["anchor_genesis_evidence_sha256"],
        "previous_anchor_proof_sha256": proof["previous_anchor_proof_sha256"],
    })


def _expected_observed_digest(
    *, previous_nv_extend_digest: str, commitment_sha256: str
) -> str:
    return hashlib.sha256(
        bytes.fromhex(previous_nv_extend_digest)
        + bytes.fromhex(commitment_sha256)
    ).hexdigest()


def _verify_activation_anchor_proof(
    *,
    proof: Any,
    activation_manifest: dict[str, Any],
    previous_proof_or_genesis_evidence: Any,
    fresh_nv_state: dict[str, str],
) -> dict[str, Any]:
    current = _require_proof_shape(proof)
    manifest_sha256 = contract._canonical_sha256(activation_manifest)
    if (
        current["activation_manifest_sha256"] != manifest_sha256
        or current["activation_generation"] != activation_manifest.get(
            "activation_generation"
        )
    ):
        raise ValueError("production_activation_anchor_mismatch")

    if set(fresh_nv_state) != {
        "nv_public_sha256", "nv_name_sha256", "observed_nv_extend_digest"
    }:
        raise ValueError("production_tpm_anchor_unavailable")
    if (
        current["nv_public_sha256"] != fresh_nv_state["nv_public_sha256"]
        or current["nv_name_sha256"] != fresh_nv_state["nv_name_sha256"]
        or current["observed_nv_extend_digest"]
        != fresh_nv_state["observed_nv_extend_digest"]
    ):
        raise ValueError("production_activation_anchor_mismatch")

    if current["commitment_sha256"] != _commitment_sha256(current):
        raise ValueError("production_tpm_anchor_proof_invalid")
    if current["observed_nv_extend_digest"] != _expected_observed_digest(
        previous_nv_extend_digest=current["previous_nv_extend_digest"],
        commitment_sha256=current["commitment_sha256"],
    ):
        raise ValueError("production_activation_anchor_mismatch")

    if current["activation_generation"] == 1:
        genesis = _require_genesis(previous_proof_or_genesis_evidence)
        genesis_sha256 = contract._canonical_sha256(genesis)
        if (
            current["previous_activation_generation"] != 0
            or current["anchor_genesis_evidence_sha256"] != genesis_sha256
            or current["previous_anchor_proof_sha256"] != genesis_sha256
            or current["previous_nv_extend_digest"]
            != genesis["genesis_nv_extend_digest"]
            or current["nv_public_sha256"] != genesis["nv_public_sha256"]
            or current["nv_name_sha256"] != genesis["nv_name_sha256"]
        ):
            raise ValueError("production_tpm_genesis_evidence_invalid")
    else:
        previous = _require_proof_shape(previous_proof_or_genesis_evidence)
        if (
            current["previous_activation_generation"]
            != current["activation_generation"] - 1
            or previous["activation_generation"]
            != current["previous_activation_generation"]
            or current["previous_anchor_proof_sha256"]
            != contract._canonical_sha256(previous)
            or current["previous_nv_extend_digest"]
            != previous["observed_nv_extend_digest"]
            or current["anchor_genesis_evidence_sha256"]
            != previous["anchor_genesis_evidence_sha256"]
            or current["nv_public_sha256"] != previous["nv_public_sha256"]
            or current["nv_name_sha256"] != previous["nv_name_sha256"]
        ):
            raise ValueError("production_activation_generation_rollback")
    return current


def _build_tpm2_nv_anchor_adapter() -> _Tpm2NvAnchorAdapter:
    # No production NV identity, policy, read authorization, or TCTI is bound yet.
    raise ValueError("production_tpm_read_custody_unprovisioned")
