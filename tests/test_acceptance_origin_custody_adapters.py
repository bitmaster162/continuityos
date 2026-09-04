from __future__ import annotations

import hashlib
import json

import pytest

import continuityos.cross_ai_ruap_acceptance_origin_signing_contract as contract
from continuityos.acceptance_origin_custody import tpm2_nv_anchor as tpm
from continuityos.acceptance_origin_custody import yubihsm2_ed25519 as hsm


def canonical_sha256(value) -> str:
    return hashlib.sha256(json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    ).encode("ascii")).hexdigest()


def test_unprovisioned_hsm_provider_fails_before_session() -> None:
    provider = hsm._UnprovisionedRuntimeHsmSessionProvider()
    with pytest.raises(ValueError, match="production_hsm_auth_custody_unprovisioned"):
        provider._open_authenticated_session()
    with pytest.raises(ValueError, match="production_hsm_auth_custody_unprovisioned"):
        hsm._build_yubihsm2_ed25519_adapter()


def test_hsm_profile_requires_direct_usb_single_domain_and_exact_caps() -> None:
    profile = hsm._BoundYubiHsmProfile(
        signing_key_object_id=41,
        runtime_auth_key_object_id=42,
        signer_domain_bit=8,
        connector_url="yhusb://",
    )

    class Session:
        def _list_asymmetric_keys(self, domain):
            assert domain == 8
            return [41]

        def _get_asymmetric_key_info(self, object_id):
            return {
                "object_id": object_id,
                "object_type": "ASYMMETRIC_KEY",
                "algorithm": "EC_ED25519",
                "domains": {8},
                "capabilities": {"SIGN_EDDSA"},
                "exportable": False,
            }

        def _get_auth_key_info(self, object_id):
            return {
                "object_id": object_id,
                "object_type": "AUTHENTICATION_KEY",
                "algorithm": "AUTH",
                "domains": {8},
                "capabilities": {"SIGN_EDDSA"},
                "exportable": False,
                "delegated_capabilities": set(),
            }

        def _read_ed25519_public_key(self, object_id):
            assert object_id == 41
            return bytes(range(32))

        def _sign_ed25519(self, object_id, message):
            assert object_id == 41
            return b"s" * 64

    class Provider(hsm._RuntimeHsmSessionProvider):
        def _open_authenticated_session(self):
            return Session()

    adapter = hsm._YubiHsm2Ed25519Adapter(
        profile=profile, session_provider=Provider()
    )
    assert adapter._read_bound_public_key() == bytes(range(32))
    assert adapter._sign_bound_acceptance_message(b"message") == b"s" * 64


def test_hsm_rejects_extra_capability_and_second_key() -> None:
    profile = hsm._BoundYubiHsmProfile(
        signing_key_object_id=41,
        runtime_auth_key_object_id=42,
        signer_domain_bit=8,
        connector_url="yhusb://",
    )

    class Session:
        def _list_asymmetric_keys(self, domain):
            return [41, 43]

        def _get_asymmetric_key_info(self, object_id):
            raise AssertionError("must fail on enumeration first")

        def _get_auth_key_info(self, object_id):
            raise AssertionError("must fail on enumeration first")

    class Provider(hsm._RuntimeHsmSessionProvider):
        def _open_authenticated_session(self):
            return Session()

    adapter = hsm._YubiHsm2Ed25519Adapter(
        profile=profile, session_provider=Provider()
    )
    with pytest.raises(ValueError, match="production_hsm_domain_isolation_invalid"):
        adapter._read_bound_public_key()


def test_unprovisioned_tpm_provider_fails_before_nv_read() -> None:
    provider = tpm._UnprovisionedRuntimeTpmReadProvider()
    with pytest.raises(ValueError, match="production_tpm_read_custody_unprovisioned"):
        provider._open_authorized_nv_read_context()
    with pytest.raises(ValueError, match="production_tpm_read_custody_unprovisioned"):
        tpm._build_tpm2_nv_anchor_adapter()


def test_tpm_wire_identity_uses_inner_public_and_raw_name_only() -> None:
    tpms = b"inner-tpms-nv-public-bytes"
    raw_name = b"\x00\x0b" + hashlib.sha256(tpms).digest()
    public_sha, name_sha = tpm._require_wire_identity(
        tpms_nv_public_marshaled=tpms,
        raw_tpm_name=raw_name,
    )
    assert public_sha == hashlib.sha256(tpms).hexdigest()
    assert name_sha == hashlib.sha256(raw_name).hexdigest()
    with pytest.raises(ValueError, match="production_tpm_nv_name_binding_invalid"):
        tpm._require_wire_identity(
            tpms_nv_public_marshaled=b"\x00\x1a" + tpms,
            raw_tpm_name=raw_name,
        )


def test_tpm_adapter_requires_exact_private_bound_profile() -> None:
    profile = tpm._BoundTpmNvProfile(
        nv_index=0x1500020,
        tpma_nv_mask=0x40004,
        auth_policy_sha256=None,
        tcti_identity="test-hardware-tcti",
    )
    tpms = b"inner-public"
    raw_name = b"\x00\x0b" + hashlib.sha256(tpms).digest()

    class Context:
        def _read_nv_extend_snapshot(self, nv_index):
            assert nv_index == profile.nv_index
            return {
                "nv_index": profile.nv_index,
                "tpma_nv_mask": profile.tpma_nv_mask,
                "auth_policy_sha256": None,
                "tcti_identity": profile.tcti_identity,
                "nv_type": "TPM_NT_EXTEND",
                "name_alg": "SHA256",
                "data_size": 32,
                "orderly": False,
                "tpms_nv_public_marshaled": tpms,
                "raw_tpm_name": raw_name,
                "observed_nv_extend_digest": "a" * 64,
            }

    class Provider(tpm._RuntimeTpmReadProvider):
        def _open_authorized_nv_read_context(self):
            return Context()

    adapter = tpm._Tpm2NvAnchorAdapter(
        profile=profile, read_provider=Provider()
    )
    state = adapter._read_current_nv_extend_state()
    assert state == {
        "nv_public_sha256": hashlib.sha256(tpms).hexdigest(),
        "nv_name_sha256": hashlib.sha256(raw_name).hexdigest(),
        "observed_nv_extend_digest": "a" * 64,
    }


def test_generation_one_anchor_proof_requires_exact_genesis_chain() -> None:
    manifest = {
        "schema": "continuityos.cross_ai_ruap_acceptance_origin_activation_manifest/v1",
        "producer_id": contract.PRODUCER_ID,
        "activation_generation": 1,
    }
    genesis = {
        "schema": tpm.GENESIS_SCHEMA,
        "producer_id": contract.PRODUCER_ID,
        "activation_generation": 0,
        "nv_public_sha256": "1" * 64,
        "nv_name_sha256": "2" * 64,
        "genesis_nv_extend_digest": "3" * 64,
        "nv_type": "TPM_NT_EXTEND",
        "name_alg": "SHA256",
        "data_size": 32,
        "orderly": False,
        "result": "GENESIS_READY",
    }
    genesis_sha = canonical_sha256(genesis)
    proof = {
        "schema": tpm.PROOF_SCHEMA,
        "producer_id": contract.PRODUCER_ID,
        "activation_generation": 1,
        "activation_manifest_sha256": canonical_sha256(manifest),
        "anchor_genesis_evidence_sha256": genesis_sha,
        "previous_activation_generation": 0,
        "previous_anchor_proof_sha256": genesis_sha,
        "previous_nv_extend_digest": genesis["genesis_nv_extend_digest"],
        "commitment_sha256": "",
        "observed_nv_extend_digest": "",
        "nv_public_sha256": genesis["nv_public_sha256"],
        "nv_name_sha256": genesis["nv_name_sha256"],
    }
    commitment = {
        "schema": tpm.COMMITMENT_SCHEMA,
        "producer_id": contract.PRODUCER_ID,
        "activation_generation": 1,
        "activation_manifest_sha256": proof["activation_manifest_sha256"],
        "anchor_genesis_evidence_sha256": genesis_sha,
        "previous_anchor_proof_sha256": genesis_sha,
    }
    proof["commitment_sha256"] = canonical_sha256(commitment)
    proof["observed_nv_extend_digest"] = hashlib.sha256(
        bytes.fromhex(proof["previous_nv_extend_digest"])
        + bytes.fromhex(proof["commitment_sha256"])
    ).hexdigest()
    fresh = {
        "nv_public_sha256": proof["nv_public_sha256"],
        "nv_name_sha256": proof["nv_name_sha256"],
        "observed_nv_extend_digest": proof["observed_nv_extend_digest"],
    }
    assert tpm._verify_activation_anchor_proof(
        proof=proof,
        activation_manifest=manifest,
        previous_proof_or_genesis_evidence=genesis,
        fresh_nv_state=fresh,
    ) == proof
    broken = dict(proof)
    broken["previous_nv_extend_digest"] = "4" * 64
    with pytest.raises(ValueError):
        tpm._verify_activation_anchor_proof(
            proof=broken,
            activation_manifest=manifest,
            previous_proof_or_genesis_evidence=genesis,
            fresh_nv_state=fresh,
        )
