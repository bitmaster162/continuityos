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


def marshal_nv_public(
    *,
    nv_index: int = 0x01500020,
    name_alg: int = 0x000B,
    attributes: int = 0x00040040,
    auth_policy: bytes = b"",
    data_size: int = 32,
) -> bytes:
    return b"".join([
        nv_index.to_bytes(4, "big"),
        name_alg.to_bytes(2, "big"),
        attributes.to_bytes(4, "big"),
        len(auth_policy).to_bytes(2, "big"),
        auth_policy,
        data_size.to_bytes(2, "big"),
    ])


def raw_name(tpms: bytes) -> bytes:
    return b"\x00\x0b" + hashlib.sha256(tpms).digest()


def hsm_profile() -> hsm._BoundYubiHsmProfile:
    return hsm._BoundYubiHsmProfile(
        signing_key_object_id=41,
        runtime_auth_key_object_id=42,
        signer_domain_bit=8,
        connector_url="yhusb://",
    )


def key_info(**updates):
    value = {
        "object_id": 41,
        "object_type": "ASYMMETRIC_KEY",
        "algorithm": "EC_ED25519",
        "domains": {8},
        "capabilities": {"SIGN_EDDSA"},
        "exportable": False,
    }
    value.update(updates)
    return value


def auth_info(**updates):
    value = {
        "object_id": 42,
        "object_type": "AUTHENTICATION_KEY",
        "algorithm": "AUTH",
        "domains": {8},
        "capabilities": {"SIGN_EDDSA"},
        "exportable": False,
        "delegated_capabilities": set(),
    }
    value.update(updates)
    return value


class HsmSession:
    def __init__(self, *, key=None, auth=None, visible=None, public_key=None):
        self.key = key if key is not None else key_info()
        self.auth = auth if auth is not None else auth_info()
        self.visible = visible if visible is not None else [41]
        self.public_key = public_key if public_key is not None else bytes(range(32))
        self.sign_calls = 0

    def _list_asymmetric_keys(self, domain):
        assert domain == 8
        return list(self.visible)

    def _get_asymmetric_key_info(self, object_id):
        assert object_id == 41
        return self.key

    def _get_auth_key_info(self, object_id):
        assert object_id == 42
        return self.auth

    def _read_ed25519_public_key(self, object_id):
        assert object_id == 41
        return self.public_key

    def _sign_ed25519(self, object_id, message):
        assert object_id == 41
        assert type(message) is bytes and message
        self.sign_calls += 1
        return b"s" * 64


def test_unprovisioned_hsm_provider_fails_before_session() -> None:
    provider = hsm._UnprovisionedRuntimeHsmSessionProvider()
    with pytest.raises(ValueError, match="production_hsm_auth_custody_unprovisioned"):
        provider._open_authenticated_session()
    with pytest.raises(ValueError, match="production_hsm_auth_custody_unprovisioned"):
        hsm._build_yubihsm2_ed25519_adapter()


def test_hsm_step12_and_step15_use_same_validated_session_once() -> None:
    good = HsmSession()
    evil = HsmSession(key=key_info(capabilities={"SIGN_EDDSA", "DELETE_ASYMMETRIC_KEY"}))

    class Provider(hsm._RuntimeHsmSessionProvider):
        def __init__(self):
            self.opens = 0

        def _open_authenticated_session(self):
            self.opens += 1
            return good if self.opens == 1 else evil

    provider = Provider()
    adapter = hsm._YubiHsm2Ed25519Adapter(
        profile=hsm_profile(), session_provider=provider
    )
    assert adapter._read_bound_public_key() == bytes(range(32))
    assert adapter._sign_bound_acceptance_message(b"message") == b"s" * 64
    assert provider.opens == 1
    assert good.sign_calls == 1
    assert evil.sign_calls == 0
    with pytest.raises(ValueError, match="production_hsm_sign_failed"):
        adapter._sign_bound_acceptance_message(b"message-2")
    assert good.sign_calls == 1


@pytest.mark.parametrize("bad_key", [
    key_info(algorithm="EC_P256"),
    key_info(capabilities={"SIGN_EDDSA", "EXPORTABLE_UNDER_WRAP"}),
    key_info(domains={8, 16}),
    key_info(exportable=True),
])
def test_hsm_rejects_wrong_key_algorithm_caps_domain_or_exportability(bad_key) -> None:
    session = HsmSession(key=bad_key)

    class Provider(hsm._RuntimeHsmSessionProvider):
        def _open_authenticated_session(self):
            return session

    adapter = hsm._YubiHsm2Ed25519Adapter(profile=hsm_profile(), session_provider=Provider())
    with pytest.raises(ValueError, match="production_hsm_capability_profile_invalid"):
        adapter._read_bound_public_key()
    assert session.sign_calls == 0


@pytest.mark.parametrize("bad_auth", [
    auth_info(capabilities={"SIGN_EDDSA", "DELETE_ASYMMETRIC_KEY"}),
    auth_info(delegated_capabilities={"SIGN_EDDSA"}),
    auth_info(domains={8, 16}),
    auth_info(exportable=True),
])
def test_hsm_rejects_wrong_auth_caps_delegation_domain_or_exportability(bad_auth) -> None:
    session = HsmSession(auth=bad_auth)

    class Provider(hsm._RuntimeHsmSessionProvider):
        def _open_authenticated_session(self):
            return session

    adapter = hsm._YubiHsm2Ed25519Adapter(profile=hsm_profile(), session_provider=Provider())
    with pytest.raises(ValueError, match="production_hsm_capability_profile_invalid"):
        adapter._read_bound_public_key()
    assert session.sign_calls == 0


def test_hsm_rejects_second_visible_asymmetric_key_before_metadata_reads() -> None:
    class Session(HsmSession):
        def _list_asymmetric_keys(self, domain):
            return [41, 43]

        def _get_asymmetric_key_info(self, object_id):
            raise AssertionError("must fail on enumeration first")

    class Provider(hsm._RuntimeHsmSessionProvider):
        def _open_authenticated_session(self):
            return Session()

    adapter = hsm._YubiHsm2Ed25519Adapter(profile=hsm_profile(), session_provider=Provider())
    with pytest.raises(ValueError, match="production_hsm_domain_isolation_invalid"):
        adapter._read_bound_public_key()


@pytest.mark.parametrize("connector", [
    "http://127.0.0.1:12345", "https://hsm.example", "yhusb://device-selected"
])
def test_hsm_profile_allows_only_exact_implementation_owned_direct_usb(connector) -> None:
    with pytest.raises(ValueError, match="production_hsm_connector_not_allowed"):
        hsm._BoundYubiHsmProfile(
            signing_key_object_id=41,
            runtime_auth_key_object_id=42,
            signer_domain_bit=8,
            connector_url=connector,
        )


def tpm_profile(*, attributes: int = 0x00040040, auth_policy_sha256=None):
    return tpm._BoundTpmNvProfile(
        nv_index=0x01500020,
        tpma_nv_mask=attributes,
        auth_policy_sha256=auth_policy_sha256,
        tcti_identity="test-hardware-tcti",
    )


def tpm_snapshot(*, tpms: bytes, profile=None, **updates):
    profile = profile or tpm_profile()
    value = {
        "nv_index": profile.nv_index,
        "tpma_nv_mask": profile.tpma_nv_mask,
        "auth_policy_sha256": profile.auth_policy_sha256,
        "tcti_identity": profile.tcti_identity,
        "nv_type": "TPM_NT_EXTEND",
        "name_alg": "SHA256",
        "data_size": 32,
        "orderly": False,
        "tpms_nv_public_marshaled": tpms,
        "raw_tpm_name": raw_name(tpms),
        "observed_nv_extend_digest": "a" * 64,
    }
    value.update(updates)
    return value


def adapter_for_snapshot(snapshot: dict, profile=None):
    profile = profile or tpm_profile()

    class Context:
        def _read_nv_extend_snapshot(self, nv_index):
            assert nv_index == profile.nv_index
            return dict(snapshot)

    class Provider(tpm._RuntimeTpmReadProvider):
        def _open_authorized_nv_read_context(self):
            return Context()

    return tpm._Tpm2NvAnchorAdapter(profile=profile, read_provider=Provider())


def test_unprovisioned_tpm_provider_fails_before_nv_read() -> None:
    provider = tpm._UnprovisionedRuntimeTpmReadProvider()
    with pytest.raises(ValueError, match="production_tpm_read_custody_unprovisioned"):
        provider._open_authorized_nv_read_context()
    with pytest.raises(ValueError, match="production_tpm_read_custody_unprovisioned"):
        tpm._build_tpm2_nv_anchor_adapter()


def test_tpm_adapter_parses_exact_inner_tpms_nv_public_wire_bytes() -> None:
    profile = tpm_profile()
    tpms = marshal_nv_public(
        nv_index=profile.nv_index, attributes=profile.tpma_nv_mask
    )
    state = adapter_for_snapshot(tpm_snapshot(tpms=tpms, profile=profile), profile)._read_current_nv_extend_state()
    assert state == {
        "nv_public_sha256": hashlib.sha256(tpms).hexdigest(),
        "nv_name_sha256": hashlib.sha256(raw_name(tpms)).hexdigest(),
        "observed_nv_extend_digest": "a" * 64,
    }


def test_tpm_rejects_outer_tpm2b_size_prefix_and_provider_wire_disagreement() -> None:
    profile = tpm_profile()
    inner = marshal_nv_public(nv_index=profile.nv_index, attributes=profile.tpma_nv_mask)
    outer_prefixed = len(inner).to_bytes(2, "big") + inner
    with pytest.raises(ValueError, match="production_tpm_nv_public_area_mismatch"):
        adapter_for_snapshot(tpm_snapshot(tpms=outer_prefixed, profile=profile), profile)._read_current_nv_extend_state()

    wrong_index_wire = marshal_nv_public(
        nv_index=profile.nv_index + 1, attributes=profile.tpma_nv_mask
    )
    supplied = tpm_snapshot(tpms=wrong_index_wire, profile=profile)
    supplied["nv_index"] = profile.nv_index
    with pytest.raises(ValueError, match="production_tpm_nv_public_area_mismatch"):
        adapter_for_snapshot(supplied, profile)._read_current_nv_extend_state()


@pytest.mark.parametrize("wire_kwargs", [
    {"name_alg": 0x000C},
    {"attributes": 0x00040000},
    {"attributes": 0x04040040},
    {"data_size": 64},
])
def test_tpm_rejects_wrong_hash_type_orderly_or_size_from_wire(wire_kwargs) -> None:
    profile = tpm_profile()
    kwargs = {"nv_index": profile.nv_index, "attributes": profile.tpma_nv_mask}
    kwargs.update(wire_kwargs)
    tpms = marshal_nv_public(**kwargs)
    with pytest.raises(ValueError, match="production_tpm_nv_public_area_mismatch"):
        adapter_for_snapshot(tpm_snapshot(tpms=tpms, profile=profile), profile)._read_current_nv_extend_state()


def test_tpm_auth_policy_is_bound_to_exact_wire_digest_or_explicit_absence() -> None:
    policy = bytes(range(32))
    profile = tpm_profile(auth_policy_sha256=policy.hex())
    tpms = marshal_nv_public(
        nv_index=profile.nv_index,
        attributes=profile.tpma_nv_mask,
        auth_policy=policy,
    )
    adapter_for_snapshot(tpm_snapshot(tpms=tpms, profile=profile), profile)._read_current_nv_extend_state()
    wrong = marshal_nv_public(
        nv_index=profile.nv_index,
        attributes=profile.tpma_nv_mask,
        auth_policy=bytes(reversed(policy)),
    )
    with pytest.raises(ValueError, match="production_tpm_nv_public_area_mismatch"):
        adapter_for_snapshot(tpm_snapshot(tpms=wrong, profile=profile), profile)._read_current_nv_extend_state()


def genesis() -> dict:
    return {
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


def proof_for(*, generation: int, manifest: dict, previous_hash: str, previous_digest: str, genesis_sha: str) -> dict:
    proof = {
        "schema": tpm.PROOF_SCHEMA,
        "producer_id": contract.PRODUCER_ID,
        "activation_generation": generation,
        "activation_manifest_sha256": canonical_sha256(manifest),
        "anchor_genesis_evidence_sha256": genesis_sha,
        "previous_activation_generation": generation - 1,
        "previous_anchor_proof_sha256": previous_hash,
        "previous_nv_extend_digest": previous_digest,
        "commitment_sha256": "",
        "observed_nv_extend_digest": "",
        "nv_public_sha256": "1" * 64,
        "nv_name_sha256": "2" * 64,
    }
    proof["commitment_sha256"] = tpm._commitment_sha256(proof)
    proof["observed_nv_extend_digest"] = tpm._expected_observed_digest(
        previous_nv_extend_digest=proof["previous_nv_extend_digest"],
        commitment_sha256=proof["commitment_sha256"],
    )
    return proof


def fresh_for(proof: dict) -> dict:
    return {
        "nv_public_sha256": proof["nv_public_sha256"],
        "nv_name_sha256": proof["nv_name_sha256"],
        "observed_nv_extend_digest": proof["observed_nv_extend_digest"],
    }


def test_generation_one_anchor_requires_exact_genesis_root() -> None:
    g = genesis()
    g_sha = canonical_sha256(g)
    manifest = {"schema": "m/v1", "activation_generation": 1}
    proof = proof_for(
        generation=1,
        manifest=manifest,
        previous_hash=g_sha,
        previous_digest=g["genesis_nv_extend_digest"],
        genesis_sha=g_sha,
    )
    assert tpm._verify_activation_anchor_proof(
        proof=proof,
        activation_manifest=manifest,
        previous_proof_or_genesis_evidence=g,
        fresh_nv_state=fresh_for(proof),
    ) == proof


def test_generation_n_gt_one_resolves_exact_genesis_and_parent_proof() -> None:
    g = genesis()
    g_sha = canonical_sha256(g)
    manifest1 = {"schema": "m/v1", "activation_generation": 1}
    proof1 = proof_for(
        generation=1,
        manifest=manifest1,
        previous_hash=g_sha,
        previous_digest=g["genesis_nv_extend_digest"],
        genesis_sha=g_sha,
    )
    manifest2 = {"schema": "m/v1", "activation_generation": 2}
    proof2 = proof_for(
        generation=2,
        manifest=manifest2,
        previous_hash=canonical_sha256(proof1),
        previous_digest=proof1["observed_nv_extend_digest"],
        genesis_sha=g_sha,
    )
    bundle = {"genesis_evidence": g, "previous_proof": proof1}
    assert tpm._verify_activation_anchor_proof(
        proof=proof2,
        activation_manifest=manifest2,
        previous_proof_or_genesis_evidence=bundle,
        fresh_nv_state=fresh_for(proof2),
    ) == proof2

    mutated_genesis = dict(g)
    mutated_genesis["genesis_nv_extend_digest"] = "4" * 64
    with pytest.raises(ValueError):
        tpm._verify_activation_anchor_proof(
            proof=proof2,
            activation_manifest=manifest2,
            previous_proof_or_genesis_evidence={
                "genesis_evidence": mutated_genesis,
                "previous_proof": proof1,
            },
            fresh_nv_state=fresh_for(proof2),
        )

    broken_parent = dict(proof1)
    broken_parent["observed_nv_extend_digest"] = "5" * 64
    with pytest.raises(ValueError):
        tpm._verify_activation_anchor_proof(
            proof=proof2,
            activation_manifest=manifest2,
            previous_proof_or_genesis_evidence={
                "genesis_evidence": g,
                "previous_proof": broken_parent,
            },
            fresh_nv_state=fresh_for(proof2),
        )
