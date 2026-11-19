from __future__ import annotations

import copy
import hashlib
import inspect
import json

import pytest

import continuityos.cross_ai_ruap_acceptance_origin_production_signer as production
import continuityos.cross_ai_ruap_acceptance_origin_signing_contract as contract
from continuityos.acceptance_origin_custody import tpm2_nv_anchor as tpm


def canonical_sha256(value) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    ).hexdigest()


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


def manifest(generation: int) -> dict:
    return {
        "schema": "activation-manifest-fixture/v1",
        "activation_generation": generation,
    }


def proof_for(
    *,
    activation_manifest: dict,
    generation: int,
    previous_generation: int,
    previous_hash: str,
    previous_digest: str,
    genesis_sha256: str,
) -> dict:
    proof = {
        "schema": tpm.PROOF_SCHEMA,
        "producer_id": contract.PRODUCER_ID,
        "activation_generation": generation,
        "activation_manifest_sha256": canonical_sha256(activation_manifest),
        "anchor_genesis_evidence_sha256": genesis_sha256,
        "previous_activation_generation": previous_generation,
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


def generation_one_values() -> tuple[dict, dict, dict]:
    root = genesis()
    root_sha = canonical_sha256(root)
    current_manifest = manifest(1)
    proof = proof_for(
        activation_manifest=current_manifest,
        generation=1,
        previous_generation=0,
        previous_hash=root_sha,
        previous_digest=root["genesis_nv_extend_digest"],
        genesis_sha256=root_sha,
    )
    return current_manifest, proof, root


def generation_two_values() -> tuple[dict, dict, dict]:
    root = genesis()
    root_sha = canonical_sha256(root)
    first_manifest = manifest(1)
    first = proof_for(
        activation_manifest=first_manifest,
        generation=1,
        previous_generation=0,
        previous_hash=root_sha,
        previous_digest=root["genesis_nv_extend_digest"],
        genesis_sha256=root_sha,
    )
    current_manifest = manifest(2)
    second = proof_for(
        activation_manifest=current_manifest,
        generation=2,
        previous_generation=1,
        previous_hash=canonical_sha256(first),
        previous_digest=first["observed_nv_extend_digest"],
        genesis_sha256=root_sha,
    )
    return current_manifest, second, {
        "genesis_evidence": root,
        "previous_proof": first,
    }


def test_static_anchor_prevalidation_precedes_current_signing_and_hardware() -> None:
    helper_source = inspect.getsource(production._prevalidate_anchor_evidence)
    flow_source = inspect.getsource(
        production.ProductionAcceptanceOriginSigner.produce
    )

    assert "_build_tpm2_nv_anchor_adapter" not in helper_source
    assert "_build_yubihsm2_ed25519_adapter" not in helper_source
    assert flow_source.index(
        "anchor_proof = _prevalidate_anchor_evidence("
    ) < flow_source.index("_require_current_signing(")
    assert flow_source.index("_require_current_signing(") < flow_source.index(
        "_build_tpm2_nv_anchor_adapter()"
    )


def test_generation_one_commitment_corruption_fails_in_step9_prevalidation() -> None:
    current_manifest, proof, root = generation_one_values()
    proof["commitment_sha256"] = "f" * 64

    with pytest.raises(ValueError):
        production._prevalidate_anchor_evidence(
            proof_value=proof,
            previous_value=root,
            activation_manifest=current_manifest,
        )


def test_generation_one_genesis_corruption_fails_in_step9_prevalidation() -> None:
    current_manifest, proof, root = generation_one_values()
    corrupted_root = copy.deepcopy(root)
    corrupted_root["genesis_nv_extend_digest"] = "4" * 64

    with pytest.raises(ValueError):
        production._prevalidate_anchor_evidence(
            proof_value=proof,
            previous_value=corrupted_root,
            activation_manifest=current_manifest,
        )


@pytest.mark.parametrize(
    "mutation",
    [
        "previous_anchor_proof_sha256",
        "previous_nv_extend_digest",
        "anchor_genesis_evidence_sha256",
    ],
)
def test_generation_two_chain_corruption_fails_in_step9_prevalidation(
    mutation: str,
) -> None:
    current_manifest, proof, bundle = generation_two_values()
    proof[mutation] = "f" * 64

    with pytest.raises(ValueError):
        production._prevalidate_anchor_evidence(
            proof_value=proof,
            previous_value=bundle,
            activation_manifest=current_manifest,
        )


def test_generation_two_parent_commitment_corruption_fails_in_step9_prevalidation() -> None:
    current_manifest, proof, bundle = generation_two_values()
    broken_bundle = copy.deepcopy(bundle)
    broken_bundle["previous_proof"]["commitment_sha256"] = "e" * 64

    with pytest.raises(ValueError):
        production._prevalidate_anchor_evidence(
            proof_value=proof,
            previous_value=broken_bundle,
            activation_manifest=current_manifest,
        )


def test_valid_generation_two_chain_passes_static_prevalidation_without_hardware() -> None:
    current_manifest, proof, bundle = generation_two_values()

    assert production._prevalidate_anchor_evidence(
        proof_value=proof,
        previous_value=bundle,
        activation_manifest=current_manifest,
    ) == proof
