from __future__ import annotations

import ast
import base64
import copy
import hashlib
import inspect
import json

import pytest

import continuityos.cross_ai_ruap_acceptance_origin_production_signer as production
import continuityos.cross_ai_ruap_acceptance_origin_signing_contract as contract
import continuityos.cross_ai_ruap_receipt_acceptance as acceptance
import continuityos.cross_ai_ruap_receipt_acceptance_origin_verifier as verifier
import continuityos.cross_ai_ruap_transport as transport
from continuityos.acceptance_origin_custody import tpm2_nv_anchor as tpm_anchor


CONSUMERS = ["consumer-a", "consumer-b"]
MASTER_SHA = "71ecbeb7210d003fcd5a9b0c1184aee5157366cc"
TREE_SHA = "43f187fa7ca9dbf14b48ab954f1550b6c939220f"
VERIFIER_BLOB = "96c16dbc8e3daab7e8ee632b26cd616507ce4521"


def canonical_sha256(value) -> str:
    return hashlib.sha256(json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    ).encode("ascii")).hexdigest()


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def ruap_snapshot() -> dict:
    return {
        "schema": "ruap.snapshot/v1",
        "generated_at": "PRIVATE_GENERATED_AT",
        "authority_ceiling": "OBSERVE_ONLY",
        "execution_authority": "NONE",
        "can_execute": False,
        "can_trade": False,
        "capital_permission": "DENY",
        "deploy_permission": "DENY",
        "sources": [{
            "id": "s1", "provider": "github",
            "locator": "PRIVATE_LOCATOR", "observed_at": "PRIVATE_OBSERVED_AT",
        }],
        "observations": [{
            "subject": "PRIVATE_SUBJECT", "claim": "PRIVATE_CLAIM",
            "class": "PROVIDER_READBACK", "source_id": "s1",
            "freshness_required_before_effect": True,
        }],
    }


def receipt() -> dict:
    return transport.build_cross_ai_ruap_transport_receipt(
        source_client="claude",
        target_client="cursor",
        ruap_snapshot=json.dumps(ruap_snapshot()),
    )


def sign_request() -> dict:
    return {
        "schema": contract.SIGN_REQUEST_SCHEMA,
        "transport_receipt": receipt(),
    }


def registry(public_key: bytes) -> dict:
    return {
        "schema": contract.REGISTRY_SCHEMA,
        "registry_id": contract.REGISTRY_ID,
        "keys": [{
            "producer_id": contract.PRODUCER_ID,
            "key_id": contract._derive_key_id(public_key),
            "algorithm": contract.ALGORITHM,
            "public_key_b64u": b64u(public_key),
            "usage": contract.PURPOSE,
            "state": "ACTIVE",
        }],
    }


def implementation_evidence() -> dict:
    return {
        "schema": production.IMPLEMENTATION_EVIDENCE_SCHEMA,
        "repository_full_name": "bitmaster162/continuityos",
        "producer_id": contract.PRODUCER_ID,
        "signer_release_id": production.SIGNER_RELEASE_ID,
        "reviewed_head_sha": "1" * 40,
        "reviewed_tree_sha": "2" * 40,
        "signer_source_blob_sha": "3" * 40,
        "signer_source_sha256": "4" * 64,
        "producer_signing_contract_file_id": production.PRODUCER_SIGNING_CONTRACT_FILE_ID,
        "producer_signing_contract_revision": production.PRODUCER_SIGNING_CONTRACT_REVISION,
        "ceremony_spec_file_id": production.CEREMONY_SPEC_FILE_ID,
        "ceremony_spec_semantic_revision": production.CEREMONY_SPEC_SEMANTIC_REVISION,
        "custody_profile": production.CUSTODY_PROFILE,
        "conformance_scope": production.CONFORMANCE_SCOPE,
        "test_only": False,
        "caller_selectable_key": False,
        "caller_selectable_purpose": False,
        "arbitrary_message_signing": False,
        "production_hardware_custody_path_supported": True,
        "conformance_result": "PASS",
    }


def phase_b_packet(public_key: bytes, impl: dict) -> dict:
    candidate = registry(public_key)
    candidate_sha = canonical_sha256(candidate)
    key_id = contract._derive_key_id(public_key)
    public_sha = hashlib.sha256(public_key).hexdigest()
    return {
        "schema": production.PROVISIONING_PACKET_SCHEMA,
        "producer_id": contract.PRODUCER_ID,
        "algorithm": contract.ALGORITHM,
        "custody_profile": production.CUSTODY_PROFILE,
        "custody_non_exportability_result": "PASS",
        "custody_capability_isolation_result": "PASS",
        "signer_conformance_scope": production.CONFORMANCE_SCOPE,
        "signer_release_id": production.SIGNER_RELEASE_ID,
        "signer_implementation_evidence_sha256": canonical_sha256(impl),
        "signer_conformance_result": "PASS",
        "key_state": "PROVISIONED_DISABLED",
        "production_signing_enabled": False,
        "production_facade_key_binding_present": False,
        "production_signer_key_reachable": False,
        "production_runtime_hsm_auth_path_enabled": False,
        "current_signing_key_configured": False,
        "current_signing": False,
        "key_id": key_id,
        "public_key_b64u": b64u(public_key),
        "public_key_sha256": public_sha,
        "candidate_registry": candidate,
        "candidate_registry_sha256": candidate_sha,
        "pre_pin_registry_sha256": verifier.PINNED_REGISTRY_SHA256,
        "verifier_master_sha": MASTER_SHA,
        "verifier_tree_sha": TREE_SHA,
        "verifier_source_blob_sha": VERIFIER_BLOB,
        "frozen_contract_file_id": production.PRODUCER_SIGNING_CONTRACT_FILE_ID,
        "frozen_contract_revision": production.PRODUCER_SIGNING_CONTRACT_REVISION,
        "parent_contract_file_id": "1_OXC2uquMxXjxDqBWfK4CvzQrB91yWRYn2I0A5yxsqU",
        "parent_contract_revision": 2,
        "chat_authority_file_id": "1zte_-igHmOwbRZjcVNQPlsmtAKEVoLPW478NSQIH1sU",
        "chat_authority_revision": 3,
        "primary_authority_file_id": "1gQbxoEgd8QefizRT_AvZHSl_xcXTBmBoUP1_zpfcawc",
        "primary_authority_revision": 2,
        "ceremony_spec_file_id": production.CEREMONY_SPEC_FILE_ID,
        "ceremony_spec_semantic_revision": production.CEREMONY_SPEC_SEMANTIC_REVISION,
        "ceremony_spec_freeze_revision": production.CEREMONY_SPEC_FREEZE_REVISION,
        "ceremony_spec_frozen": True,
        "hardware_readiness_evidence_sha256": "5" * 64,
        "private_key_exported": False,
        "production_signature_attempted": False,
        "phase_a_packet_sha256": "6" * 64,
        "contract_complete": True,
        "trust_anchor_published": True,
        "rollout_structurally_eligible": True,
        "rollout_authorized": False,
        "phase_b_review_required": True,
        "activation_eligible": False,
        "packet_phase": "FINAL_WITH_PIN_UPDATE_LINEAGE",
        "pin_update_branch": "agent/pin-update-r1",
        "pin_update_reviewed_head_sha": "7" * 40,
        "pin_update_reviewed_tree_sha": "8" * 40,
        "pin_update_verifier_source_blob_sha": "9" * 40,
        "pin_update_tests_blob_sha": "a" * 40,
        "pin_update_pr_number": 999,
        "pin_update_merge_commit_sha": "b" * 40,
        "master_sha_at_pin_merge_readback": "b" * 40,
        "phase_b_observed_master_sha": "b" * 40,
        "published_registry_sha256": candidate_sha,
        "result": "FINAL_WITH_PIN_UPDATE_LINEAGE",
    }


def phase_b_review(packet: dict) -> dict:
    return {
        "schema": production.PHASE_B_REVIEW_SCHEMA,
        "phase_b_packet_sha256": canonical_sha256(packet),
        "phase_a_packet_sha256": packet["phase_a_packet_sha256"],
        "pin_update_merge_commit_sha": packet["pin_update_merge_commit_sha"],
        "phase_b_observed_master_sha": packet["phase_b_observed_master_sha"],
        "published_registry_sha256": packet["published_registry_sha256"],
        "contract_complete_confirmed": True,
        "lineage_confirmed": True,
        "cross_object_coherence_confirmed": True,
        "rollout_authorized": True,
        "review_result": "PASS",
    }


def rollout_evidence(packet: dict) -> dict:
    cohort_id = "cohort-fixture-r1"
    registry_sha = packet["published_registry_sha256"]
    membership = canonical_sha256({
        "schema": production.COHORT_MEMBERSHIP_SCHEMA,
        "cohort_id": cohort_id,
        "consumer_ids": sorted(CONSUMERS),
    })
    return {
        "schema": production.ROLLOUT_EVIDENCE_SCHEMA,
        "cohort_id": cohort_id,
        "cohort_membership_sha256": membership,
        "expected_consumer_count": len(CONSUMERS),
        "verifier_release_id": "verifier-fixture-r1",
        "registry_sha256": registry_sha,
        "readbacks": [{
            "consumer_id": consumer,
            "verifier_release_id": "verifier-fixture-r1",
            "registry_sha256": registry_sha,
            "ok": True,
        } for consumer in CONSUMERS],
    }


def rollout_receipt(evidence: dict, packet: dict, review: dict) -> dict:
    return {
        "schema": production.ROLLOUT_RECEIPT_SCHEMA,
        "cohort_id": evidence["cohort_id"],
        "cohort_membership_sha256": evidence["cohort_membership_sha256"],
        "expected_consumer_count": evidence["expected_consumer_count"],
        "verifier_release_id": evidence["verifier_release_id"],
        "registry_sha256": evidence["registry_sha256"],
        "successful_readback_count": len(evidence["readbacks"]),
        "failed_readback_count": 0,
        "unresolved_consumer_count": 0,
        "readback_evidence_sha256": canonical_sha256(evidence),
        "result": "COMPLETE",
        "phase_b_packet_sha256": canonical_sha256(packet),
        "phase_b_review_receipt_sha256": canonical_sha256(review),
    }


def activation_manifest(
    packet: dict, rollout: dict, impl: dict, *, generation: int = 1
) -> dict:
    return {
        "schema": production.ACTIVATION_MANIFEST_SCHEMA,
        "producer_id": contract.PRODUCER_ID,
        "activation_generation": generation,
        "key_id": packet["key_id"],
        "public_key_sha256": packet["public_key_sha256"],
        "registry_sha256": packet["published_registry_sha256"],
        "verifier_release_id": rollout["verifier_release_id"],
        "rollout_cohort_id": rollout["cohort_id"],
        "rollout_membership_sha256": rollout["cohort_membership_sha256"],
        "rollout_receipt_sha256": canonical_sha256(rollout),
        "signer_release_id": production.SIGNER_RELEASE_ID,
        "implementation_evidence_sha256": canonical_sha256(impl),
    }


def genesis_and_proof(manifest: dict) -> tuple[dict, dict, dict]:
    nv_public_sha = "c" * 64
    nv_name_sha = "d" * 64
    genesis = {
        "schema": tpm_anchor.GENESIS_SCHEMA,
        "producer_id": contract.PRODUCER_ID,
        "activation_generation": 0,
        "nv_public_sha256": nv_public_sha,
        "nv_name_sha256": nv_name_sha,
        "genesis_nv_extend_digest": "e" * 64,
        "nv_type": "TPM_NT_EXTEND",
        "name_alg": "SHA256",
        "data_size": 32,
        "orderly": False,
        "result": "GENESIS_READY",
    }
    genesis_sha = canonical_sha256(genesis)
    proof = {
        "schema": tpm_anchor.PROOF_SCHEMA,
        "producer_id": contract.PRODUCER_ID,
        "activation_generation": manifest["activation_generation"],
        "activation_manifest_sha256": canonical_sha256(manifest),
        "anchor_genesis_evidence_sha256": genesis_sha,
        "previous_activation_generation": 0,
        "previous_anchor_proof_sha256": genesis_sha,
        "previous_nv_extend_digest": genesis["genesis_nv_extend_digest"],
        "commitment_sha256": "",
        "observed_nv_extend_digest": "",
        "nv_public_sha256": nv_public_sha,
        "nv_name_sha256": nv_name_sha,
    }
    commitment = {
        "schema": tpm_anchor.COMMITMENT_SCHEMA,
        "producer_id": contract.PRODUCER_ID,
        "activation_generation": proof["activation_generation"],
        "activation_manifest_sha256": proof["activation_manifest_sha256"],
        "anchor_genesis_evidence_sha256": proof["anchor_genesis_evidence_sha256"],
        "previous_anchor_proof_sha256": proof["previous_anchor_proof_sha256"],
    }
    proof["commitment_sha256"] = canonical_sha256(commitment)
    proof["observed_nv_extend_digest"] = hashlib.sha256(
        bytes.fromhex(proof["previous_nv_extend_digest"])
        + bytes.fromhex(proof["commitment_sha256"])
    ).hexdigest()
    fresh = {
        "nv_public_sha256": nv_public_sha,
        "nv_name_sha256": nv_name_sha,
        "observed_nv_extend_digest": proof["observed_nv_extend_digest"],
    }
    return genesis, proof, fresh


def runtime_context(public_key: bytes) -> tuple[dict, dict]:
    impl = implementation_evidence()
    packet = phase_b_packet(public_key, impl)
    review = phase_b_review(packet)
    evidence = rollout_evidence(packet)
    rollout = rollout_receipt(evidence, packet, review)
    manifest = activation_manifest(packet, rollout, impl)
    genesis, proof, fresh = genesis_and_proof(manifest)
    context = {
        "state": "CURRENT_SIGNING",
        "bound_key_id": packet["key_id"],
        "bound_registry_sha256": packet["published_registry_sha256"],
        "production_facade_key_binding_present": True,
        "production_signer_key_reachable": True,
        "production_runtime_hsm_auth_path_enabled": True,
        "current_signing_key_configured": True,
        "phase_b_packet": packet,
        "phase_b_review_receipt": review,
        "rollout_evidence": evidence,
        "rollout_receipt": rollout,
        "implementation_evidence": impl,
        "activation_manifest": manifest,
        "activation_anchor_proof": proof,
        "previous_anchor_proof_or_genesis_evidence": genesis,
    }
    return context, fresh


def test_default_production_facade_is_inert_before_any_hardware(monkeypatch) -> None:
    monkeypatch.setattr(
        production, "_build_tpm2_nv_anchor_adapter",
        lambda: (_ for _ in ()).throw(AssertionError("TPM must not be reached")),
    )
    monkeypatch.setattr(
        production, "_build_yubihsm2_ed25519_adapter",
        lambda: (_ for _ in ()).throw(AssertionError("HSM must not be reached")),
    )
    with pytest.raises(ValueError, match="production_signer_not_activated"):
        production.ProductionAcceptanceOriginSigner().produce(
            sign_request=sign_request()
        )


def test_request_rejects_caller_selected_signing_material_before_builder(
    monkeypatch,
) -> None:
    supplied = sign_request()
    supplied["key_id"] = "caller-key"
    monkeypatch.setattr(
        production.acceptance_builder,
        "accept_cross_ai_ruap_transport_receipt",
        lambda _: (_ for _ in ()).throw(AssertionError("builder must not run")),
    )
    with pytest.raises(ValueError, match="sign_request_unknown_key"):
        production.ProductionAcceptanceOriginSigner().produce(
            sign_request=supplied
        )


def test_phase_b_review_mismatch_fails_before_hardware(monkeypatch) -> None:
    public_key = bytes(range(32))
    context, _ = runtime_context(public_key)
    context["phase_b_review_receipt"]["phase_b_packet_sha256"] = "0" * 64
    monkeypatch.setattr(
        production, "_load_runtime_signing_context", lambda: context
    )
    monkeypatch.setattr(
        production, "_build_tpm2_nv_anchor_adapter",
        lambda: (_ for _ in ()).throw(AssertionError("TPM must not be reached")),
    )
    with pytest.raises(ValueError, match="production_phase_b_review_receipt_invalid"):
        production.ProductionAcceptanceOriginSigner().produce(
            sign_request=sign_request()
        )


def test_full_fake_hardware_free_flow_materializes_once_and_signs_once(
    monkeypatch,
) -> None:
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    private_key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    context, fresh = runtime_context(public_key)
    monkeypatch.setattr(
        production, "_load_runtime_signing_context", lambda: copy.deepcopy(context)
    )

    calls = {"builder": 0, "tpm": 0, "public": 0, "sign": 0}
    real_builder = acceptance.accept_cross_ai_ruap_transport_receipt

    def counted_builder(value):
        calls["builder"] += 1
        return real_builder(value)

    monkeypatch.setattr(
        production.acceptance_builder,
        "accept_cross_ai_ruap_transport_receipt",
        counted_builder,
    )

    class FakeTpm:
        def _read_current_nv_extend_state(self):
            calls["tpm"] += 1
            return dict(fresh)

    class FakeHsm:
        def _read_bound_public_key(self):
            calls["public"] += 1
            return public_key

        def _sign_bound_acceptance_message(self, message):
            calls["sign"] += 1
            return private_key.sign(message)

    monkeypatch.setattr(
        production, "_build_tpm2_nv_anchor_adapter", lambda: FakeTpm()
    )
    monkeypatch.setattr(
        production, "_build_yubihsm2_ed25519_adapter", lambda: FakeHsm()
    )

    request = sign_request()
    before = copy.deepcopy(request)
    response = production.ProductionAcceptanceOriginSigner().produce(
        sign_request=request
    )
    assert request == before
    assert calls == {"builder": 1, "tpm": 1, "public": 1, "sign": 1}
    assert response["schema"] == contract.PRODUCER_RESPONSE_SCHEMA
    assert set(response) == {"schema", "acceptance", "signature_envelope"}
    assert response["acceptance"] == real_builder(before["transport_receipt"])
    assert response["signature_envelope"]["acceptance_sha256"] == canonical_sha256(
        response["acceptance"]
    )

    monkeypatch.setattr(
        verifier,
        "PINNED_REGISTRY_SHA256",
        context["phase_b_packet"]["published_registry_sha256"],
    )
    checked = verifier.verify_cross_ai_ruap_receipt_acceptance_origin(
        accepted_receipt=response["acceptance"],
        key_registry=context["phase_b_packet"]["candidate_registry"],
        signature_envelope=response["signature_envelope"],
    )
    assert checked.ok is True


def test_production_facade_has_no_public_backend_or_key_selector() -> None:
    signature = inspect.signature(production.ProductionAcceptanceOriginSigner)
    assert tuple(signature.parameters) == ()
    produce = inspect.signature(
        production.ProductionAcceptanceOriginSigner.produce
    )
    assert tuple(produce.parameters) == ("self", "sign_request")
    assert produce.parameters["sign_request"].kind is inspect.Parameter.KEYWORD_ONLY


def test_production_source_has_no_effectful_or_hardware_imports() -> None:
    modules = [production, contract]
    forbidden = {
        "os", "subprocess", "socket", "requests", "urllib", "http",
        "yubihsm", "tpm2_pytss",
    }
    for module in modules:
        tree = ast.parse(inspect.getsource(module))
        roots = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                roots.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                roots.add(node.module.split(".")[0])
        assert roots.isdisjoint(forbidden)
