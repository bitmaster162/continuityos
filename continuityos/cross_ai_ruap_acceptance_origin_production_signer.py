"""Production-capable Acceptance Origin Signer R1 facade.

This source is intentionally inert until separately reviewed runtime activation,
YubiHSM authentication custody, and TPM read-authorization/NV-policy contracts are
implemented. The public facade accepts only the frozen transport-receipt sign request.
No caller can select a key, backend, purpose, registry, device, message, or digest.
"""
from __future__ import annotations

import base64
import hashlib
from typing import Any

from . import cross_ai_ruap_acceptance_origin_signing_contract as contract
from . import cross_ai_ruap_receipt_acceptance as acceptance_builder
from . import cross_ai_ruap_receipt_acceptance_origin_verifier as origin_verifier
from .acceptance_origin_custody.tpm2_nv_anchor import (
    _build_tpm2_nv_anchor_adapter,
    _require_genesis,
    _require_previous_evidence_bundle,
    _require_proof_shape,
    _verify_activation_anchor_proof,
)
from .acceptance_origin_custody.yubihsm2_ed25519 import (
    _build_yubihsm2_ed25519_adapter,
)

SIGNER_RELEASE_ID = "continuityos.cross_ai_ruap_acceptance_origin_production_signer/v1"
CUSTODY_PROFILE = "YUBIHSM2_ED25519_PLUS_TPM2_NV_R1"
CONFORMANCE_SCOPE = "PRODUCTION_ACCEPTANCE_ORIGIN_SIGNER_R1"

PROVISIONING_PACKET_SCHEMA = "continuityos.cross_ai_ruap_acceptance_origin_provisioning_packet/v1"
PHASE_B_REVIEW_SCHEMA = "continuityos.cross_ai_ruap_acceptance_origin_phase_b_review_receipt/v1"
ROLLOUT_EVIDENCE_SCHEMA = "continuityos.cross_ai_ruap_acceptance_origin_rollout_readback_evidence/v1"
ROLLOUT_RECEIPT_SCHEMA = "continuityos.cross_ai_ruap_acceptance_origin_rollout_receipt/v1"
COHORT_MEMBERSHIP_SCHEMA = "continuityos.cross_ai_ruap_acceptance_origin_rollout_membership/v1"
IMPLEMENTATION_EVIDENCE_SCHEMA = "continuityos.cross_ai_ruap_acceptance_origin_production_signer_implementation_evidence/v1"
ACTIVATION_MANIFEST_SCHEMA = "continuityos.cross_ai_ruap_acceptance_origin_activation_manifest/v1"

PRODUCER_SIGNING_CONTRACT_FILE_ID = "1o7wfzDe-CJzkQo7zFms--QCF9bpgYGwWNX_J1ywoexM"
PRODUCER_SIGNING_CONTRACT_REVISION = 6
CEREMONY_SPEC_FILE_ID = "1nWpQgo0Aihr-5F5jhoQ3F8qpbrbVlvjTIqlB4H9Bdsk"
CEREMONY_SPEC_SEMANTIC_REVISION = 9
CEREMONY_SPEC_FREEZE_REVISION = 10

_PHASE_A_IMMUTABLE_KEYS = frozenset({
    "producer_id", "algorithm", "custody_profile",
    "custody_non_exportability_result", "custody_capability_isolation_result",
    "signer_conformance_scope", "signer_release_id",
    "signer_implementation_evidence_sha256", "signer_conformance_result",
    "key_state", "production_signing_enabled",
    "production_facade_key_binding_present", "production_signer_key_reachable",
    "production_runtime_hsm_auth_path_enabled", "current_signing_key_configured",
    "current_signing", "key_id", "public_key_b64u", "public_key_sha256",
    "candidate_registry", "candidate_registry_sha256", "pre_pin_registry_sha256",
    "verifier_master_sha", "verifier_tree_sha", "verifier_source_blob_sha",
    "frozen_contract_file_id", "frozen_contract_revision",
    "parent_contract_file_id", "parent_contract_revision",
    "chat_authority_file_id", "chat_authority_revision",
    "primary_authority_file_id", "primary_authority_revision",
    "ceremony_spec_file_id", "ceremony_spec_semantic_revision",
    "ceremony_spec_freeze_revision", "ceremony_spec_frozen",
    "hardware_readiness_evidence_sha256", "private_key_exported",
    "production_signature_attempted",
})
_PHASE_B_KEYS = _PHASE_A_IMMUTABLE_KEYS | frozenset({
    "schema", "phase_a_packet_sha256", "contract_complete",
    "trust_anchor_published", "rollout_structurally_eligible",
    "rollout_authorized", "phase_b_review_required", "activation_eligible",
    "packet_phase", "pin_update_branch", "pin_update_reviewed_head_sha",
    "pin_update_reviewed_tree_sha", "pin_update_verifier_source_blob_sha",
    "pin_update_tests_blob_sha", "pin_update_pr_number",
    "pin_update_merge_commit_sha", "master_sha_at_pin_merge_readback",
    "phase_b_observed_master_sha", "published_registry_sha256", "result",
})
_PHASE_B_REVIEW_KEYS = frozenset({
    "schema", "phase_b_packet_sha256", "phase_a_packet_sha256",
    "pin_update_merge_commit_sha", "phase_b_observed_master_sha",
    "published_registry_sha256", "contract_complete_confirmed",
    "lineage_confirmed", "cross_object_coherence_confirmed",
    "rollout_authorized", "review_result",
})
_ROLLOUT_EVIDENCE_KEYS = frozenset({
    "schema", "cohort_id", "cohort_membership_sha256",
    "expected_consumer_count", "verifier_release_id", "registry_sha256",
    "readbacks",
})
_READBACK_KEYS = frozenset({
    "consumer_id", "verifier_release_id", "registry_sha256", "ok",
})
_ROLLOUT_RECEIPT_KEYS = frozenset({
    "schema", "cohort_id", "cohort_membership_sha256",
    "expected_consumer_count", "verifier_release_id", "registry_sha256",
    "successful_readback_count", "failed_readback_count",
    "unresolved_consumer_count", "readback_evidence_sha256", "result",
    "phase_b_packet_sha256", "phase_b_review_receipt_sha256",
})
_IMPLEMENTATION_EVIDENCE_KEYS = frozenset({
    "schema", "repository_full_name", "producer_id", "signer_release_id",
    "reviewed_head_sha", "reviewed_tree_sha", "signer_source_blob_sha",
    "signer_source_sha256", "producer_signing_contract_file_id",
    "producer_signing_contract_revision", "ceremony_spec_file_id",
    "ceremony_spec_semantic_revision", "custody_profile", "conformance_scope",
    "test_only", "caller_selectable_key", "caller_selectable_purpose",
    "arbitrary_message_signing", "production_hardware_custody_path_supported",
    "conformance_result",
})
_ACTIVATION_KEYS = frozenset({
    "schema", "producer_id", "activation_generation", "key_id",
    "public_key_sha256", "registry_sha256", "verifier_release_id",
    "rollout_cohort_id", "rollout_membership_sha256",
    "rollout_receipt_sha256", "signer_release_id",
    "implementation_evidence_sha256",
})
_RUNTIME_CONTEXT_KEYS = frozenset({
    "state", "bound_key_id", "bound_registry_sha256",
    "production_facade_key_binding_present", "production_signer_key_reachable",
    "production_runtime_hsm_auth_path_enabled", "current_signing_key_configured",
    "phase_b_packet", "phase_b_review_receipt", "rollout_evidence",
    "rollout_receipt", "implementation_evidence", "activation_manifest",
    "activation_anchor_proof", "previous_anchor_proof_or_genesis_evidence",
})

_MAX_ROLLOUT_CONSUMERS = contract.MAX_CONTAINER_ITEMS


def _bounded_text(value: Any) -> bool:
    return (
        type(value) is str
        and 1 <= len(value) <= contract.MAX_STRING_LEN
        and all(char.isascii() and ord(char) >= 0x20 for char in value)
    )


def _positive_revision(value: Any) -> bool:
    return type(value) is int and 1 <= value <= contract.MAX_INTEGER_ABS


def _require_phase_b_packet(value: Any) -> dict[str, Any]:
    packet = contract._require_exact_keys(
        contract._snapshot_bounded(value), _PHASE_B_KEYS, "phase_b_packet"
    )
    if (
        packet["schema"] != PROVISIONING_PACKET_SCHEMA
        or packet["packet_phase"] != "FINAL_WITH_PIN_UPDATE_LINEAGE"
        or packet["contract_complete"] is not True
        or packet["trust_anchor_published"] is not True
        or packet["rollout_structurally_eligible"] is not True
        or packet["rollout_authorized"] is not False
        or packet["phase_b_review_required"] is not True
        or packet["activation_eligible"] is not False
        or packet["current_signing"] is not False
        or packet["result"] != "FINAL_WITH_PIN_UPDATE_LINEAGE"
    ):
        raise ValueError("production_phase_b_packet_invalid")
    if (
        packet["producer_id"] != contract.PRODUCER_ID
        or packet["algorithm"] != contract.ALGORITHM
        or packet["custody_profile"] != CUSTODY_PROFILE
        or packet["custody_non_exportability_result"] != "PASS"
        or packet["custody_capability_isolation_result"] != "PASS"
        or packet["signer_conformance_scope"] != CONFORMANCE_SCOPE
        or packet["signer_release_id"] != SIGNER_RELEASE_ID
        or packet["signer_conformance_result"] != "PASS"
        or packet["key_state"] != "PROVISIONED_DISABLED"
        or packet["production_signing_enabled"] is not False
        or packet["production_facade_key_binding_present"] is not False
        or packet["production_signer_key_reachable"] is not False
        or packet["production_runtime_hsm_auth_path_enabled"] is not False
        or packet["current_signing_key_configured"] is not False
        or packet["ceremony_spec_frozen"] is not True
        or packet["private_key_exported"] is not False
        or packet["production_signature_attempted"] is not False
    ):
        raise ValueError("production_phase_b_packet_invalid")
    for key in (
        "phase_a_packet_sha256", "signer_implementation_evidence_sha256",
        "candidate_registry_sha256", "pre_pin_registry_sha256",
        "hardware_readiness_evidence_sha256", "published_registry_sha256",
        "public_key_sha256",
    ):
        if not contract._is_sha256(packet[key]):
            raise ValueError("production_phase_b_packet_invalid")
    for key in (
        "verifier_master_sha", "verifier_tree_sha", "verifier_source_blob_sha",
        "pin_update_reviewed_head_sha", "pin_update_reviewed_tree_sha",
        "pin_update_verifier_source_blob_sha", "pin_update_tests_blob_sha",
        "pin_update_merge_commit_sha", "master_sha_at_pin_merge_readback",
        "phase_b_observed_master_sha",
    ):
        if not contract._is_git_sha(packet[key]):
            raise ValueError("production_phase_b_packet_invalid")
    if (
        packet["master_sha_at_pin_merge_readback"] != packet["pin_update_merge_commit_sha"]
        or packet["published_registry_sha256"] != packet["candidate_registry_sha256"]
        or not _bounded_text(packet["pin_update_branch"])
        or type(packet["pin_update_pr_number"]) is not int
        or not 1 <= packet["pin_update_pr_number"] <= contract.MAX_INTEGER_ABS
    ):
        raise ValueError("production_phase_b_packet_invalid")
    for key in (
        "frozen_contract_file_id", "parent_contract_file_id",
        "chat_authority_file_id", "primary_authority_file_id",
        "ceremony_spec_file_id",
    ):
        if not _bounded_text(packet[key]):
            raise ValueError("production_phase_b_packet_invalid")
    for key in (
        "frozen_contract_revision", "parent_contract_revision",
        "chat_authority_revision", "primary_authority_revision",
        "ceremony_spec_semantic_revision", "ceremony_spec_freeze_revision",
    ):
        if not _positive_revision(packet[key]):
            raise ValueError("production_phase_b_packet_invalid")
    if (
        packet["frozen_contract_file_id"] != PRODUCER_SIGNING_CONTRACT_FILE_ID
        or packet["frozen_contract_revision"] != PRODUCER_SIGNING_CONTRACT_REVISION
        or packet["ceremony_spec_file_id"] != CEREMONY_SPEC_FILE_ID
        or packet["ceremony_spec_semantic_revision"] != CEREMONY_SPEC_SEMANTIC_REVISION
        or packet["ceremony_spec_freeze_revision"] != CEREMONY_SPEC_FREEZE_REVISION
    ):
        raise ValueError("production_phase_b_packet_invalid")

    public_key = contract._decode_canonical_b64u(
        packet["public_key_b64u"], expected_len=32, label="phase_b_public_key"
    )
    public_key_sha256 = hashlib.sha256(public_key).hexdigest()
    if (
        packet["public_key_sha256"] != public_key_sha256
        or packet["key_id"] != contract._derive_key_id(public_key)
    ):
        raise ValueError("production_key_id_mismatch")
    registry, keys = contract._require_registry(packet["candidate_registry"])
    if (
        len(keys) != 1
        or keys[0]["producer_id"] != contract.PRODUCER_ID
        or keys[0]["key_id"] != packet["key_id"]
        or keys[0]["public_key_b64u"] != packet["public_key_b64u"]
        or keys[0]["algorithm"] != contract.ALGORITHM
        or keys[0]["usage"] != contract.PURPOSE
        or keys[0]["state"] != "ACTIVE"
        or contract._canonical_sha256(registry) != packet["candidate_registry_sha256"]
    ):
        raise ValueError("production_registry_coherence_mismatch")
    return packet


def _require_phase_b_review(
    value: Any, *, phase_b_packet: dict[str, Any]
) -> dict[str, Any]:
    receipt = contract._require_exact_keys(
        contract._snapshot_bounded(value), _PHASE_B_REVIEW_KEYS,
        "phase_b_review_receipt",
    )
    if (
        receipt["schema"] != PHASE_B_REVIEW_SCHEMA
        or receipt["contract_complete_confirmed"] is not True
        or receipt["lineage_confirmed"] is not True
        or receipt["cross_object_coherence_confirmed"] is not True
        or receipt["rollout_authorized"] is not True
        or receipt["review_result"] != "PASS"
    ):
        raise ValueError("production_phase_b_review_receipt_invalid")
    for key in (
        "phase_b_packet_sha256", "phase_a_packet_sha256", "published_registry_sha256"
    ):
        if not contract._is_sha256(receipt[key]):
            raise ValueError("production_phase_b_review_receipt_invalid")
    for key in ("pin_update_merge_commit_sha", "phase_b_observed_master_sha"):
        if not contract._is_git_sha(receipt[key]):
            raise ValueError("production_phase_b_review_receipt_invalid")
    if (
        receipt["phase_b_packet_sha256"] != contract._canonical_sha256(phase_b_packet)
        or receipt["phase_a_packet_sha256"] != phase_b_packet["phase_a_packet_sha256"]
        or receipt["pin_update_merge_commit_sha"] != phase_b_packet["pin_update_merge_commit_sha"]
        or receipt["phase_b_observed_master_sha"] != phase_b_packet["phase_b_observed_master_sha"]
        or receipt["published_registry_sha256"] != phase_b_packet["published_registry_sha256"]
    ):
        raise ValueError("production_phase_b_review_receipt_invalid")
    return receipt


def _cohort_membership_sha256(*, cohort_id: str, consumer_ids: list[str]) -> str:
    return contract._canonical_sha256({
        "schema": COHORT_MEMBERSHIP_SCHEMA,
        "cohort_id": cohort_id,
        "consumer_ids": sorted(consumer_ids),
    })


def _require_rollout_evidence(value: Any) -> dict[str, Any]:
    evidence = contract._require_exact_keys(
        contract._snapshot_bounded(value), _ROLLOUT_EVIDENCE_KEYS,
        "rollout_evidence",
    )
    if (
        evidence["schema"] != ROLLOUT_EVIDENCE_SCHEMA
        or not contract._is_identifier(evidence["cohort_id"])
        or not contract._is_sha256(evidence["cohort_membership_sha256"])
        or not contract._is_identifier(evidence["verifier_release_id"])
        or not contract._is_sha256(evidence["registry_sha256"])
        or type(evidence["expected_consumer_count"]) is not int
        or not 1 <= evidence["expected_consumer_count"] <= _MAX_ROLLOUT_CONSUMERS
        or type(evidence["readbacks"]) is not list
        or len(evidence["readbacks"]) != evidence["expected_consumer_count"]
    ):
        raise ValueError("production_rollout_evidence_mismatch")
    seen: set[str] = set()
    consumers: list[str] = []
    for item in evidence["readbacks"]:
        readback = contract._require_exact_keys(item, _READBACK_KEYS, "rollout_readback")
        consumer_id = readback["consumer_id"]
        if (
            not contract._is_identifier(consumer_id)
            or consumer_id in seen
            or readback["verifier_release_id"] != evidence["verifier_release_id"]
            or readback["registry_sha256"] != evidence["registry_sha256"]
            or readback["ok"] is not True
        ):
            raise ValueError("production_rollout_evidence_mismatch")
        seen.add(consumer_id)
        consumers.append(consumer_id)
    if evidence["cohort_membership_sha256"] != _cohort_membership_sha256(
        cohort_id=evidence["cohort_id"], consumer_ids=consumers
    ):
        raise ValueError("production_rollout_evidence_mismatch")
    return evidence


def _require_rollout_receipt(
    value: Any,
    *,
    evidence: dict[str, Any],
    phase_b_packet: dict[str, Any],
    phase_b_review: dict[str, Any],
) -> dict[str, Any]:
    receipt = contract._require_exact_keys(
        contract._snapshot_bounded(value), _ROLLOUT_RECEIPT_KEYS,
        "rollout_receipt",
    )
    if (
        receipt["schema"] != ROLLOUT_RECEIPT_SCHEMA
        or not contract._is_identifier(receipt["cohort_id"])
        or not contract._is_sha256(receipt["cohort_membership_sha256"])
        or not contract._is_identifier(receipt["verifier_release_id"])
        or not contract._is_sha256(receipt["registry_sha256"])
        or not contract._is_sha256(receipt["readback_evidence_sha256"])
        or not contract._is_sha256(receipt["phase_b_packet_sha256"])
        or not contract._is_sha256(receipt["phase_b_review_receipt_sha256"])
    ):
        raise ValueError("production_rollout_evidence_mismatch")
    for key in (
        "expected_consumer_count", "successful_readback_count",
        "failed_readback_count", "unresolved_consumer_count",
    ):
        if type(receipt[key]) is not int or not 0 <= receipt[key] <= _MAX_ROLLOUT_CONSUMERS:
            raise ValueError("production_rollout_evidence_mismatch")
    if (
        receipt["expected_consumer_count"] < 1
        or receipt["successful_readback_count"] != receipt["expected_consumer_count"]
        or receipt["failed_readback_count"] != 0
        or receipt["unresolved_consumer_count"] != 0
        or receipt["result"] != "COMPLETE"
        or receipt["readback_evidence_sha256"] != contract._canonical_sha256(evidence)
        or receipt["phase_b_packet_sha256"] != contract._canonical_sha256(phase_b_packet)
        or receipt["phase_b_review_receipt_sha256"] != contract._canonical_sha256(phase_b_review)
    ):
        raise ValueError("production_rollout_evidence_mismatch")
    if (
        receipt["cohort_id"] != evidence["cohort_id"]
        or receipt["cohort_membership_sha256"] != evidence["cohort_membership_sha256"]
        or receipt["expected_consumer_count"] != evidence["expected_consumer_count"]
        or receipt["verifier_release_id"] != evidence["verifier_release_id"]
        or receipt["registry_sha256"] != evidence["registry_sha256"]
        or receipt["registry_sha256"] != phase_b_packet["published_registry_sha256"]
    ):
        raise ValueError("production_rollout_evidence_mismatch")
    return receipt


def _require_implementation_evidence(value: Any) -> dict[str, Any]:
    evidence = contract._require_exact_keys(
        contract._snapshot_bounded(value), _IMPLEMENTATION_EVIDENCE_KEYS,
        "implementation_evidence",
    )
    if (
        evidence["schema"] != IMPLEMENTATION_EVIDENCE_SCHEMA
        or evidence["repository_full_name"] != "bitmaster162/continuityos"
        or evidence["producer_id"] != contract.PRODUCER_ID
        or evidence["signer_release_id"] != SIGNER_RELEASE_ID
        or evidence["producer_signing_contract_file_id"] != PRODUCER_SIGNING_CONTRACT_FILE_ID
        or evidence["producer_signing_contract_revision"] != PRODUCER_SIGNING_CONTRACT_REVISION
        or evidence["ceremony_spec_file_id"] != CEREMONY_SPEC_FILE_ID
        or evidence["ceremony_spec_semantic_revision"] != CEREMONY_SPEC_SEMANTIC_REVISION
        or evidence["custody_profile"] != CUSTODY_PROFILE
        or evidence["conformance_scope"] != CONFORMANCE_SCOPE
        or evidence["test_only"] is not False
        or evidence["caller_selectable_key"] is not False
        or evidence["caller_selectable_purpose"] is not False
        or evidence["arbitrary_message_signing"] is not False
        or evidence["production_hardware_custody_path_supported"] is not True
        or evidence["conformance_result"] != "PASS"
    ):
        raise ValueError("production_implementation_evidence_mismatch")
    for key in ("reviewed_head_sha", "reviewed_tree_sha", "signer_source_blob_sha"):
        if not contract._is_git_sha(evidence[key]):
            raise ValueError("production_implementation_evidence_mismatch")
    if not contract._is_sha256(evidence["signer_source_sha256"]):
        raise ValueError("production_implementation_evidence_mismatch")
    return evidence


def _require_activation_manifest(
    value: Any,
    *,
    implementation_evidence_sha256: str,
    rollout_receipt: dict[str, Any],
    phase_b_packet: dict[str, Any],
) -> dict[str, Any]:
    manifest = contract._require_exact_keys(
        contract._snapshot_bounded(value), _ACTIVATION_KEYS, "activation_manifest"
    )
    if (
        manifest["schema"] != ACTIVATION_MANIFEST_SCHEMA
        or manifest["producer_id"] != contract.PRODUCER_ID
        or type(manifest["activation_generation"]) is not int
        or not 1 <= manifest["activation_generation"] <= contract.MAX_INTEGER_ABS
        or not contract._is_identifier(manifest["key_id"])
        or not contract._is_sha256(manifest["public_key_sha256"])
        or not contract._is_sha256(manifest["registry_sha256"])
        or not contract._is_identifier(manifest["verifier_release_id"])
        or not contract._is_identifier(manifest["rollout_cohort_id"])
        or not contract._is_sha256(manifest["rollout_membership_sha256"])
        or not contract._is_sha256(manifest["rollout_receipt_sha256"])
        or manifest["signer_release_id"] != SIGNER_RELEASE_ID
        or manifest["implementation_evidence_sha256"] != implementation_evidence_sha256
    ):
        raise ValueError("production_implementation_evidence_mismatch")
    if (
        manifest["key_id"] != phase_b_packet["key_id"]
        or manifest["public_key_sha256"] != phase_b_packet["public_key_sha256"]
        or manifest["registry_sha256"] != phase_b_packet["published_registry_sha256"]
        or manifest["verifier_release_id"] != rollout_receipt["verifier_release_id"]
        or manifest["rollout_cohort_id"] != rollout_receipt["cohort_id"]
        or manifest["rollout_membership_sha256"] != rollout_receipt["cohort_membership_sha256"]
        or manifest["rollout_receipt_sha256"] != contract._canonical_sha256(rollout_receipt)
    ):
        raise ValueError("production_rollout_evidence_mismatch")
    return manifest


def _load_runtime_signing_context() -> dict[str, Any]:
    # No activation/configuration source is selected by the R7 builder scope.
    raise ValueError("production_signer_not_activated")


def _require_runtime_context(value: Any) -> dict[str, Any]:
    # Step 9 only: snapshot the closed implementation-owned context. Activation state
    # is deliberately NOT accepted here; CURRENT_SIGNING is verified separately at
    # step 10 after every required evidence object has passed validation.
    raw = contract._require_exact_keys(value, _RUNTIME_CONTEXT_KEYS, "runtime_context")
    return {key: contract._snapshot_bounded(item) for key, item in raw.items()}


def _require_current_signing(
    context: dict[str, Any],
    *,
    phase_b_packet: dict[str, Any],
    activation_manifest: dict[str, Any],
) -> None:
    if (
        context["state"] != "CURRENT_SIGNING"
        or not contract._is_identifier(context["bound_key_id"])
        or not contract._is_sha256(context["bound_registry_sha256"])
        or context["production_facade_key_binding_present"] is not True
        or context["production_signer_key_reachable"] is not True
        or context["production_runtime_hsm_auth_path_enabled"] is not True
        or context["current_signing_key_configured"] is not True
        or context["bound_key_id"] != phase_b_packet["key_id"]
        or context["bound_key_id"] != activation_manifest["key_id"]
        or context["bound_registry_sha256"] != phase_b_packet["published_registry_sha256"]
        or context["bound_registry_sha256"] != activation_manifest["registry_sha256"]
    ):
        raise ValueError("production_signer_not_activated")


def _prevalidate_anchor_evidence(
    *,
    proof_value: Any,
    previous_value: Any,
    activation_manifest: dict[str, Any],
) -> dict[str, Any]:
    proof = _require_proof_shape(proof_value)
    if (
        proof["activation_generation"] != activation_manifest["activation_generation"]
        or proof["activation_manifest_sha256"] != contract._canonical_sha256(activation_manifest)
    ):
        raise ValueError("production_activation_anchor_mismatch")

    # Step 9 must finish every hardware-independent proof/chain check before
    # CURRENT_SIGNING is accepted at step 10. Reuse the pure proof verifier with a
    # proof-derived state so it validates commitment/genesis/parent/digest continuity
    # without pretending that any TPM read has occurred. Step 11 repeats the same
    # verifier against the actual fresh TPM readback.
    static_fresh_state = {
        "nv_public_sha256": proof["nv_public_sha256"],
        "nv_name_sha256": proof["nv_name_sha256"],
        "observed_nv_extend_digest": proof["observed_nv_extend_digest"],
    }
    _verify_activation_anchor_proof(
        proof=proof,
        activation_manifest=activation_manifest,
        previous_proof_or_genesis_evidence=previous_value,
        fresh_nv_state=static_fresh_state,
    )
    return proof


class ProductionAcceptanceOriginSigner:
    """Only externally invokable production Acceptance Origin R1 facade."""

    __slots__ = ()

    def produce(self, *, sign_request: Any) -> dict[str, Any]:
        # Steps 1-4: bounded request snapshot and exact closed input.
        request = contract._require_sign_request(sign_request)
        transport_receipt = contract._snapshot_bounded(request["transport_receipt"])
        contract._prevalidate_transport_bounds(transport_receipt)

        # Steps 5-8: materialize exactly once, snapshot exactly once, validate that
        # same snapshot without reconstructing it, then hash the exact returned object.
        materialized = acceptance_builder.accept_cross_ai_ruap_transport_receipt(
            transport_receipt
        )
        acceptance = contract._snapshot_bounded(materialized)
        origin_verifier._require_safe_acceptance(acceptance)
        acceptance_sha256 = contract._canonical_sha256(acceptance)

        # Step 9: load/snapshot and validate all exact public evidence first.
        context = _require_runtime_context(_load_runtime_signing_context())
        phase_b_packet = _require_phase_b_packet(context["phase_b_packet"])
        phase_b_review = _require_phase_b_review(
            context["phase_b_review_receipt"], phase_b_packet=phase_b_packet
        )
        rollout_evidence = _require_rollout_evidence(context["rollout_evidence"])
        rollout_receipt = _require_rollout_receipt(
            context["rollout_receipt"],
            evidence=rollout_evidence,
            phase_b_packet=phase_b_packet,
            phase_b_review=phase_b_review,
        )
        implementation_evidence = _require_implementation_evidence(
            context["implementation_evidence"]
        )
        implementation_evidence_sha256 = contract._canonical_sha256(
            implementation_evidence
        )
        if (
            phase_b_packet["signer_implementation_evidence_sha256"]
            != implementation_evidence_sha256
        ):
            raise ValueError("production_implementation_evidence_mismatch")
        activation_manifest = _require_activation_manifest(
            context["activation_manifest"],
            implementation_evidence_sha256=implementation_evidence_sha256,
            rollout_receipt=rollout_receipt,
            phase_b_packet=phase_b_packet,
        )
        anchor_proof = _prevalidate_anchor_evidence(
            proof_value=context["activation_anchor_proof"],
            previous_value=context["previous_anchor_proof_or_genesis_evidence"],
            activation_manifest=activation_manifest,
        )

        # Step 10: only after step-9 evidence passes, accept CURRENT_SIGNING/binding.
        _require_current_signing(
            context,
            phase_b_packet=phase_b_packet,
            activation_manifest=activation_manifest,
        )

        # Step 11: fresh TPM read and exact anti-rollback verification.
        tpm_adapter = _build_tpm2_nv_anchor_adapter()
        fresh_nv_state = tpm_adapter._read_current_nv_extend_state()
        _verify_activation_anchor_proof(
            proof=anchor_proof,
            activation_manifest=activation_manifest,
            previous_proof_or_genesis_evidence=(
                context["previous_anchor_proof_or_genesis_evidence"]
            ),
            fresh_nv_state=fresh_nv_state,
        )

        # Steps 12-13: bound HSM public-key read and coherence checks.
        hsm_adapter = _build_yubihsm2_ed25519_adapter()
        public_key = hsm_adapter._read_bound_public_key()
        public_key_sha256 = hashlib.sha256(public_key).hexdigest()
        key_id = contract._derive_key_id(public_key)
        registry, keys = contract._require_registry(phase_b_packet["candidate_registry"])
        matches = [
            item for item in keys
            if item["producer_id"] == contract.PRODUCER_ID
            and item["key_id"] == key_id
            and item["state"] == "ACTIVE"
        ]
        if (
            len(matches) != 1
            or key_id != context["bound_key_id"]
            or key_id != activation_manifest["key_id"]
            or public_key_sha256 != activation_manifest["public_key_sha256"]
            or public_key_sha256 != phase_b_packet["public_key_sha256"]
            or contract._canonical_sha256(registry) != context["bound_registry_sha256"]
        ):
            raise ValueError("production_registry_coherence_mismatch")

        # Steps 14-16: exact frozen message; adapter enforces one validated session
        # from step 12 and exactly one sign attempt at step 15.
        message = contract._signature_message(
            key_id=key_id, acceptance_sha256=acceptance_sha256
        )
        signature = hsm_adapter._sign_bound_acceptance_message(message)
        if type(signature) is not bytes or len(signature) != 64:
            raise ValueError("production_hsm_signature_invalid")

        # Step 17: local verification against the exact step-12 public key.
        origin_verifier._verify_ed25519(
            public_key=public_key, signature=signature, message=message
        )

        # Steps 18-19: exact atomic success bundle; exceptions expose no partial success.
        signature_envelope = {
            "schema": contract.SIGNATURE_SCHEMA,
            "purpose": contract.PURPOSE,
            "producer_id": contract.PRODUCER_ID,
            "key_id": key_id,
            "algorithm": contract.ALGORITHM,
            "acceptance_sha256": acceptance_sha256,
            "signature_b64u": base64.urlsafe_b64encode(signature)
            .rstrip(b"=")
            .decode("ascii"),
        }
        return {
            "schema": contract.PRODUCER_RESPONSE_SCHEMA,
            "acceptance": acceptance,
            "signature_envelope": signature_envelope,
        }
