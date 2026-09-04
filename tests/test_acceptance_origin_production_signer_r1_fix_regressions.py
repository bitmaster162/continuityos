from __future__ import annotations

import copy
import hashlib

import pytest

import continuityos.cross_ai_ruap_acceptance_origin_production_signer as production
import continuityos.cross_ai_ruap_acceptance_origin_signing_contract as contract
import continuityos.cross_ai_ruap_receipt_acceptance_origin_verifier as verifier


@pytest.mark.parametrize("field,value", [
    ("acceptance", {}),
    ("acceptance_sha256", "0" * 64),
    ("raw_bytes", "caller"),
    ("digest", "0" * 64),
    ("key_id", "caller-key"),
    ("purpose", contract.PURPOSE),
    ("algorithm", contract.ALGORITHM),
    ("domain", "caller-domain"),
    ("registry", {}),
    ("backend", "caller-backend"),
    ("device_locator", "caller-device"),
    ("custody_mode", "caller-mode"),
])
def test_full_caller_selector_surface_is_closed(field, value) -> None:
    request = {
        "schema": contract.SIGN_REQUEST_SCHEMA,
        "transport_receipt": {},
        field: value,
    }
    with pytest.raises(ValueError, match="sign_request_unknown_key"):
        contract._require_sign_request(request)


def test_exact_acceptance_snapshot_is_validated_without_second_reconstruction(monkeypatch) -> None:
    materialized = {"materialized": True}
    accepted_snapshot = {"accepted_snapshot": True}
    counts = {"materialized_snapshot": 0, "validator": 0}

    monkeypatch.setattr(
        contract,
        "_require_sign_request",
        lambda _: {"schema": contract.SIGN_REQUEST_SCHEMA, "transport_receipt": {}},
    )
    original_snapshot = contract._snapshot_bounded

    def snapshot(value, *args, **kwargs):
        if value is materialized:
            counts["materialized_snapshot"] += 1
            return accepted_snapshot
        return original_snapshot(value, *args, **kwargs)

    monkeypatch.setattr(contract, "_snapshot_bounded", snapshot)
    monkeypatch.setattr(contract, "_prevalidate_transport_bounds", lambda _: None)
    monkeypatch.setattr(
        production.acceptance_builder,
        "accept_cross_ai_ruap_transport_receipt",
        lambda _: materialized,
    )

    def validate_same(value):
        counts["validator"] += 1
        assert value is accepted_snapshot
        return value

    monkeypatch.setattr(verifier, "_require_safe_acceptance", validate_same)
    monkeypatch.setattr(
        production,
        "_load_runtime_signing_context",
        lambda: (_ for _ in ()).throw(ValueError("production_signer_not_activated")),
    )
    with pytest.raises(ValueError, match="production_signer_not_activated"):
        production.ProductionAcceptanceOriginSigner().produce(sign_request={})
    assert counts == {"materialized_snapshot": 1, "validator": 1}


def test_step9_evidence_validation_precedes_step10_current_signing(monkeypatch) -> None:
    order: list[str] = []
    monkeypatch.setattr(
        contract,
        "_require_sign_request",
        lambda _: {"schema": contract.SIGN_REQUEST_SCHEMA, "transport_receipt": {}},
    )
    monkeypatch.setattr(contract, "_snapshot_bounded", lambda value, *a, **k: copy.deepcopy(value))
    monkeypatch.setattr(contract, "_prevalidate_transport_bounds", lambda _: None)
    monkeypatch.setattr(
        production.acceptance_builder,
        "accept_cross_ai_ruap_transport_receipt",
        lambda _: {"safe": True},
    )
    monkeypatch.setattr(verifier, "_require_safe_acceptance", lambda value: value)
    monkeypatch.setattr(contract, "_canonical_sha256", lambda _: "a" * 64)

    context = {
        "state": "CURRENT_SIGNING",
        "bound_key_id": "key",
        "bound_registry_sha256": "b" * 64,
        "production_facade_key_binding_present": True,
        "production_signer_key_reachable": True,
        "production_runtime_hsm_auth_path_enabled": True,
        "current_signing_key_configured": True,
        "phase_b_packet": {}, "phase_b_review_receipt": {},
        "rollout_evidence": {}, "rollout_receipt": {},
        "implementation_evidence": {}, "activation_manifest": {},
        "activation_anchor_proof": {},
        "previous_anchor_proof_or_genesis_evidence": {},
    }
    monkeypatch.setattr(production, "_load_runtime_signing_context", lambda: context)
    monkeypatch.setattr(production, "_require_runtime_context", lambda value: value)

    packet = {
        "key_id": "key", "published_registry_sha256": "b" * 64,
        "signer_implementation_evidence_sha256": "a" * 64,
    }
    manifest = {"key_id": "key", "registry_sha256": "b" * 64}

    def mark(name, result):
        def inner(*args, **kwargs):
            order.append(name)
            return result
        return inner

    monkeypatch.setattr(production, "_require_phase_b_packet", mark("phase_b", packet))
    monkeypatch.setattr(production, "_require_phase_b_review", mark("review", {}))
    monkeypatch.setattr(production, "_require_rollout_evidence", mark("rollout_evidence", {}))
    monkeypatch.setattr(production, "_require_rollout_receipt", mark("rollout_receipt", {}))
    monkeypatch.setattr(production, "_require_implementation_evidence", mark("implementation", {}))
    monkeypatch.setattr(production, "_require_activation_manifest", mark("activation", manifest))
    monkeypatch.setattr(production, "_prevalidate_anchor_evidence", mark("anchor_shape", {}))

    def current(*args, **kwargs):
        order.append("current_signing")
        raise ValueError("stop-after-step10")

    monkeypatch.setattr(production, "_require_current_signing", current)
    with pytest.raises(ValueError, match="stop-after-step10"):
        production.ProductionAcceptanceOriginSigner().produce(sign_request={})
    assert order == [
        "phase_b", "review", "rollout_evidence", "rollout_receipt",
        "implementation", "activation", "anchor_shape", "current_signing",
    ]


@pytest.mark.parametrize("enabled_flag", [
    "production_facade_key_binding_present",
    "production_signer_key_reachable",
    "production_runtime_hsm_auth_path_enabled",
    "current_signing_key_configured",
])
def test_provisioned_disabled_never_accepts_any_access_path_flag(enabled_flag) -> None:
    context = {
        "state": "PROVISIONED_DISABLED",
        "bound_key_id": "ed25519-sha256:" + "1" * 64,
        "bound_registry_sha256": "2" * 64,
        "production_facade_key_binding_present": False,
        "production_signer_key_reachable": False,
        "production_runtime_hsm_auth_path_enabled": False,
        "current_signing_key_configured": False,
    }
    context[enabled_flag] = True
    packet = {
        "key_id": context["bound_key_id"],
        "published_registry_sha256": context["bound_registry_sha256"],
    }
    manifest = {
        "key_id": context["bound_key_id"],
        "registry_sha256": context["bound_registry_sha256"],
    }
    with pytest.raises(ValueError, match="production_signer_not_activated"):
        production._require_current_signing(
            context, phase_b_packet=packet, activation_manifest=manifest
        )


def test_bad_local_signature_verification_emits_no_success(monkeypatch) -> None:
    public_key = bytes(range(32))
    key_id = contract._derive_key_id(public_key)
    registry_sha = "b" * 64
    packet = {
        "key_id": key_id,
        "public_key_sha256": hashlib.sha256(public_key).hexdigest(),
        "published_registry_sha256": registry_sha,
        "candidate_registry": {},
        "signer_implementation_evidence_sha256": registry_sha,
    }
    manifest = {
        "key_id": key_id,
        "public_key_sha256": packet["public_key_sha256"],
        "registry_sha256": registry_sha,
    }
    context = {
        "bound_key_id": key_id,
        "bound_registry_sha256": registry_sha,
        "phase_b_packet": {}, "phase_b_review_receipt": {},
        "rollout_evidence": {}, "rollout_receipt": {},
        "implementation_evidence": {}, "activation_manifest": {},
        "activation_anchor_proof": {},
        "previous_anchor_proof_or_genesis_evidence": {},
    }
    monkeypatch.setattr(contract, "_require_sign_request", lambda _: {"transport_receipt": {}})
    monkeypatch.setattr(contract, "_snapshot_bounded", lambda value, *a, **k: copy.deepcopy(value))
    monkeypatch.setattr(contract, "_prevalidate_transport_bounds", lambda _: None)
    monkeypatch.setattr(production.acceptance_builder, "accept_cross_ai_ruap_transport_receipt", lambda _: {"safe": True})
    monkeypatch.setattr(verifier, "_require_safe_acceptance", lambda value: value)
    monkeypatch.setattr(production, "_load_runtime_signing_context", lambda: context)
    monkeypatch.setattr(production, "_require_runtime_context", lambda value: value)
    monkeypatch.setattr(production, "_require_phase_b_packet", lambda _: packet)
    monkeypatch.setattr(production, "_require_phase_b_review", lambda *a, **k: {})
    monkeypatch.setattr(production, "_require_rollout_evidence", lambda _: {})
    monkeypatch.setattr(production, "_require_rollout_receipt", lambda *a, **k: {})
    monkeypatch.setattr(production, "_require_implementation_evidence", lambda _: {})
    monkeypatch.setattr(production, "_require_activation_manifest", lambda *a, **k: manifest)
    monkeypatch.setattr(production, "_prevalidate_anchor_evidence", lambda *a, **k: {})
    monkeypatch.setattr(production, "_require_current_signing", lambda *a, **k: None)

    class Tpm:
        def _read_current_nv_extend_state(self):
            return {"nv_public_sha256": "1" * 64, "nv_name_sha256": "2" * 64, "observed_nv_extend_digest": "3" * 64}

    class Hsm:
        sign_calls = 0
        def _read_bound_public_key(self):
            return public_key
        def _sign_bound_acceptance_message(self, message):
            self.sign_calls += 1
            return b"s" * 64

    hsm = Hsm()
    monkeypatch.setattr(production, "_build_tpm2_nv_anchor_adapter", lambda: Tpm())
    monkeypatch.setattr(production, "_verify_activation_anchor_proof", lambda *a, **k: {})
    monkeypatch.setattr(production, "_build_yubihsm2_ed25519_adapter", lambda: hsm)
    monkeypatch.setattr(contract, "_require_registry", lambda _: ({}, [{"producer_id": contract.PRODUCER_ID, "key_id": key_id, "state": "ACTIVE"}]))
    real_canonical = contract._canonical_sha256
    monkeypatch.setattr(
        contract,
        "_canonical_sha256",
        lambda value: registry_sha if value == {} else real_canonical(value),
    )
    monkeypatch.setattr(
        verifier,
        "_verify_ed25519",
        lambda **kwargs: (_ for _ in ()).throw(ValueError("ed25519_signature_invalid")),
    )
    with pytest.raises(ValueError, match="ed25519_signature_invalid"):
        production.ProductionAcceptanceOriginSigner().produce(sign_request={})
    assert hsm.sign_calls == 1


def valid_review(packet: dict) -> dict:
    return {
        "schema": production.PHASE_B_REVIEW_SCHEMA,
        "phase_b_packet_sha256": contract._canonical_sha256(packet),
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


@pytest.mark.parametrize("mutation", [
    ("phase_b_packet_sha256", "0" * 64),
    ("phase_a_packet_sha256", "0" * 64),
    ("published_registry_sha256", "0" * 64),
    ("contract_complete_confirmed", False),
    ("lineage_confirmed", False),
    ("cross_object_coherence_confirmed", False),
    ("rollout_authorized", False),
    ("review_result", "FAIL"),
])
def test_phase_b_review_mutation_matrix_fails_closed(mutation) -> None:
    packet = {
        "phase_a_packet_sha256": "1" * 64,
        "pin_update_merge_commit_sha": "2" * 40,
        "phase_b_observed_master_sha": "2" * 40,
        "published_registry_sha256": "3" * 64,
    }
    receipt = valid_review(packet)
    receipt[mutation[0]] = mutation[1]
    with pytest.raises(ValueError, match="production_phase_b_review_receipt_invalid"):
        production._require_phase_b_review(receipt, phase_b_packet=packet)


def valid_rollout_values():
    evidence = {
        "schema": production.ROLLOUT_EVIDENCE_SCHEMA,
        "cohort_id": "cohort-r1",
        "cohort_membership_sha256": "1" * 64,
        "expected_consumer_count": 1,
        "verifier_release_id": "verifier-r1",
        "registry_sha256": "2" * 64,
        "readbacks": [],
    }
    evidence["readbacks"] = [{
        "consumer_id": "consumer-a",
        "verifier_release_id": "verifier-r1",
        "registry_sha256": "2" * 64,
        "ok": True,
    }]
    evidence["cohort_membership_sha256"] = production._cohort_membership_sha256(
        cohort_id="cohort-r1", consumer_ids=["consumer-a"]
    )
    packet = {"published_registry_sha256": "2" * 64}
    review = {"review": True}
    receipt = {
        "schema": production.ROLLOUT_RECEIPT_SCHEMA,
        "cohort_id": evidence["cohort_id"],
        "cohort_membership_sha256": evidence["cohort_membership_sha256"],
        "expected_consumer_count": 1,
        "verifier_release_id": "verifier-r1",
        "registry_sha256": "2" * 64,
        "successful_readback_count": 1,
        "failed_readback_count": 0,
        "unresolved_consumer_count": 0,
        "readback_evidence_sha256": contract._canonical_sha256(evidence),
        "result": "COMPLETE",
        "phase_b_packet_sha256": contract._canonical_sha256(packet),
        "phase_b_review_receipt_sha256": contract._canonical_sha256(review),
    }
    return evidence, packet, review, receipt


@pytest.mark.parametrize("field,value", [
    ("successful_readback_count", 0),
    ("failed_readback_count", 1),
    ("unresolved_consumer_count", 1),
    ("readback_evidence_sha256", "0" * 64),
    ("phase_b_packet_sha256", "0" * 64),
    ("phase_b_review_receipt_sha256", "0" * 64),
    ("registry_sha256", "0" * 64),
    ("result", "INCOMPLETE"),
])
def test_rollout_receipt_mutation_matrix_fails_closed(field, value) -> None:
    evidence, packet, review, receipt = valid_rollout_values()
    receipt[field] = value
    with pytest.raises(ValueError, match="production_rollout_evidence_mismatch"):
        production._require_rollout_receipt(
            receipt,
            evidence=evidence,
            phase_b_packet=packet,
            phase_b_review=review,
        )
