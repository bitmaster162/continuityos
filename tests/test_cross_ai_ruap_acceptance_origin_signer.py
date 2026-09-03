from __future__ import annotations

import ast
import base64
import copy
import hashlib
import inspect
import json

import pytest

import continuityos.cross_ai_ruap_acceptance_origin_signer as signer
import continuityos.cross_ai_ruap_receipt_acceptance as acceptance
import continuityos.cross_ai_ruap_receipt_acceptance_origin_verifier as verifier
import continuityos.cross_ai_ruap_transport as transport

FAKE_PUBLIC_KEY = bytes(range(32))
FAKE_SIGNATURE = bytes([0xA5]) * 64
CONSUMERS = ["consumer-a", "consumer-b"]
REVIEWED_HEAD_SHA = "1" * 40
REVIEWED_TREE_SHA = "2" * 40
SOURCE_BLOB_SHA = "3" * 40
SOURCE_SHA256 = "4" * 64


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def key_id(public_key: bytes) -> str:
    return "ed25519-sha256:" + hashlib.sha256(public_key).hexdigest()


def canonical_sha256(value) -> str:
    return hashlib.sha256(json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    ).encode("ascii")).hexdigest()


def membership_sha256(cohort_id: str, consumers: list[str]) -> str:
    return canonical_sha256({
        "schema": signer.COHORT_MEMBERSHIP_SCHEMA,
        "cohort_id": cohort_id,
        "consumer_ids": sorted(consumers),
    })


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
            "id": "s1",
            "provider": "github",
            "locator": "PRIVATE_LOCATOR",
            "observed_at": "PRIVATE_OBSERVED_AT",
        }],
        "observations": [{
            "subject": "PRIVATE_SUBJECT",
            "claim": "PRIVATE_CLAIM",
            "class": "PROVIDER_READBACK",
            "source_id": "s1",
            "freshness_required_before_effect": True,
        }],
    }


def receipt() -> dict:
    return transport.build_cross_ai_ruap_transport_receipt(
        source_client="claude",
        target_client="cursor",
        ruap_snapshot=json.dumps(ruap_snapshot()),
    )


def registry(public_key: bytes = FAKE_PUBLIC_KEY) -> dict:
    return {
        "schema": verifier.REGISTRY_SCHEMA,
        "registry_id": verifier.REGISTRY_ID,
        "keys": [{
            "producer_id": signer.PRODUCER_ID,
            "key_id": key_id(public_key),
            "algorithm": verifier.ALGORITHM,
            "public_key_b64u": b64u(public_key),
            "usage": verifier.PURPOSE,
            "state": "ACTIVE",
        }],
    }


def rollout_evidence(registry_value: dict) -> dict:
    cohort_id = "cohort-fixture-r1"
    registry_sha256 = canonical_sha256(registry_value)
    return {
        "schema": signer.ROLLOUT_EVIDENCE_SCHEMA,
        "cohort_id": cohort_id,
        "cohort_membership_sha256": membership_sha256(cohort_id, CONSUMERS),
        "expected_consumer_count": len(CONSUMERS),
        "verifier_release_id": "verifier-fixture-r1",
        "registry_sha256": registry_sha256,
        "readbacks": [{
            "consumer_id": consumer_id,
            "verifier_release_id": "verifier-fixture-r1",
            "registry_sha256": registry_sha256,
            "ok": True,
        } for consumer_id in CONSUMERS],
    }


def rollout(evidence: dict) -> dict:
    return {
        "schema": signer.ROLLOUT_RECEIPT_SCHEMA,
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
    }


def implementation_evidence() -> dict:
    return {
        "schema": signer.IMPLEMENTATION_EVIDENCE_SCHEMA,
        "reviewed_head_sha": REVIEWED_HEAD_SHA,
        "reviewed_tree_sha": REVIEWED_TREE_SHA,
        "signer_source_blob_sha": SOURCE_BLOB_SHA,
        "signer_source_sha256": SOURCE_SHA256,
        "signer_release_id": signer.SIGNER_RELEASE_ID,
    }


def manifest(
    public_key: bytes,
    registry_value: dict,
    rollout_value: dict,
    implementation_value: dict,
    *,
    generation: int = 1,
) -> dict:
    return {
        "schema": signer.ACTIVATION_MANIFEST_SCHEMA,
        "producer_id": signer.PRODUCER_ID,
        "activation_generation": generation,
        "key_id": key_id(public_key),
        "public_key_sha256": hashlib.sha256(public_key).hexdigest(),
        "registry_sha256": canonical_sha256(registry_value),
        "verifier_release_id": rollout_value["verifier_release_id"],
        "rollout_cohort_id": rollout_value["cohort_id"],
        "rollout_membership_sha256": rollout_value["cohort_membership_sha256"],
        "rollout_receipt_sha256": canonical_sha256(rollout_value),
        "signer_release_id": signer.SIGNER_RELEASE_ID,
        "implementation_evidence_sha256": canonical_sha256(implementation_value),
    }


def monotonic_anchor(
    manifest_value: dict,
    implementation_value: dict,
    *,
    last_committed_generation: int | None = None,
) -> dict:
    return {
        "schema": signer.TEST_ANCHOR_SCHEMA,
        "last_committed_generation": (
            manifest_value["activation_generation"]
            if last_committed_generation is None
            else last_committed_generation
        ),
        "committed_activation_manifest_sha256": canonical_sha256(manifest_value),
        "trusted_implementation_evidence_sha256": canonical_sha256(
            implementation_value
        ),
    }


def build_signer(
    *,
    public_key: bytes = FAKE_PUBLIC_KEY,
    fixed_signature: bytes | None = FAKE_SIGNATURE,
    private_seed: bytes | None = None,
    registry_value: dict | None = None,
    evidence_value: dict | None = None,
    rollout_value: dict | None = None,
    implementation_value: dict | None = None,
    manifest_value: dict | None = None,
    anchor_value: dict | None = None,
):
    registry_value = registry_value or registry(public_key)
    evidence_value = evidence_value or rollout_evidence(registry_value)
    rollout_value = rollout_value or rollout(evidence_value)
    implementation_value = implementation_value or implementation_evidence()
    manifest_value = manifest_value or manifest(
        public_key,
        registry_value,
        rollout_value,
        implementation_value,
    )
    anchor_value = anchor_value or monotonic_anchor(
        manifest_value,
        implementation_value,
    )
    instance = signer.TestOnlyAcceptanceOriginSigner(
        test_public_key_b64u=b64u(public_key),
        test_fixed_signature=fixed_signature,
        test_private_key_seed=private_seed,
        key_registry=registry_value,
        rollout_receipt=rollout_value,
        rollout_evidence=evidence_value,
        implementation_evidence=implementation_value,
        activation_manifest=manifest_value,
        test_monotonic_anchor=anchor_value,
    )
    return (
        instance,
        registry_value,
        evidence_value,
        rollout_value,
        implementation_value,
        manifest_value,
        anchor_value,
    )


def sign_request(receipt_value: dict | None = None) -> dict:
    return {
        "schema": signer.SIGN_REQUEST_SCHEMA,
        "transport_receipt": (
            receipt_value if receipt_value is not None else receipt()
        ),
    }


def test_registry_list_snapshot_and_fixed_probe_is_dry_run_only() -> None:
    instance, *_ = build_signer()
    request = sign_request()
    before = copy.deepcopy(request)
    response = instance.produce(sign_request=request)
    expected = acceptance.accept_cross_ai_ruap_transport_receipt(
        before["transport_receipt"]
    )
    assert request == before
    assert response["schema"] == signer.DRY_RUN_RESPONSE_SCHEMA
    assert response["production_response_emitted"] is False
    assert "signature_envelope" not in response
    assert response["acceptance"] == expected
    assert response["signature_probe_b64u"] == b64u(FAKE_SIGNATURE)


@pytest.mark.parametrize("field,value", [
    ("key_id", "caller-key"),
    ("algorithm", "Ed25519"),
    ("acceptance_sha256", "0" * 64),
    ("acceptance", {}),
])
def test_request_rejects_caller_selected_signing_material(field, value) -> None:
    instance, *_ = build_signer()
    request = sign_request()
    request[field] = value
    with pytest.raises(ValueError, match="sign_request_unknown_key"):
        instance.produce(sign_request=request)


def test_oversized_transport_input_is_rejected_before_builder(monkeypatch) -> None:
    instance, *_ = build_signer()
    supplied = receipt()
    supplied["source_client"] = "x" * (signer.MAX_STRING_LEN + 1)
    calls = []

    def forbidden_builder(value):
        calls.append(value)
        raise AssertionError("builder must not run")

    monkeypatch.setattr(
        signer.acceptance_builder,
        "accept_cross_ai_ruap_transport_receipt",
        forbidden_builder,
    )
    with pytest.raises(ValueError, match="snapshot_string_too_long"):
        instance.produce(sign_request=sign_request(supplied))
    assert calls == []


def test_evidence_counts_are_bounded_before_builder(monkeypatch) -> None:
    instance, *_ = build_signer()
    supplied = receipt()
    supplied["ruap_evidence"]["source_count"] = signer.MAX_EVIDENCE_COUNT + 1
    calls = []

    def forbidden_builder(value):
        calls.append(value)
        raise AssertionError("builder must not run")

    monkeypatch.setattr(
        signer.acceptance_builder,
        "accept_cross_ai_ruap_transport_receipt",
        forbidden_builder,
    )
    with pytest.raises(ValueError, match="transport_source_count_out_of_bounds"):
        instance.produce(sign_request=sign_request(supplied))
    assert calls == []


def test_no_effectful_adapter_or_self_hash_surface_exists() -> None:
    signature = inspect.signature(signer.TestOnlyAcceptanceOriginSigner)
    assert "signing_custody" not in signature.parameters
    assert "activation_anchor" not in signature.parameters
    source = inspect.getsource(signer)
    assert "Protocol" not in source
    assert "marshal" not in source
    assert "implementation_sha256" not in source


def test_rollout_receipt_requires_exact_readback_evidence_digest() -> None:
    registry_value = registry()
    evidence_value = rollout_evidence(registry_value)
    rollout_value = rollout(evidence_value)
    rollout_value["readback_evidence_sha256"] = "0" * 64
    implementation_value = implementation_evidence()
    manifest_value = manifest(
        FAKE_PUBLIC_KEY,
        registry_value,
        rollout_value,
        implementation_value,
    )
    with pytest.raises(ValueError, match="rollout_readback_evidence_digest_mismatch"):
        build_signer(
            registry_value=registry_value,
            evidence_value=evidence_value,
            rollout_value=rollout_value,
            implementation_value=implementation_value,
            manifest_value=manifest_value,
            anchor_value=monotonic_anchor(manifest_value, implementation_value),
        )


def test_every_rollout_readback_must_prove_exact_release_and_pin() -> None:
    registry_value = registry()
    evidence_value = rollout_evidence(registry_value)
    evidence_value["readbacks"][1]["registry_sha256"] = "0" * 64
    rollout_value = rollout(evidence_value)
    implementation_value = implementation_evidence()
    manifest_value = manifest(
        FAKE_PUBLIC_KEY,
        registry_value,
        rollout_value,
        implementation_value,
    )
    with pytest.raises(ValueError, match="rollout_readback_not_exact_success"):
        build_signer(
            registry_value=registry_value,
            evidence_value=evidence_value,
            rollout_value=rollout_value,
            implementation_value=implementation_value,
            manifest_value=manifest_value,
            anchor_value=monotonic_anchor(manifest_value, implementation_value),
        )


def test_external_implementation_evidence_is_anchor_pinned() -> None:
    implementation_value = implementation_evidence()
    instance, *rest = build_signer(implementation_value=implementation_value)
    assert instance is not None
    anchor_value = rest[-1]
    assert anchor_value["trusted_implementation_evidence_sha256"] == canonical_sha256(
        implementation_value
    )
    assert implementation_value["reviewed_head_sha"] == REVIEWED_HEAD_SHA
    assert implementation_value["reviewed_tree_sha"] == REVIEWED_TREE_SHA
    assert implementation_value["signer_source_blob_sha"] == SOURCE_BLOB_SHA


def test_activation_manifest_rejects_wrong_implementation_evidence_digest() -> None:
    registry_value = registry()
    evidence_value = rollout_evidence(registry_value)
    rollout_value = rollout(evidence_value)
    implementation_value = implementation_evidence()
    manifest_value = manifest(
        FAKE_PUBLIC_KEY,
        registry_value,
        rollout_value,
        implementation_value,
    )
    manifest_value["implementation_evidence_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="activation_implementation_evidence_mismatch"):
        build_signer(
            registry_value=registry_value,
            evidence_value=evidence_value,
            rollout_value=rollout_value,
            implementation_value=implementation_value,
            manifest_value=manifest_value,
            anchor_value=monotonic_anchor(manifest_value, implementation_value),
        )


def test_monotonic_anchor_rejects_coordinated_manifest_rollback() -> None:
    registry_value = registry()
    evidence_value = rollout_evidence(registry_value)
    rollout_value = rollout(evidence_value)
    implementation_value = implementation_evidence()
    manifest_n = manifest(
        FAKE_PUBLIC_KEY,
        registry_value,
        rollout_value,
        implementation_value,
        generation=1,
    )
    manifest_n1 = manifest(
        FAKE_PUBLIC_KEY,
        registry_value,
        rollout_value,
        implementation_value,
        generation=2,
    )
    anchor_n1 = monotonic_anchor(manifest_n1, implementation_value)

    build_signer(
        registry_value=registry_value,
        evidence_value=evidence_value,
        rollout_value=rollout_value,
        implementation_value=implementation_value,
        manifest_value=manifest_n1,
        anchor_value=anchor_n1,
    )

    with pytest.raises(ValueError, match="activation_generation_rollback_or_mismatch"):
        build_signer(
            registry_value=registry_value,
            evidence_value=evidence_value,
            rollout_value=rollout_value,
            implementation_value=implementation_value,
            manifest_value=manifest_n,
            anchor_value=anchor_n1,
        )


def test_fixed_probe_can_never_emit_production_response() -> None:
    instance, *_ = build_signer(fixed_signature=FAKE_SIGNATURE, private_seed=None)
    response = instance.produce(sign_request=sign_request())
    assert response["schema"] == signer.DRY_RUN_RESPONSE_SCHEMA
    assert response["production_response_emitted"] is False
    assert "signature_envelope" not in response


def test_candidate_has_no_hardware_provider_network_or_subprocess_imports() -> None:
    tree = ast.parse(inspect.getsource(signer))
    roots = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            roots.add(node.module.split(".")[0])
    assert roots.isdisjoint({
        "os", "subprocess", "socket", "requests", "urllib", "http",
        "yubihsm", "tpm2_pytss",
    })
    source = inspect.getsource(signer)
    assert "open(" not in source
    assert "CURRENT_SIGNING =" not in source


def test_only_public_facade_method_accepts_transport_sign_request() -> None:
    public_functions = [
        name for name, value in inspect.getmembers(signer, inspect.isfunction)
        if not name.startswith("_")
    ]
    assert public_functions == []
    signature = inspect.signature(signer.TestOnlyAcceptanceOriginSigner.produce)
    assert tuple(signature.parameters) == ("self", "sign_request")
    assert signature.parameters["sign_request"].kind is inspect.Parameter.KEYWORD_ONLY


def test_real_test_key_round_trip_through_existing_verifier(monkeypatch) -> None:
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    seed = bytes(range(32))
    private_key = Ed25519PrivateKey.from_private_bytes(seed)
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    instance, registry_value, *_ = build_signer(
        public_key=public_key,
        fixed_signature=None,
        private_seed=seed,
    )
    response = instance.produce(sign_request=sign_request())
    assert response["schema"] == signer.PRODUCER_RESPONSE_SCHEMA
    assert "signature_envelope" in response

    monkeypatch.setattr(
        verifier,
        "PINNED_REGISTRY_SHA256",
        canonical_sha256(registry_value),
    )
    result = verifier.verify_cross_ai_ruap_receipt_acceptance_origin(
        accepted_receipt=response["acceptance"],
        key_registry=registry_value,
        signature_envelope=response["signature_envelope"],
    )
    assert result.ok is True
    assert result.acceptance_origin_verified is True
    assert result.producer_id == signer.PRODUCER_ID
    assert result.key_id == key_id(public_key)
