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
OTHER_PUBLIC_KEY = bytes(range(1, 33))
FAKE_SIGNATURE = bytes([0xA5]) * 64


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def key_id(raw_public_key: bytes) -> str:
    return "ed25519-sha256:" + hashlib.sha256(raw_public_key).hexdigest()


def canonical_sha256(value) -> str:
    payload = json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    ).encode("ascii")
    return hashlib.sha256(payload).hexdigest()


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
        "sources": [
            {
                "id": "s1",
                "provider": "github",
                "locator": "PRIVATE_LOCATOR",
                "observed_at": "PRIVATE_OBSERVED_AT",
            }
        ],
        "observations": [
            {
                "subject": "PRIVATE_SUBJECT",
                "claim": "PRIVATE_CLAIM",
                "class": "PROVIDER_READBACK",
                "source_id": "s1",
                "freshness_required_before_effect": True,
            }
        ],
    }


def receipt() -> dict:
    return transport.build_cross_ai_ruap_transport_receipt(
        source_client="claude",
        target_client="cursor",
        ruap_snapshot=json.dumps(ruap_snapshot()),
    )


class FakeCustody:
    is_test_only = True
    producer_id = signer.PRODUCER_ID

    def __init__(self, public_key: bytes = FAKE_PUBLIC_KEY) -> None:
        self._public_key = public_key
        self.public_key_b64u = b64u(public_key)
        self.key_id = key_id(public_key)
        self.messages: list[bytes] = []
        self.drift_after_sign = False

    def sign_acceptance_origin_r1(self, message: bytes) -> bytes:
        self.messages.append(message)
        if self.drift_after_sign:
            self._public_key = OTHER_PUBLIC_KEY
            self.public_key_b64u = b64u(OTHER_PUBLIC_KEY)
            self.key_id = key_id(OTHER_PUBLIC_KEY)
        return FAKE_SIGNATURE


class FakeAnchor:
    is_test_only = True

    def __init__(self, generation: int, manifest_sha256: str) -> None:
        self.generation = generation
        self.manifest_sha256 = manifest_sha256
        self.calls: list[tuple[int, str]] = []

    def assert_current_activation(
        self,
        *,
        activation_generation: int,
        activation_manifest_sha256: str,
    ) -> None:
        self.calls.append((activation_generation, activation_manifest_sha256))
        if (
            activation_generation != self.generation
            or activation_manifest_sha256 != self.manifest_sha256
        ):
            raise ValueError("activation_anchor_mismatch")


def registry(custody: FakeCustody) -> dict:
    return {
        "schema": verifier.REGISTRY_SCHEMA,
        "registry_id": verifier.REGISTRY_ID,
        "keys": [
            {
                "producer_id": signer.PRODUCER_ID,
                "key_id": custody.key_id,
                "algorithm": verifier.ALGORITHM,
                "public_key_b64u": custody.public_key_b64u,
                "usage": verifier.PURPOSE,
                "state": "ACTIVE",
            }
        ],
    }


def rollout(registry_value: dict) -> dict:
    return {
        "schema": signer.ROLLOUT_RECEIPT_SCHEMA,
        "cohort_id": "cohort-fixture-r1",
        "cohort_membership_sha256": "3" * 64,
        "expected_consumer_count": 2,
        "verifier_release_id": "verifier-fixture-r1",
        "registry_sha256": canonical_sha256(registry_value),
        "successful_readback_count": 2,
        "failed_readback_count": 0,
        "unresolved_consumer_count": 0,
        "readback_evidence_sha256": "4" * 64,
        "result": "COMPLETE",
    }


def manifest(custody: FakeCustody, registry_value: dict, rollout_value: dict) -> dict:
    return {
        "schema": signer.ACTIVATION_MANIFEST_SCHEMA,
        "producer_id": signer.PRODUCER_ID,
        "activation_generation": 1,
        "key_id": custody.key_id,
        "public_key_sha256": hashlib.sha256(custody._public_key).hexdigest(),
        "registry_sha256": canonical_sha256(registry_value),
        "verifier_release_id": rollout_value["verifier_release_id"],
        "rollout_cohort_id": rollout_value["cohort_id"],
        "rollout_membership_sha256": rollout_value["cohort_membership_sha256"],
        "rollout_receipt_sha256": canonical_sha256(rollout_value),
        "signer_release_id": signer.SIGNER_RELEASE_ID,
    }


def build_signer(
    *,
    custody: FakeCustody | None = None,
    registry_value: dict | None = None,
    rollout_value: dict | None = None,
    manifest_value: dict | None = None,
    anchor: FakeAnchor | None = None,
):
    custody = custody or FakeCustody()
    registry_value = registry_value or registry(custody)
    rollout_value = rollout_value or rollout(registry_value)
    manifest_value = manifest_value or manifest(custody, registry_value, rollout_value)
    anchor = anchor or FakeAnchor(
        manifest_value["activation_generation"],
        canonical_sha256(manifest_value),
    )
    instance = signer.TestOnlyAcceptanceOriginSigner(
        signing_custody=custody,
        activation_anchor=anchor,
        key_registry=registry_value,
        rollout_receipt=rollout_value,
        activation_manifest=manifest_value,
    )
    return instance, custody, anchor, registry_value, rollout_value, manifest_value


def sign_request(receipt_value: dict | None = None) -> dict:
    return {
        "schema": signer.SIGN_REQUEST_SCHEMA,
        "transport_receipt": receipt_value if receipt_value is not None else receipt(),
    }


def test_test_only_facade_returns_exact_signed_snapshot_bundle() -> None:
    instance, custody, anchor, _, _, _ = build_signer()
    request = sign_request()
    before = copy.deepcopy(request)

    response = instance.produce(sign_request=request)

    expected_acceptance = acceptance.accept_cross_ai_ruap_transport_receipt(
        before["transport_receipt"]
    )
    assert request == before
    assert response["schema"] == signer.PRODUCER_RESPONSE_SCHEMA
    assert frozenset(response) == frozenset({"schema", "acceptance", "signature_envelope"})
    assert response["acceptance"] == expected_acceptance

    envelope = response["signature_envelope"]
    assert envelope == {
        "schema": verifier.SIGNATURE_SCHEMA,
        "purpose": verifier.PURPOSE,
        "producer_id": signer.PRODUCER_ID,
        "key_id": custody.key_id,
        "algorithm": verifier.ALGORITHM,
        "acceptance_sha256": canonical_sha256(expected_acceptance),
        "signature_b64u": b64u(FAKE_SIGNATURE),
    }
    signed_payload = {key: envelope[key] for key in (
        "schema", "purpose", "producer_id", "key_id", "algorithm", "acceptance_sha256"
    )}
    expected_message = verifier.DOMAIN + json.dumps(
        signed_payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    ).encode("ascii")
    assert custody.messages == [expected_message]
    assert len(anchor.calls) == 2


@pytest.mark.parametrize(
    "field,value",
    [
        ("key_id", "caller-key"),
        ("algorithm", "Ed25519"),
        ("acceptance_sha256", "0" * 64),
        ("acceptance", {}),
    ],
)
def test_request_rejects_caller_selected_signing_material(field, value) -> None:
    instance, custody, _, _, _, _ = build_signer()
    request = sign_request()
    request[field] = value
    with pytest.raises(ValueError, match="sign_request_unknown_key"):
        instance.produce(sign_request=request)
    assert custody.messages == []


def test_oversized_transport_input_is_rejected_before_builder(monkeypatch) -> None:
    instance, custody, _, _, _, _ = build_signer()
    supplied = receipt()
    supplied["source_client"] = "x" * (signer.MAX_STRING_LEN + 1)
    calls = []

    def forbidden_builder(value):
        calls.append(value)
        raise AssertionError("builder must not run")

    monkeypatch.setattr(signer.acceptance_builder, "accept_cross_ai_ruap_transport_receipt", forbidden_builder)
    with pytest.raises(ValueError, match="snapshot_string_too_long"):
        instance.produce(sign_request=sign_request(supplied))
    assert calls == []
    assert custody.messages == []


def test_evidence_counts_are_bounded_before_builder(monkeypatch) -> None:
    instance, custody, _, _, _, _ = build_signer()
    supplied = receipt()
    supplied["ruap_evidence"]["source_count"] = signer.MAX_EVIDENCE_COUNT + 1
    calls = []

    def forbidden_builder(value):
        calls.append(value)
        raise AssertionError("builder must not run")

    monkeypatch.setattr(signer.acceptance_builder, "accept_cross_ai_ruap_transport_receipt", forbidden_builder)
    with pytest.raises(ValueError, match="transport_source_count_out_of_bounds"):
        instance.produce(sign_request=sign_request(supplied))
    assert calls == []
    assert custody.messages == []


def test_registry_key_id_must_equal_public_key_fingerprint() -> None:
    custody = FakeCustody()
    registry_value = registry(custody)
    registry_value["keys"][0]["key_id"] = key_id(OTHER_PUBLIC_KEY)
    rollout_value = rollout(registry_value)
    manifest_value = manifest(custody, registry_value, rollout_value)
    with pytest.raises(ValueError, match="registry_key_id_fingerprint_mismatch"):
        build_signer(
            custody=custody,
            registry_value=registry_value,
            rollout_value=rollout_value,
            manifest_value=manifest_value,
        )


def test_rollout_requires_every_frozen_consumer_and_zero_failures() -> None:
    custody = FakeCustody()
    registry_value = registry(custody)
    rollout_value = rollout(registry_value)
    rollout_value["successful_readback_count"] = 1
    manifest_value = manifest(custody, registry_value, rollout_value)
    with pytest.raises(ValueError, match="rollout_not_complete"):
        build_signer(
            custody=custody,
            registry_value=registry_value,
            rollout_value=rollout_value,
            manifest_value=manifest_value,
        )


def test_activation_manifest_binds_exact_signer_release() -> None:
    custody = FakeCustody()
    registry_value = registry(custody)
    rollout_value = rollout(registry_value)
    manifest_value = manifest(custody, registry_value, rollout_value)
    manifest_value["signer_release_id"] = "other-signer-release"
    with pytest.raises(ValueError, match="activation_signer_release_mismatch"):
        build_signer(
            custody=custody,
            registry_value=registry_value,
            rollout_value=rollout_value,
            manifest_value=manifest_value,
        )


def test_activation_anchor_rollback_fails_before_signing() -> None:
    custody = FakeCustody()
    registry_value = registry(custody)
    rollout_value = rollout(registry_value)
    manifest_value = manifest(custody, registry_value, rollout_value)
    anchor = FakeAnchor(0, canonical_sha256(manifest_value))
    instance, custody, _, _, _, _ = build_signer(
        custody=custody,
        registry_value=registry_value,
        rollout_value=rollout_value,
        manifest_value=manifest_value,
        anchor=anchor,
    )
    with pytest.raises(ValueError, match="activation_anchor_mismatch"):
        instance.produce(sign_request=sign_request())
    assert custody.messages == []


def test_custody_identity_drift_during_signing_fails_closed() -> None:
    instance, custody, _, _, _, _ = build_signer()
    custody.drift_after_sign = True
    with pytest.raises(ValueError, match="signing_custody_identity_drift"):
        instance.produce(sign_request=sign_request())
    assert len(custody.messages) == 1


def test_non_test_only_custody_is_rejected() -> None:
    custody = FakeCustody()
    custody.is_test_only = False
    registry_value = registry(custody)
    rollout_value = rollout(registry_value)
    manifest_value = manifest(custody, registry_value, rollout_value)
    anchor = FakeAnchor(1, canonical_sha256(manifest_value))
    with pytest.raises(ValueError, match="production_signing_custody_not_authorized"):
        signer.TestOnlyAcceptanceOriginSigner(
            signing_custody=custody,
            activation_anchor=anchor,
            key_registry=registry_value,
            rollout_receipt=rollout_value,
            activation_manifest=manifest_value,
        )


def test_candidate_has_no_hardware_provider_network_or_subprocess_imports() -> None:
    tree = ast.parse(inspect.getsource(signer))
    roots = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            roots.add(node.module.split(".")[0])
    assert roots.isdisjoint(
        {"os", "subprocess", "socket", "requests", "urllib", "http", "yubihsm", "tpm2_pytss"}
    )
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

    private_key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    class RealTestCustody(FakeCustody):
        def __init__(self) -> None:
            super().__init__(public_key)

        def sign_acceptance_origin_r1(self, message: bytes) -> bytes:
            self.messages.append(message)
            return private_key.sign(message)

    custody = RealTestCustody()
    registry_value = registry(custody)
    rollout_value = rollout(registry_value)
    manifest_value = manifest(custody, registry_value, rollout_value)
    anchor = FakeAnchor(1, canonical_sha256(manifest_value))
    instance, _, _, _, _, _ = build_signer(
        custody=custody,
        registry_value=registry_value,
        rollout_value=rollout_value,
        manifest_value=manifest_value,
        anchor=anchor,
    )
    response = instance.produce(sign_request=sign_request())

    monkeypatch.setattr(verifier, "PINNED_REGISTRY_SHA256", canonical_sha256(registry_value))
    result = verifier.verify_cross_ai_ruap_receipt_acceptance_origin(
        accepted_receipt=response["acceptance"],
        key_registry=registry_value,
        signature_envelope=response["signature_envelope"],
    )
    assert result.ok is True
    assert result.acceptance_origin_verified is True
    assert result.producer_id == signer.PRODUCER_ID
    assert result.key_id == custody.key_id
