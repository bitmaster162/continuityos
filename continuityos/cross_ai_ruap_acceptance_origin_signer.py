"""Test-only acceptance-origin signer for the frozen YubiHSM2 + TPM2 R1 profile.

This candidate models the producer/signer contract without importing or touching
YubiHSM, TPM, provider, network, credential, filesystem, environment, subprocess,
runtime, deployment, trading, or capital surfaces.

Only closed plain-data fixtures plus bytes are accepted. No caller-supplied
callable, adapter, protocol object, or hardware/network/filesystem capability can
be injected into the signer. Production hardware access, production key use,
trust-anchor provisioning, and CURRENT_SIGNING activation remain separately gated.
"""
from __future__ import annotations

import base64
import hashlib
import marshal
from typing import Any

from . import cross_ai_ruap_receipt_acceptance as acceptance_builder
from . import cross_ai_ruap_receipt_acceptance_origin_verifier as origin_verifier

SIGN_REQUEST_SCHEMA = "continuityos.cross_ai_ruap_acceptance_origin_sign_request/v1"
PRODUCER_RESPONSE_SCHEMA = "continuityos.cross_ai_ruap_acceptance_origin_producer_response/v1"
ROLLOUT_RECEIPT_SCHEMA = "continuityos.cross_ai_ruap_acceptance_origin_rollout_receipt/v1"
ROLLOUT_EVIDENCE_SCHEMA = "continuityos.cross_ai_ruap_acceptance_origin_rollout_readback_evidence/v1"
COHORT_MEMBERSHIP_SCHEMA = "continuityos.cross_ai_ruap_acceptance_origin_rollout_membership/v1"
ACTIVATION_MANIFEST_SCHEMA = "continuityos.cross_ai_ruap_acceptance_origin_activation_manifest/v1"
TEST_ANCHOR_SCHEMA = "continuityos.cross_ai_ruap_acceptance_origin_test_activation_anchor/v1"
PRODUCER_ID = "continuityos.cross_ai_acceptance_producer.r1"
SIGNER_RELEASE_ID = "continuityos.cross_ai_ruap_acceptance_origin_signer_test_only/v2"
CUSTODY_PROFILE = "YUBIHSM2_ED25519_PLUS_TPM2_NV_TEST_ONLY"
TEST_ONLY_MODE = "TEST_ONLY_NO_PRODUCTION_HARDWARE"

MAX_FIELD_NAME_LEN = origin_verifier.MAX_FIELD_NAME_LEN
MAX_STRING_LEN = origin_verifier.MAX_STRING_LEN
MAX_CONTAINER_ITEMS = origin_verifier.MAX_CONTAINER_ITEMS
MAX_SNAPSHOT_NODES = origin_verifier.MAX_SNAPSHOT_NODES
MAX_EVIDENCE_COUNT = origin_verifier.MAX_EVIDENCE_COUNT
MAX_ROLLOUT_CONSUMERS = MAX_CONTAINER_ITEMS
MAX_ACTIVATION_GENERATION = 2_147_483_647
MAX_INTEGER_ABS = MAX_ACTIVATION_GENERATION
MAX_SNAPSHOT_DEPTH = 8

_SIGN_REQUEST_KEYS = frozenset({"schema", "transport_receipt"})
_ROLLOUT_KEYS = frozenset({
    "schema", "cohort_id", "cohort_membership_sha256", "expected_consumer_count",
    "verifier_release_id", "registry_sha256", "successful_readback_count",
    "failed_readback_count", "unresolved_consumer_count", "readback_evidence_sha256",
    "result",
})
_ROLLOUT_EVIDENCE_KEYS = frozenset({
    "schema", "cohort_id", "cohort_membership_sha256", "expected_consumer_count",
    "verifier_release_id", "registry_sha256", "readbacks",
})
_READBACK_KEYS = frozenset({
    "consumer_id", "verifier_release_id", "registry_sha256", "ok",
})
_ACTIVATION_KEYS = frozenset({
    "schema", "producer_id", "activation_generation", "key_id", "public_key_sha256",
    "registry_sha256", "verifier_release_id", "rollout_cohort_id",
    "rollout_membership_sha256", "rollout_receipt_sha256", "signer_release_id",
    "signer_implementation_sha256",
})
_ANCHOR_KEYS = frozenset({
    "schema", "activation_generation", "activation_manifest_sha256",
})


def _snapshot_bounded(value: Any, *, depth: int = 0, _budget: list[int] | None = None) -> Any:
    if _budget is None:
        _budget = [MAX_SNAPSHOT_NODES]
    _budget[0] -= 1
    if _budget[0] < 0:
        raise ValueError("snapshot_node_budget_exceeded")
    if depth >= MAX_SNAPSHOT_DEPTH:
        raise ValueError("snapshot_nested_too_deep")
    if type(value) is dict:
        if len(value) > MAX_CONTAINER_ITEMS:
            raise ValueError("snapshot_container_too_large")
        out: dict[str, Any] = {}
        for key, item in value.items():
            if type(key) is not str:
                raise ValueError("snapshot_non_string_key")
            if len(key) > MAX_FIELD_NAME_LEN:
                raise ValueError("snapshot_field_name_too_long")
            out[key] = _snapshot_bounded(item, depth=depth + 1, _budget=_budget)
        return out
    if type(value) is list:
        if len(value) > MAX_CONTAINER_ITEMS:
            raise ValueError("snapshot_container_too_large")
        return [_snapshot_bounded(item, depth=depth + 1, _budget=_budget) for item in value]
    if type(value) is str:
        if len(value) > MAX_STRING_LEN:
            raise ValueError("snapshot_string_too_long")
        return value
    if type(value) is bool:
        return value
    if type(value) is int:
        if not -MAX_INTEGER_ABS <= value <= MAX_INTEGER_ABS:
            raise ValueError("snapshot_integer_out_of_bounds")
        return value
    raise ValueError("snapshot_non_plain_value")


def _require_exact_keys(value: Any, expected: frozenset[str], label: str) -> dict[str, Any]:
    if type(value) is not dict:
        raise ValueError(f"{label}_not_plain_object")
    actual = frozenset(value)
    missing = sorted(expected - actual)
    unknown = sorted(actual - expected)
    if missing:
        raise ValueError(f"{label}_missing_key:{missing[0]}")
    if unknown:
        raise ValueError(f"{label}_unknown_key:{unknown[0]}")
    return value


def _canonical_sha256(value: Any) -> str:
    return origin_verifier._canonical_sha256(value)


def _derive_key_id(public_key: bytes) -> str:
    return "ed25519-sha256:" + hashlib.sha256(public_key).hexdigest()


def _decode_public_key(public_key_b64u: Any) -> bytes:
    return origin_verifier._decode_canonical_b64u(
        public_key_b64u,
        expected_len=32,
        label="test_signing_public_key",
    )


def _validate_test_signing_material(*, public_key_b64u: Any, test_fixed_signature: Any, test_private_key_seed: Any) -> tuple[str, bytes]:
    public_key = _decode_public_key(public_key_b64u)
    if test_fixed_signature is not None and test_private_key_seed is not None:
        raise ValueError("test_signing_material_ambiguous")
    if test_fixed_signature is None and test_private_key_seed is None:
        raise ValueError("test_signing_material_missing")
    if test_fixed_signature is not None:
        if type(test_fixed_signature) is not bytes or len(test_fixed_signature) != 64:
            raise ValueError("test_fixed_signature_invalid")
        return "FIXED_TEST_SIGNATURE", public_key
    if type(test_private_key_seed) is not bytes or len(test_private_key_seed) != 32:
        raise ValueError("test_private_key_seed_invalid")
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    except (ImportError, ModuleNotFoundError) as exc:
        raise ValueError("test_ed25519_backend_unavailable") from exc
    private_key = Ed25519PrivateKey.from_private_bytes(test_private_key_seed)
    derived = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    if derived != public_key:
        raise ValueError("test_private_key_public_key_mismatch")
    return "SOFTWARE_TEST_ED25519", public_key


def _cohort_membership_sha256(*, cohort_id: str, consumer_ids: list[str]) -> str:
    return _canonical_sha256({
        "schema": COHORT_MEMBERSHIP_SCHEMA,
        "cohort_id": cohort_id,
        "consumer_ids": sorted(consumer_ids),
    })


def _require_rollout_evidence(value: Any) -> dict[str, Any]:
    evidence = _require_exact_keys(value, _ROLLOUT_EVIDENCE_KEYS, "rollout_evidence")
    if evidence["schema"] != ROLLOUT_EVIDENCE_SCHEMA:
        raise ValueError("rollout_evidence_schema_invalid")
    if not origin_verifier._is_identifier(evidence["cohort_id"]):
        raise ValueError("rollout_evidence_cohort_id_invalid")
    if not origin_verifier._is_sha256(evidence["cohort_membership_sha256"]):
        raise ValueError("rollout_evidence_membership_sha256_invalid")
    if not origin_verifier._is_identifier(evidence["verifier_release_id"]):
        raise ValueError("rollout_evidence_verifier_release_invalid")
    if not origin_verifier._is_sha256(evidence["registry_sha256"]):
        raise ValueError("rollout_evidence_registry_sha256_invalid")
    expected = evidence["expected_consumer_count"]
    if type(expected) is not int or not 1 <= expected <= MAX_ROLLOUT_CONSUMERS:
        raise ValueError("rollout_evidence_expected_count_invalid")
    readbacks = evidence["readbacks"]
    if type(readbacks) is not list or len(readbacks) != expected:
        raise ValueError("rollout_evidence_readback_count_mismatch")
    seen: set[str] = set()
    consumer_ids: list[str] = []
    for item in readbacks:
        readback = _require_exact_keys(item, _READBACK_KEYS, "rollout_readback")
        consumer_id = readback["consumer_id"]
        if not origin_verifier._is_identifier(consumer_id):
            raise ValueError("rollout_readback_consumer_id_invalid")
        if consumer_id in seen:
            raise ValueError("rollout_readback_duplicate_consumer")
        seen.add(consumer_id)
        consumer_ids.append(consumer_id)
        if (
            readback["verifier_release_id"] != evidence["verifier_release_id"]
            or readback["registry_sha256"] != evidence["registry_sha256"]
            or readback["ok"] is not True
        ):
            raise ValueError("rollout_readback_not_exact_success")
    if evidence["cohort_membership_sha256"] != _cohort_membership_sha256(
        cohort_id=evidence["cohort_id"], consumer_ids=consumer_ids
    ):
        raise ValueError("rollout_evidence_membership_digest_mismatch")
    return evidence


def _require_rollout_receipt(value: Any, *, evidence: dict[str, Any]) -> dict[str, Any]:
    receipt = _require_exact_keys(value, _ROLLOUT_KEYS, "rollout_receipt")
    if receipt["schema"] != ROLLOUT_RECEIPT_SCHEMA:
        raise ValueError("rollout_receipt_schema_invalid")
    if not origin_verifier._is_identifier(receipt["cohort_id"]):
        raise ValueError("rollout_cohort_id_invalid")
    if not origin_verifier._is_sha256(receipt["cohort_membership_sha256"]):
        raise ValueError("rollout_membership_sha256_invalid")
    if not origin_verifier._is_identifier(receipt["verifier_release_id"]):
        raise ValueError("rollout_verifier_release_invalid")
    if not origin_verifier._is_sha256(receipt["registry_sha256"]):
        raise ValueError("rollout_registry_sha256_invalid")
    if not origin_verifier._is_sha256(receipt["readback_evidence_sha256"]):
        raise ValueError("rollout_readback_evidence_sha256_invalid")
    expected = receipt["expected_consumer_count"]
    success = receipt["successful_readback_count"]
    failed = receipt["failed_readback_count"]
    unresolved = receipt["unresolved_consumer_count"]
    for label, count in (("expected", expected), ("successful", success), ("failed", failed), ("unresolved", unresolved)):
        if type(count) is not int or count < 0 or count > MAX_ROLLOUT_CONSUMERS:
            raise ValueError(f"rollout_{label}_count_invalid")
    if expected < 1 or success != expected or failed != 0 or unresolved != 0 or receipt["result"] != "COMPLETE":
        raise ValueError("rollout_not_complete")
    if receipt["readback_evidence_sha256"] != _canonical_sha256(evidence):
        raise ValueError("rollout_readback_evidence_digest_mismatch")
    if (
        receipt["cohort_id"] != evidence["cohort_id"]
        or receipt["cohort_membership_sha256"] != evidence["cohort_membership_sha256"]
        or receipt["expected_consumer_count"] != evidence["expected_consumer_count"]
        or receipt["verifier_release_id"] != evidence["verifier_release_id"]
        or receipt["registry_sha256"] != evidence["registry_sha256"]
        or receipt["successful_readback_count"] != len(evidence["readbacks"])
    ):
        raise ValueError("rollout_receipt_evidence_coherence_mismatch")
    return receipt


def _require_activation_manifest(value: Any, *, signer_implementation_sha256: str) -> dict[str, Any]:
    manifest = _require_exact_keys(value, _ACTIVATION_KEYS, "activation_manifest")
    if manifest["schema"] != ACTIVATION_MANIFEST_SCHEMA:
        raise ValueError("activation_manifest_schema_invalid")
    if manifest["producer_id"] != PRODUCER_ID:
        raise ValueError("activation_manifest_producer_mismatch")
    generation = manifest["activation_generation"]
    if type(generation) is not int or generation < 1 or generation > MAX_ACTIVATION_GENERATION:
        raise ValueError("activation_generation_invalid")
    for key in (
        "public_key_sha256", "registry_sha256", "rollout_membership_sha256",
        "rollout_receipt_sha256", "signer_implementation_sha256",
    ):
        if not origin_verifier._is_sha256(manifest[key]):
            raise ValueError(f"activation_{key}_invalid")
    if not origin_verifier._is_identifier(manifest["key_id"]):
        raise ValueError("activation_key_id_invalid")
    if not origin_verifier._is_identifier(manifest["verifier_release_id"]):
        raise ValueError("activation_verifier_release_invalid")
    if not origin_verifier._is_identifier(manifest["rollout_cohort_id"]):
        raise ValueError("activation_rollout_cohort_invalid")
    if manifest["signer_release_id"] != SIGNER_RELEASE_ID:
        raise ValueError("activation_signer_release_mismatch")
    if manifest["signer_implementation_sha256"] != signer_implementation_sha256:
        raise ValueError("activation_signer_implementation_mismatch")
    return manifest


def _require_test_anchor(value: Any) -> dict[str, Any]:
    anchor = _require_exact_keys(value, _ANCHOR_KEYS, "test_activation_anchor")
    if anchor["schema"] != TEST_ANCHOR_SCHEMA:
        raise ValueError("test_activation_anchor_schema_invalid")
    generation = anchor["activation_generation"]
    if type(generation) is not int or generation < 1 or generation > MAX_ACTIVATION_GENERATION:
        raise ValueError("test_activation_anchor_generation_invalid")
    if not origin_verifier._is_sha256(anchor["activation_manifest_sha256"]):
        raise ValueError("test_activation_anchor_digest_invalid")
    return anchor


def _prevalidate_transport_bounds(receipt: Any) -> None:
    if type(receipt) is not dict:
        raise ValueError("transport_receipt_not_plain_object")
    evidence = receipt.get("ruap_evidence")
    if type(evidence) is not dict:
        return
    for key in ("source_count", "observation_count"):
        value = evidence.get(key)
        if type(value) is int and not 0 <= value <= MAX_EVIDENCE_COUNT:
            raise ValueError(f"transport_{key}_out_of_bounds")


def _signature_message(*, key_id: str, acceptance_sha256: str) -> bytes:
    payload = {
        "schema": origin_verifier.SIGNATURE_SCHEMA,
        "purpose": origin_verifier.PURPOSE,
        "producer_id": PRODUCER_ID,
        "key_id": key_id,
        "algorithm": origin_verifier.ALGORITHM,
        "acceptance_sha256": acceptance_sha256,
    }
    return origin_verifier.DOMAIN + origin_verifier._canonical_bytes(payload)


def _code_identity_sha256(code_objects: tuple[Any, ...]) -> str:
    digest = hashlib.sha256()
    for code in code_objects:
        encoded = marshal.dumps(code)
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
    return digest.hexdigest()


class TestOnlyAcceptanceOriginSigner:
    """Frozen-contract producer facade with sealed software-only test signing."""

    def __init__(
        self,
        *,
        test_public_key_b64u: str,
        test_fixed_signature: bytes | None,
        test_private_key_seed: bytes | None,
        key_registry: Any,
        rollout_receipt: Any,
        rollout_evidence: Any,
        activation_manifest: Any,
        test_activation_anchor: Any,
    ) -> None:
        self._test_public_key_b64u = test_public_key_b64u
        self._test_fixed_signature = test_fixed_signature
        self._test_private_key_seed = test_private_key_seed
        self._signing_mode, self._public_key = _validate_test_signing_material(
            public_key_b64u=test_public_key_b64u,
            test_fixed_signature=test_fixed_signature,
            test_private_key_seed=test_private_key_seed,
        )
        self._key_id = _derive_key_id(self._public_key)
        self._implementation_sha256 = self.implementation_sha256()
        self._key_registry = _snapshot_bounded(key_registry)
        self._rollout_evidence = _snapshot_bounded(rollout_evidence)
        self._rollout_receipt = _snapshot_bounded(rollout_receipt)
        self._activation_manifest = _snapshot_bounded(activation_manifest)
        self._test_activation_anchor = _snapshot_bounded(test_activation_anchor)
        self._registry_sha256 = ""
        self._activation_manifest_sha256 = ""
        self._validate_static_coherence()

    @staticmethod
    def implementation_sha256() -> str:
        return _code_identity_sha256((
            _snapshot_bounded.__code__,
            _require_exact_keys.__code__,
            _validate_test_signing_material.__code__,
            _cohort_membership_sha256.__code__,
            _require_rollout_evidence.__code__,
            _require_rollout_receipt.__code__,
            _require_activation_manifest.__code__,
            _require_test_anchor.__code__,
            _prevalidate_transport_bounds.__code__,
            _signature_message.__code__,
            acceptance_builder.accept_cross_ai_ruap_transport_receipt.__code__,
            origin_verifier._require_safe_acceptance.__code__,
            origin_verifier._canonical_bytes.__code__,
            TestOnlyAcceptanceOriginSigner.__init__.__code__,
            TestOnlyAcceptanceOriginSigner._validate_static_coherence.__code__,
            TestOnlyAcceptanceOriginSigner._assert_test_anchor.__code__,
            TestOnlyAcceptanceOriginSigner._sign_test_message.__code__,
            TestOnlyAcceptanceOriginSigner.produce.__code__,
        ))

    def _validate_static_coherence(self) -> None:
        registry, keys = origin_verifier._require_registry(origin_verifier._snapshot(self._key_registry))
        if keys != sorted(keys, key=lambda item: (item["producer_id"], item["key_id"])):
            raise ValueError("registry_key_order_invalid")
        for record in keys:
            public_key = origin_verifier._decode_canonical_b64u(
                record["public_key_b64u"], expected_len=32, label="registry_public_key"
            )
            if record["key_id"] != _derive_key_id(public_key):
                raise ValueError("registry_key_id_fingerprint_mismatch")
        registry_sha256 = _canonical_sha256(registry)
        evidence = _require_rollout_evidence(self._rollout_evidence)
        rollout = _require_rollout_receipt(self._rollout_receipt, evidence=evidence)
        rollout_sha256 = _canonical_sha256(rollout)
        manifest = _require_activation_manifest(
            self._activation_manifest,
            signer_implementation_sha256=self._implementation_sha256,
        )
        anchor = _require_test_anchor(self._test_activation_anchor)
        public_key_sha256 = hashlib.sha256(self._public_key).hexdigest()
        matches = [
            record for record in keys
            if record["producer_id"] == PRODUCER_ID
            and record["key_id"] == self._key_id
            and record["public_key_b64u"] == self._test_public_key_b64u
        ]
        if len(matches) != 1 or matches[0]["state"] != "ACTIVE":
            raise ValueError("test_signing_key_not_active_in_registry")
        if rollout["registry_sha256"] != registry_sha256:
            raise ValueError("rollout_registry_mismatch")
        if (
            manifest["key_id"] != self._key_id
            or manifest["public_key_sha256"] != public_key_sha256
            or manifest["registry_sha256"] != registry_sha256
            or manifest["verifier_release_id"] != rollout["verifier_release_id"]
            or manifest["rollout_cohort_id"] != rollout["cohort_id"]
            or manifest["rollout_membership_sha256"] != rollout["cohort_membership_sha256"]
            or manifest["rollout_receipt_sha256"] != rollout_sha256
        ):
            raise ValueError("activation_manifest_coherence_mismatch")
        manifest_sha256 = _canonical_sha256(manifest)
        if (
            anchor["activation_generation"] != manifest["activation_generation"]
            or anchor["activation_manifest_sha256"] != manifest_sha256
        ):
            raise ValueError("test_activation_anchor_mismatch")
        self._registry_sha256 = registry_sha256
        self._activation_manifest_sha256 = manifest_sha256

    def _assert_test_anchor(self) -> None:
        if self.implementation_sha256() != self._implementation_sha256:
            raise ValueError("signer_implementation_drift")
        anchor = _require_test_anchor(_snapshot_bounded(self._test_activation_anchor))
        if (
            anchor["activation_generation"] != self._activation_manifest["activation_generation"]
            or anchor["activation_manifest_sha256"] != self._activation_manifest_sha256
        ):
            raise ValueError("test_activation_anchor_mismatch")

    def _sign_test_message(self, message: bytes) -> bytes:
        if type(message) is not bytes:
            raise ValueError("test_signing_message_not_bytes")
        if self._signing_mode == "FIXED_TEST_SIGNATURE":
            assert self._test_fixed_signature is not None
            return self._test_fixed_signature
        if self._signing_mode != "SOFTWARE_TEST_ED25519":
            raise ValueError("test_signing_mode_invalid")
        assert self._test_private_key_seed is not None
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        except (ImportError, ModuleNotFoundError) as exc:
            raise ValueError("test_ed25519_backend_unavailable") from exc
        return Ed25519PrivateKey.from_private_bytes(self._test_private_key_seed).sign(message)

    def produce(self, *, sign_request: Any) -> dict[str, Any]:
        request = _snapshot_bounded(sign_request)
        request = _require_exact_keys(request, _SIGN_REQUEST_KEYS, "sign_request")
        if request["schema"] != SIGN_REQUEST_SCHEMA:
            raise ValueError("sign_request_schema_invalid")
        transport_receipt = request["transport_receipt"]
        _prevalidate_transport_bounds(transport_receipt)
        self._assert_test_anchor()
        materialized = acceptance_builder.accept_cross_ai_ruap_transport_receipt(transport_receipt)
        acceptance = origin_verifier._require_safe_acceptance(origin_verifier._snapshot(materialized))
        acceptance = _snapshot_bounded(acceptance)
        acceptance_sha256 = _canonical_sha256(acceptance)
        message = _signature_message(key_id=self._key_id, acceptance_sha256=acceptance_sha256)
        raw_signature = self._sign_test_message(message)
        if type(raw_signature) is not bytes:
            raise ValueError("ed25519_signature_not_bytes")
        if len(raw_signature) != 64:
            raise ValueError("ed25519_signature_length_invalid")
        self._assert_test_anchor()
        signature_envelope = {
            "schema": origin_verifier.SIGNATURE_SCHEMA,
            "purpose": origin_verifier.PURPOSE,
            "producer_id": PRODUCER_ID,
            "key_id": self._key_id,
            "algorithm": origin_verifier.ALGORITHM,
            "acceptance_sha256": acceptance_sha256,
            "signature_b64u": base64.urlsafe_b64encode(raw_signature).rstrip(b"=").decode("ascii"),
        }
        return {
            "schema": PRODUCER_RESPONSE_SCHEMA,
            "acceptance": acceptance,
            "signature_envelope": signature_envelope,
        }
