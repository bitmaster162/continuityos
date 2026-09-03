"""Test-only acceptance-origin signer for the frozen YubiHSM2 + TPM2 R1 profile.

This candidate models the production signing facade without importing or touching
YubiHSM, TPM, provider, network, credential, filesystem, environment, subprocess,
runtime, deployment, trading, or capital surfaces.

Only test-only scoped adapters may be injected. Production hardware access,
production key generation/use, trust-anchor provisioning, and CURRENT_SIGNING
activation remain separately gated.
"""
from __future__ import annotations

import base64
import hashlib
from typing import Any, Protocol

from .cross_ai_ruap_receipt_acceptance import accept_cross_ai_ruap_transport_receipt
from . import cross_ai_ruap_receipt_acceptance_origin_verifier as origin_verifier


SIGN_REQUEST_SCHEMA = "continuityos.cross_ai_ruap_acceptance_origin_sign_request/v1"
PRODUCER_RESPONSE_SCHEMA = "continuityos.cross_ai_ruap_acceptance_origin_producer_response/v1"
ROLLOUT_RECEIPT_SCHEMA = "continuityos.cross_ai_ruap_acceptance_origin_rollout_receipt/v1"
ACTIVATION_MANIFEST_SCHEMA = "continuityos.cross_ai_ruap_acceptance_origin_activation_manifest/v1"
PRODUCER_ID = "continuityos.cross_ai_acceptance_producer.r1"
SIGNER_RELEASE_ID = "continuityos.cross_ai_ruap_acceptance_origin_signer_test_only/v1"
CUSTODY_PROFILE = "YUBIHSM2_ED25519_PLUS_TPM2_NV_TEST_ONLY"
TEST_ONLY_MODE = "TEST_ONLY_NO_PRODUCTION_HARDWARE"

MAX_FIELD_NAME_LEN = origin_verifier.MAX_FIELD_NAME_LEN
MAX_STRING_LEN = origin_verifier.MAX_STRING_LEN
MAX_CONTAINER_ITEMS = origin_verifier.MAX_CONTAINER_ITEMS
MAX_SNAPSHOT_NODES = origin_verifier.MAX_SNAPSHOT_NODES
MAX_EVIDENCE_COUNT = origin_verifier.MAX_EVIDENCE_COUNT
MAX_ROLLOUT_CONSUMERS = 100_000
MAX_ACTIVATION_GENERATION = 2_147_483_647
MAX_INTEGER_ABS = MAX_ACTIVATION_GENERATION
MAX_SNAPSHOT_DEPTH = 6

_SIGN_REQUEST_KEYS = frozenset({"schema", "transport_receipt"})
_ROLLOUT_KEYS = frozenset({
    "schema", "cohort_id", "cohort_membership_sha256", "expected_consumer_count",
    "verifier_release_id", "registry_sha256", "successful_readback_count",
    "failed_readback_count", "unresolved_consumer_count", "readback_evidence_sha256",
    "result",
})
_ACTIVATION_KEYS = frozenset({
    "schema", "producer_id", "activation_generation", "key_id", "public_key_sha256",
    "registry_sha256", "verifier_release_id", "rollout_cohort_id",
    "rollout_membership_sha256", "rollout_receipt_sha256", "signer_release_id",
})


class _ScopedEd25519Custody(Protocol):
    is_test_only: bool
    producer_id: str
    key_id: str
    public_key_b64u: str

    def sign_acceptance_origin_r1(self, message: bytes) -> bytes: ...


class _ActivationAnchor(Protocol):
    is_test_only: bool

    def assert_current_activation(
        self,
        *,
        activation_generation: int,
        activation_manifest_sha256: str,
    ) -> None: ...


def _snapshot_bounded(
    value: Any,
    *,
    depth: int = 0,
    _budget: list[int] | None = None,
) -> Any:
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


def _read_custody_identity(custody: _ScopedEd25519Custody) -> tuple[str, str, str, bytes]:
    producer_id = custody.producer_id
    key_id = custody.key_id
    public_key_b64u = custody.public_key_b64u
    if producer_id != PRODUCER_ID:
        raise ValueError("signing_custody_producer_mismatch")
    if not origin_verifier._is_identifier(key_id):
        raise ValueError("signing_custody_key_id_invalid")
    public_key = origin_verifier._decode_canonical_b64u(
        public_key_b64u,
        expected_len=32,
        label="signing_custody_public_key",
    )
    if key_id != _derive_key_id(public_key):
        raise ValueError("signing_custody_key_id_fingerprint_mismatch")
    return producer_id, key_id, public_key_b64u, public_key


def _require_rollout_receipt(value: Any) -> dict[str, Any]:
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
    return receipt


def _require_activation_manifest(value: Any) -> dict[str, Any]:
    manifest = _require_exact_keys(value, _ACTIVATION_KEYS, "activation_manifest")
    if manifest["schema"] != ACTIVATION_MANIFEST_SCHEMA:
        raise ValueError("activation_manifest_schema_invalid")
    if manifest["producer_id"] != PRODUCER_ID:
        raise ValueError("activation_manifest_producer_mismatch")

    generation = manifest["activation_generation"]
    if type(generation) is not int or generation < 1 or generation > MAX_ACTIVATION_GENERATION:
        raise ValueError("activation_generation_invalid")

    for key in ("public_key_sha256", "registry_sha256", "rollout_membership_sha256", "rollout_receipt_sha256"):
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
    return manifest


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


class TestOnlyAcceptanceOriginSigner:
    """Frozen-contract signer facade wired only to explicit test-only adapters."""

    def __init__(
        self,
        *,
        signing_custody: _ScopedEd25519Custody,
        activation_anchor: _ActivationAnchor,
        key_registry: Any,
        rollout_receipt: Any,
        activation_manifest: Any,
    ) -> None:
        if getattr(signing_custody, "is_test_only", None) is not True:
            raise ValueError("production_signing_custody_not_authorized")
        if getattr(activation_anchor, "is_test_only", None) is not True:
            raise ValueError("production_activation_anchor_not_authorized")

        self._signing_custody = signing_custody
        self._activation_anchor = activation_anchor
        self._key_registry = _snapshot_bounded(key_registry)
        self._rollout_receipt = _snapshot_bounded(rollout_receipt)
        self._activation_manifest = _snapshot_bounded(activation_manifest)
        self._registry_sha256 = ""
        self._activation_manifest_sha256 = ""
        self._expected_custody_identity: tuple[str, str, str, bytes] | None = None
        self._validate_static_coherence()

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
        rollout = _require_rollout_receipt(self._rollout_receipt)
        manifest = _require_activation_manifest(self._activation_manifest)
        rollout_sha256 = _canonical_sha256(rollout)

        custody_identity = _read_custody_identity(self._signing_custody)
        producer_id, key_id, public_key_b64u, public_key = custody_identity
        public_key_sha256 = hashlib.sha256(public_key).hexdigest()

        matches = [
            record for record in keys
            if record["producer_id"] == producer_id
            and record["key_id"] == key_id
            and record["public_key_b64u"] == public_key_b64u
        ]
        if len(matches) != 1 or matches[0]["state"] != "ACTIVE":
            raise ValueError("signing_custody_key_not_active_in_registry")
        if rollout["registry_sha256"] != registry_sha256:
            raise ValueError("rollout_registry_mismatch")
        if (
            manifest["key_id"] != key_id
            or manifest["public_key_sha256"] != public_key_sha256
            or manifest["registry_sha256"] != registry_sha256
            or manifest["verifier_release_id"] != rollout["verifier_release_id"]
            or manifest["rollout_cohort_id"] != rollout["cohort_id"]
            or manifest["rollout_membership_sha256"] != rollout["cohort_membership_sha256"]
            or manifest["rollout_receipt_sha256"] != rollout_sha256
        ):
            raise ValueError("activation_manifest_coherence_mismatch")

        self._registry_sha256 = registry_sha256
        self._activation_manifest_sha256 = _canonical_sha256(manifest)
        self._expected_custody_identity = custody_identity

    def _assert_live_test_coherence(self) -> tuple[str, str, str, bytes]:
        current = _read_custody_identity(self._signing_custody)
        if current != self._expected_custody_identity:
            raise ValueError("signing_custody_identity_drift")
        self._activation_anchor.assert_current_activation(
            activation_generation=self._activation_manifest["activation_generation"],
            activation_manifest_sha256=self._activation_manifest_sha256,
        )
        return current

    def produce(self, *, sign_request: Any) -> dict[str, Any]:
        """Produce one atomic test-only acceptance + detached Ed25519 envelope."""
        request = _snapshot_bounded(sign_request)
        request = _require_exact_keys(request, _SIGN_REQUEST_KEYS, "sign_request")
        if request["schema"] != SIGN_REQUEST_SCHEMA:
            raise ValueError("sign_request_schema_invalid")

        transport_receipt = request["transport_receipt"]
        _prevalidate_transport_bounds(transport_receipt)
        _, key_id, _, _ = self._assert_live_test_coherence()

        materialized = accept_cross_ai_ruap_transport_receipt(transport_receipt)
        acceptance = origin_verifier._require_safe_acceptance(origin_verifier._snapshot(materialized))
        acceptance = _snapshot_bounded(acceptance)
        acceptance_sha256 = _canonical_sha256(acceptance)

        message = _signature_message(key_id=key_id, acceptance_sha256=acceptance_sha256)
        raw_signature = self._signing_custody.sign_acceptance_origin_r1(message)
        if type(raw_signature) is not bytes:
            raise ValueError("ed25519_signature_not_bytes")
        if len(raw_signature) != 64:
            raise ValueError("ed25519_signature_length_invalid")

        _, post_key_id, _, _ = self._assert_live_test_coherence()
        if post_key_id != key_id:
            raise ValueError("signing_custody_identity_drift")

        signature_envelope = {
            "schema": origin_verifier.SIGNATURE_SCHEMA,
            "purpose": origin_verifier.PURPOSE,
            "producer_id": PRODUCER_ID,
            "key_id": key_id,
            "algorithm": origin_verifier.ALGORITHM,
            "acceptance_sha256": acceptance_sha256,
            "signature_b64u": base64.urlsafe_b64encode(raw_signature).rstrip(b"=").decode("ascii"),
        }
        return {
            "schema": PRODUCER_RESPONSE_SCHEMA,
            "acceptance": acceptance,
            "signature_envelope": signature_envelope,
        }
