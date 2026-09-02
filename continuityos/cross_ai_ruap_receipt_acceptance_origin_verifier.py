"""Offline Ed25519 verifier for Cross-AI RUAP acceptance origin.

This verifier consumes caller-supplied acceptance-shaped evidence, a caller-supplied
public key-registry snapshot, and a detached signature envelope. Trust comes only
from an implementation-owned pinned SHA-256 digest for the exact key-registry
snapshot. The default R1 pin names an empty registry, so production acceptance
origin remains fail-closed until a separately authorized trust-anchor update
replaces the pin with a reviewed registry digest.

The optional ``cryptography`` backend is imported lazily. Missing/unsupported
backend support fails closed; there is no hash/HMAC/manual-attestation fallback.
No provider, network, credential, environment-secret, filesystem, subprocess,
runtime, pointer, memory, deploy, trading, or capital effect is performed.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
import hashlib
import json
from typing import Any

ACCEPTANCE_SCHEMA = "continuityos.cross_ai_ruap_receipt_acceptance/v1"
ACCEPTANCE_CLASS = "STRUCTURAL_SELF_CONSISTENCY_ONLY"
RUAP_SCHEMA = "ruap.snapshot/v1"
SUPPORTED_CLIENTS = ("claude", "cursor", "hermes", "generic-mcp")

ANCHOR_SCHEMA = "continuityos.cross_ai_ruap_acceptance_origin_anchor/v1"
REGISTRY_SCHEMA = "continuityos.cross_ai_ruap_acceptance_origin_key_registry/v1"
SIGNATURE_SCHEMA = "continuityos.cross_ai_ruap_receipt_acceptance_origin_signature/v1"
MODE = "EVIDENCE_ONLY"
ANCHOR_CLASS = "PINNED_ED25519_KEY_REGISTRY_SNAPSHOT"
PURPOSE = "CROSS_AI_RUAP_RECEIPT_ACCEPTANCE_ORIGIN"
ALGORITHM = "Ed25519"
REGISTRY_ID = "continuityos-cross-ai-acceptance-origin-r1"
DOMAIN = b"continuityos.cross_ai_ruap_receipt_acceptance_origin/v1\0"

# R1 intentionally pins the canonical empty registry. No production signing key is
# trusted by this implementation gate; a real registry pin requires a separate
# exact trust-anchor update gate.
PINNED_REGISTRY_SHA256 = "c85454892cfd528852f1f084a75dd3ed13393a959c21dca72d19537e64bc3b1e"

MAX_KEYS = 32
MAX_IDENTIFIER_LEN = 96
MAX_CONTAINER_ITEMS = 64
MAX_SNAPSHOT_DEPTH = 4

_ACCEPTANCE_KEYS = frozenset({
    "schema", "mode", "acceptance_class", "transport_id", "source_client",
    "target_client", "ruap_evidence", "verification", "execution_authority",
    "can_execute", "can_trade", "capital_permission", "deploy_permission",
})
_EVIDENCE_KEYS = frozenset({
    "schema", "snapshot_sha256", "source_count", "observation_count",
    "freshness_required", "authority_ceiling", "authority_class",
})
_ACCEPTANCE_VERIFICATION_KEYS = frozenset({
    "shape_verified", "integrity_checked", "authenticity_verified",
    "provenance_verified", "signer_identity_verified", "current_truth_promoted",
})
_REGISTRY_KEYS = frozenset({"schema", "registry_id", "keys"})
_KEY_RECORD_KEYS = frozenset({
    "producer_id", "key_id", "algorithm", "public_key_b64u", "usage", "state",
})
_SIGNATURE_KEYS = frozenset({
    "schema", "purpose", "producer_id", "key_id", "algorithm",
    "acceptance_sha256", "signature_b64u",
})
_ALLOWED_KEY_STATES = frozenset({"ACTIVE", "RETIRED", "REVOKED"})


@dataclass(frozen=True)
class AcceptanceOriginVerification:
    ok: bool
    errors: tuple[str, ...]
    acceptance_origin_verified: bool = False
    expected_acceptance_sha256: str | None = None
    expected_registry_sha256: str | None = None
    producer_id: str | None = None
    key_id: str | None = None


def _snapshot(value: Any, *, depth: int = 0) -> Any:
    if depth >= MAX_SNAPSHOT_DEPTH:
        raise ValueError("nested_too_deep")
    if type(value) is dict:
        if len(value) > MAX_CONTAINER_ITEMS:
            raise ValueError("container_too_large")
        out: dict[str, Any] = {}
        for key, item in value.items():
            if type(key) is not str:
                raise ValueError("non_string_key")
            out[key] = _snapshot(item, depth=depth + 1)
        return out
    if type(value) is list:
        if len(value) > MAX_CONTAINER_ITEMS:
            raise ValueError("container_too_large")
        return [_snapshot(item, depth=depth + 1) for item in value]
    if type(value) in (str, bool, int):
        return value
    raise ValueError("non_plain_value")


def _require_keys(value: Any, expected: frozenset[str], label: str) -> dict[str, Any]:
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


def _canonical_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value, ensure_ascii=True, sort_keys=True, separators=(",", ":")
        ).encode("ascii")
    except (TypeError, UnicodeEncodeError) as exc:
        raise ValueError("canonical_encoding_invalid") from exc


def _canonical_sha256(value: Any) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _is_sha256(value: Any) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(char in "0123456789abcdef" for char in value)
    )


def _is_transport_id(value: Any) -> bool:
    return (
        type(value) is str
        and value.startswith("xrt_")
        and _is_sha256(value.removeprefix("xrt_"))
    )


def _is_identifier(value: Any) -> bool:
    return (
        type(value) is str
        and 1 <= len(value) <= MAX_IDENTIFIER_LEN
        and all(
            char.isascii() and (char.isalnum() or char in "._:-")
            for char in value
        )
    )


def _decode_canonical_b64u(value: Any, *, expected_len: int, label: str) -> bytes:
    if type(value) is not str or "=" in value or not value:
        raise ValueError(f"{label}_encoding_invalid")
    try:
        padding = "=" * ((4 - len(value) % 4) % 4)
        decoded = base64.b64decode(value + padding, altchars=b"-_", validate=True)
    except (ValueError, TypeError) as exc:
        raise ValueError(f"{label}_encoding_invalid") from exc
    if len(decoded) != expected_len:
        raise ValueError(f"{label}_length_invalid")
    canonical = base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii")
    if canonical != value:
        raise ValueError(f"{label}_encoding_invalid")
    return decoded


def _require_safe_acceptance(value: Any) -> dict[str, Any]:
    accepted = _require_keys(value, _ACCEPTANCE_KEYS, "acceptance")
    if (
        accepted["schema"] != ACCEPTANCE_SCHEMA
        or accepted["mode"] != MODE
        or accepted["acceptance_class"] != ACCEPTANCE_CLASS
        or not _is_transport_id(accepted["transport_id"])
    ):
        raise ValueError("acceptance_contract_invalid")
    if (
        type(accepted["source_client"]) is not str
        or accepted["source_client"] not in SUPPORTED_CLIENTS
        or type(accepted["target_client"]) is not str
        or accepted["target_client"] not in SUPPORTED_CLIENTS
        or accepted["source_client"] == accepted["target_client"]
    ):
        raise ValueError("acceptance_clients_invalid")
    if (
        accepted["execution_authority"] != "NONE"
        or accepted["can_execute"] is not False
        or accepted["can_trade"] is not False
        or accepted["capital_permission"] != "DENY"
        or accepted["deploy_permission"] != "DENY"
    ):
        raise ValueError("acceptance_authority_not_safe")

    evidence = _require_keys(accepted["ruap_evidence"], _EVIDENCE_KEYS, "ruap_evidence")
    if (
        evidence["schema"] != RUAP_SCHEMA
        or not _is_sha256(evidence["snapshot_sha256"])
        or type(evidence["source_count"]) is not int
        or evidence["source_count"] < 0
        or type(evidence["observation_count"]) is not int
        or evidence["observation_count"] < 0
        or evidence["freshness_required"] is not True
        or evidence["authority_ceiling"] != "OBSERVE_ONLY"
        or evidence["authority_class"] != "EVIDENCE_ONLY"
    ):
        raise ValueError("ruap_evidence_contract_invalid")

    verification = _require_keys(
        accepted["verification"],
        _ACCEPTANCE_VERIFICATION_KEYS,
        "acceptance_verification",
    )
    if verification != {
        "shape_verified": True,
        "integrity_checked": True,
        "authenticity_verified": False,
        "provenance_verified": False,
        "signer_identity_verified": False,
        "current_truth_promoted": False,
    }:
        raise ValueError("acceptance_verification_not_safe")
    return accepted


def _require_registry(value: Any) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    registry = _require_keys(value, _REGISTRY_KEYS, "registry")
    if registry["schema"] != REGISTRY_SCHEMA or registry["registry_id"] != REGISTRY_ID:
        raise ValueError("registry_contract_invalid")
    keys = registry["keys"]
    if type(keys) is not list:
        raise ValueError("registry_keys_not_list")
    if len(keys) > MAX_KEYS:
        raise ValueError("registry_too_many_keys")

    normalized: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for item in keys:
        record = _require_keys(item, _KEY_RECORD_KEYS, "registry_key")
        producer_id = record["producer_id"]
        key_id = record["key_id"]
        if not _is_identifier(producer_id) or not _is_identifier(key_id):
            raise ValueError("registry_key_identifier_invalid")
        if (
            record["algorithm"] != ALGORITHM
            or record["usage"] != PURPOSE
            or type(record["state"]) is not str
            or record["state"] not in _ALLOWED_KEY_STATES
        ):
            raise ValueError("registry_key_contract_invalid")
        _decode_canonical_b64u(
            record["public_key_b64u"], expected_len=32, label="public_key"
        )
        identity = (producer_id, key_id)
        if identity in seen:
            raise ValueError("registry_duplicate_key")
        seen.add(identity)
        normalized.append(record)
    return registry, normalized


def _require_signature(value: Any) -> dict[str, Any]:
    signature = _require_keys(value, _SIGNATURE_KEYS, "signature")
    if (
        signature["schema"] != SIGNATURE_SCHEMA
        or signature["purpose"] != PURPOSE
        or signature["algorithm"] != ALGORITHM
        or not _is_identifier(signature["producer_id"])
        or not _is_identifier(signature["key_id"])
        or not _is_sha256(signature["acceptance_sha256"])
    ):
        raise ValueError("signature_contract_invalid")
    _decode_canonical_b64u(
        signature["signature_b64u"], expected_len=64, label="signature"
    )
    return signature


def _load_ed25519_backend():
    try:
        from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except (ImportError, ModuleNotFoundError) as exc:
        raise ValueError("ed25519_backend_unavailable") from exc
    return Ed25519PublicKey, InvalidSignature, UnsupportedAlgorithm


def _verify_ed25519(*, public_key: bytes, signature: bytes, message: bytes) -> None:
    Ed25519PublicKey, InvalidSignature, UnsupportedAlgorithm = _load_ed25519_backend()
    try:
        verifier = Ed25519PublicKey.from_public_bytes(public_key)
        verifier.verify(signature, message)
    except InvalidSignature as exc:
        raise ValueError("ed25519_signature_invalid") from exc
    except UnsupportedAlgorithm as exc:
        raise ValueError("ed25519_backend_unavailable") from exc
    except ValueError as exc:
        raise ValueError("ed25519_key_invalid") from exc


def _signature_message(signature: dict[str, Any]) -> bytes:
    signed_payload = {
        "schema": signature["schema"],
        "purpose": signature["purpose"],
        "producer_id": signature["producer_id"],
        "key_id": signature["key_id"],
        "algorithm": signature["algorithm"],
        "acceptance_sha256": signature["acceptance_sha256"],
    }
    return DOMAIN + _canonical_bytes(signed_payload)


def verify_cross_ai_ruap_receipt_acceptance_origin(
    *,
    accepted_receipt: Any,
    key_registry: Any,
    signature_envelope: Any,
) -> AcceptanceOriginVerification:
    try:
        accepted = _require_safe_acceptance(_snapshot(accepted_receipt))
        registry, keys = _require_registry(_snapshot(key_registry))
        signature = _require_signature(_snapshot(signature_envelope))

        acceptance_sha256 = _canonical_sha256(accepted)
        if signature["acceptance_sha256"] != acceptance_sha256:
            raise ValueError("acceptance_sha256_mismatch")

        registry_sha256 = _canonical_sha256(registry)
        if registry_sha256 != PINNED_REGISTRY_SHA256:
            raise ValueError("registry_sha256_mismatch")

        matches = [
            record
            for record in keys
            if record["producer_id"] == signature["producer_id"]
            and record["key_id"] == signature["key_id"]
        ]
        if not matches:
            raise ValueError("origin_key_not_found")
        record = matches[0]
        if record["state"] != "ACTIVE":
            raise ValueError("origin_key_not_active")
        if record["algorithm"] != signature["algorithm"] or record["usage"] != signature["purpose"]:
            raise ValueError("origin_key_binding_mismatch")

        public_key = _decode_canonical_b64u(
            record["public_key_b64u"], expected_len=32, label="public_key"
        )
        raw_signature = _decode_canonical_b64u(
            signature["signature_b64u"], expected_len=64, label="signature"
        )
        _verify_ed25519(
            public_key=public_key,
            signature=raw_signature,
            message=_signature_message(signature),
        )
        return AcceptanceOriginVerification(
            True,
            (),
            True,
            acceptance_sha256,
            registry_sha256,
            signature["producer_id"],
            signature["key_id"],
        )
    except ValueError as exc:
        return AcceptanceOriginVerification(False, (str(exc),))


def require_valid_cross_ai_ruap_receipt_acceptance_origin(
    *,
    accepted_receipt: Any,
    key_registry: Any,
    signature_envelope: Any,
) -> dict[str, Any]:
    accepted_snapshot = _snapshot(accepted_receipt)
    registry_snapshot = _snapshot(key_registry)
    signature_snapshot = _snapshot(signature_envelope)
    result = verify_cross_ai_ruap_receipt_acceptance_origin(
        accepted_receipt=accepted_snapshot,
        key_registry=registry_snapshot,
        signature_envelope=signature_snapshot,
    )
    if not result.ok:
        raise ValueError(
            "invalid Cross-AI RUAP acceptance origin: " + ",".join(result.errors)
        )
    assert type(accepted_snapshot) is dict
    return accepted_snapshot
