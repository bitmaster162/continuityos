"""Pure shared R1 acceptance-origin signing contract helpers.

This module is deliberately stdlib-only. It performs bounded plain-data copying,
closed-shape validation, deterministic canonicalization, and construction of the
frozen R1 signing message. It has no HSM, TPM, provider, network, filesystem,
subprocess, credential, runtime, deployment, trading, or capital effects.
"""
from __future__ import annotations

import base64
import hashlib
import json
from typing import Any

SIGN_REQUEST_SCHEMA = "continuityos.cross_ai_ruap_acceptance_origin_sign_request/v1"
PRODUCER_RESPONSE_SCHEMA = "continuityos.cross_ai_ruap_acceptance_origin_producer_response/v1"
PRODUCER_ID = "continuityos.cross_ai_acceptance_producer.r1"
SIGNATURE_SCHEMA = "continuityos.cross_ai_ruap_receipt_acceptance_origin_signature/v1"
PURPOSE = "CROSS_AI_RUAP_RECEIPT_ACCEPTANCE_ORIGIN"
ALGORITHM = "Ed25519"
DOMAIN = b"continuityos.cross_ai_ruap_receipt_acceptance_origin/v1\0"

ACCEPTANCE_SCHEMA = "continuityos.cross_ai_ruap_receipt_acceptance/v1"
ACCEPTANCE_MODE = "EVIDENCE_ONLY"
ACCEPTANCE_CLASS = "STRUCTURAL_SELF_CONSISTENCY_ONLY"
RUAP_SCHEMA = "ruap.snapshot/v1"
SUPPORTED_CLIENTS = frozenset({"claude", "cursor", "hermes", "generic-mcp"})

REGISTRY_SCHEMA = "continuityos.cross_ai_ruap_acceptance_origin_key_registry/v1"
REGISTRY_ID = "continuityos-cross-ai-acceptance-origin-r1"

MAX_KEYS = 32
MAX_IDENTIFIER_LEN = 96
MAX_FIELD_NAME_LEN = 128
MAX_STRING_LEN = 512
MAX_CONTAINER_ITEMS = 64
MAX_SNAPSHOT_DEPTH = 8
MAX_SNAPSHOT_NODES = 512
MAX_EVIDENCE_COUNT = 1_000_000
MAX_INTEGER_ABS = 2_147_483_647

_SIGN_REQUEST_KEYS = frozenset({"schema", "transport_receipt"})
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
_ALLOWED_KEY_STATES = frozenset({"ACTIVE", "RETIRED", "REVOKED"})


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
            out[key] = _snapshot_bounded(
                item, depth=depth + 1, _budget=_budget
            )
        return out

    if type(value) is list:
        if len(value) > MAX_CONTAINER_ITEMS:
            raise ValueError("snapshot_container_too_large")
        return [
            _snapshot_bounded(item, depth=depth + 1, _budget=_budget)
            for item in value
        ]

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


def _require_exact_keys(
    value: Any,
    expected: frozenset[str],
    label: str,
) -> dict[str, Any]:
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
            value,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
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


def _is_git_sha(value: Any) -> bool:
    return (
        type(value) is str
        and len(value) == 40
        and all(char in "0123456789abcdef" for char in value)
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


def _is_transport_id(value: Any) -> bool:
    return (
        type(value) is str
        and value.startswith("xrt_")
        and _is_sha256(value.removeprefix("xrt_"))
    )


def _canonical_b64u_length(decoded_len: int) -> int:
    return (decoded_len * 4 + 2) // 3


def _decode_canonical_b64u(
    value: Any,
    *,
    expected_len: int,
    label: str,
) -> bytes:
    expected_encoded_len = _canonical_b64u_length(expected_len)
    if (
        type(value) is not str
        or "=" in value
        or len(value) != expected_encoded_len
    ):
        raise ValueError(f"{label}_encoding_invalid")
    try:
        padding = "=" * ((4 - len(value) % 4) % 4)
        decoded = base64.b64decode(
            value + padding, altchars=b"-_", validate=True
        )
    except (ValueError, TypeError) as exc:
        raise ValueError(f"{label}_encoding_invalid") from exc
    if len(decoded) != expected_len:
        raise ValueError(f"{label}_length_invalid")
    canonical = base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii")
    if canonical != value:
        raise ValueError(f"{label}_encoding_invalid")
    return decoded


def _encode_canonical_b64u(raw: bytes) -> str:
    if type(raw) is not bytes:
        raise ValueError("base64url_input_not_bytes")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _derive_key_id(public_key: bytes) -> str:
    if type(public_key) is not bytes or len(public_key) != 32:
        raise ValueError("production_key_public_readback_invalid")
    return "ed25519-sha256:" + hashlib.sha256(public_key).hexdigest()


def _require_sign_request(value: Any) -> dict[str, Any]:
    request = _snapshot_bounded(value)
    request = _require_exact_keys(request, _SIGN_REQUEST_KEYS, "sign_request")
    if request["schema"] != SIGN_REQUEST_SCHEMA:
        raise ValueError("sign_request_schema_invalid")
    return request


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


def _require_safe_acceptance(value: Any) -> dict[str, Any]:
    accepted = _require_exact_keys(
        _snapshot_bounded(value), _ACCEPTANCE_KEYS, "acceptance"
    )
    if (
        accepted["schema"] != ACCEPTANCE_SCHEMA
        or accepted["mode"] != ACCEPTANCE_MODE
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

    evidence = _require_exact_keys(
        accepted["ruap_evidence"], _EVIDENCE_KEYS, "ruap_evidence"
    )
    source_count = evidence["source_count"]
    observation_count = evidence["observation_count"]
    if (
        evidence["schema"] != RUAP_SCHEMA
        or not _is_sha256(evidence["snapshot_sha256"])
        or type(source_count) is not int
        or not 0 <= source_count <= MAX_EVIDENCE_COUNT
        or type(observation_count) is not int
        or not 0 <= observation_count <= MAX_EVIDENCE_COUNT
        or evidence["freshness_required"] is not True
        or evidence["authority_ceiling"] != "OBSERVE_ONLY"
        or evidence["authority_class"] != "EVIDENCE_ONLY"
    ):
        raise ValueError("ruap_evidence_contract_invalid")

    verification = _require_exact_keys(
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


def _require_registry(
    value: Any,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    registry = _require_exact_keys(
        _snapshot_bounded(value), _REGISTRY_KEYS, "registry"
    )
    if (
        registry["schema"] != REGISTRY_SCHEMA
        or registry["registry_id"] != REGISTRY_ID
    ):
        raise ValueError("registry_contract_invalid")
    keys = registry["keys"]
    if type(keys) is not list:
        raise ValueError("registry_keys_not_list")
    if len(keys) > MAX_KEYS:
        raise ValueError("registry_too_many_keys")

    normalized: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    previous_identity: tuple[str, str] | None = None
    for item in keys:
        record = _require_exact_keys(
            item, _KEY_RECORD_KEYS, "registry_key"
        )
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
        public_key = _decode_canonical_b64u(
            record["public_key_b64u"],
            expected_len=32,
            label="public_key",
        )
        if key_id != _derive_key_id(public_key):
            raise ValueError("registry_key_id_public_key_mismatch")
        identity = (producer_id, key_id)
        if identity in seen:
            raise ValueError("registry_duplicate_key")
        if previous_identity is not None and identity < previous_identity:
            raise ValueError("registry_key_order_invalid")
        seen.add(identity)
        previous_identity = identity
        normalized.append(record)
    return registry, normalized


def _signature_payload(
    *,
    key_id: str,
    acceptance_sha256: str,
) -> dict[str, Any]:
    if not _is_identifier(key_id):
        raise ValueError("production_key_id_mismatch")
    if not _is_sha256(acceptance_sha256):
        raise ValueError("acceptance_sha256_invalid")
    return {
        "schema": SIGNATURE_SCHEMA,
        "purpose": PURPOSE,
        "producer_id": PRODUCER_ID,
        "key_id": key_id,
        "algorithm": ALGORITHM,
        "acceptance_sha256": acceptance_sha256,
    }


def _signature_message(
    *,
    key_id: str,
    acceptance_sha256: str,
) -> bytes:
    return DOMAIN + _canonical_bytes(
        _signature_payload(
            key_id=key_id,
            acceptance_sha256=acceptance_sha256,
        )
    )
