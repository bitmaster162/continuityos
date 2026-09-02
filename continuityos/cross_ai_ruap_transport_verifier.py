"""Pure verifier for bounded Cross-AI RUAP transport receipts.

The verifier accepts only the closed receipt shape emitted by the evidence-only
transport slice. It performs deterministic in-process structural and integrity
checks only. It does not read RUAP snapshots, files, credentials, connector
configuration, environment variables, runtime state, pointers, or memory, and it
does not perform provider/network/subprocess/deployment/trading/capital effects.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Any


SCHEMA = "continuityos.cross_ai_ruap_transport/v1"
MODE = "EVIDENCE_ONLY"
TRANSPORT_MODE = "RUAP_EVIDENCE_ONLY"
CONTEXT_TRANSPORT = "RUAP_EVIDENCE_ONLY"
RUAP_INTEGRATION = "BOUNDED_EVIDENCE_PROJECTION"
RUAP_SCHEMA = "ruap.snapshot/v1"
AUTHORITY_CEILING = "OBSERVE_ONLY"
AUTHORITY_CLASS = "EVIDENCE_ONLY"
SUPPORTED_CLIENTS = ("claude", "cursor", "hermes", "generic-mcp")

_CORE_KEYS = frozenset(
    {
        "schema",
        "mode",
        "transport_mode",
        "source_client",
        "target_client",
        "context_transport",
        "ruap_integration",
        "ruap_evidence",
        "effects",
        "execution_authority",
        "can_execute",
        "can_trade",
        "capital_permission",
        "deploy_permission",
    }
)
_TOP_LEVEL_KEYS = _CORE_KEYS | {"transport_id"}
_EVIDENCE_KEYS = frozenset(
    {
        "schema",
        "snapshot_sha256",
        "source_count",
        "observation_count",
        "freshness_required",
        "authority_ceiling",
        "authority_class",
        "raw_snapshot_exposed",
        "raw_sources_exposed",
        "raw_observations_exposed",
    }
)
_EFFECT_KEYS = frozenset(
    {
        "live_connection",
        "provider_access",
        "network_effect",
        "subprocess_execution",
        "credential_access",
        "connector_config_read",
        "connector_config_write",
        "filesystem_read",
        "filesystem_write",
        "runtime_mutation",
        "pointer_mutation",
        "memory_mutation",
        "current_truth_promotion",
        "deployment",
        "trading_effect",
        "capital_effect",
    }
)


@dataclass(frozen=True)
class TransportReceiptVerification:
    ok: bool
    errors: tuple[str, ...]
    expected_transport_id: str | None = None


def _canonical_bytes(value: dict[str, Any]) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")


def _is_sha256(value: Any) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(char in "0123456789abcdef" for char in value)
    )


def _exact_keys(
    value: dict[str, Any],
    expected: frozenset[str],
    prefix: str,
    errors: list[str],
) -> None:
    actual = frozenset(value)
    for key in sorted(expected - actual):
        errors.append(f"{prefix}_missing_key:{key}")
    for key in sorted(actual - expected):
        errors.append(f"{prefix}_unknown_key:{key}")


def verify_cross_ai_ruap_transport_receipt(receipt: Any) -> TransportReceiptVerification:
    """Verify one public RUAP transport receipt without reading the raw snapshot."""
    errors: list[str] = []
    if type(receipt) is not dict:
        return TransportReceiptVerification(False, ("receipt_not_plain_object",), None)

    _exact_keys(receipt, _TOP_LEVEL_KEYS, "receipt", errors)
    if errors:
        return TransportReceiptVerification(False, tuple(errors), None)

    exact_text = {
        "schema": SCHEMA,
        "mode": MODE,
        "transport_mode": TRANSPORT_MODE,
        "context_transport": CONTEXT_TRANSPORT,
        "ruap_integration": RUAP_INTEGRATION,
        "execution_authority": "NONE",
        "capital_permission": "DENY",
        "deploy_permission": "DENY",
    }
    for key, expected in exact_text.items():
        value = receipt[key]
        if type(value) is not str or value != expected:
            errors.append(f"receipt_invalid_value:{key}")

    source = receipt["source_client"]
    target = receipt["target_client"]
    if type(source) is not str or source not in SUPPORTED_CLIENTS:
        errors.append("receipt_invalid_source_client")
    if type(target) is not str or target not in SUPPORTED_CLIENTS:
        errors.append("receipt_invalid_target_client")
    if type(source) is str and type(target) is str and source == target:
        errors.append("receipt_clients_not_distinct")

    for key in ("can_execute", "can_trade"):
        if type(receipt[key]) is not bool or receipt[key] is not False:
            errors.append(f"receipt_authority_not_safe:{key}")

    evidence = receipt["ruap_evidence"]
    if type(evidence) is not dict:
        errors.append("ruap_evidence_not_plain_object")
    else:
        evidence_key_errors_before = len(errors)
        _exact_keys(evidence, _EVIDENCE_KEYS, "ruap_evidence", errors)
        if len(errors) == evidence_key_errors_before:
            evidence_text = {
                "schema": RUAP_SCHEMA,
                "authority_ceiling": AUTHORITY_CEILING,
                "authority_class": AUTHORITY_CLASS,
            }
            for key, expected in evidence_text.items():
                value = evidence[key]
                if type(value) is not str or value != expected:
                    errors.append(f"ruap_evidence_invalid_value:{key}")

            if not _is_sha256(evidence["snapshot_sha256"]):
                errors.append("ruap_evidence_invalid_snapshot_sha256")
            for key in ("source_count", "observation_count"):
                value = evidence[key]
                if type(value) is not int or value < 0:
                    errors.append(f"ruap_evidence_invalid_count:{key}")
            if type(evidence["freshness_required"]) is not bool:
                errors.append("ruap_evidence_invalid_freshness_required")
            for key in (
                "raw_snapshot_exposed",
                "raw_sources_exposed",
                "raw_observations_exposed",
            ):
                if type(evidence[key]) is not bool or evidence[key] is not False:
                    errors.append(f"ruap_evidence_raw_exposure_not_false:{key}")

    effects = receipt["effects"]
    if type(effects) is not dict:
        errors.append("effects_not_plain_object")
    else:
        effect_key_errors_before = len(errors)
        _exact_keys(effects, _EFFECT_KEYS, "effects", errors)
        if len(errors) == effect_key_errors_before:
            for key in sorted(_EFFECT_KEYS):
                if type(effects[key]) is not bool or effects[key] is not False:
                    errors.append(f"effect_not_false:{key}")

    if errors:
        return TransportReceiptVerification(False, tuple(errors), None)

    core = {key: receipt[key] for key in _CORE_KEYS}
    expected_transport_id = "xrt_" + hashlib.sha256(_canonical_bytes(core)).hexdigest()
    transport_id = receipt["transport_id"]
    if type(transport_id) is not str or transport_id != expected_transport_id:
        errors.append("transport_id_mismatch")

    return TransportReceiptVerification(
        not errors,
        tuple(errors),
        expected_transport_id,
    )


def require_valid_cross_ai_ruap_transport_receipt(receipt: Any) -> dict[str, Any]:
    """Return the verified receipt or fail closed with a bounded error."""
    verification = verify_cross_ai_ruap_transport_receipt(receipt)
    if not verification.ok:
        raise ValueError(
            "invalid Cross-AI RUAP transport receipt: " + ",".join(verification.errors)
        )
    assert type(receipt) is dict
    return receipt
