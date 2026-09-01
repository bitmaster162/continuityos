"""Synthetic-only cross-AI demo contract for ContinuityOS.

This module models a bounded handoff between two allowlisted AI client identities.
It performs no live connection, provider/network/subprocess I/O, credential access,
configuration write, runtime/pointer/memory mutation, deployment, trading, or capital
effect. RUAP transport is intentionally out of scope for this synthetic-only slice.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

from .vault_secret_reference import build_secret_reference

SCHEMA = "continuityos.cross_ai_demo/v1"
MODE = "DEMO_ONLY"
TRANSPORT_MODE = "SYNTHETIC_ONLY"
SUPPORTED_DEMO_CLIENTS = ("claude", "cursor", "hermes", "generic-mcp")


def _client(value: Any, field: str) -> str:
    if type(value) is not str or value not in SUPPORTED_DEMO_CLIENTS:
        raise ValueError(f"{field.upper()}_UNSUPPORTED")
    return value


def _effects() -> dict[str, Any]:
    return {
        "live_connection": False,
        "provider_access": False,
        "network_effect": False,
        "subprocess_execution": False,
        "credential_access": False,
        "connector_config_write": False,
        "runtime_mutation": False,
        "pointer_mutation": False,
        "memory_mutation": False,
        "deployment": False,
    }


def _governance() -> dict[str, Any]:
    return {
        "execution_authority": "NONE",
        "can_execute": False,
        "can_trade": False,
        "capital_permission": "DENY",
    }


def _canonical_bytes(value: dict[str, Any]) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")


def build_cross_ai_demo_contract(*, source_client: str, target_client: str) -> dict[str, Any]:
    """Build one deterministic synthetic cross-AI handoff receipt.

    Client identities are selected from a closed allowlist and must be distinct. The
    P6 vault reference is metadata-only with purpose ``cross_ai_demo`` and remains
    unbound. No prompt, arbitrary caller text, secret, binding locator, or provider
    session is accepted by this contract.
    """
    source = _client(source_client, "source_client")
    target = _client(target_client, "target_client")
    if source == target:
        raise ValueError("CLIENTS_MUST_BE_DISTINCT")

    reference = build_secret_reference(
        provider="unbound",
        secret_kind="credential",
        purpose_id="cross_ai_demo",
        required=False,
    )

    core = {
        "schema": SCHEMA,
        "mode": MODE,
        "transport_mode": TRANSPORT_MODE,
        "source_client": source,
        "target_client": target,
        "purpose_id": "cross_ai_demo",
        "context_transport": "NOT_IMPLEMENTED",
        "ruap_integration": "OUT_OF_SCOPE_THIS_SLICE",
        "secret_reference": {
            "reference_id": reference["reference_id"],
            "reference_id_policy": reference["reference_id_policy"],
            "purpose_id": reference["purpose_id"],
            "purpose_id_policy": reference["purpose_id_policy"],
            "provider": reference["provider"],
            "secret_kind": reference["secret_kind"],
            "required": reference["required"],
            "binding_present": reference["binding_present"],
            "binding_authorized": reference["binding_authorized"],
            "live_secret_access_available": reference["live_secret_access_available"],
        },
        "synthetic_trace": [
            "SOURCE_IDENTITY_DECLARED",
            "TARGET_IDENTITY_DECLARED",
            "SYNTHETIC_HANDOFF_MODELED",
        ],
        "effects": _effects(),
        **_governance(),
    }
    demo_id = "xad_" + hashlib.sha256(_canonical_bytes(core)).hexdigest()
    return {**core, "demo_id": demo_id}


def canonical_cross_ai_demo_json(*, source_client: str, target_client: str) -> str:
    """Return deterministic canonical JSON for one synthetic demo receipt."""
    receipt = build_cross_ai_demo_contract(
        source_client=source_client,
        target_client=target_client,
    )
    return json.dumps(
        receipt,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    )
