"""Evidence-only RUAP projection for bounded Cross-AI transport.

This module performs deterministic in-process validation and projection only. It does
not connect to AI clients or providers and does not read credentials, connector
configuration, files, environment variables, runtime state, pointers, or memory.

Caller-controlled RUAP source/observation text is never copied into the public receipt.
Only bounded evidence metadata produced by ``import_ruap_snapshot`` is exposed.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

from .ruap_portability import import_ruap_snapshot

SCHEMA = "continuityos.cross_ai_ruap_transport/v1"
MODE = "EVIDENCE_ONLY"
TRANSPORT_MODE = "RUAP_EVIDENCE_ONLY"
SUPPORTED_CLIENTS = ("claude", "cursor", "hermes", "generic-mcp")


def _client(value: Any, field: str) -> str:
    if type(value) is not str or value not in SUPPORTED_CLIENTS:
        raise ValueError(f"{field.upper()}_UNSUPPORTED")
    return value


def _effects() -> dict[str, Any]:
    return {
        "live_connection": False,
        "provider_access": False,
        "network_effect": False,
        "subprocess_execution": False,
        "credential_access": False,
        "connector_config_read": False,
        "connector_config_write": False,
        "filesystem_read": False,
        "filesystem_write": False,
        "runtime_mutation": False,
        "pointer_mutation": False,
        "memory_mutation": False,
        "current_truth_promotion": False,
        "deployment": False,
        "trading_effect": False,
        "capital_effect": False,
    }


def _governance() -> dict[str, Any]:
    return {
        "execution_authority": "NONE",
        "can_execute": False,
        "can_trade": False,
        "capital_permission": "DENY",
        "deploy_permission": "DENY",
    }


def _canonical_bytes(value: dict[str, Any]) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")


def build_cross_ai_ruap_transport_receipt(
    *,
    source_client: str,
    target_client: str,
    ruap_snapshot: bytes | str,
) -> dict[str, Any]:
    """Project one validated RUAP snapshot into a zero-effect Cross-AI receipt."""
    source = _client(source_client, "source_client")
    target = _client(target_client, "target_client")
    if source == target:
        raise ValueError("CLIENTS_MUST_BE_DISTINCT")

    evidence = import_ruap_snapshot(ruap_snapshot)
    core = {
        "schema": SCHEMA,
        "mode": MODE,
        "transport_mode": TRANSPORT_MODE,
        "source_client": source,
        "target_client": target,
        "context_transport": "RUAP_EVIDENCE_ONLY",
        "ruap_integration": "BOUNDED_EVIDENCE_PROJECTION",
        "ruap_evidence": {
            "schema": evidence.schema,
            "snapshot_sha256": evidence.snapshot_sha256,
            "source_count": evidence.source_count,
            "observation_count": evidence.observation_count,
            "freshness_required": evidence.freshness_required,
            "authority_ceiling": evidence.authority_ceiling,
            "authority_class": evidence.authority_class,
            "raw_snapshot_exposed": False,
            "raw_sources_exposed": False,
            "raw_observations_exposed": False,
        },
        "effects": _effects(),
        **_governance(),
    }
    transport_id = "xrt_" + hashlib.sha256(_canonical_bytes(core)).hexdigest()
    return {**core, "transport_id": transport_id}


def canonical_cross_ai_ruap_transport_json(
    *,
    source_client: str,
    target_client: str,
    ruap_snapshot: bytes | str,
) -> str:
    """Return deterministic canonical JSON for one evidence-only transport receipt."""
    receipt = build_cross_ai_ruap_transport_receipt(
        source_client=source_client,
        target_client=target_client,
        ruap_snapshot=ruap_snapshot,
    )
    return json.dumps(
        receipt,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    )
