"""Bind one external authenticity assertion to an accepted Cross-AI RUAP receipt.

This module performs deterministic in-process binding only. The external assertion is
treated as untrusted evidence. Binding proves only that its bounded target metadata
matches one already accepted transport receipt and that deterministic digests were
computed over plain-data snapshots.

It does not verify a signature, key, signer identity, provider attestation, trusted
provenance, authorship, or origin, and it never promotes evidence into current truth.
No provider, network, credential, connector configuration, filesystem, environment,
runtime, pointer, memory, subprocess, deployment, trading, or capital effects occur.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any


SCHEMA = "continuityos.cross_ai_ruap_receipt_authenticity_assertion_binding/v1"
MODE = "EVIDENCE_ONLY"
BINDING_CLASS = "EXTERNAL_ASSERTION_BINDING_ONLY"

ACCEPTANCE_SCHEMA = "continuityos.cross_ai_ruap_receipt_acceptance/v1"
ACCEPTANCE_CLASS = "STRUCTURAL_SELF_CONSISTENCY_ONLY"
ASSERTION_SCHEMA = "continuityos.cross_ai_ruap_external_authenticity_assertion/v1"
RUAP_SNAPSHOT_SCHEMA = "ruap.snapshot/v1"

SUPPORTED_CLIENTS = ("claude", "cursor", "hermes", "generic-mcp")
SUPPORTED_ASSERTION_METHODS = (
    "DETACHED_SIGNATURE_EVIDENCE",
    "PROVIDER_ATTESTATION_EVIDENCE",
    "MANUAL_ATTESTATION_EVIDENCE",
)

_ACCEPTANCE_KEYS = {
    "schema",
    "mode",
    "acceptance_class",
    "transport_id",
    "source_client",
    "target_client",
    "ruap_evidence",
    "verification",
    "execution_authority",
    "can_execute",
    "can_trade",
    "capital_permission",
    "deploy_permission",
}
_RUAP_EVIDENCE_KEYS = {
    "schema",
    "snapshot_sha256",
    "source_count",
    "observation_count",
    "freshness_required",
    "authority_ceiling",
    "authority_class",
}
_ACCEPTANCE_VERIFICATION_KEYS = {
    "shape_verified",
    "integrity_checked",
    "authenticity_verified",
    "provenance_verified",
    "signer_identity_verified",
    "current_truth_promoted",
}
_ASSERTION_KEYS = {
    "schema",
    "mode",
    "assertion_method",
    "transport_id",
    "source_client",
    "target_client",
    "ruap_snapshot_sha256",
    "claims",
}
_ASSERTION_CLAIM_KEYS = {
    "authenticity_claimed",
    "provenance_claimed",
    "signer_identity_claimed",
}


def _snapshot_plain_data(value: Any, *, depth: int = 0) -> Any:
    """Copy bounded dict/primitive data without retaining caller-owned containers."""
    if type(value) is dict:
        if depth >= 2:
            raise ValueError("invalid assertion binding input: nested_too_deep")
        snapshot: dict[str, Any] = {}
        for key, item in value.items():
            if type(key) is not str:
                raise ValueError("invalid assertion binding input: non_string_key")
            snapshot[key] = _snapshot_plain_data(item, depth=depth + 1)
        return snapshot
    if type(value) in (str, bool, int):
        return value
    raise ValueError("invalid assertion binding input: non_plain_value")


def _canonical_bytes(value: dict[str, Any]) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")


def _is_sha256(value: Any) -> bool:
    if type(value) is not str or len(value) != 64:
        return False
    return all(character in "0123456789abcdef" for character in value)


def _is_transport_id(value: Any) -> bool:
    return (
        type(value) is str
        and value.startswith("xrt_")
        and _is_sha256(value.removeprefix("xrt_"))
    )


def _require_exact_keys(value: Any, expected: set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != expected:
        raise ValueError(f"invalid assertion binding input: {label}_shape")
    return value


def _require_safe_acceptance(receipt: Any) -> dict[str, Any]:
    accepted = _require_exact_keys(receipt, _ACCEPTANCE_KEYS, "acceptance")

    if (
        accepted["schema"] != ACCEPTANCE_SCHEMA
        or accepted["mode"] != MODE
        or accepted["acceptance_class"] != ACCEPTANCE_CLASS
    ):
        raise ValueError("invalid assertion binding input: acceptance_contract")
    if not _is_transport_id(accepted["transport_id"]):
        raise ValueError("invalid assertion binding input: transport_id")
    if (
        type(accepted["source_client"]) is not str
        or accepted["source_client"] not in SUPPORTED_CLIENTS
        or type(accepted["target_client"]) is not str
        or accepted["target_client"] not in SUPPORTED_CLIENTS
        or accepted["source_client"] == accepted["target_client"]
    ):
        raise ValueError("invalid assertion binding input: clients")

    evidence = _require_exact_keys(
        accepted["ruap_evidence"], _RUAP_EVIDENCE_KEYS, "ruap_evidence"
    )
    if (
        evidence["schema"] != RUAP_SNAPSHOT_SCHEMA
        or not _is_sha256(evidence["snapshot_sha256"])
        or type(evidence["source_count"]) is not int
        or evidence["source_count"] < 0
        or type(evidence["observation_count"]) is not int
        or evidence["observation_count"] < 0
        or evidence["freshness_required"] is not True
        or evidence["authority_ceiling"] != "OBSERVE_ONLY"
        or evidence["authority_class"] != "EVIDENCE_ONLY"
    ):
        raise ValueError("invalid assertion binding input: ruap_evidence_contract")

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
        raise ValueError("invalid assertion binding input: acceptance_verification")

    if (
        accepted["execution_authority"] != "NONE"
        or accepted["can_execute"] is not False
        or accepted["can_trade"] is not False
        or accepted["capital_permission"] != "DENY"
        or accepted["deploy_permission"] != "DENY"
    ):
        raise ValueError("invalid assertion binding input: acceptance_authority")

    return accepted


def _require_bound_assertion(
    assertion: Any, *, accepted: dict[str, Any]
) -> dict[str, Any]:
    external = _require_exact_keys(assertion, _ASSERTION_KEYS, "external_assertion")
    if (
        external["schema"] != ASSERTION_SCHEMA
        or external["mode"] != MODE
        or external["assertion_method"] not in SUPPORTED_ASSERTION_METHODS
    ):
        raise ValueError("invalid assertion binding input: assertion_contract")

    if (
        external["transport_id"] != accepted["transport_id"]
        or external["source_client"] != accepted["source_client"]
        or external["target_client"] != accepted["target_client"]
        or external["ruap_snapshot_sha256"]
        != accepted["ruap_evidence"]["snapshot_sha256"]
    ):
        raise ValueError("invalid assertion binding input: assertion_target_mismatch")

    claims = _require_exact_keys(external["claims"], _ASSERTION_CLAIM_KEYS, "claims")
    if any(type(value) is not bool for value in claims.values()):
        raise ValueError("invalid assertion binding input: claim_type")
    if not any(claims.values()):
        raise ValueError("invalid assertion binding input: no_claim")

    return external


def bind_cross_ai_ruap_receipt_authenticity_assertion(
    *,
    accepted_receipt: Any,
    external_assertion: Any,
) -> dict[str, Any]:
    """Bind one untrusted external assertion to one accepted evidence-only receipt."""
    accepted_snapshot = _snapshot_plain_data(accepted_receipt)
    assertion_snapshot = _snapshot_plain_data(external_assertion)

    accepted = _require_safe_acceptance(accepted_snapshot)
    assertion = _require_bound_assertion(assertion_snapshot, accepted=accepted)

    acceptance_sha256 = hashlib.sha256(_canonical_bytes(accepted)).hexdigest()
    assertion_sha256 = hashlib.sha256(_canonical_bytes(assertion)).hexdigest()

    return {
        "schema": SCHEMA,
        "mode": MODE,
        "binding_class": BINDING_CLASS,
        "transport_id": accepted["transport_id"],
        "source_client": accepted["source_client"],
        "target_client": accepted["target_client"],
        "ruap_snapshot_sha256": accepted["ruap_evidence"]["snapshot_sha256"],
        "acceptance_sha256": acceptance_sha256,
        "external_assertion": {
            "schema": assertion["schema"],
            "assertion_method": assertion["assertion_method"],
            "assertion_sha256": assertion_sha256,
            "claims": dict(assertion["claims"]),
        },
        "verification": {
            "acceptance_shape_verified": True,
            "assertion_shape_verified": True,
            "transport_binding_verified": True,
            "client_binding_verified": True,
            "ruap_evidence_binding_verified": True,
            "assertion_digest_bound": True,
            "authenticity_verified": False,
            "provenance_verified": False,
            "signer_identity_verified": False,
            "current_truth_promoted": False,
        },
        "execution_authority": "NONE",
        "can_execute": False,
        "can_trade": False,
        "capital_permission": "DENY",
        "deploy_permission": "DENY",
    }
