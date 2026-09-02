"""Independent structural verifier for Cross-AI RUAP assertion bindings.

The verifier consumes caller-supplied binding, acceptance-shaped evidence, and
external assertion objects. It snapshots bounded plain data, validates closed
shapes and safe authority values, recomputes the two deterministic SHA-256
bindings, and checks exact transport/client/RUAP target equality.

This does not prove acceptance origin, signature validity, signer identity,
provider attestation, trusted provenance, authorship, or authenticity. It never
promotes current truth and performs no provider/network/credential/config/file/
environment/runtime/pointer/memory/subprocess/deploy/trading/capital effects.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Any

BINDING_SCHEMA = "continuityos.cross_ai_ruap_receipt_authenticity_assertion_binding/v1"
MODE = "EVIDENCE_ONLY"
BINDING_CLASS = "EXTERNAL_ASSERTION_BINDING_ONLY"
ACCEPTANCE_INPUT_CLASS = "CALLER_SUPPLIED_ACCEPTANCE_SHAPED_EVIDENCE"
ACCEPTANCE_SCHEMA = "continuityos.cross_ai_ruap_receipt_acceptance/v1"
ACCEPTANCE_CLASS = "STRUCTURAL_SELF_CONSISTENCY_ONLY"
ASSERTION_SCHEMA = "continuityos.cross_ai_ruap_external_authenticity_assertion/v1"
RUAP_SCHEMA = "ruap.snapshot/v1"
SUPPORTED_CLIENTS = ("claude", "cursor", "hermes", "generic-mcp")
SUPPORTED_METHODS = (
    "DETACHED_SIGNATURE_EVIDENCE",
    "PROVIDER_ATTESTATION_EVIDENCE",
    "MANUAL_ATTESTATION_EVIDENCE",
)

_ACCEPTANCE_KEYS = frozenset({
    "schema","mode","acceptance_class","transport_id","source_client","target_client",
    "ruap_evidence","verification","execution_authority","can_execute","can_trade",
    "capital_permission","deploy_permission",
})
_EVIDENCE_KEYS = frozenset({
    "schema","snapshot_sha256","source_count","observation_count","freshness_required",
    "authority_ceiling","authority_class",
})
_ACCEPTANCE_VERIFICATION_KEYS = frozenset({
    "shape_verified","integrity_checked","authenticity_verified","provenance_verified",
    "signer_identity_verified","current_truth_promoted",
})
_ASSERTION_KEYS = frozenset({
    "schema","mode","assertion_method","transport_id","source_client","target_client",
    "ruap_snapshot_sha256","claims",
})
_CLAIM_KEYS = frozenset({
    "authenticity_claimed","provenance_claimed","signer_identity_claimed",
})
_BINDING_KEYS = frozenset({
    "schema","mode","binding_class","acceptance_input_class","transport_id",
    "source_client","target_client","ruap_snapshot_sha256","acceptance_sha256",
    "external_assertion","verification","execution_authority","can_execute","can_trade",
    "capital_permission","deploy_permission",
})
_PROJECTED_ASSERTION_KEYS = frozenset({
    "schema","assertion_method","assertion_sha256","claims",
})
_BINDING_VERIFICATION_KEYS = frozenset({
    "acceptance_shape_verified","acceptance_origin_verified","assertion_shape_verified",
    "transport_binding_verified","client_binding_verified",
    "ruap_evidence_binding_verified","assertion_digest_bound","authenticity_verified",
    "provenance_verified","signer_identity_verified","current_truth_promoted",
})


@dataclass(frozen=True)
class AssertionBindingVerification:
    ok: bool
    errors: tuple[str, ...]
    expected_acceptance_sha256: str | None = None
    expected_assertion_sha256: str | None = None


def _snapshot(value: Any, *, depth: int = 0) -> Any:
    if type(value) is dict:
        if depth >= 3:
            raise ValueError("nested_too_deep")
        out: dict[str, Any] = {}
        for key, item in value.items():
            if type(key) is not str:
                raise ValueError("non_string_key")
            out[key] = _snapshot(item, depth=depth + 1)
        return out
    if type(value) in (str, bool, int):
        return value
    raise ValueError("non_plain_value")


def _canonical_sha256(value: dict[str, Any]) -> str:
    payload = json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    ).encode("ascii")
    return hashlib.sha256(payload).hexdigest()


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


def _require_safe_authority(value: dict[str, Any], label: str) -> None:
    if (
        value["execution_authority"] != "NONE"
        or value["can_execute"] is not False
        or value["can_trade"] is not False
        or value["capital_permission"] != "DENY"
        or value["deploy_permission"] != "DENY"
    ):
        raise ValueError(f"{label}_authority_not_safe")


def _require_acceptance(value: Any) -> dict[str, Any]:
    accepted = _require_keys(value, _ACCEPTANCE_KEYS, "acceptance")
    if (
        accepted["schema"] != ACCEPTANCE_SCHEMA
        or accepted["mode"] != MODE
        or accepted["acceptance_class"] != ACCEPTANCE_CLASS
        or not _is_transport_id(accepted["transport_id"])
    ):
        raise ValueError("acceptance_contract_invalid")
    source = accepted["source_client"]
    target = accepted["target_client"]
    if (
        type(source) is not str or source not in SUPPORTED_CLIENTS
        or type(target) is not str or target not in SUPPORTED_CLIENTS
        or source == target
    ):
        raise ValueError("acceptance_clients_invalid")
    _require_safe_authority(accepted, "acceptance")

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
        accepted["verification"], _ACCEPTANCE_VERIFICATION_KEYS, "acceptance_verification"
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


def _require_assertion(value: Any, accepted: dict[str, Any]) -> dict[str, Any]:
    assertion = _require_keys(value, _ASSERTION_KEYS, "assertion")
    if (
        assertion["schema"] != ASSERTION_SCHEMA
        or assertion["mode"] != MODE
        or assertion["assertion_method"] not in SUPPORTED_METHODS
        or not _is_transport_id(assertion["transport_id"])
        or not _is_sha256(assertion["ruap_snapshot_sha256"])
    ):
        raise ValueError("assertion_contract_invalid")
    source = assertion["source_client"]
    target = assertion["target_client"]
    if (
        type(source) is not str or source not in SUPPORTED_CLIENTS
        or type(target) is not str or target not in SUPPORTED_CLIENTS
        or source == target
    ):
        raise ValueError("assertion_clients_invalid")
    claims = _require_keys(assertion["claims"], _CLAIM_KEYS, "assertion_claims")
    if any(type(item) is not bool for item in claims.values()) or not any(claims.values()):
        raise ValueError("assertion_claims_invalid")
    if (
        assertion["transport_id"] != accepted["transport_id"]
        or source != accepted["source_client"]
        or target != accepted["target_client"]
        or assertion["ruap_snapshot_sha256"]
        != accepted["ruap_evidence"]["snapshot_sha256"]
    ):
        raise ValueError("assertion_target_mismatch")
    return assertion


def _require_binding(value: Any) -> dict[str, Any]:
    binding = _require_keys(value, _BINDING_KEYS, "binding")
    if (
        binding["schema"] != BINDING_SCHEMA
        or binding["mode"] != MODE
        or binding["binding_class"] != BINDING_CLASS
        or binding["acceptance_input_class"] != ACCEPTANCE_INPUT_CLASS
        or not _is_transport_id(binding["transport_id"])
        or not _is_sha256(binding["ruap_snapshot_sha256"])
        or not _is_sha256(binding["acceptance_sha256"])
    ):
        raise ValueError("binding_contract_invalid")
    source = binding["source_client"]
    target = binding["target_client"]
    if (
        type(source) is not str or source not in SUPPORTED_CLIENTS
        or type(target) is not str or target not in SUPPORTED_CLIENTS
        or source == target
    ):
        raise ValueError("binding_clients_invalid")
    _require_safe_authority(binding, "binding")

    projected = _require_keys(
        binding["external_assertion"], _PROJECTED_ASSERTION_KEYS, "projected_assertion"
    )
    if (
        projected["schema"] != ASSERTION_SCHEMA
        or projected["assertion_method"] not in SUPPORTED_METHODS
        or not _is_sha256(projected["assertion_sha256"])
    ):
        raise ValueError("projected_assertion_contract_invalid")
    claims = _require_keys(projected["claims"], _CLAIM_KEYS, "projected_claims")
    if any(type(item) is not bool for item in claims.values()) or not any(claims.values()):
        raise ValueError("projected_claims_invalid")

    verification = _require_keys(
        binding["verification"], _BINDING_VERIFICATION_KEYS, "binding_verification"
    )
    if verification != {
        "acceptance_shape_verified": True,
        "acceptance_origin_verified": False,
        "assertion_shape_verified": True,
        "transport_binding_verified": True,
        "client_binding_verified": True,
        "ruap_evidence_binding_verified": True,
        "assertion_digest_bound": True,
        "authenticity_verified": False,
        "provenance_verified": False,
        "signer_identity_verified": False,
        "current_truth_promoted": False,
    }:
        raise ValueError("binding_verification_not_safe")
    return binding


def verify_cross_ai_ruap_receipt_authenticity_assertion_binding(
    *,
    binding_result: Any,
    accepted_receipt: Any,
    external_assertion: Any,
) -> AssertionBindingVerification:
    try:
        binding = _require_binding(_snapshot(binding_result))
        accepted = _require_acceptance(_snapshot(accepted_receipt))
        assertion = _require_assertion(_snapshot(external_assertion), accepted)

        expected_acceptance = _canonical_sha256(accepted)
        expected_assertion = _canonical_sha256(assertion)
        projected = binding["external_assertion"]
        if binding["transport_id"] != accepted["transport_id"]:
            raise ValueError("binding_transport_id_mismatch")
        if (
            binding["source_client"] != accepted["source_client"]
            or binding["target_client"] != accepted["target_client"]
        ):
            raise ValueError("binding_client_mismatch")
        if (
            binding["ruap_snapshot_sha256"]
            != accepted["ruap_evidence"]["snapshot_sha256"]
        ):
            raise ValueError("binding_ruap_snapshot_sha256_mismatch")
        if binding["acceptance_sha256"] != expected_acceptance:
            raise ValueError("acceptance_sha256_mismatch")
        if projected["assertion_sha256"] != expected_assertion:
            raise ValueError("assertion_sha256_mismatch")
        if projected["schema"] != assertion["schema"]:
            raise ValueError("projected_assertion_schema_mismatch")
        if projected["assertion_method"] != assertion["assertion_method"]:
            raise ValueError("projected_assertion_method_mismatch")
        if projected["claims"] != assertion["claims"]:
            raise ValueError("projected_assertion_claims_mismatch")
        return AssertionBindingVerification(
            True, (), expected_acceptance, expected_assertion
        )
    except ValueError as exc:
        return AssertionBindingVerification(False, (str(exc),), None, None)


def require_valid_cross_ai_ruap_receipt_authenticity_assertion_binding(
    *,
    binding_result: Any,
    accepted_receipt: Any,
    external_assertion: Any,
) -> dict[str, Any]:
    result = verify_cross_ai_ruap_receipt_authenticity_assertion_binding(
        binding_result=binding_result,
        accepted_receipt=accepted_receipt,
        external_assertion=external_assertion,
    )
    if not result.ok:
        raise ValueError(
            "invalid Cross-AI RUAP authenticity assertion binding: "
            + ",".join(result.errors)
        )
    snapshot = _snapshot(binding_result)
    assert type(snapshot) is dict
    return snapshot
