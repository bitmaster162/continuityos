from __future__ import annotations

from typing import Any, Mapping

from .canon import sha256_obj
from .errors import EvidenceError
from .r13 import (
    R13_PREFLIGHT_SCHEMA,
    R13_SENTINEL_SCHEMA,
    R13_VOID_SCHEMA,
    validate_model_selection_manifest,
)

R13_OPERATOR_ATTESTATION_SCHEMA = "sct.r13-operator-runtime-attestation/v1"


def _sha(value: Any, field: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(ch not in "0123456789abcdefABCDEF" for ch in value):
        raise EvidenceError(f"R13 operator attestation requires exact SHA-256 field {field}")
    return value.lower()


def validate_r13_operator_attestation(
    attestation: Mapping[str, Any],
    *,
    model_manifest: Mapping[str, Any],
    preflight: Mapping[str, Any],
    sentinel: Mapping[str, Any],
    stable_void: Mapping[str, Any],
    expected_source_sha: str,
    expected_source_tree_sha: str,
    store_verify_ok: bool,
) -> dict[str, Any]:
    if attestation.get("schema") != R13_OPERATOR_ATTESTATION_SCHEMA:
        raise EvidenceError("R13 operator attestation schema mismatch")
    model = validate_model_selection_manifest(model_manifest)
    if _sha(attestation.get("source_code_sha"), "source_code_sha") != _sha(expected_source_sha, "expected_source_sha"):
        raise EvidenceError("R13 operator attestation source commit mismatch")
    if _sha(attestation.get("source_tree_sha"), "source_tree_sha") != _sha(expected_source_tree_sha, "expected_source_tree_sha"):
        raise EvidenceError("R13 operator attestation source tree mismatch")

    if preflight.get("schema") != R13_PREFLIGHT_SCHEMA:
        raise EvidenceError("R13 operator attestation preflight receipt schema mismatch")
    if sentinel.get("schema") != R13_SENTINEL_SCHEMA:
        raise EvidenceError("R13 operator attestation sentinel receipt schema mismatch")
    if stable_void.get("schema") != R13_VOID_SCHEMA:
        raise EvidenceError("R13 operator attestation stable VOID receipt schema mismatch")

    protocol_hashes = {preflight.get("protocol_manifest_sha256"), sentinel.get("protocol_manifest_sha256"), stable_void.get("protocol_manifest_sha256")}
    model_hashes = {preflight.get("model_selection_manifest_sha256"), sentinel.get("model_selection_manifest_sha256"), stable_void.get("model_selection_manifest_sha256")}
    if len(protocol_hashes) != 1:
        raise EvidenceError("R13 operator attestation receipt protocol bindings disagree")
    if len(model_hashes) != 1 or next(iter(model_hashes)) != model["manifest_sha256"]:
        raise EvidenceError("R13 operator attestation receipt model bindings disagree")
    protocol_sha = _sha(next(iter(protocol_hashes)), "protocol_manifest_sha256")

    exact_pairs = {
        "protocol_manifest_sha256": protocol_sha,
        "model_selection_manifest_sha256": model["manifest_sha256"],
        "model_repo_or_provider_id": model["model_repo_or_provider_id"],
        "model_revision": model["model_revision"],
        "runtime_backend": model["runtime_backend"],
        "runtime_version": model["runtime_version"],
        "precision_or_quantization": model["precision_or_quantization"],
        "device_class": model["device_class"],
        "deterministic_flags": model["deterministic_flags"],
        "preflight_receipt_sha256": sha256_obj(dict(preflight)),
        "sentinel_receipt_sha256": sha256_obj(dict(sentinel)),
        "stable_void_receipt_sha256": sha256_obj(dict(stable_void)),
    }
    for field, expected in exact_pairs.items():
        if attestation.get(field) != expected:
            raise EvidenceError(f"R13 operator attestation mismatch: {field}")

    if attestation.get("weight_hashes") != model.get("weight_hashes"):
        raise EvidenceError("R13 operator attestation weight hashes mismatch")
    if attestation.get("tokenizer_hashes") != model.get("tokenizer_hashes"):
        raise EvidenceError("R13 operator attestation tokenizer hashes mismatch")

    exact_counts = {
        "planned_real_model_calls": 50,
        "observed_preflight_calls": 2,
        "observed_sentinel_calls": 18,
        "observed_stable_void_calls": 30,
    }
    for field, expected in exact_counts.items():
        value = attestation.get(field)
        if isinstance(value, bool) or not isinstance(value, int) or value != expected:
            raise EvidenceError(f"R13 operator attestation call-count mismatch: {field}")

    if int(preflight.get("attempted_calls", -1)) != 2 or int(sentinel.get("attempted_calls", -1)) != 18 or int(stable_void.get("attempted_calls", -1)) != 30:
        raise EvidenceError("R13 operator attestation receipt call counts are incomplete")
    if attestation.get("store_verify_ok") is not True or store_verify_ok is not True:
        raise EvidenceError("R13 operator attestation requires verified Evidence Store")
    if attestation.get("automatic_retry") is not False:
        raise EvidenceError("R13 operator attestation forbids automatic retry")
    if int(attestation.get("replacement_cases", -1)) != 0 or int(attestation.get("replacement_models", -1)) != 0:
        raise EvidenceError("R13 operator attestation forbids replacements")
    if int(attestation.get("valid_live_n", -1)) != 0:
        raise EvidenceError("R13 operator attestation requires valid LIVE n = 0")
    if attestation.get("execution_authority") != "NONE" or attestation.get("can_execute") is not False:
        raise EvidenceError("R13 operator attestation cannot grant execution authority")

    body = dict(attestation)
    body.pop("attestation_sha256", None)
    calculated = sha256_obj(body)
    supplied = attestation.get("attestation_sha256")
    if supplied is not None and supplied != calculated:
        raise EvidenceError("R13 operator attestation self-hash mismatch")
    return {**body, "attestation_sha256": calculated}
