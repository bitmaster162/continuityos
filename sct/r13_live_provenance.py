from __future__ import annotations

import json
from typing import Any, Mapping, Sequence

from .baseline_r13 import ARM_B_BUILDER_SCHEMA, baseline_policy_hashes, build_arm_b_profile_rag
from .canon import canonical_json, sha256_obj
from .errors import EvidenceError

R13_ARM_B_LIVE_PROVENANCE_SCHEMA = "sct.r13-arm-b-live-provenance/v1"
R13_ARM_B_LIVE_PROVENANCE_EVENT = "R13_ARM_B_LIVE_PROVENANCE_VERIFIED"


def _sha256(value: Any, field: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(ch not in "0123456789abcdefABCDEF" for ch in value):
        raise EvidenceError(f"R13 Arm B LIVE provenance requires exact SHA-256 field {field}")
    return value.lower()


def _clean_options(options: Sequence[Any]) -> tuple[str, ...]:
    out = tuple(dict.fromkeys(str(x).strip() for x in options if str(x).strip()))
    if len(out) < 2:
        raise EvidenceError("R13 Arm B LIVE provenance requires at least two options")
    return out


def _combined_context(builder_output: Mapping[str, Any]) -> str:
    static_profile = str(builder_output.get("static_profile") or "")
    permitted_history = str(builder_output.get("permitted_history") or "")
    if not static_profile or not permitted_history:
        raise EvidenceError("R13 Arm B LIVE provenance requires non-empty frozen profile and retrieval history")
    return static_profile + "\n" + permitted_history


def build_arm_b_live_provenance_receipt(
    *,
    case_id: str,
    scenario: str,
    options: Sequence[str],
    evidence_rows: Sequence[Mapping[str, Any]],
    evidence_blob_sha256: str,
    source_cutoff: float,
    target_context_bytes: int,
    expected_admitted_pool_sha256: str,
    builder_output: Mapping[str, Any],
    profile_rag_snapshot_sha256: str,
    baseline_manifest_sha256: str,
) -> dict[str, Any]:
    clean_case_id = str(case_id).strip()
    clean_scenario = str(scenario).strip()
    clean_options = _clean_options(options)
    if not clean_case_id or not clean_scenario:
        raise EvidenceError("R13 Arm B LIVE provenance requires case_id and scenario")
    if builder_output.get("schema") != ARM_B_BUILDER_SCHEMA:
        raise EvidenceError("R13 Arm B LIVE provenance builder schema mismatch")

    expected_pool = _sha256(expected_admitted_pool_sha256, "expected_admitted_pool_sha256")
    blob_sha = _sha256(evidence_blob_sha256, "evidence_blob_sha256")
    snapshot_sha = _sha256(profile_rag_snapshot_sha256, "profile_rag_snapshot_sha256")
    baseline_sha = _sha256(baseline_manifest_sha256, "baseline_manifest_sha256")

    combined = _combined_context(builder_output)
    body = {
        "schema": R13_ARM_B_LIVE_PROVENANCE_SCHEMA,
        "case_id": clean_case_id,
        "scenario": clean_scenario,
        "options": clean_options,
        "evidence_blob_sha256": blob_sha,
        "evidence_rows_sha256": sha256_obj(list(evidence_rows)),
        "source_cutoff": float(source_cutoff),
        "target_context_bytes": int(target_context_bytes),
        "expected_admitted_pool_sha256": expected_pool,
        "builder_output": dict(builder_output),
        "builder_output_sha256": sha256_obj(dict(builder_output)),
        "profile_rag_payload_sha256": sha256_obj(combined),
        "profile_rag_snapshot_sha256": snapshot_sha,
        "baseline_manifest_sha256": baseline_sha,
        "policy_hashes": baseline_policy_hashes(),
        "can_execute": False,
        "execution_authority": "NONE",
    }
    return {**body, "receipt_sha256": sha256_obj(body)}


def validate_arm_b_live_provenance_receipt(
    receipt: Mapping[str, Any],
    *,
    evidence_blob: bytes,
    sealed_baseline: Mapping[str, Any],
) -> dict[str, Any]:
    if receipt.get("schema") != R13_ARM_B_LIVE_PROVENANCE_SCHEMA:
        raise EvidenceError("R13 Arm B LIVE provenance schema mismatch")
    if receipt.get("execution_authority") != "NONE" or receipt.get("can_execute") is not False:
        raise EvidenceError("R13 Arm B LIVE provenance cannot grant execution authority")

    case_id = str(receipt.get("case_id") or "").strip()
    scenario = str(receipt.get("scenario") or "").strip()
    options = _clean_options(receipt.get("options") or ())
    if not case_id or not scenario:
        raise EvidenceError("R13 Arm B LIVE provenance case/scenario missing")

    blob_sha = _sha256(receipt.get("evidence_blob_sha256"), "evidence_blob_sha256")
    if sha256_obj(evidence_blob.decode("utf-8")) == blob_sha:
        # sha256_obj hashes canonical JSON strings, while EvidenceStore blob IDs hash raw bytes.
        # This branch is deliberately not used as the blob identity check below.
        pass
    import hashlib
    if hashlib.sha256(evidence_blob).hexdigest() != blob_sha:
        raise EvidenceError("R13 Arm B LIVE provenance evidence blob SHA-256 mismatch")

    try:
        rows = json.loads(evidence_blob.decode("utf-8"))
    except Exception as exc:
        raise EvidenceError("R13 Arm B LIVE provenance evidence blob is not JSON") from exc
    if not isinstance(rows, list) or not all(isinstance(row, Mapping) for row in rows):
        raise EvidenceError("R13 Arm B LIVE provenance evidence blob must contain a JSON array of objects")
    if receipt.get("evidence_rows_sha256") != sha256_obj(rows):
        raise EvidenceError("R13 Arm B LIVE provenance evidence row hash mismatch")

    baseline_sha = _sha256(receipt.get("baseline_manifest_sha256"), "baseline_manifest_sha256")
    if sealed_baseline.get("baseline_manifest_sha256") != baseline_sha:
        raise EvidenceError("R13 Arm B LIVE provenance sealed baseline binding mismatch")

    expected_policy = baseline_policy_hashes()
    if receipt.get("policy_hashes") != expected_policy:
        raise EvidenceError("R13 Arm B LIVE provenance policy hash mismatch")
    for field, expected in expected_policy.items():
        if sealed_baseline.get(field) != expected:
            raise EvidenceError(f"R13 Arm B LIVE provenance sealed baseline policy mismatch: {field}")

    expected_pool = _sha256(receipt.get("expected_admitted_pool_sha256"), "expected_admitted_pool_sha256")
    rebuilt = build_arm_b_profile_rag(
        scenario=scenario,
        options=options,
        evidence_rows=rows,
        source_cutoff=float(receipt.get("source_cutoff")),
        target_context_bytes=int(receipt.get("target_context_bytes")),
        expected_admitted_pool_sha256=expected_pool,
    )
    supplied_builder = receipt.get("builder_output")
    if not isinstance(supplied_builder, Mapping) or dict(supplied_builder) != rebuilt:
        raise EvidenceError("R13 Arm B LIVE provenance builder replay mismatch")
    if receipt.get("builder_output_sha256") != sha256_obj(rebuilt):
        raise EvidenceError("R13 Arm B LIVE provenance builder output SHA-256 mismatch")

    combined = _combined_context(rebuilt)
    payload_sha = sha256_obj(combined)
    if receipt.get("profile_rag_payload_sha256") != payload_sha:
        raise EvidenceError("R13 Arm B LIVE provenance profile_rag payload SHA-256 mismatch")
    _sha256(receipt.get("profile_rag_snapshot_sha256"), "profile_rag_snapshot_sha256")

    body = dict(receipt)
    supplied_receipt_sha = body.pop("receipt_sha256", None)
    calculated_receipt_sha = sha256_obj(body)
    if supplied_receipt_sha != calculated_receipt_sha:
        raise EvidenceError("R13 Arm B LIVE provenance receipt self-hash mismatch")
    return {**body, "receipt_sha256": calculated_receipt_sha}


def canonical_evidence_blob(evidence_rows: Sequence[Mapping[str, Any]]) -> bytes:
    return canonical_json(list(evidence_rows)).encode("utf-8")
