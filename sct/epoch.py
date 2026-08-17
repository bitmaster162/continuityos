from __future__ import annotations

from typing import Any
from .canon import sha256_obj
from .errors import EvidenceError

AMENDMENT_ID = "EPOCH_001_AMENDMENT_V2"
R12_AMENDMENT_ID = "SCT_R12_PRECASE_QUALIFICATION"
EPOCH_ID = "SCT-LIVE-EPOCH-001"


def amendment_v2_manifest(*, parent_commit: str, parent_tree: str) -> dict[str, Any]:
    body = {
        "schema": "sct.epoch-amendment/v2",
        "epoch_id": EPOCH_ID,
        "amendment_id": AMENDMENT_ID,
        "parent_commit": parent_commit,
        "parent_tree": parent_tree,
        "valid_live_n_at_amendment": 0,
        "changes": [
            "full_probability_vectors",
            "multiclass_brier_and_log_loss",
            "shared_abc_envelope",
            "payload_parity_budget",
            "pre_reveal_cluster_metadata",
            "sct_namespace_rebinding",
            "fixed_cluster_analysis_plan",
        ],
        "execution_authority": "NONE",
        "can_execute": False,
    }
    return {**body, "manifest_sha256": sha256_obj(body)}


def ensure_epoch_amended(store, manifest: dict[str, Any]) -> dict[str, Any]:
    existing = list(store.query(kind="EPOCH_AMENDED"))
    if existing:
        current = existing[-1].payload
        if current.get("manifest_sha256") != manifest.get("manifest_sha256"):
            raise EvidenceError("different epoch amendment already recorded")
        return dict(current)
    if manifest.get("valid_live_n_at_amendment") != 0:
        raise EvidenceError("epoch amendment requires valid LIVE n = 0")
    payload = {
        "epoch_id": EPOCH_ID,
        "amendment_id": AMENDMENT_ID,
        "manifest_sha256": manifest["manifest_sha256"],
        "valid_live_n": 0,
        "opportunity_ledger_entries": 0,
        "execution_authority": "NONE",
        "can_execute": False,
    }
    store.append("EPOCH_AMENDED", payload)
    return payload


def r12_precase_manifest(*, parent_commit: str, parent_tree: str, r11_receipt_sha256: str) -> dict[str, Any]:
    body = {
        "schema": "sct.precase-protocol-amendment/v1",
        "epoch_id": EPOCH_ID,
        "amendment_id": R12_AMENDMENT_ID,
        "parent_commit": parent_commit,
        "parent_tree": parent_tree,
        "r11_receipt_sha256": r11_receipt_sha256,
        "r11_gate_result": "FAIL",
        "r11_planned_cases": 20,
        "r11_completed_cases": 5,
        "r11_failed_cases": 15,
        "valid_live_n_at_amendment": 0,
        "changes": [
            "prediction_schema_v3_tie_nullable",
            "scorer_v2_unique_argmax",
            "unique_argmax_top1_tie_policy",
            "brier_skill_confirmatory_primary",
            "accuracy_and_log_loss_descriptive_secondary",
            "sign_flip_symmetry_assumption_explicit",
            "context_responsiveness_sentinel",
            "stable_single_model_void_qualification",
            "no_posthoc_probability_gap_threshold",
            "r12_scientific_pass_event",
            "case001_owner_enrollment_gate",
            "case_open_r12_admission_enforcement",
            "r12_operator_cli",
        ],
        "execution_authority": "NONE",
        "can_execute": False,
    }
    return {**body, "manifest_sha256": sha256_obj(body)}


def ensure_r12_precase_amended(store, manifest: dict[str, Any]) -> dict[str, Any]:
    existing = list(store.query(kind="PRECASE_PROTOCOL_AMENDED"))
    if existing:
        current = existing[-1].payload
        if current.get("manifest_sha256") != manifest.get("manifest_sha256"):
            raise EvidenceError("different R12 pre-Case amendment already recorded")
        return dict(current)
    if manifest.get("valid_live_n_at_amendment") != 0:
        raise EvidenceError("R12 pre-Case amendment requires valid LIVE n = 0")
    if list(store.query(kind="CASE_FROZEN")):
        raise EvidenceError("R12 pre-Case amendment must be recorded before any LIVE case is frozen")
    payload = {
        "epoch_id": EPOCH_ID,
        "amendment_id": R12_AMENDMENT_ID,
        "manifest_sha256": manifest["manifest_sha256"],
        "parent_commit": manifest["parent_commit"],
        "parent_tree": manifest["parent_tree"],
        "r11_receipt_sha256": manifest["r11_receipt_sha256"],
        "valid_live_n": 0,
        "execution_authority": "NONE",
        "can_execute": False,
    }
    store.append("PRECASE_PROTOCOL_AMENDED", payload)
    return payload
