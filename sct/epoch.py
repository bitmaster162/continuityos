
from __future__ import annotations

from typing import Any
from .canon import sha256_obj
from .errors import EvidenceError

AMENDMENT_ID = "EPOCH_001_AMENDMENT_V2"
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
