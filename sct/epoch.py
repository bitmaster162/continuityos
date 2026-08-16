from __future__ import annotations

from typing import Any
from .canon import sha256_obj


def amendment_v2_manifest(*, parent_commit: str, parent_tree: str) -> dict[str,Any]:
    body={
        "schema":"sct.epoch-amendment/v2",
        "epoch_id":"SCT-LIVE-EPOCH-001",
        "amendment_id":"EPOCH_001_AMENDMENT_V2",
        "parent_commit":parent_commit,
        "parent_tree":parent_tree,
        "valid_live_n_at_amendment":0,
        "changes":["full_probability_vectors","multiclass_brier_and_log_loss","shared_abc_envelope",
                   "payload_parity_budget","pre_reveal_cluster_metadata","sct_namespace_rebinding","fixed_cluster_analysis_plan"],
        "execution_authority":"NONE","can_execute":False,
    }
    return {**body,"manifest_sha256":sha256_obj(body)}
