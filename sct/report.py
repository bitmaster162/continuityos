
from __future__ import annotations

from collections import defaultdict
from typing import Any

from .store.protocol import EvidenceStore
from .stats.cluster import inferential_gate, paired_cluster_randomization, cluster_bootstrap_ci


def epoch_score_report(store: EvidenceStore, *, inferential: bool = False) -> dict[str, Any]:
    events = list(store.query())
    voided = {e.payload.get("case_id") for e in events if e.kind == "CASE_VOIDED"}
    scores = defaultdict(dict)
    clusters = {}
    for e in events:
        cid = e.payload.get("case_id")
        if not cid or cid in voided:
            continue
        if e.kind == "CASE_FROZEN":
            clusters[cid] = e.payload.get("cluster_key")
        elif e.kind == "CASE_SCORED":
            scores[cid][e.payload["arm"]] = e.payload

    paired = []
    for cid, by in scores.items():
        if "profile_rag" not in by or "sct" not in by:
            continue
        cluster_key = clusters.get(cid) or by["sct"].get("cluster_key")
        paired.append(
            {
                "case_id": cid,
                "cluster_key": cluster_key,
                "accuracy_delta_c_minus_b": float(by["sct"]["correct"]) - float(by["profile_rag"]["correct"]),
                "brier_skill_delta_c_minus_b": float(by["sct"]["brier_skill"]) - float(by["profile_rag"]["brier_skill"]),
                "log_loss_delta_c_minus_b": float(by["sct"]["log_loss"]) - float(by["profile_rag"]["log_loss"]),
            }
        )
    cluster_keys = {r["cluster_key"] for r in paired if r["cluster_key"]}
    gate = inferential_gate(n_cases=len(paired), n_clusters=len(cluster_keys))
    result = {
        "status": "DESCRIPTIVE_ONLY" if not gate["allowed"] else "INFERENTIAL_GATE_OPEN",
        "inference_scope": "SCT_PRESENTED_DECISIONS_ONLY",
        "valid_paired_cases": len(paired),
        "independent_clusters": len(cluster_keys),
        "gate": gate,
        "means": {},
        "execution_authority": "NONE",
    }
    for field in ("accuracy_delta_c_minus_b", "brier_skill_delta_c_minus_b", "log_loss_delta_c_minus_b"):
        result["means"][field] = (sum(r[field] for r in paired) / len(paired)) if paired else None
    if inferential:
        if not gate["allowed"]:
            result["inferential_refused"] = True
            return result
        result["inferential"] = {
            "accuracy": {
                "randomization": paired_cluster_randomization(paired, metric="accuracy_delta_c_minus_b"),
                "bootstrap_ci": cluster_bootstrap_ci(paired, metric="accuracy_delta_c_minus_b"),
            },
            "brier_skill": {
                "randomization": paired_cluster_randomization(paired, metric="brier_skill_delta_c_minus_b"),
                "bootstrap_ci": cluster_bootstrap_ci(paired, metric="brier_skill_delta_c_minus_b"),
            },
            "log_loss": {
                "randomization": paired_cluster_randomization(paired, metric="log_loss_delta_c_minus_b"),
                "bootstrap_ci": cluster_bootstrap_ci(paired, metric="log_loss_delta_c_minus_b"),
            },
        }
    return result
