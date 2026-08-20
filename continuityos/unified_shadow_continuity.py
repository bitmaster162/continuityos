from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping

TRANSACTION_SCHEMA = "bitevo.unified_shadow_transaction.v2"
CONTINUITY_RECEIPT_SCHEMA = "continuityos.shadow_continuity_receipt.v1"

MODERN_SOURCE_REPO = "bitmaster162/continuityos"
MODERN_SOURCE_BRANCH = "master"
MODERN_SOURCE_HEAD = "9dfb9e5b847a27113ca7c709a0adee900e3ff63f"

# Historical local/runtime-adoption evidence is deliberately separate from modern GitHub source identity.
R52_LOCAL_ADOPTION_HEAD = "b5436f373dcb19873a3b0908b26f8d0e22cb8125"
R52_LOCAL_ADOPTION_STATUS = "LOCAL_CANONICAL_ADOPTION_PASS"
R57_RUNTIME_PREFLIGHT_ZIP_SHA256 = "187b0723de9290159da96fc45357a58acf7d177aea7d65eaecc094ef4a17521e"
R57_RUNTIME_PREFLIGHT_TERMINAL = "REVISE"

EXPECTED_NODE_COUNT = 63

REQUIRED_SAFETY = {
    "mode": "SHADOW",
    "execution_authority": "NONE",
    "can_trade": False,
    "capital_permission": "DENY",
    "orders_allowed": False,
    "signals_allowed": False,
}

REQUIRED_FALSE_EFFECTS = (
    "executor_enabled",
    "current_truth_apply",
    "continuity_write",
    "runtime_registration",
    "external_model_call",
    "exchange_call",
    "signal",
    "order",
    "credential_mutation",
    "merge",
    "deploy",
)


class ShadowContinuityError(ValueError):
    pass


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def sha256_obj(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _sha256(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise ShadowContinuityError(f"{field}_must_be_sha256")
    text = value.lower()
    if len(text) != 64 or any(ch not in "0123456789abcdef" for ch in text):
        raise ShadowContinuityError(f"{field}_must_be_sha256")
    return text


def _git_sha(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise ShadowContinuityError(f"{field}_must_be_git_sha")
    text = value.lower()
    if len(text) != 40 or any(ch not in "0123456789abcdef" for ch in text):
        raise ShadowContinuityError(f"{field}_must_be_git_sha")
    return text


def validate_unified_transaction(transaction: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    if not isinstance(transaction, Mapping):
        return ["transaction_must_be_object"]
    if transaction.get("schema") != TRANSACTION_SCHEMA:
        errors.append("transaction_schema_mismatch")

    try:
        tx_sha = _sha256(transaction.get("transaction_sha256"), "transaction_sha256")
        expected = sha256_obj({k: v for k, v in transaction.items() if k != "transaction_sha256"})
        if tx_sha != expected:
            errors.append("transaction_hash_mismatch")
    except ShadowContinuityError as exc:
        errors.append(str(exc))

    for field in (
        "trade_case_sha256",
        "decision_packet_sha256",
        "federation_sha256",
        "route_sha256",
        "control_plane_sha256",
    ):
        try:
            _sha256(transaction.get(field), field)
        except ShadowContinuityError as exc:
            errors.append(str(exc))

    if transaction.get("registered_node_count") != EXPECTED_NODE_COUNT:
        errors.append("registry_count_mismatch")

    safety = transaction.get("safety")
    if not isinstance(safety, Mapping):
        errors.append("safety_missing")
    else:
        for key, expected in REQUIRED_SAFETY.items():
            if safety.get(key) != expected or type(safety.get(key)) is not type(expected):
                errors.append(f"unsafe_transaction:{key}")

    effects = transaction.get("effect_boundary")
    if not isinstance(effects, Mapping):
        errors.append("effect_boundary_missing")
    else:
        for key in REQUIRED_FALSE_EFFECTS:
            if effects.get(key) is not False:
                errors.append(f"effect_boundary_not_false:{key}")

    gate = transaction.get("control_gate")
    action = transaction.get("control_plane_action")
    freshness = transaction.get("hanri_freshness")
    attention = transaction.get("hanri_attention_required")
    if gate not in {"PASS_SHADOW", "HOLD"}:
        errors.append("control_gate_invalid")
    if gate == "HOLD" and action != "WAIT":
        errors.append("hold_must_force_wait")
    if freshness == "STALE" and gate != "HOLD":
        errors.append("stale_control_evidence_must_hold")
    if attention is True and gate != "HOLD":
        errors.append("attention_must_hold")
    return errors


def build_shadow_continuity_receipt(
    transaction: Mapping[str, Any],
    *,
    modern_source_repo: str,
    modern_source_branch: str,
    modern_source_head: str,
    live_host_state: str = "UNVERIFIED",
) -> dict[str, Any]:
    """Create a deterministic, no-write ContinuityOS receipt for one P0 shadow transaction.

    The receipt binds modern GitHub source identity separately from historical R52/R57 local/runtime
    evidence. It creates checkpoint/replay/return *candidates* only; no canonical memory, runtime,
    Return Broker or ArchiveOS state is mutated.
    """
    errors = validate_unified_transaction(transaction)
    if errors:
        raise ShadowContinuityError(";".join(errors))

    if modern_source_repo != MODERN_SOURCE_REPO:
        raise ShadowContinuityError("modern_source_repo_mismatch")
    if modern_source_branch != MODERN_SOURCE_BRANCH:
        raise ShadowContinuityError("modern_source_branch_mismatch")
    source_head = _git_sha(modern_source_head, "modern_source_head")
    if source_head != MODERN_SOURCE_HEAD:
        raise ShadowContinuityError("modern_source_head_mismatch")

    if live_host_state != "UNVERIFIED":
        raise ShadowContinuityError("p0_live_host_state_must_remain_unverified")

    tx_sha = str(transaction["transaction_sha256"])
    gate = str(transaction["control_gate"])
    action = str(transaction["control_plane_action"])

    checkpoint_candidate = {
        "schema": "continuityos.shadow_checkpoint_candidate.v1",
        "source_transaction_sha256": tx_sha,
        "case_id": transaction.get("case_id"),
        "decision_packet_sha256": transaction.get("decision_packet_sha256"),
        "control_plane_sha256": transaction.get("control_plane_sha256"),
        "control_gate": gate,
        "control_plane_action": action,
        "modern_source_head": source_head,
        "write_allowed": False,
    }
    checkpoint_candidate["candidate_sha256"] = sha256_obj(checkpoint_candidate)

    replay_candidate = {
        "schema": "continuityos.shadow_replay_candidate.v1",
        "source_transaction_sha256": tx_sha,
        "checkpoint_candidate_sha256": checkpoint_candidate["candidate_sha256"],
        "read_only": True,
        "apply_allowed": False,
    }
    replay_candidate["candidate_sha256"] = sha256_obj(replay_candidate)

    return_candidate = {
        "schema": "continuityos.shadow_return_candidate.v1",
        "source_transaction_sha256": tx_sha,
        "checkpoint_candidate_sha256": checkpoint_candidate["candidate_sha256"],
        "replay_candidate_sha256": replay_candidate["candidate_sha256"],
        "semantic_acceptance": "NOT_PERFORMED",
        "write_allowed": False,
    }
    return_candidate["candidate_sha256"] = sha256_obj(return_candidate)

    disposition = "HOLD_SHADOW_NO_WRITE" if gate == "HOLD" else "READY_FOR_READ_ONLY_REVIEW"

    body = {
        "schema": CONTINUITY_RECEIPT_SCHEMA,
        "source_transaction_sha256": tx_sha,
        "case_id": transaction.get("case_id"),
        "disposition": disposition,
        "modern_source": {
            "repo": MODERN_SOURCE_REPO,
            "branch": MODERN_SOURCE_BRANCH,
            "head_sha": source_head,
            "claim_dimension": "SOURCE_IDENTITY",
            "claim_ceiling": "MODERN_GITHUB_SOURCE_ONLY",
            "proves_live_runtime": False,
            "proves_current_host_state": False,
        },
        "historical_lineage": {
            "r52_local_adoption": {
                "head_sha": R52_LOCAL_ADOPTION_HEAD,
                "status": R52_LOCAL_ADOPTION_STATUS,
                "source_class": "HISTORICAL_LOCAL_EXECUTION_EVIDENCE",
                "claim_ceiling": "LOCAL_CONTROL_LIBRARY_ADOPTION_ONLY",
                "is_modern_github_source": False,
                "proves_live_runtime": False,
            },
            "r57_runtime_preflight": {
                "zip_sha256": R57_RUNTIME_PREFLIGHT_ZIP_SHA256,
                "terminal": R57_RUNTIME_PREFLIGHT_TERMINAL,
                "source_class": "HISTORICAL_RUNTIME_PREFLIGHT_EVIDENCE",
                "claim_ceiling": "PREFLIGHT_ONLY",
                "proves_live_runtime": False,
            },
            "live_host_state": live_host_state,
        },
        "checkpoint_candidate": checkpoint_candidate,
        "replay_candidate": replay_candidate,
        "return_candidate": return_candidate,
        "writes": {
            "event_append": False,
            "memory_write": False,
            "checkpoint_write": False,
            "replay_write": False,
            "return_broker_write": False,
            "archive_write": False,
            "runtime_activation": False,
            "pointer_update": False,
        },
        "authority": {
            "execution_authority": "NONE",
            "apply_authorized": False,
            "human_authority_required_for_effects": True,
        },
        "semantics": {
            "modern_source_is_not_live_runtime": True,
            "historical_r52_is_not_modern_source": True,
            "historical_preflight_is_not_activation": True,
            "return_transport_is_not_semantic_acceptance": True,
            "checkpoint_candidate_is_not_canonical_checkpoint": True,
            "read_only_replay_is_not_apply": True,
        },
        "safety": dict(REQUIRED_SAFETY),
    }
    body["continuity_receipt_sha256"] = sha256_obj(body)
    return body
