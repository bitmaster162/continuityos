"""Proposal-only memory promotion evaluation bound to exact closure bytes."""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .github_transition import REQUIRED_WAVE_A, SLOTS, SLOT_STATUSES

SCHEMA = "continuityos.memory_promotion.evaluation/v1"
VERDICTS = {"ACCEPT", "PASS_WITH_CONDITIONS", "HOLD", "REVISE", "REJECT"}
REQUIRED_GLOBAL_GATES = {
    "no_self_acceptance",
    "no_registry_apply",
    "no_existing_main_merge",
    "github_visibility_preserved",
    "no_secret_or_raw_evidence_leak",
    "memory_candidate_present",
    "remote_readback_complete",
}


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _load(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8-sig"))
    except Exception as exc:
        raise ValueError(f"{label} is not valid JSON: {type(exc).__name__}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    return value


def evaluate_memory_promotion(closure_receipt_path: Path, semantic_decisions_path: Path) -> dict[str, Any]:
    closure_receipt_path = Path(closure_receipt_path)
    semantic_decisions_path = Path(semantic_decisions_path)
    reasons: list[str] = []
    closure = _load(closure_receipt_path, "closure receipt")
    decisions = _load(semantic_decisions_path, "semantic decisions")
    closure_sha = _sha256(closure_receipt_path)

    if decisions.get("closure_receipt_sha256") != closure_sha:
        reasons.append("semantic decisions are not bound to the exact closure receipt SHA-256")
    if closure.get("physical_status") != "BYTE_VERIFIED":
        reasons.append("closure physical_status is not BYTE_VERIFIED")
    if closure.get("terminal") != "FINAL_HOST_CLOSURE_AND_GITHUB_TRANSITION_COMPLETE":
        reasons.append("closure terminal is not COMPLETE")
    if closure.get("registry_apply") is not False or closure.get("r63_apply") is not False:
        reasons.append("closure receipt does not preserve registry/R63 no-apply")
    if closure.get("self_application") is not False:
        reasons.append("closure receipt self_application is not false")

    if decisions.get("authority_generation") != "R63":
        reasons.append("authority_generation must remain R63")
    if decisions.get("memory_candidate_authority") != "NON_AUTHORITATIVE_CANDIDATE":
        reasons.append("memory candidate must remain NON_AUTHORITATIVE_CANDIDATE")
    if decisions.get("promotion_decision") != "APPROVE_PROMOTION_CANDIDATE":
        reasons.append("explicit APPROVE_PROMOTION_CANDIDATE is missing")
    if decisions.get("human_irreversible_approval") is not False:
        reasons.append("this evaluator cannot record or forge irreversible human approval")
    if decisions.get("self_application") is not False:
        reasons.append("semantic decisions self_application must be false")

    global_gates = decisions.get("global_gates")
    if not isinstance(global_gates, dict):
        reasons.append("global_gates must be an object")
        global_gates = {}
    for gate in sorted(REQUIRED_GLOBAL_GATES):
        if global_gates.get(gate) != "PASS":
            reasons.append(f"global gate not PASS: {gate}")

    closure_slots_raw = closure.get("slots")
    closure_slots: dict[str, dict[str, Any]] = {}
    if isinstance(closure_slots_raw, list):
        for row in closure_slots_raw:
            if isinstance(row, dict) and row.get("slot") in SLOTS and row["slot"] not in closure_slots:
                closure_slots[row["slot"]] = row
    if set(closure_slots) != set(SLOTS):
        reasons.append("closure receipt does not contain exactly all nine slots")

    decision_rows = decisions.get("slots")
    if isinstance(decision_rows, dict):
        decision_rows = [{"slot": slot, **(row if isinstance(row, dict) else {})} for slot, row in decision_rows.items()]
    by_slot: dict[str, dict[str, Any]] = {}
    if isinstance(decision_rows, list):
        for row in decision_rows:
            if not isinstance(row, dict):
                continue
            slot = row.get("slot")
            if slot not in SLOTS or slot in by_slot:
                reasons.append(f"invalid or duplicate semantic decision slot: {slot!r}")
                continue
            by_slot[slot] = row
    if set(by_slot) != set(SLOTS):
        reasons.append("semantic decisions do not cover exactly all nine slots")

    semantic_summary: list[dict[str, Any]] = []
    for slot in SLOTS:
        physical = closure_slots.get(slot, {}).get("physical_status")
        verdict = by_slot.get(slot, {}).get("gpt_semantic_verdict")
        if physical not in SLOT_STATUSES:
            reasons.append(f"{slot}: missing or invalid physical_status")
        if verdict not in VERDICTS:
            reasons.append(f"{slot}: missing or invalid GPT semantic verdict")
        if verdict in {"ACCEPT", "PASS_WITH_CONDITIONS"} and physical != "BYTE_VERIFIED":
            reasons.append(f"{slot}: {verdict} requires BYTE_VERIFIED, got {physical}")
        semantic_summary.append({"slot": slot, "physical_status": physical, "gpt_semantic_verdict": verdict})

    repo_rows = closure.get("repositories")
    repo_names: set[str] = set()
    if isinstance(repo_rows, list):
        for row in repo_rows:
            if not isinstance(row, dict):
                continue
            name = row.get("name", row.get("repo"))
            if isinstance(name, str):
                repo_names.add(name.rsplit("/", 1)[-1])
    missing_repos = sorted(REQUIRED_WAVE_A - repo_names)
    if missing_repos:
        reasons.append("closure receipt lacks mandatory Wave A repos: " + ", ".join(missing_repos))

    status = "PROMOTION_CANDIDATE_ELIGIBLE" if not reasons else "PROMOTION_HOLD"
    return {
        "schema": SCHEMA,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "status": status,
        "closure_receipt_sha256": closure_sha,
        "reasons": reasons,
        "semantic_summary": semantic_summary,
        "mandatory_wave_a_repositories": sorted(REQUIRED_WAVE_A),
        "effect": "PROPOSAL_ONLY_NO_APPLY",
        "authority_generation": "R63",
        "memory_candidate_authority": "NON_AUTHORITATIVE_CANDIDATE",
        "human_irreversible_approval": False,
        "registry_apply": False,
        "r63_apply": False,
        "live_state_modified": False,
        "can_trade": False,
        "capital_permission": "DENY",
        "deploy_permission": "DENY",
        "self_application": False,
    }


def exit_code_for_memory_promotion(receipt: dict[str, Any]) -> int:
    return 0 if receipt.get("status") == "PROMOTION_CANDIDATE_ELIGIBLE" else 3
