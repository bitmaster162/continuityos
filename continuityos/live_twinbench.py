"""LIVE-0 bridge from SCT-R2 TwinBench to prospective human decision cases.

This module freezes reproducible A/B/C contestant inputs and writes a local case bundle.
It deliberately does not call model APIs, add memory architecture, train models, delegate
actions, or grant authority. Provider execution stays outside the evidence core.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping, Optional, Sequence, Tuple
import hashlib
import json
import math
import time

from .decision_twin import DecisionTwinError
from .twinbench import TwinBenchArena

LIVE_SCHEMA = "continuityos.sct.live0/v1"
BASELINES = ("generic", "profile_rag", "sct")

GENERIC_SYSTEM_PROMPT = (
    "You are a shadow-only prediction contestant. Predict which listed option the "
    "principal will choose using only the scenario and options. Do not assume personal "
    "facts that are not provided. Return the requested JSON fields only."
)
PROFILE_SYSTEM_PROMPT = (
    "You are a shadow-only prediction contestant. Predict which listed option the "
    "principal will choose using only the frozen approved profile/history supplied in "
    "this request. Do not invent missing personal facts. Return the requested JSON fields only."
)
SCT_SYSTEM_PROMPT = (
    "You are the shadow-only ContinuityOS SCT prediction contestant. Predict which listed "
    "option the principal will choose using only the frozen sovereign person state supplied "
    "in this request. Prediction does not grant authority. Return the requested JSON fields only."
)

RESPONSE_CONTRACT = {
    "predicted_choice": "one exact option",
    "confidence": "number in [0,1]",
    "reasons": ["short evidence-grounded reason"],
    "change_conditions": ["what new evidence could change the prediction"],
    "would_escalate": "boolean",
}


def _cj(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _sha(value: Any) -> str:
    raw = value if isinstance(value, str) else _cj(value)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _text(value: str, field: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        raise DecisionTwinError(f"{field} must be a string")
    value = value.strip()
    if not value and not allow_empty:
        raise DecisionTwinError(f"{field} must be a non-empty string")
    return value


def _ts(value: Optional[float], field: str) -> float:
    out = time.time() if value is None else float(value)
    if not math.isfinite(out):
        raise DecisionTwinError(f"{field} must be finite")
    return out


def _items(values: Sequence[str], field: str) -> Tuple[str, ...]:
    out = []
    for value in values:
        item = _text(value, field)
        if item not in out:
            out.append(item)
    return tuple(out)


@dataclass(frozen=True)
class CaseEligibility:
    prospective: bool = True
    discrete_or_rankable: bool = True
    unseen_before_registration: bool = True
    recorded_before_human_commitment: bool = True
    nontrivial: bool = True
    resolvable_in_window: bool = True
    externally_forced: bool = False

    def validate(self) -> None:
        required = {
            "prospective": self.prospective,
            "discrete_or_rankable": self.discrete_or_rankable,
            "unseen_before_registration": self.unseen_before_registration,
            "recorded_before_human_commitment": self.recorded_before_human_commitment,
            "nontrivial": self.nontrivial,
            "resolvable_in_window": self.resolvable_in_window,
        }
        failed = [name for name, value in required.items() if value is not True]
        if failed:
            raise DecisionTwinError(f"ineligible live case; failed={failed}")
        if self.externally_forced is not False:
            raise DecisionTwinError("ineligible live case; externally_forced must be false")


@dataclass(frozen=True)
class FrozenContestantInput:
    contestant_id: str
    baseline_type: str
    provider: str
    model: str
    model_version: str
    system_prompt: str
    context_sections: Tuple[Tuple[str, str], ...]
    token_budget: int
    temperature: Optional[float]
    reasoning: str
    frozen_at: float
    snapshot_sha256: str
    schema: str = LIVE_SCHEMA
    mode: str = "SHADOW"
    execution_authority: str = "NONE"
    can_execute: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def freeze_contestant_input(
    *,
    contestant_id: str,
    baseline_type: str,
    provider: str,
    model: str,
    model_version: str,
    system_prompt: str,
    context_sections: Optional[Mapping[str, str]] = None,
    token_budget: int = 4096,
    temperature: Optional[float] = 0.0,
    reasoning: str = "default",
    frozen_at: Optional[float] = None,
) -> FrozenContestantInput:
    contestant_id = _text(contestant_id, "contestant_id")
    baseline_type = _text(baseline_type, "baseline_type")
    if baseline_type not in BASELINES:
        raise DecisionTwinError(f"baseline_type must be one of {BASELINES}")
    provider = _text(provider, "provider")
    model = _text(model, "model")
    model_version = _text(model_version, "model_version")
    system_prompt = _text(system_prompt, "system_prompt")
    if isinstance(token_budget, bool) or not isinstance(token_budget, int) or token_budget < 1:
        raise DecisionTwinError("token_budget must be a positive integer")
    if temperature is not None:
        if isinstance(temperature, bool) or not isinstance(temperature, (int, float)):
            raise DecisionTwinError("temperature must be numeric or null")
        temperature = float(temperature)
        if not math.isfinite(temperature) or temperature < 0:
            raise DecisionTwinError("temperature must be finite and non-negative")
    reasoning = _text(reasoning, "reasoning")
    frozen_at = _ts(frozen_at, "frozen_at")

    sections = []
    for raw_name, raw_content in sorted((context_sections or {}).items()):
        name = _text(raw_name, "context section name")
        content = _text(raw_content, f"context_sections[{name}]", allow_empty=True)
        sections.append((name, content))
    sections_t = tuple(sections)

    identity = {
        "schema": LIVE_SCHEMA,
        "contestant_id": contestant_id,
        "baseline_type": baseline_type,
        "provider": provider,
        "model": model,
        "model_version": model_version,
        "system_prompt": system_prompt,
        "context_sections": sections_t,
        "token_budget": token_budget,
        "temperature": temperature,
        "reasoning": reasoning,
        "frozen_at": frozen_at,
        "mode": "SHADOW",
        "execution_authority": "NONE",
        "can_execute": False,
    }
    return FrozenContestantInput(
        contestant_id=contestant_id,
        baseline_type=baseline_type,
        provider=provider,
        model=model,
        model_version=model_version,
        system_prompt=system_prompt,
        context_sections=sections_t,
        token_budget=token_budget,
        temperature=temperature,
        reasoning=reasoning,
        frozen_at=frozen_at,
        snapshot_sha256=_sha(identity),
    )


def build_standard_inputs(
    *,
    provider: str,
    model: str,
    model_version: str,
    static_profile: str,
    sct_state: str,
    permitted_history: str = "",
    token_budget: int = 4096,
    temperature: Optional[float] = 0.0,
    reasoning: str = "default",
    frozen_at: Optional[float] = None,
) -> Dict[str, FrozenContestantInput]:
    """Freeze A/B/C inputs on the same serving-model manifest for a fair comparison."""
    static_profile = _text(static_profile, "static_profile")
    sct_state = _text(sct_state, "sct_state")
    permitted_history = _text(permitted_history, "permitted_history", allow_empty=True)
    frozen_at = _ts(frozen_at, "frozen_at")
    common = dict(
        provider=provider,
        model=model,
        model_version=model_version,
        token_budget=token_budget,
        temperature=temperature,
        reasoning=reasoning,
        frozen_at=frozen_at,
    )
    return {
        "generic": freeze_contestant_input(
            contestant_id="generic", baseline_type="generic",
            system_prompt=GENERIC_SYSTEM_PROMPT, context_sections={}, **common,
        ),
        "profile_rag": freeze_contestant_input(
            contestant_id="profile_rag", baseline_type="profile_rag",
            system_prompt=PROFILE_SYSTEM_PROMPT,
            context_sections={
                "approved_static_profile": static_profile,
                "permitted_frozen_history": permitted_history,
            },
            **common,
        ),
        "sct": freeze_contestant_input(
            contestant_id="sct", baseline_type="sct", system_prompt=SCT_SYSTEM_PROMPT,
            context_sections={"sovereign_person_state": sct_state}, **common,
        ),
    }


def render_request(
    *, situation: str, options: Sequence[str], frozen_input: FrozenContestantInput
) -> Dict[str, Any]:
    situation = _text(situation, "situation")
    opts = _items(options, "options")
    if len(opts) < 2:
        raise DecisionTwinError("options must contain at least two distinct choices")
    context = [
        {"name": name, "content": content}
        for name, content in frozen_input.context_sections if content
    ]
    payload = {
        "scenario": situation,
        "options": opts,
        "frozen_personal_context": context,
        "response_contract": RESPONSE_CONTRACT,
        "constraints": {
            "shadow_only": True,
            "do_not_execute": True,
            "do_not_requery_for_a_better_answer": True,
        },
    }
    return {
        "schema": LIVE_SCHEMA,
        "contestant_id": frozen_input.contestant_id,
        "snapshot_sha256": frozen_input.snapshot_sha256,
        "provider": frozen_input.provider,
        "model": frozen_input.model,
        "model_version": frozen_input.model_version,
        "token_budget": frozen_input.token_budget,
        "temperature": frozen_input.temperature,
        "reasoning": frozen_input.reasoning,
        "messages": [
            {"role": "system", "content": frozen_input.system_prompt},
            {"role": "user", "content": _cj(payload)},
        ],
        "response_contract": RESPONSE_CONTRACT,
        "mode": "SHADOW",
        "execution_authority": "NONE",
        "can_execute": False,
    }


def prepare_live_case(
    arena: TwinBenchArena,
    *,
    root: str | Path,
    case_id: str,
    decision_surface: str,
    situation: str,
    options: Sequence[str],
    frozen_inputs: Mapping[str, FrozenContestantInput],
    eligibility: Optional[CaseEligibility] = None,
    opened_at: Optional[float] = None,
) -> Dict[str, Any]:
    """Register one eligible case in R2 and persist its frozen local evidence bundle."""
    case_id = _text(case_id, "case_id")
    decision_surface = _text(decision_surface, "decision_surface")
    situation = _text(situation, "situation")
    opts = _items(options, "options")
    if len(opts) < 2:
        raise DecisionTwinError("options must contain at least two distinct choices")
    eligibility = eligibility or CaseEligibility()
    eligibility.validate()
    if set(frozen_inputs) != set(BASELINES):
        raise DecisionTwinError(f"frozen_inputs must contain exactly {BASELINES}")
    for key, value in frozen_inputs.items():
        if value.contestant_id != key or value.baseline_type != key:
            raise DecisionTwinError(f"contestant input mismatch for {key}")
    timestamps = {value.frozen_at for value in frozen_inputs.values()}
    if len(timestamps) != 1:
        raise DecisionTwinError("standard contestants must share one frozen_at timestamp")
    opened_at = _ts(opened_at, "opened_at")
    if opened_at < next(iter(timestamps)):
        raise DecisionTwinError("case opening cannot predate frozen contestant inputs")

    case_dir = Path(root) / case_id
    if case_dir.exists():
        raise DecisionTwinError("live case directory already exists")
    input_hashes = {name: frozen_inputs[name].snapshot_sha256 for name in BASELINES}
    arena_case = arena.open_case(
        case_id=case_id,
        situation=situation,
        options=opts,
        input_snapshots=input_hashes,
        opened_at=opened_at,
    )
    manifest = {
        "schema": LIVE_SCHEMA,
        "case_id": case_id,
        "decision_surface": decision_surface,
        "situation": situation,
        "options": opts,
        "eligibility": asdict(eligibility),
        "contestants": BASELINES,
        "input_snapshots": input_hashes,
        "arena_case_spec_id": arena_case["case_spec_id"],
        "opened_at": opened_at,
        "mode": "SHADOW",
        "execution_authority": "NONE",
        "can_execute": False,
    }
    manifest["manifest_sha256"] = _sha(manifest)

    (case_dir / "inputs").mkdir(parents=True, exist_ok=False)
    (case_dir / "requests").mkdir(parents=True, exist_ok=False)
    (case_dir / "case_manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )
    for name in BASELINES:
        snapshot = frozen_inputs[name]
        (case_dir / "inputs" / f"{name}.json").write_text(
            json.dumps(snapshot.to_dict(), ensure_ascii=False, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )
        request = render_request(situation=situation, options=opts, frozen_input=snapshot)
        (case_dir / "requests" / f"{name}.json").write_text(
            json.dumps(request, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )
    return manifest


def evidence_stage(common_cases: int) -> Dict[str, Any]:
    if isinstance(common_cases, bool) or not isinstance(common_cases, int) or common_cases < 0:
        raise DecisionTwinError("common_cases must be a non-negative integer")
    if common_cases < 20:
        stage = "DEBUG_ONLY"
    elif common_cases < 30:
        stage = "PILOT_NO_CLAIM"
    elif common_cases < 100:
        stage = "DIRECTIONAL_ONLY"
    else:
        stage = "DEFENSIBLE_DIRECTIONAL_CANDIDATE"
    return {
        "common_cases": common_cases,
        "stage": stage,
        "inferential_claim_allowed": common_cases >= 100,
        "note": (
            "Sample-count bands are workflow labels, not statistical proof. "
            "Effect size and confidence intervals govern claim strength."
        ),
    }


def analysis_export(arena: TwinBenchArena) -> Dict[str, Any]:
    pairs = {
        "sct_vs_generic": arena.pairwise("sct", "generic"),
        "sct_vs_profile_rag": arena.pairwise("sct", "profile_rag"),
        "profile_rag_vs_generic": arena.pairwise("profile_rag", "generic"),
    }
    common = min((value["common_cases"] for value in pairs.values()), default=0)
    return {
        "schema": LIVE_SCHEMA,
        "leaderboard": arena.leaderboard(min_cases=30),
        "pairwise": pairs,
        "evidence_stage": evidence_stage(common),
        "primary_comparison": "sct_vs_profile_rag",
        "primary_endpoint": "paired_accuracy_delta",
        "secondary_endpoint": "paired_mean_brier_delta",
        "status": "DESCRIPTIVE_ONLY" if common < 100 else "READY_FOR_PRE_REGISTERED_INFERENCE",
    }
