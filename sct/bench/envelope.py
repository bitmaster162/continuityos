from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Dict, Mapping, Optional, Sequence
import math

from ..canon import canonical_json, sha256_obj
from ..errors import BenchError

BASELINES = ("generic", "profile_rag", "sct")
LIVE_SCHEMA = "sct.live-epoch001-v2"
ENVELOPE_SYSTEM_PROMPT = (
    "You are a shadow-only prediction contestant. Predict which listed option the principal will actually choose. "
    "Use the scenario, the options, and whatever is provided in personal_context—nothing else. "
    "Do not invent personal facts. Assign a probability to every listed option; probabilities must sum to 1. "
    "Return only the requested JSON fields. Shadow only: do not act, do not execute, do not re-query for a better answer."
)
RESPONSE_CONTRACT = {
    "option_probabilities": "object mapping EVERY listed option to a probability in [0.001,0.999]; must sum to 1.0",
    "reasons": ["short reason"],
    "change_conditions": ["what new evidence could change this"],
    "would_escalate": "boolean",
}
CONSTRAINTS = {"shadow_only": True, "do_not_execute": True, "do_not_requery_for_a_better_answer": True}


def _clean(value: str, field: str, *, allow_empty: bool=False) -> str:
    if not isinstance(value, str): raise BenchError(f"{field} must be a string")
    out=value.strip()
    if not out and not allow_empty: raise BenchError(f"{field} must be non-empty")
    return out


@dataclass(frozen=True)
class FrozenContestantInput:
    arm: str
    provider: str
    model: str
    model_version: str
    token_budget: int
    temperature: Optional[float]
    reasoning: str
    frozen_at: float
    personal_context: str
    payload_bytes: int
    envelope_sha256: str
    payload_sha256: str
    snapshot_sha256: str
    schema: str = LIVE_SCHEMA
    execution_authority: str = "NONE"
    can_execute: bool = False

    def to_dict(self) -> Dict[str, Any]: return asdict(self)


def _envelope_identity(*, scenario: str, options: Sequence[str], provider: str, model: str,
                       model_version: str, token_budget: int, temperature: Optional[float], reasoning: str) -> dict[str, Any]:
    return {
        "system_prompt": ENVELOPE_SYSTEM_PROMPT,
        "scenario": scenario,
        "options": tuple(options),
        "response_contract": RESPONSE_CONTRACT,
        "constraints": CONSTRAINTS,
        "provider": provider,
        "model": model,
        "model_version": model_version,
        "token_budget": token_budget,
        "temperature": temperature,
        "reasoning": reasoning,
    }


def build_standard_inputs(*, scenario: str, options: Sequence[str], provider: str, model: str,
                          model_version: str, static_profile: str, sct_state: str,
                          permitted_history: str="", token_budget: int=4096,
                          temperature: Optional[float]=0.0, reasoning: str="default",
                          frozen_at: float) -> Dict[str, FrozenContestantInput]:
    opts=tuple(dict.fromkeys(_clean(x,"option") for x in options))
    if len(opts)<2: raise BenchError("at least two distinct options required")
    if not isinstance(token_budget,int) or isinstance(token_budget,bool) or token_budget<1: raise BenchError("token_budget")
    if temperature is not None and (not isinstance(temperature,(int,float)) or not math.isfinite(float(temperature))): raise BenchError("temperature")
    frozen_at=float(frozen_at)
    if not math.isfinite(frozen_at): raise BenchError("frozen_at")
    b = _clean(static_profile, "static_profile")
    if permitted_history.strip():
        b += "\n" + _clean(permitted_history, "permitted_history", allow_empty=True)
    c=_clean(sct_state,"sct_state")
    contexts={"generic":"NONE","profile_rag":b,"sct":c}
    envelope=_envelope_identity(scenario=scenario, options=opts, provider=_clean(provider,"provider"),
        model=_clean(model,"model"), model_version=_clean(model_version,"model_version"), token_budget=token_budget,
        temperature=None if temperature is None else float(temperature), reasoning=_clean(reasoning,"reasoning"))
    envelope_sha=sha256_obj(envelope)
    out={}
    for arm in BASELINES:
        ctx=contexts[arm]
        payload_sha=sha256_obj(ctx)
        identity={"schema":LIVE_SCHEMA,"arm":arm,"envelope_sha256":envelope_sha,
                  "payload_sha256":payload_sha,"frozen_at":frozen_at,"execution_authority":"NONE","can_execute":False}
        out[arm]=FrozenContestantInput(arm, envelope["provider"], envelope["model"], envelope["model_version"], token_budget,
            envelope["temperature"], envelope["reasoning"], frozen_at, ctx, len(ctx.encode("utf-8")), envelope_sha,
            payload_sha, sha256_obj(identity))
    return out


def assert_parity(inputs: Mapping[str, FrozenContestantInput], *, ratio: float=1.15) -> None:
    if set(inputs) != set(BASELINES): raise BenchError("inputs must contain exact A/B/C baselines")
    if len({x.envelope_sha256 for x in inputs.values()}) != 1: raise BenchError("ENVELOPE_PARITY_VIOLATION")
    if len({x.frozen_at for x in inputs.values()}) != 1: raise BenchError("FROZEN_AT_PARITY_VIOLATION")
    b=inputs["profile_rag"].payload_bytes; c=inputs["sct"].payload_bytes
    if b <= 0 or c <= 0 or c > ratio*b or b > ratio*c:
        raise BenchError("PARITY_BUDGET_VIOLATION")


def render_request(*, scenario: str, options: Sequence[str], frozen_input: FrozenContestantInput) -> Dict[str, Any]:
    payload={"scenario":_clean(scenario,"scenario"),"options":tuple(options),"personal_context":frozen_input.personal_context,
             "response_contract":RESPONSE_CONTRACT,"constraints":CONSTRAINTS}
    return {"schema":LIVE_SCHEMA,"provider":frozen_input.provider,"model":frozen_input.model,
            "model_version":frozen_input.model_version,"token_budget":frozen_input.token_budget,
            "temperature":frozen_input.temperature,"reasoning":frozen_input.reasoning,
            "messages":[{"role":"system","content":ENVELOPE_SYSTEM_PROMPT},{"role":"user","content":canonical_json(payload)}],
            "response_contract":RESPONSE_CONTRACT,"execution_authority":"NONE","can_execute":False}
