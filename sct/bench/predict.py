from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Mapping, Sequence, Tuple
import math

from ..canon import sha256_obj
from ..errors import BenchError

PREDICTION_SCHEMA = "sct.prediction/v3"


@dataclass(frozen=True)
class Prediction:
    case_id: str
    arm: str
    options: Tuple[str, ...]
    option_probabilities: Mapping[str, float]
    predicted_choice: str | None
    confidence: float
    reasons: Tuple[str, ...]
    change_conditions: Tuple[str, ...]
    would_escalate: bool
    committed_at: float
    prediction_id: str
    schema: str = PREDICTION_SCHEMA
    execution_authority: str = "NONE"
    can_execute: bool = False

    def to_dict(self):
        return asdict(self)


def validate_probability_response(options: Sequence[str], response: Mapping[str, Any]) -> tuple[dict[str, float], str | None, float]:
    opts = tuple(options)
    probs = response.get("option_probabilities") if isinstance(response, Mapping) else None
    if not isinstance(probs, Mapping) or set(probs) != set(opts):
        raise BenchError("PREDICTION_SCHEMA_VIOLATION: option keys must exactly equal case options")
    clean = {}
    for opt in opts:
        value = probs[opt]
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise BenchError("PREDICTION_SCHEMA_VIOLATION: probability must be numeric")
        value = float(value)
        if not math.isfinite(value) or not 0.001 <= value <= 0.999:
            raise BenchError("PREDICTION_SCHEMA_VIOLATION: probability outside [0.001,0.999]")
        clean[opt] = value
    if abs(sum(clean.values()) - 1.0) > 1e-6:
        raise BenchError("PREDICTION_SCHEMA_VIOLATION: probabilities must sum to 1")

    maxp = max(clean.values())
    leaders = tuple(opt for opt, p in clean.items() if abs(p - maxp) <= 1e-15)
    predicted = leaders[0] if len(leaders) == 1 else None
    return clean, predicted, maxp


def build_prediction(*, case_id: str, arm: str, options: Sequence[str], response: Mapping[str, Any], committed_at: float) -> Prediction:
    probs, pred, conf = validate_probability_response(options, response)
    reasons = tuple(str(x).strip() for x in response.get("reasons", ()) if str(x).strip())
    changes = tuple(str(x).strip() for x in response.get("change_conditions", ()) if str(x).strip())
    escalate = response.get("would_escalate", False)
    if not isinstance(escalate, bool):
        raise BenchError("PREDICTION_SCHEMA_VIOLATION: would_escalate must be boolean")
    body = {
        "schema": PREDICTION_SCHEMA,
        "case_id": case_id,
        "arm": arm,
        "options": tuple(options),
        "option_probabilities": probs,
        "predicted_choice": pred,
        "confidence": conf,
        "reasons": reasons,
        "change_conditions": changes,
        "would_escalate": escalate,
        "committed_at": float(committed_at),
        "execution_authority": "NONE",
        "can_execute": False,
    }
    return Prediction(
        prediction_id=sha256_obj(body),
        **{k: body[k] for k in (
            "case_id", "arm", "options", "option_probabilities", "predicted_choice", "confidence", "reasons",
            "change_conditions", "would_escalate", "committed_at"
        )},
    )
