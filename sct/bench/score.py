from __future__ import annotations

from typing import Mapping, Sequence, Any
import math

from ..errors import BenchError

TOP1_TIE_POLICY = "UNIQUE_ARGMAX_REQUIRED_TIE_COUNTS_AS_INCORRECT"


def score_distribution(options: Sequence[str], probabilities: Mapping[str, float], actual_choice: str,
                       *, log_floor: float = 0.001) -> dict[str, Any]:
    opts = tuple(options)
    if actual_choice not in opts:
        raise BenchError("actual choice outside registered options")
    if set(probabilities) != set(opts):
        raise BenchError("probability vector shape mismatch")
    if len(opts) < 2:
        raise BenchError("at least two options required")

    clean = {o: float(probabilities[o]) for o in opts}
    k = len(opts)
    brier = sum((clean[o] - (1.0 if o == actual_choice else 0.0)) ** 2 for o in opts)
    uniform = (k - 1) / k
    skill = 1.0 - brier / uniform
    p = max(clean[actual_choice], log_floor)
    log_loss = -math.log(p)

    max_probability = max(clean.values())
    leaders = tuple(o for o in opts if abs(clean[o] - max_probability) <= 1e-15)
    top1_tied = len(leaders) != 1
    predicted = None if top1_tied else leaders[0]

    return {
        "correct": bool(not top1_tied and predicted == actual_choice),
        "predicted_choice": predicted,
        "top1_tied": top1_tied,
        "top1_tied_options": leaders if top1_tied else (),
        "top1_tie_policy": TOP1_TIE_POLICY,
        "multiclass_brier": brier,
        "brier_skill": skill,
        "log_loss": log_loss,
    }
