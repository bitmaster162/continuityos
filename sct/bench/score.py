from __future__ import annotations

from typing import Mapping, Sequence, Any
import math

from ..errors import BenchError


def score_distribution(options: Sequence[str], probabilities: Mapping[str,float], actual_choice: str,
                       *, log_floor: float=0.001) -> dict[str,Any]:
    opts=tuple(options)
    if actual_choice not in opts: raise BenchError("actual choice outside registered options")
    if set(probabilities) != set(opts): raise BenchError("probability vector shape mismatch")
    k=len(opts)
    brier=sum((float(probabilities[o])-(1.0 if o==actual_choice else 0.0))**2 for o in opts)
    uniform=(k-1)/k
    skill=1.0-brier/uniform
    p=max(float(probabilities[actual_choice]),log_floor)
    log_loss=-math.log(p)
    predicted=min(o for o in opts if probabilities[o]==max(probabilities.values()))
    return {"correct":predicted==actual_choice,"predicted_choice":predicted,
            "multiclass_brier":brier,"brier_skill":skill,"log_loss":log_loss}
