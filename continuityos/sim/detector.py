"""Hallucination-loop detector (§4.1) — etap 6, cp-0319 (Fable 5).

The doc's novel epistemic-safety piece: detect when the agent is spinning in a
semantic loop (specs stay similar) WHILE the objective metric plateaus — i.e. it's
"prompting its way out" of a dead end, burning budget without learning. Cheap,
deterministic proxies for the OTel+SEP semantic-entropy probes (§5).

Signals combined:
  1. Semantic stall — successive parameter vectors barely move (low L2 delta).
  2. Metric plateau — best metric not improving beyond min_delta.
  3. Repetition — same spec_id seen again (exact cycle).
Two of three => hallucination_loop => loop should rollback (§4.2).
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import List, Dict
import math


@dataclass
class LoopSignals:
    semantic_stall: bool
    metric_plateau: bool
    repetition: bool
    energy: float          # 0..1 "spin energy": high = stuck & burning
    is_hallucination: bool
    detail: str = ""


@dataclass
class HallucinationDetector:
    stall_l2_threshold: float = 0.02      # param-vector move below this = stalled
    plateau_min_delta: float = 1e-3
    patience: int = 3
    _param_hist: List[Dict[str, float]] = field(default_factory=list)
    _metric_hist: List[float] = field(default_factory=list)
    _spec_ids: List[str] = field(default_factory=list)

    def _l2(self, a: Dict[str, float], b: Dict[str, float]) -> float:
        keys = set(a) | set(b)
        return math.sqrt(sum((a.get(k, 0.0) - b.get(k, 0.0)) ** 2 for k in keys))

    def _param_sig(self, params: Dict[str, float]) -> str:
        # quantized signature so near-identical param vectors count as a repeat
        # (semantic cycle detection — spec_id changes via provenance, params don't)
        return "|".join(f"{k}={round(params[k], 3)}" for k in sorted(params))

    def observe(self, params: Dict[str, float], metric: float, spec_id: str) -> LoopSignals:
        sig = self._param_sig(params)
        repetition = sig in [self._param_sig(p) for p in self._param_hist]
        self._param_hist.append(dict(params))
        self._metric_hist.append(metric)
        self._spec_ids.append(spec_id)

        # need a window before judging
        if len(self._param_hist) <= self.patience:
            return LoopSignals(False, False, repetition, 0.0, False, "warming up")

        recent_params = self._param_hist[-(self.patience + 1):]
        moves = [self._l2(recent_params[i], recent_params[i + 1])
                 for i in range(len(recent_params) - 1)]
        semantic_stall = all(m < self.stall_l2_threshold for m in moves)

        recent_metrics = self._metric_hist[-(self.patience + 1):]
        gains = [recent_metrics[i + 1] - recent_metrics[i]
                 for i in range(len(recent_metrics) - 1)]
        metric_plateau = all(g <= self.plateau_min_delta for g in gains)

        votes = sum([semantic_stall, metric_plateau, repetition])
        # energy: stalled movement + flat metric + budget spent = high spin
        avg_move = sum(moves) / len(moves) if moves else 0.0
        energy = round(min(1.0, (1.0 - min(avg_move / max(self.stall_l2_threshold, 1e-9), 1.0))
                           * (1.0 if metric_plateau else 0.3)), 4)
        is_hallucination = votes >= 2
        detail = (f"stall={semantic_stall} plateau={metric_plateau} rep={repetition} "
                  f"avg_move={avg_move:.4f} energy={energy}")
        return LoopSignals(semantic_stall, metric_plateau, repetition, energy,
                           is_hallucination, detail)


def _selftest():
    # case A: stuck agent (frozen params, flat metric, unique spec_ids) -> flagged
    d = Hallucination