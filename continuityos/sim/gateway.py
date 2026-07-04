"""Governance Gateway (§2) — etap 4, cp-0325 (Opus).

Deterministic ALLOW / WARN / HOLD / DENY before any intent reaches Pandora. Replaces
the MVP stub in loop.py with a real risk-scoring finite state machine driven by
telemetry: budget, canon constraints, parameter sanity, and (optional) confidence.

FSM (§2.1):  INTENT -> CHECK -> {ALLOW -> SIM | WARN -> SIM(flagged) | HOLD -> PAUSE | DENY -> HALT}
Risk score (§2.2): weighted sum of signals in 0..1; thresholds map score -> verdict.
This is the Python/deterministic mirror of the OPA/Rego policy (§5) — same logic,
swappable for a WASM policy later without touching the loop.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any


class Verdict(str, Enum):
    ALLOW = "ALLOW"   # low risk -> run
    WARN = "WARN"     # elevated -> run but flag for review
    HOLD = "HOLD"     # budget/rate limit -> pause, resumable
    DENY = "DENY"     # canon violation / hard breach -> halt, do NOT run


@dataclass
class GatewayDecision:
    verdict: Verdict
    risk_score: float           # 0..1
    reasons: List[str] = field(default_factory=list)
    signals: Dict[str, float] = field(default_factory=dict)


@dataclass
class GovernanceGateway:
    # risk-signal weights (§2.2) — tune per deployment; sum need not be 1
    w_budget: float = 0.35
    w_constraint: float = 0.40
    w_range: float = 0.15
    w_confidence: float = 0.10
    # score thresholds -> verdict
    warn_at: float = 0.35
    hold_at: float = 0.60       # budget-driven pause
    deny_at: float = 0.80

    def evaluate(self, spec, budget_left: int, budget_total: int,
                 confidence: Optional[float] = None) -> GatewayDecision:
        reasons: List[str] = []
        sig: Dict[str, float] = {}

        # 1) operator-canon + constraint checks — a real breach is an immediate DENY.
        # P1-6 (GPT audit): enforce the loaded operator canon, not just local demo bounds.
        # Canon bounds (from operator_canon entities) OVERRIDE / augment spec.constraints.
        # NOTE: build_spec() in loop.py currently injects DEMO defaults (hard_bounds=2.0,
        # empty CanonicalState). A real deployment must populate operator_canon from the
        # operator's ContinuityOS canon — then this check enforces the real rules.
        canon_bounds = dict(getattr(spec.constraints, "hard_bounds", {}) or {})
        operator_canon = getattr(spec, "operator_canon", None)
        canon_entities = getattr(operator_canon, "entities", None) or []
        canon_keys = set()
        for ent in canon_entities:
            for k, lim in (getattr(ent, "attributes", None) or {}).items():
                if k.endswith("_max") or k.endswith("_limit"):
                    base = k.rsplit("_", 1)[0]
                    canon_bounds[base] = lim         # operator canon wins over demo bounds
                    canon_keys.add(base)
        for p, v in spec.parameters.items():
            cap = canon_bounds.get(p)
            if cap is not None and abs(v) > cap:
                src = "operator canon" if p in canon_keys else "declared constraint"
                return GatewayDecision(
                    Verdict.DENY, 1.0,
                    [f"{src} breach: {p}={v} exceeds bound {cap}"],
                    {"constraint": 1.0})
        # forbidden regions declared by canon/constraints
        for region in getattr(spec.constraints, "forbidden_regions", []) or []:
            if region and any(region in f"{p}={v}" for p, v in spec.parameters.items()):
                return GatewayDecision(Verdict.DENY, 1.0,
                                       [f"forbidden region hit: {region}"], {"constraint": 1.0})
        sig["constraint"] = 0.0

        # 2) budget pressure (0 = plenty, 1 = exhausted)
        frac_left = max(0.0, min(1.0, budget_left / budget_total)) if budget_total else 0.0
        budget_risk = 1.0 - frac_left
        sig["budget"] = round(budget_risk, 3)
        if budget_left <= 0:
            return GatewayDecision(Verdict.HOLD, max(0.6, budget_risk),
                                   ["budget exhausted — pause, resumable"], sig)

        # 3) parameter range sanity (nominal 0..1); out-of-range = elevated, not fatal
        out = [p for p, v in spec.parameters.items() if v < 0 or v > 1]
        range_risk = min(1.0, len(out) / max(1, len(spec.parameters))) if out else 0.0
        sig["range"] = round(range_risk, 3)
        if out:
            reasons.append(f"params out of nominal 0..1: {out}")

        # 4) confidence (optional) — low confidence raises risk
        conf_risk = 0.0
        if confidence is not None:
            conf_risk = max(0.0, min(1.0, 1.0 - confidence))
            sig["confidence"] = round(conf_risk, 3)

        score = (self.w_budget * budget_risk + self.w_constraint * sig["constraint"]
                 + self.w_range * range_risk + self.w_confidence * conf_risk)
        score = round(min(1.0, score), 4)

        if score >= self.deny_at:
            verdict = Verdict.DENY; reasons.append(f"aggregate risk {score} >= deny {self.deny_at}")
        elif score >= self.hold_at:
            verdict = Verdict.HOLD; reasons.append(f"aggregate risk {score} >= hold {self.hold_at}")
        elif score >= self.warn_at:
            verdict = Verdict.WARN; reasons.append(f"aggregate risk {score} >= warn {self.warn_at}")
        else:
            verdict = Verdict.ALLOW; reasons.append(f"aggregate risk {score} < warn {self.warn_at}")
        return GatewayDecision(verdict, score, reasons, sig)


if __name__ == "__main__":  # self-test across the four verdicts
    from types import SimpleNamespace
    def mkspec(params, bounds=None):
        return SimpleNamespace(parameters=params,
                               constraints=SimpleNamespace(hard_bounds=bounds or {}))
    gw = GovernanceGateway()
    d1 = gw.evaluate(mkspec({"x": 0.5, "y": 0.5}), 9000, 10000, confidence=0.9)
    d2 = gw.evaluate(mkspec({"x": 1.4, "y": 0.5}), 9000, 10000, confidence=0.5)   # out of range
    d3 = gw.evaluate(mkspec({"x": 0.5}), 0, 10000)                                # budget gone
    d4 = gw.evaluate(mkspec({"x": 3.0}, {"x": 2.0}), 9000, 10000)                 # canon breach
    for name, d in [("healthy", d1), ("out-of-range", d2), ("no-budget", d3), ("canon-breach", d4)]:
        print(f"{name:14s} -> {d.verdict.value:5s} score={d.risk_score} {d.reasons[0]}")
    assert d1.verdict == Verdict.ALLOW and d3.verdict == Verdict.HOLD and d4.verdict == Verdict.DENY
    print("OK: gateway produces ALLOW/WARN/HOLD/DENY from risk score")
