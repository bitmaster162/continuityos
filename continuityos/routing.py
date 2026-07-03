"""ORCA Ф2 — cost-aware routing (adopted from BitEvo routing_policy_v1).

Picks WHICH agent tier runs a step, by declared task type and risk, so cheap
local agents do commodity work and premium models are reserved for high-stakes
steps. Anti-looping + role-drift guards travel with it. Pure-python, no deps.

    from continuityos.routing import Router, TaskClass
    r = Router()
    tier = r.route(goal="summarize arena stats", risk=0.2)   # -> "local"
    tier = r.route(goal="design migration architecture", risk=0.5)  # -> "premium"
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, List

# routing_policy_v1 (BitEvo) — thresholds + task routing, made explicit here.
DEFAULT_POLICY = {
    "confidence_escalate": 0.60,
    "risk_hitl": 0.80,                 # above this -> human in the loop
    "risk_block_write_without_hitl": 0.70,
    "local_task_types":   ["summarize", "extract", "classify", "format"],
    "premium_task_types": ["research", "architecture", "code"],
    "browser_task_types": ["web_read", "web_write"],
    "budgets": {
        "low":    {"max_tokens": 12000,  "max_steps": 6,  "max_runtime_sec": 180},
        "medium": {"max_tokens": 50000,  "max_steps": 12, "max_runtime_sec": 900},
        "high":   {"max_tokens": 120000, "max_steps": 24, "max_runtime_sec": 1800},
    },
}

_KEYWORDS = {
    "summarize": ("summar", "digest", "дайджест", "сводк"),
    "extract":   ("extract", "collect", "собер", "gather", "pull"),
    "classify":  ("classif", "label", "категор", "bucket"),
    "format":    ("format", "render", "оформ"),
    "research":  ("research", "investigate", "ресёрч", "analy", "исслед"),
    "architecture": ("architect", "design", "спроектир", "plan the", "migration"),
    "code":      ("code", "implement", "patch", "refactor", "напиши код", "fix bug"),
    "web_read":  ("fetch", "scrape", "read url", "web_read"),
    "web_write": ("post to", "submit", "deploy", "publish", "web_write"),
}


def classify_task(goal: str) -> str:
    g = (goal or "").lower()
    best, score = "summarize", 0
    for t, kws in _KEYWORDS.items():
        n = sum(1 for k in kws if k in g)
        if n > score:
            best, score = t, n
    return best


@dataclass
class Router:
    policy: Dict = field(default_factory=lambda: dict(DEFAULT_POLICY))

    def route(self, goal: str, risk: float = 0.0) -> str:
        """Return tier: 'human' | 'premium' | 'browser' | 'local'."""
        if risk >= self.policy["risk_hitl"]:
            return "human"
        t = classify_task(goal)
        if t in self.policy["premium_task_types"]:
            return "premium"
        if t in self.policy["browser_task_types"]:
            return "browser"
        return "local"

    def budget(self, risk: float = 0.0) -> Dict:
        tier = "high" if risk >= 0.6 else ("medium" if risk >= 0.3 else "low")
        return self.policy["budgets"][tier]

    def needs_hitl_for_write(self, risk: float) -> bool:
        return risk >= self.policy["risk_block_write_without_hitl"]


@dataclass
class RoleGuard:
    """Anti-looping + role-drift (BitEvo agent_safety, minimal)."""
    max_repeat: int = 3
    _seen: Dict[str, int] = field(default_factory=dict)

    def check(self, step_id: str, signature: str) -> bool:
        """True = ok to proceed; False = looping (same step+output signature too often)."""
        key = f"{step_id}:{hash(signature) & 0xffff}"
        self._seen[key] = self._seen.get(key, 0) + 1
        return self._seen[key] <= self.max_repeat
