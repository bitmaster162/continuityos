"""Usage metering + quota — the local foundation for RaaS (hosted, metered governance).

The free OSS gate/twin run unmetered on your own machine. The moment you expose them
as a hosted API you need three things this module provides: (1) a durable usage ledger,
(2) plan-based quotas enforced FAIL-CLOSED, and (3) a billing-adapter seam so Stripe/Unkey
plug in later without touching call sites. Stdlib-only, offline.

    meter = Meter("usage.db")
    r = meter.charge("cust_42", "gate.decision")   # atomic quota-check + count
    if not r["allowed"]:
        return r["action"]                          # upgrade message / 429
    result = run_gate(...)
"""
from __future__ import annotations
import os, sqlite3, time
from typing import Dict, Optional

DAY = 86400.0

# Per-window quotas by plan. None = unlimited. memory.seat is a static plan attribute
# (reported, not windowed). Numbers are a starting skeleton — tune with real pricing.
PLANS: Dict[str, Dict[str, Optional[int]]] = {
    "free":       {"gate.decision": 100,    "twin.call": 20,    "memory.seat": 1},
    "pro":        {"gate.decision": 5000,   "twin.call": 1000,  "memory.seat": 1},
    "team":       {"gate.decision": 100000, "twin.call": 20000, "memory.seat": 10},
    "enterprise": {"*": None},
}
METERED_EVENTS = ("gate.decision", "twin.call")


class LocalBilling:
    """Default over-quota behaviour: return an upgrade hint (no external calls)."""
    def on_over_quota(self, key: str, event: str, usage: int, limit: int) -> str:
        return (f"quota exceeded: {event} {usage}/{limit} on plan — "
                f"upgrade with `cos usage --key {key} --set-plan pro`")


class StripeBilling:
    """Seam for hosted RaaS. Requires Stripe (metered price) + Unkey (API keys).
    Intentionally inert until configured, so nothing ships half-wired."""
    def __init__(self):
        if not os.environ.get("STRIPE_API_KEY"):
            raise RuntimeError("StripeBilling requires STRIPE_API_KEY + Unkey key mgmt — not configured")

    def on_over_quota(self, key, event, usage, limit):  # pragma: no cover
        raise NotImplementedError("wire Stripe metered usage record here")


class Meter:
    def __init__(self, path: str = "usage.db", window: float = DAY):
        self.window = window
        d = os.path.dirname(path)
        if d:
            os.makedirs(d, exist_ok=True)
        self.db = sqlite3.connect(path)
        self.db.execute("CREATE TABLE IF NOT EXISTS usage(key TEXT, event TEXT, ts REAL)")
        self.db.execute("CREATE INDEX IF NOT EXISTS idx_usage ON usage(key, event, ts)")
        self.db.execute("CREATE TABLE IF NOT EXISTS plans(key TEXT PRIMARY KEY, plan TEXT)")
        self.db.commit()

    def set_plan(self, key: str, plan: str) -> None:
        if plan not in PLANS:
            raise ValueError(f"unknown plan {plan!r}; choose from {sorted(PLANS)}")
        self.db.execute("INSERT OR REPLACE INTO plans(key, plan) VALUES(?, ?)", (key, plan))
        self.db.commit()

    def plan(self, key: str) -> str:
        row = self.db.execute("SELECT plan FROM plans WHERE key=?", (key,)).fetchone()
        return row[0] if row else "free"

    def limit(self, key: str, event: str) -> Optional[int]:
        p = PLANS[self.plan(key)]
        if "*" in p:
            return p["*"]                # enterprise: unlimited
        return p.get(event, 0)           # unknown event on a bounded plan = deny (fail-closed)

    def usage(self, key: str, event: str, window: Optional[float] = None) -> int:
        since = time.time() - (window or self.window)
        return self.db.execute(
            "SELECT COUNT(*) FROM usage WHERE key=? AND event=? AND ts>=?",
            (key, event, since)).fetchone()[0]

    def allow(self, key: str, event: str) -> bool:
        lim = self.limit(key, event)
        return True if lim is None else self.usage(key, event) < lim

    def record(self, key: str, event: str, units: int = 1) -> None:
        now = time.time()
        self.db.executemany("INSERT INTO usage(key, event, ts) VALUES(?, ?, ?)",
                            [(key, event, now)] * max(1, units))
        self.db.commit()

    def charge(self, key: str, event: str, billing=None) -> Dict:
        """Atomic quota-check + count. Over quota => not recorded, returns action."""
        lim = self.limit(key, event)
        used = self.usage(key, event)
        if lim is not None and used >= lim:
            action = (billing or LocalBilling()).on_over_quota(key, event, used, lim)
            return {"allowed": False, "event": event, "usage": used, "limit": lim,
                    "plan": self.plan(key), "action": action}
        self.record(key, event)
        return {"allowed": True, "event": event, "usage": used + 1, "limit": lim,
                "plan": self.plan(key)}

    def report(self, key: str) -> Dict:
        p = PLANS[self.plan(key)]
        events = METERED_EVENTS if "*" in p else tuple(p.keys())
        return {"key": key, "plan": self.plan(key),
                "usage": {e: {"used": self.usage(key, e), "limit": self.limit(key, e)}
                          for e in events}}
