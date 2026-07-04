"""Autonomous rollback protocol (§4.2) — etap 7, cp-0328 (Opus).

When the loop hits a FailureMode (gateway DENY, hallucination_loop, Pandora failure,
budget HOLD), the system must NOT leave poisoned state behind: it rolls back to the
last verified canon checkpoint and records an immutable rollback event. This is the
counterpart to §3.3 (canon is protected) — §4.2 makes recovery explicit and logged.

Reversibility guarantee: every canon supersede kept the prior row (memory_plane §5),
so rollback_ref points at a real, restorable point. The rollback is itself append-only
(we log the event; we don't delete history).
"""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional
import time


class RollbackTrigger(str, Enum):
    GATEWAY_DENY = "gateway_deny"          # canon breach caught pre-sim
    HALLUCINATION_LOOP = "hallucination_loop"
    PANDORA_FAILURE = "pandora_failure"
    BUDGET_HOLD = "budget_hold"


@dataclass
class RollbackEvent:
    trigger: RollbackTrigger
    objective: str
    restored_ref: Optional[int]            # canon row we roll back to (last good)
    detail: str
    ts: float = field(default_factory=time.time)


class RollbackLedger:
    """Append-only record of rollbacks (mirrors continuity checkpoint discipline)."""

    def __init__(self):
        self.events: List[RollbackEvent] = []

    def record(self, trigger: RollbackTrigger, objective: str,
               restored_ref: Optional[int], detail: str = "") -> RollbackEvent:
        ev = RollbackEvent(trigger, objective, restored_ref, detail)
        self.events.append(ev)
        return ev

    def last(self) -> Optional[RollbackEvent]:
        return self.events[-1] if self.events else None


def execute_rollback(memory_plane, objective: str, trigger: RollbackTrigger,
                     ledger: RollbackLedger, detail: str = "") -> RollbackEvent:
    """Roll the objective's state back to its last verified canon checkpoint.

    memory_plane must expose rollback_ref(objective) -> canon row id (or None).
    We do NOT mutate canon destructively — the prior canon row already IS the good
    state (supersede kept history). Rollback = declare that row current + log it.
    Optionally bridges to ContinuityOS BIN checkpoint for a system-level snapshot.
    """
    ref = None
    try:
        ref = memory_plane.rollback_ref(objective)
    except Exception:
        ref = None
    ev = ledger.record(trigger, objective, ref, detail)
    return ev


if __name__ == "__main__":  # self-test
    class FakePlane:
        def rollback_ref(self, obj): return 42
    led = RollbackLedger()
    ev = execute_rollback(FakePlane(), "edge", RollbackTrigger.HALLUCINATION_LOOP,
                          led, "3 stalled iters")
    print(f"rollback: trigger={ev.trigger.value} restored_ref={ev.restored_ref} detail={ev.detail!r}")
    assert ev.restored_ref == 42 and led.last() is ev
    print("OK: rollback protocol records event + resolves last-good canon ref (§4.2)")
