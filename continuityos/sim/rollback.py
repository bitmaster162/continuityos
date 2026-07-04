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
    failed: bool = False                    # P0-D: True if the durable restore failed
    ts: float = field(default_factory=time.time)


class RollbackLedger:
    """Append-only record of rollbacks (mirrors continuity checkpoint discipline)."""

    def __init__(self):
        self.events: List[RollbackEvent] = []

    def record(self, trigger: RollbackTrigger, objective: str,
               restored_ref: Optional[int], detail: str = "", failed: bool = False) -> RollbackEvent:
        ev = RollbackEvent(trigger, objective, restored_ref, detail, failed=failed)
        self.events.append(ev)
        return ev

    def last(self) -> Optional[RollbackEvent]:
        return self.events[-1] if self.events else None


def execute_rollback(memory_plane, objective: str, trigger: RollbackTrigger,
                     ledger: RollbackLedger, detail: str = "") -> RollbackEvent:
    """Roll the objective's state back to its last verified canon checkpoint.

    memory_plane must expose rollback_ref(objective) and restore_to(objective, ref).

    P0-3/P0-D fix: this ACTUALLY restores durable state (memory_plane.restore_to re-points
    current canon and resets confirmations). P0-D: a restore FAILURE is NOT swallowed —
    the event is flagged `failed=True` (ROLLBACK_FAILED) so the caller can fail closed
    (HALT/HOLD) instead of continuing as if the rollback succeeded.
    """
    ref = None
    try:
        ref = memory_plane.rollback_ref(objective)
    except Exception:
        ref = None
    failed = False
    try:
        restored = memory_plane.restore_to(objective, ref)
        restored_ref = restored.get("restored_canon", ref) if isinstance(restored, dict) else ref
        detail_out = f"{detail} | restored={restored}"
    except Exception as e:
        failed = True                              # durable restore did NOT happen
        restored_ref = None
        detail_out = f"{detail} | ROLLBACK_FAILED: {str(e)[:120]}"
    ev = ledger.record(trigger, objective, restored_ref, detail_out, failed=failed)
    return ev


if __name__ == "__main__":  # self-test
    class FakePlane:
        def __init__(self): self.pointer = 42; self.confirms = 3
        def rollback_ref(self, obj): return self.pointer
        def restore_to(self, obj, ref):
            self.pointer = ref if ref is not None else self.pointer
            self.confirms = 0                      # real state change
            return {"objective": obj, "restored_canon": self.pointer}
    plane = FakePlane()
    led = RollbackLedger()
    ev = execute_rollback(plane, "edge", RollbackTrigger.HALLUCINATION_LOOP, led, "3 stalled iters")
    assert plane.confirms == 0, "restore must reset confirmation counter (real state change)"
    assert ev.failed is False and ev.restored_ref == 42 and led.last() is ev
    print(f"OK: rollback restores state (confirms={plane.confirms}, ref={ev.restored_ref}), failed={ev.failed}")

    # P0-D: a failing restore must be flagged (fail-closed), not swallowed
    class BrokenPlane:
        def rollback_ref(self, obj): return 7
        def restore_to(self, obj, ref): raise RuntimeError("durable store unavailable")
    ev2 = execute_rollback(BrokenPlane(), "edge", RollbackTrigger.GATEWAY_DENY, led, "breach")
    assert ev2.failed is True, "restore failure must set failed=True (P0-D, fail closed)"
    print(f"OK: rollback failure flagged failed={ev2.failed} (caller must HALT) — P0-D")
