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

    memory_plane must expose rollback_ref(objective) and restore_to(objective, ref).

    P0-3 fix (GPT audit 2026-07-04): this ACTUALLY restores state, not just logs.
    It calls memory_plane.restore_to(), which re-points current canon to the last good
    row and resets the promotion-confirmation counter (so poisoned progress can't
    auto-promote). Then it records the immutable rollback event. Experiment history is
    append-only and left intact for audit.
    """
    ref = None
    restored = None
    try:
        ref = memory_plane.rollback_ref(objective)
    except Exception:
        ref = None
    # ACTUAL restore (not just a log line)
    try:
        restored = memory_plane.restore_to(objective, ref)
    except AttributeError:
        restored = {"error": "memory_plane has no restore_to (rollback logged only)"}
    except Exception as e:
        restored = {"error": str(e)[:120]}
    ev = ledger.record(trigger, objective, ref, f"{detail} | restored={restored}")
    ev.restored_ref = (restored or {}).get("restored_canon", ref) if isinstance(restored, dict) else ref
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
    print(f"rollback: trigger={ev.trigger.value} restored_ref={ev.restored_ref} "
          f"confirms_after={plane.confirms}")
    print("OK: rollback restores state (resets confirmations), not just logs (§4.2, P0-3)")
    assert ev.restored_ref == 42 and led.last() is ev
    print("OK: rollback protocol records event + resolves last-good canon ref (§4.2)")
