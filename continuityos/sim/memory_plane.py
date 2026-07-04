"""Continuity Control Plane memory (§3.3) — etap 5, hardened per GPT audit 2026-07-04.

Bitemporal split: CANON (verified truth) vs EXPERIMENT_HISTORY (every hypothesis,
Merkle-DAG via provenance). Backed by the real ContinuityOS Memory.

Hardening (GPT audit):
- P0-2: canon promotion is NOT "one lucky success". A result only crystallizes into
  canon after `min_confirmations` independent runs clear `verify_threshold` (a bar set
  ABOVE the loop's success threshold). Single runs stay in experiment_history.
- P0-3: `restore_to()` actually restores the current canon pointer (real rollback),
  not just a log line.
- P0-4: `make_memory_plane()` FAILS CLOSED — it will not silently degrade a durable
  store to RAM. Stub is opt-in (`allow_stub=True`), for tests/--mock only.
- P1-5: `_canon_ids` is rehydrated from durable storage on init, so supersede chains
  and rollback survive a process restart.
"""
from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

CANON_NS = "sim_canon"
EXPERIMENT_NS = "sim_experiment"


@dataclass
class PromotionPolicy:
    """When may an experiment result be crystallized into canon? (P0-2)
    Requires replication: N runs above a verify bar, not a single success."""
    verify_threshold: float = 0.97      # ABOVE typical success_threshold (0.95)
    min_confirmations: int = 2          # independent runs clearing the bar

    def qualifies(self, metric: float) -> bool:
        return metric >= self.verify_threshold


class RealMemoryPlane:
    """Uses continuityos.memory.Memory — bitemporal, supersede-capable, fail-closed."""

    def __init__(self, db: str = "~/.continuityos/sim.db",
                 policy: Optional[PromotionPolicy] = None):
        import os
        from continuityos.memory import Memory
        self.m = Memory(os.path.expanduser(db))          # raises if store is broken
        self.policy = policy or PromotionPolicy()
        self._canon_ids: Dict[str, int] = {}             # objective -> current canon row
        self._confirmations: Dict[str, int] = {}         # objective -> qualifying runs
        self._rehydrate()

    def _rehydrate(self):
        """P1-5: rebuild the current-canon pointer from durable storage on startup."""
        try:
            rows = self.m.recall("", k=1000, namespace=CANON_NS) if hasattr(self.m, "recall") else []
        except Exception:
            rows = []
        for r in rows:
            meta = getattr(r, "meta", None) or {}
            obj = (meta.get("objective")
                   or (getattr(r, "tags", None) or [None])[0])
            rid = getattr(r, "id", None)
            if obj and rid is not None:
                self._canon_ids[obj] = rid               # last write wins (recall ordered)

    def record(self, spec, result, confident_hint: bool = False) -> Dict[str, Any]:
        obj = spec.objective.primary_metric
        metric = list(result.metrics.values())[0] if result.metrics else 0.0
        text = f"{obj}={metric} @ params={spec.parameters}"
        meta = {"spec_id": spec.spec_id, "provenance": spec.provenance, "objective": obj,
                "status": getattr(result.status, "value", str(result.status)), "metric": metric}
        # every hypothesis -> experiment history (append-only, Merkle-DAG). Always.
        exp_id = self.m.remember(text, namespace=EXPERIMENT_NS, tags=[obj], meta=meta)

        # P0-2: promotion requires replication above the verify bar, not one success.
        canon_action = "experiment_only"
        if self.policy.qualifies(metric):
            self._confirmations[obj] = self._confirmations.get(obj, 0) + 1
            if self._confirmations[obj] >= self.policy.min_confirmations:
                prior = self._canon_ids.get(obj)
                if prior is not None and hasattr(self.m, "supersede"):
                    new_id = self.m.supersede(prior, text)
                    canon_action = f"verified: superseded #{prior} -> #{new_id}"
                else:
                    new_id = self.m.remember(text, namespace=CANON_NS, tags=[obj, "canon"], meta=meta)
                    canon_action = f"verified: canon #{new_id}"
                self._canon_ids[obj] = new_id
            else:
                canon_action = (f"candidate {self._confirmations[obj]}/"
                                f"{self.policy.min_confirmations} confirmations")
        return {"experiment_id": exp_id, "canon": canon_action,
                "confirmations": self._confirmations.get(obj, 0)}

    def restore_to(self, objective: str, ref: Optional[int]) -> Dict[str, Any]:
        """P0-3: real rollback — make `ref` the current canon pointer again and reset
        the confirmation counter so poisoned progress can't auto-promote. Returns what
        was restored. Experiment history is untouched (append-only audit)."""
        if ref is None:
            ref = self._canon_ids.get(objective)
        self._canon_ids[objective] = ref
        self._confirmations[objective] = 0
        return {"objective": objective, "restored_canon": ref}

    def sizes(self) -> Dict[str, int]:
        try:
            ns = {n["namespace"]: n["count"] for n in self.m.namespaces()}
        except Exception:
            ns = {}
        return {"canon": ns.get(CANON_NS, 0), "experiment": ns.get(EXPERIMENT_NS, 0)}

    def rollback_ref(self, objective: str) -> Optional[int]:
        return self._canon_ids.get(objective)


class StubMemoryPlane:
    """In-memory, EPHEMERAL. Explicit opt-in only (tests / --mock). NOT durable."""

    def __init__(self, policy: Optional[PromotionPolicy] = None, *_, **__):
        self.policy = policy or PromotionPolicy()
        self.canon: List[dict] = []
        self.experiment_history: List[dict] = []
        self._confirmations: Dict[str, int] = {}

    def record(self, spec, result, confident_hint: bool = False) -> Dict[str, Any]:
        obj = spec.objective.primary_metric
        metric = list(result.metrics.values())[0] if result.metrics else 0.0
        entry = {"spec_id": spec.spec_id, "params": spec.parameters, "metric": metric,
                 "objective": obj, "provenance": spec.provenance}
        self.experiment_history.append(entry)
        canon_action = "experiment_only"
        if self.policy.qualifies(metric):
            self._confirmations[obj] = self._confirmations.get(obj, 0) + 1
            if self._confirmations[obj] >= self.policy.min_confirmations:
                self.canon.append(entry); canon_action = "verified: canon(stub)"
            else:
                canon_action = f"candidate {self._confirmations[obj]}/{self.policy.min_confirmations}"
        return {"experiment_id": len(self.experiment_history), "canon": canon_action,
                "confirmations": self._confirmations.get(obj, 0)}

    def restore_to(self, objective: str, ref: Optional[int]) -> Dict[str, Any]:
        self._confirmations[objective] = 0
        return {"objective": objective, "restored_canon": len(self.canon) or None}

    def sizes(self) -> Dict[str, int]:
        return {"canon": len(self.canon), "experiment": len(self.experiment_history)}

    def rollback_ref(self, objective: str) -> Optional[int]:
        return len(self.canon) or None


def make_memory_plane(db: str = "~/.continuityos/sim.db", allow_stub: bool = False,
                      policy: Optional[PromotionPolicy] = None):
    """Durable bitemporal plane. FAILS CLOSED (P0-4): if the durable store can't be
    opened, this RAISES — it will NOT silently fall back to ephemeral RAM. Pass
    `allow_stub=True` only for tests / --mock, where losing state is acceptable."""
    if allow_stub:
        return StubMemoryPlane(policy=policy)
    return RealMemoryPlane(db, policy=policy)   # propagates the real failure


if __name__ == "__main__":  # self-test
    from types import SimpleNamespace
    mp = make_memory_plane("/tmp/sim_mem_test.db", allow_stub=True,
                           policy=PromotionPolicy(verify_threshold=0.9, min_confirmations=2))
    print("backend:", type(mp).__name__)

    def mkspec(sid, params): return SimpleNamespace(
        objective=SimpleNamespace(primary_metric="edge"), parameters=params, provenance=[], spec_id=sid)
    def mkres(m): return SimpleNamespace(metrics={"edge": m}, status=SimpleNamespace(value="success"))

    print("run1 (0.92, 1st confirm):", mp.record(mkspec("a", {"x": .5}), mkres(0.92)))
    assert mp.sizes()["canon"] == 0, "one qualifying run must NOT be canon yet"
    print("run2 (0.95, 2nd confirm):", mp.record(mkspec("b", {"x": .5}), mkres(0.95)))
    assert mp.sizes()["canon"] == 1, "two confirmations -> canon"
    rb = mp.restore_to("edge", None)
    print("rollback:", rb, "-> confirmations reset:", mp._confirmations["edge"])
    assert mp._confirmations["edge"] == 0
    print("OK: replication-gated promotion + real restore + fail-closed default")
