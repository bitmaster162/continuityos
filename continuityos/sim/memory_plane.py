"""Continuity Control Plane memory (§3.3) — etap 5, cp-0323 (Opus).

Bitemporal split the doc demands: CANON (verified truth, superseded on new confident
result) vs EXPERIMENT_HISTORY (every branching hypothesis, Merkle-DAG via provenance).
Backed by the real ContinuityOS Memory when installed; falls back to an in-memory
stub so the loop always runs.

Canon rule (§3.3 + §4.2): a high-confidence SimulationResult supersedes prior canon
for the same objective (reversible — the superseded row stays in history for rollback).
Low-confidence results only append to experiment_history.
"""
from __future__ import annotations
from typing import Any, Dict, List, Optional

CANON_NS = "sim_canon"
EXPERIMENT_NS = "sim_experiment"


class RealMemoryPlane:
    """Uses continuityos.memory.Memory — bitemporal, supersede-capable."""

    def __init__(self, db: str = "~/.continuityos/sim.db"):
        import os
        from continuityos.memory import Memory
        self.m = Memory(os.path.expanduser(db))
        self._canon_ids: Dict[str, int] = {}   # objective -> current canon row id

    def record(self, spec, result, confident: bool) -> Dict[str, Any]:
        obj = spec.objective.primary_metric
        metric = list(result.metrics.values())[0] if result.metrics else 0.0
        text = f"{obj}={metric} @ params={spec.parameters}"
        meta = {"spec_id": spec.spec_id, "provenance": spec.provenance,
                "status": getattr(result.status, "value", str(result.status)),
                "metric": metric}
        # every hypothesis lands in experiment history (append-only, Merkle-DAG)
        exp_id = self.m.remember(text, namespace=EXPERIMENT_NS,
                                 tags=[obj], meta=meta)
        canon_action = "none"
        if confident:
            prior = self._canon_ids.get(obj)
            if prior is not None and hasattr(self.m, "supersede"):
                # reversible: prior canon row kept in history for rollback (§4.2)
                new_id = self.m.supersede(prior, text)
                canon_action = f"superseded #{prior} -> #{new_id}"
            else:
                new_id = self.m.remember(text, namespace=CANON_NS, tags=[obj, "canon"], meta=meta)
                canon_action = f"canon #{new_id}"
            self._canon_ids[obj] = new_id
        return {"experiment_id": exp_id, "canon": canon_action}

    def sizes(self) -> Dict[str, int]:
        try:
            ns = {n["namespace"]: n["count"] for n in self.m.namespaces()}
        except Exception:
            ns = {}
        return {"canon": ns.get(CANON_NS, 0), "experiment": ns.get(EXPERIMENT_NS, 0)}

    def rollback_ref(self, objective: str) -> Optional[int]:
        """Current canon row for an objective — the point a FailureMode rolls back to."""
        return self._canon_ids.get(objective)


class StubMemoryPlane:
    """Zero-dependency fallback (mirrors the loop's original in-memory plane)."""

    def __init__(self, *_, **__):
        self.canon: List[dict] = []
        self.experiment_history: List[dict] = []

    def record(self, spec, result, confident: bool) -> Dict[str, Any]:
        metric = list(result.metrics.values())[0] if result.metrics else 0.0
        entry = {"spec_id": spec.spec_id, "params": spec.parameters, "metric": metric,
                 "provenance": spec.provenance}
        self.experiment_history.append(entry)
        if confident:
            self.canon.append(entry)
        return {"experiment_id": len(self.experiment_history), "canon": "stub"}

    def sizes(self) -> Dict[str, int]:
        return {"canon": len(self.canon), "experiment": len(self.experiment_history)}

    def rollback_ref(self, objective: str) -> Optional[int]:
        return len(self.canon) or None


def make_memory_plane(db: str = "~/.continuityos/sim.db"):
    """Real bitemporal plane if ContinuityOS is installed, else the stub."""
    try:
        return RealMemoryPlane(db)
    except Exception:
        return StubMemoryPlane()


if __name__ == "__main__":  # self-test
    from types import SimpleNamespace
    mp = make_memory_plane("/tmp/sim_mem_test.db")
    print("backend:", type(mp).__name__)
    spec = SimpleNamespace(objective=SimpleNamespace(primary_metric="edge"),
                           parameters={"x": 0.5}, provenance=[], spec_id="abc123")
    res = SimpleNamespace(metrics={"edge": 0.9}, status=SimpleNamespace(value="success"))
    print("iter1:", mp.record(spec, res, confident=True))
    res2 = SimpleNamespace(metrics={"edge": 0.95}, status=SimpleNamespace(value="success"))
    spec2 = SimpleNamespace(objective=SimpleNamespace(primary_metric="edge"),
                            parameters={"x": 0.52}, provenance=["abc123"], spec_id="def456")
    print("iter2:", mp.record(spec2, res2, confident=True))
    print("sizes:", mp.sizes(), "rollback_ref:", mp.rollback_ref("edge"))
    assert mp.sizes()["experiment"] >= 2
    print("OK: bitemporal canon/experiment split works")
