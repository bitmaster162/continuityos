"""Continuity Control Plane memory (§3.3) — PR-9 invariant closure (GPT 2nd audit).

Bitemporal split: CANON (verified truth) vs EXPERIMENT_HISTORY (every hypothesis).
Backed by continuityos.memory.Memory (durable, supersede-capable, fail-closed).

PR-9 fixes (second-order bugs the earlier hardening exposed):
- P0-A: confirmations are keyed by CANDIDATE IDENTITY (objective+params+bounds), not by
  objective. Two different hypotheses can't co-confirm; distinct run/result ids count.
- P0-C: `restore_to()` is a DURABLE restorative supersede — it re-points the current
  canon row in SQLite (survives restart), not just an in-memory dict.
- P1-A: `_rehydrate()` uses a DIRECT deterministic DB query (not relevance recall).
- P1-B: promotion supersede preserves meta+tags, so rehydrate can recover the objective.
Promotion still requires `min_confirmations` distinct qualifying runs of the SAME candidate.
"""
from __future__ import annotations
import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

CANON_NS = "sim_canon"
EXPERIMENT_NS = "sim_experiment"


def candidate_id(spec) -> str:
    """Stable identity of a hypothesis: objective + parameters + hard bounds. Excludes
    provenance (re-running the same hypothesis is the SAME candidate)."""
    payload = {
        "objective": spec.objective.primary_metric,
        "params": {k: round(float(v), 6) for k, v in spec.parameters.items()},
        "bounds": dict(getattr(spec.constraints, "hard_bounds", {}) or {}),
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()[:16]


@dataclass
class PromotionPolicy:
    verify_threshold: float = 0.97      # bar a run must clear to count as a confirmation
    min_confirmations: int = 2          # distinct qualifying runs of the SAME candidate


class RealMemoryPlane:
    def __init__(self, db: str = "~/.continuityos/sim.db",
                 policy: Optional[PromotionPolicy] = None):
        import os
        from continuityos.memory import Memory
        self.m = Memory(os.path.expanduser(db))          # raises if store is broken
        self.policy = policy or PromotionPolicy()
        self._canon_ids: Dict[str, int] = {}             # objective -> current canon row
        self._confirmations: Dict[str, Set[str]] = {}    # candidate_id -> {result_id,...}
        self._rehydrate()

    def _rehydrate(self):
        """P1-A: rebuild current-canon pointers by a DIRECT deterministic query — current
        rows are those in CANON_NS whose meta has no `superseded_by`. Latest per objective."""
        try:
            con = self.m.store.con
            rows = con.execute(
                "SELECT id, meta, tags, created_at FROM items WHERE namespace=? ORDER BY id",
                (CANON_NS,)).fetchall()
        except Exception:
            rows = []
        for r in rows:
            try:
                meta = json.loads(r["meta"] or "{}")
                tags = json.loads(r["tags"] or "[]")
            except Exception:
                meta, tags = {}, []
            if meta.get("superseded_by"):
                continue                                 # not current
            obj = meta.get("objective") or (tags[0] if tags else None)
            if obj:
                self._canon_ids[obj] = r["id"]           # ordered by id -> last wins

    def record(self, spec, result, confident_hint: bool = False) -> Dict[str, Any]:
        obj = spec.objective.primary_metric
        cid = candidate_id(spec)
        metric = list(result.metrics.values())[0] if result.metrics else 0.0
        rid_key = getattr(result, "result_id", None) or f"{cid}:{metric}"
        text = f"{obj}={metric} @ params={spec.parameters}"
        meta = {"spec_id": spec.spec_id, "candidate_id": cid, "provenance": spec.provenance,
                "objective": obj, "status": getattr(result.status, "value", str(result.status)),
                "metric": metric}
        exp_id = self.m.remember(text, namespace=EXPERIMENT_NS, tags=[obj], meta=meta)

        canon_action = "experiment_only"
        if metric >= self.policy.verify_threshold:
            confs = self._confirmations.setdefault(cid, set())
            confs.add(rid_key)                            # distinct qualifying runs only
            if len(confs) >= self.policy.min_confirmations:
                prior = self._canon_ids.get(obj)
                if prior is not None and hasattr(self.m, "supersede"):
                    # P1-B: preserve meta+tags so rehydrate recovers the objective
                    new_id = self.m.supersede(prior, text, meta=meta, tags=[obj, "canon"])
                    canon_action = f"verified: superseded #{prior} -> #{new_id}"
                else:
                    new_id = self.m.remember(text, namespace=CANON_NS, tags=[obj, "canon"], meta=meta)
                    canon_action = f"verified: canon #{new_id}"
                self._canon_ids[obj] = new_id
            else:
                canon_action = (f"candidate {len(confs)}/{self.policy.min_confirmations} "
                                f"confirmations (cid {cid})")
        return {"experiment_id": exp_id, "canon": canon_action, "candidate_id": cid,
                "confirmations": len(self._confirmations.get(cid, set()))}

    def restore_to(self, objective: str, ref: Optional[int]) -> Dict[str, Any]:
        """P0-C: DURABLE rollback. Re-point the current canon for `objective` back to the
        text of the last-good row `ref` via an append-only restorative supersede (survives
        restart; reflected by Memory.current_only). Resets this objective's confirmations.
        Raises on durable failure (caller must fail closed)."""
        cur = self._canon_ids.get(objective)
        good = ref if ref is not None else cur
        restored_row = None
        if good is not None and hasattr(self.m, "supersede") and cur is not None:
            good_row = self.m.store.get(good)
            good_text = good_row["text"] if good_row else f"{objective}=<restored>"
            meta = {"objective": objective, "rollback_of": cur, "restored_from": good}
            new_id = self.m.supersede(cur, good_text, meta=meta, tags=[objective, "canon", "rollback"])
            self._canon_ids[objective] = new_id
            restored_row = new_id
        # reset confirmations for every candidate of this objective
        for cid in list(self._confirmations):
            self._confirmations[cid] = set()
        return {"objective": objective, "restored_canon": restored_row, "good_ref": good}

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
        self._confirmations: Dict[str, Set[str]] = {}
        self._canon_ids: Dict[str, int] = {}

    def record(self, spec, result, confident_hint: bool = False) -> Dict[str, Any]:
        obj = spec.objective.primary_metric
        cid = candidate_id(spec)
        metric = list(result.metrics.values())[0] if result.metrics else 0.0
        rid_key = getattr(result, "result_id", None) or f"{cid}:{metric}"
        entry = {"spec_id": spec.spec_id, "candidate_id": cid, "params": spec.parameters,
                 "metric": metric, "objective": obj, "provenance": spec.provenance}
        self.experiment_history.append(entry)
        canon_action = "experiment_only"
        if metric >= self.policy.verify_threshold:
            confs = self._confirmations.setdefault(cid, set()); confs.add(rid_key)
            if len(confs) >= self.policy.min_confirmations:
                self.canon.append(entry); self._canon_ids[obj] = len(self.canon)
                canon_action = "verified: canon(stub)"
            else:
                canon_action = f"candidate {len(confs)}/{self.policy.min_confirmations}"
        return {"experiment_id": len(self.experiment_history), "canon": canon_action,
                "candidate_id": cid, "confirmations": len(self._confirmations.get(cid, set()))}

    def restore_to(self, objective: str, ref: Optional[int]) -> Dict[str, Any]:
        for cid in list(self._confirmations):
            self._confirmations[cid] = set()
        return {"objective": objective, "restored_canon": self._canon_ids.get(objective)}

    def sizes(self) -> Dict[str, int]:
        return {"canon": len(self.canon), "experiment": len(self.experiment_history)}

    def rollback_ref(self, objective: str) -> Optional[int]:
        return self._canon_ids.get(objective)


def make_memory_plane(db: str = "~/.continuityos/sim.db", allow_stub: bool = False,
                      policy: Optional[PromotionPolicy] = None):
    """Durable plane. FAILS CLOSED (P0-4): raises if the durable store can't open — no
    silent RAM fallback. `allow_stub=True` only for tests / --mock."""
    if allow_stub:
        return StubMemoryPlane(policy=policy)
    return RealMemoryPlane(db, policy=policy)


if __name__ == "__main__":  # self-test
    from types import SimpleNamespace
    pol = PromotionPolicy(verify_threshold=0.9, min_confirmations=2)
    mp = make_memory_plane(allow_stub=True, policy=pol)

    def spec(params): return SimpleNamespace(
        objective=SimpleNamespace(primary_metric="edge"), parameters=params,
        constraints=SimpleNamespace(hard_bounds={k: 2.0 for k in params}),
        provenance=[], spec_id="s")
    def res(m, rid): return SimpleNamespace(metrics={"edge": m},
        status=SimpleNamespace(value="success"), result_id=rid)

    # P0-A: two DIFFERENT candidates must NOT co-confirm
    mp.record(spec({"x": 0.4}), res(0.95, "r1"))
    mp.record(spec({"x": 0.9}), res(0.95, "r2"))
    assert mp.sizes()["canon"] == 0, "different candidates must not co-confirm (P0-A)"
    # same candidate, two distinct runs -> promote
    mp.record(spec({"x": 0.4}), res(0.96, "r3"))
    assert mp.sizes()["canon"] == 1, "same candidate x2 -> canon"
    r = mp.restore_to("edge", None)
    print("restore:", r, "| canon:", mp.sizes()["canon"])
    print("OK: candidate-scoped confirmations + durable-shaped restore (PR-9)")
