"""Continuity layer — ContinuityOS is more than a memory store.

A continuity OS keeps the *thread* between sessions (and between versions of you
and versions of the model): slow truths (canon), live state (frontiers + open
loops), session checkpoints, anti-drift checks, and handoff packs. All of it is
just structured memory, so it shares the same local store and hybrid recall.

Reserved namespaces: `canon` (non-negotiable truths/rules), `frontier`
(trunk/cash/lab focus), `loop` (open loops), `checkpoint` (session deltas).
"""
from __future__ import annotations
import time, json
from typing import List, Dict, Any, Optional
from .memory import Memory

FRONTIER_KINDS = ("trunk", "cash", "lab", "parked")

class Continuity:
    def __init__(self, memory: Optional[Memory] = None, db: str = "continuityos.db",
                 *, read_only: bool = False):
        self.m = memory or Memory(db, read_only=read_only)

    # ---- canon: slow truths ----
    def add_canon(self, text: str, tags: Optional[List[str]] = None) -> int:
        return self.m.remember(text, namespace="canon", tags=tags or [])

    def canon(self) -> List[Dict[str, Any]]:
        return [r.to_dict() for r in self.m.recall("", k=100, namespace="canon")] or \
               self._dump("canon")

    # ---- frontiers: 1 trunk + 1 cash + 1 lab discipline ----
    def set_frontier(self, kind: str, item: str) -> int:
        kind = kind.lower()
        if kind not in FRONTIER_KINDS:
            raise ValueError(f"kind must be one of {FRONTIER_KINDS}")
        # supersede previous frontier of same kind (keep history via meta)
        return self.m.remember(item, namespace="frontier", tags=[kind],
                               meta={"kind": kind, "ts": time.time()})

    def frontiers(self) -> Dict[str, Optional[str]]:
        rows = self._dump("frontier")
        latest: Dict[str, Dict[str, Any]] = {}
        for r in rows:
            k = (r["meta"] or {}).get("kind") or (r["tags"][0] if r["tags"] else "parked")
            ts = (r["meta"] or {}).get("ts", 0)
            if k not in latest or ts >= latest[k]["meta"].get("ts", 0):
                latest[k] = r
        return {k: latest[k]["text"] for k in latest}

    # ---- open loops ----
    def add_loop(self, text: str, tags: Optional[List[str]] = None) -> int:
        return self.m.remember(text, namespace="loop", tags=(tags or []) + ["open"],
                               meta={"open": True, "ts": time.time()})

    def close_loop(self, loop_id: int) -> bool:
        return self.m.forget(loop_id)

    def open_loops(self) -> List[Dict[str, Any]]:
        return [r for r in self._dump("loop")]

    # ---- checkpoints: every session ends with delta + next + proof ----
    def checkpoint(self, summary: str, next_action: str, proof: str = "") -> int:
        text = f"DELTA: {summary} | NEXT: {next_action}" + (f" | PROOF: {proof}" if proof else "")
        return self.m.remember(text, namespace="checkpoint",
                               tags=["checkpoint"], meta={"ts": time.time(),
                               "summary": summary, "next": next_action, "proof": proof})

    def last_checkpoint(self) -> Optional[Dict[str, Any]]:
        rows = sorted(self._dump("checkpoint"), key=lambda r: (r["meta"] or {}).get("ts", 0), reverse=True)
        return rows[0] if rows else None

    # ---- anti-drift doctor ----
    def doctor(self, max_open_loops: int = 7, checkpoint_stale_hours: float = 48) -> Dict[str, Any]:
        fr = self.frontiers()
        loops = self.open_loops()
        last = self.last_checkpoint()
        now = time.time()
        checks = []
        def chk(ok, name, detail): checks.append({"ok": bool(ok), "check": name, "detail": detail})
        chk("cash" in fr, "cash_frontier_set", fr.get("cash", "— not set"))
        chk("trunk" in fr, "trunk_set", fr.get("trunk", "— not set"))
        chk(len(loops) <= max_open_loops, "open_loops_bounded", f"{len(loops)} open (max {max_open_loops})")
        if last:
            age_h = (now - (last["meta"] or {}).get("ts", now)) / 3600
            chk(age_h <= checkpoint_stale_hours, "checkpoint_fresh", f"{age_h:.1f}h old")
            chk(bool((last["meta"] or {}).get("proof")), "has_proof", (last["meta"] or {}).get("proof") or "— no proof")
        else:
            chk(False, "checkpoint_fresh", "no checkpoint yet")
            chk(False, "has_proof", "no checkpoint yet")
        # L6 autopoiesis — self-maintenance invariants (system "alive")
        chk(self.m.count() > 0, "memory_persists", f"{self.m.count()} memories")
        chk(len(self._dump("canon")) > 0, "identity_persists", "canon present" )
        chk(len(loops) > 0, "purpose_persists", f"{len(loops)} open loop(s)")
        passed = sum(1 for c in checks if c["ok"])
        return {"healthy": passed == len(checks), "passed": passed, "total": len(checks), "checks": checks}

    # ---- handoff pack: context for the next session / agent ----
    def handoff(self) -> str:
        fr = self.frontiers()
        loops = self.open_loops()
        last = self.last_checkpoint()
        canon = self._dump("canon")
        out = ["# ContinuityOS handoff pack"]
        out.append("\n## Canon (non-negotiable)")
        out += [f"- {c['text']}" for c in canon[:12]] or ["- (none)"]
        out.append("\n## Frontiers")
        out += [f"- {k}: {v}" for k, v in fr.items()] or ["- (none)"]
        out.append("\n## Open loops")
        out += [f"- [#{l['id']}] {l['text']}" for l in loops[:20]] or ["- (none)"]
        out.append("\n## Last checkpoint")
        out.append(f"- {last['text']}" if last else "- (none)")
        return "\n".join(out)

    def _dump(self, namespace: str) -> List[Dict[str, Any]]:
        rows = self.m.store.all_with_vecs(namespace=namespace)
        import json as _j
        return [{"id": r["id"], "text": r["text"], "namespace": r["namespace"],
                 "tags": _j.loads(r["tags"]), "meta": _j.loads(r["meta"])} for r in rows]
