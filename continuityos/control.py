"""L5 Control Plane — operator actions over memory (from Twin admin-control-plane spec).

corrections, redaction (privacy), rollback to a checkpoint, and a transparency
export (what is stored about whom). Every control action is itself recorded.
"""
from __future__ import annotations
import time, json
from typing import List, Dict, Any, Optional
from .memory import Memory

class ControlPlane:
    def __init__(self, memory: Optional[Memory] = None, db: str = "continuityos.db"):
        self.m = memory or Memory(db)

    def correct(self, item_id: int, new_text: str, namespace: str = "notes") -> int:
        """Supersede a memory: forget the old, store the corrected one, log it."""
        old = self.m.store.get(item_id)
        self.m.forget(item_id)
        rid = self.m.remember(new_text, namespace=namespace, tags=["corrected"],
                              meta={"corrects": item_id})
        self.m.remember(f"correction of #{item_id} -> #{rid}", namespace="control",
                        tags=["control","correct"], meta={"ts": time.time()})
        return rid

    def redact(self, query: str, namespace: Optional[str] = None) -> int:
        """Privacy: delete memories matching a query. Returns count removed."""
        hits = self.m.recall(query, k=100, namespace=namespace)
        n = 0
        for h in hits:
            if h.score > 0.2:
                self.m.forget(h.id); n += 1
        self.m.remember(f"redacted {n} memories matching '{query}'", namespace="control",
                        tags=["control","redact"], meta={"ts": time.time(), "count": n})
        return n

    def rollback(self, checkpoint_id: int) -> Dict[str, Any]:
        """Revert state created AFTER a checkpoint: forget loop/frontier/checkpoint items newer than it."""
        cp = self.m.store.get(checkpoint_id)
        if not cp:
            return {"ok": False, "error": "checkpoint not found"}
        cutoff = cp["created_at"]
        removed = 0
        for ns in ("loop", "frontier", "checkpoint", "notes"):
            for r in self.m.store.all_with_vecs(namespace=ns):
                if r["created_at"] > cutoff:
                    self.m.forget(r["id"]); removed += 1
        self.m.remember(f"rollback to checkpoint #{checkpoint_id}, removed {removed} newer items",
                        namespace="control", tags=["control","rollback"], meta={"ts": time.time()})
        return {"ok": True, "checkpoint": checkpoint_id, "removed": removed}

    def export(self) -> Dict[str, Any]:
        """Transparency: what is stored, by namespace (consent / data-subject view)."""
        return {"namespaces": self.m.namespaces(), "total": self.m.count(),
                "note": "All data is local. Use redact() to remove, correct() to fix."}
