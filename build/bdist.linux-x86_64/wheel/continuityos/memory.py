"""Memory facade: the one class agents and humans use.

    m = Memory("mybrain.db")
    m.remember("Robert prefers Apache-2.0 licenses", namespace="rules", tags=["license"])
    hits = m.recall("what license should I pick?")

`recall` is HYBRID: it blends structural keyword (FTS) hits with semantic
(vector cosine) hits, so it finds the right memory whether you match words or
meaning. Returns ranked MemoryItem list.
"""
from __future__ import annotations
import json
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any, Callable
from .store import Store, unpack_vec
from .embed import HashingEmbedder, cosine

# Conventional folder-like namespaces (free to invent your own)
CORE_NAMESPACES = ["identity", "projects", "rules", "facts", "events", "notes"]

@dataclass
class MemoryItem:
    id: int
    text: str
    namespace: str
    tags: List[str] = field(default_factory=list)
    meta: Dict[str, Any] = field(default_factory=dict)
    score: float = 0.0
    why: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"id": self.id, "text": self.text, "namespace": self.namespace,
                "tags": self.tags, "meta": self.meta,
                "score": round(self.score, 4), "why": self.why}

class Memory:
    def __init__(self, path: str = "continuityos.db",
                 embedder: Optional[Callable[[str], List[float]]] = None,
                 semantic_weight: float = 0.6):
        self.store = Store(path)
        self.embed = embedder or HashingEmbedder()
        self.semantic_weight = semantic_weight  # 0=keyword only, 1=semantic only

    # ---- write ----
    def remember(self, text: str, namespace: str = "notes",
                 tags: Optional[List[str]] = None, meta: Optional[Dict[str, Any]] = None) -> int:
        vec = self.embed(text)
        return self.store.add(text, namespace=namespace, tags=tags, meta=meta, vec=vec)

    def forget(self, item_id: int) -> bool:
        return self.store.delete(item_id)

    # ---- read ----
    def recall(self, query: str, k: int = 5, namespace: Optional[str] = None) -> List[MemoryItem]:
        sw = self.semantic_weight
        scores: Dict[int, Dict[str, Any]] = {}

        # structural / keyword leg
        for rank, row in enumerate(self.store.keyword_search(query, namespace=namespace, limit=50)):
            kw = 1.0 / (1.0 + rank)  # reciprocal-rank
            scores.setdefault(row["id"], {"row": row, "kw": 0.0, "sem": 0.0})["kw"] = kw

        # semantic leg
        qv = self.embed(query)
        sem_rows = self.store.all_with_vecs(namespace=namespace)
        sims = []
        for row in sem_rows:
            sim = cosine(qv, unpack_vec(row["vec"]))
            sims.append((sim, row))
        sims.sort(key=lambda x: x[0], reverse=True)
        for sim, row in sims[:50]:
            scores.setdefault(row["id"], {"row": row, "kw": 0.0, "sem": 0.0})["sem"] = max(0.0, sim)

        out: List[MemoryItem] = []
        for rid, d in scores.items():
            row = d["row"]
            final = sw * d["sem"] + (1 - sw) * d["kw"]
            legs = []
            if d["sem"] > 0: legs.append("semantic %.2f" % d["sem"])
            if d["kw"] > 0:  legs.append("keyword")
            out.append(MemoryItem(
                id=rid, text=row["text"], namespace=row["namespace"],
                tags=json.loads(row["tags"]), meta=json.loads(row["meta"]),
                score=final, why=" + ".join(legs)))
        out.sort(key=lambda x: x.score, reverse=True)
        return out[:k]

    # ---- structure ----
    def namespaces(self) -> List[Dict[str, Any]]:
        return self.store.namespaces()

    def context(self, query: str, k: int = 6) -> str:
        """Render a ready-to-inject context block for an agent prompt."""
        hits = self.recall(query, k=k)
        if not hits:
            return ""
        lines = ["# Relevant memory (ContinuityOS)"]
        for h in hits:
            lines.append(f"- [{h.namespace}] {h.text}  ({h.why})")
        return "\n".join(lines)

    def count(self) -> int:
        return self.store.count()
