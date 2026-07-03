"""Memory facade: the one class agents and humans use.

    m = Memory("mybrain.db")
    m.remember("Robert prefers Apache-2.0 licenses", namespace="rules", tags=["license"])
    hits = m.recall("what license should I pick?")

`recall` is HYBRID: it blends structural keyword (FTS) hits with semantic
(vector cosine) hits, so it finds the right memory whether you match words or
meaning. Returns ranked MemoryItem list.
"""
from __future__ import annotations
import json, time
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any, Callable
from .store import Store, unpack_vec
from .index import rank as _rank
from .embed import HashingEmbedder

# Conventional folder-like namespaces (free to invent your own)
CORE_NAMESPACES = ["identity", "projects", "rules", "facts", "events", "notes"]

# Frontier model registry (mid-2026 landscape research). Pricing = USD per million
# tokens; context = max input window. Used by estimate_tokens/estimate_cost so callers
# can cost-route ("commodity → interactive → high-stakes") instead of always paying top tier.
MODEL_REGISTRY = {
    "claude-fable-5":   {"vendor": "anthropic", "in_per_mtok": 10.0, "out_per_mtok": 50.0, "context": 1_000_000, "char_per_tok": 3.5},
    "claude-mythos-5":  {"vendor": "anthropic", "in_per_mtok": 10.0, "out_per_mtok": 50.0, "context": 1_000_000, "char_per_tok": 3.5},
    "claude-opus-4-8":  {"vendor": "anthropic", "in_per_mtok": 5.0,  "out_per_mtok": 25.0, "context": 1_000_000, "char_per_tok": 3.5},
    "claude-haiku-4-5": {"vendor": "anthropic", "in_per_mtok": 1.0,  "out_per_mtok": 5.0,  "context": 1_000_000, "char_per_tok": 3.5},
    "gpt-5.5":          {"vendor": "openai",    "in_per_mtok": 5.0,  "out_per_mtok": 30.0, "context": 1_050_000, "char_per_tok": 3.9},
    "gemini-3.1-pro":   {"vendor": "google",    "in_per_mtok": 2.0,  "out_per_mtok": 12.0, "context": 1_000_000, "char_per_tok": 4.0},
    "gemini-3.5-flash": {"vendor": "google",    "in_per_mtok": 0.5,  "out_per_mtok": 3.0,  "context": 1_000_000, "char_per_tok": 4.0},
    "grok-4.3":         {"vendor": "xai",       "in_per_mtok": 1.25, "out_per_mtok": 2.0,  "context": 1_000_000, "char_per_tok": 3.8},
    "deepseek-v4-pro":  {"vendor": "deepseek",  "in_per_mtok": 0.435,"out_per_mtok": 1.2,  "context": 1_000_000, "char_per_tok": 3.6},
}

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

def _valid(meta: Dict[str, Any], created_at: float, as_of: Optional[float],
           current_only: bool, mtype: Optional[str]) -> bool:
    """Bi-temporal + type filter. valid_from defaults to created_at (a fact is assumed true
    from the moment we learned it unless told otherwise); open valid_to = still true."""
    if mtype and meta.get("type") != mtype:
        return False
    vf = meta.get("valid_from", created_at)
    vt = meta.get("valid_to")
    if as_of is not None:
        return vf <= as_of and (vt is None or as_of < vt)
    if current_only:
        return vt is None and "superseded_by" not in meta
    return True

class Memory:
    def __init__(self, path: str = "continuityos.db",
                 embedder: Optional[Callable[[str], List[float]]] = None,
                 semantic_weight: float = 0.6):
        self.store = Store(path)
        if embedder is None:
            import os as _os
            if not _os.environ.get("CONTINUITYOS_SILENCE_EMBED_WARN"):
                import sys as _sys
                print("[continuityos] using zero-dep HashingEmbedder (weak semantic recall). "
                      "For real synonym/paraphrase matching: pip install 'continuityos[fast]'. "
                      "Silence: CONTINUITYOS_SILENCE_EMBED_WARN=1", file=_sys.stderr)
        self.embed = embedder or HashingEmbedder()
        self.semantic_weight = semantic_weight  # 0=keyword only, 1=semantic only

    # ---- write ----
    def remember(self, text: str, namespace: str = "notes",
                 tags: Optional[List[str]] = None, meta: Optional[Dict[str, Any]] = None,
                 mtype: Optional[str] = None, valid_from: Optional[float] = None,
                 valid_to: Optional[float] = None, supersedes: Optional[int] = None) -> int:
        """Store a fact. Bi-temporal (Zep pattern): valid_from/valid_to bound when the fact
        is TRUE in the world, distinct from created_at (= when we learned it). mtype = semantic
        type (Memanto pattern: fact/preference/decision/goal/event/learning/error).
        supersedes=<id> closes the old fact's validity now and links both ways — nothing is
        ever deleted (append-only)."""
        meta = dict(meta or {})
        if mtype: meta["type"] = mtype
        if valid_from is not None: meta["valid_from"] = float(valid_from)
        if valid_to is not None: meta["valid_to"] = float(valid_to)
        if supersedes is not None: meta["supersedes"] = int(supersedes)
        vec = self.embed(text)
        rid = self.store.add(text, namespace=namespace, tags=tags, meta=meta, vec=vec)
        if supersedes is not None:
            old = self.store.get(int(supersedes))
            if old is not None:
                om = json.loads(old["meta"])
                om.setdefault("valid_to", time.time())
                om["superseded_by"] = rid
                self.store.update_meta(int(supersedes), om)
        return rid

    def supersede(self, old_id: int, text: str, **kw) -> int:
        """Replace a fact: the new version becomes current, the old one keeps history with a
        closed validity window (Mem0 v3 ADD-only spirit: corrections never destroy)."""
        old = self.store.get(old_id)
        if old is not None and "namespace" not in kw:
            kw["namespace"] = old["namespace"]
        return self.remember(text, supersedes=old_id, **kw)

    def forget(self, item_id: int) -> bool:
        return self.store.delete(item_id)

    # ---- read ----
    def recall(self, query: str, k: int = 5, namespace: Optional[str] = None,
               as_of: Optional[float] = None, current_only: bool = False,
               mtype: Optional[str] = None) -> List[MemoryItem]:
        """Hybrid recall + bi-temporal filters: as_of=<ts> answers what was true THEN;
        current_only=True hides superseded/expired facts; mtype filters by semantic type."""
        sw = self.semantic_weight
        scores: Dict[int, Dict[str, Any]] = {}

        # structural / keyword leg
        for rank, row in enumerate(self.store.keyword_search(query, namespace=namespace, limit=50)):
            kw = 1.0 / (1.0 + rank)  # reciprocal-rank
            scores.setdefault(row["id"], {"row": row, "kw": 0.0, "sem": 0.0})["kw"] = kw

        # semantic leg (vectorized via best available backend)
        qv = self.embed(query)
        sem_rows = self.store.all_with_vecs(namespace=namespace)
        cand = [{"row": r, "vec": unpack_vec(r["vec"])} for r in sem_rows]
        for sim, c in _rank(qv, cand, top=50):
            row = c["row"]
            scores.setdefault(row["id"], {"row": row, "kw": 0.0, "sem": 0.0})["sem"] = max(0.0, sim)

        out: List[MemoryItem] = []
        for rid, d in scores.items():
            row = d["row"]
            meta = json.loads(row["meta"])
            if not _valid(meta, row["created_at"], as_of, current_only, mtype):
                continue
            final = sw * d["sem"] + (1 - sw) * d["kw"]
            legs = []
            if d["sem"] > 0: legs.append("semantic %.2f" % d["sem"])
            if d["kw"] > 0:  legs.append("keyword")
            out.append(MemoryItem(
                id=rid, text=row["text"], namespace=row["namespace"],
                tags=json.loads(row["tags"]), meta=meta,
                score=final, why=" + ".join(legs)))
        out.sort(key=lambda x: x.score, reverse=True)
        return out[:k]

    # ---- structure ----
    def namespaces(self) -> List[Dict[str, Any]]:
        return self.store.namespaces()

    def estimate_tokens(self, text: str, model_id: str = "claude-opus-4-8") -> int:
        """Token count for budgeting. Exact via Anthropic count_tokens if SDK+key present
        (tiktoken under-counts Claude 15-20%, per token-optimization research); else a
        conservative char estimate. Stdlib-only at import time."""
        try:
            import os as _os
            if _os.environ.get("ANTHROPIC_API_KEY") and model_id in MODEL_REGISTRY \
               and MODEL_REGISTRY[model_id].get("vendor") == "anthropic":
                from anthropic import Anthropic
                return Anthropic().messages.count_tokens(
                    model=model_id, messages=[{"role": "user", "content": text}]).input_tokens
        except Exception:
            pass
        # vendor-aware char/token ratio (closed tokenizers differ slightly; values are
        # conservative defaults, refined from the mid-2026 model-landscape research)
        ratio = MODEL_REGISTRY.get(model_id, {}).get("char_per_tok", 3.5)
        return int(len(text) / ratio) + 1

    def estimate_cost(self, text: str, model_id: str = "claude-opus-4-8",
                      output_tokens: int = 0) -> dict:
        """Budget the $ cost of injecting `text` as input (+ optional output) on a given
        model. Pricing from the mid-2026 landscape research (USD per million tokens).
        Returns tokens + cost so callers can route to the cheapest sufficient model."""
        m = MODEL_REGISTRY.get(model_id, MODEL_REGISTRY["claude-opus-4-8"])
        intok = self.estimate_tokens(text, model_id)
        cost = intok / 1e6 * m["in_per_mtok"] + output_tokens / 1e6 * m["out_per_mtok"]
        return {"model": model_id, "input_tokens": intok, "output_tokens": output_tokens,
                "usd": round(cost, 6), "context_window": m["context"]}

    def context(self, query: str, k: int = 6, max_tokens=None, compact: bool = False) -> str:
        """Ready-to-inject context block. Token-budget aware (max_tokens): packs the most
        relevant memories until the budget is hit, so recall stays cheap. compact=True drops
        annotations. Deterministic order = prompt-cache-stable."""
        hits = self.recall(query, k=k if not max_tokens else max(k, 20))
        if not hits:
            return ""
        header = "# Relevant memory (ContinuityOS)"
        lines = [header]
        budget = None if max_tokens is None else max_tokens - self.estimate_tokens(header)
        used = 0
        for h in hits:
            line = (f"- [{h.namespace}] {h.text}" if compact
                    else f"- [{h.namespace}] {h.text}  ({h.why})")
            if budget is not None:
                t = self.estimate_tokens(line)
                if used + t > budget:
                    break
                used += t
            lines.append(line)
            if max_tokens is None and len(lines) - 1 >= k:
                break
        return "\n".join(lines)

    def count(self) -> int:
        return self.store.count()
