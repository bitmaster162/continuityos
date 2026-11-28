"""Memory facade: the one class agents and humans use.

    m = Memory("mybrain.db")
    m.remember("Robert prefers Apache-2.0 licenses", namespace="rules", tags=["license"])
    hits = m.recall("what license should I pick?")

`recall` is HYBRID: it blends structural keyword (FTS) hits with semantic
(vector cosine) hits, so it finds the right memory whether you match words or
meaning. Returns ranked MemoryItem list.
"""
from __future__ import annotations
import json, time, math
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any, Callable
from .store import Store, unpack_vec
from .index import rank as _rank
from .embed import HashingEmbedder

# Conventional folder-like namespaces (free to invent your own)
CORE_NAMESPACES = ["identity", "projects", "rules", "facts", "events", "notes"]

# Legacy static configuration, retained for compatibility, not verified provider
# specifications or a current price feed. Rates are USD per million tokens.
# Callers must verify model identity, rates and limits before making decisions.
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

# Legacy name retained for import compatibility. These are uncalibrated local
# budget settings, not measured maximum effective context windows. No measurement
# receipt is bundled with these numbers. Prefer an explicit caller context budget.
MECW = {
    "claude-opus-4-8": 185_000, "claude-fable-5": 900_000, "claude-mythos-5": 900_000,
    "claude-haiku-4-5": 185_000, "gpt-5.5": 980_000, "gemini-3.1-pro": 920_000,
    "gemini-3.5-flash": 920_000, "grok-4.3": 900_000, "deepseek-v4-pro": 105_000,
}

class Conflict(Exception):
    """Raised by write_checked() on an optimistic-concurrency version mismatch."""


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
           current_only: bool, mtype: Optional[str], now: Optional[float] = None) -> bool:
    """Bi-temporal + type filter. valid_from defaults to created_at (a fact is assumed true
    from the moment we learned it unless told otherwise); open valid_to = still true."""
    if mtype and meta.get("type") != mtype:
        return False
    if as_of is None and not current_only:
        return True
    vf = meta.get("valid_from", created_at)
    vt = meta.get("valid_to")
    at = as_of if as_of is not None else (time.time() if now is None else now)
    if any(isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value)
           for value in (vf, at)):
        return False
    if vt is not None and (isinstance(vt, bool) or not isinstance(vt, (int, float)) or not math.isfinite(vt)):
        return False
    if as_of is None and (meta.get("active") is False or str(meta.get("status", "")).upper() in {
            "SUPERSEDED", "REVOKED", "REJECTED", "DELETED", "EXPIRED"}):
        return False
    valid_at = vf <= at and (vt is None or at < vt)
    return valid_at and (as_of is not None or "superseded_by" not in meta)


def _scope_matches(meta: Dict[str, Any], scope: Optional[Dict[str, Any]],
                   include_global: bool = False) -> bool:
    if scope is None:
        return True
    if include_global and all(meta.get(key) is None for key in ("project", "subject")):
        return True
    return all(meta.get(key) == value for key, value in scope.items())

class Memory:
    def __init__(self, path: str = "continuityos.db",
                 embedder: Optional[Callable[[str], List[float]]] = None,
                 semantic_weight: float = 0.6, *, read_only: bool = False):
        self.store = Store(path, read_only=read_only)
        if embedder is None:
            import os as _os
            if not _os.environ.get("CONTINUITYOS_SILENCE_EMBED_WARN"):
                import sys as _sys
                print("[continuityos] using zero-dep HashingEmbedder (weak semantic recall). "
                      "For real synonym/paraphrase matching: pip install 'continuityos[fast]'. "
                      "Silence: CONTINUITYOS_SILENCE_EMBED_WARN=1", file=_sys.stderr)
        self.embed = HashingEmbedder() if embedder is None else embedder
        if not callable(self.embed):
            self.store.con.close()
            raise TypeError("embedder must be callable")
        self.semantic_weight = semantic_weight  # 0=keyword only, 1=semantic only

    # ---- write ----
    def remember(self, text: str, namespace: str = "notes",
                 tags: Optional[List[str]] = None, meta: Optional[Dict[str, Any]] = None,
                 mtype: Optional[str] = None, valid_from: Optional[float] = None,
                 valid_to: Optional[float] = None, supersedes: Optional[int] = None,
                 key: Optional[str] = None) -> int:
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
        with self.store.transaction():
            old = None
            if supersedes is not None:
                old = self.store.get(int(supersedes))
                if old is None:
                    raise ValueError("MEMORY_PREDECESSOR_NOT_FOUND")
                om = json.loads(old["meta"])
                if "superseded_by" in om:
                    raise Conflict("MEMORY_PREDECESSOR_ALREADY_SUPERSEDED")
            rid = self.store.add(text, namespace=namespace, tags=tags, meta=meta, vec=vec, key=key)
            if old is not None:
                end = time.time()
                if om.get("valid_to") is not None:
                    end = min(end, float(om["valid_to"]))
                om["valid_to"] = end
                om["superseded_by"] = rid
                self.store.update_meta(int(supersedes), om)
            return rid

    def supersede(self, old_id: int, text: str, **kw) -> int:
        """Replace a fact: the new version becomes current, the old one keeps history with a
        closed validity window (Mem0 v3 ADD-only spirit: corrections never destroy)."""
        with self.store.transaction():
            old = self.store.get(old_id)
            if old is None:
                raise ValueError("MEMORY_PREDECESSOR_NOT_FOUND")
            kw.setdefault("namespace", old["namespace"])
            if old["key"] is not None and kw["namespace"] == old["namespace"]:
                kw.setdefault("key", old["key"])
            return self.remember(text, supersedes=old_id, **kw)

    def find(self, namespace: str, key: str) -> Optional[MemoryItem]:
        """Exact key-based point read: the current value under (namespace, key), or None.
        Deterministic O(log n) — unlike recall(), which is ranked/fuzzy. (HMOS upstream.)"""
        row = self.store.find_by_key(namespace, key)
        if row is None:
            return None
        meta = json.loads(row["meta"])
        if "superseded_by" in meta:            # newest row was retired without a re-key
            return None
        return MemoryItem(id=row["id"], text=row["text"], namespace=row["namespace"],
                          tags=json.loads(row["tags"]), meta=meta, score=1.0, why="key")

    def upsert(self, text: str, namespace: str, key: str, **kw) -> int:
        """CREATE-or-UPDATE by semantic key. If (namespace, key) already exists, the old value
        is superseded (append-only: history kept, validity closed) and the new becomes current;
        otherwise a new keyed memory is created. Returns the (new) id. (HMOS upstream.)"""
        with self.store.transaction():
            existing = self.store.find_by_key(namespace, key)
            if existing is not None and "superseded_by" not in json.loads(existing["meta"]):
                return self.supersede(existing["id"], text, namespace=namespace, key=key, **kw)
            return self.remember(text, namespace=namespace, key=key, **kw)

    def pointer(self, namespace: str, key: str) -> Optional[Dict[str, Any]]:
        """Pass-by-reference: return a lightweight {namespace,key,version} pointer to the current
        value (no content), or None. Agents can hand each other pointers instead of copying whole
        documents into context (A2A \"courier tax\" fix; keeps injected text out of the planner)."""
        row = self.store.find_by_key(namespace, key)
        if row is None or "superseded_by" in json.loads(row["meta"]):
            return None
        return {"namespace": namespace, "key": key, "version": row["version"]}

    def resolve(self, ptr: Dict[str, Any]) -> Optional[MemoryItem]:
        """Dereference a pointer to its current MemoryItem."""
        return self.find(ptr["namespace"], ptr["key"])

    def write_checked(self, text: str, namespace: str, key: str, expected_version: int, **kw) -> int:
        """Optimistic-concurrency write: only succeeds if the current version equals
        expected_version, else raises Conflict (the caller re-reads and retries). Prevents
        lost updates / stale-read poisoning when multiple agents write the same key."""
        if type(expected_version) is not int or expected_version < 0:
            raise ValueError("expected_version must be a non-negative integer")
        with self.store.transaction():
            cur = self.store.current_version(namespace, key)
            if cur != expected_version:
                raise Conflict("OCC conflict on %s/%s: current v%d, expected v%d" % (namespace, key, cur, expected_version))
            return self.upsert(text, namespace=namespace, key=key, **kw)

    def forget(self, item_id: int) -> bool:
        return self.store.delete(item_id)

    # ---- read ----
    def recall(self, query: str, k: int = 5, namespace: Optional[str] = None,
               as_of: Optional[float] = None, current_only: bool = False,
               mtype: Optional[str] = None, *, scope: Optional[Dict[str, Any]] = None,
               include_global: bool = False, exclude_unreviewed: bool = False) -> List[MemoryItem]:
        """Hybrid recall + bi-temporal filters: as_of=<ts> answers what was true THEN;
        current_only=True hides superseded/expired facts; mtype filters by semantic type."""
        with self.store.read_snapshot():
            return self._recall_snapshot(query, k, namespace, as_of, current_only, mtype,
                                         scope, include_global, exclude_unreviewed)

    def _recall_snapshot(self, query, k, namespace, as_of, current_only, mtype,
                         scope, include_global, exclude_unreviewed):
        sw = self.semantic_weight
        scores: Dict[int, Dict[str, Any]] = {}
        now = time.time()
        if scope is not None and (not isinstance(scope, dict) or not set(scope) <= {"project", "subject"}):
            raise ValueError("scope supports project and subject only")

        def eligible(row):
            meta = json.loads(row["meta"])
            if exclude_unreviewed and (meta.get("accepted") is False
                    or meta.get("review_status") in {"UNREVIEWED", "REJECTED"}
                    or meta.get("admission_status") in {"CANDIDATE", "QUARANTINED"}):
                return False
            return (_valid(meta, row["created_at"], as_of, current_only, mtype, now)
                    and _scope_matches(meta, scope, include_global))

        # structural / keyword leg
        filtered = as_of is not None or current_only or mtype is not None or scope is not None or exclude_unreviewed
        keywords = self.store.keyword_search(query, namespace=namespace, limit=None if filtered else 50)
        keywords = [row for row in keywords if eligible(row)][:50]
        for rank, row in enumerate(keywords):
            kw = 1.0 / (1.0 + rank)  # reciprocal-rank
            scores.setdefault(row["id"], {"row": row, "kw": 0.0, "sem": 0.0})["kw"] = kw

        # semantic leg (vectorized via best available backend)
        qv = self.embed(query)
        sem_rows = self.store.all_with_vecs(namespace=namespace)
        cand = [{"row": r, "vec": unpack_vec(r["vec"])} for r in sem_rows if eligible(r)]
        for sim, c in _rank(qv, cand, top=50):
            row = c["row"]
            scores.setdefault(row["id"], {"row": row, "kw": 0.0, "sem": 0.0})["sem"] = max(0.0, sim)

        out: List[MemoryItem] = []
        for rid, d in scores.items():
            row = d["row"]
            meta = json.loads(row["meta"])
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

    def estimate_tokens(self, text: str, model_id: str = "claude-opus-4-8", *,
                        allow_network: bool = False, provider: Optional[str] = None,
                        data_scope: Optional[str] = None) -> int:
        """Local estimate by default, regardless of installed SDKs or credentials.

        Remote counting requires per-call opt-in, an exact provider and a caller
        data-scope declaration. That declaration is not an authority grant; the
        current-session effect ceiling still applies. Remote errors propagate.
        """
        if type(allow_network) is not bool:
            raise TypeError("allow_network must be bool")
        if allow_network:
            if provider != "anthropic" or MODEL_REGISTRY.get(model_id, {}).get("vendor") != "anthropic":
                raise ValueError("REMOTE_TOKEN_PROVIDER_MODEL_MISMATCH")
            if not isinstance(data_scope, str) or not data_scope.strip():
                raise ValueError("REMOTE_TOKEN_DATA_SCOPE_REQUIRED")
            from .current_effect_boundary import assert_current_effect_allowed
            assert_current_effect_allowed("network.anthropic.count_tokens")
            from anthropic import Anthropic
            return Anthropic().messages.count_tokens(
                model=model_id, messages=[{"role": "user", "content": text}]).input_tokens
        # Local character estimate; the configured ratio is not an exact tokenizer
        # or a proven upper bound, particularly for multilingual/code content.
        ratio = MODEL_REGISTRY.get(model_id, {}).get("char_per_tok", 3.5)
        return int(len(text) / ratio) + 1

    def estimate_cost(self, text: str, model_id: str = "claude-opus-4-8",
                      output_tokens: int = 0, *, allow_network: bool = False,
                      provider: Optional[str] = None, data_scope: Optional[str] = None) -> dict:
        """Arithmetic using unverified static rates, not a current price quote.

        Unknown models fail explicitly instead of inheriting another model's
        pricing. Default token counts are approximate and remain local.
        """
        if model_id not in MODEL_REGISTRY:
            raise ValueError("UNCONFIGURED_MODEL_PRICING")
        if type(output_tokens) is not int or output_tokens < 0:
            raise ValueError("output_tokens must be a non-negative integer")
        m = MODEL_REGISTRY[model_id]
        intok = self.estimate_tokens(text, model_id, allow_network=allow_network,
                                    provider=provider, data_scope=data_scope)
        cost = intok / 1e6 * m["in_per_mtok"] + output_tokens / 1e6 * m["out_per_mtok"]
        return {"model": model_id, "input_tokens": intok, "output_tokens": output_tokens,
                "usd": round(cost, 6), "context_window": m["context"],
                "pricing_kind": "UNVERIFIED_STATIC_CONFIGURATION", "pricing_verified": False,
                "token_count_kind": "PROVIDER_COUNT" if allow_network else "LOCAL_CHARACTER_ESTIMATE",
                "model_metadata_verified": False}

    def compaction_policy(self, model_id: str = "claude-opus-4-8", frac: float = 0.65, *,
                          context_tokens: Optional[int] = None) -> Dict[str, Any]:
        """Expose the source of a local budget; no universal safe threshold is claimed."""
        if isinstance(frac, bool) or not isinstance(frac, (int, float)) or not math.isfinite(frac) or not 0 < frac <= 1:
            raise ValueError("frac must be finite and within (0, 1]")
        if context_tokens is not None:
            if type(context_tokens) is not int or context_tokens < 1:
                raise ValueError("context_tokens must be a positive integer")
            budget, basis = context_tokens, "CALLER_CONTEXT_BUDGET"
        elif model_id in MECW:
            budget, basis = MECW[model_id], "LEGACY_UNCALIBRATED_CONFIGURATION"
        else:
            configured = MODEL_REGISTRY.get(model_id, MODEL_REGISTRY["claude-opus-4-8"])
            budget, basis = int(configured.get("context", 200_000) * 0.92), "LEGACY_UNCALIBRATED_FALLBACK"
        return {"model": model_id, "context_budget_tokens": budget,
                "fraction": frac, "threshold_tokens": int(budget * frac), "basis": basis,
                "calibrated": False, "measurement_receipt": None, "authority_granted": False}

    def compaction_threshold(self, model_id: str = "claude-opus-4-8", frac: float = 0.65, *,
                             context_tokens: Optional[int] = None) -> int:
        """Compatibility integer view of compaction_policy; not a proven safe limit."""
        return self.compaction_policy(model_id, frac, context_tokens=context_tokens)["threshold_tokens"]

    def context(self, query: str, k: int = 6, max_tokens=None, compact: bool = False, *,
                current_only: bool = True, as_of: Optional[float] = None,
                scope: Optional[Dict[str, Any]] = None) -> str:
        """Ready-to-inject context block. Token-budget aware (max_tokens): packs the most
        relevant memories until the budget is hit, so recall stays cheap. compact=True drops
        annotations. Deterministic order = prompt-cache-stable."""
        hits = self.recall(query, k=k if not max_tokens else max(k, 20),
                           current_only=current_only, as_of=as_of, scope=scope)
        if not hits:
            return ""
        header = "# Relevant memory (ContinuityOS)"
        lines = [header]
        budget = None if max_tokens is None else max_tokens - self.estimate_tokens(header)
        if budget is not None and budget < 0:
            return ""
        used = 0
        for h in hits:
            state = h.meta.get("review_status", "RECORDED_NOT_VERIFIED")
            if h.meta.get("accepted") is False or h.meta.get("admission_status") == "CANDIDATE":
                state = "UNREVIEWED_CANDIDATE"
            annotation = f"mem:{h.id} {h.namespace}; {state}"
            line = (f"- [{annotation}] {h.text}" if compact
                    else f"- [{annotation}] {h.text}  ({h.why})")
            if budget is not None:
                t = self.estimate_tokens(line)
                if used + t > budget:
                    continue
                used += t
            lines.append(line)
            if max_tokens is None and len(lines) - 1 >= k:
                break
        return "\n".join(lines)

    def count(self) -> int:
        return self.store.count()
