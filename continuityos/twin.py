"""L4 Twin — digital twin / co-evolution layer.

A twin is not magic: it is a behavioral model *derived from your own memory*.
ContinuityOS builds it from what you've recorded — identity, canon (rules you
don't break), and past decisions (checkpoints) — and uses it to (a) describe the
persona, (b) predict the likely stance on a new situation from recorded rules and
precedent, and (c) check a proposed action for alignment with canon.

Honest by design: predictions cite the memories they're built on. Swap in an LLM
for richer synthesis; the evidence layer stays the same.
"""
from __future__ import annotations
from typing import List, Dict, Any, Optional
from .memory import Memory

class Twin:
    def __init__(self, memory: Optional[Memory] = None, db: str = "continuityos.db",
                 owner: str = "owner"):
        self.m = memory or Memory(db)
        self.owner = owner

    def profile(self, k: int = 8) -> Dict[str, Any]:
        ident = [r["text"] for r in self.m.store.all_with_vecs(namespace="identity")]
        canon = [r["text"] for r in self.m.store.all_with_vecs(namespace="canon")]
        rules = [r["text"] for r in self.m.store.all_with_vecs(namespace="rules")]
        return {"owner": self.owner, "identity": ident[:k], "canon": canon[:k], "rules": rules[:k]}

    def predict(self, situation: str, k: int = 5) -> Dict[str, Any]:
        """Likely stance on a new situation, grounded in recorded rules + precedent."""
        ev = []
        for ns in ("canon", "rules", "checkpoint", "facts"):
            for h in self.m.recall(situation, k=k, namespace=ns):
                if h.score > 0:
                    ev.append({"namespace": ns, "text": h.text, "score": round(h.score, 3)})
        ev.sort(key=lambda x: x["score"], reverse=True)
        ev = ev[:k]
        stance = ("Based on recorded rules and precedent, the likely stance is to follow: "
                  + "; ".join(e["text"] for e in ev[:3])) if ev else \
                 "No recorded rules or precedent cover this situation yet."
        return {"situation": situation, "predicted_stance": stance, "evidence": ev,
                "confidence": round(min(1.0, sum(e["score"] for e in ev)), 3)}

    def alignment(self, proposed_action: str, k: int = 6) -> Dict[str, Any]:
        """Check a proposed action against canon/rules. Flags possible conflicts."""
        hits = []
        for ns in ("canon", "rules"):
            for h in self.m.recall(proposed_action, k=k, namespace=ns):
                if h.score > 0.15:
                    hits.append({"namespace": ns, "rule": h.text, "relevance": round(h.score, 3)})
        hits.sort(key=lambda x: x["relevance"], reverse=True)
        # naive conflict heuristic: a rule containing negation near the action's keywords
        flags = [h for h in hits if any(w in h["rule"].lower()
                 for w in ("never", "not ", "don't", "do not", "нельзя", "не ", "запрещ", "avoid"))]
        return {"action": proposed_action, "relevant_rules": hits[:k],
                "possible_conflicts": flags[:k],
                "verdict": ("⚠ review — touches a prohibitive rule" if flags else
                            "✓ no recorded rule conflicts found")}
