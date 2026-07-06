"""Dialectic — Devil's Advocate (antithesis) + Angel's Advocate (thesis) over one claim,
synthesized. A contradiction is treated as REAL only when the claim's own success-words are
NOT echoed in the overlapping memory (so 'attack failed' / 'no PYTHONPATH' phrasing doesn't
false-fire, but 'deploy done' vs 'deploy NOT run' does)."""
import re
from .advocate import DevilsAdvocate, _keywords
from .angel import AngelsAdvocate, _POS, _MOMENTUM

_R = {"STOP": 3, "RECONSIDER": 2, "PROCEED WITH CAUTION": 1, "PROCEED": 0}
_U = {"SEIZE": 3, "ADVANCE": 2, "PROCEED": 1, "HOLD": 0}
def _lvl(v, t):
    for k, x in t.items():
        if v.startswith(k): return x
    return 0

def _claim_echoed_in_memory(claim, hits):
    """True if the claim's positive/momentum words actually appear in overlapping memory."""
    pos = [w for w in _keywords(claim) if _POS.search(w) or _MOMENTUM.search(w)]
    if not pos:
        return False
    ck = set(_keywords(claim))
    for h in hits[:3]:
        hk = _keywords(h.text)
        if len(ck & set(hk)) >= 3 and any(p in hk for p in pos):
            return True
    return False

class Dialectic:
    def __init__(self, memory=None, twin=None):
        self.m = memory
        self.devil = DevilsAdvocate(memory, twin)
        self.angel = AngelsAdvocate(memory, twin)

    def run(self, claim, action=False, namespace=None):
        d = self.devil.challenge(claim, action, namespace)
        a = self.angel.champion(claim, action, namespace)
        R, U = _lvl(d["verdict"], _R), _lvl(a["verdict"], _U)
        contradiction = any(c["angle"] == "contradiction" and c["flag"] for c in d["checks"])
        note = ""
        if contradiction:
            hits = self.m.recall(claim, k=6, namespace=namespace) if self.m else []
            if _claim_echoed_in_memory(claim, hits):
                contradiction = False; R = min(R, 1)
                note = "  (devil saw a phrasing flip; memory actually echoes the claim)"
        if contradiction:
            synth = "❗ CHECK FACTS — memory contradicts the claim; verify before anything else"
        elif U >= 2 and R >= 2:
            synth = "⚡ TENSION — real upside gated by a real risk; de-risk, then capture (highest leverage)"
        elif U >= 2 and R <= 1:
            synth = "✅ GO — strong upside, contained risk"
        elif U <= 1 and R >= 2:
            synth = "⛔ DROP/DEFER — low upside, high risk"
        else:
            synth = "◽ OPTIONAL — modest either way; do only if cheap"
        return {"claim": claim, "devil": d["verdict"], "angel": a["verdict"], "synthesis": synth + note, "_d": d, "_a": a}
