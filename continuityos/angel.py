"""Angel's Advocate — the antipode of the Devil's Advocate, same shape, mirrored.

Where the devil hunts for reasons a claim/action is WRONG or unsafe, the angel builds the
strongest honest case FOR it: corroboration in memory, real evidence, calibrated (hedged)
confidence, candor about limits (credibility), reversibility as 'safe to try', asymmetric
upside, and momentum (proof of progress). Together (see dialectic.py) they are thesis and
antithesis; the synthesis is the decision. stdlib-only, deterministic."""
from __future__ import annotations
import re, time
from typing import Any, Dict, List, Optional

_NEG = re.compile(r"\b(not|no|never|none|false|wrong|fail(?:ed|s|ure)?|isn't|aren't|doesn't|didn't|can't|won't|broke|broken|dead|down)\b", re.I)
_HEDGE = re.compile(r"(~|\b(maybe|might|likely|probably|approximately|about|around|roughly|estimat\w+|seems|appears|could|should|median|per|verified|measured|tested)\b)", re.I)
_POS = re.compile(r"\b(success\w*|passed|profit\w*|win\w*|works?|complete[d]?|verified|live|running|shipped|built|contained|holds?)\b", re.I)
_CANDOR = re.compile(r"\b(fail\w*|loss\w*|limit\w*|weak\w*|gap|risk\w*|caveat|however|but|except|not yet|todo|unknown|unverified|honest|by design|trade[- ]?off)\b", re.I)
_ASYM = re.compile(r"\b(edge|advantage|moat|first|only|10x|100x|unlock\w*|leverage|wedge|defensib\w+|own(?:ed|s)?|rare|asymmetr\w+|unique|category|mandat\w+|deadline)\b", re.I)
_MOMENTUM = re.compile(r"\b(built|ship\w*|verified|works?|live|passed|running|done|proven|deployed|end[- ]?to[- ]?end|reproduc\w+|chain_ok)\b", re.I)
_REVERSIBLE_SAFE = re.compile(r"\b(sandbox\w*|rollback|revert\w*|append[- ]?only|snapshot|shadow|canary|dry[- ]?run|contained|reversible|two[- ]?phase)\b", re.I)
_STOP = set("the a an of to in on for and or is are be this that it with as at by from your you our we they has have was were will".split())

def _keywords(text, n=12):
    out = []
    for w in re.findall(r"[A-Za-z0-9%/.\-]{3,}", (text or "").lower()):
        w = w.strip(".,;:!?()[]{}'\"").strip()
        if len(w) < 3 or w in _STOP or w in out: continue
        out.append(w)
    return out[:n]

DEFAULT_RUBRIC = [
    ("corroboration", "Does memory independently agree with this?"),
    ("evidence",      "Is there recorded, checkable evidence for it?"),
    ("calibration",   "Is confidence calibrated (hedged / numeric), not reckless?"),
    ("candor",        "Does it own its limits — a sign of a trustworthy claim?"),
    ("reversibility", "Is it cheap/safe to try (sandboxed / rollback-able)?"),
    ("asymmetry",     "Is there asymmetric upside — an edge others don't have?"),
    ("momentum",      "Is there proof of real progress, not just intent?"),
]

class AngelsAdvocate:
    def __init__(self, memory=None, twin=None, rubric=None):
        self.m = memory; self.twin = twin; self.rubric = rubric or DEFAULT_RUBRIC

    def champion(self, claim: str, action: bool = False, namespace: Optional[str] = None) -> Dict[str, Any]:
        claim = (claim or "").strip(); strengths = []
        def add(angle, strength, flag, detail):
            strengths.append({"angle": angle, "strength": strength, "flag": bool(flag), "detail": detail})
        kws = _keywords(claim, 8)
        hits = self.m.recall(claim, k=6, namespace=namespace) if (self.m and claim) else []
        claim_neg = bool(_NEG.search(claim))
        # corroboration: same-polarity overlapping memory
        corr = next((h for h in hits if len(set(kws) & set(_keywords(h.text))) >= 2
                     and bool(_NEG.search(h.text)) == claim_neg), None)
        add("corroboration", "strong" if corr else "info", bool(corr),
            (f"memory agrees: “{corr.text[:80]}”" if corr else "no independent corroboration yet"))
        supp = max((len(set(kws) & set(_keywords(h.text))) for h in hits), default=0)
        add("evidence", "strong" if supp >= 2 else "info", supp >= 2,
            (f"supporting evidence in memory (overlap {supp})" if supp >= 2 else "assertion — get a datapoint"))
        add("calibration", "solid" if _HEDGE.search(claim) else "info", bool(_HEDGE.search(claim)),
            ("calibrated / measured phrasing" if _HEDGE.search(claim) else "no hedges — is it really certain?"))
        add("candor", "solid" if _CANDOR.search(claim) else "info", bool(_CANDOR.search(claim)),
            ("owns a limit/risk — credible" if _CANDOR.search(claim) else "no stated limit"))
        add("reversibility", "solid" if _REVERSIBLE_SAFE.search(claim) else "info", bool(_REVERSIBLE_SAFE.search(claim)),
            ("safe to try (sandbox/rollback)" if _REVERSIBLE_SAFE.search(claim) else "reversibility not shown"))
        add("asymmetry", "strong" if _ASYM.search(claim) else "info", bool(_ASYM.search(claim)),
            (f"asymmetric upside: '{_ASYM.search(claim).group(0)}'" if _ASYM.search(claim) else "no clear edge stated"))
        add("momentum", "strong" if _MOMENTUM.search(claim) else "info", bool(_MOMENTUM.search(claim)),
            (f"proof of progress: '{_MOMENTUM.search(claim).group(0)}'" if _MOMENTUM.search(claim) else "intent, not yet proof"))
        strong = [s for s in strengths if s["flag"] and s["strength"] == "strong"]
        solid = [s for s in strengths if s["flag"] and s["strength"] == "solid"]
        key = {s["angle"] for s in strong} & {"asymmetry", "evidence", "momentum", "corroboration"}
        if len(key) >= 2: verdict = "SEIZE — asymmetric, evidenced upside; act while the window is open"
        elif len(strong) >= 2: verdict = "ADVANCE — solid case to proceed"
        elif strong or len(solid) >= 2: verdict = "PROCEED — modest but real value"
        else: verdict = "HOLD — little upside found; needs a reason to act"
        return {"claim": claim, "action": action, "ts": time.time(),
                "strengths": strengths, "flags": strong + solid, "verdict": verdict}

    def render(self, r):
        out = ["FOR: %s" % r["verdict"], "CLAIM: %s" % r["claim"], "", "Strengths:"]
        for s in r["strengths"]:
            mark = {"strong": "★", "solid": "+", "info": "·"}.get(s["strength"], "?")
            if s["flag"] or s["strength"] != "info":
                out.append("  %s [%s] %s: %s" % (mark, s["strength"], s["angle"], s["detail"]))
        return "\n".join(out)
