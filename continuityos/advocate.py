"""Devil's Advocate — adversarial self-check baked into ContinuityOS governance.

Every consequential claim or action should be run through DevilsAdvocate before
it is accepted. It challenges the claim across a persistent rubric of angles,
running deterministic checks against your OWN memory — contradictions, superseded
facts, missing evidence, canon conflicts, overconfidence, honesty (canon: ship
honest numbers), reversibility — and emits the open questions a skeptic would ask.
The full challenge is written append-only to the ``audit`` namespace, so the record
that "we considered the counter-case" is itself durable and queryable (EU AI Act
Article-12 spirit).

    from continuityos.advocate import DevilsAdvocate
    da = DevilsAdvocate(memory, twin)
    r = da.challenge("All 150 arena bots are profitable", action=False)
    print(r["verdict"]); da.record(r)

stdlib-only, deterministic, no network, no LLM.
"""
from __future__ import annotations
import re, time
from typing import Any, Dict, List, Optional

SEV_ORDER = {"info": 0, "low": 1, "med": 2, "high": 3}

# Persistent rubric — angle -> the skeptic's question. Editable; loadable from file.
DEFAULT_RUBRIC: List[tuple] = [
    ("contradiction",  "Does anything in memory directly contradict this?"),
    ("staleness",      "Is this built on a fact that has since been superseded?"),
    ("evidence",       "Is there recorded evidence for this, or is it just assertion?"),
    ("canon",          "Does this conflict with a non-negotiable canon rule?"),
    ("overconfidence", "Are there absolute claims (always/never/100%) without proof?"),
    ("honesty",        "Does this report only wins and omit failures/limits? (canon: honest numbers)"),
    ("reversibility",  "Is the action irreversible (delete/publish/send/rotate/deploy/pay)?"),
    ("alternatives",   "What is the strongest alternative, and why not that?"),
    ("assumptions",    "What must be true for this to hold? Are those verified?"),
    ("blast_radius",   "Who or what breaks if this is wrong?"),
]

_NEG = re.compile(r"\b(not|no|never|none|false|wrong|fail(?:ed|s|ure)?|isn't|aren't|doesn't|didn't|can't|won't|broke|broken|dead|down)\b", re.I)
_ABS = re.compile(r"\b(always|never|every|all\b|none|guaranteed|certainly|definitely|100%|zero[- ]risk|no[- ]risk|impossible|proven|undeniabl\w*)", re.I)
_HEDGE = re.compile(r"(~|\b(maybe|might|likely|probably|approximately|about|around|roughly|estimat\w+|seems|appears|could|should|suggest\w*|median|median|per)\b)", re.I)
_POS = re.compile(r"\b(success\w*|passed|profit\w*|win\w*|works?|complete[d]?|perfect|best|sota|beats?|100%|all \w+ (?:pass|work|profit))\b", re.I)
_FAILWORD = re.compile(r"(\b(fail\w*|loss\w*|lose|limit\w*|weak\w*|gap|risk\w*|caveat|however|but|except|not yet|todo|unknown|unverified|reject\w*|none|by design)\b|\b0\s*(?:of|/)\s*\d)", re.I)
_IRREVERSIBLE = re.compile(r"\b(delet\w+|drop|remov\w+|publish\w*|post\w*|send\w*|deploy\w*|push\w*|rotat\w+|revok\w+|pay\w*|purchas\w+|transfer\w*|force[- ]?push|overwrit\w+)\b", re.I)

_STOP = set("the a an of to in on for and or is are be this that it with as at by from your you our we they has have was were will".split())


def _keywords(text: str, n: int = 12) -> List[str]:
    out: List[str] = []
    for w in re.findall(r"[A-Za-z0-9%/.\-]{3,}", (text or "").lower()):
        w = w.strip(".,;:!?()[]{}'\"").strip()
        if len(w) < 3 or w in _STOP or w in out:
            continue
        out.append(w)
    return out[:n]


class DevilsAdvocate:
    """Adversarial gate. `challenge()` returns a verdict + per-angle checks."""

    def __init__(self, memory, twin=None, rubric: Optional[List[tuple]] = None):
        self.m = memory
        self.twin = twin
        self.rubric = rubric or DEFAULT_RUBRIC

    def challenge(self, claim: str, action: bool = False, namespace: Optional[str] = None) -> Dict[str, Any]:
        claim = (claim or "").strip()
        checks: List[Dict[str, Any]] = []

        def add(angle, severity, flag, detail):
            checks.append({"angle": angle, "severity": severity, "flag": bool(flag), "detail": detail})

        kws = _keywords(claim, 8)
        hits = self.m.recall(claim, k=6, namespace=namespace) if claim else []
        claim_neg = bool(_NEG.search(claim))

        # 1) contradiction: strong-overlap memory of opposite polarity
        claim_pos = bool(_POS.search(claim)); claim_fail = bool(_FAILWORD.search(claim))
        contra = None
        for h in hits:
            if len(set(kws) & set(_keywords(h.text))) < 2:
                continue
            neg_flip = bool(_NEG.search(h.text)) != claim_neg
            succ_flip = (claim_pos and bool(_FAILWORD.search(h.text))) or (claim_fail and bool(_POS.search(h.text)))
            if neg_flip or succ_flip:
                contra = h
                break
        add("contradiction", "high" if contra else "info", bool(contra),
            (f"possible contradiction: [#{contra.id}] “{contra.text[:90]}”" if contra
             else "no direct contradiction in top matches"))

        # 2) staleness: an overlapping source was superseded
        stale = next((h for h in hits if (h.meta or {}).get("superseded_by")
                      and len(set(kws) & set(_keywords(h.text))) >= 2), None)
        add("staleness", "med" if stale else "info", bool(stale),
            (f"related fact [#{stale.id}] was superseded — confirm you are on the current value" if stale
             else "no superseded source detected"))

        # 3) evidence: any decent supporting overlap?
        supp = max((len(set(kws) & set(_keywords(h.text))) for h in hits), default=0)
        add("evidence", "med" if supp < 2 else "info", supp < 2,
            (f"weak/no supporting memory (best overlap {supp}) — assertion, not evidence" if supp < 2
             else f"supporting memory found (overlap {supp})"))

        # 4) canon conflict (reuse twin.alignment)
        if self.twin is not None and claim:
            try:
                conf = (self.twin.alignment(claim) or {}).get("possible_conflicts") or []
                add("canon", "high" if conf else "info", bool(conf),
                    ("canon conflict: " + "; ".join((c.get("text", "") or "")[:60] for c in conf[:2]) if conf
                     else "no recorded canon conflict"))
            except Exception as e:
                add("canon", "info", False, f"alignment skipped: {e}")

        # 5) overconfidence
        absol = _ABS.search(claim)
        add("overconfidence", "med" if (absol and not _HEDGE.search(claim)) else "info",
            bool(absol and not _HEDGE.search(claim)),
            (f"absolute '{absol.group(0)}' without hedge — is it literally true?" if absol
             else "no unqualified absolutes"))

        # 6) honesty (canon: ship honest numbers)
        pos = _POS.search(claim)
        add("honesty", "med" if (pos and not _FAILWORD.search(claim)) else "info",
            bool(pos and not _FAILWORD.search(claim)),
            ("positive claim with no failure/limit mentioned — confirm nothing omitted" if (pos and not _FAILWORD.search(claim))
             else "balanced or non-triumphal phrasing"))

        # 7) reversibility (meaningful for actions)
        irr = _IRREVERSIBLE.search(claim)
        add("reversibility", "high" if (action and irr) else ("low" if irr else "info"),
            bool(action and irr),
            (f"irreversible verb '{irr.group(0)}' — needs explicit confirmation + rollback" if irr
             else "no irreversible action detected"))

        open_qs = [q for a, q in self.rubric if a in ("alternatives", "assumptions", "blast_radius")]

        high = [c for c in checks if c["flag"] and c["severity"] == "high"]
        med = [c for c in checks if c["flag"] and c["severity"] == "med"]
        stop_angles = {"contradiction", "canon", "reversibility"}
        if high and any(c["angle"] in stop_angles for c in high):
            verdict = "STOP — resolve high-severity flags before proceeding"
        elif high:
            verdict = "RECONSIDER — a high-severity challenge stands"
        elif med:
            verdict = "PROCEED WITH CAUTION — address medium flags"
        else:
            verdict = "PROCEED — no material challenge found"

        return {"claim": claim, "action": action, "ts": time.time(),
                "checks": checks, "flags": high + med,
                "open_questions": open_qs, "verdict": verdict}

    def record(self, result: Dict[str, Any], namespace: str = "audit") -> int:
        v = (result.get("verdict") or "?").split(" ")[0]
        return self.m.remember("DA[%s] %s" % (v, result.get("claim", "")[:200]),
                               namespace=namespace, tags=["devils_advocate", "audit"],
                               meta={"advocate": True, "verdict": result.get("verdict"),
                                     "flags": result.get("flags"), "ts": result.get("ts")})

    def render(self, result: Dict[str, Any]) -> str:
        lines = ["VERDICT: %s" % result["verdict"], "CLAIM: %s" % result["claim"], "", "Challenges:"]
        for c in result["checks"]:
            mark = {"high": "⛔", "med": "⚠", "low": "·", "info": "✓"}.get(c["severity"], "?")
            if c["flag"] or c["severity"] != "info":
                lines.append("  %s [%s] %s: %s" % (mark, c["severity"], c["angle"], c["detail"]))
        lines.append("\nAnswer before proceeding:")
        lines += ["  - %s" % q for q in result["open_questions"]]
        return "\n".join(lines)
