"""cos frontier — a Personal Frontier Intelligence Desk on top of memory.

Track frontier-tech signals across watch-domains, score each (asymmetry, the
OpenAI 5-level capability taxonomy, time-horizon), and synthesize a decision
digest: LEARN / BUILD / TEST / AVOID / EDGE — "what to learn, what to sell,
what to test, where not to go, where an asymmetric edge appears."

Signals are bi-temporal memories (namespace ``frontier``), so ``--as-of``
reconstructs the desk as it stood then. Deterministic, stdlib-only.

    cos frontier signal -d ai-agents -s "EU AI Act" -t "Article 12 enforceable Aug 2 2026" -a 0.8 -l 3
    cos frontier digest
    cos frontier watch
"""
from __future__ import annotations
import json, time
from typing import Any, Dict, List, Optional

NS = "frontier"

DOMAINS: Dict[str, str] = {
    "ai-agents":   "AI agents / Agent OS / governance / audit / black box",
    "crypto-web3": "crypto / Web3 / onchain identity / prediction markets / risk",
    "robotics":    "robotics / embodied AI",
    "neurotech":   "neurotech / BCI / cognitive augmentation",
    "longevity":   "longevity / synthetic biology",
    "quantum-sec": "quantum / cybersecurity / post-quantum",
    "deep-tech":   "energy / materials / semiconductors / space",
}
# OpenAI 5-level capability taxonomy (from the ASI roadmap) — the frontier is L2->L3
LEVELS = {1: "Chatbots", 2: "Reasoners", 3: "Agents", 4: "Innovators", 5: "Organizations"}
# where we have home-court advantage — signals here bias toward BUILD/EDGE
HOME = {"ai-agents"}
DECISIONS = ["EDGE", "BUILD", "TEST", "LEARN", "AVOID"]


class FrontierDesk:
    def __init__(self, memory):
        self.m = memory

    def signal(self, domain: str, source: str, title: str, asymmetry: float = 0.5,
               level: int = 3, horizon: str = "now", decision: Optional[str] = None) -> int:
        if domain not in DOMAINS:
            domain = "ai-agents"
        dec = decision or self._suggest(domain, asymmetry, level, horizon)
        meta = {"frontier": True, "domain": domain, "source": source, "asymmetry": float(asymmetry),
                "level": int(level), "horizon": horizon, "decision": dec, "ts": time.time()}
        return self.m.remember(title, namespace=NS, tags=["frontier", domain, dec.lower()], meta=meta)

    def _suggest(self, domain: str, asym: float, level: int, horizon: str) -> str:
        """Heuristic decision. High asymmetry in a home domain -> EDGE/BUILD; high asymmetry
        elsewhere -> TEST/LEARN; low asymmetry -> AVOID (noise)."""
        if asym < 0.3:
            return "AVOID"
        if domain in HOME:
            return "EDGE" if asym >= 0.7 else "BUILD"
        if asym >= 0.7 and horizon in ("now", "soon"):
            return "TEST"
        return "LEARN"

    def signals(self, domain: Optional[str] = None, as_of: Optional[float] = None) -> List[Dict[str, Any]]:
        rows = self.m.store.all_with_vecs(namespace=NS)
        out = []
        for r in rows:
            meta = json.loads(r["meta"])
            if not meta.get("frontier"):
                continue
            if domain and meta.get("domain") != domain:
                continue
            if as_of is not None and meta.get("ts", 0) > as_of:
                continue
            out.append({"id": r["id"], "title": r["text"], **meta})
        out.sort(key=lambda s: (s.get("asymmetry", 0), s.get("ts", 0)), reverse=True)
        return out

    def digest(self, as_of: Optional[float] = None) -> Dict[str, Any]:
        sigs = self.signals(as_of=as_of)
        by_dec: Dict[str, List[Dict[str, Any]]] = {d: [] for d in DECISIONS}
        for s in sigs:
            by_dec.setdefault(s.get("decision", "LEARN"), []).append(s)
        return {"total": len(sigs), "by_decision": by_dec,
                "by_domain": {d: sum(1 for s in sigs if s["domain"] == d) for d in DOMAINS}}

    def render(self, dg: Dict[str, Any]) -> str:
        icon = {"EDGE": "◆ asymmetric edge", "BUILD": "▲ build / sell",
                "TEST": "◇ test / probe", "LEARN": "· learn / watch", "AVOID": "✗ avoid (noise)"}
        out = ["# Frontier Intelligence Desk — digest (%d signals)" % dg["total"], ""]
        for dec in DECISIONS:
            items = dg["by_decision"].get(dec, [])
            if not items:
                continue
            out.append("## %s" % icon.get(dec, dec))
            for s in items[:8]:
                out.append("  - [%s · L%d %s · asym %.2f · %s] %s — %s"
                           % (s["domain"], s["level"], LEVELS.get(s["level"], "?"),
                              s["asymmetry"], s["horizon"], s["title"], s["source"]))
            out.append("")
        cov = ", ".join("%s=%d" % (d, n) for d, n in dg["by_domain"].items() if n)
        out.append("coverage: " + (cov or "(no signals yet — add with `cos frontier signal`)"))
        return "\n".join(out)
