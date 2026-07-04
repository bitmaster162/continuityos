"""Monetization-map builder — assemble a tiered money-map from the user's OWN data.

Permission model: the user grants access by pointing `cos moneymap --from <dir>` (or the
setup wizard) at a folder of their notes/plans/exports. Nothing is uploaded anywhere —
scanning is local, stdlib-only. Heuristics pull price + offer signals ($X, $X/mo, $X/yr,
$Xk, per-hour) out of text and bucket them into tiers (products / subscriptions / services
/ enterprise). Optional: also mine the ContinuityOS memory itself.

    from continuityos.monetization import build
    m = build(paths=["~/notes"], memory=mem)
    open("money_map.md","w").write(render_map_md(m))
"""
from __future__ import annotations
import os, re
from typing import Dict, List, Optional

TEXT_EXT = (".md", ".txt", ".json", ".csv", ".org", ".rst")
MAX_FILE_BYTES = 2_000_000
MAX_FILES = 2000

# $9,970  ·  $135K  ·  $99/mo  ·  $299/ч  ·  $350K/мес
PRICE_RE = re.compile(
    r"\$\s?(\d[\d,]*(?:\.\d+)?)\s*([Kk])?\s*"
    r"(?:/\s*(mo|month|mes|мес|yr|year|год|hr|hour|ч|wk|week|нед))?",
    re.I)
_CADENCE = {
    "mo": "monthly", "month": "monthly", "mes": "monthly", "мес": "monthly",
    "yr": "annual", "year": "annual", "год": "annual",
    "hr": "hourly", "hour": "hourly", "ч": "hourly",
    "wk": "weekly", "week": "weekly", "нед": "weekly",
}
TIERS = ("Services (hourly)", "Recurring (monthly)", "Recurring (annual)",
         "One-time / products", "Enterprise / high-ticket")


def _amount(num: str, k: Optional[str]) -> float:
    val = float(num.replace(",", ""))
    return val * 1000 if k else val


def _clean(line: str) -> str:
    line = re.sub(r"[#>*`|_\-]{1,}", " ", line)
    return re.sub(r"\s+", " ", line).strip()[:160]


def extract_signals(text: str) -> List[Dict]:
    """Return [{text, price_usd, cadence}] for every priced line."""
    out: List[Dict] = []
    for raw in text.splitlines():
        for m in PRICE_RE.finditer(raw):
            amt = _amount(m.group(1), m.group(2))
            if amt < 1:            # skip $0 / noise
                continue
            cad = _CADENCE.get((m.group(3) or "").lower(), "one-time")
            desc = _clean(raw)
            if desc:
                out.append({"text": desc, "price_usd": amt, "cadence": cad})
    return out


def _tier(sig: Dict) -> str:
    c = sig["cadence"]
    if c == "hourly":
        return "Services (hourly)"
    if c == "monthly" or c == "weekly":
        return "Recurring (monthly)"
    if c == "annual":
        return "Recurring (annual)"
    return "Enterprise / high-ticket" if sig["price_usd"] >= 5000 else "One-time / products"


def build_map(signals: List[Dict]) -> Dict:
    seen = set()
    offers: List[Dict] = []
    for s in signals:
        key = (s["text"].lower(), round(s["price_usd"], 2), s["cadence"])
        if key in seen:
            continue
        seen.add(key)
        s = dict(s); s["tier"] = _tier(s)
        offers.append(s)
    tiers: Dict[str, List[Dict]] = {t: [] for t in TIERS}
    for o in offers:
        tiers[o["tier"]].append(o)
    for t in tiers:
        tiers[t].sort(key=lambda o: o["price_usd"], reverse=True)
    return {"offers": offers, "tiers": tiers, "count": len(offers)}


def scan_paths(paths: List[str]) -> Dict:
    """Read text files under the given files/dirs. Returns {text, files}."""
    files = 0
    chunks: List[str] = []
    for p in paths:
        p = os.path.expanduser(p)
        cand: List[str] = []
        if os.path.isfile(p):
            cand = [p]
        elif os.path.isdir(p):
            for root, _dirs, names in os.walk(p):
                if any(seg in root for seg in (".git", "node_modules", "__pycache__")):
                    continue
                for n in names:
                    if n.lower().endswith(TEXT_EXT):
                        cand.append(os.path.join(root, n))
        for fp in cand:
            if files >= MAX_FILES:
                break
            try:
                if os.path.getsize(fp) > MAX_FILE_BYTES:
                    continue
                chunks.append(open(fp, encoding="utf-8", errors="ignore").read())
                files += 1
            except Exception:
                continue
    return {"text": "\n".join(chunks), "files": files}


def build(paths: Optional[List[str]] = None, memory=None) -> Dict:
    signals: List[Dict] = []
    files = 0
    sources: List[str] = []
    if paths:
        sc = scan_paths(paths)
        signals += extract_signals(sc["text"])
        files = sc["files"]
        sources += list(paths)
    if memory is not None:
        try:
            texts = []
            for ns in memory.namespaces():
                for row in memory.store.all_with_vecs(namespace=ns["namespace"]):
                    texts.append(row["text"])
            signals += extract_signals("\n".join(texts))
            sources.append("continuityos-memory")
        except Exception:
            pass
    m = build_map(signals)
    m["files_scanned"] = files
    m["sources"] = sources
    return m


def render_map_md(m: Dict) -> str:
    L = ["# Monetization map (built from your data)",
         f"<!-- {m['count']} offers from {m.get('files_scanned', 0)} file(s); "
         f"sources: {', '.join(m.get('sources') or ['-'])}. Built by `cos moneymap`. -->", ""]
    if not m["count"]:
        L += ["_No priced offers found. Point `cos moneymap --from <dir>` at notes/plans that "
              "mention prices (e.g. `$99/mo`, `$4,999`)._", ""]
        return "\n".join(L)
    L += ["| Tier | # | Price range | Example offer |", "|---|--:|---|---|"]
    for t, offers in m["tiers"].items():
        if not offers:
            continue
        lo = min(o["price_usd"] for o in offers)
        hi = max(o["price_usd"] for o in offers)
        rng = f"${lo:,.0f}" if lo == hi else f"${lo:,.0f}–${hi:,.0f}"
        ex = offers[0]["text"][:60]
        L.append(f"| {t} | {len(offers)} | {rng} | {ex} |")
    L += ["", "## All detected offers"]
    for o in m["offers"]:
        cad = "" if o["cadence"] == "one-time" else f"/{o['cadence']}"
        L.append(f"- **${o['price_usd']:,.0f}{cad}** [{o['tier']}] — {o['text']}")
    L += ["", "_Heuristic extract from your own files; review before acting. Not financial advice._"]
    return "\n".join(L) + "\n"
