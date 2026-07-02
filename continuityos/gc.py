"""ContinuityOS Context Garbage Collection (applies guide_context_garbage_collection).

When the working context approaches the model limit, attention drifts and safety rules
get dropped. CGC keeps context lean: strip terminal/tool noise, collapse near-duplicates
(via dedupe), and once over PRUNE_AT of budget, hand off old history as a dense semantic
summary while preserving checkpoints. Pure-python, no deps.

    from continuityos.gc import collect
    kept, report = collect(items, max_tokens=128000)

Each item: dict with at least {"text": str}; optional "kind" ("checkpoint" is never dropped),
"pinned" (bool, kept). Returns (kept_items, report).
"""
from __future__ import annotations
import re
from typing import List, Dict, Tuple, Callable

PRUNE_AT = 0.80                  # guide: compact at 80% of max_context_tokens
SUMMARY_INTERVAL = 10            # guide summary_interval_turns
# noise: raw tool dumps, stack traces, dir listings, repeated warnings
_NOISE = re.compile(
    r"(Traceback \(most recent call last\)|^\s*File \".*\", line \d+|"
    r"^\s*[-d]rwx|^total \d+|node_modules/|__pycache__|"
    r"^\s*\{?\s*\"[\w_]+\":\s|WARNING:|DeprecationWarning)", re.M)


def _toks(text: str, char_per_tok: float = 3.7) -> int:
    return int(len(text or "") / char_per_tok) + 1


def is_noise(text: str) -> bool:
    t = (text or "").strip()
    if not t:
        return True
    hits = len(_NOISE.findall(t))
    return hits >= 2 or (hits >= 1 and len(t) > 400)  # dense machine output


def collect(items: List[Dict], max_tokens: int = 128000,
            prune_at: float = PRUNE_AT,
            est: Callable[[str], int] = _toks) -> Tuple[List[Dict], Dict]:
    budget = int(max_tokens * prune_at)
    total = sum(est(i.get("text", "")) for i in items)
    report = {"in_items": len(items), "in_tokens": total, "dropped_noise": 0,
              "dropped_dupe": 0, "summarized": 0, "kept_tokens": 0, "triggered": total > budget}
    if total <= budget:
        report["kept_tokens"] = total
        return items, report

    def protected(it):
        return it.get("kind") == "checkpoint" or it.get("pinned")

    # 1) drop tool/terminal noise (never checkpoints)
    stage1 = []
    for it in items:
        if not protected(it) and is_noise(it.get("text", "")):
            report["dropped_noise"] += 1
        else:
            stage1.append(it)

    # 2) collapse near-duplicates among non-protected
    try:
        from continuityos.dedupe import find_near_duplicates
        idx = {id(it): it for it in stage1}
        pool = [(str(id(it)), it.get("text", "")) for it in stage1 if not protected(it)]
        groups = find_near_duplicates(pool)
        drop_ids = set()
        for g in groups:
            keep = max(g, key=lambda k: len(idx[int(k)].get("text", "")))
            for k in g:
                if k != keep:
                    drop_ids.add(int(k))
        stage2 = [it for it in stage1 if id(it) not in drop_ids]
        report["dropped_dupe"] = len(stage1) - len(stage2)
    except Exception:
        stage2 = stage1

    # 3) if still over budget: summarize oldest non-protected history (handoff)
    kept = list(stage2)
    cur = sum(est(i.get("text", "")) for i in kept)
    if cur > budget:
        head, tail = [], []
        for it in kept:
            (head if not protected(it) else tail).append(it)
        # drop oldest head items, replace with one dense summary marker
        summarized, freed = [], 0
        need = cur - budget
        i = 0
        while i < len(head) and freed < need:
            summarized.append(head[i]); freed += est(head[i].get("text", "")); i += 1
        survivors = head[i:]
        if summarized:
            facts = [s.get("text", "")[:120] for s in summarized[-SUMMARY_INTERVAL:]]
            marker = {"kind": "summary",
                      "text": f"[CGC handoff: compacted {len(summarized)} stale items. "
                              f"Key residue: " + " | ".join(facts) + "]"}
            kept = [marker] + survivors + tail
            report["summarized"] = len(summarized)

    report["kept_tokens"] = sum(est(i.get("text", "")) for i in kept)
    return kept, report


def compress_tool_output(text: str, max_chars: int = 4000) -> str:
    """Headroom pattern (github.com/chopratejas/headroom): shrink tool/log/JSON output
    before it reaches the LLM — same answers, far fewer tokens. Three passes:
    JSON array-of-objects -> compact pipe table; JSON object -> drop empty fields;
    anything long -> whitespace squeeze + head/tail slice with explicit elision marker."""
    t = (text or "").strip()
    if len(t) <= max_chars:
        return t
    import json as _json
    try:
        data = _json.loads(t)
        if isinstance(data, list) and data and all(isinstance(r, dict) for r in data):
            keys = list(data[0].keys())
            rows = [" | ".join(str(r.get(k, ""))[:80] for k in keys) for r in data]
            out = " | ".join(keys) + "\n" + "\n".join(rows)
            if len(out) > max_chars:
                out = out[:max_chars] + "\n… [compressed: %d rows, was %d chars]" % (len(data), len(t))
            return out
        if isinstance(data, dict):
            slim = {k: v for k, v in data.items() if v not in (None, "", [], {})}
            return _json.dumps(slim, ensure_ascii=False, separators=(",", ":"))[:max_chars]
    except Exception:
        pass
    t = re.sub(r"[ \t]+", " ", t)
    t = re.sub(r"\n{3,}", "\n\n", t)
    if len(t) <= max_chars:
        return t
    head, tail = t[:int(max_chars * 0.7)], t[-int(max_chars * 0.2):]
    return head + "\n… [compressed: elided %d chars] …\n" % (len(t) - len(head) - len(tail)) + tail


if __name__ == "__main__":
    demo = ([{"text": "INVARIANT: never delete checkpoints.", "kind": "checkpoint"}]
            + [{"text": f'Traceback (most recent call last)\n  File "x.py", line {n}\nWARNING: deprecated'} for n in range(8)]
            + [{"text": "The arena uses GCP spot preemption causing reboots."}] * 3
            + [{"text": f"Useful insight number {n} about market-neutral grid edges."} for n in range(40)])
    kept, rep = collect(demo, max_tokens=2000)
    print("report:", rep)
    print("kept:", len(kept), "| checkpoint preserved:",
          any(k.get("kind") == "checkpoint" for k in kept))
