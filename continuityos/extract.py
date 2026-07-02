"""Auto-extraction of memory candidates (Mem0 v3 pattern, ADD-only).

Mem0's April-2026 algorithm showed a single extraction pass with NO update/delete
(memories only accumulate) beats complex reconcile pipelines (LongMemEval 94.8).
ContinuityOS adopts the shape: one pass over session text, typed candidates out,
ADD-only writes; supersede() handles corrections instead of destructive updates.

Offline-first: a marker heuristic works with zero deps/keys. Pass llm=callable
(prompt -> str) to upgrade extraction quality; falls back to the heuristic on
any error. Removes the friction of manual remember() at session close:

    from continuityos.extract import extract_and_store
    ids = extract_and_store(session_text, memory)          # heuristic
    ids = extract_and_store(session_text, memory, llm=ask) # LLM-graded
"""
from __future__ import annotations
import json, re
from typing import Callable, Dict, List, Optional

# Memanto-style semantic types (the subset that earns its keep for an operator log)
TYPES = ("fact", "preference", "decision", "goal", "event", "learning", "error")

_MARKERS: Dict[str, tuple] = {
    "decision":   ("decided", "we will", "решил", "решение", "выбрал", "договорились", "будем "),
    "preference": ("prefer", "likes", "хочу", "предпочит", "нравится", "не люблю"),
    "goal":       ("goal", "target", "цель", "план на", "хотим"),
    "learning":   ("learned", "lesson", "turns out", "урок", "вывод", "оказалось"),
    "error":      ("error", "failed", "broke", "ошибк", "упал", "сломал"),
    "event":      ("today", "yesterday", "deployed", "запущен", "сегодня", "вчера", "задеплоен"),
}
_FACTY = re.compile(r"(\d|=| is | are |составляет|равно)", re.I)

_LLM_PROMPT = """Extract durable memory candidates from the session text below.
Return ONLY a JSON array: [{"text": "...", "type": "fact|preference|decision|goal|event|learning|error"}].
Rules: only facts worth remembering across sessions; one sentence each; skip chit-chat.

SESSION:
%s"""


def _sentences(text: str) -> List[str]:
    parts = re.split(r"(?<=[.!?])\s+|\n+", text or "")
    return [p.strip() for p in parts if 20 <= len(p.strip()) <= 300]


def extract(text: str, llm: Optional[Callable[[str], str]] = None) -> List[Dict]:
    """Single pass -> [{"text","type","confidence"}]. LLM path first, heuristic fallback."""
    if llm is not None:
        try:
            raw = llm(_LLM_PROMPT % text[:12000])
            data = json.loads(re.search(r"\[.*\]", raw, re.S).group(0))
            return [{"text": d["text"].strip(), "type": d.get("type", "fact"),
                     "confidence": 0.9} for d in data
                    if d.get("text") and d.get("type", "fact") in TYPES]
        except Exception:
            pass  # never fail the close ritual over an LLM hiccup
    out = []
    for s in _sentences(text):
        low = s.lower()
        mtype, score = None, 0
        for t, marks in _MARKERS.items():
            n = sum(1 for mk in marks if mk in low)
            if n and n > score:
                mtype, score = t, n
        if mtype is None and _FACTY.search(s):
            mtype, score = "fact", 1
        if mtype:
            out.append({"text": s, "type": mtype,
                        "confidence": min(0.5 + 0.15 * score, 0.9)})
    return out


def extract_and_store(text: str, memory, namespace: str = "facts",
                      llm: Optional[Callable[[str], str]] = None,
                      min_confidence: float = 0.5) -> List[int]:
    """ADD-only write path with an exact-duplicate guard (no update/delete)."""
    ids: List[int] = []
    for c in extract(text, llm=llm):
        if c["confidence"] < min_confidence:
            continue
        dup = any(h.text.strip().lower() == c["text"].strip().lower()
                  for h in memory.recall(c["text"], k=3, namespace=namespace))
        if dup:
            continue
        ids.append(memory.remember(c["text"], namespace=namespace, mtype=c["type"],
                                   meta={"source": "auto-extract",
                                         "confidence": c["confidence"]}))
    return ids
