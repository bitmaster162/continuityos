"""Migration adapters — import your existing AI history into ContinuityOS memory.

    cos import path/to/chatgpt-export/conversations.json
    cos import path/to/claude-export/            # dir with conversations.json / memories.json
    cos import export.json --extract             # distill typed salient facts, not raw turns

Auto-detects the ChatGPT and Claude data-export formats. **Bi-temporal**: every
imported memory's ``valid_from`` is set to the ORIGINAL message time, so
``cos recall --as-of <date>`` reconstructs what you knew THEN — your old history
becomes time-travelable memory, not a flat dump. Deterministic and fully offline
(no API keys). ``--extract`` runs the zero-dep heuristic extractor to keep only
typed durable facts (decision/preference/goal/...) instead of every raw turn.
"""
from __future__ import annotations
import json, os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class ImportRecord:
    text: str
    role: str = "user"
    ts: Optional[float] = None            # original message time (epoch seconds)
    conversation_id: str = ""
    conversation_title: str = ""
    source: str = ""                      # "chatgpt" | "claude"


@dataclass
class ImportResult:
    source: str = ""
    conversations: int = 0
    messages_seen: int = 0
    imported: int = 0
    skipped_short: int = 0
    skipped_dup: int = 0
    ids: List[int] = field(default_factory=list)

    def as_dict(self) -> Dict[str, Any]:
        return {"source": self.source, "conversations": self.conversations,
                "messages_seen": self.messages_seen, "imported": self.imported,
                "skipped_short": self.skipped_short, "skipped_dup": self.skipped_dup,
                "ids": self.ids}


# ---------------------------------------------------------------- helpers
def _flt(v: Any) -> Optional[float]:
    """Coerce a timestamp (epoch int/float or ISO-8601 string) to epoch seconds."""
    if v is None:
        return None
    if isinstance(v, (int, float)):
        return float(v)
    if isinstance(v, str):
        s = v.strip()
        if not s:
            return None
        try:
            return float(s)
        except ValueError:
            pass
        try:
            import datetime as _dt
            return _dt.datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()
        except Exception:
            return None
    return None


def _text_from_parts(parts: Any) -> str:
    """ChatGPT content.parts: list of strings and/or multimodal dicts."""
    out: List[str] = []
    for p in parts or []:
        if isinstance(p, str):
            out.append(p)
        elif isinstance(p, dict) and isinstance(p.get("text"), str):
            out.append(p["text"])
    return "\n".join(x for x in out if x and x.strip())


# ---------------------------------------------------------------- parsers
def parse_chatgpt(data: Any) -> List[ImportRecord]:
    """Parse a ChatGPT `conversations.json` export (list of conversations, each a
    `mapping` node-graph). Messages are ordered by create_time within a conversation."""
    convs = data if isinstance(data, list) else data.get("conversations", [data])
    recs: List[ImportRecord] = []
    for conv in convs:
        if not isinstance(conv, dict):
            continue
        title = conv.get("title") or ""
        cid = str(conv.get("conversation_id") or conv.get("id") or "")
        msgs: List[dict] = []
        mapping = conv.get("mapping")
        if isinstance(mapping, dict):
            for node in mapping.values():
                if isinstance(node, dict) and isinstance(node.get("message"), dict):
                    msgs.append(node["message"])
        elif isinstance(conv.get("messages"), list):
            msgs = [m for m in conv["messages"] if isinstance(m, dict)]
        for msg in msgs:
            author = msg.get("author") or {}
            role = author.get("role") or msg.get("role") or "user"
            content = msg.get("content")
            if isinstance(content, dict):
                text = _text_from_parts(content.get("parts"))
            elif isinstance(content, str):
                text = content
            else:
                text = ""
            recs.append(ImportRecord(text=text.strip(), role=role, ts=_flt(msg.get("create_time")),
                                     conversation_id=cid, conversation_title=title, source="chatgpt"))
    recs = [r for r in recs if r.text]
    recs.sort(key=lambda r: (r.conversation_id, r.ts if r.ts is not None else 0.0))
    return recs


def parse_claude(data: Any) -> List[ImportRecord]:
    """Parse a Claude export: `conversations.json` (list w/ `chat_messages`) or
    `memories.json` (list of strings, or list of {text|content|summary})."""
    if isinstance(data, dict) and isinstance(data.get("memories"), list):
        data = data["memories"]
    # memories.json as a bare list of strings
    if isinstance(data, list) and data and all(isinstance(x, str) for x in data):
        return [ImportRecord(text=s.strip(), role="memory", source="claude")
                for s in data if s and s.strip()]
    convs = data if isinstance(data, list) else [data]
    recs: List[ImportRecord] = []
    for conv in convs:
        if not isinstance(conv, dict):
            continue
        if isinstance(conv.get("chat_messages"), list):
            title = conv.get("name") or conv.get("title") or ""
            cid = str(conv.get("uuid") or conv.get("id") or "")
            for msg in conv["chat_messages"]:
                if not isinstance(msg, dict):
                    continue
                role = msg.get("sender") or msg.get("role") or "user"
                text = msg.get("text") or ""
                if not text and isinstance(msg.get("content"), list):
                    text = "\n".join(b.get("text", "") for b in msg["content"]
                                     if isinstance(b, dict))
                recs.append(ImportRecord(
                    text=(text or "").strip(),
                    role=("human" if role in ("human", "user") else role),
                    ts=_flt(msg.get("created_at") or conv.get("created_at")),
                    conversation_id=cid, conversation_title=title, source="claude"))
        else:
            text = conv.get("text") or conv.get("content") or conv.get("summary") or conv.get("name") or ""
            if isinstance(text, str) and text.strip():
                recs.append(ImportRecord(text=text.strip(), role="memory",
                                         ts=_flt(conv.get("created_at") or conv.get("updated_at")),
                                         source="claude"))
    recs = [r for r in recs if r.text]
    recs.sort(key=lambda r: (r.conversation_id, r.ts if r.ts is not None else 0.0))
    return recs


def sniff(data: Any) -> str:
    """Best-effort format detection from a loaded JSON object."""
    if isinstance(data, list) and data:
        it = data[0]
        if isinstance(it, dict):
            if "mapping" in it:
                return "chatgpt"
            if "chat_messages" in it:
                return "claude"
            if any(k in it for k in ("content", "summary", "text")) and "author" not in it:
                return "claude"
        elif isinstance(it, str):
            return "claude"
    if isinstance(data, dict):
        if "mapping" in data:
            return "chatgpt"
        if "chat_messages" in data or "memories" in data:
            return "claude"
    return "unknown"


def load_export(path: str) -> List[Tuple[str, Any]]:
    """Load one file or a whole export directory. Returns [(filename_hint, json)]."""
    def _load(fp): return (os.path.basename(fp), json.load(open(fp, encoding="utf-8")))
    if os.path.isdir(path):
        items: List[Tuple[str, Any]] = []
        for name in ("conversations.json", "memories.json"):
            fp = os.path.join(path, name)
            if os.path.exists(fp):
                items.append(_load(fp))
        if not items:
            for name in sorted(os.listdir(path)):
                if name.endswith(".json"):
                    items.append(_load(os.path.join(path, name)))
        return items
    return [_load(path)]


# ---------------------------------------------------------------- import
def import_records(records: List[ImportRecord], memory, namespace: str = "imported",
                   roles: Tuple[str, ...] = ("user", "human", "memory"),
                   extract_mode: bool = False, dry_run: bool = False,
                   min_len: int = 12) -> ImportResult:
    res = ImportResult()
    res.conversations = len({r.conversation_id for r in records if r.conversation_id}) or (1 if records else 0)

    if extract_mode:
        from .extract import extract, extract_and_store
        grouped: Dict[str, List[ImportRecord]] = {}
        for r in records:
            grouped.setdefault(r.conversation_id, []).append(r)
        for _cid, rs in grouped.items():
            res.messages_seen += len(rs)
            text = "\n".join(f"{r.role}: {r.text}" for r in rs)
            if dry_run:
                res.imported += len(extract(text))
                continue
            ids = extract_and_store(text, memory, namespace=namespace)
            res.ids += ids
            res.imported += len(ids)
        return res

    seen: set = set()
    for r in records:
        res.messages_seen += 1
        if roles and r.role not in roles:
            continue
        t = r.text.strip()
        if len(t) < min_len:
            res.skipped_short += 1
            continue
        key = t.lower()
        if key in seen:
            res.skipped_dup += 1
            continue
        seen.add(key)
        if not dry_run and any(h.text.strip().lower() == key
                               for h in memory.recall(t, k=3, namespace=namespace)):
            res.skipped_dup += 1
            continue
        if dry_run:
            res.imported += 1
            continue
        tags = [x for x in (r.source, "import") if x]
        meta = {"source": r.source, "import": True, "role": r.role,
                "conversation_id": r.conversation_id, "conversation_title": r.conversation_title}
        rid = memory.remember(t, namespace=namespace, tags=tags, meta=meta, valid_from=r.ts)
        res.ids.append(rid)
        res.imported += 1
    return res


def import_path(path: str, memory, namespace: str = "imported", source: str = "auto",
                roles: Tuple[str, ...] = ("user", "human", "memory"),
                extract_mode: bool = False, dry_run: bool = False) -> ImportResult:
    """Top-level: auto-detect + parse + ingest an export file or directory."""
    all_recs: List[ImportRecord] = []
    detected: set = set()
    for hint, data in load_export(path):
        src = source if source and source != "auto" else sniff(data)
        if src == "unknown":
            low = hint.lower()
            if "claude" in low or "memor" in low:
                src = "claude"
            elif "chatgpt" in low or "conversation" in low:
                src = "chatgpt"
        if src == "chatgpt":
            all_recs += parse_chatgpt(data)
        elif src == "claude":
            all_recs += parse_claude(data)
        else:
            continue
        detected.add(src)
    res = import_records(all_recs, memory, namespace=namespace, roles=roles,
                         extract_mode=extract_mode, dry_run=dry_run)
    res.source = "+".join(sorted(detected)) if detected else "unknown"
    return res
