"""Migration adapters — import your existing AI history into ContinuityOS memory.

    cos import path/to/chatgpt-export/conversations.json   # OpenAI (DAG)
    cos import path/to/claude-export/                       # Anthropic (+ memories/projects)
    cos import Takeout/                                     # Google Gemini (MyActivity.json)
    cos import grok-export.json                             # xAI Grok (BSON $date)
    cos import lechat-export.json                           # Mistral Le Chat / Vibe
    cos import perplexity_thread.json                       # Perplexity (dual-schema)
    cos import export.json --extract                        # distill typed salient facts

Auto-detects six vendor export formats via Format-Detection Heuristics
(``sniff``): a ``mapping`` dict => OpenAI, ``chat_messages`` => Anthropic,
``userInteractions`` => Gemini, ``$numberLong`` => Grok, ``thread_metadata``/
``entries`` => Perplexity, else Mistral/Claude by shape. **Bi-temporal**: every
imported memory's ``valid_from`` is the ORIGINAL message time, so
``cos recall --as-of <date>`` reconstructs what you knew THEN. Deterministic,
fully offline (no API keys). Cross-platform dedup uses the **PAM content_hash**
standard (strip / Unicode-NFC / lowercase / collapse-whitespace / SHA-256), so
the same question asked to different models collapses to one memory.
"""
from __future__ import annotations
import json, os, re, hashlib, unicodedata
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class ImportRecord:
    text: str
    role: str = "user"
    ts: Optional[float] = None            # original message time (epoch seconds)
    conversation_id: str = ""
    conversation_title: str = ""
    source: str = ""                      # chatgpt|claude|gemini|grok|mistral|perplexity
    is_thought: bool = False              # Claude/Perplexity chain-of-thought block


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
    """Coerce a timestamp to epoch *seconds*. Handles epoch int/float (s or ms),
    ISO-8601 strings, and BSON wrappers ``{"$date": {"$numberLong": "<ms>"}}``
    (xAI Grok) / ``{"$date": "<iso>"}`` / ``{"$numberLong": "<ms>"}``."""
    if v is None:
        return None
    if isinstance(v, bool):
        return None
    if isinstance(v, (int, float)):
        f = float(v)
        return f / 1000.0 if f > 1e12 else f          # ms -> s
    if isinstance(v, dict):
        if "$date" in v:
            return _flt(v["$date"])
        if "$numberLong" in v:
            try:
                return float(v["$numberLong"]) / 1000.0
            except (ValueError, TypeError):
                return None
        return None
    if isinstance(v, str):
        s = v.strip()
        if not s:
            return None
        try:
            f = float(s)
            return f / 1000.0 if f > 1e12 else f
        except ValueError:
            pass
        try:
            import datetime as _dt
            return _dt.datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()
        except Exception:
            return None
    return None


def content_hash(text: str) -> str:
    """PAM content_hash: strip, Unicode-NFC, lowercase, collapse whitespace,
    SHA-256. Deterministic cross-platform dedup key."""
    s = unicodedata.normalize("NFC", (text or "").strip().lower())
    s = re.sub(r"\s+", " ", s)
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def _text_from_parts(parts: Any) -> str:
    """content.parts: list of strings and/or multimodal dicts ({"text": ...})."""
    out: List[str] = []
    for p in parts or []:
        if isinstance(p, str):
            out.append(p)
        elif isinstance(p, dict) and isinstance(p.get("text"), str):
            out.append(p["text"])
    return "\n".join(x for x in out if x and x.strip())


def _synth_title(text: str, n: int = 50) -> str:
    t = (text or "").strip().replace("\n", " ")
    return (t[:n] + "…") if len(t) > n else t


# ---------------------------------------------------------------- parsers
def parse_chatgpt(data: Any) -> List[ImportRecord]:
    """OpenAI conversations.json (DAG). Uses **backward traversal** from
    ``current_node`` up ``parent`` links, then reverses — reconstructing the
    canonical read path and discarding regenerated/rejected branches. Filters
    null-message placeholder nodes; falls back to session create_time."""
    convs = data if isinstance(data, list) else data.get("conversations", [data])
    recs: List[ImportRecord] = []
    for conv in convs:
        if not isinstance(conv, dict):
            continue
        title = conv.get("title") or ""
        cid = str(conv.get("conversation_id") or conv.get("id") or "")
        sess_ct = _flt(conv.get("create_time"))
        mapping = conv.get("mapping")
        ordered: List[dict] = []
        if isinstance(mapping, dict):
            cur = conv.get("current_node")
            chain: List[dict] = []
            seen: set = set()
            while cur and cur in mapping and cur not in seen:
                seen.add(cur)
                node = mapping[cur]
                if not isinstance(node, dict):
                    break
                msg = node.get("message")
                if isinstance(msg, dict):                 # skip null-message nodes
                    chain.append(msg)
                cur = node.get("parent")
            if chain:
                ordered = list(reversed(chain))
            else:                                          # no current_node: sort all msg nodes
                ordered = sorted(
                    (n["message"] for n in mapping.values()
                     if isinstance(n, dict) and isinstance(n.get("message"), dict)),
                    key=lambda m: _flt(m.get("create_time")) or 0.0)
        elif isinstance(conv.get("messages"), list):
            ordered = [m for m in conv["messages"] if isinstance(m, dict)]
        for msg in ordered:
            if not isinstance(msg, dict):
                continue
            author = msg.get("author") or {}
            role = author.get("role") or msg.get("role") or "user"
            content = msg.get("content")
            if isinstance(content, dict):
                text = _text_from_parts(content.get("parts"))
            elif isinstance(content, str):
                text = content
            else:
                text = ""
            if not text.strip():
                continue
            ts = _flt(msg.get("create_time")) or sess_ct
            recs.append(ImportRecord(text=text.strip(), role=role, ts=ts,
                                     conversation_id=cid, conversation_title=title, source="chatgpt"))
    return recs


def parse_claude(data: Any) -> List[ImportRecord]:
    """Anthropic export. conversations.json (chat_messages), memories.json
    (conversations_memory text block -> heuristic paragraph split), projects.json
    (project_memories UUID->text). Normalizes ``human`` -> ``user``, merges
    attachments+files, flags ``thinking`` blocks, drops tool/token_budget noise."""
    # memories.json shapes
    if isinstance(data, dict) and isinstance(data.get("conversations_memory"), str):
        return _split_memory_block(data["conversations_memory"], data.get("project_memories"))
    if isinstance(data, dict) and isinstance(data.get("project_memories"), dict):
        return _split_memory_block(data.get("conversations_memory", ""), data["project_memories"])
    if isinstance(data, dict) and isinstance(data.get("memories"), list):
        data = data["memories"]
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
                raw_role = msg.get("sender") or msg.get("role") or "user"
                role = "user" if raw_role in ("human", "user") else raw_role
                text = msg.get("text") or ""
                is_thought = False
                if isinstance(msg.get("content"), list):
                    parts: List[str] = []
                    for b in msg["content"]:
                        if not isinstance(b, dict):
                            continue
                        bt = b.get("type")
                        if bt == "thinking":
                            is_thought = True
                            parts.append(b.get("thinking") or b.get("text") or "")
                        elif bt in ("tool_use", "tool_result", "token_budget"):
                            continue                       # drop tool/budget noise
                        elif isinstance(b.get("text"), str):
                            parts.append(b["text"])
                    if parts and not text:
                        text = "\n".join(p for p in parts if p)
                recs.append(ImportRecord(
                    text=(text or "").strip(), role=role,
                    ts=_flt(msg.get("created_at") or conv.get("created_at")),
                    conversation_id=cid, conversation_title=title,
                    source="claude", is_thought=is_thought))
        else:
            text = conv.get("text") or conv.get("content") or conv.get("summary") or conv.get("name") or ""
            if isinstance(text, str) and text.strip():
                recs.append(ImportRecord(text=text.strip(), role="memory",
                                         ts=_flt(conv.get("created_at") or conv.get("updated_at")),
                                         source="claude"))
    return recs


def _split_memory_block(conv_mem: str, project_mem: Any) -> List[ImportRecord]:
    """Claude memories.json: split the global profile block into discrete units
    (by blank-line paragraphs) and unpack project_memories (UUID -> section text)."""
    recs: List[ImportRecord] = []
    for para in re.split(r"\n\s*\n", conv_mem or ""):
        p = para.strip()
        if len(p) >= 12:
            recs.append(ImportRecord(text=p, role="memory", source="claude"))
    if isinstance(project_mem, dict):
        for uuid, val in project_mem.items():
            if isinstance(val, str) and val.strip():
                recs.append(ImportRecord(text=val.strip(), role="memory",
                                         conversation_id=str(uuid),
                                         conversation_title="project:%s" % uuid, source="claude"))
    return recs


def _gemini_unwrap(v: Any) -> str:
    """Gemini Variant-B request/response are escaped JSON strings like
    '[{"text": "..."}]'. Deserialize then extract text."""
    if v is None:
        return ""
    if isinstance(v, list):
        return _text_from_parts(v)
    if isinstance(v, str):
        s = v.strip()
        if s[:1] in ("[", "{"):
            try:
                j = json.loads(s)
                if isinstance(j, list):
                    return _text_from_parts(j)
                if isinstance(j, dict):
                    return j.get("text", "") or ""
            except Exception:
                return s
        return s
    return ""


def parse_gemini(data: Any) -> List[ImportRecord]:
    """Google Takeout MyActivity.json — a flat activity log. Groups events by
    conversation id parsed from titleUrl (/app/c/<id>), sorts by ``time``,
    synthesizes a title from the first user prompt (all titles are the static
    "Used Gemini Apps"). Handles Variant A (title=prompt) and B (userInteractions)."""
    events = data if isinstance(data, list) else data.get("MyActivity", data.get("items", [data]))
    groups: Dict[str, List[Tuple[str, str, Optional[float]]]] = {}
    order: List[str] = []
    for ev in events:
        if not isinstance(ev, dict):
            continue
        turl = ev.get("titleUrl") or ""
        m = re.search(r"/app/c/([A-Za-z0-9_-]+)", turl)
        cid = m.group(1) if m else (turl or "gemini")
        ts = _flt(ev.get("time"))
        if cid not in groups:
            groups[cid] = []; order.append(cid)
        uis = ev.get("userInteractions")
        if isinstance(uis, list):                          # Variant B
            for ui in uis:
                inter = ui.get("userInteraction") if isinstance(ui, dict) else None
                if not isinstance(inter, dict):
                    continue
                req = _gemini_unwrap(inter.get("request"))
                resp = _gemini_unwrap(inter.get("response"))
                if req:
                    groups[cid].append(("user", req, ts))
                if resp:
                    groups[cid].append(("assistant", resp, ts))
        else:                                              # Variant A
            t = ev.get("title") or ""
            prompt = ""
            if t and t != "Used Gemini Apps":
                prompt = re.sub(r"^Prompted\s+", "", t)
            elif isinstance(ev.get("details"), list):
                prompt = _text_from_parts(ev["details"])
            if prompt:
                groups[cid].append(("user", prompt, ts))
    recs: List[ImportRecord] = []
    for cid in order:
        evs = sorted(groups[cid], key=lambda e: e[2] or 0.0)
        title = ""
        for role, text, ts in evs:
            if not title and role == "user" and text:
                title = _synth_title(text)
            if text and text.strip():
                recs.append(ImportRecord(text=text.strip(), role=role, ts=ts,
                                         conversation_id=cid, conversation_title=title, source="gemini"))
    return recs


def parse_grok(data: Any) -> List[ImportRecord]:
    """xAI Grok export. Session created_at is ISO-8601 but message timestamps
    leak BSON ``{"$date": {"$numberLong": "<ms>"}}`` — handled by _flt."""
    convs = data if isinstance(data, list) else data.get("conversations", [data])
    recs: List[ImportRecord] = []
    for conv in convs:
        if not isinstance(conv, dict):
            continue
        c = conv.get("conversation") if isinstance(conv.get("conversation"), dict) else conv
        title = c.get("title") or conv.get("title") or ""
        cid = str(c.get("id") or c.get("_id") or conv.get("id") or "")
        sess_ts = _flt(c.get("created_at") or conv.get("created_at"))
        msgs = conv.get("messages") or c.get("messages") or conv.get("responses") or []
        for m in msgs:
            if not isinstance(m, dict):
                continue
            role = m.get("sender") or m.get("role") or ("assistant" if m.get("is_assistant") else "user")
            text = m.get("message") or m.get("text") or m.get("content") or ""
            if isinstance(text, dict):
                text = text.get("text", "")
            elif isinstance(text, list):
                text = _text_from_parts(text)
            ts = _flt(m.get("create_time") or m.get("created_at") or m.get("timestamp")) or sess_ts
            if text and str(text).strip():
                recs.append(ImportRecord(text=str(text).strip(), role=str(role), ts=ts,
                                         conversation_id=cid, conversation_title=title, source="grok"))
    return recs


def parse_mistral(data: Any) -> List[ImportRecord]:
    """Mistral Le Chat / Vibe. Minimal flat export, base roles, no titles ->
    synthesize from first user turn. tool_calls already stripped by vendor."""
    convs = data if isinstance(data, list) else data.get("conversations", [data])
    recs: List[ImportRecord] = []
    for conv in convs:
        if not isinstance(conv, dict):
            continue
        msgs = conv.get("messages")
        if not isinstance(msgs, list):
            if conv.get("role") and (conv.get("content") or conv.get("text")):
                msgs = [conv]
            else:
                continue
        cid = str(conv.get("id") or conv.get("chat_id") or "")
        title = conv.get("title") or ""
        start = len(recs); first_user = ""
        for m in msgs:
            if not isinstance(m, dict):
                continue
            role = m.get("role") or "user"
            text = m.get("content") or m.get("text") or ""
            if isinstance(text, list):
                text = _text_from_parts(text)
            ts = _flt(m.get("created_at") or m.get("timestamp"))
            if role == "user" and not first_user and text:
                first_user = str(text)
            if text and str(text).strip():
                recs.append(ImportRecord(text=str(text).strip(), role=str(role), ts=ts,
                                         conversation_id=cid, conversation_title=title, source="mistral"))
        if not title and first_user:
            st = _synth_title(first_user)
            for r in recs[start:]:
                r.conversation_title = st
    return recs


def parse_perplexity(data: Any) -> List[ImportRecord]:
    """Perplexity dual-schema: {"conversations": [...]} OR {"thread_metadata":..,
    "entries":[...]}. Preserves citation markers by appending sources as a footer
    and related_queries as a trailer."""
    threads = data if isinstance(data, list) else [data]
    recs: List[ImportRecord] = []
    for th in threads:
        if not isinstance(th, dict):
            continue
        meta = th.get("thread_metadata") if isinstance(th.get("thread_metadata"), dict) else {}
        title = meta.get("title") or th.get("title") or ""
        cid = str(meta.get("id") or th.get("id") or "") or "perplexity"
        entries = th.get("entries")
        if not isinstance(entries, list):
            entries = th.get("conversations")
        if not isinstance(entries, list):
            continue
        for e in entries:
            if not isinstance(e, dict):
                continue
            role = e.get("role") or ("user" if "query" in e else "assistant")
            text = e.get("query") or e.get("answer") or e.get("content") or e.get("text") or ""
            text = str(text)
            ts = _flt(e.get("created_at") or e.get("time") or th.get("created_at") or (meta or {}).get("created_at"))
            srcs = e.get("sources") or e.get("annotations")
            if role != "user" and isinstance(srcs, list) and srcs:
                refs = "\n".join("[%d] %s" % (i + 1, s if isinstance(s, str) else s.get("url", ""))
                                 for i, s in enumerate(srcs))
                text = text + "\n\nSources:\n" + refs
            rq = e.get("related_queries")
            if isinstance(rq, list) and rq:
                text = text + "\n\nRelated: " + "; ".join(str(x) for x in rq)
            if not title and role == "user" and text:
                title = _synth_title(text)
            if text.strip():
                recs.append(ImportRecord(text=text.strip(), role=str(role), ts=ts,
                                         conversation_id=cid, conversation_title=title, source="perplexity"))
    return recs


_PARSERS = {"chatgpt": parse_chatgpt, "claude": parse_claude, "gemini": parse_gemini,
            "grok": parse_grok, "mistral": parse_mistral, "perplexity": parse_perplexity}


def sniff(data: Any) -> str:
    """Format-Detection Heuristics — classify an export by root-element shape."""
    probe = data[0] if isinstance(data, list) and data else data
    if isinstance(probe, dict):
        if "mapping" in probe:
            return "chatgpt"
        if "chat_messages" in probe:
            return "claude"
        if "userInteractions" in probe or probe.get("header") == "Gemini" or (
                "titleUrl" in probe and "title" in probe):
            return "gemini"
        if "thread_metadata" in probe or "entries" in probe or "related_queries" in probe:
            return "perplexity"
    if isinstance(data, dict):
        if "memories" in data or "conversations_memory" in data or "project_memories" in data:
            return "claude"
        if "MyActivity" in data:
            return "gemini"
    if isinstance(probe, str):
        return "claude"
    try:
        blob = json.dumps(data)[:6000]
        if '"$numberLong"' in blob or '"$date"' in blob:
            return "grok"
    except Exception:
        pass
    # last resort: a flat list of {role, content} with no vendor markers => mistral
    if isinstance(probe, dict) and probe.get("role") and (probe.get("content") or probe.get("text")):
        return "mistral"
    if isinstance(probe, dict) and isinstance(probe.get("messages"), list):
        return "mistral"
    return "unknown"


def load_export(path: str) -> List[Tuple[str, Any]]:
    """Load one file or a whole export directory (incl. Google Takeout layout)."""
    def _load(fp):
        return (os.path.basename(fp), json.load(open(fp, encoding="utf-8")))
    if os.path.isdir(path):
        items: List[Tuple[str, Any]] = []
        # Google Takeout nests MyActivity.json under My Activity/Gemini Apps/
        for root, _dirs, files in os.walk(path):
            for name in files:
                if name == "MyActivity.json":
                    items.append(_load(os.path.join(root, name)))
        for name in ("conversations.json", "memories.json", "projects.json"):
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
            text = "\n".join("%s: %s" % (r.role, r.text) for r in rs)
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
        key = content_hash(t)                              # PAM cross-platform dedup
        if key in seen:
            res.skipped_dup += 1
            continue
        seen.add(key)
        if not dry_run and any(content_hash(h.text) == key
                               for h in memory.recall(t, k=3, namespace=namespace)):
            res.skipped_dup += 1
            continue
        if dry_run:
            res.imported += 1
            continue
        tags = [x for x in (r.source, "import") if x]
        meta = {"source": r.source, "import": True, "role": r.role,
                "conversation_id": r.conversation_id, "conversation_title": r.conversation_title}
        if r.is_thought:
            meta["is_thought"] = True
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
            if "myactivity" in low or "takeout" in low or "gemini" in low:
                src = "gemini"
            elif "grok" in low:
                src = "grok"
            elif "perplexity" in low:
                src = "perplexity"
            elif "lechat" in low or "mistral" in low or "vibe" in low:
                src = "mistral"
            elif "claude" in low or "memor" in low or "project" in low:
                src = "claude"
            elif "chatgpt" in low or "conversation" in low:
                src = "chatgpt"
        parser = _PARSERS.get(src)
        if parser is None:
            continue
        all_recs += parser(data)
        detected.add(src)
    res = import_records(all_recs, memory, namespace=namespace, roles=roles,
                         extract_mode=extract_mode, dry_run=dry_run)
    res.source = "+".join(sorted(detected)) if detected else "unknown"
    return res
