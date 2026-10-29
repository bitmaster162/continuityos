"""Allowlisted CENTRAL MEMORY MCP adapter; core and client configs remain unchanged."""
from __future__ import annotations
import argparse, hashlib, json, os, sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from . import __version__
from .mcp_server import PROTOCOL, Server as CoreServer

REGISTRY_SCHEMA = "continuityos.ai_selection_registry/v1"
FIELDS = ("line", "executor_chat", "bucket", "current_state", "next_turn", "evidence", "updated_at")
MAX_REGISTRY_BYTES = 1_048_576
TOOLS = [
 {"name":"registry_read","description":"Read bounded AI-selection registry projection; never promotes canonical truth.","inputSchema":{"type":"object","properties":{},"additionalProperties":False}},
 {"name":"memory_recall","description":"Read-only ContinuityOS memory recall.","inputSchema":{"type":"object","properties":{"query":{"type":"string","minLength":1},"k":{"type":"integer","minimum":1,"maximum":20},"namespace":{"type":"string"}},"required":["query"],"additionalProperties":False}},
 {"name":"memory_find","description":"Read-only exact memory lookup.","inputSchema":{"type":"object","properties":{"namespace":{"type":"string"},"key":{"type":"string","minLength":1}},"required":["key"],"additionalProperties":False}},
 {"name":"memory_namespaces","description":"Read-only list of memory namespaces.","inputSchema":{"type":"object","properties":{},"additionalProperties":False}},
 {"name":"journal_append","description":"Append a bounded journal entry.","inputSchema":{"type":"object","properties":{"event":{"type":"string","minLength":1,"maxLength":128},"line":{"type":"string","maxLength":512},"evidence":{"type":"string","maxLength":4096}},"required":["event"],"additionalProperties":False}},
 {"name":"gate_request","description":"GateBroker preflight only; never executes the requested action.","inputSchema":{"type":"object","properties":{"request_id":{"type":"string","minLength":1,"maxLength":256},"argv":{"type":"array","minItems":1,"maxItems":256,"items":{"type":"string","maxLength":32768}},"cwd":{"type":"string","minLength":1,"maxLength":32768},"paths":{"type":"array","maxItems":256,"items":{"type":"string","maxLength":32768}}},"required":["request_id","argv","cwd"],"additionalProperties":False}},
]
_ALLOWED = {t["name"] for t in TOOLS}

class CentralMemoryMCPAdapter:
    def __init__(self, core_server: Any, registry_path: str, journal_path: str):
        self._core = core_server
        self._registry = Path(registry_path).expanduser()
        self._journal = Path(journal_path).expanduser()

    def _read_registry(self):
        try:
            raw = self._registry.read_bytes()
        except FileNotFoundError as exc:
            raise ValueError("AI_SELECTION_REGISTRY_NOT_FOUND") from exc
        if len(raw) > MAX_REGISTRY_BYTES:
            raise ValueError("AI_SELECTION_REGISTRY_TOO_LARGE")
        try:
            doc = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("AI_SELECTION_REGISTRY_INVALID_JSON") from exc
        if not isinstance(doc, dict) or doc.get("schema") != REGISTRY_SCHEMA:
            raise ValueError("AI_SELECTION_REGISTRY_SCHEMA_MISMATCH")
        records = doc.get("records")
        if not isinstance(records, list) or len(records) > 100:
            raise ValueError("AI_SELECTION_REGISTRY_RECORDS_INVALID")
        out = []
        for rec in records:
            if not isinstance(rec, dict) or any(not isinstance(rec.get(k), str) for k in FIELDS):
                raise ValueError("AI_SELECTION_REGISTRY_RECORD_INVALID")
            out.append({k: rec[k] for k in FIELDS})
        return {"schema": REGISTRY_SCHEMA, "mode": "READ_ONLY_SELECTION_PROJECTION",
                "canonical_truth_promoted": False, "records": out,
                "source_sha256": hashlib.sha256(raw).hexdigest()}

    def _journal_append(self, args):
        event, line, evidence = args.get("event"), args.get("line", ""), args.get("evidence", "")
        if not isinstance(event, str) or not event.strip() or len(event) > 128:
            raise ValueError("JOURNAL_EVENT_INVALID")
        if not isinstance(line, str) or len(line) > 512 or not isinstance(evidence, str) or len(evidence) > 4096:
            raise ValueError("JOURNAL_FIELDS_INVALID")
        entry = {"schema":"continuityos.ai_selection_journal/v1","event":event,"line":line,
                 "evidence":evidence,"recorded_at":datetime.now(timezone.utc).isoformat()}
        data = (json.dumps(entry, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
        self._journal.parent.mkdir(parents=True, exist_ok=True)
        flags = os.O_APPEND | os.O_CREAT | os.O_WRONLY
        if hasattr(os, "O_BINARY"): flags |= os.O_BINARY
        fd = os.open(str(self._journal), flags, 0o600)
        with os.fdopen(fd, "ab") as stream:
            stream.write(data); stream.flush(); os.fsync(stream.fileno())
        return json.dumps({"appended":True,"entry_sha256":hashlib.sha256(data.rstrip(b"\n")).hexdigest()})

    def call(self, name: str, arguments: Any):
        # Deny by default before dispatch: forget/delete/write/execute_preflight are not reachable.
        if name not in _ALLOWED:
            raise PermissionError("TOOL_NOT_EXPOSED_BY_CENTRAL_MEMORY_ADAPTER")
        if not isinstance(arguments, dict):
            raise ValueError("ARGUMENTS_MUST_BE_OBJECT")
        if name == "registry_read":
            if arguments: raise ValueError("REGISTRY_READ_TAKES_NO_ARGUMENTS")
            return json.dumps(self._read_registry(), ensure_ascii=False, sort_keys=True)
        if name == "memory_recall": return self._core.call("recall", arguments)
        if name == "memory_find": return self._core.call("find", arguments)
        if name == "memory_namespaces":
            if arguments: raise ValueError("MEMORY_NAMESPACES_TAKES_NO_ARGUMENTS")
            return self._core.call("list_namespaces", {})
        if name == "journal_append": return self._journal_append(arguments)
        if name == "gate_request":
            # Exact GateBroker preflight only; never call execute_preflight.
            return self._core.call("preflight_exec", arguments)
        raise PermissionError("TOOL_NOT_EXPOSED_BY_CENTRAL_MEMORY_ADAPTER")

def _send(obj):
    sys.stdout.write(json.dumps(obj, ensure_ascii=False) + "\n"); sys.stdout.flush()

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default=None)
    ap.add_argument("--registry", default=os.environ.get("CONTINUITYOS_AI_SELECTION_PATH", "~/.continuityos/ai_selection_registry.json"))
    ap.add_argument("--journal", default=os.environ.get("CONTINUITYOS_ADAPTER_JOURNAL", "~/.continuityos/ai_selection_journal.jsonl"))
    a = ap.parse_args()
    adapter = CentralMemoryMCPAdapter(CoreServer(a.db), a.registry, a.journal)
    for raw in sys.stdin:
        if not raw.strip(): continue
        try: req = json.loads(raw)
        except json.JSONDecodeError: continue
        mid, method = req.get("id"), req.get("method")
        if method == "initialize":
            _send({"jsonrpc":"2.0","id":mid,"result":{"protocolVersion":PROTOCOL,"capabilities":{"tools":{}},
                   "serverInfo":{"name":"continuityos-central-memory-adapter","version":__version__}}})
        elif method == "notifications/initialized": continue
        elif method == "tools/list": _send({"jsonrpc":"2.0","id":mid,"result":{"tools":TOOLS}})
        elif method == "tools/call":
            p = req.get("params", {}) or {}
            try:
                result = adapter.call(p.get("name"), p.get("arguments", {}) or {})
                _send({"jsonrpc":"2.0","id":mid,"result":{"content":[{"type":"text","text":str(result)}]}})
            except Exception as exc:
                _send({"jsonrpc":"2.0","id":mid,"result":{"isError":True,"content":[{"type":"text","text":f"{type(exc).__name__}: {exc}"}]}})
        elif method == "ping": _send({"jsonrpc":"2.0","id":mid,"result":{}})
        elif mid is not None: _send({"jsonrpc":"2.0","id":mid,"error":{"code":-32601,"message":f"method not found: {method}"}})

if __name__ == "__main__": main()
