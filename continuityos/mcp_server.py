"""ContinuityOS MCP server (stdio transport, dependency-free).

Exposes durable memory to any MCP client (Claude Desktop, Claude Code, etc.):
  - remember(text, namespace?, tags?)   -> store a memory
  - recall(query, k?, namespace?)        -> hybrid (structural+semantic) recall
  - forget(id)                           -> delete a memory
  - list_namespaces()                    -> folder-like overview
  - context(query, k?)                   -> ready-to-inject context block

Run:  python -m continuityos.mcp_server --db ~/.continuityos/memory.db
Newline-delimited JSON-RPC over stdin/stdout (MCP stdio transport).
"""
from __future__ import annotations
import sys, json, os, argparse
from .memory import Memory
from .continuity import Continuity
from .twin import Twin
from .control import ControlPlane
from .gate import ActionSpec as _AS, preflight as _preflight, Ledger as _Ledger

PROTOCOL = "2024-11-05"

TOOLS = [
 {"name":"remember","description":"Store a durable memory. Use for facts about the user, projects, rules, decisions you should recall later.",
  "inputSchema":{"type":"object","properties":{
     "text":{"type":"string","description":"The memory content."},
     "namespace":{"type":"string","description":"Folder-like bucket: identity|projects|rules|facts|events|notes (or your own).","default":"notes"},
     "tags":{"type":"array","items":{"type":"string"},"description":"Optional tags."}},
   "required":["text"]}},
 {"name":"recall","description":"Hybrid recall (structural keyword + semantic vector) of the most relevant memories for a query.",
  "inputSchema":{"type":"object","properties":{
     "query":{"type":"string"},
     "k":{"type":"integer","default":5},
     "namespace":{"type":"string","description":"Optional: restrict to one namespace."}},
   "required":["query"]}},
 {"name":"context","description":"Return a ready-to-inject context block of the most relevant memories for a query.",
  "inputSchema":{"type":"object","properties":{"query":{"type":"string"},"k":{"type":"integer","default":6}},"required":["query"]}},
 {"name":"forget","description":"Delete a memory by id.",
  "inputSchema":{"type":"object","properties":{"id":{"type":"integer"}},"required":["id"]}},
 {"name":"list_namespaces","description":"List folder-like namespaces and how many memories each holds.",
  "inputSchema":{"type":"object","properties":{}}} ,
 {"name":"checkpoint","description":"Close a session: record a delta, the next irreversible action, and a proof artifact path.",
  "inputSchema":{"type":"object","properties":{"summary":{"type":"string"},"next_action":{"type":"string"},"proof":{"type":"string"}},"required":["summary","next_action"]}},
 {"name":"handoff","description":"Return a handoff pack (canon + frontiers + open loops + last checkpoint) to resume context in a new session/agent.",
  "inputSchema":{"type":"object","properties":{}}},
 {"name":"doctor","description":"Anti-drift check: cash/trunk frontier set, open loops bounded, checkpoint fresh, has proof.",
  "inputSchema":{"type":"object","properties":{}}},
 {"name":"set_frontier","description":"Set the trunk/cash/lab/parked focus (1 trunk + 1 cash + 1 lab discipline).",
  "inputSchema":{"type":"object","properties":{"kind":{"type":"string","enum":["trunk","cash","lab","parked"]},"item":{"type":"string"}},"required":["kind","item"]}},
 {"name":"predict","description":"Digital-twin: likely stance on a situation, grounded in recorded rules and precedent.",
  "inputSchema":{"type":"object","properties":{"situation":{"type":"string"}},"required":["situation"]}},
 {"name":"alignment","description":"Check a proposed action against canon/rules; flags conflicts with non-negotiable rules.",
  "inputSchema":{"type":"object","properties":{"proposed_action":{"type":"string"}},"required":["proposed_action"]}},
 {"name":"preflight_action","description":"GOVERNANCE GATE: before running a tool/shell command, get a safety decision (ALLOW/WARN/HOLD/DENY/REQUIRE_CONFIRMATION/DRY_RUN_ONLY) with reasons + rollback plan. Call this BEFORE any dangerous action.",
  "inputSchema":{"type":"object","properties":{"tool":{"type":"string","default":"shell"},"command":{"type":"string"},"paths":{"type":"array","items":{"type":"string"}}},"required":["command"]}}
]

class Server:
    def __init__(self, db):
        try:
            from .embedders import FastEmbedEmbedder
            self.m = Memory(db, embedder=FastEmbedEmbedder())
        except Exception:
            self.m = Memory(db)  # fallback to HashingEmbedder
        self.c = Continuity(memory=self.m)
        self.t = Twin(memory=self.m)
        self.ctl = ControlPlane(memory=self.m)

    def call(self, name, args):
        if name == "remember":
            rid = self.m.remember(args["text"], namespace=args.get("namespace","notes"), tags=args.get("tags"))
            return f"stored #{rid} in [{args.get('namespace','notes')}]"
        if name == "recall":
            hits = self.m.recall(args["query"], k=int(args.get("k",5)), namespace=args.get("namespace"))
            return json.dumps([h.to_dict() for h in hits], ensure_ascii=False, indent=2)
        if name == "context":
            return self.m.context(args["query"], k=int(args.get("k",6))) or "(no relevant memory)"
        if name == "forget":
            self.m.forget(int(args["id"])); return f"forgot #{args['id']}"
        if name == "list_namespaces":
            return json.dumps(self.m.namespaces(), ensure_ascii=False, indent=2)
        if name == "checkpoint":
            return f"checkpoint #{self.c.checkpoint(summary=args['summary'], next_action=args['next_action'], proof=args.get('proof',''))}"
        if name == "handoff":
            return self.c.handoff()
        if name == "doctor":
            return json.dumps(self.c.doctor(), ensure_ascii=False, indent=2)
        if name == "set_frontier":
            return f"set {args['kind']} -> {args['item']} (#{self.c.set_frontier(args['kind'], args['item'])})"
        if name == "predict":
            return json.dumps(self.t.predict(args["situation"]), ensure_ascii=False, indent=2)
        if name == "alignment":
            return json.dumps(self.t.alignment(args["proposed_action"]), ensure_ascii=False, indent=2)
        if name == "preflight_action":
            spec=_AS(tool=args.get("tool","shell"), command=args["command"], paths=args.get("paths",[]), agent="mcp")
            return json.dumps(_preflight(spec, ledger=_Ledger(os.path.expanduser("~/.continuityos/ledger.db"))), ensure_ascii=False, indent=2)
        raise ValueError(f"unknown tool {name}")

def _send(obj):
    sys.stdout.write(json.dumps(obj) + "\n"); sys.stdout.flush()

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default=os.path.expanduser("~/.continuityos/memory.db"))
    a = ap.parse_args()
    srv = Server(a.db)
    for line in sys.stdin:
        line = line.strip()
        if not line: continue
        try:
            req = json.loads(line)
        except Exception:
            continue
        mid = req.get("id"); method = req.get("method")
        if method == "initialize":
            _send({"jsonrpc":"2.0","id":mid,"result":{
                "protocolVersion":PROTOCOL,
                "capabilities":{"tools":{}},
                "serverInfo":{"name":"continuityos","version":"0.1.0"}}})
        elif method == "notifications/initialized":
            continue
        elif method == "tools/list":
            _send({"jsonrpc":"2.0","id":mid,"result":{"tools":TOOLS}})
        elif method == "tools/call":
            p = req.get("params",{}) or {}
            try:
                out = srv.call(p.get("name"), p.get("arguments",{}) or {})
                _send({"jsonrpc":"2.0","id":mid,"result":{"content":[{"type":"text","text":str(out)}]}})
            except Exception as e:
                _send({"jsonrpc":"2.0","id":mid,"result":{"isError":True,"content":[{"type":"text","text":f"error: {e}"}]}})
        elif method == "ping":
            _send({"jsonrpc":"2.0","id":mid,"result":{}})
        else:
            if mid is not None:
                _send({"jsonrpc":"2.0","id":mid,"error":{"code":-32601,"message":f"method not found: {method}"}})

if __name__ == "__main__":
    main()
