"""ContinuityOS MCP server (stdio transport, dependency-free).

Exposes durable memory to any MCP client (Claude Desktop, Claude Code, etc.):
  - remember(text, namespace?, tags?)   -> store a memory
  - recall(query, k?, namespace?)        -> hybrid (structural+semantic) recall
  - upsert(text, namespace?, key)        -> create-or-update by semantic key (idempotent)
  - find(namespace?, key)                -> exact key lookup (deterministic point-read)
  - forget(id)                           -> delete a memory
  - list_namespaces()                    -> folder-like overview
  - context(query, k?)                   -> ready-to-inject context block

Run:  python -m continuityos.mcp_server --db ~/.continuityos/memory.db [--policy path/to/policy.json]
Newline-delimited JSON-RPC over stdin/stdout (MCP stdio transport).
"""
from __future__ import annotations
import sys, json, os, argparse
from .memory import Memory
from .continuity import Continuity
from .twin import Twin
from .control import ControlPlane
from .db import resolve_memory_db
from .gate import ActionSpec as _AS, preflight as _preflight, Ledger as _Ledger
from .gate.policy import discover_policy as _discover_policy, load_policy as _load_policy
from . import __version__

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
 {"name":"upsert","description":"Create-or-update a memory by semantic KEY (idempotent). If (namespace,key) exists it is superseded (history kept) and replaced; else created. Use for stable values an agent overwrites over time: a config value, a current decision, a user preference.",
  "inputSchema":{"type":"object","properties":{
     "text":{"type":"string","description":"The new value."},
     "namespace":{"type":"string","default":"facts"},
     "key":{"type":"string","description":"Stable semantic key, e.g. default_model or user.timezone."},
     "tags":{"type":"array","items":{"type":"string"}}},
   "required":["text","key"]}},
 {"name":"find","description":"Exact key lookup: the CURRENT value stored under (namespace,key), or null. Deterministic point-read (not fuzzy recall) - reads back what upsert wrote.",
  "inputSchema":{"type":"object","properties":{
     "namespace":{"type":"string","default":"facts"},
     "key":{"type":"string"}},
   "required":["key"]}},
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
 {"name":"preflight_action","description":"ADVISORY PREFLIGHT: returns a safety decision for a typed action. The MCP tool does not intercept other tools; the caller must enforce the result.",
  "inputSchema":{"type":"object","properties":{"tool":{"type":"string","default":"shell"},"command":{"type":"string"},"args":{"type":"array","items":{"type":"string"},"description":"Exact argument vector assessed by tool_schemas.max_args."},"paths":{"type":"array","items":{"type":"string"}},"cwd":{"type":"string","description":"Authoritative execution working directory; required for reliable relative-path decisions."}},"required":["command","args"]}},
 {"name":"srd_status","description":"Long-session safety: interaction count vs Safe Turn Depth. When reinject_due=true, re-inject the returned canon_reminder into context - omission-rules ('never do X') decay by ~turn 10 (Security-Recall Divergence).",
  "inputSchema":{"type":"object","properties":{}}},
 {"name":"memory_pointer","description":"Pass-by-reference: get a lightweight {namespace,key,version} pointer to a memory value instead of its content (A2A courier-tax fix). Dereference with recall/find.",
  "inputSchema":{"type":"object","properties":{"namespace":{"type":"string","default":"facts"},"key":{"type":"string"}},"required":["key"]}},
 {"name":"memory_write_checked","description":"Optimistic-concurrency write by key: succeeds only if current version equals expected_version, else returns a conflict. Prevents lost updates when multiple agents write the same key.",
  "inputSchema":{"type":"object","properties":{"text":{"type":"string"},"namespace":{"type":"string","default":"facts"},"key":{"type":"string"},"expected_version":{"type":"integer"}},"required":["text","key","expected_version"]}},
 {"name":"devils_advocate","description":"Challenge a claim or proposed action against your own memory + canon BEFORE acting: flags contradictions, superseded facts, missing evidence, canon conflicts, overconfidence, dishonest omissions, irreversible actions. Returns a verdict (STOP/RECONSIDER/PROCEED WITH CAUTION/PROCEED). Call before consequential moves.",
  "inputSchema":{"type":"object","properties":{"claim":{"type":"string"},"action":{"type":"boolean","default":False},"namespace":{"type":"string"}},"required":["claim"]}},
 {"name":"system_audit","description":"Full-system audit: memory inventory + invariants (append-only integrity, bi-temporal ordering, canon presence, dangling supersede pointers). devil=true runs the devil's advocate over every failing finding. EU-AI-Act Article-12 style record.",
  "inputSchema":{"type":"object","properties":{"devil":{"type":"boolean","default":False}}}}
]

class Server:
    def __init__(self, db=None, policy_path: str = "", db_source: str = ""):
        resolved = resolve_memory_db(db)
        db = resolved["path"]
        configured_missing = (
            resolved["configured"]
            and db != ":memory:"
            and not os.path.isfile(db)
        )
        try:
            from .embedders import FastEmbedEmbedder
            self.m = Memory(db, embedder=FastEmbedEmbedder())
        except Exception:
            self.m = Memory(db)  # fallback to HashingEmbedder
        self.c = Continuity(memory=self.m)
        self.c._context_source = db_source or resolved["source"]
        self._governance_context_error = (
            f"configured memory database was missing at server startup: {db}; "
            "initialize it intentionally and restart before governance preflight"
            if configured_missing
            else ""
        )
        self.t = Twin(memory=self.m)
        self.ctl = ControlPlane(memory=self.m)
        runtime_policy = policy_path or _discover_policy(os.path.expanduser("~/.continuityos"))
        self.policy = _load_policy(runtime_policy)
        self.turns = 0
        self.std = 10  # Safe Turn Depth: re-inject canon before omission-rules ("never do X") decay (long-session SRD research)

    def call(self, name, args):
        self.turns += 1
        if name == "remember":
            rid = self.m.remember(args["text"], namespace=args.get("namespace","notes"), tags=args.get("tags"))
            return f"stored #{rid} in [{args.get('namespace','notes')}]"
        if name == "recall":
            hits = self.m.recall(args["query"], k=int(args.get("k",5)), namespace=args.get("namespace"))
            return json.dumps([h.to_dict() for h in hits], ensure_ascii=False, indent=2)
        if name == "context":
            return self.m.context(args["query"], k=int(args.get("k",6))) or "(no relevant memory)"
        if name == "upsert":
            rid = self.m.upsert(args["text"], namespace=args.get("namespace","facts"), key=args["key"], tags=args.get("tags"))
            return f"upserted #{rid} in [{args.get('namespace','facts')}] key={args['key']}"
        if name == "find":
            hit = self.m.find(args.get("namespace","facts"), args["key"])
            return json.dumps(hit.to_dict(), ensure_ascii=False, indent=2) if hit else "null"
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
            spec=_AS(tool=args.get("tool","shell"), command=args["command"], args=args.get("args"), paths=args.get("paths",[]), cwd=args.get("cwd",""), agent="mcp")
            governance_context_error = getattr(
                self, "_governance_context_error", None
            )
            if governance_context_error is None:
                spec.meta["context_error"] = (
                    "governance context initialization state unavailable"
                )
            elif governance_context_error:
                spec.meta["context_error"] = governance_context_error
            with _Ledger(os.path.expanduser("~/.continuityos/ledger.db")) as ledger:
                decision = _preflight(spec, policy=self.policy, ledger=ledger, context=self.c)
            return json.dumps(decision, ensure_ascii=False, indent=2)
        if name == "srd_status":
            due = self.turns >= self.std
            canon = [r["text"] for r in self.c._dump("canon")][:8]
            if due: self.turns = 0
            return json.dumps({"turns": self.turns, "safe_turn_depth": self.std, "reinject_due": due,
                               "canon_reminder": canon if due else [],
                               "note": "Omission-rules decay by ~turn 10 (SRD); re-inject canon_reminder when reinject_due."},
                              ensure_ascii=False, indent=2)
        if name == "memory_pointer":
            ptr = self.m.pointer(args.get("namespace", "facts"), args["key"])
            return json.dumps(ptr, ensure_ascii=False) if ptr else "null"
        if name == "memory_write_checked":
            from .memory import Conflict
            try:
                rid = self.m.write_checked(args["text"], namespace=args.get("namespace", "facts"),
                                           key=args["key"], expected_version=int(args["expected_version"]))
                return "wrote #%d to %s/%s" % (rid, args.get("namespace", "facts"), args["key"])
            except Conflict as e:
                return json.dumps({"error": "conflict", "detail": str(e)}, ensure_ascii=False)
        if name == "devils_advocate":
            from .advocate import DevilsAdvocate
            da = DevilsAdvocate(self.m, self.t)
            r = da.challenge(args["claim"], action=bool(args.get("action", False)), namespace=args.get("namespace"))
            da.record(r)
            return json.dumps({"verdict": r["verdict"], "flags": r["flags"], "open_questions": r["open_questions"]}, ensure_ascii=False, indent=2)
        if name == "system_audit":
            from .audit import SystemAudit
            return json.dumps(SystemAudit(self.m, self.c, self.t).run(devil=bool(args.get("devil", False))), ensure_ascii=False, indent=2)
        raise ValueError(f"unknown tool {name}")

def _send(obj):
    sys.stdout.write(json.dumps(obj) + "\n"); sys.stdout.flush()

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default=None)
    ap.add_argument("--policy", default="", help="Path to one JSON policy, or YAML when PyYAML is installed")
    a = ap.parse_args()
    srv = Server(a.db, a.policy)
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
                "serverInfo":{"name":"continuityos","version":__version__}}})
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
