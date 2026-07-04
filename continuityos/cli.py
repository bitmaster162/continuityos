"""ContinuityOS CLI.
Memory:     cos remember | recall | namespaces | import
Continuity: cos canon | frontier | loop | checkpoint | doctor | handoff
Twin:       cos predict | alignment
Setup:      cos setup (guided onboarding wizard)
Serve:      cos serve (MCP stdio) | cos api (HTTP)
"""
from __future__ import annotations
import argparse, os, json, sys
from .memory import Memory
from .continuity import Continuity
from .twin import Twin

def _db(a): return a.db or os.path.expanduser("~/.continuityos/memory.db")

def main(argv=None):
    ap = argparse.ArgumentParser(prog="cos", description="ContinuityOS — durable memory + continuity for agents & humans")
    ap.add_argument("--db", default=None)
    s = ap.add_subparsers(dest="cmd", required=True)
    r = s.add_parser("remember"); r.add_argument("text"); r.add_argument("-n","--namespace",default="notes"); r.add_argument("-t","--tags",default="")
    q = s.add_parser("recall"); q.add_argument("query"); q.add_argument("-k",type=int,default=5); q.add_argument("-n","--namespace",default=None)
    q.add_argument("--as-of",dest="as_of",default=None,help="ISO date/datetime: what was true THEN")
    q.add_argument("--current-only",action="store_true",help="hide superseded/expired facts")
    q.add_argument("--type",dest="mtype",default=None,help="filter by semantic type (fact/preference/decision/...)")
    ex = s.add_parser("extract", help="Mem0-style ADD-only auto-extraction of memories from text/stdin")
    ex.add_argument("text", nargs="?"); ex.add_argument("-n","--namespace",default="facts")
    im = s.add_parser("import", help="Import ChatGPT/Claude export (conversations.json / memories.json) into memory")
    im.add_argument("path", help="export file or directory")
    im.add_argument("-n","--namespace",default="imported")
    im.add_argument("--source",default="auto",choices=["auto","chatgpt","claude"])
    im.add_argument("--extract",dest="distill",action="store_true",help="distill typed salient facts instead of raw turns")
    im.add_argument("--roles",default="user,human,memory",help="comma-separated roles to import (default: your own turns)")
    im.add_argument("--dry-run",dest="dry_run",action="store_true",help="report what would import, write nothing")
    s.add_parser("namespaces")
    cn = s.add_parser("canon"); cn.add_argument("text", nargs="?");
    fr = s.add_parser("frontier"); fr.add_argument("kind", nargs="?", choices=["trunk","cash","lab","parked"]); fr.add_argument("item", nargs="?")
    lp = s.add_parser("loop"); lp.add_argument("text", nargs="?"); lp.add_argument("--close", type=int, default=None)
    cp = s.add_parser("checkpoint"); cp.add_argument("--summary",required=True); cp.add_argument("--next",required=True,dest="nxt"); cp.add_argument("--proof",default="")
    s.add_parser("doctor")
    s.add_parser("handoff")
    s.add_parser("boot")
    bc = s.add_parser("close"); bc.add_argument("--summary",required=True); bc.add_argument("--next",required=True,dest="nxt"); bc.add_argument("--proof",default="")
    s.add_parser("compress")
    s.add_parser("serve")
    pa = s.add_parser("api"); pa.add_argument("--host",default="127.0.0.1"); pa.add_argument("--port",type=int,default=8077)
    pr = s.add_parser("predict", help="Digital-twin: likely stance on a situation, grounded in recorded rules and precedent")
    pr.add_argument("situation")
    al = s.add_parser("alignment", help="Check a proposed action against canon/rules; flags conflicts with non-negotiable rules")
    al.add_argument("action")
    sw = s.add_parser("setup", help="Guided onboarding wizard — sets up memory, frontiers, twin, agents, dashboard")
    sw.add_argument("--quick", action="store_true", help="accept all recommended defaults (non-interactive)")
    sw.add_argument("--dashboard-only", action="store_true", help="just (re)generate the ORCA dashboard")
    sm = s.add_parser("sim", help="Sim-OS: closed-loop self-improving simulation (ContinuityOS <-> Pandora)")
    sm.add_argument("--objective", default="test_metric")
    sm.add_argument("--iters", type=int, default=5)
    a = ap.parse_args(argv)

    if a.cmd == "setup":
        from . import wizard
        if a.dashboard_only:
            return wizard.build_dashboard_only(_db(a))
        return wizard.run_wizard(_db(a), quick=a.quick)
    if a.cmd == "sim":
        from .sim.loop import run_loop
        run_loop(a.objective, a.iters); return 0
    if a.cmd == "serve":
        from . import mcp_server; sys.argv = ["mcp","--db",_db(a)]; return mcp_server.main()
    if a.cmd == "api":
        from . import api; return api.run(_db(a), a.host, a.port)

    db = _db(a);
    try:
        from .embedders import FastEmbedEmbedder
        m = Memory(db, embedder=FastEmbedEmbedder())
    except Exception:
        m = Memory(db)
    c = Continuity(memory=m)
    t = Twin(memory=m)
    if a.cmd == "remember":
        tags=[t.strip() for t in a.tags.split(",") if t.strip()]
        print("stored #%d in [%s]" % (m.remember(a.text,namespace=a.namespace,tags=tags), a.namespace))
    elif a.cmd == "recall":
        as_of = None
        if a.as_of:
            import datetime as _dt
            as_of = _dt.datetime.fromisoformat(a.as_of).timestamp()
        for h in m.recall(a.query,k=a.k,namespace=a.namespace,as_of=as_of,
                          current_only=a.current_only,mtype=a.mtype):
            print("%.3f [%s] %s  (%s)" % (h.score,h.namespace,h.text,h.why))
    elif a.cmd == "extract":
        txt = a.text or sys.stdin.read()
        from .extract import extract_and_store
        ids = extract_and_store(txt, m, namespace=a.namespace)
        print("stored %d candidate(s): %s" % (len(ids), ids))
    elif a.cmd == "import":
        from .adapters import import_path
        roles = tuple(x.strip() for x in a.roles.split(",") if x.strip())
        res = import_path(a.path, m, namespace=a.namespace, source=a.source,
                          roles=roles, extract_mode=a.distill, dry_run=a.dry_run)
        d = res.as_dict()
        print("import [%s] %s%s: %d imported, %d dup, %d short (from %d msgs / %d conversations) -> ns [%s]" % (
            d["source"], os.path.basename(a.path.rstrip("/\\")) or a.path,
            " (dry-run)" if a.dry_run else "", d["imported"], d["skipped_dup"],
            d["skipped_short"], d["messages_seen"], d["conversations"], a.namespace))
        if res.ids:
            print("  ids: %s%s" % (res.ids[:10], " ..." if len(res.ids) > 10 else ""))
    elif a.cmd == "namespaces":
        print(json.dumps(m.namespaces(),ensure_ascii=False,indent=2))
    elif a.cmd == "canon":
        if a.text: print("canon #%d" % c.add_canon(a.text))
        else:
            for r in c._dump("canon"): print("- "+r["text"])
    elif a.cmd == "frontier":
        if a.kind and a.item: print("set %s -> %s (#%d)" % (a.kind,a.item,c.set_frontier(a.kind,a.item)))
        else: print(json.dumps(c.frontiers(),ensure_ascii=False,indent=2))
    elif a.cmd == "loop":
        if a.close is not None: c.close_loop(a.close); print("closed loop #%d" % a.close)
        elif a.text: print("loop #%d opened" % c.add_loop(a.text))
        else:
            for l in c.open_loops(): print("[#%d] %s" % (l["id"],l["text"]))
    elif a.cmd == "checkpoint":
        print("checkpoint #%d" % c.checkpoint(summary=a.summary,next_action=a.nxt,proof=a.proof))
    elif a.cmd == "doctor":
        d=c.doctor(); print("%s  %d/%d" % ("healthy" if d["healthy"] else "drift", d["passed"], d["total"]))
        for ch in d["checks"]: print("  %s %s — %s" % ("ok" if ch["ok"] else "x", ch["check"], ch["detail"]))
    elif a.cmd == "handoff":
        print(c.handoff())
    elif a.cmd == "boot":
        print(c.handoff()); print("\n--- doctor ---")
        d=c.doctor(); print("%s %d/%d" % ("OK" if d["healthy"] else "DRIFT", d["passed"], d["total"]))
        for ch in d["checks"]:
            if not ch["ok"]: print("  ! %s — %s" % (ch["check"], ch["detail"]))
    elif a.cmd == "close":
        cid=c.checkpoint(summary=a.summary, next_action=a.nxt, proof=a.proof)
        print("checkpoint #%d" % cid); d=c.doctor()
        print("doctor: %s %d/%d" % ("OK" if d["healthy"] else "DRIFT", d["passed"], d["total"]))
    elif a.cmd == "compress":
        print("namespace sizes (compress candidates):")
        for ns in m.namespaces(): print("  %-12s %d" % (ns["namespace"], ns["count"]))
        ol=c.open_loops()
        print("open loops: %d (close stale ones with: cos loop --close <id>)" % len(ol))
    elif a.cmd == "predict":
        print(json.dumps(t.predict(a.situation), ensure_ascii=False, indent=2))
    elif a.cmd == "alignment":
        print(json.dumps(t.alignment(a.action), ensure_ascii=False, indent=2))

if __name__ == "__main__":
    main()
