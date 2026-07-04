"""ContinuityOS CLI.
Memory:     cos remember | recall | namespaces | import
Continuity: cos canon | frontier | loop | checkpoint | doctor | handoff | rules
Twin:       cos predict | alignment
RaaS:       cos usage (metering + plan quota)
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
    # Windows consoles default to cp1252 and crash on Cyrillic/emoji memory output; force UTF-8.
    for _stream in (sys.stdout, sys.stderr):
        try:
            _stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    ap = argparse.ArgumentParser(prog="cos", description="ContinuityOS — durable memory + continuity for agents & humans")
    ap.add_argument("--db", default=None)
    s = ap.add_subparsers(dest="cmd", required=True)
    r = s.add_parser("remember"); r.add_argument("text"); r.add_argument("-n","--namespace",default="notes"); r.add_argument("-t","--tags",default=""); r.add_argument("-K","--key",default=None,help="semantic key: upsert (create-or-update) instead of append")
    fi = s.add_parser("find", help="Exact key lookup: current value under namespace/key (deterministic, not fuzzy)")
    fi.add_argument("namespace"); fi.add_argument("key")
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
    ru = s.add_parser("rules", help="Export canon+rules to agent configs (CLAUDE.md / AGENTS.md / .cursor/rules)")
    ru.add_argument("--to", default="all", choices=["all","claude","agents","cursor"])
    ru.add_argument("--out", default=".", help="directory to write agent config files into")
    ru.add_argument("--stdout", action="store_true", help="print rendered rules instead of writing files")
    ru.add_argument("--dry-run", dest="dry_run", action="store_true")
    s.add_parser("scan", help="SCAN: reload rule-attention before a critical action (long-session SRD mitigation)")
    us = s.add_parser("usage", help="RaaS metering: usage vs plan quota; set plan; simulate a metered call")
    us.add_argument("--key", default="local", help="billing key / customer id")
    us.add_argument("--set-plan", dest="set_plan", default=None, choices=["free","pro","team","enterprise"])
    us.add_argument("--charge", dest="charge_event", default=None, help="simulate one metered event, e.g. gate.decision")
    up = s.add_parser("update", help="Self-update ContinuityOS from PyPI/git (check for a newer version)")
    up.add_argument("--check", action="store_true", help="only report, do not upgrade")
    up.add_argument("--yes", action="store_true", help="apply the upgrade in place")
    mm = s.add_parser("moneymap", help="Build a tiered monetization map from YOUR data (files you point at) + memory")
    mm.add_argument("--from", dest="sources", action="append", default=[], help="file or directory to scan (repeatable)")
    mm.add_argument("--from-memory", dest="from_memory", action="store_true", help="also mine your ContinuityOS memory")
    mm.add_argument("--out", default=None, help="write map markdown to this path (default: print)")
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
    if a.cmd == "update":
        from . import updater
        info = updater.check(force=True)
        print("continuityos %s | latest: %s | %s" % (info["current"], info.get("latest") or "?",
              "UPDATE AVAILABLE" if info["update_available"] else "up to date"))
        if a.check or not info["update_available"]:
            return 0
        if not a.yes:
            print("run:  cos update --yes   to upgrade in place"); return 0
        res = updater.apply(yes=True)
        print("updated to %s" % res.get("latest") if res.get("updated") else "not updated: %s" % res.get("reason",""))
        return 0
    if a.cmd == "usage":
        from .metering import Meter
        meter = Meter(os.path.expanduser("~/.continuityos/usage.db"))
        if a.set_plan:
            meter.set_plan(a.key, a.set_plan); print("plan[%s] = %s" % (a.key, a.set_plan))
        if a.charge_event:
            print(json.dumps(meter.charge(a.key, a.charge_event), ensure_ascii=False))
        print(json.dumps(meter.report(a.key), ensure_ascii=False, indent=2)); return 0

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
        if a.key:
            print("upserted #%d in [%s] key=%s" % (m.upsert(a.text,namespace=a.namespace,key=a.key,tags=tags), a.namespace, a.key))
        else:
            print("stored #%d in [%s]" % (m.remember(a.text,namespace=a.namespace,tags=tags), a.namespace))
    elif a.cmd == "find":
        hit = m.find(a.namespace, a.key)
        print(json.dumps(hit.to_dict(), ensure_ascii=False, indent=2) if hit else "(not found)")
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
    elif a.cmd == "rules":
        from .rules_export import export_rules
        targets = ("claude","agents","cursor") if a.to == "all" else (a.to,)
        res = export_rules(m, out_dir=a.out, targets=targets, dry_run=a.dry_run or a.stdout)
        if a.stdout:
            for tg in targets:
                print("----- %s -----\n%s" % (tg, res["contents"][tg]))
        else:
            print("rules export: canon=%d rules=%d frontiers=%d -> %s" % (
                res["canon"], res["rules"], res["frontiers"],
                ", ".join(res["written"]) or "(dry-run)"))
    elif a.cmd == "moneymap":
        from .monetization import build as _build_mm, render_map_md as _render_mm
        mp = _build_mm(paths=[os.path.expanduser(x) for x in a.sources] or None,
                       memory=m if a.from_memory else None)
        md = _render_mm(mp)
        if a.out:
            open(os.path.expanduser(a.out), "w", encoding="utf-8").write(md)
            print("money map: %d offers from %d file(s) -> %s" % (mp["count"], mp.get("files_scanned", 0), a.out))
        else:
            print(md)
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
    elif a.cmd == "scan":
        canon = [r["text"] for r in c._dump("canon")]
        print("SCAN — reload attention to your rules before the next critical action.")
        print("Generate 100-300 tokens answering these (long-session research: omission-rules decay by ~turn 10):")
        print("  1. Which 3 of your canon rules are EASIEST to violate in the current task?")
        print("  2. Which single 'never do X' rule must you NOT forget right now, and why?")
        print("  3. Restate your current [ROLE] and [COMMITMENT] in one line each.")
        print("\ncanon (%d):" % len(canon))
        for i, r in enumerate(canon[:12], 1):
            print("  %d. %s" % (i, r))
    elif a.cmd == "handoff":
        print(c.handoff())
    elif a.cmd == "boot":
        print(c.handoff()); print("\n--- doctor ---")
        d=c.doctor(); print("%s %d/%d" % ("OK" if d["healthy"] else "DRIFT", d["passed"], d["total"]))
        for ch in d["checks"]:
            if not ch["ok"]: print("  ! %s — %s" % (ch["check"], ch["detail"]))
        try:
            from . import updater
            u = updater.check()
            if u.get("update_available"):
                print("\n[update] %s -> %s available  (run: cos update)" % (u["current"], u["latest"]))
        except Exception:
            pass
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
