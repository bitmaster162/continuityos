"""ContinuityOS CLI:  cos remember | recall | namespaces | serve | api"""
from __future__ import annotations
import argparse, os, json, sys
from .memory import Memory

def _db(a): return a.db or os.path.expanduser("~/.continuityos/memory.db")

def main(argv=None):
    ap = argparse.ArgumentParser(prog="cos", description="ContinuityOS — durable hybrid memory")
    ap.add_argument("--db", default=None, help="memory db path")
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("remember"); r.add_argument("text"); r.add_argument("-n","--namespace",default="notes"); r.add_argument("-t","--tags",default="")
    q = sub.add_parser("recall"); q.add_argument("query"); q.add_argument("-k",type=int,default=5); q.add_argument("-n","--namespace",default=None)
    sub.add_parser("namespaces")
    sv = sub.add_parser("serve", help="run MCP stdio server")
    ap2 = sub.add_parser("api", help="run HTTP API"); ap2.add_argument("--host",default="127.0.0.1"); ap2.add_argument("--port",type=int,default=8077)
    a = ap.parse_args(argv)
    if a.cmd == "serve":
        from . import mcp_server; sys.argv = ["mcp", "--db", _db(a)]; return mcp_server.main()
    if a.cmd == "api":
        from . import api; return api.run(_db(a), a.host, a.port)
    m = Memory(_db(a))
    if a.cmd == "remember":
        tags = [t.strip() for t in a.tags.split(",") if t.strip()]
        print("stored #%d in [%s]" % (m.remember(a.text, namespace=a.namespace, tags=tags), a.namespace))
    elif a.cmd == "recall":
        for h in m.recall(a.query, k=a.k, namespace=a.namespace):
            print("%.3f [%s] %s  (%s)" % (h.score, h.namespace, h.text, h.why))
    elif a.cmd == "namespaces":
        print(json.dumps(m.namespaces(), ensure_ascii=False, indent=2))

if __name__ == "__main__":
    main()
