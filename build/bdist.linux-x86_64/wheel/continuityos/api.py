"""Tiny stdlib HTTP API (no FastAPI dependency) so `pip install continuityos` stays light.
  POST /remember {text,namespace?,tags?}   GET /recall?q=..&k=..   GET /namespaces
"""
from __future__ import annotations
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs
from .memory import Memory

def run(db: str, host: str = "127.0.0.1", port: int = 8077):
    mem = Memory(db)
    class H(BaseHTTPRequestHandler):
        def _j(self, code, obj):
            b = json.dumps(obj, ensure_ascii=False).encode()
            self.send_response(code); self.send_header("Content-Type","application/json; charset=utf-8")
            self.send_header("Content-Length",str(len(b))); self.end_headers(); self.wfile.write(b)
        def log_message(self,*a): pass
        def do_GET(self):
            u = urlparse(self.path); qs = parse_qs(u.query)
            if u.path == "/recall":
                q = (qs.get("q") or [""])[0]; k = int((qs.get("k") or ["5"])[0])
                ns = (qs.get("namespace") or [None])[0]
                return self._j(200, {"hits":[h.to_dict() for h in mem.recall(q,k=k,namespace=ns)]})
            if u.path == "/namespaces":
                return self._j(200, {"namespaces": mem.namespaces(), "count": mem.count()})
            if u.path in ("/","/health"):
                return self._j(200, {"ok":True,"product":"ContinuityOS","count":mem.count()})
            self._j(404, {"error":"not found"})
        def do_POST(self):
            n = int(self.headers.get("Content-Length",0)); body = json.loads(self.rfile.read(n) or b"{}")
            if self.path == "/remember":
                rid = mem.remember(body["text"], namespace=body.get("namespace","notes"), tags=body.get("tags"))
                return self._j(200, {"id":rid})
            self._j(404, {"error":"not found"})
    print(f"ContinuityOS API on http://{host}:{port}")
    ThreadingHTTPServer((host,port), H).serve_forever()
