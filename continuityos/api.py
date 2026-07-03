"""Tiny local HTTP API (stdlib only).
  POST /remember {text,namespace?,tags?}   GET /recall?q=..&k=..   GET /namespaces
"""
from __future__ import annotations
import json, os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs
from .memory import Memory

TOKEN_ENV = "CONTINUITYOS_TOKEN"
ALLOW_REMOTE_ENV = "CONTINUITYOS_ALLOW_REMOTE"
_LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1", ""}


def _truthy(v: str | None) -> bool:
    return str(v or "").strip().lower() in {"1", "true", "yes", "on"}


def _is_local_host(host: str) -> bool:
    return (host or "").strip().lower() in _LOCAL_HOSTS


def _assert_bind_allowed(host: str) -> None:
    """Default to local-only. Binding 0.0.0.0 requires an explicit operator opt-in."""
    if _is_local_host(host):
        return
    if _truthy(os.environ.get(ALLOW_REMOTE_ENV)):
        return
    raise RuntimeError(
        f"refusing to bind HTTP API to non-local host {host!r}; "
        f"set {ALLOW_REMOTE_ENV}=1 if you intentionally expose it"
    )


def make_handler(mem: Memory, token: str | None = None):
    """Build the stdlib HTTP handler. Exposed for tests without starting serve_forever()."""
    class H(BaseHTTPRequestHandler):
        def _j(self, code, obj, headers=None):
            b = json.dumps(obj, ensure_ascii=False).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(b)))
            for k, v in (headers or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(b)

        def _authorized(self) -> bool:
            if not token:
                return True
            return self.headers.get("Authorization", "") == f"Bearer {token}"

        def _ensure_auth(self) -> bool:
            if self._authorized():
                return True
            self._j(401, {"error": "unauthorized"}, {"WWW-Authenticate": "Bearer"})
            return False

        def _json_body(self):
            try:
                n = int(self.headers.get("Content-Length", 0))
            except ValueError:
                return None, "invalid content-length"
            if n > 1_000_000:
                return None, "request body too large"
            raw = self.rfile.read(n) if n else b"{}"
            try:
                body = json.loads(raw or b"{}")
            except json.JSONDecodeError:
                return None, "invalid json"
            if not isinstance(body, dict):
                return None, "json body must be an object"
            return body, None

        def log_message(self, *a):
            pass

        def do_GET(self):
            if not self._ensure_auth():
                return
            u = urlparse(self.path); qs = parse_qs(u.query)
            if u.path == "/recall":
                q = (qs.get("q") or [""])[0]; k = int((qs.get("k") or ["5"])[0])
                ns = (qs.get("namespace") or [None])[0]
                return self._j(200, {"hits": [h.to_dict() for h in mem.recall(q, k=k, namespace=ns)]})
            if u.path == "/namespaces":
                return self._j(200, {"namespaces": mem.namespaces(), "count": mem.count()})
            if u.path in ("/", "/health"):
                return self._j(200, {"ok": True, "product": "ContinuityOS", "count": mem.count()})
            self._j(404, {"error": "not found"})

        def do_POST(self):
            if not self._ensure_auth():
                return
            u = urlparse(self.path)
            body, err = self._json_body()
            if err:
                return self._j(400, {"error": err})
            if u.path == "/remember":
                text = body.get("text")
                if not isinstance(text, str) or not text.strip():
                    return self._j(400, {"error": "text is required"})
                namespace = body.get("namespace", "notes")
                if not isinstance(namespace, str):
                    return self._j(400, {"error": "namespace must be a string"})
                tags = body.get("tags")
                if tags is not None and not isinstance(tags, list):
                    return self._j(400, {"error": "tags must be a list"})
                rid = mem.remember(text, namespace=namespace, tags=tags)
                return self._j(200, {"id": rid})
            self._j(404, {"error": "not found"})

    return H


def run(db: str, host: str = "127.0.0.1", port: int = 8077):
    _assert_bind_allowed(host)
    mem = Memory(db)
    token = os.environ.get(TOKEN_ENV)
    print(f"ContinuityOS API on http://{host}:{port}")
    ThreadingHTTPServer((host, port), make_handler(mem, token=token)).serve_forever()
