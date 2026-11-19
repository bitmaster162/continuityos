"""Tiny local HTTP API (stdlib only).
  POST /remember {text,namespace?,tags?}   GET /recall?q=..&k=..   GET /namespaces
"""
from __future__ import annotations
import json, os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs
from .memory import Memory
from .current_effect_boundary import CurrentEffectBoundaryError, assert_current_effect_allowed

TOKEN_ENV = "CONTINUITYOS_TOKEN"
ALLOW_REMOTE_ENV = "CONTINUITYOS_ALLOW_REMOTE"
ALLOWED_ORIGINS_ENV = "CONTINUITYOS_ALLOWED_ORIGINS"
_LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1", ""}


def _truthy(v: str | None) -> bool:
    return str(v or "").strip().lower() in {"1", "true", "yes", "on"}


def _is_local_host(host: str) -> bool:
    return (host or "").strip().lower() in _LOCAL_HOSTS


def _assert_bind_allowed(host: str, token: str | None = None) -> None:
    """Default to local-only; any remote bind also requires bearer authentication."""
    if _is_local_host(host):
        return
    if not _truthy(os.environ.get(ALLOW_REMOTE_ENV)):
        raise RuntimeError(
            f"refusing to bind HTTP API to non-local host {host!r}; "
            f"set {ALLOW_REMOTE_ENV}=1 if you intentionally expose it"
        )
    if not token:
        raise RuntimeError("remote HTTP API bind requires CONTINUITYOS_TOKEN")


def _valid_cors_origin(value: str) -> bool:
    if value == "null":
        return True
    if not value or value == "*" or value != value.strip():
        return False
    if any(ord(ch) < 0x21 or ord(ch) > 0x7e for ch in value):
        return False
    try:
        parsed = urlparse(value)
        host = parsed.hostname
        parsed.port
    except ValueError:
        return False
    return (
        parsed.scheme in {"http", "https"}
        and bool(host)
        and parsed.username is None
        and parsed.password is None
        and not parsed.path
        and not parsed.params
        and not parsed.query
        and not parsed.fragment
    )


def _canonical_allowed_origins(values) -> tuple[str, ...]:
    canonical = []
    for value in values:
        if not isinstance(value, str) or not _valid_cors_origin(value):
            raise RuntimeError("invalid CORS origin in allowlist")
        canonical.append(value)
    return tuple(sorted(set(canonical)))


def _allowed_origins(value: str | None = None) -> tuple[str, ...]:
    raw = os.environ.get(ALLOWED_ORIGINS_ENV, "") if value is None else value
    values = [item.strip() for item in str(raw or "").split(",") if item.strip()]
    return _canonical_allowed_origins(values)


def make_handler(mem: Memory, token: str | None = None, allowed_origins: set[str] | None = None):
    """Build the stdlib HTTP handler. Exposed for tests without starting serve_forever()."""
    allowed_origins = _canonical_allowed_origins(allowed_origins or ())
    if allowed_origins and not token:
        raise RuntimeError("browser-origin HTTP API access requires a bearer token")

    class H(BaseHTTPRequestHandler):
        def _cors_origin(self) -> str | None:
            values = self.headers.get_all("Origin") or []
            if len(values) != 1:
                return None
            candidate = values[0].strip()
            if not _valid_cors_origin(candidate):
                return None
            for configured_origin in allowed_origins:
                if candidate == configured_origin:
                    return configured_origin
            return None

        def _origin_allowed(self) -> bool:
            values = self.headers.get_all("Origin") or []
            return not values or self._cors_origin() is not None

        def _j(self, code, obj, headers=None):
            b = json.dumps(obj, ensure_ascii=False).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            cors_origin = self._cors_origin()
            if cors_origin is not None:
                self.send_header("Access-Control-Allow-Origin", cors_origin)
                self.send_header("Vary", "Origin")
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

        def do_OPTIONS(self):
            if not self._origin_allowed():
                return self._j(403, {"error": "origin not allowed"})
            self.send_response(204)
            cors_origin = self._cors_origin()
            if cors_origin is not None:
                self.send_header("Access-Control-Allow-Origin", cors_origin)
                self.send_header("Vary", "Origin")
                self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
                self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
            self.end_headers()

        def do_GET(self):
            if not self._origin_allowed():
                return self._j(403, {"error": "origin not allowed"})
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
            if u.path == "/epoch/graph":
                from .epochgraph import EpochGraph
                return self._j(200, EpochGraph(mem).to_graph())
            if u.path.startswith("/graph/"):
                name = u.path[len("/graph/"):]
                it = mem.find("graphs", name)
                if it is None:
                    return self._j(404, {"error": "no graph '%s' (POST one first)" % name})
                try:
                    return self._j(200, json.loads(it.text))
                except Exception:
                    return self._j(200, {"raw": it.text})
            self._j(404, {"error": "not found"})

        def do_POST(self):
            if not self._origin_allowed():
                return self._j(403, {"error": "origin not allowed"})
            if not self._ensure_auth():
                return
            try:
                assert_current_effect_allowed("http_api.write")
            except CurrentEffectBoundaryError as exc:
                return self._j(423, {"error": "current_session_hold", "receipt": exc.to_dict()})
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
            if u.path == "/epoch/commit":
                from .epochgraph import EpochGraph
                g = EpochGraph(mem)
                branch = body.get("branch") or "main"
                metrics = body.get("metrics") or {}
                if not isinstance(metrics, dict):
                    return self._j(400, {"error": "metrics must be an object"})
                clean = {k: float(v) for k, v in metrics.items() if isinstance(v, (int, float))}
                cid = g.commit(str(branch), str(body.get("label", "")), clean)
                return self._j(200, {"id": cid, "graph": g.to_graph()})
            if u.path == "/epoch/branch":
                from .epochgraph import EpochGraph
                name = body.get("name")
                if not name:
                    return self._j(400, {"error": "name is required"})
                bid = EpochGraph(mem).branch(str(name), str(body.get("from", "main")))
                return self._j(200, {"id": bid})
            if u.path.startswith("/graph/"):
                gname = u.path[len("/graph/"):]
                if not gname:
                    return self._j(400, {"error": "graph name required"})
                gid = mem.upsert(json.dumps(body, ensure_ascii=False), namespace="graphs", key=gname)
                return self._j(200, {"ok": True, "graph": gname, "id": gid})
            self._j(404, {"error": "not found"})

    return H


def run(db: str, host: str = "127.0.0.1", port: int = 8077):
    assert_current_effect_allowed("http_api.server_start")
    token = os.environ.get(TOKEN_ENV)
    origins = _allowed_origins()
    _assert_bind_allowed(host, token=token)
    if origins and not token:
        raise RuntimeError("browser-origin HTTP API access requires CONTINUITYOS_TOKEN")
    mem = Memory(db)
    print(f"ContinuityOS API on http://{host}:{port}")
    ThreadingHTTPServer(
        (host, port), make_handler(mem, token=token, allowed_origins=origins)
    ).serve_forever()
