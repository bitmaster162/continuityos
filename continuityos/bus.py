"""cos bus — zero-dep capability-token message bus (JSON-RPC over http.server).

NOTE: this is a lightweight home-grown bus, NOT the Linux Foundation **A2A** protocol
(Google-origin, signed Agent Cards, 150+ orgs). Renamed from `a2a` to avoid confusion.
Aligning with the A2A Agent-Card spec is a possible fast-follow.

Exposes a whitelisted, capability-gated slice of ContinuityOS to other agents:
memory.find / memory.recall / memory.upsert / governance.alignment /
advocate.challenge / audit.run. Auth is an HMAC capability token scoped to a role
(read | write) — NO new dependencies (stdlib hmac/hashlib/http.server). This is
the shared bi-temporal memory + governance bus that makes multi-agent handoffs safe.

    cos a2a serve --port 8079 --secret "$COS_A2A_SECRET"
    cos a2a token --secret "$COS_A2A_SECRET" --sub codex --scope read

Token = "<sub>.<scope>.<exp>.<hmac_sha256(secret,'sub.scope.exp')>", verified with
constant-time compare. Read methods need scope=read; upsert/remember need write.
Binds 127.0.0.1 by default. Every write is recorded append-only (bi-temporal).
"""
from __future__ import annotations
import json, hmac, hashlib, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Optional, Tuple

READ_METHODS = {"ping", "memory.find", "memory.recall", "governance.alignment",
                "advocate.challenge", "audit.run"}
WRITE_METHODS = {"memory.upsert", "memory.remember"}
SCOPE_METHODS = {"read": READ_METHODS, "write": READ_METHODS | WRITE_METHODS}


def _sig(secret: str, msg: str) -> str:
    return hmac.new(secret.encode(), msg.encode(), hashlib.sha256).hexdigest()


def mint_token(secret: str, sub: str, scope: str = "read", ttl: int = 86400) -> str:
    if scope not in SCOPE_METHODS:
        raise ValueError("scope must be read|write")
    body = "%s.%s.%s" % (sub, scope, int(time.time()) + ttl)
    return "%s.%s" % (body, _sig(secret, body))


def verify_token(secret: str, token: str, method: str) -> Tuple[bool, str]:
    try:
        sub, scope, exp, sig = token.split(".")
    except (ValueError, AttributeError):
        return (False, "malformed token")
    body = "%s.%s.%s" % (sub, scope, exp)
    if not hmac.compare_digest(sig, _sig(secret, body)):
        return (False, "bad signature")
    try:
        if int(exp) < time.time():
            return (False, "expired")
    except ValueError:
        return (False, "bad exp")
    if method not in SCOPE_METHODS.get(scope, set()):
        return (False, f"scope '{scope}' not permitted for '{method}'")
    return (True, sub)


def build_dispatch(memory, twin=None, continuity=None):
    try:
        from .advocate import DevilsAdvocate
        from .audit import SystemAudit
    except ImportError:
        from advocate import DevilsAdvocate
        from audit import SystemAudit

    def m_recall(p):
        hits = memory.recall(p.get("query", ""), k=int(p.get("k", 5)),
                             namespace=p.get("namespace"), as_of=p.get("as_of"),
                             current_only=bool(p.get("current_only", False)))
        return [{"id": h.id, "text": h.text, "namespace": h.namespace, "score": h.score} for h in hits]

    def m_find(p):
        it = memory.find(p["namespace"], p["key"])
        return None if it is None else {"id": it.id, "text": it.text, "namespace": it.namespace, "meta": it.meta}

    def m_upsert(p):
        return {"id": memory.upsert(p["text"], namespace=p["namespace"], key=p["key"])}

    def m_remember(p):
        return {"id": memory.remember(p["text"], namespace=p.get("namespace", "notes"))}

    def g_align(p):
        return twin.alignment(p["action"]) if twin is not None else {"error": "no twin"}

    def a_challenge(p):
        return DevilsAdvocate(memory, twin).challenge(p.get("claim", ""), action=bool(p.get("action", False)))

    def a_audit(p):
        return SystemAudit(memory, continuity, twin).run(devil=bool(p.get("devil", False)))

    return {"ping": lambda p: {"ok": True, "ts": time.time()},
            "memory.recall": m_recall, "memory.find": m_find, "memory.upsert": m_upsert,
            "memory.remember": m_remember, "governance.alignment": g_align,
            "advocate.challenge": a_challenge, "audit.run": a_audit}


def make_handler(secret: str, dispatch: Dict[str, Any]):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):  # quiet
            pass

        def _send(self, code, obj):
            body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            try:
                n = int(self.headers.get("Content-Length", 0))
                req = json.loads(self.rfile.read(n) or b"{}")
            except Exception as e:
                return self._send(400, {"error": f"bad request: {e}"})
            method = req.get("method", "")
            if method not in dispatch:
                return self._send(404, {"error": f"unknown method '{method}'"})
            ok, who = verify_token(secret, req.get("token", ""), method)
            if not ok:
                return self._send(401, {"error": f"unauthorized: {who}"})
            try:
                return self._send(200, {"result": dispatch[method](req.get("params") or {}), "sub": who})
            except Exception as e:
                return self._send(500, {"error": f"{type(e).__name__}: {e}"})
    return Handler


def serve(memory, secret: str, host: str = "127.0.0.1", port: int = 8079,
          twin=None, continuity=None):
    if not secret:
        raise ValueError("A2A requires a non-empty --secret (HMAC key)")
    dispatch = build_dispatch(memory, twin, continuity)
    httpd = ThreadingHTTPServer((host, port), make_handler(secret, dispatch))
    return httpd
