"""cos ledger — a centralized, tamper-evident hash-chain audit ledger over HTTP.

Every governance decision from every fleet member (BitEvo, the arena battle_client,
any agent) is dual-written here, so `GET /ledger/article12` is a single EU-AI-Act
Article-12 record across the WHOLE fleet — not one SQLite file per host. Auth = HMAC
capability tokens (same scheme as cos bus). The client `LedgerSink` is **fail-open**:
if the ledger is unreachable it buffers locally and never raises, so the caller
(e.g. trading) never blocks; buffered events replay on the next successful call.

    cos ledger serve --secret "$COS_LEDGER_SECRET" --path fleet_ledger.db --port 8090
    cos ledger token --secret ... --sub bitevo --scope write
    # in the fleet member (fail-open):
    from continuityos.ledger_server import LedgerSink
    sink = LedgerSink("http://brain:8090", token, buffer="cos_ledger_buffer.jsonl")
    sink.record("trade", {"symbol": "BTC", "decision": "ALLOW"})

stdlib-only.
"""
from __future__ import annotations
import json, hmac, hashlib, time, os, threading, urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

READ = {"ledger.verify", "ledger.export", "ledger.article12", "ping"}
WRITE = {"ledger.append"}
SCOPE = {"read": READ, "write": READ | WRITE}
_WLOCK = threading.Lock()


def _sig(secret: str, msg: str) -> str:
    return hmac.new(secret.encode(), msg.encode(), hashlib.sha256).hexdigest()


def mint_token(secret: str, sub: str, scope: str = "read", ttl: int = 86400) -> str:
    if scope not in SCOPE:
        raise ValueError("scope must be read|write")
    body = "%s.%s.%s" % (sub, scope, int(time.time()) + ttl)
    return "%s.%s" % (body, _sig(secret, body))


def verify_token(secret: str, token: str, method: str):
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
    if method not in SCOPE.get(scope, set()):
        return (False, "scope '%s' not permitted for %s" % (scope, method))
    return (True, sub)


def _article12(ledger):
    import collections, datetime as dt
    events = ledger.export(limit=1000000)
    v = ledger.verify()
    kinds = collections.Counter(e.get("kind") for e in events)
    return {"standard": "EU AI Act Article 12 - record-keeping (fleet ledger)",
            "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
            "chain_verified": v, "event_count": len(events), "by_kind": dict(kinds),
            "tamper_evidence": "append-only SHA-256 hash chain; each event binds prev_hash; verify() recomputes the whole chain.",
            "disclaimer": "record-keeping export, not legal advice."}


def make_handler(path: str, secret: str):
    from .gate.ledger import Ledger
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, code, obj):
            b = json.dumps(obj, ensure_ascii=False).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)

        def _auth(self, method):
            tok = self.headers.get("Authorization", "").replace("Bearer ", "")
            return verify_token(secret, tok, method)

        def do_GET(self):
            u = urlparse(self.path); q = parse_qs(u.query)
            method = {"/ledger/verify": "ledger.verify", "/ledger/export": "ledger.export",
                      "/ledger/article12": "ledger.article12", "/": "ping", "/health": "ping"}.get(u.path)
            if method is None:
                return self._send(404, {"error": "not found"})
            if method != "ping":
                ok, who = self._auth(method)
                if not ok:
                    return self._send(401, {"error": "unauthorized: %s" % who})
            if u.path in ("/", "/health"):
                return self._send(200, {"ok": True, "product": "cos-ledger"})
            led = Ledger(path)
            if method == "ledger.verify":
                return self._send(200, led.verify())
            if method == "ledger.export":
                return self._send(200, {"events": led.export(int((q.get("limit") or ["100"])[0]))})
            if method == "ledger.article12":
                return self._send(200, _article12(led))

        def do_POST(self):
            if urlparse(self.path).path != "/ledger/append":
                return self._send(404, {"error": "not found"})
            ok, who = self._auth("ledger.append")
            if not ok:
                return self._send(401, {"error": "unauthorized: %s" % who})
            try:
                n = int(self.headers.get("Content-Length", 0))
                body = json.loads(self.rfile.read(n) or b"{}")
            except Exception as e:
                return self._send(400, {"error": str(e)})
            payload = body.get("payload", {})
            payload = dict(payload) if isinstance(payload, dict) else {"value": payload}
            payload["_source"] = who
            with _WLOCK:
                h = Ledger(path).append(str(body.get("kind", "event")), payload)
            return self._send(200, {"hash": h, "source": who})
    return H


def serve(path: str, secret: str, host: str = "127.0.0.1", port: int = 8090):
    if not secret:
        raise ValueError("cos ledger requires a non-empty --secret (HMAC key)")
    return ThreadingHTTPServer((host, port), make_handler(path, secret))


class LedgerSink:
    """Fail-open ledger client. record() posts to the central ledger; on ANY failure
    it appends to a local buffer and returns — never raises. Buffered events replay
    on the next successful record()/flush(). Trading never blocks on the ledger."""

    def __init__(self, url: str, token: str, buffer: str = "cos_ledger_buffer.jsonl", timeout: float = 1.5):
        self.url = url.rstrip("/"); self.token = token; self.buffer = buffer; self.timeout = timeout

    def _post(self, kind, payload):
        req = urllib.request.Request(self.url + "/ledger/append",
                                     data=json.dumps({"kind": kind, "payload": payload}).encode(),
                                     headers={"Content-Type": "application/json",
                                              "Authorization": "Bearer " + self.token})
        return json.loads(urllib.request.urlopen(req, timeout=self.timeout).read())

    def record(self, kind, payload):
        try:
            self.flush()
            return self._post(kind, payload)
        except Exception:
            try:
                with open(self.buffer, "a", encoding="utf-8") as f:
                    f.write(json.dumps({"kind": kind, "payload": payload, "ts": time.time()}) + "\n")
            except Exception:
                pass
            return {"buffered": True}

    def flush(self):
        if not os.path.exists(self.buffer):
            return 0
        lines = [ln for ln in open(self.buffer, encoding="utf-8").read().splitlines() if ln.strip()]
        rest = []; sent = 0
        for ln in lines:
            try:
                r = json.loads(ln); self._post(r["kind"], r["payload"]); sent += 1
            except Exception:
                rest.append(ln)
        if rest:
            open(self.buffer, "w", encoding="utf-8").write("\n".join(rest) + "\n")
        elif os.path.exists(self.buffer):
            try:
                os.remove(self.buffer)
            except Exception:
                pass
        return sent
