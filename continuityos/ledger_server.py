"""cos ledger — a centralized, tamper-evident hash-chain audit ledger over HTTP.

Every governance decision from every fleet member (BitEvo, the arena battle_client,
any agent) is dual-written here, so `GET /ledger/article12` is a single EU-AI-Act
Article-12 record across the WHOLE fleet — not one SQLite file per host. Auth = HMAC
capability tokens (same scheme as cos bus). The client `LedgerSink` is **fail-open
for delivery errors**: if the ledger is unreachable it buffers locally and does
not propagate the delivery exception. Calls can still wait for configured HTTP
timeouts and backlog replay. Delivery is at-least-once, so crash recovery can
duplicate an accepted event until server-side event IDs/deduplication exist.

    cos ledger serve --secret "$COS_LEDGER_SECRET" --path fleet_ledger.db --port 8090
    cos ledger token --secret ... --sub bitevo --scope write
    # in the fleet member (fail-open):
    from continuityos.ledger_server import LedgerSink
    sink = LedgerSink("http://brain:8090", token, buffer="cos_ledger_buffer.jsonl")
    sink.record("trade", {"symbol": "BTC", "decision": "ALLOW"})

stdlib-only.
"""
from __future__ import annotations
import contextlib, errno, json, hmac, hashlib, time, os, tempfile, threading, urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

READ = {"ledger.verify", "ledger.export", "ledger.article12", "ping"}
WRITE = {"ledger.append"}
SCOPE = {"read": READ, "write": READ | WRITE}
_WLOCK = threading.Lock()


@contextlib.contextmanager
def _file_lock(path: str, *, blocking: bool, timeout: float = 5.0):
    """Cross-process one-byte advisory lock backed by a persistent sidecar."""
    parent = os.path.dirname(os.path.abspath(path))
    os.makedirs(parent, exist_ok=True)
    stream = open(path, "a+b")
    stream.seek(0, os.SEEK_END)
    if stream.tell() == 0:
        stream.write(b"\0")
        stream.flush()
        os.fsync(stream.fileno())
    stream.seek(0)
    acquired = False
    deadline = time.monotonic() + timeout
    try:
        while True:
            try:
                if os.name == "nt":
                    import msvcrt
                    stream.seek(0)
                    msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                acquired = True
                break
            except OSError as exc:
                contention = exc.errno in {
                    errno.EACCES,
                    errno.EAGAIN,
                    getattr(errno, "EDEADLK", -1),
                }
                if not contention:
                    raise
                if not blocking or time.monotonic() >= deadline:
                    break
                time.sleep(0.01)
        yield acquired
    finally:
        if acquired:
            if os.name == "nt":
                import msvcrt
                stream.seek(0)
                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
        stream.close()


def _sync_parent(path: str) -> None:
    if os.name == "nt":
        return
    parent_fd = os.open(os.path.dirname(os.path.abspath(path)), os.O_RDONLY)
    try:
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)


def _atomic_replace_lines(path: str, lines) -> None:
    """Durably replace one JSONL file without truncating the previous version."""
    parent = os.path.dirname(os.path.abspath(path))
    os.makedirs(parent, exist_ok=True)
    fd, temporary = tempfile.mkstemp(
        prefix="." + os.path.basename(path) + ".",
        suffix=".tmp",
        dir=parent,
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            for line in lines:
                stream.write(line.rstrip("\r\n") + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        _sync_parent(path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _read_lines(path: str):
    if not os.path.isfile(path):
        return []
    with open(path, "r", encoding="utf-8") as stream:
        return [line for line in stream.read().splitlines() if line.strip()]


def _require_append_receipt(response):
    """Accept only a full server hash as proof that an append was durable."""
    if not isinstance(response, dict):
        raise ValueError("ledger append response must be an object")
    receipt_hash = response.get("hash")
    if (
        not isinstance(receipt_hash, str)
        or len(receipt_hash) != 64
        or receipt_hash != receipt_hash.lower()
        or any(char not in "0123456789abcdef" for char in receipt_hash)
    ):
        raise ValueError("ledger append response has no valid full SHA-256 hash")
    return response


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
            with Ledger(path) as led:
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
                with Ledger(path) as ledger:
                    h = ledger.append(str(body.get("kind", "event")), payload)
            return self._send(200, {"hash": h, "source": who})
    return H


def serve(path: str, secret: str, host: str = "127.0.0.1", port: int = 8090):
    if not secret:
        raise ValueError("cos ledger requires a non-empty --secret (HMAC key)")
    return ThreadingHTTPServer((host, port), make_handler(path, secret))


class LedgerSink:
    """Fail-open ledger client. record() posts to the central ledger; on ANY failure
    it durably appends to a local buffer and returns an honest buffered result.
    Buffered events replay on the next successful record()/flush(); replay can
    block up to the configured request timeouts and is at-least-once."""

    def __init__(self, url: str, token: str, buffer: str = "cos_ledger_buffer.jsonl", timeout: float = 1.5):
        self.url = url.rstrip("/")
        self.token = token
        self.buffer = os.path.abspath(os.path.expanduser(buffer))
        self.timeout = timeout
        self._inflight = self.buffer + ".inflight"
        self._corrupt = self.buffer + ".corrupt.jsonl"
        self._buffer_lock = self.buffer + ".buffer.lock"
        self._flush_lock = self.buffer + ".flush.lock"

    def _post(self, kind, payload):
        req = urllib.request.Request(self.url + "/ledger/append",
                                     data=json.dumps({"kind": kind, "payload": payload}).encode(),
                                     headers={"Content-Type": "application/json",
                                              "Authorization": "Bearer " + self.token})
        return json.loads(urllib.request.urlopen(req, timeout=self.timeout).read())

    def _append_buffered_event_locked(self, event: str) -> None:
        """Append one encoded event while the caller holds ``_buffer_lock``."""
        os.makedirs(os.path.dirname(self.buffer), exist_ok=True)
        with open(self.buffer, "a", encoding="utf-8", newline="\n") as stream:
            stream.write(event + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        _sync_parent(self.buffer)

    def _buffer_event(
        self,
        event: str,
        central_error: Exception,
        *,
        before_concurrent: bool = False,
    ):
        try:
            with _file_lock(self._buffer_lock, blocking=True) as acquired:
                if not acquired:
                    raise TimeoutError("timed out acquiring ledger buffer lock")
                if before_concurrent:
                    # The caller owns the flush lock and already observed an empty
                    # backlog. Anything appended since that observation belongs to
                    # a later record that lost flush-lock admission, so a failed
                    # direct POST must be restored ahead of those newer records.
                    concurrent = _read_lines(self.buffer)
                    _atomic_replace_lines(self.buffer, [event] + concurrent)
                else:
                    self._append_buffered_event_locked(event)
            return {"buffered": True}
        except Exception as buffer_error:
            return {
                "buffered": False,
                "error": "central ledger unavailable and local buffer write failed",
                "central_error_type": type(central_error).__name__,
                "error_type": type(buffer_error).__name__,
            }

    def _durable_backlog_locked(self) -> bool:
        """Return whether a non-empty delivery generation remains on disk."""
        return any(
            os.path.isfile(path) and os.path.getsize(path) > 0
            for path in (self._inflight, self.buffer)
        )

    def record(self, kind, payload):
        try:
            event = json.dumps(
                {"kind": kind, "payload": payload, "ts": time.time()},
                ensure_ascii=False,
                separators=(",", ":"),
            )
        except Exception as serialization_error:
            return {
                "buffered": False,
                "error": "central ledger unavailable and local buffer write failed",
                "central_error_type": type(serialization_error).__name__,
                "error_type": type(serialization_error).__name__,
            }

        with _file_lock(self._flush_lock, blocking=False) as flush_acquired:
            if not flush_acquired:
                return self._buffer_event(
                    event,
                    BlockingIOError("ledger flush already in progress"),
                )
            target_index = None
            with _file_lock(self._buffer_lock, blocking=True) as buffer_acquired:
                if not buffer_acquired:
                    return self._buffer_event(
                        event,
                        TimeoutError("timed out acquiring ledger buffer lock"),
                    )
                if self._durable_backlog_locked():
                    try:
                        target_index = (
                            len(_read_lines(self._inflight))
                            + len(_read_lines(self.buffer))
                        )
                        self._append_buffered_event_locked(event)
                    except Exception as buffer_error:
                        return {
                            "buffered": False,
                            "error": "central ledger unavailable and local buffer write failed",
                            "central_error_type": "BacklogPending",
                            "error_type": type(buffer_error).__name__,
                        }
            if target_index is not None:
                try:
                    _, target_state, target_receipt = self._flush_locked(
                        target_index=target_index
                    )
                except Exception:
                    # The current event was fsynced before replay began. Any
                    # replay exception leaves it in the active or inflight
                    # generation for at-least-once recovery.
                    return {"buffered": True}
                if target_state == "sent":
                    return target_receipt
                if target_state == "pending":
                    return {"buffered": True}
                return {
                    "buffered": False,
                    "error": "queued ledger event was not acknowledged",
                    "error_type": target_state,
                }
            try:
                return _require_append_receipt(self._post(kind, payload))
            except Exception as central_error:
                return self._buffer_event(
                    event,
                    central_error,
                    before_concurrent=True,
                )

    def _flush_locked(self, *, target_index=None):
        """Flush while the caller exclusively holds ``_flush_lock``."""
        with _file_lock(self._buffer_lock, blocking=True) as buffer_acquired:
            if not buffer_acquired:
                raise TimeoutError("timed out acquiring ledger buffer lock")
            if not os.path.isfile(self._inflight):
                if not os.path.isfile(self.buffer):
                    if target_index is None:
                        return 0
                    return 0, "missing", None
                os.replace(self.buffer, self._inflight)
                _sync_parent(self._inflight)
            elif os.path.isfile(self.buffer):
                # A stale crash-recovery batch predates the active generation.
                # Merge the already-buffered generation before network I/O so a
                # subsequent direct record cannot overtake it. A crash between
                # replace and unlink can duplicate, but cannot lose, evidence.
                stale = _read_lines(self._inflight)
                active = _read_lines(self.buffer)
                _atomic_replace_lines(self._inflight, stale + active)
                os.unlink(self.buffer)
                _sync_parent(self.buffer)
        lines = _read_lines(self._inflight)
        rest = []
        corrupt = []
        sent = 0
        target_state = "pending" if target_index is not None else None
        target_receipt = None
        for index, line in enumerate(lines):
            try:
                event = json.loads(line)
                if (
                    not isinstance(event, dict)
                    or not isinstance(event.get("kind"), str)
                    or not event.get("kind")
                    or "payload" not in event
                ):
                    raise ValueError("buffered event must contain kind and payload")
            except Exception as exc:
                if index == target_index:
                    target_state = "quarantined"
                corrupt.append(json.dumps({
                    "raw": line,
                    "raw_sha256": hashlib.sha256(
                        line.encode("utf-8")
                    ).hexdigest(),
                    "error_type": type(exc).__name__,
                    "error": str(exc),
                    "quarantined_ts": time.time(),
                }, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
                continue
            try:
                receipt = _require_append_receipt(
                    self._post(event["kind"], event["payload"])
                )
                sent += 1
                if index == target_index:
                    target_state = "sent"
                    target_receipt = receipt
            except Exception:
                rest = lines[index:]
                break
        with _file_lock(self._buffer_lock, blocking=True) as buffer_acquired:
            if not buffer_acquired:
                raise TimeoutError("timed out acquiring ledger buffer lock")
            if corrupt:
                os.makedirs(os.path.dirname(self._corrupt), exist_ok=True)
                with open(
                    self._corrupt, "a", encoding="utf-8", newline="\n"
                ) as stream:
                    for record in corrupt:
                        stream.write(record + "\n")
                    stream.flush()
                    os.fsync(stream.fileno())
                _sync_parent(self._corrupt)
            if rest:
                concurrent = _read_lines(self.buffer)
                _atomic_replace_lines(self.buffer, rest + concurrent)
            if os.path.exists(self._inflight):
                os.unlink(self._inflight)
                _sync_parent(self._inflight)
        if target_index is None:
            return sent
        return sent, target_state, target_receipt

    def flush(self):
        with _file_lock(self._flush_lock, blocking=False) as flush_acquired:
            if not flush_acquired:
                return 0
            return self._flush_locked()
