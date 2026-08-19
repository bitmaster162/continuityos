"""Loopback-only HTTP/UI shell for Sovereign Twin."""
from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .sovereign_twin_admission import ShadowMemoryAdmissionQueue
from .sovereign_twin_runtime import DEFAULT_EMBEDDING_MODEL, LmStudioClient, SovereignTwinRuntime

EXECUTION_AUTHORITY = "NONE"

_UI = """<!doctype html>
<meta charset=\"utf-8\">
<title>Sovereign Twin Local</title>
<style>
body{font:16px system-ui;max-width:900px;margin:40px auto;padding:0 18px}
textarea{width:100%;height:120px}button{padding:10px 16px;margin:8px 8px 8px 0}
pre{white-space:pre-wrap;background:#111;color:#eee;padding:16px;border-radius:10px}
</style>
<h1>Sovereign Twin — Local</h1>
<p>Local shadow mode. No execution authority.</p>
<textarea id=q placeholder=\"Ask your local Twin\"></textarea><br>
<button onclick=\"ask('fast')\">FAST</button><button onclick=\"ask('deep')\">DEEP</button>
<pre id=o>Ready.</pre>
<script>
async function ask(mode){
 const q=document.getElementById('q').value;
 document.getElementById('o').textContent='Thinking...';
 const r=await fetch('/ask',{method:'POST',headers:{'Content-Type':'application/json'},
 body:JSON.stringify({query:q,mode})});
 const j=await r.json();
 document.getElementById('o').textContent=JSON.stringify(j,null,2);
}
</script>"""


def _validate_bind(host: str) -> str:
    value = str(host).strip().lower()
    if value not in {"127.0.0.1", "localhost", "::1"}:
        raise ValueError("Sovereign Twin API is loopback-only")
    return value


class _TwinServer(ThreadingHTTPServer):
    runtime: SovereignTwinRuntime
    admissions: ShadowMemoryAdmissionQueue


class _Handler(BaseHTTPRequestHandler):
    server: _TwinServer

    def log_message(self, fmt: str, *args: Any) -> None:
        return

    def _json(self, status: int, payload: Any) -> None:
        raw = json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _body(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0 or length > 1_000_000:
            raise ValueError("request body size invalid")
        value = json.loads(self.rfile.read(length).decode("utf-8"))
        if not isinstance(value, dict):
            raise ValueError("JSON object required")
        return value

    def do_GET(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        try:
            if path == "/":
                raw = _UI.encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)
                return
            if path == "/health":
                self._json(200, {
                    "ok": True,
                    "mode": "LOCAL_SHADOW",
                    "execution_authority": EXECUTION_AUTHORITY,
                    "can_execute": False,
                })
                return
            if path == "/doctor":
                report = self.server.runtime.doctor()
                self._json(200 if report.get("ok") else 503, report)
                return
            if path == "/admissions":
                self._json(200, {
                    "pending": self.server.admissions.pending(),
                    "verify": self.server.admissions.verify(),
                    "execution_authority": EXECUTION_AUTHORITY,
                })
                return
            self._json(404, {"ok": False, "error": "not found"})
        except Exception as exc:
            self._json(500, {"ok": False, "error": str(exc), "execution_authority": EXECUTION_AUTHORITY})

    def do_POST(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        try:
            body = self._body()
            if path == "/ask":
                query = str(body.get("query", "")).strip()
                mode = str(body.get("mode", "fast"))
                if not query:
                    raise ValueError("query required")
                self._json(200, self.server.runtime.ask(query, mode=mode).to_dict())
                return
            if path == "/admissions":
                text = str(body.get("text", "")).strip()
                event = self.server.admissions.propose(
                    text,
                    namespace=str(body.get("namespace", "notes")),
                    tags=body.get("tags") or (),
                    source=str(body.get("source", "LOCAL_TWIN")),
                    evidence_refs=body.get("evidence_refs") or (),
                )
                self._json(201, event)
                return
            self._json(404, {"ok": False, "error": "not found"})
        except (ValueError, json.JSONDecodeError) as exc:
            self._json(400, {"ok": False, "error": str(exc), "execution_authority": EXECUTION_AUTHORITY})
        except Exception as exc:
            self._json(500, {"ok": False, "error": str(exc), "execution_authority": EXECUTION_AUTHORITY})


def serve(
    *,
    memory_db: str,
    base_url: str = "http://127.0.0.1:1234",
    host: str = "127.0.0.1",
    port: int = 8765,
    admission_path: str | None = None,
    embedding_model: str = DEFAULT_EMBEDDING_MODEL,
) -> None:
    host = _validate_bind(host)
    runtime = SovereignTwinRuntime(
        memory_db,
        client=LmStudioClient(base_url),
        embedding_model=embedding_model,
    )
    queue_path = admission_path or str(Path(memory_db).with_suffix(".twin-admissions.jsonl"))
    admissions = ShadowMemoryAdmissionQueue(queue_path)
    server = _TwinServer((host, int(port)), _Handler)
    server.runtime = runtime
    server.admissions = admissions
    try:
        server.serve_forever()
    finally:
        server.server_close()
        runtime.close()
