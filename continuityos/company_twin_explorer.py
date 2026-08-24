from __future__ import annotations

import argparse
import json
import socket
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

from .company_twin import explorer_payload, load_dataset

_UI = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ContinuityOS Company Twin Explorer — P2A</title>
<style>
:root{color-scheme:dark;background:#071018;color:#dbeafe;font-family:Inter,ui-sans-serif,system-ui,sans-serif}
*{box-sizing:border-box}body{margin:0}.wrap{max-width:1180px;margin:0 auto;padding:28px 20px 60px}
header{display:flex;gap:14px;justify-content:space-between;align-items:flex-start;flex-wrap:wrap}
h1{font-size:30px;margin:5px 0}.kicker{font-size:12px;letter-spacing:.16em;text-transform:uppercase;color:#67e8f9}
.badge{border:1px solid #22d3ee55;border-radius:999px;padding:7px 11px;font-size:12px;color:#67e8f9}
.notice{margin:18px 0;padding:13px 15px;border:1px solid #334155;border-radius:12px;background:#0f172a}
.controls,.grid{display:grid;gap:12px}.controls{grid-template-columns:1fr 1fr auto;margin:18px 0}
.grid{grid-template-columns:repeat(4,1fr)}.card{background:#0b1624;border:1px solid #1e293b;border-radius:14px;padding:16px}
label{display:block;font-size:12px;color:#94a3b8;margin-bottom:6px}select,input,button{width:100%;background:#111c2c;color:#e2e8f0;border:1px solid #334155;border-radius:9px;padding:10px}
button{cursor:pointer;background:#123047;border-color:#155e75}.muted{color:#94a3b8;font-size:13px}
.timeline{margin-top:18px}.row{display:grid;grid-template-columns:160px 105px 1fr 120px;gap:10px;padding:11px 0;border-bottom:1px solid #1e293b}
.truth{font-size:11px;letter-spacing:.08em}.FACT{color:#86efac}.EVIDENCE{color:#93c5fd}.INFERENCE{color:#fcd34d}
pre{white-space:pre-wrap;word-break:break-word;background:#020617;padding:14px;border-radius:10px;max-height:420px;overflow:auto}
@media(max-width:760px){.controls,.grid{grid-template-columns:1fr}.row{grid-template-columns:1fr}.hide-mobile{display:none}}
</style>
</head>
<body>
<div class="wrap">
<header>
<div><div class="kicker">ContinuityOS · Company Twin P2A</div><h1>Organizational Memory Explorer</h1>
<div class="muted">Synthetic 12-month company · temporal replay · scoped visibility · evidence lineage</div></div>
<div class="badge">READ ONLY · NO EXECUTION</div>
</header>
<div class="notice">This prototype separates historical <b>FACT / EVIDENCE</b> from model <b>INFERENCE</b>. It exposes no mutation or agent-execution routes.</div>
<div class="controls">
<div><label for="principal">Principal</label><select id="principal"></select></div>
<div><label for="asof">Replay as of</label><input id="asof" type="date"></div>
<div><label>&nbsp;</label><button id="load">Replay</button></div>
</div>
<div class="grid">
<div class="card"><div class="muted">Organization</div><strong id="org">—</strong></div>
<div class="card"><div class="muted">Visible decisions</div><strong id="decisions">—</strong></div>
<div class="card"><div class="muted">Visible evidence</div><strong id="evidence">—</strong></div>
<div class="card"><div class="muted">Visible inferences</div><strong id="inferences">—</strong></div>
</div>
<div class="timeline card"><h2>Historical timeline</h2><div id="timeline"></div></div>
<div class="card" style="margin-top:18px"><h2>Replay snapshot</h2><pre id="raw"></pre></div>
</div>
<script>
const principal = document.getElementById('principal');
const asof = document.getElementById('asof');
const timeline = document.getElementById('timeline');

function addText(parent, tag, text, className='') {
  const el = document.createElement(tag);
  el.textContent = text;
  if (className) el.className = className;
  parent.appendChild(el);
  return el;
}
async function bootstrap() {
  const r = await fetch('/api/meta');
  const data = await r.json();
  for (const p of data.principals) {
    const option = document.createElement('option');
    option.value = p.id;
    option.textContent = `${p.name} · ${p.role}`;
    principal.appendChild(option);
  }
  asof.value = data.period.end.slice(0,10);
  await replay();
}
async function replay() {
  const params = new URLSearchParams({principal: principal.value, as_of: asof.value + 'T23:59:59Z'});
  const r = await fetch('/api/replay?' + params.toString());
  const data = await r.json();
  if (!r.ok) { document.getElementById('raw').textContent = JSON.stringify(data,null,2); return; }
  document.getElementById('org').textContent = data.organization.name;
  document.getElementById('decisions').textContent = String(data.counts.decisions);
  document.getElementById('evidence').textContent = String(data.counts.evidence);
  document.getElementById('inferences').textContent = String(data.counts.inferences);
  timeline.replaceChildren();
  for (const item of data.timeline) {
    const row = document.createElement('div'); row.className='row';
    addText(row,'div',item.at || '—','muted');
    addText(row,'div',item.type);
    addText(row,'div',item.title);
    addText(row,'div',item.truth_class,'truth ' + item.truth_class);
    timeline.appendChild(row);
  }
  document.getElementById('raw').textContent = JSON.stringify(data.snapshot,null,2);
}
document.getElementById('load').addEventListener('click', replay);
bootstrap().catch(err => { document.getElementById('raw').textContent = String(err); });
</script>
</body>
</html>
"""


def _is_loopback_host(host: str) -> bool:
    if host.lower() == "localhost":
        return True
    try:
        return bool(socket.getaddrinfo(host, None)) and all(
            item[4][0] in {"127.0.0.1", "::1"} for item in socket.getaddrinfo(host, None)
        )
    except socket.gaierror:
        return False


def _make_handler(fixture: Path):
    data = load_dataset(fixture)

    class Handler(BaseHTTPRequestHandler):
        server_version = "ContinuityOSCompanyTwinP2A/1"

        def _send_json(self, payload: dict[str, Any], status: int = 200) -> None:
            body = json.dumps(payload, indent=2, sort_keys=True).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _send_html(self) -> None:
            body = _UI.encode("utf-8")
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:  # noqa: N802
            parsed = urlsplit(self.path)
            if parsed.path in {"/", "/index.html"}:
                self._send_html()
                return
            if parsed.path == "/health":
                self._send_json(
                    {
                        "ok": True,
                        "read_only": True,
                        "execution_authority": "NONE",
                        "can_execute": False,
                        "product": "Company Twin P2A",
                    }
                )
                return
            if parsed.path == "/api/meta":
                self._send_json(
                    {
                        "read_only": True,
                        "organization": data["organization"],
                        "period": data["period"],
                        "principals": [
                            {"id": p["id"], "name": p["name"], "role": p["role"]}
                            for p in data["principals"]
                        ],
                    }
                )
                return
            if parsed.path == "/api/replay":
                query = parse_qs(parsed.query)
                principal = query.get("principal", [""])[0]
                as_of = query.get("as_of", [""])[0]
                try:
                    payload = explorer_payload(data, principal_id=principal, as_of=as_of)
                except (KeyError, ValueError) as exc:
                    self._send_json({"ok": False, "error": str(exc)}, HTTPStatus.BAD_REQUEST)
                    return
                self._send_json(payload)
                return
            self._send_json({"ok": False, "error": "not_found"}, HTTPStatus.NOT_FOUND)

        def do_POST(self) -> None:  # noqa: N802
            self._send_json(
                {"ok": False, "error": "read_only_surface"},
                HTTPStatus.METHOD_NOT_ALLOWED,
            )

        do_PUT = do_POST
        do_PATCH = do_POST
        do_DELETE = do_POST

        def log_message(self, _format: str, *_args: Any) -> None:
            return

    return Handler


def serve(*, fixture: Path, host: str = "127.0.0.1", port: int = 8767) -> None:
    if not _is_loopback_host(host):
        raise ValueError("Company Twin Explorer is loopback-only")
    server = ThreadingHTTPServer((host, port), _make_handler(fixture))
    print(f"Company Twin P2A Explorer: http://{host}:{server.server_port}")
    print("READ_ONLY=true execution_authority=NONE can_execute=false")
    try:
        server.serve_forever()
    finally:
        server.server_close()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="ContinuityOS Company Twin P2A read-only explorer")
    parser.add_argument("--fixture", required=True, type=Path)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", default=8767, type=int)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if not _is_loopback_host(args.host):
        print("ERROR: Company Twin Explorer is loopback-only")
        return 2
    serve(fixture=args.fixture, host=args.host, port=args.port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
