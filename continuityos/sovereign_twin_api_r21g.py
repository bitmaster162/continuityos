"""Loopback-only HTTP/UI shell for Sovereign Twin."""
from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .sovereign_twin_admission import ShadowMemoryAdmissionQueue
from .sovereign_twin_deep_lite import run_deep_lite
from .sovereign_twin_runtime import DEFAULT_EMBEDDING_MODEL, LmStudioClient, SovereignTwinRuntime

EXECUTION_AUTHORITY = "NONE"

_UI = """<!doctype html>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sovereign Twin Local</title>
<style>
:root{color-scheme:dark}
*{box-sizing:border-box}
body{font:15px/1.5 system-ui,-apple-system,Segoe UI,sans-serif;max-width:980px;margin:0 auto;padding:32px 18px 64px;background:#0b0d10;color:#eef2f6}
header{display:flex;align-items:flex-start;justify-content:space-between;gap:16px;margin-bottom:24px}
h1{margin:0 0 4px;font-size:26px}.sub{margin:0;color:#9ba7b4}
.badges{display:flex;gap:8px;flex-wrap:wrap;justify-content:flex-end}.badge{border:1px solid #2f3a46;border-radius:999px;padding:5px 9px;color:#b7c3cf;font-size:12px}
.panel{background:#12161b;border:1px solid #252d36;border-radius:14px;padding:16px;margin-top:14px}
textarea{width:100%;min-height:126px;resize:vertical;border:1px solid #37414c;border-radius:10px;background:#0d1116;color:#f4f7fa;padding:13px;font:inherit}
textarea:focus{outline:2px solid #637083;outline-offset:1px}
.controls{display:flex;gap:8px;flex-wrap:wrap;margin-top:10px}
button{padding:10px 15px;border:1px solid #44505d;border-radius:9px;background:#1a2027;color:#eef2f6;font:inherit;cursor:pointer}
button:hover{background:#222a33}button:disabled{opacity:.5;cursor:wait}
#status{min-height:24px;margin-top:10px;color:#aab5c0}
#status.error{color:#ffb4b4}
#result[hidden]{display:none}
.result-head{display:flex;justify-content:space-between;gap:12px;align-items:center;flex-wrap:wrap}
#mode{font-weight:700}.meta{color:#9ba7b4;font-size:13px}
#answer{white-space:pre-wrap;margin:16px 0 0;font-size:16px;line-height:1.65}
h2{font-size:16px;margin:20px 0 8px}
#evidence{display:grid;gap:8px;padding:0;margin:0;list-style:none}
.evidence-item{border:1px solid #2d3742;border-radius:9px;padding:10px 12px;background:#0e1217}
.evidence-id{font-weight:700;margin-right:8px}.evidence-text{white-space:pre-wrap;color:#cbd4dd}
details{margin-top:18px;border-top:1px solid #28313a;padding-top:12px}
summary{cursor:pointer;color:#aeb9c4}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#090b0e;color:#cbd4dd;padding:12px;border-radius:9px;max-height:420px;overflow:auto}
@media(max-width:640px){header{display:block}.badges{justify-content:flex-start;margin-top:10px}}
</style>
<header>
 <div>
  <h1>Sovereign Twin — Local</h1>
  <p class="sub">Read-only local shadow assistant backed by ContinuityOS memory.</p>
 </div>
 <div class="badges">
  <span class="badge">LOCAL_SHADOW</span>
  <span class="badge">AUTHORITY NONE</span>
  <span id="fast-readiness" class="badge" data-state="UNKNOWN">FAST CHECKING</span>
 </div>
</header>
<div class="panel">
 <textarea id="q" placeholder="Ask your local Twin"></textarea>
 <div class="controls">
  <button data-ask onclick="ask('fast')">FAST</button>
  <button data-ask onclick="ask('deep')">DEEP</button>
  <button data-ask onclick="askDeepLite()">DEEP-LITE</button>
 </div>
 <div id="status">Ready.</div>
</div>
<section id="result" class="panel" hidden>
 <div class="result-head">
  <div id="mode"></div>
  <div id="meta" class="meta"></div>
 </div>
 <div id="answer"></div>
 <div id="evidence-wrap" hidden>
  <h2>Evidence</h2>
  <ul id="evidence"></ul>
 </div>
 <details>
  <summary>Raw response</summary>
  <pre id="raw"></pre>
 </details>
</section>
<script>
const buttons=()=>Array.from(document.querySelectorAll('[data-ask]'));
function setBusy(message,busy){
 const status=document.getElementById('status');
 status.classList.remove('error');
 status.textContent=busy?message:'Ready.';
 buttons().forEach(b=>b.disabled=busy);
}
function readinessBadge(){return document.getElementById('fast-readiness')}
function applyReadiness(payload){
 const badge=readinessBadge();
 const state=String(payload&&payload.state?payload.state:'UNAVAILABLE').toUpperCase();
 badge.dataset.state=state;
 if(state==='READY'){
  badge.textContent='FAST READY';
  badge.title='FAST profile is resident with the required configuration.';
 }else if(state==='COLD'){
  badge.textContent='FAST COLD';
  badge.title='First FAST answer will load the local model.';
 }else{
  badge.textContent='FAST BLOCKED';
  badge.title='FAST is unavailable or misconfigured; inspect readiness or doctor.';
 }
}
async function refreshReadiness(){
 try{
  const response=await fetch('/readiness',{method:'GET'});
  const data=await response.json();
  if(!response.ok||data.error)throw new Error(String(data.error||('HTTP '+response.status)));
  applyReadiness(data);
  return data;
 }catch(error){
  applyReadiness({state:'UNAVAILABLE'});
  return null;
 }
}
function clearNode(node){while(node.firstChild)node.removeChild(node.firstChild)}
function evidenceLabel(item){
 const id=item&&item.id!==undefined?'mem:'+String(item.id):'memory';
 const score=item&&item.score!==undefined?' · score '+String(item.score):'';
 return id+score;
}
function renderAnswer(payload,label){
 const result=document.getElementById('result');
 const answer=document.getElementById('answer');
 const mode=document.getElementById('mode');
 const meta=document.getElementById('meta');
 const raw=document.getElementById('raw');
 const list=document.getElementById('evidence');
 const wrap=document.getElementById('evidence-wrap');

 mode.textContent=String(payload.mode||label||'answer').toUpperCase();
 const metaBits=[];
 if(payload.model)metaBits.push(String(payload.model));
 if(payload.stats&&payload.stats.pass_count!==undefined)metaBits.push(String(payload.stats.pass_count)+' pass');
 if(payload.execution_authority)metaBits.push('authority '+String(payload.execution_authority));
 meta.textContent=metaBits.join(' · ');

 const text=payload.text!==undefined?payload.text:(payload.answer!==undefined?payload.answer:'');
 answer.textContent=String(text||'No answer text returned.');
 raw.textContent=JSON.stringify(payload,null,2);

 clearNode(list);
 const evidence=Array.isArray(payload.evidence)?payload.evidence:[];
 for(const item of evidence){
  const li=document.createElement('li');
  li.className='evidence-item';
  const id=document.createElement('span');
  id.className='evidence-id';
  id.textContent=evidenceLabel(item);
  const body=document.createElement('div');
  body.className='evidence-text';
  body.textContent=String((item&&item.text)!==undefined?item.text:'');
  li.appendChild(id);
  li.appendChild(body);
  list.appendChild(li);
 }
 wrap.hidden=evidence.length===0;
 result.hidden=false;
}
async function postAsk(path,payload,label,busyMessage){
 const query=String(payload.query||'').trim();
 const status=document.getElementById('status');
 if(!query){
  status.classList.add('error');
  status.textContent='Query required.';
  return;
 }
 setBusy(busyMessage||label+' thinking...',true);
 try{
  const response=await fetch(path,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});
  const data=await response.json();
  if(!response.ok||data.ok===false||data.error)throw new Error(String(data.error||('HTTP '+response.status)));
  renderAnswer(data,label);
  status.textContent=label+' complete.';
 }catch(error){
  status.classList.add('error');
  status.textContent='Error: '+String(error&&error.message?error.message:error);
 }finally{
  buttons().forEach(b=>b.disabled=false);
  await refreshReadiness();
 }
}
async function ask(mode){
 const q=document.getElementById('q').value;
 let state=readinessBadge().dataset.state;
 if((mode==='fast'||mode==='deep')&&state==='UNKNOWN'){
  const readiness=await refreshReadiness();
  state=readiness&&readiness.state?String(readiness.state).toUpperCase():'UNAVAILABLE';
 }
 const busyMessage=mode==='fast'&&state==='COLD'
  ?'Loading FAST locally, then answering...'
  :mode==='deep'&&state==='READY'
   ?'Releasing FAST, then running DEEP locally...'
   :mode.toUpperCase()+' thinking...';
 return postAsk('/ask',{query:q,mode},mode.toUpperCase(),busyMessage);
}
async function askDeepLite(){
 const q=document.getElementById('q').value;
 return postAsk('/ask/deep-lite',{query:q},'DEEP-LITE');
}
refreshReadiness();
</script>"""


def _validate_bind(host: str) -> str:
    value = str(host).strip().lower()
    if value not in {"127.0.0.1", "localhost", "::1"}:
        raise ValueError("Sovereign Twin API is loopback-only")
    return value


class _TwinServer(ThreadingHTTPServer):
    runtime: SovereignTwinRuntime
    admissions: ShadowMemoryAdmissionQueue


def _answer_request(server: _TwinServer, path: str, body: dict[str, Any]) -> dict[str, Any] | None:
    """Dispatch read-only Twin answers while keeping DEEP-LITE on its dedicated contract."""
    if path not in {"/ask", "/ask/deep-lite"}:
        return None

    query = str(body.get("query", "")).strip()
    if not query:
        raise ValueError("query required")

    if path == "/ask/deep-lite":
        return run_deep_lite(
            query,
            memory_db=server.runtime.memory_db,
            client=server.runtime.client,
            embedding_model=server.runtime.embedding_model,
            recall_k=server.runtime.recall_k,
        ).to_dict()

    mode = str(body.get("mode", "fast"))
    return server.runtime.ask(query, mode=mode).to_dict()


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
                    "memory_db": self.server.runtime.memory_db,
                    "execution_authority": EXECUTION_AUTHORITY,
                    "can_execute": False,
                })
                return
            if path == "/readiness":
                self._json(200, self.server.runtime.fast_readiness())
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
            answer = _answer_request(self.server, path, body)
            if answer is not None:
                self._json(200, answer)
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
