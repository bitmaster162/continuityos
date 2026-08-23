"""Read-only local Control Center for the Sovereign Twin R21H baseline."""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Callable, Mapping
from urllib.error import URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from ._version import __version__


DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8766
DEFAULT_TWIN_URL = "http://127.0.0.1:8765"
DEFAULT_LM_STUDIO_URL = "http://127.0.0.1:1234"
DEFAULT_FAST_MODEL = "qwen3.5-4b"
DEFAULT_DEEP_MODEL = "qwen3.6-35b-a3b"
DEFAULT_EMBEDDING_MODEL = "text-embedding-nomic-embed-text-v1.5"
TWIN_BASELINE = "R21H"


@dataclass(frozen=True)
class ControlCenterConfig:
    runtime_root: Path
    twin_url: str = DEFAULT_TWIN_URL
    lm_studio_url: str = DEFAULT_LM_STUDIO_URL
    fast_model: str = DEFAULT_FAST_MODEL
    deep_model: str = DEFAULT_DEEP_MODEL
    embedding_model: str = DEFAULT_EMBEDDING_MODEL


def default_runtime_root() -> Path:
    local_app_data = os.environ.get("LOCALAPPDATA")
    if local_app_data:
        return Path(local_app_data) / "SovereignTwin"
    return Path.home() / ".local" / "share" / "SovereignTwin"


def _is_loopback_host(host: str) -> bool:
    value = host.strip().lower()
    if value == "localhost":
        return True
    try:
        return ipaddress.ip_address(value).is_loopback
    except ValueError:
        return False


def _is_loopback_url(url: str) -> bool:
    parsed = urlparse(url)
    return (
        parsed.scheme in {"http", "https"}
        and parsed.hostname is not None
        and _is_loopback_host(parsed.hostname)
        and parsed.username is None
        and parsed.password is None
    )


def _validate_local_config(host: str, config: ControlCenterConfig) -> None:
    if not _is_loopback_host(host):
        raise ValueError("Control Center refuses non-loopback bind")
    if not _is_loopback_url(config.twin_url):
        raise ValueError("Control Center refuses non-loopback Twin URL")
    if not _is_loopback_url(config.lm_studio_url):
        raise ValueError("Control Center refuses non-loopback LM Studio URL")


def _json_get(url: str, *, timeout: float = 2.0) -> dict:
    request = Request(url, headers={"Accept": "application/json"}, method="GET")
    with urlopen(request, timeout=timeout) as response:
        payload = json.loads(response.read().decode("utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"expected JSON object from {url}")
    return payload


def _read_json_file(path: Path) -> dict:
    if not path.is_file():
        return {}
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"expected JSON object in {path}")
    return payload


def _sha256_file(path: Path) -> str | None:
    if not path.is_file():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _line_count(path: Path) -> int:
    if not path.is_file():
        return 0
    count = 0
    with path.open("rb") as handle:
        for line in handle:
            if line.strip():
                count += 1
    return count


def _first_text(mapping: Mapping[str, object], *keys: str) -> str | None:
    for key in keys:
        value = mapping.get(key)
        if isinstance(value, str) and value.strip():
            return value
    return None


def _model_instances(catalog: Mapping[str, object], key: str) -> list[str]:
    models = catalog.get("models")
    if not isinstance(models, list):
        return []
    for model in models:
        if not isinstance(model, dict) or str(model.get("key", "")) != key:
            continue
        instances = model.get("loaded_instances")
        if not isinstance(instances, list):
            return []
        result: list[str] = []
        for instance in instances:
            if isinstance(instance, dict):
                instance_id = instance.get("id")
                if instance_id is not None:
                    result.append(str(instance_id))
        return result
    return []


def _safe_remote(
    url: str,
    getter: Callable[..., dict],
) -> tuple[dict, str | None]:
    try:
        return getter(url, timeout=2.0), None
    except (OSError, URLError, ValueError, json.JSONDecodeError) as exc:
        return {}, f"{type(exc).__name__}: {exc}"


def _resolve_memory_path(twin_health: Mapping[str, object], manifest: Mapping[str, object]) -> Path:
    value = _first_text(twin_health, "memory_db")
    if value is None:
        value = _first_text(manifest, "memory_db", "db", "database")
    if value is None:
        return Path.home() / ".continuityos" / "memory.db"
    return Path(value).expanduser()


def _resolve_admissions_path(manifest: Mapping[str, object]) -> Path:
    value = _first_text(
        manifest,
        "admissions_path",
        "admission_path",
        "admission_queue",
        "admission_queue_path",
    )
    if value is None:
        return Path.home() / ".continuityos" / "twin-admissions.jsonl"
    return Path(value).expanduser()


def build_status(
    config: ControlCenterConfig,
    *,
    get_json: Callable[..., dict] = _json_get,
) -> dict:
    manifest_path = config.runtime_root / "runtime-source.json"
    manifest_error = None
    try:
        manifest = _read_json_file(manifest_path)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        manifest = {}
        manifest_error = f"{type(exc).__name__}: {exc}"

    twin_health, twin_error = _safe_remote(
        f"{config.twin_url.rstrip('/')}/health",
        get_json,
    )
    lm_catalog, lm_error = _safe_remote(
        f"{config.lm_studio_url.rstrip('/')}/api/v1/models",
        get_json,
    )

    memory_path = _resolve_memory_path(twin_health, manifest)
    admissions_path = _resolve_admissions_path(manifest)

    memory_exists = memory_path.is_file()
    memory_size = memory_path.stat().st_size if memory_exists else None
    try:
        memory_sha = _sha256_file(memory_path)
    except OSError:
        memory_sha = None

    try:
        admissions_count = _line_count(admissions_path)
    except OSError:
        admissions_count = 0

    fast_instances = _model_instances(lm_catalog, config.fast_model)
    deep_instances = _model_instances(lm_catalog, config.deep_model)
    embedding_instances = _model_instances(lm_catalog, config.embedding_model)

    authority = twin_health.get("execution_authority")
    if not isinstance(authority, str) or not authority:
        authority = manifest.get("execution_authority")
    if not isinstance(authority, str) or not authority:
        authority = "UNKNOWN"

    can_execute_value = twin_health.get("can_execute")
    if not isinstance(can_execute_value, bool):
        can_execute_value = manifest.get("can_execute")
    can_execute = can_execute_value if isinstance(can_execute_value, bool) else False

    rollback_dirs = sorted(
        path.name
        for path in config.runtime_root.glob("rollback-*")
        if path.is_dir()
    )

    source_sha = _first_text(manifest, "source_sha", "git_sha", "commit_sha")
    python_path = _first_text(manifest, "python", "python_executable")
    twin_executable = _first_text(manifest, "twin_executable", "executable")

    twin_reachable = bool(twin_health)
    lm_reachable = bool(lm_catalog)

    return {
        "ok": True,
        "read_only": True,
        "product": {
            "continuityos_version": __version__,
            "twin_baseline": TWIN_BASELINE,
        },
        "twin": {
            "reachable": twin_reachable,
            "error": twin_error,
            "ok": twin_health.get("ok") is True,
            "mode": twin_health.get("mode", "UNKNOWN"),
            "execution_authority": authority,
            "can_execute": can_execute,
            "url": config.twin_url,
        },
        "memory": {
            "path": str(memory_path),
            "exists": memory_exists,
            "size_bytes": memory_size,
            "sha256": memory_sha,
        },
        "admissions": {
            "path": str(admissions_path),
            "exists": admissions_path.is_file(),
            "count": admissions_count,
        },
        "models": {
            "reachable": lm_reachable,
            "error": lm_error,
            "url": config.lm_studio_url,
            "fast": {
                "key": config.fast_model,
                "resident_instances": len(fast_instances),
                "instance_ids": fast_instances,
            },
            "deep": {
                "key": config.deep_model,
                "resident_instances": len(deep_instances),
                "instance_ids": deep_instances,
            },
            "embedding": {
                "key": config.embedding_model,
                "resident_instances": len(embedding_instances),
                "instance_ids": embedding_instances,
            },
        },
        "runtime_source": {
            "manifest_path": str(manifest_path),
            "manifest_exists": manifest_path.is_file(),
            "manifest_error": manifest_error,
            "source_sha": source_sha,
            "python": python_path,
            "twin_executable": twin_executable,
        },
        "rollback": {
            "old_venv_exists": (config.runtime_root / "runtime-venv").is_dir(),
            "backup_count": len(rollback_dirs),
            "backups": rollback_dirs,
        },
        "governance": {
            "execution_authority": authority,
            "can_execute": can_execute,
            "can_trade": False,
            "capital_permission": "DENY",
        },
    }


_UI = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ContinuityOS Control Center</title>
<style>
:root{color-scheme:dark;--bg:#080b10;--panel:#101720;--line:#253142;--text:#edf4fb;--muted:#91a2b4;--green:#34e57a;--amber:#ffd166;--red:#ff7d8b}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 50% -20%,#172435,#080b10 46%);color:var(--text);font:14px/1.5 system-ui,-apple-system,Segoe UI,sans-serif}
.wrap{max-width:1120px;margin:auto;padding:28px 20px 48px}header{display:flex;justify-content:space-between;gap:16px;align-items:flex-start;flex-wrap:wrap;margin-bottom:22px}
h1{margin:0;font-size:30px}.sub{color:var(--muted);margin-top:6px}.badge{border:1px solid #287947;background:#0d2115;color:#8affb0;border-radius:999px;padding:5px 10px;font-weight:800;font-size:12px}
.grid{display:grid;grid-template-columns:repeat(3,1fr);gap:12px}.card{border:1px solid var(--line);background:rgba(16,23,32,.93);border-radius:14px;padding:17px;min-width:0}
.card.wide{grid-column:span 2}h2{font-size:13px;letter-spacing:.08em;text-transform:uppercase;color:var(--muted);margin:0 0 12px}.big{font-size:25px;font-weight:800;margin:3px 0}
.row{display:flex;justify-content:space-between;gap:12px;padding:7px 0;border-top:1px solid #1b2633}.row:first-of-type{border-top:0}.row span{color:var(--muted)}.row b{overflow-wrap:anywhere;text-align:right}
.ok{color:var(--green)}.warn{color:var(--amber)}.bad{color:var(--red)}code{color:#bfeaff;font:12px ui-monospace,SFMono-Regular,Consolas,monospace;overflow-wrap:anywhere}
button{border:1px solid var(--line);border-radius:9px;background:#141d28;color:var(--text);padding:9px 12px;font-weight:700;cursor:pointer}button:hover{border-color:#3a4c64}
footer{color:var(--muted);font-size:12px;margin-top:18px}.error{color:var(--red)}
@media(max-width:850px){.grid{grid-template-columns:1fr 1fr}.card.wide{grid-column:span 2}}@media(max-width:570px){.grid{grid-template-columns:1fr}.card.wide{grid-column:span 1}}
</style>
</head>
<body><div class="wrap">
<header><div><h1>ContinuityOS Control Center</h1><div class="sub">Sovereign Twin R21H · local read-only observability</div></div><div><span class="badge">READ ONLY</span> <button id="refresh" type="button">Refresh</button></div></header>
<div id="error" class="error"></div>
<div class="grid">
<section class="card"><h2>Twin</h2><div id="twinState" class="big">Loading…</div><div class="row"><span>Mode</span><b id="mode">—</b></div><div class="row"><span>Authority</span><b id="authority">—</b></div><div class="row"><span>Can execute</span><b id="canExecute">—</b></div></section>
<section class="card"><h2>Models</h2><div class="row"><span>FAST</span><b id="fast">—</b></div><div class="row"><span>DEEP</span><b id="deep">—</b></div><div class="row"><span>Embedding</span><b id="embed">—</b></div><div class="row"><span>LM Studio</span><b id="lm">—</b></div></section>
<section class="card"><h2>Governance</h2><div class="row"><span>Execution</span><b id="govExec">—</b></div><div class="row"><span>Trading</span><b id="trade">—</b></div><div class="row"><span>Capital</span><b id="capital">—</b></div></section>
<section class="card wide"><h2>Canonical memory</h2><div class="row"><span>Path</span><b><code id="dbPath">—</code></b></div><div class="row"><span>SHA256</span><b><code id="dbSha">—</code></b></div><div class="row"><span>Size</span><b id="dbSize">—</b></div><div class="row"><span>Admissions</span><b id="admissions">—</b></div></section>
<section class="card"><h2>Runtime source</h2><div class="row"><span>ContinuityOS</span><b id="version">—</b></div><div class="row"><span>Baseline</span><b id="baseline">—</b></div><div class="row"><span>Source SHA</span><b><code id="sourceSha">—</code></b></div><div class="row"><span>Old venv</span><b id="oldVenv">—</b></div><div class="row"><span>Rollback backups</span><b id="backups">—</b></div></section>
</div>
<footer id="stamp">No state loaded. This surface has no mutation routes and does not grant execution authority.</footer>
</div>
<script>
const byId=(id)=>document.getElementById(id);
const set=(id,value)=>{byId(id).textContent=value==null?'—':String(value)};
const state=(id,value,good)=>{set(id,value);byId(id).className=good===true?'ok':good===false?'bad':'warn'};
async function refresh(){
  byId('error').textContent='';
  try{
    const response=await fetch('/api/status',{cache:'no-store'});
    const data=await response.json();
    if(!response.ok||data.ok!==true)throw new Error(data.error||('HTTP '+response.status));
    state('twinState',data.twin.reachable?'ONLINE':'OFFLINE',data.twin.reachable);
    set('mode',data.twin.mode);set('authority',data.twin.execution_authority);set('canExecute',data.twin.can_execute);
    state('lm',data.models.reachable?'ONLINE':'OFFLINE',data.models.reachable);
    set('fast',data.models.fast.resident_instances+' resident');
    set('deep',data.models.deep.resident_instances+' resident');
    set('embed',data.models.embedding.resident_instances+' resident');
    set('govExec',data.governance.execution_authority+' / '+data.governance.can_execute);
    set('trade',data.governance.can_trade);set('capital',data.governance.capital_permission);
    set('dbPath',data.memory.path);set('dbSha',data.memory.sha256);
    set('dbSize',data.memory.size_bytes==null?'missing':data.memory.size_bytes+' bytes');
    set('admissions',data.admissions.exists?(data.admissions.count+' records'):'absent');
    set('version',data.product.continuityos_version);set('baseline',data.product.twin_baseline);
    set('sourceSha',data.runtime_source.source_sha);
    set('oldVenv',data.rollback.old_venv_exists);set('backups',data.rollback.backup_count);
    set('stamp','Updated '+new Date().toLocaleTimeString()+'. READ ONLY · no mutation routes · no execution authority granted.');
  }catch(error){byId('error').textContent='Status read failed: '+error.message}
}
byId('refresh').addEventListener('click',refresh);
refresh();
</script>
</body></html>"""


def _json_bytes(payload: dict) -> bytes:
    return json.dumps(
        payload,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _make_handler(config: ControlCenterConfig):
    class ControlCenterHandler(BaseHTTPRequestHandler):
        server_version = "ContinuityOS-ControlCenter/1"

        def _headers(self, status: int, content_type: str, length: int) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(length))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header(
                "Content-Security-Policy",
                "default-src 'self'; style-src 'unsafe-inline'; "
                "script-src 'unsafe-inline'; connect-src 'self'; "
                "img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'",
            )
            self.end_headers()

        def _send_json(self, status: int, payload: dict) -> None:
            body = _json_bytes(payload)
            self._headers(status, "application/json; charset=utf-8", len(body))
            self.wfile.write(body)

        def do_GET(self) -> None:  # noqa: N802 - stdlib handler contract
            path = self.path.split("?", 1)[0]
            if path == "/":
                body = _UI.encode("utf-8")
                self._headers(200, "text/html; charset=utf-8", len(body))
                self.wfile.write(body)
                return
            if path == "/health":
                self._send_json(
                    200,
                    {
                        "ok": True,
                        "read_only": True,
                        "mode": "LOCAL_SHADOW",
                        "execution_authority": "NONE",
                        "can_execute": False,
                        "twin_baseline": TWIN_BASELINE,
                    },
                )
                return
            if path == "/api/status":
                self._send_json(200, build_status(config))
                return
            self._send_json(404, {"ok": False, "error": "not found", "read_only": True})

        def do_POST(self) -> None:  # noqa: N802 - stdlib handler contract
            self._send_json(
                405,
                {
                    "ok": False,
                    "error": "Control Center is read-only",
                    "read_only": True,
                    "execution_authority": "NONE",
                    "can_execute": False,
                },
            )

        def log_message(self, _format: str, *_args: object) -> None:
            return

    return ControlCenterHandler


def serve(
    *,
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
    config: ControlCenterConfig | None = None,
) -> None:
    active_config = config or ControlCenterConfig(runtime_root=default_runtime_root())
    _validate_local_config(host, active_config)
    server = ThreadingHTTPServer((host, port), _make_handler(active_config))
    try:
        server.serve_forever()
    finally:
        server.server_close()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="continuityos-control-center")
    sub = parser.add_subparsers(dest="cmd", required=True)
    serve_parser = sub.add_parser("serve")
    serve_parser.add_argument("--host", default=DEFAULT_HOST)
    serve_parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    serve_parser.add_argument("--runtime-root", default=str(default_runtime_root()))
    serve_parser.add_argument("--twin-url", default=DEFAULT_TWIN_URL)
    serve_parser.add_argument("--lm-studio-url", default=DEFAULT_LM_STUDIO_URL)
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    if args.cmd != "serve":
        return 2
    config = ControlCenterConfig(
        runtime_root=Path(args.runtime_root).expanduser(),
        twin_url=args.twin_url,
        lm_studio_url=args.lm_studio_url,
    )
    try:
        _validate_local_config(args.host, config)
    except ValueError as exc:
        print(
            json.dumps(
                {
                    "ok": False,
                    "error": str(exc),
                    "read_only": True,
                    "execution_authority": "NONE",
                    "can_execute": False,
                },
                sort_keys=True,
            )
        )
        return 2
    serve(host=args.host, port=args.port, config=config)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
