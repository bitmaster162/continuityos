"""Product onboarding for ``cos setup``.

The setup path is deliberately local-first and small. It initializes the same durable
memory used by the rest of the packaged ``cos`` surface, records only operator-provided
identity/focus data, writes a first checkpoint, and generates a local status dashboard.

Optional semantic embeddings are never auto-selected. ``HashingEmbedder`` remains the
default even when FastEmbed is installed; FastEmbed is constructed only after the
operator explicitly sets ``CONTINUITYOS_EMBEDDER=fast`` (or ``fastembed``).
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import sys
import time

from .continuity import Continuity
from .current_entrypoints import (
    EMBEDDER_ENV,
    _DEFAULT_EMBEDDER_MODES,
    _FAST_EMBEDDER_MODES,
    _embedder_policy_hold,
)
from .memory import Memory

HOME = Path(os.path.expanduser("~/.continuityos"))
STATE_FILE = HOME / "setup_state.json"
DASH_FILE = HOME / "continuityos_dashboard.html"


class C:
    B = "\033[1m"
    DIM = "\033[2m"
    G = "\033[32m"
    CY = "\033[36m"
    R = "\033[0m"

    @staticmethod
    def strip() -> None:
        for key in ("B", "DIM", "G", "CY", "R"):
            setattr(C, key, "")


if not sys.stdout.isatty() or os.environ.get("NO_COLOR"):
    C.strip()

_INTERACTIVE = sys.stdin.isatty()


def _say(msg: str = "") -> None:
    print(msg)


def _why(msg: str) -> None:
    print(f"{C.DIM}  {msg}{C.R}")


def _ok(msg: str) -> None:
    print(f"{C.G}  OK {msg}{C.R}")


def _hdr(n: int, total: int, title: str) -> None:
    print(f"\n{C.B}[{n}/{total}] {title}{C.R}")


def _ask(prompt: str, default: str = "", quick: bool = False) -> str:
    """Prompt with a default; non-interactive/quick mode accepts that default."""
    suffix = f" {C.DIM}[{default}]{C.R}" if default else ""
    if quick or not _INTERACTIVE:
        print(f"{C.CY}? {prompt}{suffix}{C.R} {C.DIM}(auto: {default or '-'}){C.R}")
        return default
    try:
        answer = input(f"{C.CY}? {prompt}{suffix}{C.R} ").strip()
    except (EOFError, KeyboardInterrupt):
        return default
    return answer or default


def _load_state() -> dict[str, object]:
    try:
        value = json.loads(STATE_FILE.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except Exception:
        return {}


def _save_state(state: dict[str, object]) -> None:
    HOME.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")


def _requested_embedder_mode() -> tuple[str | None, int | None]:
    """Resolve setup's embedder policy before any setup filesystem/database write."""
    mode = os.environ.get(EMBEDDER_ENV, "").strip().lower()
    if mode in _DEFAULT_EMBEDDER_MODES or mode in _FAST_EMBEDDER_MODES:
        return mode, None
    return None, _embedder_policy_hold("setup", mode)


def _open_memory(db: str, mode: str) -> tuple[Memory | None, str, int | None]:
    if mode in _FAST_EMBEDDER_MODES:
        try:
            from .embedders import FastEmbedEmbedder

            return Memory(db, embedder=FastEmbedEmbedder()), "FastEmbed (explicit opt-in)", None
        except Exception as exc:
            print(
                json.dumps(
                    {
                        "schema": "continuityos.product.setup/v1",
                        "terminal": "COS_SETUP_EMBEDDER_REVISE",
                        "reason": "FASTEMBED_UNAVAILABLE",
                        "environment_variable": EMBEDDER_ENV,
                        "requested": mode,
                        "error_type": type(exc).__name__,
                        "error": str(exc),
                    },
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                )
            )
            return None, "", 2
    return Memory(db), "HashingEmbedder (local, offline)", None


def _prepare_paths(db: str) -> None:
    HOME.mkdir(parents=True, exist_ok=True)
    db_path = Path(db).expanduser()
    parent = db_path.parent
    if str(parent) not in ("", "."):
        parent.mkdir(parents=True, exist_ok=True)


def run_wizard(db: str, quick: bool = False) -> int:
    """Run the bounded canonical onboarding used by ``cos setup``."""
    mode, policy_rc = _requested_embedder_mode()
    if policy_rc is not None:
        return policy_rc
    assert mode is not None

    _prepare_paths(db)
    memory, embedder_label, memory_rc = _open_memory(db, mode)
    if memory_rc is not None:
        return memory_rc
    assert memory is not None
    continuity = Continuity(memory=memory)

    old = _load_state()
    default_name = str(old.get("name") or "")
    default_role = str(old.get("role") or "")
    default_tz = str(old.get("tz") or os.environ.get("TZ") or "")
    default_focus = str(old.get("focus") or old.get("trunk") or "")

    total = 4
    print(f"{C.B}ContinuityOS setup{C.R}")
    _say("Local durable memory and continuity. No account or cloud service is required.\n")

    _hdr(1, total, "Local memory")
    _why("The default path uses deterministic local hashing and does not initialize an optional model.")
    _ok(f"Python {sys.version_info.major}.{sys.version_info.minor}")
    _ok(f"database: {db}")
    _ok(f"embedder: {embedder_label}")

    _hdr(2, total, "Operator context")
    _why("Only values you provide here are added to canon. Blank values are skipped.")
    name = _ask("Name (optional)", default_name, quick)
    role = _ask("Role or work context (optional)", default_role, quick)
    tz = _ask("Timezone (optional)", default_tz, quick)
    if name:
        continuity.add_canon(f"Operator name: {name}")
    if role:
        continuity.add_canon(f"Operator role: {role}")
    if tz:
        continuity.add_canon(f"Operator timezone: {tz}")
    _ok("operator context recorded" if any((name, role, tz)) else "operator context left unchanged")

    _hdr(3, total, "Current focus")
    _why("A focus is optional; when provided it becomes the trunk frontier for later handoff/boot output.")
    focus = _ask("Current focus (optional)", default_focus, quick)
    if focus:
        continuity.set_frontier("trunk", focus)
        _ok("trunk frontier recorded")
    else:
        _ok("no focus recorded")

    _hdr(4, total, "First checkpoint")
    checkpoint_id = continuity.checkpoint(
        summary="ContinuityOS setup complete",
        next_action="import history, remember durable context, or run cos boot",
        proof="cos setup",
    )
    _ok(f"checkpoint #{checkpoint_id} written")

    _build_dashboard(memory, continuity, db)
    _save_state(
        {
            "name": name,
            "role": role,
            "tz": tz,
            "focus": focus,
            "embedder": "fast" if mode in _FAST_EMBEDDER_MODES else "hash",
            "completed_at": time.time(),
        }
    )

    _say("\nNext:")
    _say("  cos import <export-path> --extract")
    _say("  cos status")
    _say("  cos connect <client>")
    _say("  cos demo continuity")
    _say("  cos boot")
    _say(f"\nLocal dashboard: {DASH_FILE}")
    return 0


def _build_dashboard(memory: Memory, continuity: Continuity, db: str) -> None:
    """Generate a small self-contained local status dashboard."""
    try:
        namespaces = memory.namespaces()
    except Exception:
        namespaces = []
    try:
        frontiers = continuity.frontiers()
    except Exception:
        frontiers = {}
    try:
        loops = continuity.open_loops()
    except Exception:
        loops = []
    try:
        last_checkpoint = continuity.last_checkpoint() or {}
    except Exception:
        last_checkpoint = {}

    data = {
        "db": db,
        "namespaces": namespaces,
        "frontiers": frontiers,
        "open_loops": len(loops),
        "last_checkpoint": last_checkpoint,
        "generated": time.strftime("%Y-%m-%d %H:%M"),
    }
    payload = json.dumps(data, ensure_ascii=False, default=str).replace("</", "<\\/")
    DASH_FILE.write_text(_DASH_TEMPLATE.replace("__DATA__", payload), encoding="utf-8")


_DASH_TEMPLATE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>ContinuityOS status</title>
<style>
body{font-family:system-ui,sans-serif;max-width:900px;margin:40px auto;padding:0 20px;color:#1f2328}
h1{margin-bottom:4px}.muted{color:#656d76}.grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:16px;margin-top:24px}
.card{border:1px solid #d0d7de;border-radius:10px;padding:16px}.row{display:flex;justify-content:space-between;gap:20px;padding:5px 0;border-bottom:1px solid #f0f1f2}.row:last-child{border:0}
code{overflow-wrap:anywhere}@media(max-width:700px){.grid{grid-template-columns:1fr}}
</style></head><body>
<h1>ContinuityOS</h1><div class="muted">Local continuity status · generated <span id="generated"></span></div>
<div class="grid"><div class="card"><h2>Memory</h2><div id="memory"></div></div>
<div class="card"><h2>Frontiers</h2><div id="frontiers"></div></div>
<div class="card"><h2>Continuity</h2><div id="continuity"></div></div>
<div class="card"><h2>Storage</h2><code id="db"></code></div></div>
<script>
const D=__DATA__;document.getElementById('generated').textContent=D.generated;document.getElementById('db').textContent=D.db;
function rows(id,pairs){const el=document.getElementById(id);el.innerHTML=pairs.length?pairs.map(([k,v])=>`<div class="row"><span>${String(k)}</span><span>${String(v)}</span></div>`).join(''):'<span class="muted">nothing yet</span>'}
rows('memory',(D.namespaces||[]).map(n=>[n.namespace,n.count]));rows('frontiers',Object.entries(D.frontiers||{}));
const cp=D.last_checkpoint||{};rows('continuity',[['open loops',D.open_loops||0],['last checkpoint',cp.summary||'—']]);
</script></body></html>"""


def build_dashboard_only(db: str) -> int:
    """Regenerate the local dashboard under the same setup embedder policy."""
    mode, policy_rc = _requested_embedder_mode()
    if policy_rc is not None:
        return policy_rc
    assert mode is not None

    _prepare_paths(db)
    memory, _label, memory_rc = _open_memory(db, mode)
    if memory_rc is not None:
        return memory_rc
    assert memory is not None
    _build_dashboard(memory, Continuity(memory=memory), db)
    print(f"dashboard: {DASH_FILE}")
    return 0
