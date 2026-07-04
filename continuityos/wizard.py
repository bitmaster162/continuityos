"""ContinuityOS setup wizard — `cos setup`.

Guided onboarding so a non-technical user can stand up the whole stack and use every
feature. Spec: Trade/HANDOFF/COS_SETUP_WIZARD_SPEC_20260704.md (cp-0321).

Design principles:
- Every step: explain WHY in plain words -> ask (Enter = recommended default) -> do -> show result.
- Idempotent: re-running is safe; state tracked in ~/.continuityos/setup_state.json.
- Non-interactive safe: if stdin is not a TTY (CI, pipes), all prompts take defaults.
- Nothing irreversible without asking. Secrets go to ~/.continuityos/.env (chmod 600), never canon.
"""
from __future__ import annotations
import json
import os
import sys
import time
from pathlib import Path
from typing import Optional

from .memory import Memory
from .continuity import Continuity
from .twin import Twin

HOME = Path(os.path.expanduser("~/.continuityos"))
STATE_FILE = HOME / "setup_state.json"
ENV_FILE = HOME / ".env"
DASH_FILE = HOME / "orca_dashboard.html"

# ---- tiny UI helpers -------------------------------------------------------
class C:
    B = "\033[1m"; DIM = "\033[2m"; G = "\033[32m"; Y = "\033[33m"; CY = "\033[36m"; R = "\033[0m"
    @staticmethod
    def strip():
        for k in ("B", "DIM", "G", "Y", "CY", "R"):
            setattr(C, k, "")

if not sys.stdout.isatty() or os.environ.get("NO_COLOR"):
    C.strip()

_INTERACTIVE = sys.stdin.isatty()


def _say(msg=""): print(msg)
def _why(msg): print(f"{C.DIM}  {msg}{C.R}")
def _ok(msg): print(f"{C.G}  ✓ {msg}{C.R}")
def _hdr(n, total, title): print(f"\n{C.B}[{n}/{total}] {title}{C.R}")


def _ask(prompt: str, default: str = "", quick: bool = False) -> str:
    """Prompt with a default. In --quick or non-interactive mode, returns default."""
    suffix = f" {C.DIM}[{default}]{C.R}" if default else ""
    if quick or not _INTERACTIVE:
        print(f"{C.CY}? {prompt}{suffix}{C.R} {C.DIM}(auto: {default or '-'}){C.R}")
        return default
    try:
        ans = input(f"{C.CY}? {prompt}{suffix}{C.R} ").strip()
    except (EOFError, KeyboardInterrupt):
        return default
    return ans or default


def _yes(prompt: str, default_yes: bool = True, quick: bool = False) -> bool:
    d = "Y/n" if default_yes else "y/N"
    ans = _ask(f"{prompt} ({d})", "", quick).lower()
    if not ans:
        return default_yes
    return ans in ("y", "yes", "да", "д", "1", "true")


def _load_state() -> dict:
    try:
        return json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _save_state(st: dict):
    HOME.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(st, ensure_ascii=False, indent=2), encoding="utf-8")


def _write_secret(key: str, value: str):
    HOME.mkdir(parents=True, exist_ok=True)
    lines = []
    if ENV_FILE.exists():
        lines = [l for l in ENV_FILE.read_text(encoding="utf-8").splitlines()
                 if not l.startswith(f"{key}=")]
    lines.append(f"{key}={value}")
    ENV_FILE.write_text("\n".join(lines) + "\n", encoding="utf-8")
    try:
        os.chmod(ENV_FILE, 0o600)
    except OSError:
        pass


# ---- the wizard ------------------------------------------------------------
def run_wizard(db: str, quick: bool = False) -> int:
    total = 8
    st = _load_state()
    HOME.mkdir(parents=True, exist_ok=True)

    print(f"{C.B}{C.CY}")
    print("  ┌───────────────────────────────────────────────┐")
    print("  │   ContinuityOS · Setup                        │")
    print("  │   durable memory + continuity for your AI     │")
    print("  └───────────────────────────────────────────────┘")
    print(C.R)
    _say("In ~5 minutes you'll have a personal memory layer your AI keeps across")
    _say("sessions and even across model swaps. Enter = the recommended choice.\n")

    # memory + continuity + twin handles
    try:
        from .embedders import FastEmbedEmbedder
        m = Memory(db, embedder=FastEmbedEmbedder())
        embed = "fast (semantic)"
    except Exception:
        m = Memory(db)
        embed = "zero-dep (keyword+hash)"
    c = Continuity(memory=m)
    tw = Twin(memory=m)

    # --- Step 0: environment ---
    _hdr(0, total, "Checking your setup")
    _why("A local SQLite file holds everything. No cloud, no account, no telemetry.")
    _ok(f"Python {sys.version_info.major}.{sys.version_info.minor} · db: {db}")
    _ok(f"embedder: {embed}")
    if embed.startswith("zero") and _yes("Install better semantic recall now? (pip continuityos[fast])",
                                          default_yes=False, quick=quick):
        _say(f"  Run:  {C.B}pip install 'continuityos[fast]'{C.R}  then re-run  cos setup")

    # --- Step 1: who you are ---
    _hdr(1, total, "Who you are")
    _why("These become the core facts your agents always know about you (your canon).")
    name = _ask("Your name", st.get("name", ""), quick)
    role = _ask("What you do (one line)", st.get("role", ""), quick)
    tz = _ask("Timezone", st.get("tz", "Asia/Bangkok"), quick)
    if name:
        c.add_canon(f"Operator name: {name}")
    if role:
        c.add_canon(f"Operator role: {role}")
    if tz:
        c.add_canon(f"Operator timezone: {tz}")
    st.update(name=name, role=role, tz=tz)
    _ok("Saved to canon (verified, always-loaded truth).")

    # --- Step 2: frontiers ---
    _hdr(2, total, "Your focus (frontiers)")
    _why("A frontier is what you're focused on. Three lanes keep you honest:")
    _why("🌳 trunk = main project · 💰 cash = what earns · 🔬 lab = experiments.")
    trunk = _ask("🌳 trunk (main project)", st.get("trunk", "my-project"), quick)
    cash = _ask("💰 cash (what brings money)", st.get("cash", "—"), quick)
    lab = _ask("🔬 lab (an experiment)", st.get("lab", "—"), quick)
    for kind, val in (("trunk", trunk), ("cash", cash), ("lab", lab)):
        if val and val != "—":
            c.set_frontier(kind, val)
    st.update(trunk=trunk, cash=cash, lab=lab)
    _ok("Frontiers set:")
    for k, v in c.frontiers().items():
        print(f"    {k}: {v}")

    # --- Step 3: digital twin ---
    _hdr(3, total, "Your digital twin")
    _why("The twin is a behavioral model of YOU, built from your memory. It predicts your")
    _why("stance and checks proposed actions against your canon. More rules = sharper twin.")
    if _yes("Add a few of your non-negotiable rules now?", default_yes=True, quick=quick):
        examples = [
            "Never move real money without my explicit confirmation.",
            "Ship honest numbers, never inflated marketing claims.",
        ]
        rules = []
        if quick or not _INTERACTIVE:
            rules = examples
        else:
            _say(f"  {C.DIM}Examples: {examples[0]!r}{C.R}")
            for i in range(1, 6):
                rule = _ask(f"  rule #{i} (blank to finish)", "", quick)
                if not rule:
                    break
                rules.append(rule)
            if not rules:
                rules = examples
        for r in rules:
            c.add_canon(r, tags=["rule"])
        _ok(f"Added {len(rules)} rule(s). Live demo of the governance gate:")
        # pick a demo action that actually collides with a seeded rule, so the
        # user SEES the gate fire (falls back to a generic risky action).
        demo_action = ("transfer $5000 to a new wallet right now, no confirmation"
                       if any("money" in r.lower() or "confirm" in r.lower() for r in rules)
                       else "delete all production data without a backup")
        verdict = tw.alignment(demo_action)
        v = verdict.get("verdict", verdict) if isinstance(verdict, dict) else verdict
        print(f"    action: {C.Y}{demo_action}{C.R}")
        print(f"    twin  : {json.dumps(v, ensure_ascii=False)[:140]}")
        _why("That's your twin checking a risky action against your own rules.")
    st["twin_seeded"] = True

    # --- Step 4: agents ---
    _hdr(4, total, "Your agents")
    _why("Solo (just your chat) or a team? ContinuityOS runs a council of agents on one memory.")
    _say(f"  {C.B}1{C.R}) Solo — just me + my AI chat (default)")
    _say(f"  {C.B}2{C.R}) + Hermes worker — an autonomous agent that runs tasks 24/7,")
    _say(f"       so it does the grunt work instead of burning your chat tokens")
    _say(f"  {C.B}3{C.R}) + Antigravity — a Gemini agent for content/guides")
    choice = _ask("Pick 1 / 2 / 3", st.get("agents", "1"), quick)
    st["agents"] = choice
    if choice.strip() in ("2", "3"):
        _say(f"\n  {C.B}Hermes runs on a FREE model — NVIDIA Nemotron via OpenRouter.{C.R}")
        _why("How: go to openrouter.ai -> create an API key.")
        _why(f"{C.Y}TIP:{C.R} put $10 on OpenRouter ONCE. It won't be spent on free models —")
        _why("it just activates a full account and lifts the harsh free-tier rate limits.")
        key = _ask("Paste your OpenRouter API key (blank to do it later)", "", quick)
        if key:
            _write_secret("OPENROUTER_API_KEY", key)
            _ok("Key saved to ~/.continuityos/.env (chmod 600, never in git).")
        _say(f"  Then run:  {C.B}hermes setup{C.R}  (it auto-imports OpenClaw settings if found)")
        if choice.strip() == "3":
            _say(f"  For Antigravity: open it and paste our onboarding brief")
            _say(f"  (Trade/HANDOFF/ANTIGRAVITY_ONBOARD_PROMPT_20260704.md).")

    # --- Step 5: first checkpoint ---
    _hdr(5, total, "Your first checkpoint (the magic)")
    _why("A checkpoint saves your thread. Swap models or start a new session — it restores.")
    cid = c.checkpoint(summary="ContinuityOS setup complete",
                       next_action="start using cos remember / recall / boot",
                       proof="setup wizard")
    _ok(f"checkpoint #{cid} written.")
    _say(f"  {C.DIM}This is what a fresh agent reads to continue with zero prior context:{C.R}")
    ho = c.handoff()
    for line in ho.splitlines()[:8]:
        print(f"    {C.DIM}{line}{C.R}")
    _why("Your thread is now immortal across model changes. That's the whole point.")

    # --- Step 6: monetization map (from your data, with permission) ---
    _hdr(6, total, "Your monetization map")
    _why("Point me at a folder of your notes/plans and I build a tiered money-map from the")
    _why("prices and offers you already wrote down. Local only - nothing is uploaded.")
    src = _ask("Folder to scan for offers (blank = just your memory / skip)", st.get("moneymap_src", ""), quick)
    try:
        from .monetization import build as _mm_build, render_map_md as _mm_render
        _paths = [os.path.expanduser(src)] if src.strip() else None
        _mp = _mm_build(paths=_paths, memory=m)
        if _mp["count"]:
            _mmfile = HOME / "monetization_map.md"
            _mmfile.write_text(_mm_render(_mp), encoding="utf-8")
            _tiers_used = sum(1 for _t in _mp["tiers"].values() if _t)
            _ok("Money-map: %d offers across %d tier(s)" % (_mp["count"], _tiers_used))
            _say("  Saved: %s" % _mmfile)
            for _tname, _offers in _mp["tiers"].items():
                if _offers:
                    print("    %s: %d" % (_tname, len(_offers)))
        else:
            _why("No priced offers found yet - add notes with prices, then: cos moneymap --from <dir>")
    except Exception as _e:
        _why("(money-map skipped: %s)" % _e)
    st["moneymap_src"] = src

    # --- Step 7: ORCA dashboard ---
    _hdr(7, total, "Your control room (ORCA dashboard)")
    _why("One page: your memory, frontiers, agent queue and checkpoints at a glance.")
    _build_dashboard(m, c, db)
    _ok(f"Dashboard generated: {DASH_FILE}")
    _say(f"  Open it in your browser:  {C.B}{DASH_FILE}{C.R}")
    _say(f"  {C.DIM}(regenerate anytime with: cos setup --dashboard-only){C.R}")

    # --- Step 7: done ---
    _hdr(8, total, "You're set up")
    print(f"""    {C.G}✓{C.R} memory      {C.G}✓{C.R} frontiers   {C.G}✓{C.R} twin
    {C.G}✓{C.R} agents      {C.G}✓{C.R} checkpoint  {C.G}✓{C.R} dashboard""")
    _say("\n  Three commands for every day:")
    _say(f"    {C.B}cos remember{C.R} \"…\"   save something that matters")
    _say(f"    {C.B}cos recall{C.R}  \"…\"    get it back when it's relevant")
    _say(f"    {C.B}cos boot{C.R}            your morning context + health check")
    _say(f"\n  {C.DIM}Welcome aboard{(', ' + name) if name else ''}. Models are disposable — your continuity isn't.{C.R}\n")

    st["completed_at"] = time.time()
    _save_state(st)
    return 0


def _build_dashboard(m: Memory, c: Continuity, db: str):
    """Generate a self-contained static ORCA dashboard from current state."""
    try:
        namespaces = m.namespaces()
    except Exception:
        namespaces = []
    frontiers = c.frontiers()
    try:
        loops = c.open_loops()
    except Exception:
        loops = []
    try:
        last_cp = c.last_checkpoint() or {}
    except Exception:
        last_cp = {}
    # optional Hermes kanban peek (best-effort, read-only)
    kanban = []
    kpath = Path(os.path.expanduser("~/AppData/Local/hermes/kanban.db"))
    try:
        if kpath.exists():
            import sqlite3
            cn = sqlite3.connect(f"file:{kpath}?mode=ro&immutable=1", uri=True)
            kanban = [dict(zip(("title", "status"), r)) for r in
                      cn.execute("SELECT title,status FROM tasks ORDER BY created_at DESC LIMIT 10")]
    except Exception:
        kanban = []

    data = {"namespaces": namespaces, "frontiers": frontiers, "loops": loops,
            "last_checkpoint": last_cp, "kanban": kanban,
            "generated": time.strftime("%Y-%m-%d %H:%M")}
    html = _DASH_TEMPLATE.replace("__DATA__", json.dumps(data, ensure_ascii=False, default=str))
    DASH_FILE.write_text(html, encoding="utf-8")


_DASH_TEMPLATE = """<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<title>ContinuityOS · ORCA Dashboard</title><style>
:root{--bg:#0d1117;--card:#161b22;--fg:#e6edf3;--dim:#8b949e;--acc:#4ea1ff;--g:#2fae66}
*{box-sizing:border-box;margin:0;padding:0}body{background:var(--bg);color:var(--fg);
font-family:-apple-system,Segoe UI,Roboto,sans-serif;padding:28px;max-width:1100px;margin:0 auto}
h1{font-size:22px;margin-bottom:2px}.sub{color:var(--dim);font-size:13px;margin-bottom:22px}
.grid{display:grid;grid-template-columns:repeat(2,1fr);gap:16px}
.card{background:var(--card);border:1px solid #30363d;border-radius:12px;padding:18px}
.card h2{font-size:13px;text-transform:uppercase;letter-spacing:1px;color:var(--acc);margin-bottom:12px}
.row{display:flex;justify-content:space-between;padding:6px 0;border-bottom:1px solid #21262d;font-size:14px}
.row:last-child{border:0}.pill{background:#21262d;border-radius:20px;padding:2px 10px;font-size:12px;color:var(--dim)}
.big{font-size:15px;color:var(--fg)}.empty{color:var(--dim);font-style:italic;font-size:13px}
.foot{color:var(--dim);font-size:12px;margin-top:20px;text-align:center}
.status-ready{color:var(--acc)}.status-running{color:var(--g)}
</style></head><body>
<h1>🎛️ ORCA Dashboard</h1><div class="sub">ContinuityOS control room · generated <span id="gen"></span></div>
<div class="grid">
  <div class="card"><h2>🌳 Frontiers</h2><div id="frontiers"></div></div>
  <div class="card"><h2>🧠 Memory</h2><div id="memory"></div></div>
  <div class="card"><h2>🤖 Agent queue (Hermes kanban)</h2><div id="kanban"></div></div>
  <div class="card"><h2>📍 Continuity</h2><div id="cont"></div></div>
</div>
<div class="foot">Local · one SQLite file · no cloud. Models are disposable — continuity isn't.</div>
<script>
const D = __DATA__;
document.getElementById('gen').textContent = D.generated;
function rows(el, pairs){el.innerHTML = pairs.length ? pairs.map(([k,v])=>
  `<div class="row"><span>${k}</span><span class="big">${v}</span></div>`).join('') :
  '<div class="empty">nothing yet</div>';}
rows(document.getElementById('frontiers'), Object.entries(D.frontiers||{}));
rows(document.getElementById('memory'), (D.namespaces||[]).map(n=>[n.namespace, n.count]));
const kb=document.getElementById('kanban');
kb.innerHTML = (D.kanban&&D.kanban.length)? D.kanban.map(t=>
  `<div class="row"><span>${t.title}</span><span class="pill status-${t.status}">${t.status}</span></div>`).join('')
  : '<div class="empty">no worker connected — add Hermes in step 4</div>';
const cp=D.last_checkpoint||{};
rows(document.getElementById('cont'), [
  ['open loops', (D.loops||[]).length],
  ['last checkpoint', cp.summary? (String(cp.summary).slice(0,42)) : '—']
]);
</script></body></html>"""


def build_dashboard_only(db: str) -> int:
    try:
        from .embedders import FastEmbedEmbedder
        m = Memory(db, embedder=FastEmbedEmbedder())
    except Exception:
        m = Memory(db)
    _build_dashboard(m, Continuity(memory=m), db)
    print(f"dashboard: {DASH_FILE}")
    return 0
