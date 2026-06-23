"""continuity — AI Agent Governance Gateway CLI.

  continuity init                         # create ledger + default policy
  continuity preflight shell "<cmd>"      # decide without running
  continuity run shell -- <cmd...>        # HARD mediation: preflight then run/refuse
  continuity audit                        # show + verify the audit ledger
"""
from __future__ import annotations
import argparse, os, sys, subprocess, shlex, re
from .spec import ActionSpec
from .engine import preflight
from .ledger import Ledger
from .policy import load_policy

HOME = os.path.expanduser("~/.continuityos")
LEDGER = os.path.join(HOME, "ledger.db")
POLICY = os.path.join(HOME, "policy.yaml")

def _paths_from(cmd: str):
    # heuristic: pull file-ish tokens (paths, dotfiles) from a command
    toks = re.findall(r"(?:\.{0,2}/[\w./\-*]+|~[\w./\-*]*|[\w\-]+\.(?:env|pem|key|db|sqlite|git)|\.git[\w./\-]*)", cmd)
    return list(dict.fromkeys(toks))

def _context():
    # canon-aware decisions: use the local continuity memory if present
    try:
        from ..continuity import Continuity
        mdb = os.path.join(HOME, "memory.db")
        return Continuity(db=mdb) if os.path.exists(mdb) or True else None
    except Exception:
        return None

def _decide(cmd: str, tool="shell", agent="cli"):
    led = Ledger(LEDGER)
    pol = load_policy(POLICY if os.path.exists(POLICY) else "")
    spec = ActionSpec(tool=tool, command=cmd, paths=_paths_from(cmd), agent=agent, cwd=os.getcwd())
    return preflight(spec, policy=pol, ledger=led, context=_context()), spec

def main(argv=None):
    ap = argparse.ArgumentParser(prog="continuity", description="AI Agent Governance Gateway")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("init")
    pf = sub.add_parser("preflight"); pf.add_argument("tool"); pf.add_argument("command")
    rn = sub.add_parser("run"); rn.add_argument("tool"); rn.add_argument("rest", nargs=argparse.REMAINDER)
    au = sub.add_parser("audit"); au.add_argument("-n", type=int, default=20)
    rb = sub.add_parser("rollback"); rb.add_argument("snapshot_id")
    a = ap.parse_args(argv)

    if a.cmd == "init":
        os.makedirs(HOME, exist_ok=True); Ledger(LEDGER)
        if not os.path.exists(POLICY):
            from .policy import DEFAULT_POLICY
            try:
                import yaml; open(POLICY, "w").write(yaml.safe_dump(DEFAULT_POLICY, allow_unicode=True))
            except ImportError:
                import json; open(POLICY.replace(".yaml", ".json"), "w").write(json.dumps(DEFAULT_POLICY, indent=2))
        print(f"initialized: {LEDGER}\npolicy: {POLICY} (edit to customize)")
        return 0

    if a.cmd == "preflight":
        r, _ = _decide(a.command, tool=a.tool, agent="cli-preflight")
        _print(r); return 0

    if a.cmd == "rollback":
        from .rollback import restore
        r = restore(a.snapshot_id); print(r); return 0 if r.get("ok") else 1

    if a.cmd == "audit":
        led = Ledger(LEDGER)
        for e in reversed(led.export(a.n)):
            p = e["payload"]
            print(f"  {e['hash']} [{p.get('decision','?'):20}] {p.get('command','')[:50]}")
        v = led.verify()
        print(("\n✓ ledger intact, %d events" % v["verified"]) if v["ok"] else ("\n✗ TAMPERED at #%s" % v.get("broken_at")))
        return 0

    if a.cmd == "run":
        rest = a.rest
        if rest and rest[0] == "--": rest = rest[1:]
        cmd = " ".join(rest)
        if not cmd:
            print("usage: continuity run shell -- <command>"); return 2
        r, spec = _decide(cmd, tool=a.tool, agent="cli-run")
        _print(r)
        d = r["decision"]
        if d == "ALLOW":
            return subprocess.call(cmd, shell=True)
        if d == "DRY_RUN_ONLY":
            print("\n⟂ DRY-RUN: command NOT executed (protected). Re-run with explicit approval if intended.")
            return 0
        if d in ("DENY", "HOLD"):
            print(f"\n⛔ BLOCKED ({d}). Command was NOT executed. ContinuityOS prevented this action.")
            return 1
        if d == "WARN":
            print("\n⚠ WARN — proceeding (logged). Review the reasons above.")
            return subprocess.call(cmd, shell=True)
        if d == "REQUIRE_CONFIRMATION":
            if not sys.stdin.isatty():
                print("\n⛔ HELD (REQUIRE_CONFIRMATION, non-interactive). NOT executed."); return 1
            ans = input("\nRequires confirmation. Execute anyway? [y/N] ").strip().lower()
            if ans == "y":
                Ledger(LEDGER).append("override", {"command": cmd, "by": "human"})
                return subprocess.call(cmd, shell=True)
            print("aborted by user."); return 1
    return 0

def _print(r):
    print(f"decision: {r['decision']}" + (f"  (severity: {r['severity']})" if r.get('severity') else ""))
    for rs in r["reasons"]: print("  -", rs)
    if r.get("ledger_hash"): print("  ledger:", r["ledger_hash"][:12])

if __name__ == "__main__":
    sys.exit(main())
