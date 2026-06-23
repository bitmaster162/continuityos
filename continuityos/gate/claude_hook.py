"""ContinuityOS — Claude Code PreToolUse hook.

Wire ContinuityOS into a *real* coding agent. Claude Code runs this BEFORE every
tool call; we preflight Bash/file/git actions and allow / ask / deny — with the
decision fed straight back to the agent, plus an append-only audit record.

Install (.claude/settings.json):
{
  "hooks": {
    "PreToolUse": [
      { "matcher": "Bash",
        "hooks": [ { "type": "command",
                     "command": "python -m continuityos.gate.claude_hook" } ] }
    ]
  }
}

Protocol: reads the hook JSON on stdin (tool_name, tool_input.command), prints a
PreToolUse permission decision on stdout. deny blocks the call; ask prompts the
user; allow proceeds. Also exits 2 on hard-deny as a belt-and-suspenders block.
"""
from __future__ import annotations
import sys, json, os
from .spec import ActionSpec
from .engine import preflight
from .ledger import Ledger
from .policy import load_policy

# preflight decision -> Claude Code permissionDecision
_MAP = {
    "ALLOW": "allow", "WARN": "allow",
    "REQUIRE_CONFIRMATION": "ask", "DRY_RUN_ONLY": "ask",
    "DENY": "deny", "HOLD": "deny",
}

def _extract(tool_name: str, tool_input: dict):
    """Map a Claude Code tool call to an ActionSpec."""
    ti = tool_input or {}
    if tool_name == "Bash":
        cmd = ti.get("command", "")
        return ActionSpec(tool="shell", command=cmd, paths=_paths(cmd), agent="claude-code")
    if tool_name in ("Write", "Edit", "MultiEdit", "NotebookEdit"):
        p = ti.get("file_path") or ti.get("notebook_path") or ""
        return ActionSpec(tool="file.write", command=f"write {p}", paths=[p] if p else [], agent="claude-code")
    # unknown tool -> let ContinuityOS see it as a generic action
    return ActionSpec(tool=tool_name.lower(), command=json.dumps(ti)[:200], agent="claude-code")

def _paths(cmd: str):
    import re
    return list(dict.fromkeys(re.findall(
        r"(?:\.{0,2}/[\w./\-*]+|~[\w./\-*]*|[\w\-]+\.(?:env|pem|key|db|sqlite)|\.git[\w./\-]*)", cmd or "")))

def main():
    try:
        data = json.load(sys.stdin)
    except Exception:
        print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse",
              "permissionDecision": "allow"}})); return 0
    tool_name = data.get("tool_name", "")
    spec = _extract(tool_name, data.get("tool_input", {}))
    home = os.path.expanduser("~/.continuityos")
    os.makedirs(home, exist_ok=True)
    pol_path = os.path.join(home, "policy.yaml")
    pol = load_policy(pol_path if os.path.exists(pol_path) else "")
    ctx = None
    try:
        from ..continuity import Continuity
        ctx = Continuity(db=os.path.join(home, "memory.db"))
    except Exception:
        pass
    r = preflight(spec, policy=pol, ledger=Ledger(os.path.join(home, "ledger.db")), context=ctx)
    decision = r["decision"]
    perm = _MAP.get(decision, "ask")
    reason = f"ContinuityOS [{decision}]: " + "; ".join(r["reasons"][:3])
    out = {"hookSpecificOutput": {"hookEventName": "PreToolUse",
           "permissionDecision": perm, "permissionDecisionReason": reason}}
    print(json.dumps(out))
    if perm == "deny":
        sys.stderr.write(reason + "\n")
        return 2   # hard block
    return 0

if __name__ == "__main__":
    sys.exit(main())
