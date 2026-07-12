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
from ..db import open_existing_context, resolve_memory_db
from .spec import ActionSpec
from .engine import preflight
from .ledger import Ledger
from .policy import PolicyError, default_policy, discover_policy, load_policy

# preflight decision -> Claude Code permissionDecision
_MAP = {
    "ALLOW": "allow", "WARN": "allow",
    "REQUIRE_CONFIRMATION": "ask",
    "DRY_RUN_ONLY": "deny", "DENY": "deny", "HOLD": "deny",
}

def _extract(tool_name: str, tool_input: dict, cwd: str = ""):
    """Map a Claude Code tool call to an ActionSpec."""
    ti = tool_input or {}
    if tool_name == "Bash":
        cmd = ti.get("command", "")
        return ActionSpec(tool="shell", command=cmd, paths=_paths(cmd), agent="claude-code", cwd=cwd)
    if tool_name in ("Write", "Edit", "MultiEdit", "NotebookEdit"):
        p = ti.get("file_path") or ti.get("notebook_path") or ""
        return ActionSpec(tool="file.write", command=f"write {p}", paths=[p] if p else [], agent="claude-code", cwd=cwd)
    # unknown tool -> let ContinuityOS see it as a generic action
    return ActionSpec(tool=tool_name.lower(), command=json.dumps(ti)[:200], agent="claude-code", cwd=cwd)

def _paths(cmd: str):
    import re
    return list(dict.fromkeys(re.findall(
        r"(?:\.{0,2}/[\w./\-*]+|~[\w./\-*]*|[\w\-]+\.(?:env|pem|key|db|sqlite)|\.git[\w./\-]*)", cmd or "")))

def _context(home: str):
    """Resolve and validate the exact governance context without creating it.

    This intentionally mirrors the gate CLI's authority order and read-only
    validation.  A configured path is authoritative: if it is missing or
    invalid, the hook must report a context error instead of opening a default
    database (which would silently create a different source of truth).
    """
    try:
        resolved = resolve_memory_db(default=os.path.join(home, "memory.db"))
    except Exception as exc:
        return None, f"{type(exc).__name__}: {exc}", None
    mdb = resolved["path"]
    if not os.path.isfile(mdb):
        if resolved["configured"]:
            return (
                None,
                f"FileNotFoundError: configured memory database not found: {mdb}",
                {**resolved, "status": "missing"},
            )
        return None, None, {**resolved, "status": "absent"}
    try:
        # Open the exact artifact read-only and fingerprint that live handle.
        # mode=ro fails if the resolved path disappears and never initializes,
        # migrates, or recreates a configured authority.
        context, identity = open_existing_context(
            mdb,
            source=resolved["source"],
        )
        identity["status"] = "ready"
        return context, None, identity
    except Exception as exc:
        return (
            None,
            f"{type(exc).__name__}: {exc}",
            {**resolved, "status": "invalid"},
        )

def main():
    try:
        data = json.load(sys.stdin)
    except Exception:
        print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse",
              "permissionDecision": "deny",
              "permissionDecisionReason": "ContinuityOS: failed to parse hook payload (fail-closed)"}}))
        return 2
    tool_name = data.get("tool_name", "")
    cwd = data.get("cwd") or os.getcwd()
    spec = _extract(tool_name, data.get("tool_input", {}), cwd=cwd)
    home = os.path.expanduser("~/.continuityos")
    os.makedirs(home, exist_ok=True)
    try:
        pol = load_policy(discover_policy(home))
    except (PolicyError, OSError) as exc:
        pol = default_policy()
        spec.meta["policy_error"] = f"{type(exc).__name__}: {exc}"
    ctx, context_error, _context_identity = _context(home)
    if context_error:
        spec.meta["context_error"] = context_error
    with Ledger(os.path.join(home, "ledger.db")) as ledger:
        r = preflight(spec, policy=pol, ledger=ledger, context=ctx)
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
