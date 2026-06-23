# Integrate ContinuityOS into a real coding agent

ContinuityOS becomes useful the moment it's in the **mandatory execution path** of an agent.
Here's how to put the gate in front of Claude Code (and the pattern for Cursor / Codex CLI).

## Claude Code (PreToolUse hook)

1. Install: `pip install continuityos`, then `continuity init` (creates `~/.continuityos/ledger.db` + policy).
2. Add the hook to `.claude/settings.json` (project) or `~/.claude/settings.json` (global):

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash|Write|Edit|MultiEdit",
        "hooks": [
          { "type": "command", "command": "python -m continuityos.gate.claude_hook" }
        ]
      }
    ]
  }
}
```

That's it. Before Claude Code runs any Bash/file action, ContinuityOS preflights it and returns
a decision the agent must honor:

| ContinuityOS decision | Claude Code result | Meaning |
|---|---|---|
| ALLOW / WARN | `allow` | runs (WARN is logged) |
| REQUIRE_CONFIRMATION / DRY_RUN_ONLY | `ask` | user is prompted |
| DENY / HOLD | `deny` (exit 2) | **blocked — the agent cannot run it** |

Every decision is appended to a tamper-evident hash-chain ledger (`continuity audit` to view/verify).

## What it catches (ContinuityBench v0: 100% on 30 cases, 0 false positives)

Blocks outright: `rm -rf /`, `rm -rf ~`, `dd of=/dev/sda`, `mkfs`, fork bombs.
Asks first: `git push --force`, `git reset --hard`, `git clean -fdx`, `cat .env`, reading SSH keys,
`curl … | bash`, `chmod 777`, `sudo`, clearing shell history, deleting `.git/` files or databases.
Lets through: `npm test`, `git status`, `git commit`, `pytest`, builds, reads of normal files.

## Try it now (60-second demo)

```bash
bash demo/killer_demo.sh
```
Shows the catastrophic delete being blocked both via `continuity run` and via the Claude Code
hook payload, a safe command passing, and the audit trail.

## Cursor / Codex CLI / others

Same engine, different entry point. Any agent that exposes a pre-execution hook or an MCP tool
gate can call:
- **MCP:** the `continuityos` MCP server exposes `preflight_action` — point the agent's MCP client
  at it and have it preflight before tool use.
- **Wrapper:** run commands through `continuity run shell -- <cmd>` instead of raw shell.

## Customize the policy

Edit `~/.continuityos/policy.yaml` (needs `pip install pyyaml`): add protected paths, change
severity→decision mapping, restrict allowed tools. Defaults are sensible and ship in-code.

## Honest limits (v0.1)

Pattern-based classifier (transparent, auditable — not an LLM). Rollback covers local file
snapshots only; it **cannot** undo irreversible external side effects (network, prod, external
APIs). This is a hard boundary for coding agents, not an enterprise compliance suite.
