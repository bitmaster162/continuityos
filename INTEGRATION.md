# Integrate ContinuityOS into a real coding agent

ContinuityOS enforces decisions only after it is placed in a host's execution path.
The Claude Code hook below is one supported path; other hosts remain advisory until their own
pre-execution adapter is installed and verified.

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

For tool names matched by this hook, Claude Code invokes ContinuityOS before execution and consumes
the returned host permission decision:

| ContinuityOS decision | Claude Code result | Meaning |
|---|---|---|
| ALLOW / WARN | `allow` | runs (WARN is logged) |
| REQUIRE_CONFIRMATION | `ask` | user is prompted |
| DRY_RUN_ONLY / DENY / HOLD | `deny` (exit 2) | **blocked — the agent cannot run it** |

Every matched hook decision is appended to a tamper-evident hash-chain ledger
(`continuity audit` to view/verify).

Repository tests exercise the documented hook JSON protocol, not a live Claude Code installation.
Verify the hook in the actual host and retain that receipt before treating it as an operational
boundary.

## What the narrow regression corpus currently covers

ContinuityBench v0 is 30 hand-labeled examples plus eight obfuscated cases. It is run in CI and is
documented in [BUILD_GATE_STATUS.md](BUILD_GATE_STATUS.md); it is not proof that raw tools cannot
bypass the hook. The current default blocks outright: `rm -rf /`, `rm -rf ~`, `dd of=/dev/sda`,
`mkfs`, and fork bombs. It asks first for `git push --force`, `git reset --hard`, `git clean -fdx`, `cat .env`, reading SSH keys,
`curl … | bash`, `chmod 777`, `sudo`, and clearing shell history. Protected deletes such as
database or `.git/` removal are `DRY_RUN_ONLY` and cannot be authorized by an ordinary prompt.
Lets through: `npm test`, `git status`, `git commit`, `pytest`, builds, reads of normal files.

## Try it now (60-second demo)

```bash
bash demo/killer_demo.sh
```
Shows the catastrophic delete being blocked both via `continuity run` and via the Claude Code
hook payload, a safe command passing, and the audit trail.

## Cursor / Codex CLI / others

Same engine, different entry point. A host with a real pre-execution hook can enforce the result;
an MCP tool call alone remains advisory:
- **MCP:** the `continuityos` MCP server exposes `preflight_action`. This returns a decision but
  does not intercept the client's other tools.
- **Wrapper:** run commands through `continuity run shell -- <cmd>` instead of raw shell.

## Customize the policy

`continuity init` writes the zero-dependency `~/.continuityos/policy.json`. YAML is also accepted
when PyYAML is installed. Keep exactly one policy file; malformed or ambiguous configuration holds
execution instead of silently loading permissive defaults.

## Honest limits (v0.1)

The classifier is pattern-based (transparent, auditable — not an LLM). It does not close the
decision-to-execution TOCTOU gap or understand arbitrary script behavior. The controlled CLI can
snapshot supported explicit local file targets; it **cannot** undo directories, symlinks, remote
side effects, or execution paths that were not wired through it. This is not an enterprise
compliance suite or a universal agent boundary.
