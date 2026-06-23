#!/usr/bin/env python3
"""Hermes shell hook → ContinuityOS Gate bridge.

This script is called by Hermes BEFORE every terminal/file tool execution.
It sends the command to ContinuityOS preflight and returns ALLOW/BLOCK.

Wire format (stdin from Hermes):
{
    "hook_event_name": "pre_tool_call",
    "tool_name": "terminal",
    "tool_input": {"command": "rm -rf /"},
    ...
}

Output (stdout to Hermes):
    {"decision": "block", "reason": "DENY: rm -rf on critical path"}
    or empty = allow
"""
import sys
import json
import subprocess
import os

GATE_PYTHON = os.environ.get(
    "CONTINUITYOS_PYTHON",
    r"C:\PROJECTS\continuityos\.venv\Scripts\python.exe"
)
GATE_DB = os.environ.get(
    "CONTINUITYOS_DB",
    r"C:\PROJECTS\continuityos\hermes_memory.db"
)

# Tools that should be gate-checked
GATED_TOOLS = {"terminal", "execute_code"}

def main():
    try:
        payload = json.load(sys.stdin)
    except Exception:
        # Can't parse → allow (don't block on parse errors)
        return

    tool = payload.get("tool_name", "")
    if tool not in GATED_TOOLS:
        return  # Not a shell tool → allow

    tool_input = payload.get("tool_input", {})
    command = tool_input.get("command", "")
    if not command:
        return  # Empty command → allow

    # Call ContinuityOS preflight
    try:
        result = subprocess.run(
            [GATE_PYTHON, "-m", "continuityos.gate.cli",
             "preflight", "shell", command],
            capture_output=True, text=True, timeout=10,
            env={**os.environ, "CONTINUITYOS_DB": GATE_DB}
        )

        output = result.stdout.strip()

        # Parse decision from CLI output
        if "decision: DENY" in output:
            reason = "⛔ ContinuityOS GATE: DENY"
            for line in output.split("\n"):
                if line.strip().startswith("- "):
                    reason += f"\n{line.strip()}"
            print(json.dumps({"decision": "block", "reason": reason}))
        elif "decision: HOLD" in output:
            reason = "⏸️ ContinuityOS GATE: HOLD for review"
            print(json.dumps({"decision": "block", "reason": reason}))
        elif "decision: REQUIRE_CONFIRMATION" in output:
            # Let Hermes handle the confirmation via its own approval system
            # Don't block — just let it through, Hermes approvals will catch it
            return
        else:
            # ALLOW or WARN → let it through
            return

    except subprocess.TimeoutExpired:
        # Gate timeout → fail open (don't block everything if gate is slow)
        return
    except Exception:
        # Any error → fail open
        return

if __name__ == "__main__":
    main()
