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
# Tools that should be gate-checked
GATED_TOOLS = {"terminal", "execute_code"}

def _block(reason):
    print(json.dumps({
        "decision": "block",
        "reason": "ContinuityOS GATE: " + reason + " (fail-closed)",
    }))


def main():
    try:
        payload = json.load(sys.stdin)
        if not isinstance(payload, dict):
            raise TypeError("hook payload must be an object")
    except Exception as exc:
        # Can't parse → DENY (fail-closed for governance)
        _block(f"invalid hook payload: {type(exc).__name__}: {exc}")
        return

    tool = payload.get("tool_name", "")
    if not isinstance(tool, str):
        _block("tool_name must be a string")
        return
    if tool not in GATED_TOOLS:
        return  # Not a shell tool → allow
    if tool == "execute_code":
        _block("execute_code cannot be reduced to one authoritative shell action")
        return

    tool_input = payload.get("tool_input", {})
    if not isinstance(tool_input, dict):
        _block("tool_input must be an object")
        return
    command = tool_input.get("command", "")
    if not isinstance(command, str):
        _block("tool_input.command must be a string")
        return
    if not command:
        return  # Empty command → allow

    tool_workdir = tool_input.get("workdir")
    payload_cwd = payload.get("cwd")
    if tool_workdir is not None:
        if (
            not isinstance(tool_workdir, str)
            or not tool_workdir
            or not os.path.isabs(os.path.expandvars(os.path.expanduser(tool_workdir)))
        ):
            _block("tool_input.workdir must be a non-empty absolute path")
            return
        authoritative_cwd = tool_workdir
    elif payload_cwd is None:
        authoritative_cwd = ""
    elif isinstance(payload_cwd, str):
        authoritative_cwd = payload_cwd
    else:
        _block("payload cwd must be a string")
        return

    # Call ContinuityOS preflight
    try:
        result = subprocess.run(
            [GATE_PYTHON, "-m", "continuityos.gate.cli",
             "preflight", "shell", command,
             "--cwd", authoritative_cwd, "--json"],
            capture_output=True, text=True, timeout=10,
            env=dict(os.environ),
        )

        if result.returncode != 0:
            print(json.dumps({"decision": "block", "reason":
                  f"ContinuityOS GATE: preflight exited {result.returncode} (fail-closed)"}))
            return
        try:
            response = json.loads(result.stdout)
            decision = response["decision"]
            reasons = response.get("reasons") or []
        except Exception:
            print(json.dumps({"decision": "block", "reason":
                  "ContinuityOS GATE: invalid preflight response (fail-closed)"}))
            return

        if decision in {"DENY", "HOLD", "DRY_RUN_ONLY", "REQUIRE_CONFIRMATION"}:
            reason = f"ContinuityOS GATE: {decision}"
            if reasons:
                reason += ": " + "; ".join(str(item) for item in reasons[:3])
            print(json.dumps({"decision": "block", "reason": reason}))
            return
        if decision in {"ALLOW", "WARN"}:
            return
        print(json.dumps({"decision": "block", "reason":
              f"ContinuityOS GATE: unknown decision {decision!r} (fail-closed)"}))
        return

    except subprocess.TimeoutExpired:
        # Gate timeout → fail-closed (block if gate is unreachable)
        print(json.dumps({"decision": "block", "reason": "⛔ ContinuityOS GATE: preflight timeout (fail-closed)"}))
        return
    except Exception as e:
        # Any error → fail-closed
        print(json.dumps({"decision": "block", "reason": f"⛔ ContinuityOS GATE: error (fail-closed): {e}"}))
        return

if __name__ == "__main__":
    main()
