import json, subprocess, sys

def _hook(payload):
    p = subprocess.run([sys.executable, "-m", "continuityos.gate.claude_hook"],
                       input=json.dumps(payload), capture_output=True, text=True)
    out = json.loads(p.stdout.strip().splitlines()[-1])
    return out["hookSpecificOutput"]["permissionDecision"], p.returncode

def test_hook_blocks_rm_rf():
    d, code = _hook({"tool_name": "Bash", "tool_input": {"command": "rm -rf /"}})
    assert d == "deny" and code == 2

def test_hook_allows_safe():
    d, code = _hook({"tool_name": "Bash", "tool_input": {"command": "npm test"}})
    assert d == "allow" and code == 0

def test_hook_asks_force_push():
    d, _ = _hook({"tool_name": "Bash", "tool_input": {"command": "git push -f"}})
    assert d == "ask"

def test_hook_protected_write():
    d, _ = _hook({"tool_name": "Write", "tool_input": {"file_path": ".env"}})
    assert d == "ask"
