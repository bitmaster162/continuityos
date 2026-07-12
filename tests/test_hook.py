import json, os, subprocess, sys

def _hook(payload, home):
    payload.setdefault("cwd", str(home))
    env = os.environ.copy()
    env.update({"HOME": str(home), "USERPROFILE": str(home), "PYTHONUTF8": "1"})
    p = subprocess.run([sys.executable, "-m", "continuityos.gate.claude_hook"],
                       input=json.dumps(payload), capture_output=True, text=True, env=env)
    out = json.loads(p.stdout.strip().splitlines()[-1])
    return out["hookSpecificOutput"]["permissionDecision"], p.returncode

def test_hook_blocks_rm_rf(tmp_path):
    d, code = _hook({"tool_name": "Bash", "tool_input": {"command": "rm -rf /"}}, tmp_path)
    assert d == "deny" and code == 2

def test_hook_allows_safe(tmp_path):
    d, code = _hook({"tool_name": "Bash", "tool_input": {"command": "npm test"}}, tmp_path)
    assert d == "allow" and code == 0

def test_hook_asks_force_push(tmp_path):
    d, _ = _hook({"tool_name": "Bash", "tool_input": {"command": "git push -f"}}, tmp_path)
    assert d == "ask"

def test_hook_protected_write(tmp_path):
    d, _ = _hook({"tool_name": "Write", "tool_input": {"file_path": ".env"}}, tmp_path)
    assert d == "ask"


def test_dry_run_only_is_denied_not_human_overridable():
    from continuityos.gate.claude_hook import _MAP
    assert _MAP["DRY_RUN_ONLY"] == "deny"
