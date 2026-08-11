import hashlib
import json, os, sqlite3, subprocess, sys

from continuityos import Memory
from continuityos.db import context_fingerprint

def _hook(payload, home, continuityos_db=None):
    payload.setdefault("cwd", str(home))
    env = os.environ.copy()
    env.update({"HOME": str(home), "USERPROFILE": str(home), "PYTHONUTF8": "1"})
    env.pop("CONTINUITYOS_DB", None)
    if continuityos_db is not None:
        env["CONTINUITYOS_DB"] = continuityos_db
    p = subprocess.run([sys.executable, "-m", "continuityos.gate.claude_hook"],
                       input=json.dumps(payload), capture_output=True, text=True, env=env)
    out = json.loads(p.stdout.strip().splitlines()[-1])
    hook_output = out["hookSpecificOutput"]
    return (
        hook_output["permissionDecision"],
        p.returncode,
        hook_output["permissionDecisionReason"],
    )

def test_hook_blocks_rm_rf(tmp_path):
    d, code, _ = _hook({"tool_name": "Bash", "tool_input": {"command": "rm -rf /"}}, tmp_path)
    assert d == "deny" and code == 2

def test_hook_allows_safe(tmp_path):
    d, code, _ = _hook({"tool_name": "Bash", "tool_input": {"command": "npm test"}}, tmp_path)
    assert d == "allow" and code == 0

def test_hook_asks_force_push(tmp_path):
    d, _, _ = _hook({"tool_name": "Bash", "tool_input": {"command": "git push -f"}}, tmp_path)
    assert d == "ask"

def test_hook_protected_write(tmp_path):
    d, _, _ = _hook({"tool_name": "Write", "tool_input": {"file_path": ".env"}}, tmp_path)
    assert d == "ask"


def test_hook_holds_when_configured_db_is_missing_without_fallback(tmp_path):
    configured = tmp_path / "configured" / "missing.db"
    d, code, reason = _hook(
        {"tool_name": "Bash", "tool_input": {"command": "npm test"}},
        tmp_path,
        continuityos_db=str(configured),
    )

    assert d == "deny" and code == 2
    assert "ContinuityOS [HOLD]" in reason
    assert "configured memory database not found" in reason
    assert not configured.exists()
    assert not (tmp_path / ".continuityos" / "memory.db").exists()


def test_hook_holds_when_configured_db_value_is_empty_without_fallback(tmp_path):
    d, code, reason = _hook(
        {"tool_name": "Bash", "tool_input": {"command": "npm test"}},
        tmp_path,
        continuityos_db="",
    )

    assert d == "deny" and code == 2
    assert "ContinuityOS [HOLD]" in reason
    assert "environment memory database path is empty" in reason
    assert not (tmp_path / ".continuityos" / "memory.db").exists()


def test_hook_holds_without_mutating_invalid_configured_db(tmp_path):
    configured = tmp_path / "invalid.db"
    with sqlite3.connect(configured) as con:
        con.execute("CREATE TABLE unrelated(value TEXT)")
    before = hashlib.sha256(configured.read_bytes()).hexdigest()

    d, code, reason = _hook(
        {"tool_name": "Bash", "tool_input": {"command": "npm test"}},
        tmp_path,
        continuityos_db=str(configured),
    )

    assert d == "deny" and code == 2
    assert "ContinuityOS [HOLD]" in reason
    assert "memory database has no items table" in reason
    assert hashlib.sha256(configured.read_bytes()).hexdigest() == before
    assert not (tmp_path / ".continuityos" / "memory.db").exists()


def test_hook_uses_valid_configured_db_without_creating_fallback(tmp_path):
    configured = tmp_path / "configured.db"
    memory = Memory(str(configured))
    try:
        memory.remember("Never bypass governance.", namespace="canon")
    finally:
        memory.store.con.close()

    d, code, reason = _hook(
        {"tool_name": "Bash", "tool_input": {"command": "npm test"}},
        tmp_path,
        continuityos_db=str(configured),
    )

    assert d == "allow" and code == 0
    assert "ContinuityOS [ALLOW]" in reason
    assert not (tmp_path / ".continuityos" / "memory.db").exists()


def test_hook_context_uses_authoritative_resolver_and_fingerprint(
    tmp_path, monkeypatch
):
    from continuityos.gate.claude_hook import _context

    configured = tmp_path / "authoritative.db"
    memory = Memory(str(configured))
    try:
        memory.remember("Require bound context evidence.", namespace="rules")
    finally:
        memory.store.con.close()
    expected = context_fingerprint(str(configured))
    monkeypatch.setenv("CONTINUITYOS_DB", str(configured))

    context, error, identity = _context(str(tmp_path / ".continuityos"))
    try:
        assert error is None
        assert identity["source"] == "environment"
        assert identity["status"] == "ready"
        assert identity["path"] == expected["path"]
        assert identity["path_sha256"] == expected["path_sha256"]
        assert identity["context_sha256"] == expected["context_sha256"]
        assert identity["scheme"] == expected["scheme"]
    finally:
        context.m.store.con.close()


def test_hook_context_does_not_recreate_db_removed_before_open(
    tmp_path, monkeypatch
):
    from continuityos.db import open_existing_context as real_open
    from continuityos.gate import claude_hook

    configured = tmp_path / "removed-before-open.db"
    memory = Memory(str(configured))
    try:
        memory.remember("Bind the opened artifact.", namespace="canon")
    finally:
        memory.store.con.close()
    monkeypatch.setenv("CONTINUITYOS_DB", str(configured))

    def remove_then_open(path, *, source=""):
        configured.unlink()
        return real_open(path, source=source)

    monkeypatch.setattr(claude_hook, "open_existing_context", remove_then_open)
    context, error, identity = claude_hook._context(
        str(tmp_path / ".continuityos")
    )

    assert context is None
    assert "OperationalError" in error
    assert identity["status"] == "invalid"
    assert not configured.exists()


def test_dry_run_only_is_denied_not_human_overridable():
    from continuityos.gate.claude_hook import _MAP
    assert _MAP["DRY_RUN_ONLY"] == "deny"
