"""R13 product MCP -> GateBroker integration and stdio framing tests."""
from __future__ import annotations

import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor

import pytest

from continuityos.gate.ledger import Ledger
from continuityos.mcp_server import Server, TOOLS
from continuityos.memory import Memory


ROOT = Path(__file__).resolve().parents[1]


def _memory(path):
    memory = Memory(str(path))
    memory.store.con.close()


def _policy(path, decision="ALLOW"):
    body = {
        "default_decision": decision,
        "protected_path_decision": decision,
        "missing_paths_decision": decision,
        "severity_decision": {
            "critical": decision,
            "high": decision,
            "medium": decision,
            "low": decision,
        },
    }
    path.write_text(json.dumps(body), encoding="utf-8")


class MCP:
    def __init__(self, home, db, policy, extra_env=None):
        env = os.environ.copy()
        env.update({
            "HOME": str(home),
            "USERPROFILE": str(home),
            "CONTINUITYOS_SILENCE_EMBED_WARN": "1",
            "PYTHONPATH": str(ROOT) + os.pathsep + env.get("PYTHONPATH", ""),
        })
        env.update(extra_env or {})
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "continuityos.mcp_server", "--db", str(db),
             "--policy", str(policy)],
            cwd=str(ROOT), env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, encoding="utf-8", errors="replace",
            bufsize=1,
        )
        self.next_id = 1
        initialized = self.rpc("initialize", {})
        assert "result" in initialized, initialized

    def rpc(self, method, params):
        request_id = self.next_id
        self.next_id += 1
        request = {
            "jsonrpc": "2.0", "id": request_id,
            "method": method, "params": params,
        }
        self.proc.stdin.write(json.dumps(request) + "\n")
        self.proc.stdin.flush()
        line = self.proc.stdout.readline()
        assert line, self.proc.stderr.read()
        response = json.loads(line)
        assert response["id"] == request_id
        return response

    def call(self, name, arguments):
        response = self.rpc("tools/call", {"name": name, "arguments": arguments})
        result = response["result"]
        text = result["content"][0]["text"]
        return result, json.loads(text) if not result.get("isError") else text

    def close(self):
        if self.proc.poll() is None:
            self.proc.stdin.close()
            self.proc.wait(timeout=20)
        stderr = self.proc.stderr.read()
        assert self.proc.returncode == 0, stderr


@pytest.fixture
def product(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    db = tmp_path / "memory.db"
    policy = tmp_path / "policy.json"
    _memory(db)
    _policy(policy)
    clients = []

    def start(extra_env=None):
        client = MCP(home, db, policy, extra_env)
        clients.append(client)
        return client

    yield start, home, db, policy
    for client in clients:
        client.close()


def test_tools_are_additive_bounded_and_have_no_self_approval_surface():
    by_name = {tool["name"]: tool for tool in TOOLS}
    assert len(by_name) == len(TOOLS)
    assert "preflight_action" in by_name
    assert {"preflight_exec", "execute_preflight"} <= set(by_name)
    assert not any(
        token in name
        for name in by_name
        for token in ("approve", "confirm", "override", "human_override")
    )
    preflight = by_name["preflight_exec"]["inputSchema"]
    execute = by_name["execute_preflight"]["inputSchema"]
    assert preflight["additionalProperties"] is False
    assert preflight["properties"]["request_id"]["maxLength"] == 256
    assert preflight["properties"]["argv"]["minItems"] == 1
    assert preflight["properties"]["argv"]["maxItems"] < 1000
    assert execute == {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "request_id": {"type": "string", "minLength": 1, "maxLength": 256}
        },
        "required": ["request_id"],
    }


def test_server_owns_exact_db_policy_snapshot_and_runtime_rejects_extras(
    tmp_path, monkeypatch
):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    db = tmp_path / "memory.db"
    policy_path = tmp_path / "policy.json"
    _memory(db)
    _policy(policy_path)
    server = Server(str(db), str(policy_path))
    broker = server._gate_broker()
    assert broker.db == server.db_path == os.path.normcase(os.path.realpath(db))
    assert broker._policy_snapshot is server.policy

    class MustNotRun:
        def execute_preflight(self, request_id):
            raise AssertionError("broker called after unexpected execution arguments")

    server._broker = MustNotRun()
    with pytest.raises(ValueError, match="unexpected arguments"):
        server.call("execute_preflight", {"request_id": "x", "argv": ["replacement"]})


def test_actual_jsonrpc_once_retry_restart_policy_snapshot_env_and_bounding(product):
    start, _home, _db, policy = product
    effect_dir = policy.parent / "effect"
    effect_dir.mkdir()
    script = effect_dir / "effect.py"
    script.write_text(
        "import os, pathlib, sys\n"
        "p=pathlib.Path('effect.txt')\n"
        "p.write_text((p.read_text() if p.exists() else '')+'x')\n"
        "sys.stdout.buffer.write(b'\\xff'+b'o'*70000)\n"
        "sys.stderr.buffer.write(b'secret:'+os.environ.get('R13_SECRET','absent').encode()+b'\\xff')\n",
        encoding="utf-8",
    )
    client = start({"R13_SECRET": "must-not-leak"})
    listed = client.rpc("tools/list", {})
    names = [tool["name"] for tool in listed["result"]["tools"]]
    assert names.count("preflight_exec") == names.count("execute_preflight") == 1

    # The server has loaded ALLOW. Replacing the file must not split advisory
    # and broker policy authority during this process lifetime.
    _policy(policy, "DENY")
    advisory_result, advisory = client.call("preflight_action", {
        "tool": "exec", "command": "benign", "args": ["benign"],
        "paths": [], "cwd": str(effect_dir),
    })
    assert not advisory_result.get("isError")
    assert advisory["decision"] == "ALLOW"

    argv = [sys.executable, str(script)]
    _, preflight = client.call("preflight_exec", {
        "request_id": "bounded-once", "argv": argv,
        "cwd": str(effect_dir), "paths": [],
    })
    assert preflight["decision"] == "ALLOW"
    _, first = client.call("execute_preflight", {"request_id": "bounded-once"})
    assert first["state"] == "TERMINAL"
    assert first["cached"] is False
    assert first["stdout_truncated"] is True
    assert first["stdout_bytes"] > 64 * 1024
    assert "�" in first["stdout"]
    assert "secret:absent" in first["stderr"]
    assert len(json.dumps(first).encode("utf-8")) < 2 * 1024 * 1024
    assert (effect_dir / "effect.txt").read_text() == "x"

    _, retry = client.call("execute_preflight", {"request_id": "bounded-once"})
    assert retry["state"] == "CACHED"
    _, conflict = client.call("preflight_exec", {
        "request_id": "bounded-once", "argv": argv + ["changed"],
        "cwd": str(effect_dir), "paths": [],
    })
    assert conflict["state"] == "HELD"
    assert (effect_dir / "effect.txt").read_text() == "x"
    client.close()

    restarted = start()
    _, cached = restarted.call("execute_preflight", {"request_id": "bounded-once"})
    assert cached["state"] == "CACHED"
    assert (effect_dir / "effect.txt").read_text() == "x"


def test_actual_jsonrpc_execute_extras_fail_before_broker(product):
    start, _home, _db, _policy_path = product
    client = start()
    result, text = client.call("execute_preflight", {
        "request_id": "x", "cwd": str(ROOT), "policy": {},
    })
    assert result["isError"] is True
    assert "unexpected arguments" in text


def test_configured_missing_at_start_stays_held_when_memory_is_created(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    missing = tmp_path / "configured-missing.db"
    policy = tmp_path / "policy.json"
    _policy(policy)
    client = MCP(home, missing, policy)
    try:
        assert missing.exists()  # Memory compatibility initialized it.
        _, preflight = client.call("preflight_exec", {
            "request_id": "missing", "argv": [sys.executable, "-c", "print(1)"],
            "cwd": str(tmp_path), "paths": [],
        })
        assert preflight["decision"] == "HOLD"
        _, execution = client.call("execute_preflight", {"request_id": "missing"})
        assert execution["state"] == "HELD"
    finally:
        client.close()


def test_distinct_product_processes_have_one_owner_and_one_effect(product):
    start, _home, _db, _policy_path = product
    effect_dir = _policy_path.parent / "race"
    effect_dir.mkdir()
    script = effect_dir / "slow.py"
    script.write_text(
        "import pathlib,time\ntime.sleep(.3)\n"
        "p=pathlib.Path('effect.txt')\n"
        "p.write_text((p.read_text() if p.exists() else '')+'x')\n",
        encoding="utf-8",
    )
    owner = start()
    _, preflight = owner.call("preflight_exec", {
        "request_id": "process-race", "argv": [sys.executable, str(script)],
        "cwd": str(effect_dir), "paths": [],
    })
    assert preflight["decision"] == "ALLOW"
    contender = start()
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [
            pool.submit(client.call, "execute_preflight", {"request_id": "process-race"})
            for client in (owner, contender)
        ]
        results = [future.result()[1] for future in futures]
    owners = [
        result for result in results
        if result["state"] == "TERMINAL" and result.get("cached") is False
    ]
    assert len(owners) == 1
    assert all(result["state"] in ("TERMINAL", "CACHED", "HELD") for result in results)
    assert (effect_dir / "effect.txt").read_text() == "x"


def test_product_path_tamper_and_orphan_claim_fail_closed(product):
    start, home, _db, _policy_path = product
    effect_dir = _policy_path.parent / "held"
    effect_dir.mkdir()
    script = effect_dir / "effect.py"
    script.write_text("from pathlib import Path\nPath('effect.txt').write_text('x')\n")
    client = start()
    argv = [sys.executable, str(script)]

    _, tamper = client.call("preflight_exec", {
        "request_id": "tamper", "argv": argv, "cwd": str(effect_dir), "paths": [],
    })
    ledger_path = home / ".continuityos" / "ledger.db"
    with sqlite3.connect(ledger_path) as con:
        row = con.execute(
            "SELECT payload FROM events WHERE hash=?", (tamper["preflight_hash"],)
        ).fetchone()
        payload = json.loads(row[0])
        payload["action"]["cwd"] = str(effect_dir / "other")
        con.execute(
            "UPDATE events SET payload=? WHERE hash=?",
            (json.dumps(payload), tamper["preflight_hash"]),
        )
        con.commit()
    _, held = client.call("execute_preflight", {"request_id": "tamper"})
    assert held["state"] == "HELD"
    assert not (effect_dir / "effect.txt").exists()

    # Use a fresh product home because the deliberately corrupted ledger must
    # remain fail-closed rather than being repaired in-place.
    client.close()
    home2 = _policy_path.parent / "home2"
    home2.mkdir()
    client2 = MCP(home2, _db, _policy_path)
    try:
        _, orphan = client2.call("preflight_exec", {
            "request_id": "orphan", "argv": argv,
            "cwd": str(effect_dir), "paths": [],
        })
        with Ledger(str(home2 / ".continuityos" / "ledger.db")) as ledger:
            ledger.append("attempt_claimed", {
                "preflight_hash": orphan["preflight_hash"],
                "binding_sha256": "1" * 64,
                "phase": "CLAIMED",
            })
        _, held = client2.call("execute_preflight", {"request_id": "orphan"})
        assert held["state"] == "HELD"
        assert not (effect_dir / "effect.txt").exists()
    finally:
        client2.close()


def test_require_confirmation_has_no_mcp_minting_path(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    db = tmp_path / "memory.db"
    policy = tmp_path / "confirmation.json"
    _memory(db)
    _policy(policy, "REQUIRE_CONFIRMATION")
    effect = tmp_path / "effect.py"
    effect.write_text("from pathlib import Path\nPath('effect.txt').write_text('x')\n")
    client = MCP(home, db, policy)
    try:
        _, preflight = client.call("preflight_exec", {
            "request_id": "confirmation", "argv": [sys.executable, str(effect)],
            "cwd": str(tmp_path), "paths": [],
        })
        assert preflight["decision"] == "REQUIRE_CONFIRMATION"
        _, execution = client.call("execute_preflight", {"request_id": "confirmation"})
        assert execution["state"] == "HELD"
        assert not (tmp_path / "effect.txt").exists()
    finally:
        client.close()
