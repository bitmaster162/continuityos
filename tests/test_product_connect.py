from __future__ import annotations

import json
from pathlib import Path

from continuityos import connect
from continuityos import current_entrypoints


def _pass_verify(db_path: str, *, timeout: float = 5.0):
    return {
        "verified": True,
        "reason": "MCP_INITIALIZE_PASS",
        "returncode": 0,
        "response": {"jsonrpc": "2.0", "id": 1, "result": {"protocolVersion": "test"}},
        "stderr": "",
        "command": ["python", "-m", "continuityos.mcp_server", "--db", db_path],
    }


def _fail_verify(db_path: str, *, timeout: float = 5.0):
    return {
        "verified": False,
        "reason": "MCP_INITIALIZE_FAILED",
        "returncode": 1,
        "response": None,
        "stderr": "synthetic failure",
        "command": ["python", "-m", "continuityos.mcp_server", "--db", db_path],
    }


def test_dry_run_writes_nothing(tmp_path, capsys):
    config = tmp_path / "mcp.json"
    db = tmp_path / "memory.db"

    rc = connect.main(
        ["cursor", "--db", str(db), "--config", str(config), "--dry-run", "--json"]
    )

    assert rc == 0
    assert not config.exists()
    receipt = json.loads(capsys.readouterr().out)
    assert receipt["terminal"] == "COS_CONNECT_DRY_RUN_PASS"
    assert receipt["would_change"] is True
    assert receipt["patched_config"]["servers"]["continuityos"]["args"][-1] == str(db.resolve())


def test_write_preserves_unrelated_config_and_creates_backup(tmp_path, monkeypatch, capsys):
    config = tmp_path / "claude.json"
    original = {
        "theme": "dark",
        "mcpServers": {"other": {"command": "other", "args": []}},
    }
    original_bytes = (json.dumps(original, indent=2) + "\n").encode()
    config.write_bytes(original_bytes)
    db = tmp_path / "memory.db"
    state_path = tmp_path / "connect_state.json"

    monkeypatch.setattr(connect, "_verify_mcp", _pass_verify)
    monkeypatch.setattr(connect, "_state_path", lambda home=None: state_path)

    rc = connect.main(
        ["claude", "--db", str(db), "--config", str(config), "--yes", "--json"]
    )

    assert rc == 0
    receipt = json.loads(capsys.readouterr().out)
    assert receipt["terminal"] == "COS_CONNECT_PASS"
    assert receipt["verified"] is True
    written = json.loads(config.read_text(encoding="utf-8"))
    assert written["theme"] == "dark"
    assert written["mcpServers"]["other"] == original["mcpServers"]["other"]
    assert "continuityos" in written["mcpServers"]
    backup = Path(receipt["backup_path"])
    assert backup.read_bytes() == original_bytes
    assert state_path.exists()


def test_verify_failure_automatically_rolls_back(tmp_path, monkeypatch, capsys):
    config = tmp_path / "cursor.json"
    original = {"servers": {"other": {"command": "other"}}}
    original_bytes = (json.dumps(original, indent=2) + "\n").encode()
    config.write_bytes(original_bytes)
    db = tmp_path / "memory.db"
    state_path = tmp_path / "connect_state.json"

    monkeypatch.setattr(connect, "_verify_mcp", _fail_verify)
    monkeypatch.setattr(connect, "_state_path", lambda home=None: state_path)

    rc = connect.main(
        ["cursor", "--db", str(db), "--config", str(config), "--yes", "--json"]
    )

    assert rc == 3
    receipt = json.loads(capsys.readouterr().out)
    assert receipt["terminal"] == "COS_CONNECT_VERIFY_HOLD"
    assert receipt["automatic_rollback"]["terminal"] == "COS_CONNECT_ROLLBACK_PASS"
    assert config.read_bytes() == original_bytes


def test_rollback_refuses_config_drift(tmp_path, monkeypatch, capsys):
    config = tmp_path / "claude.json"
    config.write_text('{"mcpServers":{}}\n', encoding="utf-8")
    db = tmp_path / "memory.db"
    state_path = tmp_path / "connect_state.json"

    monkeypatch.setattr(connect, "_verify_mcp", _pass_verify)
    monkeypatch.setattr(connect, "_state_path", lambda home=None: state_path)

    assert connect.main(
        ["claude", "--db", str(db), "--config", str(config), "--yes", "--json"]
    ) == 0
    capsys.readouterr()

    changed = json.loads(config.read_text(encoding="utf-8"))
    changed["user_change"] = True
    config.write_text(json.dumps(changed) + "\n", encoding="utf-8")

    rc = connect.main(["claude", "--db", str(db), "--rollback", "--json"])
    assert rc == 2
    receipt = json.loads(capsys.readouterr().out)
    assert receipt["terminal"] == "COS_CONNECT_ROLLBACK_HOLD"
    assert receipt["reason"] == "CONFIG_DRIFTED_SINCE_CONNECT"
    assert json.loads(config.read_text(encoding="utf-8"))["user_change"] is True


def test_status_detects_wrong_memory_binding(tmp_path, capsys):
    config = tmp_path / "cursor.json"
    wrong = connect._server_spec(str(tmp_path / "wrong.db"))
    config.write_text(
        json.dumps({"servers": {"continuityos": wrong}}) + "\n",
        encoding="utf-8",
    )

    rc = connect.main(
        ["cursor", "--db", str(tmp_path / "right.db"), "--config", str(config), "--status", "--json"]
    )

    assert rc == 0
    receipt = json.loads(capsys.readouterr().out)
    status = receipt["clients"][0]
    assert status["configured"] is True
    assert status["connected"] is False
    assert status["drift"] is True


def test_cos_connect_routes_when_unbound(monkeypatch):
    seen = {}

    def fake_connect(argv=None):
        seen["argv"] = list(argv or [])
        return 7

    monkeypatch.setattr(connect, "main", fake_connect)
    monkeypatch.setattr(current_entrypoints, "current_binding_from_env", lambda env: (None, []))

    rc = current_entrypoints.cos_main(["connect", "claude", "--dry-run"])

    assert rc == 7
    assert seen["argv"] == ["claude", "--dry-run"]


def test_cos_connect_preserves_top_level_db(monkeypatch):
    seen = {}

    def fake_connect(argv=None):
        seen["argv"] = list(argv or [])
        return 0

    monkeypatch.setattr(connect, "main", fake_connect)
    monkeypatch.setattr(current_entrypoints, "current_binding_from_env", lambda env: (None, []))

    rc = current_entrypoints.cos_main(["--db", "custom.db", "connect", "cursor", "--dry-run"])

    assert rc == 0
    assert seen["argv"] == ["--db", "custom.db", "cursor", "--dry-run"]


def test_cos_connect_cannot_bypass_bound_current_session(monkeypatch):
    called = {"connect": False}

    def fake_connect(argv=None):
        called["connect"] = True
        return 0

    monkeypatch.setattr(connect, "main", fake_connect)
    monkeypatch.setattr(
        current_entrypoints,
        "current_binding_from_env",
        lambda env: (
            {"challenge": "x", "ack": "y", "challenge_sha256": "z"},
            [],
        ),
    )
    monkeypatch.setattr(
        current_entrypoints,
        "_verify_binding",
        lambda binding, surface, command: (
            {
                "binding_verified": True,
                "authority_generation": "R64",
                "challenge_id": "cid",
                "challenge_sha256": "sha",
            },
            None,
        ),
    )

    rc = current_entrypoints.cos_main(["connect", "claude", "--dry-run"])

    assert rc == 3
    assert called["connect"] is False
