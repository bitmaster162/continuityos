from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess

from continuityos import connect
from continuityos import current_entrypoints
from continuityos import status
from continuityos.continuity import Continuity
from continuityos.memory import Memory


def _ready_db(tmp_path: Path) -> Path:
    db = tmp_path / "memory.db"
    m = Memory(str(db))
    c = Continuity(memory=m)
    c.add_canon("Preserve durable continuity")
    c.set_frontier("trunk", "Productize ContinuityOS")
    c.set_frontier("cash", "Ship a usable local-first product")
    c.add_loop("Finish Productization v1")
    c.checkpoint(summary="P0 merged", next_action="Ship cos status", proof="PR #40 merged")
    m.store.con.close()
    return db


def _is_same_path(left: str, right: str | Path) -> bool:
    return os.path.normcase(os.path.realpath(left)) == os.path.normcase(os.path.realpath(str(right)))


def test_status_reads_existing_memory_without_writes(tmp_path, monkeypatch):
    db = _ready_db(tmp_path)
    claude = tmp_path / "claude.json"
    cursor = tmp_path / "cursor.json"
    monkeypatch.setenv("CONTINUITYOS_CLAUDE_CONFIG", str(claude))
    monkeypatch.setenv("CONTINUITYOS_CURSOR_CONFIG", str(cursor))
    before = db.read_bytes()

    value, code = status.collect(str(db))

    assert code == 0
    assert value["terminal"] == "COS_STATUS_PASS"
    assert value["state"] == "READY"
    assert value["memory"]["state"] == "READY"
    assert value["memory"]["count"] == 5
    assert _is_same_path(value["memory"]["path"], db)
    assert value["continuity"]["state"] == "HEALTHY"
    assert value["continuity"]["open_loop_count"] == 1
    assert value["continuity"]["next_action"] == "Ship cos status"
    assert value["continuity"]["last_checkpoint"]["proof_present"] is True
    assert value["governance"]["state"] == "ARMED"
    assert value["mcp"]["live_probe_performed"] is False
    assert value["effects"]["filesystem_write"] is False
    assert value["effects"]["memory_write"] is False
    assert value["effects"]["subprocess_execution"] is False
    assert db.read_bytes() == before
    assert not claude.exists()
    assert not cursor.exists()


def test_status_missing_db_holds_without_creating_it(tmp_path):
    db = tmp_path / "missing.db"

    value, code = status.collect(str(db))

    assert code == 2
    assert value["terminal"] == "COS_STATUS_HOLD"
    assert value["reason"] == "MEMORY_DB_NOT_FOUND"
    assert value["memory"]["state"] == "MISSING"
    assert not db.exists()


def test_status_invalid_db_holds_without_repairing_it(tmp_path):
    db = tmp_path / "invalid.db"
    db.write_bytes(b"not sqlite")
    before = db.read_bytes()

    value, code = status.collect(str(db))

    assert code == 2
    assert value["terminal"] == "COS_STATUS_HOLD"
    assert value["reason"] == "MEMORY_DB_INVALID_OR_UNREADABLE"
    assert db.read_bytes() == before


def test_status_reports_connected_clients_from_config_only(tmp_path, monkeypatch):
    db = _ready_db(tmp_path)
    claude = tmp_path / "claude.json"
    cursor = tmp_path / "cursor.json"
    monkeypatch.setenv("CONTINUITYOS_CLAUDE_CONFIG", str(claude))
    monkeypatch.setenv("CONTINUITYOS_CURSOR_CONFIG", str(cursor))
    server = connect._server(str(db))
    claude.write_text(json.dumps({"mcpServers": {"continuityos": server}}) + "\n", encoding="utf-8")

    def forbidden_subprocess(*args, **kwargs):
        raise AssertionError("cos status must not spawn an MCP process")

    monkeypatch.setattr(subprocess, "run", forbidden_subprocess)
    value, code = status.collect(str(db))

    assert code == 0
    assert value["agents"]["connected_count"] == 1
    assert value["agents"]["drifted_count"] == 0
    assert value["mcp"]["state"] == "CONFIGURED"
    clients = {item["client"]: item for item in value["agents"]["managed_clients"]}
    assert clients["claude"]["connected"] is True
    assert clients["cursor"]["configured"] is False


def test_status_surfaces_client_db_drift_as_attention(tmp_path, monkeypatch):
    db = _ready_db(tmp_path)
    claude = tmp_path / "claude.json"
    cursor = tmp_path / "cursor.json"
    monkeypatch.setenv("CONTINUITYOS_CLAUDE_CONFIG", str(claude))
    monkeypatch.setenv("CONTINUITYOS_CURSOR_CONFIG", str(cursor))
    wrong = connect._server(str(tmp_path / "wrong.db"))
    cursor.write_text(json.dumps({"mcpServers": {"continuityos": wrong}}) + "\n", encoding="utf-8")

    value, code = status.collect(str(db))

    assert code == 0
    assert value["state"] == "ATTENTION"
    assert value["agents"]["drifted_count"] == 1
    assert value["mcp"]["state"] == "DRIFT"


def test_status_human_output_contains_primary_product_signals(tmp_path, monkeypatch, capsys):
    db = _ready_db(tmp_path)
    monkeypatch.setenv("CONTINUITYOS_CLAUDE_CONFIG", str(tmp_path / "claude.json"))
    monkeypatch.setenv("CONTINUITYOS_CURSOR_CONFIG", str(tmp_path / "cursor.json"))

    rc = status.main(["--db", str(db), "--verbose"])

    assert rc == 0
    out = capsys.readouterr().out
    assert "Memory      READY" in out
    assert "Continuity  HEALTHY" in out
    assert "Open loops  1" in out
    assert "Next action Ship cos status" in out
    assert "MCP         NOT_CONNECTED" in out
    assert "Governance  ARMED" in out
    assert "Doctor" in out


def test_status_json_is_machine_readable(tmp_path, monkeypatch, capsys):
    db = _ready_db(tmp_path)
    monkeypatch.setenv("CONTINUITYOS_CLAUDE_CONFIG", str(tmp_path / "claude.json"))
    monkeypatch.setenv("CONTINUITYOS_CURSOR_CONFIG", str(tmp_path / "cursor.json"))

    rc = status.main(["--db", str(db), "--json"])

    assert rc == 0
    value = json.loads(capsys.readouterr().out)
    assert value["schema"] == "continuityos.product_status/v1"
    assert value["terminal"] == "COS_STATUS_PASS"


def test_cos_status_routes_when_unbound_and_preserves_top_level_db(monkeypatch):
    seen = {}

    def fake_status(argv=None):
        seen["argv"] = list(argv or [])
        return 7

    monkeypatch.setattr(status, "main", fake_status)
    monkeypatch.setattr(current_entrypoints, "current_binding_from_env", lambda env: (None, []))

    rc = current_entrypoints.cos_main(["--db", "custom.db", "status", "--json"])

    assert rc == 7
    assert seen["argv"] == ["--db", "custom.db", "--json"]


def test_cos_status_cannot_bypass_bound_session(monkeypatch):
    called = {"status": False}

    def fake_status(argv=None):
        called["status"] = True
        return 0

    monkeypatch.setattr(status, "main", fake_status)
    monkeypatch.setattr(
        current_entrypoints,
        "current_binding_from_env",
        lambda env: ({"challenge": "x", "ack": "y", "challenge_sha256": "z"}, []),
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

    assert current_entrypoints.cos_main(["status", "--json"]) == 3
    assert called["status"] is False
