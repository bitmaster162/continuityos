from __future__ import annotations

import json
import os
from pathlib import Path

from continuityos import current_entrypoints
from continuityos import demo


def _controlled_root(tmp_path: Path, monkeypatch) -> Path:
    root = tmp_path / "ephemeral-demo-root"

    def fake_mkdtemp(*args, **kwargs):
        root.mkdir(parents=True, exist_ok=False)
        return str(root)

    monkeypatch.setattr(demo.tempfile, "mkdtemp", fake_mkdtemp)
    return root


def test_continuity_demo_recovers_in_fresh_process_and_cleans(tmp_path, monkeypatch):
    user_db = tmp_path / "user-memory.db"
    user_db.write_bytes(b"user-memory-sentinel")
    monkeypatch.setenv("CONTINUITYOS_DB", str(user_db))
    before = user_db.read_bytes()
    root = _controlled_root(tmp_path, monkeypatch)

    value, code = demo.run_continuity(timeout=30.0)

    assert code == 0
    assert value["terminal"] == "COS_DEMO_CONTINUITY_PASS"
    assert value["reason"] == "DURABLE_STATE_RECOVERED_ACROSS_FRESH_PROCESS"
    assert value["session_boundary"] == "separate_python_process"
    assert value["recovered"]["process_id"] != os.getpid()
    assert value["recovered"]["passed"] == value["recovered"]["total"]
    assert value["recovered"]["doctor"]["healthy"] is True
    assert all(value["recovered"]["checks"].values())
    assert value["temporary_path_removed"] is True
    assert value["effects"]["temporary_cleanup_pass"] is True
    assert value["effects"]["ephemeral_filesystem_write"] is True
    assert value["effects"]["ephemeral_memory_write"] is True
    assert value["effects"]["user_memory_read"] is False
    assert value["effects"]["user_memory_write"] is False
    assert value["effects"]["network_effect"] is False
    assert value["effects"]["external_model_call"] is False
    assert value["effects"]["subprocess_execution"] is True
    assert not root.exists()
    assert user_db.read_bytes() == before


def test_continuity_demo_json_is_machine_readable(tmp_path, monkeypatch, capsys):
    _controlled_root(tmp_path, monkeypatch)

    rc = demo.main(["continuity", "--json", "--timeout", "30"])

    assert rc == 0
    value = json.loads(capsys.readouterr().out)
    assert value["schema"] == "continuityos.product_demo_continuity/v1"
    assert value["terminal"] == "COS_DEMO_CONTINUITY_PASS"
    assert value["recovered"]["checks"]["next_action_recovered"] is True
    assert value["temporary_path_removed"] is True


def test_probe_fails_closed_on_wrong_marker(tmp_path):
    db = tmp_path / "demo.db"
    demo._write_demo_state(db, "correct-marker")

    value, code = demo._probe(str(db), "wrong-marker")

    assert code == 2
    assert value["terminal"] == "COS_DEMO_CONTINUITY_PROBE_FAIL"
    assert value["reason"] == "RECOVERY_MISMATCH"
    assert value["checks"]["fact_recovered"] is False


def test_demo_subprocess_failure_still_cleans_temp_dir(tmp_path, monkeypatch):
    root = _controlled_root(tmp_path, monkeypatch)
    monkeypatch.setattr(
        demo,
        "_probe_process",
        lambda *args, **kwargs: {"ok": False, "started": False, "reason": "TEST_PROBE_FAILURE"},
    )

    value, code = demo.run_continuity()

    assert code == 2
    assert value["terminal"] == "COS_DEMO_CONTINUITY_HOLD"
    assert value["reason"] == "FRESH_PROCESS_RECOVERY_FAILED"
    assert value["temporary_path_removed"] is True
    assert value["effects"]["ephemeral_filesystem_write"] is True
    assert value["effects"]["ephemeral_memory_write"] is True
    assert value["effects"]["subprocess_execution"] is False
    assert not root.exists()


def test_demo_rejects_user_db_argument_before_ephemeral_write(tmp_path, monkeypatch, capsys):
    user_db = tmp_path / "user.db"
    user_db.write_bytes(b"sentinel")
    before = user_db.read_bytes()

    def forbidden_run(*args, **kwargs):
        raise AssertionError("demo must reject --db before creating temporary state")

    monkeypatch.setattr(demo, "run_continuity", forbidden_run)
    monkeypatch.setattr(current_entrypoints, "current_binding_from_env", lambda env: (None, []))

    rc = current_entrypoints.cos_main(["--db", str(user_db), "demo", "continuity", "--json"])

    assert rc == 2
    value = json.loads(capsys.readouterr().out)
    assert value["terminal"] == "COS_DEMO_CONTINUITY_HOLD"
    assert value["reason"] == "USER_DB_ARGUMENT_NOT_ALLOWED"
    assert value["effects"]["ephemeral_filesystem_write"] is False
    assert value["effects"]["ephemeral_memory_write"] is False
    assert value["effects"]["subprocess_execution"] is False
    assert value["effects"]["user_memory_read"] is False
    assert value["effects"]["user_memory_write"] is False
    assert user_db.read_bytes() == before


def test_cos_demo_routes_unbound(monkeypatch):
    seen = {}

    def fake_demo(argv=None):
        seen["argv"] = list(argv or [])
        return 7

    monkeypatch.setattr(demo, "main", fake_demo)
    monkeypatch.setattr(current_entrypoints, "current_binding_from_env", lambda env: (None, []))

    rc = current_entrypoints.cos_main(["demo", "continuity", "--json"])

    assert rc == 7
    assert seen["argv"] == ["continuity", "--json"]


def test_cos_demo_cannot_bypass_bound_r64_session(monkeypatch):
    called = {"demo": False}

    def fake_demo(argv=None):
        called["demo"] = True
        return 0

    monkeypatch.setattr(demo, "main", fake_demo)
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

    assert current_entrypoints.cos_main(["demo", "continuity", "--json"]) == 3
    assert called["demo"] is False


def test_product_arg_routing_preserves_existing_connect_and_status_helpers():
    assert current_entrypoints._connect_args(["connect", "claude", "--dry-run"]) == ["claude", "--dry-run"]
    assert current_entrypoints._status_args(["status", "--json"]) == ["--json"]
    assert current_entrypoints._demo_args(["demo", "continuity", "--json"]) == ["continuity", "--json"]
