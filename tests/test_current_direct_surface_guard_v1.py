from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys

import pytest

import continuityos.current_effect_boundary as boundary
from continuityos.operational_memory import OperationalMemory
from continuityos.gate.engine import preflight as direct_engine_preflight
from continuityos.gate.ledger import Ledger as DirectLedger
from continuityos.gate.spec import ActionSpec
import continuityos.mcp_server as mcp_server


def clear_binding(monkeypatch):
    for name in (
        boundary.ENV_CHALLENGE,
        boundary.ENV_CHALLENGE_SHA,
        boundary.ENV_ACK,
        boundary.ENV_REQUIRED,
    ):
        monkeypatch.delenv(name, raising=False)


def set_current(monkeypatch):
    monkeypatch.setenv(boundary.ENV_CHALLENGE, "challenge.json")
    monkeypatch.setenv(boundary.ENV_CHALLENGE_SHA, "a" * 64)
    monkeypatch.setenv(boundary.ENV_ACK, "ack.json")
    monkeypatch.setattr(
        boundary,
        "verify_current_runtime_binding",
        lambda *args, **kwargs: {
            "terminal": "CURRENT_RUNTIME_BINDING_PASS",
            "binding_verified": True,
            "authority_generation": "R64",
            "challenge_id": "c" * 64,
            "challenge_sha256": "a" * 64,
            "ack_sha256": "b" * 64,
        },
    )


def _append(memory: OperationalMemory, value: int):
    return memory.append_event(
        stream="r27.test",
        event_type="TEST_EVENT",
        subject_id="surface",
        actor_type="AGENT",
        actor_id="pytest",
        payload={"value": value},
    )


def test_direct_operational_memory_is_guarded_and_rechecks_existing_object(monkeypatch, tmp_path):
    clear_binding(monkeypatch)
    path = tmp_path / "operational.db"

    legacy = OperationalMemory(str(path))
    assert getattr(legacy.__class__, "__continuityos_r27_guarded__", False) is True
    _append(legacy, 1)
    assert legacy.con.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 1

    # Binding appears after a writable capability already exists.
    set_current(monkeypatch)
    with pytest.raises(boundary.CurrentEffectBoundaryError) as exc:
        _append(legacy, 2)
    assert exc.value.to_dict()["terminal"] == "CURRENT_EFFECT_HOLD"
    assert legacy.con.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 1
    legacy.close()

    # A fresh direct import object is forced read-only before mkdir/sqlite/WAL/schema effects.
    current = OperationalMemory(str(path))
    assert current.read_only is True
    assert current.con.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 1
    with pytest.raises(boundary.CurrentEffectBoundaryError):
        _append(current, 3)
    current.close()


def test_direct_operational_memory_current_mode_never_creates_missing_db(monkeypatch, tmp_path):
    clear_binding(monkeypatch)
    set_current(monkeypatch)
    path = tmp_path / "missing" / "operational.db"
    with pytest.raises(FileNotFoundError):
        OperationalMemory(str(path))
    assert not path.exists()
    assert not path.parent.exists()


def test_direct_historical_engine_holds_before_policy_or_ledger(monkeypatch):
    clear_binding(monkeypatch)
    set_current(monkeypatch)

    class ExplodingPolicy(dict):
        def get(self, *args, **kwargs):
            raise AssertionError("historical policy must not be evaluated in current mode")

    class ExplodingLedger:
        def append(self, *args, **kwargs):
            raise AssertionError("historical ledger must not be written in current mode")

    spec = ActionSpec(tool="shell", command="echo direct", args=[], paths=[], cwd="/tmp")
    result = direct_engine_preflight(
        spec,
        policy=ExplodingPolicy(),
        ledger=ExplodingLedger(),
        context=None,
    )
    assert result["decision"] == "HOLD"
    assert result["execution_authorized"] is False
    assert result["legacy_policy_evaluated"] is False
    assert result["legacy_ledger_write"] is False
    assert result["current_authority"]["authority_generation"] == "R64"


def test_direct_historical_ledger_is_read_only_and_existing_object_loses_write(monkeypatch, tmp_path):
    clear_binding(monkeypatch)
    path = tmp_path / "ledger.db"
    legacy = DirectLedger(str(path))
    assert getattr(legacy.__class__, "__continuityos_r27_guarded__", False) is True
    legacy.append("seed", {"x": 1})

    set_current(monkeypatch)
    with pytest.raises(boundary.CurrentEffectBoundaryError):
        legacy.append("blocked-existing", {"x": 2})
    assert len(legacy.export()) == 1
    legacy.close()

    current = DirectLedger(str(path))
    assert current.read_only is True
    assert current.verify()["ok"] is True
    assert len(current.export()) == 1
    with pytest.raises(boundary.CurrentEffectBoundaryError):
        current.append("blocked-new", {"x": 3})
    current.close()

    clear_binding(monkeypatch)
    check = DirectLedger(str(path))
    assert len(check.export()) == 1
    check.close()


def test_direct_historical_ledger_current_mode_never_creates_missing_file(monkeypatch, tmp_path):
    clear_binding(monkeypatch)
    set_current(monkeypatch)
    path = tmp_path / "missing-ledger.db"
    with pytest.raises(FileNotFoundError):
        DirectLedger(str(path))
    assert not path.exists()


def test_mcp_main_and_server_are_blocked_before_memory_or_service_start(monkeypatch, tmp_path):
    clear_binding(monkeypatch)
    set_current(monkeypatch)
    path = tmp_path / "mcp.db"

    assert getattr(mcp_server.main, "__continuityos_r27_guarded__", False) is True
    assert getattr(mcp_server.Server, "__continuityos_r27_guarded__", False) is True

    with pytest.raises(boundary.CurrentEffectBoundaryError):
        mcp_server.Server(str(path))
    assert not path.exists()

    # Guard fires before argparse, stdin loop, Server construction or any service lifecycle.
    with pytest.raises(boundary.CurrentEffectBoundaryError):
        mcp_server.main()
    assert not path.exists()


def test_partial_binding_never_falls_back_on_direct_surfaces(monkeypatch, tmp_path):
    clear_binding(monkeypatch)
    monkeypatch.setenv(boundary.ENV_CHALLENGE, "challenge.json")

    path = tmp_path / "partial.db"
    with pytest.raises(boundary.CurrentEffectBoundaryError):
        OperationalMemory(str(path))
    with pytest.raises(boundary.CurrentEffectBoundaryError):
        DirectLedger(str(path))
    with pytest.raises(boundary.CurrentEffectBoundaryError):
        mcp_server.Server(str(path))
    assert not path.exists()


def test_python_m_direct_modules_fail_closed_before_file_or_service_effects(tmp_path):
    env = dict(os.environ)
    for name in (
        boundary.ENV_CHALLENGE_SHA,
        boundary.ENV_ACK,
        boundary.ENV_REQUIRED,
    ):
        env.pop(name, None)
    env[boundary.ENV_CHALLENGE] = "declared-but-incomplete.json"

    operational_db = tmp_path / "module-operational.db"
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "continuityos.operational_memory",
            "--db",
            str(operational_db),
            "status",
        ],
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=20,
    )
    assert proc.returncode != 0
    assert not operational_db.exists()

    proc = subprocess.run(
        [sys.executable, "-m", "continuityos.mcp_server"],
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=20,
    )
    assert proc.returncode != 0


def test_top_level_import_remains_lazy_in_fresh_interpreter():
    env = dict(os.environ)
    for name in (
        boundary.ENV_CHALLENGE,
        boundary.ENV_CHALLENGE_SHA,
        boundary.ENV_ACK,
        boundary.ENV_REQUIRED,
    ):
        env.pop(name, None)
    code = (
        "import sys, continuityos; "
        "targets={'continuityos.operational_memory','continuityos.gate.engine',"
        "'continuityos.gate.ledger','continuityos.mcp_server'}; "
        "loaded=targets.intersection(sys.modules); "
        "assert not loaded, loaded"
    )
    proc = subprocess.run(
        [sys.executable, "-c", code],
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=20,
    )
    assert proc.returncode == 0, proc.stderr
