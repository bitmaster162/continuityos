from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys

import pytest

import continuityos
import continuityos.current_effect_boundary as boundary
import continuityos.updater as updater
import continuityos.rules_export as rules_export
import continuityos.operational_context as operational_context
import continuityos.session_input as session_input
import continuityos.wizard as wizard
import continuityos.sim.loop as sim_loop
import continuityos.fork as fork
import continuityos.ledger_server as ledger_server


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


def assert_hold(exc):
    receipt = exc.value.to_dict()
    assert receipt["terminal"] == "CURRENT_EFFECT_HOLD"
    assert receipt["effects"]["can_trade"] is False
    assert receipt["effects"]["capital_permission"] == "DENY"


def test_updater_direct_network_cache_and_apply_are_blocked_before_effect(monkeypatch, tmp_path):
    clear_binding(monkeypatch)
    set_current(monkeypatch)

    monkeypatch.setattr(
        updater.urllib.request,
        "urlopen",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("network must not run")),
    )
    monkeypatch.setattr(
        updater,
        "install_info",
        lambda: (_ for _ in ()).throw(AssertionError("apply body must not run")),
    )
    cache = tmp_path / "update_check.json"
    monkeypatch.setattr(updater, "CACHE", str(cache))

    for call in (
        lambda: updater.latest_pypi(),
        lambda: updater.check(force=True),
        lambda: updater.apply(yes=True),
    ):
        with pytest.raises(boundary.CurrentEffectBoundaryError) as exc:
            call()
        assert_hold(exc)
    assert not cache.exists()


def test_rules_export_allows_dry_run_but_blocks_filesystem_write(monkeypatch, tmp_path):
    clear_binding(monkeypatch)
    set_current(monkeypatch)
    monkeypatch.setattr(
        rules_export,
        "_gather",
        lambda memory: (["keep truth"], ["read only"], {"trunk": "ContinuityOS"}),
    )

    dry = rules_export.export_rules(object(), out_dir=str(tmp_path), targets=("agents",), dry_run=True)
    assert dry["written"] == []
    assert "keep truth" in dry["contents"]["agents"]
    assert list(tmp_path.rglob("*")) == []

    with pytest.raises(boundary.CurrentEffectBoundaryError) as exc:
        rules_export.export_rules(object(), out_dir=str(tmp_path), targets=("agents",), dry_run=False)
    assert_hold(exc)
    assert list(tmp_path.rglob("*")) == []


def test_historical_context_and_session_prepare_block_before_input_or_output_io(monkeypatch, tmp_path):
    clear_binding(monkeypatch)
    set_current(monkeypatch)

    context_out = tmp_path / "context.json"
    with pytest.raises(boundary.CurrentEffectBoundaryError) as exc:
        operational_context.prepare_context_pack(
            db_path=str(tmp_path / "missing.db"),
            capsule_path=tmp_path / "missing-capsule.json",
            spec_path=tmp_path / "missing-spec.json",
            output_path=context_out,
        )
    assert_hold(exc)
    assert not context_out.exists()

    session_out = tmp_path / "session.json"
    with pytest.raises(boundary.CurrentEffectBoundaryError) as exc:
        session_input.prepare_session_input_manifest(
            capsule_path=tmp_path / "missing-capsule.json",
            context_path=tmp_path / "missing-context.json",
            spec_path=tmp_path / "missing-spec.json",
            context_verification_path=tmp_path / "missing-verify.json",
            output_path=session_out,
        )
    assert_hold(exc)
    assert not session_out.exists()


def test_wizard_and_dashboard_block_before_home_or_memory_effect(monkeypatch, tmp_path):
    clear_binding(monkeypatch)
    set_current(monkeypatch)
    home = tmp_path / "home"
    monkeypatch.setattr(wizard, "HOME", home)
    monkeypatch.setattr(wizard, "STATE_FILE", home / "setup_state.json")
    monkeypatch.setattr(wizard, "ENV_FILE", home / ".env")
    monkeypatch.setattr(wizard, "DASH_FILE", home / "orca_dashboard.html")

    with pytest.raises(boundary.CurrentEffectBoundaryError) as exc:
        wizard.run_wizard(str(tmp_path / "memory.db"), quick=True)
    assert_hold(exc)
    with pytest.raises(boundary.CurrentEffectBoundaryError) as exc:
        wizard.build_dashboard_only(str(tmp_path / "memory.db"))
    assert_hold(exc)
    assert not home.exists()
    assert not (tmp_path / "memory.db").exists()


def test_simulation_direct_run_and_main_are_held_before_work(monkeypatch):
    clear_binding(monkeypatch)
    set_current(monkeypatch)
    monkeypatch.setattr(
        sim_loop,
        "make_memory_plane",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("simulation body must not run")),
    )

    with pytest.raises(boundary.CurrentEffectBoundaryError) as exc:
        sim_loop.run_loop("test_metric", 1, allow_stub=True)
    assert_hold(exc)
    with pytest.raises(boundary.CurrentEffectBoundaryError) as exc:
        sim_loop.main(["--objective", "test_metric", "--iters", "1", "--mock"])
    assert_hold(exc)


def test_fork_snapshot_and_merge_back_are_held_before_sqlite_or_memory_write(monkeypatch, tmp_path):
    clear_binding(monkeypatch)
    set_current(monkeypatch)
    dest = tmp_path / "snapshot.db"

    with pytest.raises(boundary.CurrentEffectBoundaryError) as exc:
        fork.snapshot(object(), str(dest))
    assert_hold(exc)
    assert not dest.exists()

    with pytest.raises(boundary.CurrentEffectBoundaryError) as exc:
        fork.merge_back(object(), object())
    assert_hold(exc)


def test_ledger_server_read_token_is_pure_but_write_capability_and_lifecycle_hold(monkeypatch, tmp_path):
    clear_binding(monkeypatch)
    set_current(monkeypatch)

    read_token = ledger_server.mint_token("secret", "reader", scope="read", ttl=60)
    assert read_token.startswith("reader.read.")

    with pytest.raises(boundary.CurrentEffectBoundaryError) as exc:
        ledger_server.mint_token("secret", "writer", scope="write", ttl=60)
    assert_hold(exc)

    monkeypatch.setattr(
        ledger_server,
        "ThreadingHTTPServer",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("socket must not open")),
    )
    with pytest.raises(boundary.CurrentEffectBoundaryError) as exc:
        ledger_server.serve(str(tmp_path / "fleet.db"), "secret", port=0)
    assert_hold(exc)
    assert not (tmp_path / "fleet.db").exists()

    buffer = tmp_path / "ledger-buffer.jsonl"
    sink = ledger_server.LedgerSink("http://127.0.0.1:1", "token", buffer=str(buffer), timeout=0.01)
    with pytest.raises(boundary.CurrentEffectBoundaryError) as exc:
        sink.record("test", {"x": 1})
    assert_hold(exc)
    with pytest.raises(boundary.CurrentEffectBoundaryError) as exc:
        sink.flush()
    assert_hold(exc)
    assert not buffer.exists()
    assert not (tmp_path / "ledger-buffer.jsonl.buffer.lock").exists()
    assert not (tmp_path / "ledger-buffer.jsonl.flush.lock").exists()


def test_preexisting_ledger_sink_loses_effect_capability_when_binding_appears(monkeypatch, tmp_path):
    clear_binding(monkeypatch)
    buffer = tmp_path / "preexisting-buffer.jsonl"
    sink = ledger_server.LedgerSink("http://127.0.0.1:1", "token", buffer=str(buffer), timeout=0.01)

    set_current(monkeypatch)
    with pytest.raises(boundary.CurrentEffectBoundaryError):
        sink.record("test", {"x": 1})
    with pytest.raises(boundary.CurrentEffectBoundaryError):
        sink.flush()
    assert not buffer.exists()


def test_partial_binding_never_falls_back_for_new_library_effects(monkeypatch, tmp_path):
    clear_binding(monkeypatch)
    monkeypatch.setenv(boundary.ENV_CHALLENGE, "declared-but-incomplete.json")

    with pytest.raises(boundary.CurrentEffectBoundaryError):
        updater.check(force=True)
    with pytest.raises(boundary.CurrentEffectBoundaryError):
        rules_export.export_rules(object(), out_dir=str(tmp_path), targets=("agents",))
    with pytest.raises(boundary.CurrentEffectBoundaryError):
        sim_loop.run_loop("test_metric", 1, allow_stub=True)
    assert list(tmp_path.rglob("*")) == []


def test_python_m_effect_commands_fail_closed_but_verify_is_not_blanket_blocked(tmp_path):
    env = dict(os.environ)
    for name in (
        boundary.ENV_CHALLENGE_SHA,
        boundary.ENV_ACK,
        boundary.ENV_REQUIRED,
    ):
        env.pop(name, None)
    env[boundary.ENV_CHALLENGE] = "declared-but-incomplete.json"

    commands = [
        [sys.executable, "-m", "continuityos.sim.loop", "--mock", "--iters", "1"],
        [
            sys.executable, "-m", "continuityos.operational_context", "prepare",
            "--db", str(tmp_path / "missing.db"),
            "--capsule", str(tmp_path / "missing-capsule.json"),
            "--spec", str(tmp_path / "missing-spec.json"),
            "--out", str(tmp_path / "context.json"),
        ],
        [
            sys.executable, "-m", "continuityos.session_input", "prepare",
            "--capsule", str(tmp_path / "missing-capsule.json"),
            "--context", str(tmp_path / "missing-context.json"),
            "--spec", str(tmp_path / "missing-spec.json"),
            "--context-verification", str(tmp_path / "missing-verify.json"),
            "--out", str(tmp_path / "session.json"),
        ],
    ]
    for command in commands:
        proc = subprocess.run(
            command,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=20,
        )
        assert proc.returncode != 0
        assert "CurrentEffectBoundaryError" in proc.stderr

    assert not (tmp_path / "context.json").exists()
    assert not (tmp_path / "session.json").exists()

    # Selective historical verifier stays executable: argparse reaches its own
    # required-argument validation rather than the import guard rejecting it.
    verify = subprocess.run(
        [sys.executable, "-m", "continuityos.operational_context", "verify"],
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=20,
    )
    assert verify.returncode != 0
    assert "usage:" in verify.stderr.lower()
    assert "CurrentEffectBoundaryError" not in verify.stderr


def test_top_level_import_remains_lazy_for_r28_targets():
    env = dict(os.environ)
    for name in (
        boundary.ENV_CHALLENGE,
        boundary.ENV_CHALLENGE_SHA,
        boundary.ENV_ACK,
        boundary.ENV_REQUIRED,
    ):
        env.pop(name, None)
    code = """
import sys, continuityos
names = {
    'continuityos.operational_memory',
    'continuityos.gate.engine',
    'continuityos.gate.ledger',
    'continuityos.mcp_server',
    'continuityos.updater',
    'continuityos.rules_export',
    'continuityos.operational_context',
    'continuityos.session_input',
    'continuityos.wizard',
    'continuityos.sim.loop',
    'continuityos.fork',
    'continuityos.ledger_server',
}
loaded = names.intersection(sys.modules)
assert not loaded, loaded
"""
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
