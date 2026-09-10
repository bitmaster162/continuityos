"""R14 external anti-rollback witness acceptance and red-team tests."""
from __future__ import annotations

import inspect
import json
import os
import sqlite3
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from continuityos.gate import cli
from continuityos.gate.broker import GateBroker
from continuityos.gate.ledger import GENESIS, Ledger
from continuityos.gate.policy import default_policy
from continuityos.gate.witness import (
    WitnessAuthority, WitnessError, _canonical, _document,
)
from continuityos.mcp_server import TOOLS
from continuityos.gate.witness_migrate import migrate


def _allow(_self, _spec):
    policy = default_policy()
    policy["default_decision"] = "ALLOW"
    policy["severity_decision"] = {
        key: "ALLOW" for key in policy["severity_decision"]
    }
    return policy, None


@pytest.fixture
def authority_broker(tmp_path, monkeypatch):
    cli._require_legacy_gate()
    monkeypatch.setattr(GateBroker, "_load_adapter", _allow)
    return GateBroker(
        registry_path=str(tmp_path / "registry.db"),
        ledger_path=str(tmp_path / "ledger.db"),
        witness_path=str(tmp_path / "outside" / "witness.json"),
    )


def _script(tmp_path):
    script = tmp_path / "effect.py"
    script.write_text(
        "from pathlib import Path\n"
        "p=Path('effect.txt')\n"
        "p.write_text((p.read_text() if p.exists() else '')+'x')\n",
        encoding="utf-8",
    )
    return script


def _preflight(broker, tmp_path, request_id="r14"):
    script = _script(tmp_path)
    result = broker.preflight_exec(
        request_id, [sys.executable, str(script)], str(tmp_path), []
    )
    assert result["decision"] in ("ALLOW", "REQUIRE_CONFIRMATION"), result
    if result["decision"] == "REQUIRE_CONFIRMATION":
        with broker._ledger() as ledger:
            ledger.append("override", {
                "preflight_hash": result["preflight_hash"], "by": "human",
            })
    return result


def _checkpoint(path):
    with sqlite3.connect(path) as con:
        con.execute("PRAGMA wal_checkpoint(TRUNCATE)")


def _backup(source, destination):
    with sqlite3.connect(source) as src, sqlite3.connect(destination) as dst:
        src.backup(dst)


def _restore(source, destination):
    _backup(source, destination)


def test_fresh_bootstrap_is_canonical_and_advances(authority_broker):
    broker = authority_broker
    doc = broker.witness.read()
    assert doc["event_count"] == 0 and doc["event_hash"] == GENESIS
    assert broker.witness.path != broker.ledger_path != broker.registry_path
    raw = open(broker.witness.path, "rb").read()
    assert raw == json.dumps(
        doc, sort_keys=True, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")
    with broker._ledger() as ledger:
        ledger.append("test", {"n": 1})
        assert ledger.state_id() == doc["state_id"]
    assert broker.witness.read()["event_count"] == 1
    with sqlite3.connect(broker.registry_path) as con:
        assert con.execute(
            "SELECT state_id FROM governance_metadata"
        ).fetchone()[0] == doc["state_id"]


@pytest.mark.parametrize("corrupt", [False, True])
def test_missing_or_corrupt_witness_with_state_fails_closed(
    authority_broker, corrupt
):
    broker = authority_broker
    if corrupt:
        open(broker.witness.path, "wb").write(b"{}")
    else:
        __import__("os").unlink(broker.witness.path)
    result = broker.preflight_exec("blocked", [sys.executable], broker.ledger_path)
    assert result["state"] == "HELD"
    with pytest.raises(WitnessError):
        GateBroker(
            broker.registry_path, broker.ledger_path,
            witness_path=broker.witness.path,
        )


def test_shorter_and_divergent_hash_valid_ledgers_are_held(
    authority_broker, tmp_path
):
    broker = authority_broker
    with broker._ledger() as ledger:
        ledger.append("one", {})
    _checkpoint(broker.ledger_path)
    old = tmp_path / "old.db"
    _backup(broker.ledger_path, old)
    with broker._ledger() as ledger:
        ledger.append("two", {"branch": "real"})
    _restore(old, broker.ledger_path)
    assert broker.preflight_exec("short", [sys.executable], str(tmp_path))["state"] == "HELD"

    # Build a coherent but different second event without witness authority.
    divergent = tmp_path / "divergent.db"
    _backup(old, divergent)
    with Ledger(str(divergent)) as ledger:
        ledger.append("two", {"branch": "other"})
        assert ledger.verify()["ok"]
    _restore(divergent, broker.ledger_path)
    assert broker.preflight_exec("diverge", [sys.executable], str(tmp_path))["state"] == "HELD"


def test_coherent_rollback_after_terminal_holds_but_exact_terminal_restore_caches(
    authority_broker, tmp_path
):
    broker = authority_broker
    _preflight(broker, tmp_path)
    _checkpoint(broker.ledger_path)
    pre_ledger, pre_registry = tmp_path / "pre-ledger", tmp_path / "pre-registry"
    _backup(broker.ledger_path, pre_ledger)
    _backup(broker.registry_path, pre_registry)
    first = broker.execute_preflight("r14")
    assert first["state"] == "TERMINAL"
    _checkpoint(broker.ledger_path)
    terminal_ledger, terminal_registry = tmp_path / "term-ledger", tmp_path / "term-registry"
    _backup(broker.ledger_path, terminal_ledger)
    _backup(broker.registry_path, terminal_registry)

    _restore(pre_ledger, broker.ledger_path)
    _restore(pre_registry, broker.registry_path)
    assert broker.execute_preflight("r14")["state"] == "HELD"
    assert (tmp_path / "effect.txt").read_text() == "x"

    _restore(terminal_ledger, broker.ledger_path)
    _restore(terminal_registry, broker.registry_path)
    cached = broker.execute_preflight("r14")
    assert cached["state"] == "CACHED"
    assert (tmp_path / "effect.txt").read_text() == "x"


def test_started_witness_failure_prevents_subprocess(
    authority_broker, tmp_path, monkeypatch
):
    broker = authority_broker
    _preflight(broker, tmp_path)
    before = broker.witness.read()["event_count"]
    import continuityos.gate.witness as witness_module
    real_write = witness_module.durable_atomic_write

    def fail_started(path, data):
        if json.loads(data)["event_count"] >= before + 2:
            raise OSError("injected witness failure")
        return real_write(path, data)

    calls = []
    monkeypatch.setattr(witness_module, "durable_atomic_write", fail_started)
    monkeypatch.setattr(cli.subprocess, "call", lambda *a, **k: calls.append((a, k)))
    result = broker.execute_preflight("r14")
    assert result["state"] == "HELD"
    assert calls == []


def test_terminal_commit_recovers_witness_and_retry_is_cached(
    authority_broker, tmp_path, monkeypatch
):
    broker = authority_broker
    _preflight(broker, tmp_path)
    before = broker.witness.read()["event_count"]
    import continuityos.gate.witness as witness_module
    real_write = witness_module.durable_atomic_write
    failed = {"done": False}

    def fail_terminal_once(path, data):
        if json.loads(data)["event_count"] >= before + 3 and not failed["done"]:
            failed["done"] = True
            raise OSError("injected terminal witness failure")
        return real_write(path, data)

    monkeypatch.setattr(witness_module, "durable_atomic_write", fail_terminal_once)
    broker.execute_preflight("r14")
    retry = broker.execute_preflight("r14")
    assert retry["state"] == "CACHED"
    assert (tmp_path / "effect.txt").read_text() == "x"


def test_state_id_mismatch_is_held(authority_broker, tmp_path):
    broker = authority_broker
    with sqlite3.connect(broker.registry_path) as con:
        con.execute("DROP TRIGGER governance_metadata_no_update")
        con.execute("UPDATE governance_metadata SET state_id='different'")
        con.commit()
    assert broker.preflight_exec("mismatch", [sys.executable], str(tmp_path))["state"] == "HELD"


def test_product_tools_do_not_widen_authority():
    forbidden = ("witness", "reset", "migrate", "advance", "approval")
    for tool in TOOLS:
        assert not any(token in tool["name"] for token in forbidden)
    by_name = {tool["name"]: tool["inputSchema"] for tool in TOOLS}
    assert set(by_name["execute_preflight"]["properties"]) == {"request_id"}
    assert set(by_name["preflight_exec"]["properties"]) == {
        "request_id", "argv", "cwd", "paths"
    }


def test_witness_mode_concurrency_has_one_effect(authority_broker, tmp_path):
    broker = authority_broker
    _preflight(broker, tmp_path)
    other = GateBroker(
        broker.registry_path, broker.ledger_path,
        witness_path=broker.witness.path,
    )
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(
            lambda b: b.execute_preflight("r14"), (broker, other)
        ))
    assert sorted(result["state"] for result in results) == ["CACHED", "TERMINAL"]
    assert (tmp_path / "effect.txt").read_text() == "x"


def test_explicit_offline_r13_migration(tmp_path):
    ledger_path = str(tmp_path / "legacy-ledger.db")
    registry_path = str(tmp_path / "legacy-registry.db")
    witness_path = str(tmp_path / "external" / "witness.json")
    legacy = GateBroker(registry_path, ledger_path)
    with Ledger(ledger_path) as ledger:
        ledger.append("legacy", {"valid": True})
    result = migrate(ledger_path, registry_path, witness_path)
    assert result["event_count"] == 1
    migrated = GateBroker(
        registry_path, ledger_path, witness_path=witness_path
    )
    assert migrated.witness.read()["state_id"] == result["state_id"]


@pytest.mark.parametrize("collision", ["ledger", "registry"])
def test_witness_authority_rejects_normalized_path_collisions_early(
    tmp_path, collision
):
    same = tmp_path / "authority.db"
    alias = tmp_path / "nested" / ".." / same.name
    ledger = alias if collision == "ledger" else tmp_path / "ledger.db"
    registry = alias if collision == "registry" else tmp_path / "registry.db"
    with pytest.raises(WitnessError, match="distinct"):
        WitnessAuthority(str(same), str(ledger), str(registry))
    assert not same.exists()


def test_witness_rejects_document_larger_than_4096_bytes(tmp_path):
    witness_path = tmp_path / "witness.json"
    raw = _canonical(_document("a" * 5000, 0, GENESIS))
    assert len(raw) == 5303
    witness_path.write_bytes(raw)
    authority = WitnessAuthority(
        str(witness_path), str(tmp_path / "ledger.db"),
        str(tmp_path / "registry.db"),
    )
    with pytest.raises(WitnessError, match="maximum size"):
        authority.read()


@pytest.mark.parametrize("state_id", ["a" * 63, "A" * 64, "0" * 64])
def test_witness_state_id_parser_requires_strong_lowercase_hex(
    tmp_path, state_id
):
    witness_path = tmp_path / "witness.json"
    witness_path.write_bytes(_canonical(_document(state_id, 0, GENESIS)))
    authority = WitnessAuthority(
        str(witness_path), str(tmp_path / "ledger.db"),
        str(tmp_path / "registry.db"),
    )
    with pytest.raises(WitnessError, match="fields are invalid"):
        authority.read()


def test_fresh_state_id_is_64_lowercase_hex(authority_broker):
    state_id = authority_broker.witness.read()["state_id"]
    assert len(state_id) == 64
    assert state_id != "0" * 64
    assert set(state_id) <= set("0123456789abcdef")


def test_offline_migration_rejects_registry_action_digest_mismatch(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(GateBroker, "_load_adapter", _allow)
    ledger_path = str(tmp_path / "legacy-ledger.db")
    registry_path = str(tmp_path / "legacy-registry.db")
    witness_path = str(tmp_path / "witness.json")
    legacy = GateBroker(registry_path, ledger_path)
    _preflight(legacy, tmp_path, "migration-digest")
    with sqlite3.connect(registry_path) as con:
        con.execute("UPDATE broker_requests SET action_sha256=?", ("f" * 64,))
        con.commit()
    with pytest.raises(WitnessError, match="broker registry mapping"):
        migrate(ledger_path, registry_path, witness_path)
    assert not os.path.exists(witness_path)


def test_offline_migration_rejects_structurally_valid_wrong_attempt_binding(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(GateBroker, "_load_adapter", _allow)
    ledger_path = str(tmp_path / "legacy-ledger.db")
    registry_path = str(tmp_path / "legacy-registry.db")
    witness_path = str(tmp_path / "witness.json")
    legacy = GateBroker(registry_path, ledger_path)
    preflight = _preflight(legacy, tmp_path, "migration-binding")
    with Ledger(ledger_path) as ledger:
        event = ledger.event(preflight["preflight_hash"])
        payload = event["payload"]
        ledger.claim_execution_attempt(
            preflight_hash=preflight["preflight_hash"],
            binding_sha256="2" * 64,
            expected_action=payload["action"],
            expected_rollback_plan=payload["rollback_plan"],
            expected_decision=payload["decision"],
        )
    with pytest.raises(WitnessError, match="binding differs from exact preflight"):
        migrate(ledger_path, registry_path, witness_path)
    assert not os.path.exists(witness_path)


def test_offline_migration_rejects_orphan_attempt_claim(tmp_path):
    ledger_path = str(tmp_path / "legacy-ledger.db")
    registry_path = str(tmp_path / "legacy-registry.db")
    witness_path = str(tmp_path / "witness.json")
    GateBroker(registry_path, ledger_path)
    with Ledger(ledger_path) as ledger:
        ledger.append("attempt_claimed", {
            "preflight_hash": "1" * 64,
            "binding_sha256": "2" * 64,
            "phase": "CLAIMED",
        })
    with pytest.raises(WitnessError, match="execution lifecycle"):
        migrate(ledger_path, registry_path, witness_path)
    assert not os.path.exists(witness_path)


def test_db_commit_witness_write_failure_recovers_forward(
    authority_broker, monkeypatch
):
    broker = authority_broker
    before = broker.witness.read()["event_count"]
    import continuityos.gate.witness as witness_module
    real_write = witness_module.durable_atomic_write
    failed = {"done": False}

    def fail_once(path, data):
        if not failed["done"]:
            failed["done"] = True
            raise OSError("injected witness write failure after DB commit")
        return real_write(path, data)

    monkeypatch.setattr(witness_module, "durable_atomic_write", fail_once)
    with pytest.raises(OSError, match="after DB commit"):
        with broker._ledger() as ledger:
            ledger.append("generic-recovery", {"committed": True})

    assert broker.witness.read()["event_count"] == before
    with broker._ledger() as ledger:
        assert ledger.verify()["ok"]
        assert ledger.frontier()["event_count"] == before + 1
    assert broker.witness.read()["event_count"] == before + 1


@pytest.mark.skipif(os.name != "nt", reason="Windows locking contract")
def test_windows_witness_lock_uses_lockfileex_not_msvcrt():
    import continuityos.gate.witness as witness_module
    source = inspect.getsource(witness_module)
    assert "LockFileEx" in source
    assert "UnlockFileEx" in source
    assert "msvcrt.locking" not in source


@pytest.mark.skipif(os.name != "nt", reason="Windows cross-process locking contract")
def test_windows_witness_lock_blocks_across_processes(tmp_path):
    witness_path = str(tmp_path / "witness.json")
    ledger_path = str(tmp_path / "ledger.db")
    registry_path = str(tmp_path / "registry.db")
    ready_path = str(tmp_path / "locked.ready")
    code = (
        "import time\n"
        "from pathlib import Path\n"
        "from continuityos.gate.witness import WitnessAuthority\n"
        f"a=WitnessAuthority({witness_path!r},{ledger_path!r},{registry_path!r})\n"
        "with a.locked():\n"
        f" Path({ready_path!r}).write_text('ready', encoding='utf-8')\n"
        " time.sleep(0.8)\n"
    )
    child = subprocess.Popen([sys.executable, "-c", code], cwd=os.getcwd())
    try:
        deadline = time.monotonic() + 5
        while not os.path.exists(ready_path) and time.monotonic() < deadline:
            time.sleep(0.01)
        assert os.path.exists(ready_path)
        authority = WitnessAuthority(witness_path, ledger_path, registry_path)
        started = time.monotonic()
        with authority.locked():
            elapsed = time.monotonic() - started
        assert elapsed >= 0.4
        assert child.wait(timeout=5) == 0
    finally:
        if child.poll() is None:
            child.kill()
            child.wait(timeout=5)


def test_witness_rejects_parent_identity_replacement_after_construction(tmp_path):
    root = tmp_path / "authority"
    root.mkdir()
    authority = WitnessAuthority(
        str(root / "witness.json"), str(root / "ledger.db"),
        str(root / "registry.db"),
    )
    moved = tmp_path / "authority-old"
    root.rename(moved)
    root.mkdir()
    with pytest.raises(WitnessError, match="parent identity changed"):
        with authority.locked():
            pass


def test_witness_rejects_lock_substitution_before_first_acquisition(tmp_path):
    authority = WitnessAuthority(
        str(tmp_path / "witness.json"), str(tmp_path / "ledger.db"),
        str(tmp_path / "registry.db"),
    )
    pinned = authority._lock_identity
    os.unlink(authority.lock_path)
    with open(authority.lock_path, "wb") as stream:
        stream.write(b"replacement-before-first-lock")
    assert authority._lock_identity == pinned
    with pytest.raises(WitnessError, match="lock file identity changed"):
        with authority.locked():
            pass


@pytest.mark.skipif(os.name == "nt", reason="POSIX unlink/flock substitution contract")
def test_posix_lock_substitution_while_held_blocks_second_authority(tmp_path):
    witness = str(tmp_path / "witness.json")
    ledger = str(tmp_path / "ledger.db")
    registry = str(tmp_path / "registry.db")
    owner = WitnessAuthority(witness, ledger, registry)
    contender = WitnessAuthority(witness, ledger, registry)
    with owner.locked():
        pinned = contender._lock_identity
        os.unlink(owner.lock_path)
        with open(owner.lock_path, "wb") as stream:
            stream.write(b"replacement-while-held")
        assert (os.lstat(owner.lock_path).st_dev, os.lstat(owner.lock_path).st_ino, __import__("stat").S_IFMT(os.lstat(owner.lock_path).st_mode)) != pinned
        with pytest.raises(WitnessError, match="lock file identity changed"):
            with contender.locked():
                pass


def test_nested_second_authority_still_runs_its_own_identity_validation(tmp_path, monkeypatch):
    witness = str(tmp_path / "witness.json")
    ledger = str(tmp_path / "ledger.db")
    registry = str(tmp_path / "registry.db")
    owner = WitnessAuthority(witness, ledger, registry)
    contender = WitnessAuthority(witness, ledger, registry)

    def reject(*args, **kwargs):
        raise WitnessError("contender identity validation ran")

    monkeypatch.setattr(contender, "_validate_stable_paths", reject)
    with owner.locked():
        with pytest.raises(WitnessError, match="contender identity validation ran"):
            with contender.locked():
                pass


def test_witness_rejects_lock_file_identity_replacement(tmp_path):
    authority = WitnessAuthority(
        str(tmp_path / "witness.json"), str(tmp_path / "ledger.db"),
        str(tmp_path / "registry.db"),
    )
    with authority.locked():
        pass
    os.unlink(authority.lock_path)
    with open(authority.lock_path, "wb") as stream:
        stream.write(b"replacement")
    with pytest.raises(WitnessError, match="lock file identity changed"):
        with authority.locked():
            pass


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="symlink unavailable")
def test_witness_rejects_symlink_component_after_construction(tmp_path):
    parent = tmp_path / "parent"
    parent.mkdir()
    authority = WitnessAuthority(
        str(parent / "witness.json"), str(parent / "ledger.db"),
        str(parent / "registry.db"),
    )
    moved = tmp_path / "real-parent"
    parent.rename(moved)
    try:
        os.symlink(moved, parent, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation is not permitted on this host")
    with pytest.raises(WitnessError, match="symlink/reparse"):
        authority.read()


@pytest.mark.parametrize("mutation", ["duplicate", "whitespace", "trailing", "bom"])
def test_witness_parser_rejects_noncanonical_or_ambiguous_bytes(tmp_path, mutation):
    state_id = "1" * 64
    raw = _canonical(_document(state_id, 0, GENESIS))
    if mutation == "duplicate":
        text = raw.decode("utf-8")
        raw = text.replace('{', '{"schema":"duplicate",', 1).encode("utf-8")
    elif mutation == "whitespace":
        raw = b" " + raw
    elif mutation == "trailing":
        raw = raw + b"\n"
    else:
        raw = b"\xef\xbb\xbf" + raw
    path = tmp_path / "witness.json"
    path.write_bytes(raw)
    authority = WitnessAuthority(
        str(path), str(tmp_path / "ledger.db"), str(tmp_path / "registry.db")
    )
    with pytest.raises(WitnessError):
        authority.read()


def test_offline_migration_is_packaged_module_and_not_mcp_surface():
    import continuityos.gate.witness_migrate as migration
    assert migration.migrate.__module__ == "continuityos.gate.witness_migrate"
    names = {tool["name"] for tool in TOOLS}
    assert not any("migrate" in name or "witness" in name for name in names)
    completed = subprocess.run(
        [sys.executable, "-m", "continuityos.gate.witness_migrate", "--help"],
        cwd=os.getcwd(), capture_output=True, text=True, timeout=20,
    )
    assert completed.returncode == 0, completed.stderr
    assert "--ledger" in completed.stdout and "--registry" in completed.stdout
    assert "--witness" in completed.stdout


def test_product_lazy_broker_witness_failure_is_structured_hold(monkeypatch):
    from continuityos.mcp_server import Server
    server = Server.__new__(Server)
    server.turns = 0
    def fail_broker():
        raise WitnessError("ledger is shorter than witnessed frontier")
    monkeypatch.setattr(server, "_gate_broker", fail_broker)
    execution = json.loads(server.call(
        "execute_preflight", {"request_id": "rollback-restart"}
    ))
    assert execution["state"] == "HELD"
    assert execution["decision"] == "HELD"
    assert "shorter than witnessed frontier" in execution["reasons"][0]
    preflight = json.loads(server.call("preflight_exec", {
        "request_id": "rollback-restart", "argv": [sys.executable],
        "cwd": os.getcwd(), "paths": [],
    }))
    assert preflight["state"] == "HELD"
    assert preflight["request_key"] == execution["request_key"]


def test_offline_migration_of_terminal_r13_request_preserves_cached_state(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(GateBroker, "_load_adapter", _allow)
    ledger_path = str(tmp_path / "legacy-ledger.db")
    registry_path = str(tmp_path / "legacy-registry.db")
    witness_path = str(tmp_path / "external" / "witness.json")
    legacy = GateBroker(registry_path, ledger_path)
    _preflight(legacy, tmp_path, "migrate-terminal")
    first = legacy.execute_preflight("migrate-terminal")
    assert first["state"] == "TERMINAL"
    assert (tmp_path / "effect.txt").read_text() == "x"
    result = migrate(ledger_path, registry_path, witness_path)
    migrated = GateBroker(
        registry_path, ledger_path, witness_path=witness_path
    )
    cached = migrated.execute_preflight("migrate-terminal")
    assert cached["state"] == "CACHED"
    assert (tmp_path / "effect.txt").read_text() == "x"
    assert migrated.witness.read()["event_count"] == result["event_count"]


def test_offline_migration_recovers_after_witness_before_metadata(
    tmp_path, monkeypatch
):
    import continuityos.gate.witness_migrate as migration
    ledger_path = str(tmp_path / "legacy-ledger.db")
    registry_path = str(tmp_path / "legacy-registry.db")
    witness_path = str(tmp_path / "external" / "witness.json")
    GateBroker(registry_path, ledger_path)
    with Ledger(ledger_path) as ledger:
        ledger.append("legacy", {"valid": True})
    real_commit = migration._commit_metadata
    monkeypatch.setattr(
        migration, "_commit_metadata",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            OSError("injected crash after witness")
        ),
    )
    with pytest.raises(OSError, match="after witness"):
        migration.migrate(ledger_path, registry_path, witness_path)
    doc = WitnessAuthority(witness_path, ledger_path, registry_path).read()
    with sqlite3.connect(ledger_path) as ledger, sqlite3.connect(registry_path) as registry:
        assert migration._metadata(ledger) is None
        assert migration._metadata(registry) is None
    monkeypatch.setattr(migration, "_commit_metadata", real_commit)
    recovered = migration.migrate(ledger_path, registry_path, witness_path)
    assert recovered["state_id"] == doc["state_id"]


def test_offline_migration_recovers_after_split_metadata_commit(
    tmp_path, monkeypatch
):
    import continuityos.gate.witness_migrate as migration
    ledger_path = str(tmp_path / "legacy-ledger.db")
    registry_path = str(tmp_path / "legacy-registry.db")
    witness_path = str(tmp_path / "external" / "witness.json")
    GateBroker(registry_path, ledger_path)
    with Ledger(ledger_path) as ledger:
        ledger.append("legacy", {"valid": True})
    real_commit = migration._commit_metadata
    calls = {"count": 0}
    def fail_second(con, state_id):
        calls["count"] += 1
        if calls["count"] == 2:
            raise OSError("injected crash between metadata commits")
        return real_commit(con, state_id)
    monkeypatch.setattr(migration, "_commit_metadata", fail_second)
    with pytest.raises(OSError, match="between metadata commits"):
        migration.migrate(ledger_path, registry_path, witness_path)
    doc = WitnessAuthority(witness_path, ledger_path, registry_path).read()
    with sqlite3.connect(ledger_path) as ledger, sqlite3.connect(registry_path) as registry:
        assert migration._metadata(ledger) == doc["state_id"]
        assert migration._metadata(registry) is None
    monkeypatch.setattr(migration, "_commit_metadata", real_commit)
    recovered = migration.migrate(ledger_path, registry_path, witness_path)
    assert recovered["state_id"] == doc["state_id"]
    migrated = GateBroker(registry_path, ledger_path, witness_path=witness_path)
    assert migrated.witness.read()["state_id"] == doc["state_id"]


def test_fresh_bootstrap_recovers_after_witness_before_databases(tmp_path):
    witness_path = str(tmp_path / "outside" / "witness.json")
    ledger_path = str(tmp_path / "ledger.db")
    registry_path = str(tmp_path / "registry.db")
    authority = WitnessAuthority(witness_path, ledger_path, registry_path)
    doc = authority.bootstrap()
    assert os.path.exists(witness_path)
    assert not os.path.exists(ledger_path)
    assert not os.path.exists(registry_path)
    recovered = GateBroker(
        registry_path, ledger_path, witness_path=witness_path
    )
    assert recovered.witness.read()["state_id"] == doc["state_id"]
    with recovered._ledger() as ledger:
        assert ledger.state_id() == doc["state_id"]
    with sqlite3.connect(registry_path) as registry:
        assert registry.execute(
            "SELECT state_id FROM governance_metadata WHERE singleton=1"
        ).fetchone()[0] == doc["state_id"]


def test_fresh_bootstrap_recovers_empty_registry_fragment(tmp_path):
    witness_path = str(tmp_path / "outside" / "witness.json")
    ledger_path = str(tmp_path / "ledger.db")
    registry_path = str(tmp_path / "registry.db")
    authority = WitnessAuthority(witness_path, ledger_path, registry_path)
    doc = authority.bootstrap()
    with sqlite3.connect(registry_path) as registry:
        registry.execute("""CREATE TABLE broker_requests(
            request_key TEXT PRIMARY KEY, action_sha256 TEXT NOT NULL,
            preflight_hash TEXT NOT NULL UNIQUE, created_ts REAL NOT NULL)""")
        registry.commit()
    recovered = GateBroker(
        registry_path, ledger_path, witness_path=witness_path
    )
    assert recovered.witness.read()["state_id"] == doc["state_id"]
    with recovered._ledger() as ledger:
        assert ledger.frontier()["event_count"] == 0


def test_fresh_bootstrap_refuses_nonempty_partial_registry(tmp_path):
    witness_path = str(tmp_path / "outside" / "witness.json")
    ledger_path = str(tmp_path / "ledger.db")
    registry_path = str(tmp_path / "registry.db")
    WitnessAuthority(witness_path, ledger_path, registry_path).bootstrap()
    with sqlite3.connect(registry_path) as registry:
        registry.execute("""CREATE TABLE broker_requests(
            request_key TEXT PRIMARY KEY, action_sha256 TEXT NOT NULL,
            preflight_hash TEXT NOT NULL UNIQUE, created_ts REAL NOT NULL)""")
        registry.execute(
            "INSERT INTO broker_requests VALUES(?,?,?,?)",
            ("1" * 64, "2" * 64, "3" * 64, 1.0),
        )
        registry.commit()
    with pytest.raises(WitnessError, match="safe GENESIS"):
        GateBroker(registry_path, ledger_path, witness_path=witness_path)


def test_authority_rejects_lexical_alias_to_witness_lock(tmp_path):
    witness = tmp_path / "witness.json"
    lock = str(witness) + ".lock"
    with pytest.raises(WitnessError, match="paths must be distinct"):
        WitnessAuthority(str(witness), lock, str(tmp_path / "registry.db"))
    with pytest.raises(WitnessError, match="paths must be distinct"):
        WitnessAuthority(str(witness), str(tmp_path / "ledger.db"), lock)


@pytest.mark.parametrize("role", ["ledger", "registry"])
def test_authority_rejects_hardlink_alias_to_existing_lock(tmp_path, role):
    witness = tmp_path / "witness.json"
    lock = tmp_path / "witness.json.lock"
    lock.write_bytes(b"0")
    ledger = tmp_path / "ledger.db"
    registry = tmp_path / "registry.db"
    alias = ledger if role == "ledger" else registry
    os.link(lock, alias)
    with pytest.raises(WitnessError, match="alias each other"):
        WitnessAuthority(str(witness), str(ledger), str(registry))


@pytest.mark.skipif(os.name != "nt", reason="Windows junction contract")
def test_windows_junction_component_is_rejected(tmp_path):
    real = tmp_path / "real"
    junction = tmp_path / "junction"
    real.mkdir()
    made = subprocess.run(["cmd", "/c", "mklink", "/J", str(junction), str(real)], capture_output=True, text=True)
    if made.returncode != 0:
        pytest.skip("junction creation unavailable")
    with pytest.raises(WitnessError, match="reparse"):
        WitnessAuthority(str(junction / "witness.json"), str(tmp_path / "ledger.db"), str(tmp_path / "registry.db"))