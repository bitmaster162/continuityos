"""Product-owned broker execution boundary tests."""
import json
import os
import sqlite3
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from continuityos.gate import cli
from continuityos.gate.broker import GateBroker
from continuityos.gate.ledger import Ledger
from continuityos.gate.policy import default_policy


@pytest.fixture
def broker(tmp_path, monkeypatch):
    cli._require_legacy_gate()

    def allow(_self, _spec):
        policy = default_policy()
        policy["default_decision"] = "ALLOW"
        policy["severity_decision"] = {
            key: "ALLOW" for key in policy["severity_decision"]
        }
        return policy, None

    monkeypatch.setattr(GateBroker, "_load_adapter", allow)
    return GateBroker(
        registry_path=str(tmp_path / "registry.db"),
        ledger_path=str(tmp_path / "ledger.db"),
    )


def _script(tmp_path):
    script = tmp_path / "effect.py"
    script.write_text(
        "import os, pathlib, sys\n"
        "p = pathlib.Path('effect.txt')\n"
        "p.write_text(p.read_text() + 'x' if p.exists() else 'x')\n"
        "print('child-out:' + os.environ.get('BROKER_TEST_VALUE', 'missing'))\n"
        "print('secret:' + os.environ.get('BROKER_API_SECRET', 'absent'), file=sys.stderr)\n",
        encoding="utf-8",
    )
    return script


def _preflight(broker, request_id, tmp_path, script):
    result = broker.preflight_exec(
        request_id, [sys.executable, str(script)], str(tmp_path)
    )
    assert result["decision"] in ("ALLOW", "WARN", "REQUIRE_CONFIRMATION"), result.get("reasons")
    if result["decision"] == "REQUIRE_CONFIRMATION":
        with Ledger(broker.ledger_path) as ledger:
            ledger.append("override", {
                "preflight_hash": result["preflight_hash"], "by": "human",
            })
    return result


def _bound_result(ledger_path, argv, cwd):
    action = {
        "tool": "exec",
        "command": GateBroker._canonical(argv),
        "args": list(argv),
        "paths": [],
        "cwd": str(cwd),
        "agent": "test",
        "meta": {},
    }
    with Ledger(str(ledger_path)) as ledger:
        preflight_hash = ledger.append("preflight", {
            "action": action,
            "decision": "ALLOW",
            "rollback_plan": {},
        })
    return {
        "action": action,
        "decision": "ALLOW",
        "ledger_hash": preflight_hash,
        "rollback_plan": {},
    }


def test_phase1_execution_overrides_and_legacy_defaults(tmp_path, monkeypatch):
    script = tmp_path / "phase1.py"
    script.write_text(
        "import os, pathlib, sys\n"
        "pathlib.Path('cwd-effect.txt').write_text(os.getcwd())\n"
        "print(os.environ.get('PHASE1_VALUE', 'inherited'))\n"
        "print('phase1-err', file=sys.stderr)\n",
        encoding="utf-8",
    )
    argv = [sys.executable, str(script)]

    explicit_cwd = tmp_path / "explicit-cwd"
    explicit_cwd.mkdir()
    explicit_ledger = tmp_path / "explicit-ledger.db"
    explicit = _bound_result(explicit_ledger, argv, explicit_cwd)
    outcome = {}
    with tempfile.TemporaryFile("w+b") as stdout, tempfile.TemporaryFile("w+b") as stderr:
        code = cli._execute_approved(
            explicit["action"]["command"], "exec", explicit,
            argv=argv, ledger_path=str(explicit_ledger),
            execution_cwd=str(explicit_cwd), stdout=stdout, stderr=stderr,
            env={"PHASE1_VALUE": "explicit-value"}, outcome=outcome,
        )
        stdout.seek(0)
        stderr.seek(0)
        assert stdout.read().decode().strip() == "explicit-value"
        assert stderr.read().decode().strip() == "phase1-err"
    assert code == 0
    assert outcome["claim_status"] == "CLAIMED_NEW"
    assert len(outcome["claim_hash"]) == 64
    assert (explicit_cwd / "cwd-effect.txt").read_text() == str(explicit_cwd)

    legacy_cwd = tmp_path / "legacy-cwd"
    legacy_cwd.mkdir()
    legacy_ledger = tmp_path / "legacy-ledger.db"
    monkeypatch.chdir(legacy_cwd)
    monkeypatch.setattr(cli, "LEDGER", str(legacy_ledger))
    legacy = _bound_result(legacy_ledger, argv, legacy_cwd)
    assert cli._execute_approved(
        legacy["action"]["command"], "exec", legacy, argv=argv
    ) == 0
    assert (legacy_cwd / "cwd-effect.txt").read_text() == str(legacy_cwd)


def test_first_effect_exact_retry_env_and_transport_isolation(
    broker, tmp_path, monkeypatch, capsys
):
    script = _script(tmp_path)
    monkeypatch.setenv("BROKER_TEST_VALUE", "allowlisted-caller-value")
    monkeypatch.setenv("BROKER_API_SECRET", "must-not-leak")
    preflight = _preflight(broker, "once", tmp_path, script)

    first = broker.execute_preflight("once")
    leaked = capsys.readouterr()
    assert leaked.out == leaked.err == ""
    assert first["state"] == "TERMINAL"
    assert first["exit_code"] == 0
    # Neither variable is broker-allowlisted, regardless of its innocuous value.
    assert "child-out:missing" in first["stdout"]
    assert "secret:absent" in first["stderr"]
    assert isinstance(first["stdout"], str)
    assert first["stdout_bytes"] == len(first["stdout"].encode())
    assert not first["stdout_truncated"]
    assert (tmp_path / "effect.txt").read_text() == "x"

    second = broker.execute_preflight("once")
    assert second["state"] == "CACHED"
    assert second["cached"] is True
    assert second["preflight_hash"] == preflight["preflight_hash"]
    assert (tmp_path / "effect.txt").read_text() == "x"


def test_allowlisted_parent_value_is_available(broker, tmp_path, monkeypatch):
    script = tmp_path / "path.py"
    script.write_text("import os; print(os.environ.get('PATH', ''))\n", encoding="utf-8")
    monkeypatch.setenv("PATH", "broker-safe-path")
    _preflight(broker, "env", tmp_path, script)
    result = broker.execute_preflight("env")
    assert result["stdout"].strip() == "broker-safe-path"


def test_changed_action_is_held(broker, tmp_path):
    script = _script(tmp_path)
    original = _preflight(broker, "identity", tmp_path, script)
    changed = broker.preflight_exec(
        "identity", [sys.executable, str(script), "changed"], str(tmp_path)
    )
    assert changed["state"] == "HELD"
    assert changed["preflight_hash"] == original["preflight_hash"]
    assert not (tmp_path / "effect.txt").exists()


@pytest.mark.parametrize("tamper", ["registry", "preflight", "action", "cwd"])
def test_registry_preflight_action_and_cwd_tamper_fail_closed(
    broker, tmp_path, tamper, monkeypatch
):
    script = _script(tmp_path)
    preflight = _preflight(broker, "tamper", tmp_path, script)
    with sqlite3.connect(broker.registry_path) as con:
        if tamper == "registry":
            con.execute(
                "UPDATE broker_requests SET action_sha256=?",
                ("0" * 64,),
            )
        elif tamper == "preflight":
            con.execute(
                "UPDATE broker_requests SET preflight_hash=?",
                ("0" * 64,),
            )
        con.commit()
    if tamper in ("action", "cwd"):
        with sqlite3.connect(broker.ledger_path) as con:
            row = con.execute(
                "SELECT payload FROM events WHERE hash=?",
                (preflight["preflight_hash"],),
            ).fetchone()
            payload = json.loads(row[0])
            if tamper == "action":
                payload["action"]["args"].append("tampered")
            else:
                payload["action"]["cwd"] = str(tmp_path / "other-cwd")
            con.execute(
                "UPDATE events SET payload=? WHERE hash=?",
                (json.dumps(payload), preflight["preflight_hash"]),
            )
            con.commit()
    called = []
    monkeypatch.setattr(cli, "_execute_approved", lambda **kwargs: called.append(kwargs))
    assert broker.execute_preflight("tamper")["state"] == "HELD"
    assert called == []
    assert not (tmp_path / "effect.txt").exists()


def test_concurrent_calls_have_one_physical_effect(
    broker, tmp_path, monkeypatch
):
    script = _script(tmp_path)
    _preflight(broker, "race", tmp_path, script)
    calls = 0
    calls_lock = threading.Lock()
    execute = cli._execute_approved

    def counted(**kwargs):
        nonlocal calls
        with calls_lock:
            calls += 1
        return execute(**kwargs)

    monkeypatch.setattr(cli, "_execute_approved", counted)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: broker.execute_preflight("race"), range(2)))
    assert sorted(result["state"] for result in results) == ["CACHED", "TERMINAL"]
    assert calls == 1
    assert (tmp_path / "effect.txt").read_text() == "x"


def test_distinct_brokers_concurrent_execute_has_one_owner(broker, tmp_path):
    script = tmp_path / "slow-effect.py"
    script.write_text(
        "import pathlib, time\n"
        "time.sleep(0.2)\n"
        "p = pathlib.Path('effect.txt')\n"
        "p.write_text(p.read_text() + 'x' if p.exists() else 'x')\n",
        encoding="utf-8",
    )
    _preflight(broker, "distinct-race", tmp_path, script)
    other = GateBroker(broker.registry_path, broker.ledger_path)

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [
            pool.submit(instance.execute_preflight, "distinct-race")
            for instance in (broker, other)
        ]
        results = [future.result() for future in futures]

    owners = [
        result for result in results
        if result["state"] == "TERMINAL"
        and result.get("cached") is False
        and result.get("executed") is True
    ]
    assert len(owners) == 1
    assert all(
        result["state"] in ("TERMINAL", "CACHED", "HELD")
        for result in results
    )
    assert (tmp_path / "effect.txt").read_text() == "x"


def test_distinct_brokers_serialize_global_stdio_redirects(
    broker, tmp_path, monkeypatch, capsys
):
    other = GateBroker(broker.registry_path, broker.ledger_path)
    for index in range(2):
        script = tmp_path / f"output-{index}.py"
        script.write_text(
            f"import sys\nprint('child-out-{index}')\n"
            f"print('child-err-{index}', file=sys.stderr)\n",
            encoding="utf-8",
        )
        _preflight(broker, f"stdio-{index}", tmp_path, script)

    original_stdout, original_stderr = sys.stdout, sys.stderr
    execute = cli._execute_approved

    def noisy(**kwargs):
        marker = kwargs["result"]["ledger_hash"]
        print("status-out-" + marker)
        print("status-err-" + marker, file=sys.stderr)
        time.sleep(0.1)
        return execute(**kwargs)

    monkeypatch.setattr(cli, "_execute_approved", noisy)
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [
            pool.submit(instance.execute_preflight, f"stdio-{index}")
            for index, instance in enumerate((broker, other))
        ]
        results = [future.result() for future in futures]

    leaked = capsys.readouterr()
    assert leaked.out == leaked.err == ""
    assert sys.stdout is original_stdout
    assert sys.stderr is original_stderr
    for index, result in enumerate(results):
        assert result["state"] == "TERMINAL"
        assert result["stdout"].strip() == f"child-out-{index}"
        assert result["stderr"].strip() == f"child-err-{index}"
        assert result["status_stdout"].strip() == (
            "status-out-" + result["preflight_hash"]
        )
        assert result["status_stderr"].strip() == (
            "status-err-" + result["preflight_hash"]
        )


@pytest.mark.parametrize("losing_status", ["CLAIMED", "ATTEMPT_STARTED"])
def test_losing_claim_does_not_adopt_winners_terminal(
    broker, tmp_path, monkeypatch, losing_status
):
    script = _script(tmp_path)
    _preflight(broker, "provenance-race", tmp_path, script)
    execute = cli._execute_approved
    entered = threading.Event()
    release = threading.Event()
    captured_kwargs = {}

    def losing_core(**kwargs):
        captured_kwargs.update(kwargs)
        entered.set()
        assert release.wait(timeout=10)
        kwargs["outcome"]["claim_status"] = losing_status
        return 1

    monkeypatch.setattr(cli, "_execute_approved", losing_core)
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(broker.execute_preflight, "provenance-race")
        assert entered.wait(timeout=10)
        owner_outcome = {}
        with tempfile.TemporaryFile("w+b") as owner_out:
            with tempfile.TemporaryFile("w+b") as owner_err:
                owner_kwargs = dict(captured_kwargs)
                owner_kwargs.update(
                    stdout=owner_out, stderr=owner_err, outcome=owner_outcome,
                )
                assert execute(**owner_kwargs) == 0
        release.set()
        result = future.result(timeout=10)

    assert owner_outcome["claim_status"] == "CLAIMED_NEW"
    assert len(owner_outcome["claim_hash"]) == 64
    assert result["state"] == "HELD"
    assert "this caller did not execute" in result["reasons"][0]
    assert not result.get("executed", False)
    assert result.get("cached") is not False
    assert (tmp_path / "effect.txt").read_text() == "x"


def test_child_and_status_output_isolated_and_bounded(
    broker, tmp_path, monkeypatch, capsys
):
    script = tmp_path / "large-output.py"
    script.write_text(
        "import sys\n"
        "sys.stdout.buffer.write(b'o' * 70000 + b'\\xff')\n"
        "sys.stderr.buffer.write(b'e' * 70000 + b'\\xff')\n",
        encoding="utf-8",
    )
    _preflight(broker, "large-output", tmp_path, script)
    execute = cli._execute_approved

    def noisy(**kwargs):
        print("s" * 70000)
        print("t" * 70000, file=sys.stderr)
        return execute(**kwargs)

    monkeypatch.setattr(cli, "_execute_approved", noisy)
    result = broker.execute_preflight("large-output")
    leaked = capsys.readouterr()
    assert leaked.out == leaked.err == ""
    assert result["state"] == "TERMINAL"
    for field in ("stdout", "stderr", "status_stdout", "status_stderr"):
        assert isinstance(result[field], str)
        assert len(result[field].encode("utf-8")) <= 64 * 1024
        assert result[field + "_bytes"] > 64 * 1024
        assert result[field + "_truncated"] is True
    json.dumps(result)


def test_orphaned_claim_is_held_through_broker(broker, tmp_path):
    script = _script(tmp_path)
    preflight = _preflight(broker, "orphan", tmp_path, script)
    with Ledger(broker.ledger_path) as ledger:
        ledger.append("attempt_claimed", {
            "preflight_hash": preflight["preflight_hash"],
            "binding_sha256": "1" * 64,
            "phase": "CLAIMED",
        })
    result = broker.execute_preflight("orphan")
    assert result["state"] == "HELD"
    assert "no verified terminal state" in result["reasons"][0]
    assert "orphaned prior claim" in result["status_stdout"]
    assert not (tmp_path / "effect.txt").exists()
