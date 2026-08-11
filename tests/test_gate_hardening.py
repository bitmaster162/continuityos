import json
import os
import sqlite3
import subprocess
import threading
import builtins
from concurrent.futures import ThreadPoolExecutor

import pytest

from continuityos.gate import ActionSpec, Ledger, preflight
from continuityos.gate.policy import (
    DEFAULT_POLICY,
    PolicyError,
    default_policy,
    discover_policy,
    load_policy,
)


def test_json_policy_deep_merge_and_default_isolation(tmp_path):
    path = tmp_path / "policy.json"
    path.write_text(json.dumps({
        "version": "test",
        "severity_decision": {"high": "DENY"},
    }), encoding="utf-8")
    loaded = load_policy(str(path))
    assert loaded["severity_decision"]["high"] == "DENY"
    assert loaded["severity_decision"]["medium"] == "REQUIRE_CONFIRMATION"
    loaded["allowed_tools"].append("mutated")
    assert "mutated" not in DEFAULT_POLICY["allowed_tools"]


def test_policy_rejects_severity_typo_and_ambiguous_files(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"severity_decision": {"critcal": "DENY"}}), encoding="utf-8")
    with pytest.raises(PolicyError):
        load_policy(str(bad))
    (tmp_path / "policy.json").write_text("{}", encoding="utf-8")
    (tmp_path / "policy.yaml").write_text("version: test\n", encoding="utf-8")
    with pytest.raises(PolicyError):
        discover_policy(str(tmp_path))


def test_yaml_without_optional_parser_fails_closed(tmp_path, monkeypatch):
    path = tmp_path / "policy.yaml"
    path.write_text("version: test\n", encoding="utf-8")
    real_import = builtins.__import__

    def without_yaml(name, *args, **kwargs):
        if name == "yaml":
            raise ImportError("injected missing dependency")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", without_yaml)
    with pytest.raises(PolicyError, match="policy.json"):
        load_policy(str(path))


def test_policy_rejects_malformed_nested_schema(tmp_path):
    path = tmp_path / "policy.json"
    path.write_text(json.dumps({
        "tool_schemas": {"http": {"allowed_domains": "example.com"}},
        "capabilities": {"agent": {"max_paths": -1}},
    }), encoding="utf-8")
    with pytest.raises(PolicyError):
        load_policy(str(path))


@pytest.mark.parametrize(
    ("payload", "field_path"),
    [
        ({"typo": True}, "policy.typo"),
        ({"severity_decision": {"critcal": "DENY"}}, "policy.severity_decision.critcal"),
        ({"tool_schemas": {"shell": {"max_argz": 2}}}, "policy.tool_schemas.shell.max_argz"),
        ({"capabilities": {"agent": {"toolz": ["shell"]}}}, "policy.capabilities.agent.toolz"),
    ],
)
def test_policy_rejects_unknown_fields_with_exact_paths(tmp_path, payload, field_path):
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(PolicyError, match=field_path.replace(".", r"\.")):
        load_policy(str(path))


def test_cli_init_writes_and_uses_zero_dependency_json_policy(tmp_path, monkeypatch):
    import continuityos.gate.cli as cli

    home = tmp_path / "home"
    monkeypatch.setattr(cli, "HOME", str(home))
    monkeypatch.setattr(cli, "LEDGER", str(home / "ledger.db"))
    monkeypatch.setattr(cli, "POLICY", str(home / "policy.yaml"))
    monkeypatch.setattr(cli, "POLICY_JSON", str(home / "policy.json"))
    assert cli.main(["init"]) == 0
    policy_path = home / "policy.json"
    assert policy_path.is_file()
    policy = json.loads(policy_path.read_text(encoding="utf-8"))
    policy["default_decision"] = "DENY"
    policy_path.write_text(json.dumps(policy), encoding="utf-8")
    result, _ = cli._decide("echo ok", tool="exec")
    assert result["decision"] == "DENY"
    assert result["policy"]["sha256"]


def test_cli_policy_parse_error_holds_instead_of_falling_back(tmp_path, monkeypatch):
    import continuityos.gate.cli as cli

    home = tmp_path / "home"
    home.mkdir()
    (home / "policy.json").write_text("{not-json", encoding="utf-8")
    monkeypatch.setattr(cli, "HOME", str(home))
    monkeypatch.setattr(cli, "LEDGER", str(home / "ledger.db"))
    result, _ = cli._decide("echo ok", tool="exec")
    assert result["decision"] == "HOLD"
    assert any("policy load failed" in reason for reason in result["reasons"])


def test_mcp_preflight_schema_and_adapter_propagate_cwd_and_context(monkeypatch):
    import continuityos.mcp_server as mcp

    tool = next(tool for tool in mcp.TOOLS if tool["name"] == "preflight_action")
    assert "cwd" in tool["inputSchema"]["properties"]
    assert "args" in tool["inputSchema"]["properties"]
    assert "args" in tool["inputSchema"]["required"]
    captured = {}

    class DummyLedger:
        def __init__(self, path):
            captured["ledger_path"] = path

        def __enter__(self):
            return self

        def __exit__(self, *args):
            captured["ledger_closed"] = True

    def fake_preflight(spec, policy, ledger, context):
        captured.update({"spec": spec, "policy": policy, "context": context})
        return {"decision": "HOLD"}

    monkeypatch.setattr(mcp, "_Ledger", DummyLedger)
    monkeypatch.setattr(mcp, "_preflight", fake_preflight)
    server = object.__new__(mcp.Server)
    server.turns = 0
    server.policy = {"version": "test"}
    server.c = object()
    server._governance_context_error = ""
    result = json.loads(server.call("preflight_action", {
        "tool": "file.delete",
        "command": "rm target.txt",
        "paths": ["target.txt"],
        "args": ["rm", "target.txt"],
        "cwd": "/authoritative/workdir",
    }))
    assert result["decision"] == "HOLD"
    assert captured["spec"].cwd == "/authoritative/workdir"
    assert captured["spec"].args == ["rm", "target.txt"]
    assert captured["context"] is server.c
    assert captured["ledger_closed"] is True


def test_mcp_exact_args_enforce_max_args_through_preflight(tmp_path, monkeypatch):
    import continuityos.mcp_server as mcp

    server = object.__new__(mcp.Server)
    server.turns = 0
    server.policy = default_policy()
    server.policy["tool_schemas"] = {"exec": {"max_args": 1}}
    server.c = None
    server._governance_context_error = ""
    monkeypatch.setattr(
        mcp, "_Ledger", lambda _path: Ledger(str(tmp_path / "mcp-ledger.db"))
    )
    result = json.loads(server.call("preflight_action", {
        "tool": "exec",
        "command": "python --version",
        "args": ["python", "--version"],
        "cwd": os.getcwd(),
    }))
    assert result["action"]["args"] == ["python", "--version"]
    assert result["decision"] == "REQUIRE_CONFIRMATION"
    assert any("arg-count 2 > max 1" in reason for reason in result["reasons"])


@pytest.mark.parametrize("bad_args", [None, "python --version"])
def test_mcp_missing_or_non_vector_args_hold(tmp_path, monkeypatch, bad_args):
    import continuityos.mcp_server as mcp

    server = object.__new__(mcp.Server)
    server.turns = 0
    server.policy = default_policy()
    server.c = None
    server._governance_context_error = ""
    monkeypatch.setattr(
        mcp, "_Ledger", lambda _path: Ledger(str(tmp_path / "mcp-ledger.db"))
    )
    call_args = {
        "tool": "exec",
        "command": "python --version",
        "cwd": os.getcwd(),
    }
    if bad_args is not None:
        call_args["args"] = bad_args
    result = json.loads(server.call("preflight_action", call_args))
    assert result["decision"] == "HOLD"
    assert result["action"]["args"] == bad_args
    assert any("ActionSpec.args" in reason for reason in result["reasons"])


def test_mcp_partial_server_state_fails_closed(tmp_path, monkeypatch):
    import continuityos.mcp_server as mcp

    server = object.__new__(mcp.Server)
    server.turns = 0
    server.policy = default_policy()
    server.c = None
    monkeypatch.setattr(
        mcp, "_Ledger", lambda _path: Ledger(str(tmp_path / "mcp-ledger.db"))
    )
    result = json.loads(server.call("preflight_action", {
        "tool": "exec",
        "command": (
            subprocess.list2cmdline(["python", "--version"])
            if os.name == "nt"
            else "python --version"
        ),
        "args": ["python", "--version"],
        "cwd": str(tmp_path),
    }))
    assert result["decision"] == "HOLD"
    assert "initialization state unavailable" in result["context"]["error"]


def test_mcp_preflight_recomputes_context_digest_after_canon_write(
    tmp_path, monkeypatch
):
    import continuityos.mcp_server as mcp

    server = mcp.Server(str(tmp_path / "memory.db"))
    monkeypatch.setattr(
        mcp, "_Ledger", lambda _path: Ledger(str(tmp_path / "mcp-ledger.db"))
    )
    request = {
        "tool": "exec",
        "command": "python --version",
        "args": ["python", "--version"],
        "cwd": str(tmp_path),
    }
    try:
        before = json.loads(server.call("preflight_action", request))
        server.m.remember("Never bypass the broker.", namespace="canon")
        after = json.loads(server.call("preflight_action", request))
        assert before["context"]["identity"]["row_count"] == 0
        assert after["context"]["identity"]["row_count"] == 1
        assert (
            before["context"]["identity"]["context_sha256"]
            != after["context"]["identity"]["context_sha256"]
        )
    finally:
        server.m.store.con.close()


def test_mcp_configured_missing_db_holds_until_intentional_restart(
    tmp_path, monkeypatch
):
    import continuityos.mcp_server as mcp

    db = tmp_path / "new-authority.db"
    monkeypatch.setattr(
        mcp, "_Ledger", lambda _path: Ledger(str(tmp_path / "mcp-ledger.db"))
    )
    request = {
        "tool": "exec",
        "command": (
            subprocess.list2cmdline(["python", "--version"])
            if os.name == "nt"
            else "python --version"
        ),
        "args": ["python", "--version"],
        "cwd": str(tmp_path),
    }
    first = mcp.Server(str(db))
    try:
        held = json.loads(first.call("preflight_action", request))
        assert held["decision"] == "HOLD"
        assert "missing at server startup" in held["context"]["error"]
    finally:
        first.m.store.con.close()
    restarted = mcp.Server(str(db))
    try:
        ready = json.loads(restarted.call("preflight_action", request))
        assert "missing at server startup" not in (ready["context"]["error"] or "")
    finally:
        restarted.m.store.con.close()


def test_exec_binds_and_classifies_the_exact_argument_vector(tmp_path):
    destructive = preflight(ActionSpec(
        tool="exec",
        command="echo ok",
        args=["rm", "-rf", "/"],
        cwd=str(tmp_path),
    ))
    assert destructive["decision"] == "DENY"
    assert any("argument vector" in reason for reason in destructive["reasons"])
    assert any("rm_rf" in reason for reason in destructive["reasons"])

    policy = default_policy()
    policy["protected_paths"] = []
    matching = preflight(ActionSpec(
        tool="exec",
        command=(
            subprocess.list2cmdline(["python", "--version"])
            if os.name == "nt"
            else "python --version"
        ),
        args=["python", "--version"],
        cwd=str(tmp_path),
    ), policy=policy)
    assert matching["decision"] == "ALLOW"


def test_concurrent_ledger_appends_form_one_linear_chain(tmp_path):
    path = str(tmp_path / "ledger.db")
    with Ledger(path):
        pass
    workers = 8
    barrier = threading.Barrier(workers)

    def append(worker):
        with Ledger(path) as ledger:
            barrier.wait(timeout=10)
            for sequence in range(4):
                ledger.append("test", {"worker": worker, "sequence": sequence})

    with ThreadPoolExecutor(max_workers=workers) as pool:
        list(pool.map(append, range(workers)))
    with Ledger(path) as ledger:
        assert ledger.verify() == {"ok": True, "verified": workers * 4}


def test_context_evaluation_error_is_hold():
    result = preflight(ActionSpec(tool="exec", command="echo ok"), context=object())
    assert result["decision"] == "HOLD"
    assert result["context"]["error"]


def test_generic_and_windows_deletes_are_not_silent_allow(tmp_path):
    ordinary = tmp_path / "ordinary.txt"
    ordinary.write_text("x", encoding="utf-8")
    ordinary_policy = default_policy()
    ordinary_policy["protected_paths"] = []
    result = preflight(ActionSpec(
        tool="shell", command="rm ordinary.txt", paths=["ordinary.txt"], cwd=str(tmp_path)
    ), policy=ordinary_policy)
    assert result["decision"] == "REQUIRE_CONFIRMATION"
    typed = preflight(ActionSpec(
        tool="file.delete", command="", paths=[str(ordinary)], cwd=str(tmp_path)
    ), policy=ordinary_policy)
    assert typed["decision"] == "REQUIRE_CONFIRMATION"
    windows = preflight(ActionSpec(
        tool="shell",
        command=r"Remove-Item -Recurse -Force C:\temp\target",
        paths=[r"C:\temp\target"],
        cwd=str(tmp_path),
    ))
    assert windows["decision"] == "DENY"


def test_protected_delete_is_not_ordinary_confirmation(tmp_path):
    protected = tmp_path / ".env"
    protected.write_text("secret", encoding="utf-8")
    policy = default_policy()
    policy["protected_paths"] = [str(protected)]
    shell = preflight(ActionSpec(
        tool="shell", command=f"rm {protected}", paths=[str(protected)], cwd=str(tmp_path)
    ), policy=policy)
    typed = preflight(ActionSpec(
        tool="file.delete", command="", paths=[str(protected)], cwd=str(tmp_path)
    ), policy=policy)
    assert shell["decision"] == typed["decision"] == "DRY_RUN_ONLY"
    assert shell["rollback_plan"]["snapshot_required"] is False


@pytest.mark.parametrize(
    "command",
    [
        "rm .env",
        "unlink .env",
        "echo ok;rm .env",
        "echo ok&&rm .env",
        "echo ok|rm .env",
        "sudo rm .env",
        "command rm .env",
        "env X=1 rm .env",
        "powershell Remove-Item .env",
        "cmd /c del .env",
        "ri .env",
        "rd /s /q .env",
        "powershell -Command \"Remove-Item .env\"",
        "cmd /c \"del .env\"",
        "bash -c 'rm .env'",
        "sh -c 'unlink .env'",
        "Microsoft.PowerShell.Management\\Remove-Item .env",
        "(rm .env)",
        "$(rm .env)",
        "bash -c '(rm .env)'",
        "cmd /c \"(del .env)\"",
        "powershell -Command \"&(Remove-Item .env)\"",
        chr(96) + "rm .env" + chr(96),
        "/bin/rm .env",
        "/usr/bin/unlink .env",
        "./rm .env",
        "command /bin/rm .env",
        "srm .env",
        "wipe .env",
        "sdelete .env",
        "sdelete64.exe .env",
        "shred -u .env",
        "truncate -s 0 .env",
        "echo x > .env",
        "> .env",
        "git clean -f .env",
    ],
)
def test_protected_erasure_aliases_and_shell_boundaries_are_dry_only(
    tmp_path, command
):
    target = tmp_path / ".env"
    target.write_text("secret", encoding="utf-8")
    policy = default_policy()
    policy["protected_paths"] = [str(target)]
    result = preflight(
        ActionSpec(
            tool="shell",
            command=command,
            paths=[".env"],
            cwd=str(tmp_path),
        ),
        policy=policy,
    )
    assert result["decision"] == "DRY_RUN_ONLY", (command, result)
    assert result["rollback_plan"]["snapshot_required"] is False


@pytest.mark.parametrize(
    ("tool", "command"),
    [
        ("shell", "cat .env"),
        ("shell", "echo x >> .env"),
        ("shell", "< .env"),
        ("file.write", "write .env"),
    ],
)
def test_protected_non_erasing_actions_do_not_claim_dry_run(tmp_path, tool, command):
    target = tmp_path / ".env"
    target.write_text("secret", encoding="utf-8")
    policy = default_policy()
    policy["protected_paths"] = [str(target)]
    result = preflight(
        ActionSpec(tool=tool, command=command, paths=[".env"], cwd=str(tmp_path)),
        policy=policy,
    )
    assert result["decision"] == "REQUIRE_CONFIRMATION"


def test_protected_dry_run_can_be_disabled_only_by_policy(tmp_path):
    target = tmp_path / ".env"
    target.write_text("secret", encoding="utf-8")
    policy = default_policy()
    policy["protected_paths"] = [str(target)]
    policy["dry_run_on_protected_delete"] = False
    result = preflight(
        ActionSpec(
            tool="shell", command="rm .env", paths=[".env"], cwd=str(tmp_path)
        ),
        policy=policy,
    )
    assert result["decision"] == "REQUIRE_CONFIRMATION"


@pytest.mark.parametrize("cwd", ["", ".", "relative/work"])
def test_relative_mutation_without_authoritative_cwd_holds(cwd):
    result = preflight(
        ActionSpec(
            tool="shell",
            command="rm ordinary.txt",
            paths=["ordinary.txt"],
            cwd=cwd,
        )
    )
    assert result["decision"] == "HOLD"
    assert any("authoritative cwd" in reason for reason in result["reasons"])


def test_absolute_cwd_is_preserved_as_authoritative(tmp_path):
    policy = default_policy()
    policy["protected_paths"] = []
    result = preflight(
        ActionSpec(
            tool="shell",
            command="touch new.txt",
            paths=["new.txt"],
            cwd=str(tmp_path),
        ),
        policy=policy,
    )
    assert result["decision"] != "HOLD"
    assert result["action"]["cwd"] == str(tmp_path)


def test_protected_paths_resolve_traversal_and_symlink(tmp_path):
    git_dir = tmp_path / ".git"
    git_dir.mkdir()
    (git_dir / "config").write_text("x", encoding="utf-8")
    result = preflight(ActionSpec(
        tool="file.read", command="read", paths=["sub/../.git/config"], cwd=str(tmp_path)
    ))
    assert result["decision"] == "REQUIRE_CONFIRMATION"

    protected = tmp_path / "protected"
    protected.mkdir()
    (protected / "secret.txt").write_text("x", encoding="utf-8")
    link = tmp_path / "link"
    try:
        link.symlink_to(protected, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are not available for this user/platform")
    policy = default_policy()
    policy["protected_paths"] = [str(protected / "*")]
    linked = preflight(ActionSpec(
        tool="file.read", command="read", paths=[str(link / "secret.txt")], cwd=str(tmp_path)
    ), policy=policy)
    assert linked["decision"] == "REQUIRE_CONFIRMATION"


def test_allowed_root_rejects_prefix_sibling(tmp_path):
    root = tmp_path / "allowed"
    sibling = tmp_path / "allowed_evil"
    root.mkdir()
    sibling.mkdir()
    policy = default_policy()
    policy["tool_schemas"] = {"file.write": {"allowed_roots": [str(root)]}}
    result = preflight(ActionSpec(
        tool="file.write", command="write", paths=[str(sibling / "x.txt")], cwd=str(tmp_path)
    ), policy=policy)
    assert any("outside allowed roots" in reason for reason in result["reasons"])
    assert result["decision"] == "REQUIRE_CONFIRMATION"


def test_allowed_domain_matches_hostname_boundary_not_substring():
    policy = default_policy()
    policy["tool_schemas"] = {"http": {"allowed_domains": ["example.com"]}}
    valid = preflight(ActionSpec(
        tool="http", command="https://api.example.com/upload"
    ), policy=policy)
    assert valid["decision"] == "ALLOW"
    deceptive = preflight(ActionSpec(
        tool="http", command="https://example.com.evil.test/upload"
    ), policy=policy)
    assert deceptive["decision"] == "REQUIRE_CONFIRMATION"
    assert any("not in allowed domains" in reason for reason in deceptive["reasons"])


def test_preflight_is_snapshot_free_and_executor_materializes(tmp_path, monkeypatch):
    import continuityos.gate.cli as cli
    import continuityos.gate.rollback as rollback

    monkeypatch.setattr(rollback, "SNAP_ROOT", str(tmp_path / "snapshots"))
    monkeypatch.setattr(cli, "LEDGER", str(tmp_path / "ledger.db"))
    target = tmp_path / "ordinary.txt"
    target.write_text("before", encoding="utf-8")
    policy = default_policy()
    policy["protected_paths"] = []
    result = preflight(ActionSpec(
        tool="shell", command=f"rm {target}", paths=[str(target)], cwd=str(tmp_path)
    ), policy=policy)
    assert result["rollback_plan"]["snapshot_required"] is True
    assert result["rollback_plan"]["restorable"] is False
    assert not (tmp_path / "snapshots").exists()
    assert cli._materialize_rollback(result) is True
    assert result["rollback_plan"]["restorable"] is True
    assert len(result["rollback_plan"]["receipt_hash"]) == 64
    target.write_text("after", encoding="utf-8")
    restored = rollback.restore(result["rollback_plan"]["snapshot_id"])
    assert restored["ok"] is True
    assert target.read_text(encoding="utf-8") == "before"


def test_executor_aborts_when_required_snapshot_is_unsupported(tmp_path, monkeypatch):
    import continuityos.gate.cli as cli
    import continuityos.gate.rollback as rollback

    directory = tmp_path / "directory"
    directory.mkdir()
    monkeypatch.setattr(rollback, "SNAP_ROOT", str(tmp_path / "snapshots"))
    monkeypatch.setattr(cli, "LEDGER", str(tmp_path / "ledger.db"))
    called = []
    monkeypatch.setattr(cli.subprocess, "call", lambda *a, **k: called.append((a, k)) or 0)
    result = {
        "action": {"tool": "shell", "command": "rmdir directory"},
        "rollback_plan": {"snapshot_required": True, "targets": [str(directory)]},
    }
    assert cli._execute_approved("rmdir directory", "exec", result) == 1
    assert called == []


def test_missing_file_snapshot_removes_created_file(tmp_path, monkeypatch):
    import continuityos.gate.rollback as rollback

    monkeypatch.setattr(rollback, "SNAP_ROOT", str(tmp_path / "snapshots"))
    target = tmp_path / "new.txt"
    snap = rollback.snapshot([str(target)], allow_missing_files=True)
    assert snap["restorable"] is True
    target.write_text("created", encoding="utf-8")
    result = rollback.restore(snap["id"])
    assert result["ok"] is True
    assert not target.exists()


def test_unbound_missing_target_and_glob_are_not_claimed_restorable(tmp_path, monkeypatch):
    import continuityos.gate.rollback as rollback

    monkeypatch.setattr(rollback, "SNAP_ROOT", str(tmp_path / "snapshots"))
    missing = tmp_path / "future"
    snap = rollback.snapshot([str(missing)])
    assert snap["restorable"] is False
    assert snap["errors"]
    with pytest.raises(ValueError, match="globs"):
        rollback.snapshot([str(tmp_path / "*.txt")])


def test_cli_holds_shell_wildcard_instead_of_issuing_mismatched_receipt(tmp_path, monkeypatch):
    import continuityos.gate.cli as cli
    import continuityos.gate.rollback as rollback

    monkeypatch.setattr(rollback, "SNAP_ROOT", str(tmp_path / "snapshots"))
    monkeypatch.setattr(cli, "LEDGER", str(tmp_path / "ledger.db"))
    first = tmp_path / "first.txt"
    second = tmp_path / "second.txt"
    first.write_text("one", encoding="utf-8")
    second.write_text("two", encoding="utf-8")
    pattern = str(tmp_path / "*.txt")
    policy = default_policy()
    policy["protected_paths"] = []
    result = preflight(ActionSpec(
        tool="shell", command=f"rm {pattern}", paths=[pattern], cwd=str(tmp_path)
    ), policy=policy)
    assert cli._materialize_rollback(result) is False
    assert first.read_text(encoding="utf-8") == "one"
    assert second.read_text(encoding="utf-8") == "two"


def test_recursive_directory_copy_cannot_get_missing_file_receipt(tmp_path, monkeypatch):
    import continuityos.gate.cli as cli
    import continuityos.gate.rollback as rollback

    monkeypatch.setattr(rollback, "SNAP_ROOT", str(tmp_path / "snapshots"))
    monkeypatch.setattr(cli, "LEDGER", str(tmp_path / "ledger.db"))
    source = tmp_path / "source"
    source.mkdir()
    target = tmp_path / "destination"
    result = preflight(ActionSpec(
        tool="shell",
        command=f"cp -r {source} {target}",
        paths=[str(source), str(target)],
        cwd=str(tmp_path),
    ))
    assert result["rollback_plan"]["targets"] == [str(target)]
    assert result["rollback_plan"]["allow_missing_files"] is False
    assert cli._materialize_rollback(result) is False
    assert not target.exists()


def test_missing_directory_creation_cannot_get_false_rollback_receipt(tmp_path, monkeypatch):
    import continuityos.gate.cli as cli
    import continuityos.gate.rollback as rollback

    monkeypatch.setattr(rollback, "SNAP_ROOT", str(tmp_path / "snapshots"))
    monkeypatch.setattr(cli, "LEDGER", str(tmp_path / "ledger.db"))
    target = tmp_path / "new-directory"
    result = preflight(ActionSpec(
        tool="shell", command=f"mkdir {target}", paths=[str(target)], cwd=str(tmp_path)
    ))
    assert result["rollback_plan"]["allow_missing_files"] is False
    assert cli._materialize_rollback(result) is False
    assert not target.exists()


def test_sqlite_wal_snapshot_restores_committed_state(tmp_path, monkeypatch):
    import continuityos.gate.rollback as rollback

    monkeypatch.setattr(rollback, "SNAP_ROOT", str(tmp_path / "snapshots"))
    db = tmp_path / "live.db"
    con = sqlite3.connect(db)
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA wal_autocheckpoint=0")
    con.execute("CREATE TABLE items(value TEXT)")
    con.execute("INSERT INTO items VALUES ('snapshot')")
    con.commit()
    snap = rollback.snapshot([str(db)])
    assert snap["restorable"] is True
    con.execute("INSERT INTO items VALUES ('later')")
    con.commit()
    con.close()
    # A stale sidecar must not be replayed over the restored main DB.
    for suffix in ("-wal", "-shm"):
        sidecar = str(db) + suffix
        if not os.path.exists(sidecar):
            open(sidecar, "wb").write(b"stale")
    assert rollback.restore(snap["id"])["ok"] is True
    with sqlite3.connect(db) as restored:
        assert restored.execute("SELECT value FROM items").fetchall() == [("snapshot",)]


def test_corrupt_manifest_cannot_turn_empty_path_into_cwd_delete(tmp_path, monkeypatch):
    import continuityos.gate.rollback as rollback

    snap_root = tmp_path / "snapshots"
    monkeypatch.setattr(rollback, "SNAP_ROOT", str(snap_root))
    absent = tmp_path / "absent.txt"
    snap = rollback.snapshot([str(absent)], allow_missing_files=True)
    manifest_path = snap_root / snap["id"] / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["items"][0]["original"] = ""
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    sentinel = tmp_path / "sentinel.txt"
    sentinel.write_text("safe", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    result = rollback.restore(snap["id"])
    assert result["ok"] is False
    assert sentinel.read_text(encoding="utf-8") == "safe"


def test_restore_copy_failure_leaves_original_untouched(tmp_path, monkeypatch):
    import continuityos.gate.rollback as rollback

    monkeypatch.setattr(rollback, "SNAP_ROOT", str(tmp_path / "snapshots"))
    target = tmp_path / "file.txt"
    target.write_text("snapshot", encoding="utf-8")
    snap = rollback.snapshot([str(target)])
    target.write_text("current", encoding="utf-8")

    def fail_copy(*args, **kwargs):
        raise OSError("injected copy failure")

    monkeypatch.setattr(rollback.shutil, "copy2", fail_copy)
    result = rollback.restore(snap["id"])
    assert result["ok"] is False
    assert target.read_text(encoding="utf-8") == "current"


def test_gate_db_identity_is_bound_to_result_and_ledger(tmp_path, monkeypatch):
    from continuityos import Continuity
    import continuityos.gate.cli as cli

    db = str(tmp_path / "authoritative.db")
    context = Continuity(db=db)
    context.add_canon("Never bypass the approved execution broker.")
    context.m.store.con.close()

    home = tmp_path / "gate-home"
    monkeypatch.setattr(cli, "HOME", str(home))
    monkeypatch.setattr(cli, "LEDGER", str(home / "ledger.db"))
    result, spec = cli._decide(
        "echo ok",
        tool="exec",
        args=["echo", "ok"],
        cwd=str(tmp_path),
        db=db,
    )
    identity = result["context"]["identity"]
    assert identity["path"] == os.path.normcase(os.path.abspath(db))
    assert identity["source"] == "explicit"
    assert len(identity["context_sha256"]) == 64
    assert identity["row_count"] == 1
    assert spec.cwd == str(tmp_path)
    with Ledger(cli.LEDGER) as ledger:
        event = next(
            item for item in ledger.export(20)
            if item["hash"] == result["ledger_hash"]
        )
    assert event["payload"]["context"] == result["context"]


def test_configured_missing_db_holds_without_creating_it(tmp_path, monkeypatch):
    import continuityos.gate.cli as cli

    missing = tmp_path / "missing.db"
    monkeypatch.setattr(cli, "HOME", str(tmp_path / "home"))
    monkeypatch.setattr(cli, "LEDGER", str(tmp_path / "home" / "ledger.db"))
    result, _ = cli._decide(
        "echo ok",
        tool="exec",
        args=["echo", "ok"],
        cwd=str(tmp_path),
        db=str(missing),
    )
    assert result["decision"] == "HOLD"
    assert "configured memory database not found" in result["context"]["error"]
    assert result["context"]["identity"] is None
    assert not missing.exists()


def test_caller_spoofed_context_identity_is_ignored(tmp_path):
    from continuityos import Continuity

    context = Continuity(db=str(tmp_path / "context.db"))
    context.add_canon("Never fabricate proof.")
    try:
        spec = ActionSpec(
            tool="exec",
            command="echo ok",
            args=["echo", "ok"],
            cwd=str(tmp_path),
            meta={"context_identity": {"context_sha256": "spoofed"}},
        )
        result = preflight(spec, context=context)
        assert result["context"]["identity"]["context_sha256"] != "spoofed"
        assert len(result["context"]["identity"]["context_sha256"]) == 64
    finally:
        context.m.store.con.close()


def _bound_execution_result(ledger_path, command, args, rollback_plan=None):
    rollback_plan = rollback_plan or {}
    action = {
        "tool": "exec",
        "command": command,
        "args": list(args),
        "paths": [],
        "cwd": os.getcwd(),
        "agent": "test",
        "meta": {},
    }
    with Ledger(str(ledger_path)) as ledger:
        preflight_hash = ledger.append("preflight", {
            "action": action,
            "decision": "ALLOW",
            "rollback_plan": rollback_plan,
        })
    return {
        "decision": "ALLOW",
        "action": action,
        "ledger_hash": preflight_hash,
        "rollback_plan": rollback_plan,
    }


def _execution_events(ledger_path):
    with Ledger(str(ledger_path)) as ledger:
        return [
            event for event in sorted(ledger.export(100), key=lambda item: item["id"])
            if event["kind"].startswith("execution_")
        ]


def test_execution_lifecycle_success_receipts(tmp_path, monkeypatch):
    import continuityos.gate.cli as cli

    ledger_path = tmp_path / "execution.db"
    monkeypatch.setattr(cli, "LEDGER", str(ledger_path))
    monkeypatch.setattr(cli.subprocess, "call", lambda *args, **kwargs: 0)
    command = "python --version"
    argv = ["python", "--version"]
    result = _bound_execution_result(ledger_path, command, argv)
    assert cli._execute_approved(command, "exec", result, argv=argv) == 0
    events = _execution_events(ledger_path)
    assert [event["kind"] for event in events] == [
        "execution_started", "execution_completed"
    ]
    started, completed = events
    assert completed["payload"]["execution_started_hash"] == started["hash"]
    assert completed["payload"]["exit_code"] == 0
    assert completed["payload"]["preflight_hash"] == result["ledger_hash"]
    assert completed["payload"]["action"] == result["action"]
    assert completed["payload"]["rollback_receipt"] == {
        "required": False, "status": "not_required"
    }


def test_execution_lifecycle_binds_materialized_snapshot_receipt(
    tmp_path, monkeypatch
):
    import continuityos.gate.cli as cli
    import continuityos.gate.rollback as rollback

    ledger_path = tmp_path / "snapshot-execution.db"
    monkeypatch.setattr(cli, "LEDGER", str(ledger_path))
    monkeypatch.setattr(rollback, "SNAP_ROOT", str(tmp_path / "snapshots"))
    monkeypatch.setattr(cli.subprocess, "call", lambda *args, **kwargs: 0)
    target = tmp_path / "target.txt"
    target.write_text("before", encoding="utf-8")
    command = "python --version"
    argv = ["python", "--version"]
    result = _bound_execution_result(
        ledger_path,
        command,
        argv,
        rollback_plan={
            "snapshot_required": True,
            "targets": [str(target)],
            "allow_missing_files": False,
        },
    )
    assert cli._execute_approved(command, "exec", result, argv=argv) == 0
    with Ledger(str(ledger_path)) as ledger:
        events = sorted(ledger.export(100), key=lambda item: item["id"])
    snapshot = next(event for event in events if event["kind"] == "rollback_snapshot")
    completed = next(
        event for event in events if event["kind"] == "execution_completed"
    )
    receipt = completed["payload"]["rollback_receipt"]
    assert receipt["status"] == "materialized"
    assert receipt["receipt_hash"] == snapshot["hash"]
    assert result["rollback_plan"]["receipt_hash"] == snapshot["hash"]


def test_execution_lifecycle_nonzero_and_exception_receipts(tmp_path, monkeypatch):
    import continuityos.gate.cli as cli

    command = "python --version"
    argv = ["python", "--version"]

    nonzero_ledger = tmp_path / "nonzero.db"
    monkeypatch.setattr(cli, "LEDGER", str(nonzero_ledger))
    monkeypatch.setattr(cli.subprocess, "call", lambda *args, **kwargs: 7)
    result = _bound_execution_result(nonzero_ledger, command, argv)
    assert cli._execute_approved(command, "exec", result, argv=argv) == 7
    events = _execution_events(nonzero_ledger)
    assert [event["kind"] for event in events] == [
        "execution_started", "execution_failed"
    ]
    assert events[-1]["payload"]["exit_code"] == 7
    assert events[-1]["payload"]["error_type"] == "NonZeroExit"

    exception_ledger = tmp_path / "exception.db"
    monkeypatch.setattr(cli, "LEDGER", str(exception_ledger))

    def fail_to_start(*args, **kwargs):
        raise OSError("injected launch failure")

    monkeypatch.setattr(cli.subprocess, "call", fail_to_start)
    result = _bound_execution_result(exception_ledger, command, argv)
    assert cli._execute_approved(command, "exec", result, argv=argv) == 1
    events = _execution_events(exception_ledger)
    assert [event["kind"] for event in events] == [
        "execution_started", "execution_failed"
    ]
    assert events[-1]["payload"]["exit_code"] is None
    assert events[-1]["payload"]["error_type"] == "OSError"


def test_snapshot_failure_records_terminal_failure_without_execution(
    tmp_path, monkeypatch
):
    import continuityos.gate.cli as cli

    ledger_path = tmp_path / "rollback-failure.db"
    monkeypatch.setattr(cli, "LEDGER", str(ledger_path))
    calls = []
    monkeypatch.setattr(
        cli.subprocess,
        "call",
        lambda *args, **kwargs: calls.append((args, kwargs)) or 0,
    )
    command = "rm *.txt"
    argv = ["rm", "*.txt"]
    result = _bound_execution_result(
        ledger_path,
        command,
        argv,
        rollback_plan={
            "snapshot_required": True,
            "targets": [str(tmp_path / "*.txt")],
        },
    )
    assert cli._execute_approved(command, "exec", result, argv=argv) == 1
    assert calls == []
    events = _execution_events(ledger_path)
    assert [event["kind"] for event in events] == ["execution_failed"]
    assert events[0]["payload"]["executed"] is False
    assert events[0]["payload"]["rollback_receipt"]["status"] == "failed"


def test_execution_rejects_unbound_or_non_executable_preflight(
    tmp_path, monkeypatch
):
    import continuityos.gate.cli as cli

    ledger_path = tmp_path / "binding.db"
    monkeypatch.setattr(cli, "LEDGER", str(ledger_path))
    calls = []
    monkeypatch.setattr(
        cli.subprocess,
        "call",
        lambda *args, **kwargs: calls.append((args, kwargs)) or 0,
    )
    command = "python --version"
    argv = ["python", "--version"]

    missing = _bound_execution_result(ledger_path, command, argv)
    missing["ledger_hash"] = "f" * 64
    assert cli._execute_approved(command, "exec", missing, argv=argv) == 1

    wrong_action = _bound_execution_result(ledger_path, command, argv)
    other = _bound_execution_result(
        ledger_path, "python -c pass", ["python", "-c", "pass"]
    )
    wrong_action["ledger_hash"] = other["ledger_hash"]
    assert cli._execute_approved(command, "exec", wrong_action, argv=argv) == 1

    wrong_mode = _bound_execution_result(ledger_path, command, argv)
    assert cli._execute_approved(command, "shell", wrong_mode, argv=argv) == 1

    denied_action = {
        "tool": "exec",
        "command": command,
        "args": argv,
        "paths": [],
        "cwd": os.getcwd(),
        "agent": "test",
        "meta": {},
    }
    with Ledger(str(ledger_path)) as ledger:
        denied_hash = ledger.append("preflight", {
            "action": denied_action,
            "decision": "DENY",
            "rollback_plan": {},
        })
    denied = {
        "decision": "DENY",
        "action": denied_action,
        "ledger_hash": denied_hash,
        "rollback_plan": {},
    }
    assert cli._execute_approved(command, "exec", denied, argv=argv) == 1

    stale_cwd = _bound_execution_result(ledger_path, command, argv)
    changed_cwd = tmp_path / "changed-cwd"
    changed_cwd.mkdir()
    monkeypatch.chdir(changed_cwd)
    assert cli._execute_approved(command, "exec", stale_cwd, argv=argv) == 1
    assert calls == []


def test_terminal_receipt_failure_returns_ambiguous_side_effect_code(
    tmp_path, monkeypatch, capsys
):
    import continuityos.gate.cli as cli

    ledger_path = tmp_path / "receipt-failure.db"
    monkeypatch.setattr(cli, "LEDGER", str(ledger_path))
    monkeypatch.setattr(cli.subprocess, "call", lambda *args, **kwargs: 0)
    command = "python --version"
    argv = ["python", "--version"]
    result = _bound_execution_result(ledger_path, command, argv)
    real_append = cli._append_execution

    def fail_terminal(kind, *args, **kwargs):
        if kind == "execution_completed":
            raise OSError("injected terminal receipt failure")
        return real_append(kind, *args, **kwargs)

    monkeypatch.setattr(cli, "_append_execution", fail_terminal)
    code = cli._execute_approved(command, "exec", result, argv=argv)
    output = capsys.readouterr().out
    assert code == cli.EXIT_RECEIPT_FAILURE == 4
    assert "EXECUTED_BUT_RECEIPT_FAILED" in output
    fallback = str(ledger_path) + ".receipt_failures.jsonl"
    with open(fallback, encoding="utf-8") as stream:
        ambiguity = json.loads(stream.read())
    assert ambiguity["process_exit_code"] == 0
    assert ambiguity["execution_started_hash"]
    assert ambiguity["instruction"].startswith("Do not retry blindly")
    assert [event["kind"] for event in _execution_events(ledger_path)] == [
        "execution_started"
    ]


def test_cli_dry_run_is_single_structured_non_success_result(
    tmp_path, monkeypatch, capsys
):
    import continuityos.gate.cli as cli

    calls = []

    def decide(command, tool="shell", agent="cli-run", **kwargs):
        return {
            "decision": "DRY_RUN_ONLY",
            "reasons": ["protected delete"],
            "ledger_hash": "d" * 64,
            "action": {
                "command": command,
                "args": kwargs["args"],
            },
            "rollback_plan": {},
        }, None

    monkeypatch.setattr(cli, "_decide", decide)
    monkeypatch.setattr(
        cli.subprocess,
        "call",
        lambda *args, **kwargs: calls.append((args, kwargs)) or 0,
    )
    code = cli.main(["run", "exec", "--", "python", "--version"])
    output = json.loads(capsys.readouterr().out)
    assert code == cli.EXIT_DRY_RUN_ONLY == 3
    assert output["decision"] == "DRY_RUN_ONLY"
    assert output["executed"] is False
    assert output["execution_attempted"] is False
    assert output["exit_code"] == 3
    assert output["preflight_hash"] == "d" * 64
    assert calls == []
