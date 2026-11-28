"""Scoped CLI/boot regression: honest HOLDs, no hidden writes or optional network."""
from __future__ import annotations

import json
import socket
import sqlite3
import time

import pytest

from continuityos import boot, cli, current_entrypoints
from continuityos.continuity import Continuity
from continuityos.embed import HashingEmbedder
from continuityos.memory import Memory


@pytest.fixture
def database(tmp_path, monkeypatch):
    monkeypatch.delenv("CONTINUITYOS_EMBEDDER", raising=False)
    monkeypatch.setattr(current_entrypoints, "current_binding_from_env", lambda env: (None, []))

    def no_network(*args, **kwargs):
        raise AssertionError("local CLI regressions must not use a network")

    monkeypatch.setattr(socket.socket, "connect", no_network)
    path = tmp_path / "memory.db"
    memory = Memory(str(path), embedder=HashingEmbedder())
    a, b = Continuity(memory, project="A", subject="Robert"), Continuity(memory, project="B", subject="Other")
    Continuity(memory).add_canon("global rule")
    a.add_canon("A release rule")
    loop_id = a.add_loop("A delivery task")
    b.add_canon("B private rule")
    b.add_loop("B private loop")
    b.checkpoint("B private state", "B private next", "B receipt")
    memory.store.con.close()
    return path, loop_id


def invoke(path, *args):
    return current_entrypoints.cos_main(["--db", str(path), *args])


def test_cli_closure_and_terminal_checkpoint_recover_in_scoped_handoff(database, capsys):
    path, loop_id = database
    assert invoke(path, "loop", "--close", str(loop_id), "--result", "delivered", "--proof", "provider:1",
                  "--project", "A", "--subject", "Robert") == 0
    capsys.readouterr()
    assert invoke(path, "close", "--summary", "finished", "--next", "", "--proof", "provider:1",
                  "--lifecycle", "DONE", "--project", "A", "--subject", "Robert") == 0
    capsys.readouterr()
    assert invoke(path, "handoff", "--json", "--project", "A", "--subject", "Robert") == 0
    result = json.loads(capsys.readouterr().out)
    assert result["payload"]["open_loops"] == []
    assert result["payload"]["closed_loops"][0]["meta"]["result"] == "delivered"
    assert result["payload"]["last_checkpoint"]["meta"]["lifecycle"] == "DONE"
    assert "B private" not in json.dumps(result)
    assert invoke(path, "doctor", "--json", "--project", "A", "--subject", "Robert") == 0
    doctor = json.loads(capsys.readouterr().out)
    assert doctor["healthy"] and doctor["lifecycle"] == "DONE"
    assert doctor["proof_verification"] == "NOT_PERFORMED"


def test_cli_missing_or_foreign_loop_returns_hold_without_closure(database, capsys):
    path, loop_id = database
    before = path.read_bytes()
    assert invoke(path, "loop", "--close", str(loop_id), "--project", "B", "--subject", "Other") == 2
    assert "LOOP_NOT_FOUND_OR_OUTSIDE_SCOPE" in capsys.readouterr().out
    assert invoke(path, "loop", "--close", "99999") == 2
    assert "closed loop" not in capsys.readouterr().out
    assert path.read_bytes() == before


def test_handoff_budget_hold_is_json_nonzero_and_read_only(database, capsys):
    path, _ = database
    before = path.read_bytes()
    assert invoke(path, "handoff", "--json", "--max-items", "0", "--project", "A", "--subject", "Robert") == 2
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "HOLD" and result["payload"] is None
    assert path.read_bytes() == before


def test_canon_and_scan_show_current_rules_without_legacy_truncation(database, capsys):
    path, _ = database
    memory = Memory(str(path), embedder=HashingEmbedder())
    old = memory.remember("OLD CANON", namespace="canon")
    memory.supersede(old, "CURRENT CANON", namespace="canon")
    memory.remember("CANDIDATE CANON", namespace="canon", meta={"accepted": False})
    for index in range(14):
        Continuity(memory).add_canon(f"mandatory-rule-{index}")
    memory.store.con.close()
    assert invoke(path, "canon") == 0
    output = capsys.readouterr().out
    assert "OLD CANON" not in output and "CANDIDATE CANON" not in output and "CURRENT CANON" in output
    assert invoke(path, "scan") == 0
    assert "mandatory-rule-13" in capsys.readouterr().out


@pytest.mark.parametrize("command,query", [("predict", ["release"]), ("alignment", ["release"]), ("profile", [])])
def test_twin_cli_forwards_scope_and_returns_honest_json(database, capsys, command, query):
    path, _ = database
    assert invoke(path, command, *query, "--project", "A", "--subject", "Robert") == 0
    result = json.loads(capsys.readouterr().out)
    assert result["scope"] == {"project": "A", "subject": "Robert"}
    assert "B private" not in json.dumps(result)
    assert "confidence" not in result


@pytest.mark.parametrize("fail_capture", [False, True])
def test_boot_uses_one_read_only_snapshot_and_closes_on_every_path(database, monkeypatch, capsys, fail_capture):
    path, _ = database
    opened = []
    original_memory = boot.Memory

    def tracked_memory(*args, **kwargs):
        assert kwargs["read_only"] is True
        value = original_memory(*args, **kwargs)
        opened.append(value)
        return value

    monkeypatch.setattr(boot, "Memory", tracked_memory)
    monkeypatch.setattr(Continuity, "doctor", lambda *args, **kwargs: (_ for _ in ()).throw(
        AssertionError("boot must derive doctor from its captured handoff rows")))
    if fail_capture:
        monkeypatch.setattr(Continuity, "handoff_snapshot", lambda *args, **kwargs: (_ for _ in ()).throw(
            ValueError("synthetic snapshot failure")))
    before = path.read_bytes()
    code = invoke(path, "boot", "--json", "--project", "A", "--subject", "Robert")
    result = json.loads(capsys.readouterr().out)
    assert code == (2 if fail_capture else 0)
    assert result["terminal"] == ("COS_BOOT_HOLD" if fail_capture else "COS_BOOT_PASS")
    if not fail_capture:
        assert result["doctor"]["scope"] == result["handoff"]["scope"]
        assert "B private" not in json.dumps(result)
    with pytest.raises(sqlite3.ProgrammingError):
        opened[0].store.con.execute("SELECT 1")
    assert path.read_bytes() == before


def test_direct_cli_boot_has_no_legacy_updater_or_fastembed_path(database, monkeypatch, capsys):
    path, _ = database
    from continuityos import embedders, updater

    def forbidden(*args, **kwargs):
        raise AssertionError("offline boot called optional provider")

    monkeypatch.setattr(embedders, "FastEmbedEmbedder", forbidden)
    monkeypatch.setattr(updater, "check", forbidden)
    assert cli.main(["--db", str(path), "boot", "--project", "A", "--subject", "Robert"]) == 0
    assert "--- doctor ---" in capsys.readouterr().out


def test_new_profile_command_remains_behind_current_session_gate(database, monkeypatch, capsys):
    path, _ = database
    monkeypatch.setattr(current_entrypoints, "current_binding_from_env", lambda env: ({"challenge": "x"}, []))
    monkeypatch.setattr(current_entrypoints, "_verify_binding", lambda *args: (
        {"binding_verified": True, "authority_generation": "R64", "challenge_id": "id", "challenge_sha256": "sha"}, None))
    monkeypatch.setattr(cli, "Memory", lambda *args, **kwargs: (_ for _ in ()).throw(
        AssertionError("bound profile must HOLD before memory access")))
    assert invoke(path, "profile", "--project", "A") == 3
    assert json.loads(capsys.readouterr().out)["terminal"] == "CURRENT_ENTRYPOINT_HOLD"


def test_rules_stdout_exports_current_scoped_records_without_candidates(database, tmp_path, capsys):
    path, _ = database
    memory = Memory(str(path), embedder=HashingEmbedder())
    scope = {"project": "A", "subject": "Robert"}
    old = memory.remember("RETIRED RULE", namespace="rules", meta=scope)
    memory.supersede(old, "CURRENT SCOPED RULE", namespace="rules", meta=scope)
    memory.remember("CANDIDATE RULE", namespace="rules", meta={**scope, "accepted": False})
    memory.remember("FUTURE RULE", namespace="rules", meta=scope, valid_from=time.time() + 3600)
    memory.remember("FOREIGN RULE", namespace="rules", meta={"project": "B", "subject": "Other"})
    continuity = Continuity(memory, **scope)
    continuity.set_frontier("trunk", "CURRENT SCOPED FRONTIER")
    memory.remember("CANDIDATE FRONTIER", namespace="frontier",
                    meta={**scope, "kind": "trunk", "ts": time.time() + 1, "accepted": False})
    memory.store.con.close()
    output_dir = tmp_path / "no-config-write"
    before = path.read_bytes()
    assert invoke(path, "rules", "--stdout", "--to", "agents", "--out", str(output_dir),
                  "--project", "A", "--subject", "Robert") == 0
    result = capsys.readouterr().out
    assert "CURRENT SCOPED RULE" in result and "CURRENT SCOPED FRONTIER" in result
    assert "global rule" in result and "A release rule" in result
    for excluded in ("RETIRED RULE", "CANDIDATE RULE", "FUTURE RULE", "FOREIGN RULE", "CANDIDATE FRONTIER", "B private"):
        assert excluded not in result
    assert "authenticity is unverified" in result and "no execution authority" in result
    assert not output_dir.exists() and path.read_bytes() == before


@pytest.mark.parametrize("existing", [False, True])
@pytest.mark.parametrize("extract", [False, True])
def test_import_preview_never_creates_or_migrates_target_database(database, tmp_path, monkeypatch, capsys,
                                                                existing, extract):
    from continuityos import embedders

    optional_calls = []

    def optional_embedder():
        optional_calls.append(True)
        raise AssertionError("source preview does not need optional model construction")

    monkeypatch.setenv("CONTINUITYOS_EMBEDDER", "fast")
    monkeypatch.setattr(embedders, "FastEmbedEmbedder", optional_embedder)
    source = tmp_path / "conversations.json"
    source.write_text(json.dumps([{"id": "chat-1", "title": "synthetic export", "mapping": {
        "node-1": {"message": {"id": "message-1", "author": {"role": "user"},
                               "create_time": 1, "content": {"content_type": "text", "parts": [
                                   "I prefer Apache-2.0 licenses for my OSS projects."]}}}
    }}]), encoding="utf-8")
    target = database[0] if existing else tmp_path / "missing-directory/new.db"
    if existing:
        before = target.read_bytes()
    args = ["import", str(source), "--dry-run"] + (["--extract"] if extract else [])
    assert invoke(target, *args) == 0
    assert "(dry-run)" in capsys.readouterr().out
    assert optional_calls == []
    if existing:
        assert target.read_bytes() == before
    else:
        assert not target.exists() and not target.parent.exists()


def test_import_extraction_preview_holds_without_migrating_legacy_schema(database, tmp_path, capsys):
    target = tmp_path / "legacy.db"
    source = tmp_path / "legacy-conversations.json"
    source.write_text(json.dumps([{"id": "chat-legacy", "mapping": {
        "node": {"message": {"author": {"role": "user"}, "content": {"content_type": "text", "parts": [
            "I prefer Apache-2.0 licenses for my projects."]}}}
    }}]), encoding="utf-8")
    connection = sqlite3.connect(target)
    connection.execute("CREATE TABLE items(id INTEGER PRIMARY KEY, namespace TEXT, text TEXT, "
                       "tags TEXT, meta TEXT, vec BLOB, created_at REAL, updated_at REAL)")
    connection.commit()
    connection.close()
    before = target.read_bytes()
    assert invoke(target, "import", str(source), "--dry-run", "--extract") == 2
    assert "READ_ONLY_PREVIEW_UNAVAILABLE" in capsys.readouterr().out
    assert target.read_bytes() == before
    connection = sqlite3.connect(target)
    try:
        columns = {row[1] for row in connection.execute("PRAGMA table_info(items)")}
        assert "key" not in columns and "version" not in columns
    finally:
        connection.close()
