"""Product status and public Continuity agree on scoped lifecycle state."""
import json
import time

import pytest

from continuityos import status
from continuityos.continuity import Continuity
from continuityos.memory import Memory


@pytest.mark.parametrize("lifecycle", ["ACTIVE", "PAUSED", "DONE"])
def test_status_matches_doctor_and_retains_closed_outcomes(tmp_path, monkeypatch, lifecycle):
    db = tmp_path / "continuity.db"
    monkeypatch.setattr(status, "_client_statuses", lambda path: [])
    memory = Memory(str(db))
    c = Continuity(memory, project="repair", subject="owner")
    c.add_canon("Record evidence before status claims")
    c.set_frontier("trunk", "Repair public continuity")
    c.set_frontier("cash", "Usable product")
    loop = c.add_loop("Finish scoped repair")
    assert c.close_loop(loop, result="reviewable change", proof="repository:commit")
    checkpoint = c.checkpoint("repair complete", "await review", "repository:commit", lifecycle=lifecycle)
    if lifecycle != "ACTIVE":
        meta = json.loads(memory.store.get(checkpoint)["meta"])
        meta["ts"] = time.time() - 100 * 86400
        memory.store.update_meta(checkpoint, meta)
    foreign = Continuity(memory, project="other", subject="owner")
    foreign.add_loop("foreign task")
    foreign.checkpoint("foreign latest", "do not select", "other", lifecycle="ACTIVE")
    memory.remember("unreviewed restrictive rule", namespace="canon", meta={
        "project": "repair", "subject": "owner", "accepted": False})
    expected = c.doctor()
    memory.store.con.close()
    before = db.read_bytes()

    value, code = status.collect(str(db), project="repair", subject="owner")

    assert code == 0
    assert value["continuity"]["state"] == "HEALTHY"
    assert expected["healthy"]
    observed = value["continuity"]
    assert {r["check"]: r["ok"] for r in observed["checks"]} == {
        r["check"]: r["ok"] for r in expected["checks"]}
    assert observed["scope"] == {"project": "repair", "subject": "owner"}
    assert observed["lifecycle"] == lifecycle
    assert observed["open_loop_count"] == 0
    assert observed["proof_verification"] == "NOT_PERFORMED"
    assert not observed["authority_granted"]
    assert value["governance"]["canon_count"] == 1
    assert observed["last_checkpoint"]["id"] == checkpoint
    assert observed["next_action"] == ("await review" if lifecycle == "ACTIVE" else None)
    assert db.read_bytes() == before


def test_status_default_scope_does_not_select_foreign_state(tmp_path, monkeypatch):
    monkeypatch.setattr(status, "_client_statuses", lambda path: [])
    db = tmp_path / "foreign.db"
    memory = Memory(str(db))
    c = Continuity(memory, project="foreign")
    c.add_canon("Foreign rule")
    c.checkpoint("Foreign state", "Foreign next", "ref", lifecycle="DONE")
    memory.store.con.close()
    value, code = status.collect(str(db))
    assert code == 0
    assert value["memory"]["count"] == 2
    assert value["memory"]["scoped_count"] == 0
    assert value["continuity"]["last_checkpoint"] is None
    assert value["governance"]["canon_count"] == 0


def test_status_cli_selects_scope_and_reports_caller_policy(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(status, "_client_statuses", lambda path: [])
    db = tmp_path / "policy.db"
    memory = Memory(str(db))
    c = Continuity(memory, project="p")
    c.add_canon("Preserve identity of local evidence")
    c.checkpoint("Done", "", "ref", lifecycle="DONE")
    memory.store.con.close()
    assert status.main(["--db", str(db), "--json", "--project", "p",
                        "--max-open-loops", "2", "--checkpoint-stale-hours", "24"]) == 0
    observed = json.loads(capsys.readouterr().out)["continuity"]
    assert observed["scope"]["project"] == "p"
    assert observed["policy"]["max_open_loops"] == 2
    assert observed["policy"]["checkpoint_stale_hours"] == 24


@pytest.mark.parametrize("invalid_meta", ["{broken", "[]", "null"])
def test_malformed_metadata_cannot_turn_into_global_canon(tmp_path, monkeypatch, invalid_meta):
    monkeypatch.setattr(status, "_client_statuses", lambda path: [])
    db = tmp_path / "invalid-meta.db"
    memory = Memory(str(db))
    rid = memory.remember("foreign candidate", namespace="canon", meta={
        "project": "foreign", "accepted": False})
    memory.store.con.execute("UPDATE items SET meta=? WHERE id=?", (invalid_meta, rid))
    memory.store.con.commit()
    memory.store.con.close()
    before = db.read_bytes()
    value, code = status.collect(str(db), project="ours")
    assert code == 2
    assert value["terminal"] == "COS_STATUS_HOLD"
    assert "INVALID_RECORD_METADATA" in value["error"]
    assert "governance" not in value
    assert db.read_bytes() == before
