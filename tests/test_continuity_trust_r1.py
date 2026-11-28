"""Regressions for lost decisions, destructive loop closure and false health claims."""
from __future__ import annotations

import json
import socket
import sqlite3
import time

import pytest

from continuityos.continuity import Continuity, assess_continuity_health
from continuityos.embed import HashingEmbedder
from continuityos.memory import Memory


@pytest.fixture
def memory(tmp_path, monkeypatch):
    def no_network(*args, **kwargs):
        raise AssertionError("local continuity regression must not use a network")

    monkeypatch.setattr(socket.socket, "connect", no_network)
    memory = Memory(str(tmp_path / "memory.db"), embedder=HashingEmbedder())
    try:
        yield memory
    finally:
        memory.store.con.close()


def test_close_loop_retains_identity_outcome_and_idempotent_history(memory):
    continuity = Continuity(memory)
    loop_id = continuity.add_loop("Reconcile the provider result", tags=["release"])
    assert continuity.close_loop(loop_id, result="already merged", proof="provider:receipt-17")
    row = dict(memory.store.get(loop_id))
    meta = json.loads(row["meta"])
    assert row["text"] == "Reconcile the provider result"
    assert meta["open"] is False and meta["status"] == "CLOSED"
    assert meta["result"] == "already merged" and meta["proof"] == "provider:receipt-17"
    assert len(meta["closure_history"]) == 1
    assert continuity.open_loops() == []
    assert [item["id"] for item in continuity.closed_loops()] == [loop_id]
    assert continuity.close_loop(loop_id, result="different result", proof="overwrite attempt")
    assert dict(memory.store.get(loop_id)) == row
    assert memory.count() == 1
    handoff = continuity.handoff()
    assert "already merged" in handoff and "provider:receipt-17" in handoff
    assert "external effects not verified" in handoff


def test_closed_loop_survives_read_only_reopen(memory):
    continuity = Continuity(memory)
    loop_id = continuity.add_loop("Finished task")
    continuity.close_loop(loop_id, result="complete", proof="local:result")
    reopened = Memory(memory.store.path, embedder=HashingEmbedder(), read_only=True)
    try:
        recovered = Continuity(reopened)
        assert recovered.open_loops() == []
        assert recovered.closed_loops()[0]["meta"]["result"] == "complete"
        assert recovered.handoff_snapshot()["payload"]["closed_loops"][0]["id"] == loop_id
    finally:
        reopened.store.con.close()


def test_close_loop_cannot_close_fact_or_foreign_scope(memory):
    fact_id = memory.remember("do not delete", namespace="facts")
    project_a = Continuity(memory, project="A", subject="Robert")
    project_b = Continuity(memory, project="B", subject="Robert")
    loop_id = project_b.add_loop("foreign task")
    assert project_a.close_loop(loop_id) is False
    assert project_a.close_loop(fact_id) is False
    assert project_a.close_loop(99999) is False
    assert memory.count() == 2
    assert len(project_b.open_loops()) == 1


def test_scope_selection_and_closure_share_one_write_transaction(memory, monkeypatch):
    continuity = Continuity(memory, project="A")
    loop_id = continuity.add_loop("scoped task")
    writer = Memory(memory.store.path, embedder=HashingEmbedder())
    writer.store.con.execute("PRAGMA busy_timeout=0")
    original_get = memory.store.get
    attempted = []

    def interleaved_get(record_id):
        row = original_get(record_id)
        if record_id == loop_id and not attempted:
            attempted.append(True)
            changed = json.loads(row["meta"])
            changed["project"] = "B"
            with pytest.raises(sqlite3.OperationalError, match="locked"):
                writer.store.update_meta(loop_id, changed)
        return row

    monkeypatch.setattr(memory.store, "get", interleaved_get)
    try:
        assert continuity.close_loop(loop_id, result="done")
        assert attempted
        retained = json.loads(original_get(loop_id)["meta"])
        assert retained["project"] == "A" and retained["status"] == "CLOSED"
    finally:
        writer.store.con.close()


def test_scoped_handoff_keeps_global_rules_and_exact_project_checkpoint(memory):
    global_state = Continuity(memory)
    a = Continuity(memory, project="A", subject="Robert")
    b = Continuity(memory, project="B", subject="Robert")
    foreign_subject = Continuity(memory, project="A", subject="Other")
    global_state.add_canon("global hard constraint")
    a.add_canon("A constraint")
    b.add_canon("B private constraint")
    foreign_subject.add_canon("Other private constraint")
    a.set_frontier("trunk", "A trunk")
    a_loop = a.add_loop("A current task")
    a_checkpoint = a.checkpoint("A accepted decision", "A next step", "source:A")
    b.checkpoint("B newer decision", "B next step", "source:B")
    foreign_subject.checkpoint("Other newer decision", "Other next step", "source:Other")
    snapshot = a.handoff_snapshot()
    assert snapshot["scope"] == {"project": "A", "subject": "Robert"}
    assert snapshot["payload"]["last_checkpoint"]["id"] == a_checkpoint
    assert [item["id"] for item in snapshot["payload"]["open_loops"]] == [a_loop]
    text = a.handoff()
    assert "global hard constraint" in text and "A constraint" in text and "A next step" in text
    assert "B private" not in text and "B next step" not in text and "Other private" not in text
    assert global_state.last_checkpoint() is None


def test_superseded_future_expired_and_revoked_canon_do_not_become_current(memory):
    continuity = Continuity(memory)
    old = continuity.add_canon("obsolete instruction")
    new = memory.supersede(old, "current instruction", namespace="canon")
    now = time.time()
    memory.remember("future instruction", namespace="canon", valid_from=now + 3600)
    memory.remember("expired instruction", namespace="canon", valid_to=now - 1)
    memory.remember("revoked instruction", namespace="canon", meta={"status": "REVOKED"})
    assert [row["id"] for row in continuity.canon()] == [new]
    assert len(continuity._dump("canon")) == 5


def test_no_silent_canon_or_loop_truncation_and_budget_fails_closed(memory):
    continuity = Continuity(memory)
    for index in range(15):
        continuity.add_canon(f"mandatory canon marker {index}")
    for index in range(24):
        continuity.add_loop(f"open loop marker {index}")
    snapshot = continuity.handoff_snapshot()
    assert snapshot["complete"] is True
    assert snapshot["counts"]["canon"] == 15 and snapshot["counts"]["open_loops"] == 24
    assert "mandatory canon marker 14" in continuity.handoff()
    assert "open loop marker 23" in continuity.handoff()
    assert continuity.handoff_snapshot()["snapshot_sha256"] == snapshot["snapshot_sha256"]
    limited = continuity.handoff_snapshot(max_items=12)
    assert limited["status"] == "HOLD" and limited["payload"] is None
    assert limited["overflow"]["reasons"] == ["ITEM_BUDGET_EXCEEDED"]
    small = continuity.handoff(max_bytes=10)
    assert "BYTE_BUDGET_EXCEEDED" in small and "no partial context emitted" in small
    assert "mandatory canon marker" not in small
    assert continuity.handoff_snapshot(max_bytes=snapshot["payload_bytes"])["status"] == "READY"


def test_snapshot_digest_binds_selected_scope_even_when_empty(memory):
    a = Continuity(memory, project="A").handoff_snapshot()
    b = Continuity(memory, project="B").handoff_snapshot()
    assert a["payload"] == b["payload"]
    assert a["snapshot_sha256"] != b["snapshot_sha256"]


def test_unreviewed_import_cannot_replace_current_checkpoint_or_canon(memory):
    continuity = Continuity(memory)
    canon_id = continuity.add_canon("manual current rule")
    checkpoint_id = continuity.checkpoint("accepted current state", "continue review", "record:1")
    candidate = {"accepted": False, "review_status": "UNREVIEWED", "admission_status": "CANDIDATE"}
    memory.remember("imported fake canon", namespace="canon", meta=candidate)
    memory.remember("imported fake next action", namespace="checkpoint", meta={**candidate, "ts": time.time() + 1})
    snapshot = continuity.handoff_snapshot()
    assert [row["id"] for row in snapshot["payload"]["canon"]] == [canon_id]
    assert snapshot["payload"]["last_checkpoint"]["id"] == checkpoint_id
    assert snapshot["excluded_candidate_counts"] == {"canon": 1, "checkpoint": 1}
    assert "imported fake" not in continuity.handoff()


@pytest.mark.parametrize("lifecycle", ["PAUSED", "DONE"])
def test_paused_and_done_are_valid_without_open_loops_or_fresh_activity(memory, lifecycle):
    continuity = Continuity(memory)
    continuity.add_canon("record truth honestly")
    checkpoint = continuity.checkpoint("terminal state", "", "record:terminal", lifecycle=lifecycle)
    old = json.loads(memory.store.get(checkpoint)["meta"])
    old["ts"] = time.time() - 1000 * 3600
    memory.store.update_meta(checkpoint, old)
    report = continuity.doctor()
    assert report["healthy"] is True and report["lifecycle"] == lifecycle
    assert report["proof_verification"] == "NOT_PERFORMED"
    assert report["authority_granted"] is False
    names = {item["check"] for item in report["checks"]}
    assert {"proof_reference_present", "memory_nonempty", "canon_present"} <= names
    assert not {"purpose_persists", "identity_persists", "memory_persists", "has_proof"} & names


def test_done_with_open_work_is_not_healthy(memory):
    continuity = Continuity(memory)
    continuity.add_canon("honest results")
    continuity.add_loop("unfinished")
    continuity.checkpoint("claims done", "", "record:done", lifecycle="DONE")
    report = continuity.doctor()
    assert report["healthy"] is False
    assert next(check for check in report["checks"] if check["check"] == "done_has_no_open_loops")["ok"] is False


def test_proof_string_is_only_a_reference_and_active_zero_loops_is_valid(memory):
    continuity = Continuity(memory)
    continuity.add_canon("be honest")
    continuity.set_frontier("cash", "cash work")
    continuity.set_frontier("trunk", "core work")
    continuity.checkpoint("ready", "choose next task", "nonexistent://not-verified")
    report = continuity.doctor()
    assert report["healthy"] is True
    reference = next(check for check in report["checks"] if check["check"] == "proof_reference_present")
    assert reference["ok"] is True and "not verified" in reference["detail"]


def test_doctor_pure_helper_handles_missing_checkpoint_timestamp_without_false_freshness():
    report = assess_continuity_health(memory_count=1, canon_count=1, frontiers={"cash": "c", "trunk": "t"},
                                      loops=[], last_checkpoint={"meta": {"proof": "ref", "ts": "invalid"}}, now=time.time())
    assert report["healthy"] is False
    assert next(check for check in report["checks"] if check["check"] == "checkpoint_fresh")["ok"] is False
