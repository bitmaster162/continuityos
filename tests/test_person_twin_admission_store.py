"""Offline durable admission proofs using temporary synthetic Memory databases.

Subprocess B receives only the DB path and the controller's expected identity,
not A's source/candidate/pointer/receipt or a cached authorization decision.
Model clients record calls. These tests do not prove live host/owner authority.
"""
from __future__ import annotations

import copy
from dataclasses import replace
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import runpy
import sqlite3
import subprocess
import sys
import time

import pytest

from continuityos.embed import HashingEmbedder
from continuityos.memory import Memory
from continuityos import person_twin_admission_store as durable
from continuityos import person_twin_demo as demo
from continuityos.person_twin_admission_contracts import (
    build_consent_revocation_entry, build_consent_revocation_ledger, build_person_twin_identity,
)
from continuityos.person_twin_authority_replay import evaluate_person_twin_authority_replay
from continuityos.person_twin_privacy_provenance import build_person_twin_provenance
from continuityos.person_twin_r21h_evidence import PersonReadIntent, PersonTwinR21HEvidenceAdapter, PersonTwinEvidenceError
from continuityos.sovereign_twin_runtime import DEFAULT_PROFILES, SovereignTwinRuntime

AT = "2026-08-25T12:50:00Z"
NS = "synthetic-durable-admission"
QUERY = "Restore the admitted current context."
TEXT = ("Goal: resume the project after a process restart.\n"
        "Decision: keep the existing R21H engine.\n"
        "Constraint: synthetic data only; no external effects.\n"
        "Next step: inspect the recovered evidence and admission receipt.")


def _fixture_module():
    path = Path(__file__).with_name("test_person_twin_authority_replay.py")
    spec = importlib.util.spec_from_file_location("_durable_r4_fixture", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _data():
    ctx = _fixture_module()._inputs()
    source = copy.deepcopy(ctx["source_record"])
    source["payload"] = {"title": "Synthetic durable context", "text": TEXT}
    source["content_hash"] = durable._hash(durable._canonical(source["payload"]))
    record = build_person_twin_provenance(ctx["identity"], ctx["consent_receipt"],
        ctx["current_revocation_ledger"], source, admission_session_id="admission:durable:r1",
        purpose="person-memory", at="2026-08-25T11:00:00Z")
    return {**ctx, "source_record": source, "person_record": record}


def _write_memory(path, ctx):
    memory = Memory(str(path), embedder=HashingEmbedder())
    try:
        memory.remember("OLD_DECISION_NOT_ADMITTED", namespace=NS)
        memory.remember("FOREIGN_PRIVATE_NOT_ADMITTED", namespace="foreign-person")
        rid = memory.remember(ctx["source_record"]["payload"]["text"], namespace=NS)
    finally:
        memory.store.con.close()
    return rid


def _fresh(ctx):
    return {"current_revocation_ledger": copy.deepcopy(ctx["current_revocation_ledger"]), "at": AT}


def _admit(store, ctx, rid, reader=None, namespace=NS):
    return store.admit(consent_receipt=ctx["consent_receipt"], source_record=ctx["source_record"],
        candidate_record=ctx["person_record"], purpose="person-memory", memory_id=rid, namespace=namespace,
        read_current_evidence=(lambda: _fresh(ctx)) if reader is None else reader)


@pytest.fixture
def ready(tmp_path):
    ctx, path = _data(), tmp_path / "memory.db"
    rid = _write_memory(path, ctx)
    durable.PersonTwinAdmissionStore.initialize(path)
    return path, ctx, rid


def _context(snapshot, store, host=None, ledger=None):
    anchors = snapshot.anchors
    if host is None:
        host = demo._fresh_host_context({"context": {"identity": anchors["identity"],
                                       "person_record": snapshot.candidate}}, "B")
    return {"identity": anchors["identity"], "consent_receipt": anchors["consent_receipt"],
        "source_record": anchors["source_record"], "person_record": snapshot.candidate,
        "admission_receipt": snapshot.receipt, "current_pointer": snapshot.pointer,
        "admission_store": store, "replay_store": demo._EmptyReplayFixture(),
        "current_revocation_ledger": build_consent_revocation_ledger() if ledger is None else ledger, **host}


def _run_r21h(path, store, *, drift=None):
    snapshot = store.load_current()
    assert snapshot is not None
    ctx = _context(snapshot, store)
    query_hash = durable._hash(QUERY.encode())
    session_hash = durable._hash(durable._canonical(ctx["current_session"]))
    binding = snapshot.binding
    intent = PersonReadIntent(query_sha256=query_hash, current_session_sha256=session_hash,
        request_id=ctx["authorization_request"]["request_id"], packet_id=ctx["authorization_preflight"]["packet_id"],
        memory_id=binding["memory_id"], namespace=binding["namespace"],
        person_record_id=snapshot.candidate["id"], source_record_id=snapshot.anchors["source_record"]["id"],
        principal_id=ctx["principal_id"], scope=ctx["requested_scope"], privacy_class=ctx["requested_privacy_class"],
        purpose=ctx["purpose"])
    if drift is not None:
        drift(ctx)
    class Provider:
        def read_context(self):
            latest = store.load_current()
            assert latest is not None
            return {**ctx, "person_record": latest.candidate, "current_pointer": latest.pointer,
                    "admission_receipt": latest.receipt}
    profile = replace(DEFAULT_PROFILES["fast"], model="synthetic-durable-fast")
    model = demo._RecordingModel(profile, cold=False)
    runtime = SovereignTwinRuntime(str(path), profiles={**DEFAULT_PROFILES, "fast": profile},
        client=model, person_evidence_adapter=PersonTwinR21HEvidenceAdapter(intent, Provider()))
    try:
        if drift is not None:
            with pytest.raises(PersonTwinEvidenceError):
                runtime.ask(QUERY)
            assert model.calls == []
            return {"decision": "DENY", "model_calls": 0}
        answer = runtime.ask(QUERY)
        assert len(model.calls) == 1
        call = model.calls[0]
        prompt = call["system_prompt"]
        evidence = json.loads(prompt.split("MEMORY_EVIDENCE_JSON:\n", 1)[1])
        assert len(evidence) == 1 and evidence[0]["text"] == TEXT
        assert "OLD_DECISION_NOT_ADMITTED" not in prompt and "FOREIGN_PRIVATE_NOT_ADMITTED" not in prompt
        assert f"mem:{binding['memory_id']}" in prompt
        assert answer.stats["person_evidence"]["decision"] == "ALLOW"
        return {"decision": "ALLOW", "model_calls": 1, "prompt_hash": durable._hash(prompt.encode()),
                "session_hash": session_hash, "receipt_hash": durable._hash(snapshot.receipt_bytes)}
    finally:
        runtime.close()


def test_actual_receipt_and_same_db_row_survive_reopen(ready):
    path, ctx, rid = ready
    with durable.PersonTwinAdmissionStore(path, identity=ctx["identity"], read_only=False) as store:
        outcome = _admit(store, ctx, rid)
        assert outcome["status"] == "PASS", outcome
        assert outcome["commit_state"] == "CONFIRMED"
        first = store.load_current()
    with durable.PersonTwinAdmissionStore(path, identity=ctx["identity"]) as reader:
        recovered = reader.load_current()
        assert recovered == first
        assert recovered.receipt_bytes == durable._canonical(outcome["admission_receipt"])
        assert recovered.binding["memory_id"] == rid
        assert recovered.candidate["payload"]["text"] == TEXT
        assert evaluate_person_twin_authority_replay(**_context(recovered, reader))["decision"] == "ALLOW"
        assert reader._con.execute("PRAGMA query_only").fetchone()[0] == 1
        assert reader._con.execute("SELECT COUNT(*) FROM items").fetchone()[0] == 3
        assert outcome["production_admission_status"] == "NOT_PRODUCTION_ADMITTED"
        assert outcome["execution_authority"] == "NONE" and outcome["can_execute"] is False
        assert outcome["can_trade"] is False and outcome["capital_permission"] == "DENY"


@pytest.mark.parametrize("kind", ["missing", "memory-no-schema", "partial-schema", "wrong-version", "wrong-ddl", "trigger"])
def test_read_only_missing_or_corrupt_schema_never_initializes(tmp_path, kind):
    ctx, path = _data(), tmp_path / "isolated.db"
    if kind != "missing":
        _write_memory(path, ctx)
    if kind not in {"missing", "memory-no-schema"}:
        durable.PersonTwinAdmissionStore.initialize(path)
        with sqlite3.connect(path) as con:
            if kind == "partial-schema":
                con.execute("DROP TABLE person_admission_current")
            elif kind == "wrong-version":
                con.execute("UPDATE person_admission_meta SET schema_id='other'")
            elif kind == "wrong-ddl":
                con.execute("ALTER TABLE person_admission_meta ADD COLUMN unexpected TEXT")
            else:
                con.execute("CREATE TRIGGER unsafe_admission AFTER INSERT ON person_admission_meta BEGIN SELECT 1; END")
    before = None if not path.exists() else path.read_bytes()
    with pytest.raises(durable.DurableAdmissionError):
        durable.PersonTwinAdmissionStore(path, identity=ctx["identity"])
    assert (None if not path.exists() else path.read_bytes()) == before


def test_schema_creation_is_explicit_idempotent_and_preserves_memory(ready):
    path, ctx, rid = ready
    with sqlite3.connect(path) as con:
        before = con.execute("SELECT * FROM items ORDER BY id").fetchall()
    durable.PersonTwinAdmissionStore.initialize(path)
    with sqlite3.connect(path) as con:
        assert con.execute("SELECT * FROM items ORDER BY id").fetchall() == before
        assert con.execute("SELECT COUNT(*) FROM person_admission_current").fetchone()[0] == 0


@pytest.mark.parametrize("action", ["candidate", "pointer", "readonly-admit"])
def test_direct_write_callbacks_cannot_bypass_real_r3(ready, action):
    path, ctx, rid = ready
    with durable.PersonTwinAdmissionStore(path, identity=ctx["identity"]) as store:
        with pytest.raises(durable.DurableAdmissionError):
            if action == "candidate":
                store.commit_candidate_not_current(ctx["person_record"]["id"], durable._canonical(ctx["person_record"]))
            elif action == "pointer":
                store.promote_current_pointer(expected_pointer_sha256=None, pointer_bytes=b'{}')
            else:
                _admit(store, ctx, rid)
        assert store.load_current() is None


@pytest.mark.parametrize("phase", [1, 2, 3, 4])
def test_revocation_at_each_boundary_prevents_current_publication(ready, phase):
    path, ctx, rid = ready
    calls = 0
    entry = build_consent_revocation_entry(ctx["identity"], ctx["consent_receipt"],
        revoking_principal="human:owner", revoking_principal_kind="HUMAN",
        revoked_at="2026-08-25T12:00:00Z", reason="synthetic boundary revocation")
    def reader():
        nonlocal calls
        calls += 1
        value = _fresh(ctx)
        if calls >= phase:
            value["current_revocation_ledger"] = build_consent_revocation_ledger([entry])
        return value
    with durable.PersonTwinAdmissionStore(path, identity=ctx["identity"], read_only=False) as store:
        value = _admit(store, ctx, rid, reader)
        assert value["status"] == "HOLD"
        assert value["admission_receipt"] is None
        assert store.load_current() is None
        assert store._con.execute("SELECT COUNT(*) FROM person_admission_publications").fetchone()[0] == 0


@pytest.mark.parametrize("drift", ["text", "namespace", "superseded", "missing"])
def test_memory_drift_before_promotion_never_publishes(ready, drift):
    path, ctx, rid = ready
    calls = 0
    def reader():
        nonlocal calls
        calls += 1
        if calls == 3:
            with sqlite3.connect(path) as con:
                if drift == "text":
                    con.execute("UPDATE items SET text='SYNTHETIC_TAMPER' WHERE id=?", (rid,))
                elif drift == "namespace":
                    con.execute("UPDATE items SET namespace='foreign-person' WHERE id=?", (rid,))
                elif drift == "superseded":
                    con.execute('UPDATE items SET meta=? WHERE id=?', ('{"superseded_by":99}', rid))
                else:
                    con.execute("DELETE FROM items WHERE id=?", (rid,))
        return _fresh(ctx)
    with durable.PersonTwinAdmissionStore(path, identity=ctx["identity"], read_only=False) as store:
        outcome = _admit(store, ctx, rid, reader)
        assert outcome["status"] == "HOLD"
        assert store.load_current() is None


def test_same_candidate_cannot_be_rebound_to_another_memory_id(ready):
    path, ctx, rid = ready
    with durable.PersonTwinAdmissionStore(path, identity=ctx["identity"], read_only=False) as store:
        assert _admit(store, ctx, rid)["status"] == "PASS"
        old = store.load_current()
        memory = Memory(str(path), embedder=HashingEmbedder())
        try:
            other = memory.remember(TEXT, namespace=NS)
        finally:
            memory.store.con.close()
        value = _admit(store, ctx, other)
        assert value["status"] == "HOLD"
        assert store.load_current() == old


@pytest.mark.parametrize("table,column", [("person_admission_candidates", "candidate"),
    ("person_admission_candidates", "anchors"), ("person_admission_candidates", "binding"),
    ("person_admission_publications", "receipt"), ("person_admission_current", "pointer")])
def test_corrupt_stored_bundle_fails_closed(ready, table, column):
    path, ctx, rid = ready
    with durable.PersonTwinAdmissionStore(path, identity=ctx["identity"], read_only=False) as store:
        assert _admit(store, ctx, rid)["status"] == "PASS"
    with sqlite3.connect(path) as con:
        con.execute(f"UPDATE {table} SET {column}=?", (b'{}',))
    with durable.PersonTwinAdmissionStore(path, identity=ctx["identity"]) as reader:
        with pytest.raises(durable.DurableAdmissionError):
            reader.load_current()


def test_different_valid_twin_cannot_read_other_identity(ready):
    path, ctx, rid = ready
    with durable.PersonTwinAdmissionStore(path, identity=ctx["identity"], read_only=False) as store:
        assert _admit(store, ctx, rid)["status"] == "PASS"
    other = build_person_twin_identity(tenant_id="tenant:other", subject_id="subject:other", owner_id="human:other",
        controller_id="human:other", controller_kind="HUMAN", ownership_epoch=1, created_at="2026-08-25T00:00:00Z")
    with durable.PersonTwinAdmissionStore(path, identity=other) as reader:
        assert reader.load_current() is None
        assert reader.read_candidate_bytes(ctx["person_record"]["id"]) is None


@pytest.mark.parametrize("which", ["session", "request", "revocation"])
def test_fresh_read_authority_still_required_before_model_call(ready, which):
    path, ctx, rid = ready
    with durable.PersonTwinAdmissionStore(path, identity=ctx["identity"], read_only=False) as store:
        assert _admit(store, ctx, rid)["status"] == "PASS"
    def change(context):
        if which == "session":
            context["current_session"]["challenge_id"] += ":stale"
        elif which == "request":
            context["authorization_request"]["request_id"] += ":stale"
        else:
            entry = build_consent_revocation_entry(context["identity"], context["consent_receipt"],
                revoking_principal="human:owner", revoking_principal_kind="HUMAN",
                revoked_at="2026-08-25T12:00:00Z", reason="synthetic read revocation")
            context["current_revocation_ledger"] = build_consent_revocation_ledger([entry])
    with durable.PersonTwinAdmissionStore(path, identity=ctx["identity"]) as reader:
        assert _run_r21h(path, reader, drift=change)["model_calls"] == 0


class _CommitAckLoss:
    def __init__(self, store, phase):
        self.store, self.real, self.phase, self.calls = store, store._con, phase, 0
    def __getattr__(self, name):
        return getattr(self.real, name)
    def execute(self, sql, args=()):
        if sql == "COMMIT" and self.store._phase == self.phase:
            self.calls += 1
            self.real.execute(sql, args)
            raise OSError("SYNTHETIC_COMMIT_ACK_LOST_PRIVATE_TEXT")
        return self.real.execute(sql, args)


@pytest.mark.parametrize("phase", ["CANDIDATE", "PROMOTING"])
def test_lost_commit_ack_is_hold_with_possible_persisted_effect(ready, phase):
    path, ctx, rid = ready
    with durable.PersonTwinAdmissionStore(path, identity=ctx["identity"], read_only=False) as store:
        fault = _CommitAckLoss(store, phase)
        store._con = fault
        value = _admit(store, ctx, rid)
        assert value["status"] == "HOLD" and value["possible_persisted_effect"] is True, value
        assert value["admission_receipt"] is None and fault.calls == 1
        assert "PRIVATE_TEXT" not in json.dumps(value)
    with durable.PersonTwinAdmissionStore(path, identity=ctx["identity"]) as reader:
        snapshot = reader.load_current()
        assert (snapshot is not None) == (phase == "PROMOTING")
        assert reader.read_candidate_bytes(ctx["person_record"]["id"]) is not None


def test_failed_postcommit_reopen_is_not_reported_as_rollback(ready, monkeypatch):
    path, ctx, rid = ready
    original = durable.PersonTwinAdmissionStore.load_current
    with durable.PersonTwinAdmissionStore(path, identity=ctx["identity"], read_only=False) as store:
        def fail_new(instance):
            if instance is not store:
                raise OSError("SYNTHETIC_READBACK_UNAVAILABLE")
            return original(instance)
        with monkeypatch.context() as m:
            m.setattr(durable.PersonTwinAdmissionStore, "load_current", fail_new)
            value = _admit(store, ctx, rid)
        assert value["status"] == "HOLD" and value["commit_state"] == "CONFIRMED"
        assert value["reason"] == "POSTCOMMIT_READBACK_FAILED" and value["possible_persisted_effect"]
        assert store.load_current() is not None


def test_declared_current_mode_blocks_writes_without_schema_mutation(ready, monkeypatch):
    path, ctx, rid = ready
    with durable.PersonTwinAdmissionStore(path, identity=ctx["identity"], read_only=False) as store:
        monkeypatch.setenv("CONTINUITYOS_CURRENT_SESSION_REQUIRED", "1")
        value = _admit(store, ctx, rid)
        assert value["status"] == "HOLD"
        assert store.load_current() is None
        with pytest.raises(Exception):
            durable.PersonTwinAdmissionStore.initialize(path)
        with pytest.raises(Exception):
            durable.PersonTwinAdmissionStore(path, identity=ctx["identity"], read_only=False)


def _worker(mode, path, expected_identity, token=""):
    if mode == "write":
        ctx = _data()
        rid = _write_memory(path, ctx)
        durable.PersonTwinAdmissionStore.initialize(path)
        with durable.PersonTwinAdmissionStore(path, identity=ctx["identity"], read_only=False) as store:
            out = _admit(store, ctx, rid)
            assert out["status"] == "PASS", out
            observation = _run_r21h(path, store)
            return {"pid": os.getpid(), "publication_id": out["publication_id"], **observation}
    if mode == "read":
        # A reader must not manufacture a replacement R3 receipt after restart.
        def forbidden(*args, **kwargs):
            raise AssertionError("R3_MUST_NOT_RUN_IN_READER")
        durable.PersonTwinAdmissionCoordinator.promote_current = forbidden
        with durable.PersonTwinAdmissionStore(path, identity=expected_identity) as reader:
            snap = reader.load_current()
            assert snap is not None
            return {"pid": os.getpid(), "publication_id": snap.publication_id, **_run_r21h(path, reader)}
    ctx = _data()
    with durable.PersonTwinAdmissionStore(path, identity=expected_identity, read_only=False, timeout=3) as store:
        if mode == "race":
            calls = 0
            def barrier():
                nonlocal calls
                calls += 1
                if calls == 1:
                    path.with_name(token + ".ready").write_text("ready", encoding="ascii")
                    end = time.monotonic() + 8
                    while not all(path.with_name(x + ".ready").exists() for x in ("A", "B")):
                        if time.monotonic() > end:
                            raise TimeoutError("SYNTHETIC_BARRIER_TIMEOUT")
                        time.sleep(0.02)
                return _fresh(ctx)
            return _admit(store, ctx, 3, barrier)
        def crash(sql):
            if store._phase == "PROMOTING" and (
                (mode == "crash-after-pointer" and sql.startswith("INSERT INTO person_admission_publications")) or
                (mode == "crash-precommit" and sql == "COMMIT")):
                os._exit(73)
        store._con.set_trace_callback(crash)
        _admit(store, ctx, 3)
        raise AssertionError("CRASH_CHECKPOINT_NOT_REACHED")


def _command(mode, path, identity, token=""):
    root = Path(__file__).resolve().parents[1]
    code = ("import sys,json,runpy; "
        "sys.addaudithook(lambda e,a: (_ for _ in ()).throw(RuntimeError('OFFLINE_SOCKET_DENIED')) if e.startswith('socket.') else None); "
        "sys.path.insert(0,sys.argv[1]); m=runpy.run_path(sys.argv[2]); "
        "print(json.dumps(m['_worker'](sys.argv[3],m['Path'](sys.argv[4]),json.loads(sys.argv[5]),sys.argv[6]),sort_keys=True))")
    return [sys.executable, "-I", "-B", "-c", code, str(root), str(Path(__file__).resolve()),
            mode, str(path), json.dumps(identity, separators=(",", ":")), token]


def _run_child(mode, path, identity):
    return subprocess.run(_command(mode, path, identity), capture_output=True, text=True,
                          encoding="utf-8", timeout=20, check=False)


def test_two_real_processes_recover_receipt_without_sidecar(tmp_path):
    path = tmp_path / "process-memory.db"
    identity = _data()["identity"]
    first = _run_child("write", path, identity)
    assert first.returncode == 0, first.stderr
    second = _run_child("read", path, identity)
    assert second.returncode == 0, second.stderr
    a, b = json.loads(first.stdout), json.loads(second.stdout)
    assert a["pid"] != b["pid"] and a["pid"] != os.getpid() and b["pid"] != os.getpid()
    for key in ("publication_id", "receipt_hash", "prompt_hash"):
        assert a[key] == b[key]
    assert a["session_hash"] != b["session_hash"]
    assert a["model_calls"] == b["model_calls"] == 1
    assert not list(tmp_path.glob("*.json"))


def test_two_process_writers_have_exactly_one_winner(ready):
    path, ctx, rid = ready
    workers = [subprocess.Popen(_command("race", path, ctx["identity"], token), stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, text=True, encoding="utf-8") for token in ("A", "B")]
    results = []
    try:
        for proc in workers:
            stdout, stderr = proc.communicate(timeout=20)
            assert proc.returncode == 0, stderr
            results.append(json.loads(stdout))
    finally:
        for proc in workers:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=5)
    assert sorted(r["status"] for r in results) == ["HOLD", "PASS"], results
    winner = next(r for r in results if r["status"] == "PASS")
    with durable.PersonTwinAdmissionStore(path, identity=ctx["identity"]) as reader:
        assert reader.load_current().publication_id == winner["publication_id"]
        assert reader._con.execute("SELECT COUNT(*) FROM person_admission_publications").fetchone()[0] == 1


@pytest.mark.parametrize("checkpoint", ["crash-after-pointer", "crash-precommit"])
def test_actual_process_exit_before_commit_preserves_last_known_good(ready, checkpoint):
    path, ctx, rid = ready
    with durable.PersonTwinAdmissionStore(path, identity=ctx["identity"], read_only=False) as store:
        assert _admit(store, ctx, rid)["status"] == "PASS"
        old = store.load_current()
    crashed = _run_child(checkpoint, path, ctx["identity"])
    assert crashed.returncode == 73, (crashed.stdout, crashed.stderr)
    with durable.PersonTwinAdmissionStore(path, identity=ctx["identity"]) as reader:
        assert reader.load_current() == old
        assert reader._con.execute("PRAGMA foreign_key_check").fetchall() == []


def test_deferred_fk_refuses_pointer_without_receipt(ready):
    path, ctx, rid = ready
    with durable.PersonTwinAdmissionStore(path, identity=ctx["identity"], read_only=False) as store:
        store._con.execute("BEGIN IMMEDIATE")
        store._con.execute("INSERT INTO person_admission_current VALUES(?,?,?,?)", (store.twin_key, "missing", b'{}', "bad"))
        with pytest.raises(sqlite3.IntegrityError):
            store._con.execute("COMMIT")
        store._con.execute("ROLLBACK")
        assert store.load_current() is None


@pytest.mark.parametrize("memory_id", [True, 0, -1, "3"])
def test_malformed_memory_identity_cannot_stage(ready, memory_id):
    path, ctx, _ = ready
    with durable.PersonTwinAdmissionStore(path, identity=ctx["identity"], read_only=False) as store:
        value = _admit(store, ctx, memory_id)
        assert value["status"] == "HOLD" and value["possible_persisted_effect"] is False
        assert store.load_current() is None


@pytest.mark.parametrize("mode", ["missing-ledger", "extra-field", "bad-time", "expired"])
def test_fresh_input_shape_or_expiry_cannot_stage(ready, mode):
    path, ctx, rid = ready
    def bad():
        value = _fresh(ctx)
        if mode == "missing-ledger":
            del value["current_revocation_ledger"]
        elif mode == "extra-field":
            value["authorization_granted"] = True
        elif mode == "bad-time":
            value["at"] = "not-a-timestamp"
        else:
            value["at"] = "2026-08-27T12:50:00Z"
        return value
    with durable.PersonTwinAdmissionStore(path, identity=ctx["identity"], read_only=False) as store:
        value = _admit(store, ctx, rid, bad)
        assert value["status"] == "HOLD"
        assert store.load_current() is None


def test_failed_postverify_retains_only_noncurrent_candidate(ready):
    path, ctx, rid = ready
    calls = 0
    def fail_third():
        nonlocal calls
        calls += 1
        if calls == 3:
            raise OSError("SYNTHETIC_PROVIDER_UNAVAILABLE")
        return _fresh(ctx)
    with durable.PersonTwinAdmissionStore(path, identity=ctx["identity"], read_only=False) as store:
        result = _admit(store, ctx, rid, fail_third)
        assert result["status"] == "HOLD" and result["candidate_persisted"] is True
        assert result["commit_state"] == "NOT_ATTEMPTED"
        assert store.read_candidate_bytes(ctx["person_record"]["id"]) == durable._canonical(ctx["person_record"])
        assert store.load_current() is None


def test_next_promotion_preserves_exact_receipt_predecessor(ready):
    path, ctx, rid = ready
    with durable.PersonTwinAdmissionStore(path, identity=ctx["identity"], read_only=False) as store:
        assert _admit(store, ctx, rid)["status"] == "PASS"
        first = store.load_current()
        assert _admit(store, ctx, rid)["status"] == "PASS"
        second = store.load_current()
        assert first.publication_id != second.publication_id
        assert first.candidate_bytes == second.candidate_bytes
        assert second.receipt["expected_pointer_sha256"] == durable._hash(first.pointer_bytes)
        assert second.receipt_bytes != first.receipt_bytes
        assert store._con.execute("SELECT COUNT(*) FROM person_admission_publications").fetchone()[0] == 2


def test_reentrant_admit_does_not_replace_the_outer_transaction(ready):
    path, ctx, rid = ready
    with durable.PersonTwinAdmissionStore(path, identity=ctx["identity"], read_only=False) as store:
        calls = 0
        def provider():
            nonlocal calls
            calls += 1
            with pytest.raises(durable.DurableAdmissionError):
                _admit(store, ctx, rid)
            return _fresh(ctx)
        result = _admit(store, ctx, rid, provider)
        assert result["status"] == "PASS" and calls == 4
        assert store._phase is None and store._active is None
        assert store._con.execute("SELECT COUNT(*) FROM person_admission_publications").fetchone()[0] == 1


def test_lock_contention_holds_without_automatic_replay(ready):
    path, ctx, rid = ready
    with durable.PersonTwinAdmissionStore(path, identity=ctx["identity"], read_only=False, timeout=0.05) as store:
        lock = sqlite3.connect(path, isolation_level=None)
        try:
            lock.execute("BEGIN IMMEDIATE")
            outcome = _admit(store, ctx, rid)
            assert outcome["status"] == "HOLD"
        finally:
            lock.execute("ROLLBACK")
            lock.close()
        assert store.load_current() is None
        assert store._con.execute("SELECT COUNT(*) FROM person_admission_candidates").fetchone()[0] == 0


def test_changed_foreign_key_setting_cannot_publish(ready):
    path, ctx, rid = ready
    with durable.PersonTwinAdmissionStore(path, identity=ctx["identity"], read_only=False) as store:
        store._con.execute("PRAGMA foreign_keys=OFF")
        result = _admit(store, ctx, rid)
        assert result["status"] == "HOLD" and result["possible_persisted_effect"] is False
        store._con.execute("PRAGMA foreign_keys=ON")
        assert store.load_current() is None


def test_unverified_rollback_suspends_connection_and_keeps_hold(ready):
    path, ctx, rid = ready
    with durable.PersonTwinAdmissionStore(path, identity=ctx["identity"], read_only=False) as store:
        class Fault:
            def __init__(self, real):
                self.real = real
            def __getattr__(self, name):
                return getattr(self.real, name)
            def execute(self, sql, args=()):
                if sql == "ROLLBACK":
                    raise OSError("SYNTHETIC_ROLLBACK_ACK_LOST")
                return self.real.execute(sql, args)
        store._con = Fault(store._con)
        calls = 0
        def fail_promotion():
            nonlocal calls
            calls += 1
            if calls == 4:
                raise OSError("SYNTHETIC_PROVIDER_FAILURE")
            return _fresh(ctx)
        result = _admit(store, ctx, rid, fail_promotion)
        assert result["status"] == "HOLD" and result["reason"] == "ROLLBACK_UNVERIFIED"
        assert result["possible_persisted_effect"] is True and result["admission_receipt"] is None
        with pytest.raises(durable.DurableAdmissionError):
            store.load_current()
        with pytest.raises(durable.DurableAdmissionError):
            _admit(store, ctx, rid)
    with durable.PersonTwinAdmissionStore(path, identity=ctx["identity"]) as fresh:
        assert fresh.load_current() is None


# A4: admission's stored row binding must constrain the existing R21H intent.
def _a4_attempt(path, identity, *, selected_id=None, cold=False, decorate=None):
    with durable.PersonTwinAdmissionStore(path, identity=identity) as store:
        snapshot = store.load_current()
        context = _context(snapshot, store)
        if decorate is not None:
            context["admission_store"] = decorate(store)
        intent = PersonReadIntent(
            query_sha256=hashlib.sha256(QUERY.encode()).hexdigest(),
            current_session_sha256=durable._hash(durable._canonical(context["current_session"])),
            request_id=context["authorization_request"]["request_id"],
            packet_id=context["authorization_preflight"]["packet_id"],
            memory_id=snapshot.binding["memory_id"] if selected_id is None else selected_id,
            namespace=snapshot.binding["namespace"], person_record_id=snapshot.candidate["id"],
            source_record_id=snapshot.anchors["source_record"]["id"],
            principal_id=context["principal_id"], scope=context["requested_scope"],
            privacy_class=context["requested_privacy_class"], purpose=context["purpose"],
        )
        class Provider:
            reads = 0
            def read_context(self):
                self.reads += 1
                return dict(context)
        provider = Provider()
        profile = replace(DEFAULT_PROFILES["fast"], model="synthetic-a4-binding")
        model = demo._RecordingModel(profile, cold=cold)
        runtime = SovereignTwinRuntime(str(path), client=model,
            profiles={**DEFAULT_PROFILES, "fast": profile},
            person_evidence_adapter=PersonTwinR21HEvidenceAdapter(intent, provider))
        gets = []
        original_get = runtime.memory.store.get
        def traced_get(rid):
            gets.append(rid)
            return original_get(rid)
        runtime.memory.store.get = traced_get
        try:
            try:
                answer = runtime.ask(QUERY)
            except PersonTwinEvidenceError as exc:
                return {"decision":"DENY", "reason":str(exc), "calls":len(model.calls),
                        "memory_gets":gets, "provider_reads":provider.reads}
            assert len(model.calls) == 1
            rows = json.loads(model.calls[0]["system_prompt"].split("MEMORY_EVIDENCE_JSON:\n", 1)[1])
            return {"decision":answer.stats["person_evidence"]["decision"], "calls":len(model.calls),
                    "memory_gets":gets, "provider_reads":provider.reads,
                    "refs":[r["ref"] for r in rows], "receipt":answer.stats["person_evidence"]}
        finally:
            runtime.close()


@pytest.mark.parametrize("cold", [False, True])
@pytest.mark.parametrize("selection", ["bound", "identical_other_row", "different_text", "different_namespace", "superseded", "missing"])
def test_a4_exact_stored_row_binding_before_warm_and_streaming_models(ready, cold, selection):
    from contextlib import closing
    path, ctx, rid = ready
    with durable.PersonTwinAdmissionStore(path, identity=ctx["identity"], read_only=False) as writer:
        assert _admit(writer, ctx, rid)["status"] == "PASS"
    selected = rid
    if selection not in {"bound", "missing"}:
        with closing(sqlite3.connect(path)) as con, con:
            names = [r[1] for r in con.execute("PRAGMA table_info(items)") if r[1] != "id"]
            columns = ",".join('"' + n + '"' for n in names)
            selected = con.execute(f"INSERT INTO items ({columns}) SELECT {columns} FROM items WHERE id=?", (rid,)).lastrowid
            assert selected != rid
            if selection == "different_text":
                con.execute("UPDATE items SET text=? WHERE id=?", ("SYNTHETIC_OTHER_TEXT", selected))
            elif selection == "different_namespace":
                con.execute("UPDATE items SET namespace=? WHERE id=?", ("synthetic-other-ns", selected))
            elif selection == "superseded":
                con.execute("UPDATE items SET meta=? WHERE id=?", ('{"superseded_by":999}', selected))
    elif selection == "missing":
        selected = 999999
    before = path.read_bytes()
    value = _a4_attempt(path, ctx["identity"], selected_id=selected, cold=cold)
    assert path.read_bytes() == before
    if selection == "bound":
        assert value["decision"] == "ALLOW" and value["calls"] == 1
        assert value["refs"] == [f"mem:{rid}"]
        assert set(value["receipt"]) == demo.PERSON_RECEIPT_KEYS
    else:
        assert value["decision"] == "DENY" and value["calls"] == 0, value
        assert value["memory_gets"] == []
        assert value["reason"] == "PERSON_ADMISSION_MEMORY_BINDING_MISMATCH"


@pytest.mark.parametrize("fault", ["absent", "noncallable", "none", "text", "invalid_json", "duplicate_key", "noncanonical", "bool_id", "memory_id", "namespace", "pointer_sha256", "candidate_sha256", "person_record_id", "source_record_id", "extra", "exception"])
def test_a4_binding_interface_has_no_fallback_or_caller_override(ready, fault):
    path, ctx, rid = ready
    with durable.PersonTwinAdmissionStore(path, identity=ctx["identity"], read_only=False) as writer:
        assert _admit(writer, ctx, rid)["status"] == "PASS"
    def decorate(store):
        class Proxy:
            def read_current_pointer_bytes(self):
                return store.read_current_pointer_bytes()
            def read_candidate_bytes(self, candidate_id):
                return store.read_candidate_bytes(candidate_id)
        proxy = Proxy()
        if fault == "absent":
            return proxy
        if fault == "noncallable":
            proxy.read_current_memory_binding_bytes = b"not-a-callable"
            return proxy
        raw = store.read_current_memory_binding_bytes()
        record = json.loads(raw)
        def read_binding():
            if fault == "exception":
                raise ValueError("SYNTHETIC_PRIVATE_A4_READ_ERROR")
            if fault == "none": return None
            if fault == "text": return raw.decode()
            if fault == "invalid_json": return b"not json"
            if fault == "duplicate_key": return b'{"memory_id":999,' + raw[1:]
            if fault == "noncanonical": return json.dumps(record, indent=2).encode()
            changed = dict(record)
            if fault == "bool_id": changed["memory_id"] = True
            elif fault == "extra": changed["unexpected"] = "must deny"
            elif fault == "memory_id": changed["memory_id"] = rid + 1
            else: changed[fault] = "SYNTHETIC_WRONG_BINDING"
            return durable._canonical(changed)
        proxy.read_current_memory_binding_bytes = read_binding
        return proxy
    before = path.read_bytes()
    result = _a4_attempt(path, ctx["identity"], decorate=decorate)
    assert result["decision"] == "DENY" and result["calls"] == 0
    assert result["memory_gets"] == []
    assert "SYNTHETIC_PRIVATE" not in result["reason"]
    assert "SYNTHETIC_WRONG" not in result["reason"]
    assert path.read_bytes() == before


@pytest.mark.parametrize("cold", [False, True])
def test_a4_read_binding_is_rechecked_at_the_final_prompt_boundary(ready, cold):
    path, ctx, rid = ready
    with durable.PersonTwinAdmissionStore(path, identity=ctx["identity"], read_only=False) as writer:
        assert _admit(writer, ctx, rid)["status"] == "PASS"
    reads = []
    def decorate(store):
        class Proxy:
            def read_current_pointer_bytes(self):
                return store.read_current_pointer_bytes()
            def read_candidate_bytes(self, candidate_id):
                return store.read_candidate_bytes(candidate_id)
            def read_current_memory_binding_bytes(self):
                raw = store.read_current_memory_binding_bytes()
                reads.append(raw)
                if len(reads) == 2:
                    value = json.loads(raw)
                    value["memory_id"] = rid + 1
                    return durable._canonical(value)
                return raw
        return Proxy()
    before = path.read_bytes()
    value = _a4_attempt(path, ctx["identity"], cold=cold, decorate=decorate)
    assert value["decision"] == "DENY" and value["calls"] == 0
    assert len(reads) == 2 and value["provider_reads"] == 2
    assert value["memory_gets"] == [rid]
    assert path.read_bytes() == before


def test_a4_saved_binding_read_is_fresh_exact_and_nonmutating(ready):
    path, ctx, rid = ready
    with durable.PersonTwinAdmissionStore(path, identity=ctx["identity"]) as empty:
        assert empty.read_current_memory_binding_bytes() is None
    with durable.PersonTwinAdmissionStore(path, identity=ctx["identity"], read_only=False) as writer:
        assert _admit(writer, ctx, rid)["status"] == "PASS"
    before = path.read_bytes()
    with durable.PersonTwinAdmissionStore(path, identity=ctx["identity"]) as reader:
        snapshot = reader.load_current()
        first = reader.read_current_memory_binding_bytes()
        assert first == reader.read_current_memory_binding_bytes()
        value = json.loads(first)
        assert first == durable._canonical(value)
        assert value["memory_id"] == rid and value["namespace"] == NS
        assert value["pointer_sha256"] == durable._hash(snapshot.pointer_bytes)
        assert value["candidate_sha256"] == durable._hash(snapshot.candidate_bytes)
        assert reader._con.execute("PRAGMA query_only").fetchone()[0] == 1
        reader._suspended = True
        with pytest.raises(durable.DurableAdmissionError):
            reader.read_current_memory_binding_bytes()
    assert path.read_bytes() == before


# A3: a prospective transaction identifier is not proof of a committed publication.
def _a3_assert_result_ids(value, *, attempted, confirmed):
    expected_keys = {
        "schema", "status", "reason", "candidate_persisted", "candidate_commit_state",
        "commit_state", "possible_persisted_effect", "publication_id",
        "attempt_publication_id", "admission_receipt", "production_admission_status",
        "execution_authority", "can_execute", "can_trade", "capital_permission",
    }
    assert set(value) == expected_keys
    attempt = value["attempt_publication_id"]
    if attempted:
        assert type(attempt) is str and len(attempt) == 32
        assert set(attempt) <= set("0123456789abcdef")
    else:
        assert attempt is None
    assert value["publication_id"] == (attempt if confirmed else None)
    assert value["production_admission_status"] == "NOT_PRODUCTION_ADMITTED"
    assert value["execution_authority"] == "NONE"
    assert value["can_execute"] is False and value["can_trade"] is False
    assert value["capital_permission"] == "DENY"
    if value["status"] == "HOLD":
        assert value["admission_receipt"] is None
    assert "SYNTHETIC_PRIVATE_A3" not in json.dumps(value)


@pytest.mark.parametrize("effect,attempted,candidate", [
    ("admit", False, False),
    ("candidate_write", False, False),
    ("candidate_commit", False, False),
    ("promotion_begin", False, True),
    ("pointer_write", True, True),
    ("promotion_commit", True, True),
])
def test_a3_precommit_denial_has_no_confirmed_publication(ready, monkeypatch, effect, attempted, candidate):
    path, ctx, rid = ready
    calls = []
    original = durable.assert_current_effect_allowed
    def deny_one(name):
        if name == "person.admission." + effect:
            calls.append(name)
            raise RuntimeError("SYNTHETIC_PRIVATE_A3_ADDITIONAL_DENIAL")
        return original(name)
    with durable.PersonTwinAdmissionStore(path, identity=ctx["identity"], read_only=False) as store:
        with monkeypatch.context() as patch:
            patch.setattr(durable, "assert_current_effect_allowed", deny_one)
            value = _admit(store, ctx, rid)
        assert calls == ["person.admission." + effect]
        assert value["status"] == "HOLD" and value["commit_state"] == "NOT_ATTEMPTED"
        assert value["publication_id"] is None, value
        _a3_assert_result_ids(value, attempted=attempted, confirmed=False)
        assert value["candidate_persisted"] is candidate
        assert store.load_current() is None
        assert store._con.execute("SELECT COUNT(*) FROM person_admission_publications").fetchone()[0] == 0
        assert store._con.execute("SELECT COUNT(*) FROM person_admission_candidates").fetchone()[0] == int(candidate)


def test_a3_success_retains_the_same_publication_and_actual_receipt(ready):
    path, ctx, rid = ready
    with durable.PersonTwinAdmissionStore(path, identity=ctx["identity"], read_only=False) as store:
        value = _admit(store, ctx, rid)
        snapshot = store.load_current()
        assert value["status"] == "PASS" and value["commit_state"] == "CONFIRMED"
        _a3_assert_result_ids(value, attempted=True, confirmed=True)
        assert value["publication_id"] == snapshot.publication_id
        assert durable._canonical(value["admission_receipt"]) == snapshot.receipt_bytes
        # Attempt metadata belongs to the outer result, never to saved R3 bytes.
        assert "attempt_publication_id" not in snapshot.receipt
        assert snapshot.binding["memory_id"] == rid


class _A3CommitOutcomeFault:
    def __init__(self, store, phase, *, after_sql):
        self.store, self.real, self.phase = store, store._con, phase
        self.after_sql, self.calls = after_sql, 0
    def __getattr__(self, name):
        return getattr(self.real, name)
    def execute(self, sql, args=()):
        if sql == "COMMIT" and self.store._phase == self.phase:
            self.calls += 1
            if self.after_sql:
                self.real.execute(sql, args)
            raise OSError("SYNTHETIC_PRIVATE_A3_COMMIT_RESPONSE_LOST")
        return self.real.execute(sql, args)


@pytest.mark.parametrize("phase", ["CANDIDATE", "PROMOTING"])
@pytest.mark.parametrize("after_sql", [False, True])
def test_a3_uncertain_commit_preserves_attempt_not_confirmed_publication(ready, phase, after_sql):
    path, ctx, rid = ready
    with durable.PersonTwinAdmissionStore(path, identity=ctx["identity"], read_only=False) as store:
        fault = _A3CommitOutcomeFault(store, phase, after_sql=after_sql)
        store._con = fault
        value = _admit(store, ctx, rid)
        assert fault.calls == 1  # Never automatically retry an uncertain commit.
        assert value["status"] == "HOLD" and value["possible_persisted_effect"] is True
        assert value["publication_id"] is None, value
        _a3_assert_result_ids(value, attempted=phase == "PROMOTING", confirmed=False)
        assert value["commit_state"] == ("UNKNOWN" if phase == "PROMOTING" else "NOT_ATTEMPTED")
        assert value["candidate_commit_state"] == ("CONFIRMED" if phase == "PROMOTING" else "UNKNOWN")
        assert value["candidate_persisted"] is (True if phase == "PROMOTING" else None)
    with durable.PersonTwinAdmissionStore(path, identity=ctx["identity"]) as fresh:
        snapshot = fresh.load_current()
        persisted = phase == "PROMOTING" and after_sql
        assert (snapshot is not None) is persisted
        if persisted:
            assert snapshot.publication_id == value["attempt_publication_id"]
        assert fresh._con.execute("SELECT COUNT(*) FROM person_admission_publications").fetchone()[0] == int(persisted)
        assert fresh._con.execute("SELECT COUNT(*) FROM person_admission_candidates").fetchone()[0] == int(after_sql or phase == "PROMOTING")


@pytest.mark.parametrize("mode", ["unavailable", "mismatched-snapshot"])
def test_a3_postcommit_hold_preserves_confirmed_id_without_allow_receipt(ready, monkeypatch, mode):
    path, ctx, rid = ready
    original = durable.PersonTwinAdmissionStore.load_current
    with durable.PersonTwinAdmissionStore(path, identity=ctx["identity"], read_only=False) as store:
        def fault(instance):
            actual = original(instance)
            if instance is not store:
                if mode == "unavailable":
                    raise OSError("SYNTHETIC_PRIVATE_A3_READBACK_UNAVAILABLE")
                return replace(actual, publication_id="0" * 32)
            return actual
        with monkeypatch.context() as patch:
            patch.setattr(durable.PersonTwinAdmissionStore, "load_current", fault)
            value = _admit(store, ctx, rid)
        assert value["status"] == "HOLD" and value["reason"] == "POSTCOMMIT_READBACK_FAILED"
        assert value["commit_state"] == "CONFIRMED" and value["possible_persisted_effect"] is True
        _a3_assert_result_ids(value, attempted=True, confirmed=True)
        assert store.load_current().publication_id == value["publication_id"]
        assert store._con.execute("SELECT COUNT(*) FROM person_admission_publications").fetchone()[0] == 1


@pytest.mark.parametrize("phase", ["promotion_begin", "pointer_write", "promotion_commit", "unknown-before-sql"])
def test_a3_failed_republication_does_not_report_previous_current_as_its_own(ready, monkeypatch, phase):
    path, ctx, rid = ready
    with durable.PersonTwinAdmissionStore(path, identity=ctx["identity"], read_only=False) as store:
        first = _admit(store, ctx, rid)
        assert first["status"] == "PASS"
        before = store.load_current()
        original = durable.assert_current_effect_allowed
        def deny(name):
            if name == "person.admission." + phase:
                raise RuntimeError("SYNTHETIC_PRIVATE_A3_REPUBLICATION_DENIED")
            return original(name)
        with monkeypatch.context() as patch:
            patch.setattr(durable, "assert_current_effect_allowed", deny)
            if phase == "unknown-before-sql":
                fault = _A3CommitOutcomeFault(store, "PROMOTING", after_sql=False)
                store._con = fault
            value = _admit(store, ctx, rid)
        assert value["status"] == "HOLD" and value["publication_id"] is None
        _a3_assert_result_ids(value, attempted=phase != "promotion_begin", confirmed=False)
        assert value["attempt_publication_id"] != before.publication_id
        assert store.load_current() == before
        assert store._con.execute("SELECT COUNT(*) FROM person_admission_publications").fetchone()[0] == 1


def test_a3_attempt_identifier_is_reset_between_explicit_calls(ready, monkeypatch):
    path, ctx, rid = ready
    original = durable.assert_current_effect_allowed
    with durable.PersonTwinAdmissionStore(path, identity=ctx["identity"], read_only=False) as store:
        def deny_commit(name):
            if name == "person.admission.promotion_commit":
                raise RuntimeError("SYNTHETIC_PRIVATE_A3_DENY_COMMIT")
            return original(name)
        with monkeypatch.context() as patch:
            patch.setattr(durable, "assert_current_effect_allowed", deny_commit)
            first = _admit(store, ctx, rid)
        _a3_assert_result_ids(first, attempted=True, confirmed=False)
        def deny_start(name):
            if name == "person.admission.admit":
                raise RuntimeError("SYNTHETIC_PRIVATE_A3_DENY_START")
            return original(name)
        with monkeypatch.context() as patch:
            patch.setattr(durable, "assert_current_effect_allowed", deny_start)
            second = _admit(store, ctx, rid)
        _a3_assert_result_ids(second, attempted=False, confirmed=False)
        third = _admit(store, ctx, rid)
        assert third["status"] == "PASS"
        _a3_assert_result_ids(third, attempted=True, confirmed=True)
        assert third["attempt_publication_id"] != first["attempt_publication_id"]


def test_a3_unverified_rollback_keeps_attempt_without_confirmation(ready, monkeypatch):
    path, ctx, rid = ready
    with durable.PersonTwinAdmissionStore(path, identity=ctx["identity"], read_only=False) as store:
        class RollbackFault:
            def __init__(self, real):
                self.real, self.rollbacks = real, 0
            def __getattr__(self, name):
                return getattr(self.real, name)
            def execute(self, sql, args=()):
                if sql == "ROLLBACK":
                    self.rollbacks += 1
                    raise OSError("SYNTHETIC_PRIVATE_A3_ROLLBACK_UNVERIFIED")
                return self.real.execute(sql, args)
        fault = RollbackFault(store._con)
        store._con = fault
        original = durable.assert_current_effect_allowed
        def deny(name):
            if name == "person.admission.promotion_commit":
                raise RuntimeError("SYNTHETIC_PRIVATE_A3_DENY_BEFORE_COMMIT")
            return original(name)
        with monkeypatch.context() as patch:
            patch.setattr(durable, "assert_current_effect_allowed", deny)
            value = _admit(store, ctx, rid)
        assert fault.rollbacks == 1
        assert value["status"] == "HOLD" and value["reason"] == "ROLLBACK_UNVERIFIED"
        assert value["commit_state"] == "NOT_ATTEMPTED" and value["possible_persisted_effect"] is True
        _a3_assert_result_ids(value, attempted=True, confirmed=False)
        with pytest.raises(durable.DurableAdmissionError):
            store.load_current()
        with pytest.raises(durable.DurableAdmissionError):
            _admit(store, ctx, rid)
    # Closing SQLite actually rolled it back, but the returned result must not
    # retroactively claim a successful rollback that its own code could not verify.
    with durable.PersonTwinAdmissionStore(path, identity=ctx["identity"]) as fresh:
        assert fresh.load_current() is None
