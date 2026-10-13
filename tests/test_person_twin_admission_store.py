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
