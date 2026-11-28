"""Public-path regressions for local budgeting, temporal recall and atomic writes."""
import json
import sqlite3
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import pytest

from continuityos.memory import Conflict, Memory
from continuityos.store import StoreOutcomeUnknown, StoreRecoveryFailed


@pytest.fixture
def memory(tmp_path):
    m = Memory(str(tmp_path / "memory.db"))
    yield m
    m.store.con.close()


def test_budget_and_cost_remain_local_with_sdk_and_key(memory, monkeypatch):
    calls = []
    def forbidden_client():
        calls.append("client-created")
        raise AssertionError("local budgeting must never initialize a provider")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "synthetic-test-key")
    monkeypatch.setitem(sys.modules, "anthropic", SimpleNamespace(Anthropic=forbidden_client))
    rid = memory.remember("PRIVATE_SYNTHETIC_CONTEXT local decision")
    context = memory.context("local decision", max_tokens=100)
    assert "PRIVATE_SYNTHETIC_CONTEXT" in context and f"mem:{rid}" in context
    assert memory.estimate_cost(context)["input_tokens"] > 0
    assert calls == []


def test_remote_count_requires_explicit_scope_and_obeys_effect_ceiling(memory, monkeypatch):
    calls = []
    def count_tokens(**kw):
        calls.append(kw)
        return SimpleNamespace(input_tokens=7)
    monkeypatch.setitem(sys.modules, "anthropic", SimpleNamespace(
        Anthropic=lambda: SimpleNamespace(messages=SimpleNamespace(count_tokens=count_tokens))))
    with pytest.raises(ValueError, match="DATA_SCOPE"):
        memory.estimate_tokens("synthetic", allow_network=True, provider="anthropic")
    assert calls == []
    assert memory.estimate_tokens("synthetic", allow_network=True,
                                  provider="anthropic", data_scope="test-only") == 7
    assert calls[0]["messages"][0]["content"] == "synthetic"
    from continuityos import current_effect_boundary
    def deny(_effect):
        raise PermissionError("test current-session ceiling")
    monkeypatch.setattr(current_effect_boundary, "assert_current_effect_allowed", deny)
    with pytest.raises(PermissionError):
        memory.estimate_tokens("denied", allow_network=True,
                               provider="anthropic", data_scope="test-only")
    assert len(calls) == 1


def test_falsey_callable_is_used_for_write_and_read(tmp_path):
    class Embedder:
        def __init__(self): self.calls = []
        def __bool__(self): return False
        def __call__(self, text):
            self.calls.append(text)
            return [1.0, 0.0]
    embedder = Embedder()
    m = Memory(str(tmp_path / "custom.db"), embedder=embedder)
    try:
        m.remember("one decision")
        assert m.recall("decision")
        assert m.embed is embedder
        assert embedder.calls == ["one decision", "decision"]
    finally:
        m.store.con.close()


def test_current_recall_respects_both_temporal_boundaries(memory):
    now = time.time()
    future = memory.remember("decision future", valid_from=now + 3600)
    current = memory.remember("decision current", valid_from=now - 3600, valid_to=now + 3600)
    expired = memory.remember("decision expired", valid_from=now - 7200, valid_to=now - 3600)
    ids = {h.id for h in memory.recall("decision", k=10, current_only=True)}
    assert ids == {current}
    assert future not in ids and expired not in ids


def test_scope_and_time_filter_precede_candidate_limit(memory):
    for n in range(60):
        memory.remember("decision token token", meta={"project": "foreign"})
    wanted = memory.remember("decision token", meta={"project": "ours"})
    result = memory.recall("decision token", k=1, current_only=True,
                           scope={"project": "ours", "subject": None})
    assert [h.id for h in result] == [wanted]


def test_context_omits_superseded_text_by_default(memory):
    old = memory.remember("decision RETIRED_SENTINEL", namespace="facts")
    memory.supersede(old, "decision CURRENT_SENTINEL")
    context = memory.context("decision")
    assert "CURRENT_SENTINEL" in context and "RETIRED_SENTINEL" not in context


def test_fts_failure_rolls_back_the_base_item(memory):
    if not memory.store.fts:
        pytest.skip("SQLite fixture has no FTS5")
    def authorizer(action, table, _column, _database, _trigger):
        return sqlite3.SQLITE_DENY if action == sqlite3.SQLITE_INSERT and table == "items_fts" else sqlite3.SQLITE_OK
    memory.store.con.set_authorizer(authorizer)
    try:
        with pytest.raises(sqlite3.DatabaseError):
            memory.remember("must not leave an orphan")
    finally:
        memory.store.con.set_authorizer(None)
    assert memory.count() == 0
    assert not memory.store.con.in_transaction


def test_supersede_failure_preserves_old_current_and_no_new_item(memory, monkeypatch):
    old = memory.remember("decision original", namespace="facts", key="decision")
    def fail(*args, **kw):
        raise RuntimeError("injected predecessor update failure")
    monkeypatch.setattr(memory.store, "update_meta", fail)
    with pytest.raises(RuntimeError):
        memory.supersede(old, "decision incomplete")
    assert memory.count() == 1
    assert memory.find("facts", "decision").id == old
    assert "superseded_by" not in json.loads(memory.store.get(old)["meta"])
    assert not memory.store.con.in_transaction


def test_missing_predecessor_does_not_create_memory(memory):
    with pytest.raises(ValueError, match="PREDECESSOR_NOT_FOUND"):
        memory.supersede(999, "unbound replacement")
    assert memory.count() == 0


def test_nested_writes_do_not_commit_callers_transaction(memory):
    memory.store.con.execute("BEGIN IMMEDIATE")
    memory.remember("caller-owned transaction")
    assert memory.store.con.in_transaction
    memory.store.con.rollback()
    assert memory.count() == 0


def test_concurrent_checked_writers_accept_one_expected_version(tmp_path):
    path = str(tmp_path / "concurrent.db")
    initial = Memory(path)
    initial.upsert("initial", "facts", key="selected")
    initial.store.con.close()
    writers = [Memory(path) for _ in range(6)]
    ready = threading.Barrier(len(writers))
    def write(item):
        index, m = item
        ready.wait(timeout=10)
        try:
            return ("committed", m.write_checked(str(index), "facts", "selected", 1))
        except Conflict:
            return ("conflict", None)
    try:
        with ThreadPoolExecutor(max_workers=len(writers)) as pool:
            results = list(pool.map(write, enumerate(writers)))
        assert sum(kind == "committed" for kind, _ in results) == 1
        assert sum(kind == "conflict" for kind, _ in results) == 5
        assert writers[0].count() == 2
        assert writers[0].store.current_version("facts", "selected") == 2
        assert len(writers[0].recall("", current_only=True)) == 1
    finally:
        for m in writers:
            m.store.con.close()


def test_loop_closure_is_retained_and_retry_does_not_rewrite_it(memory):
    rid = memory.remember("finished work", namespace="loop", meta={"open": True})
    assert memory.store.close_loop(rid, result="artifact", proof="source:1")
    saved = dict(memory.store.get(rid))
    assert memory.store.close_loop(rid, result="retry must not replace evidence")
    assert dict(memory.store.get(rid)) == saved
    assert saved["text"] == "finished work"
    assert json.loads(saved["meta"])["closure_history"][0]["proof"] == "source:1"


def test_shared_reader_waits_for_failed_managed_write(memory, monkeypatch):
    old = memory.remember("decision original")
    writer_pending, release_writer = threading.Event(), threading.Event()
    reader_started, reader_done = threading.Event(), threading.Event()
    def fail_after_new_item(*args, **kwargs):
        writer_pending.set()
        assert release_writer.wait(5)
        raise RuntimeError("predecessor update failed")
    def read_count():
        reader_started.set()
        value = memory.count()
        reader_done.set()
        return value
    monkeypatch.setattr(memory.store, "update_meta", fail_after_new_item)
    with ThreadPoolExecutor(max_workers=2) as pool:
        writer = pool.submit(memory.supersede, old, "uncommitted replacement")
        try:
            assert writer_pending.wait(5)
            reader = pool.submit(read_count)
            assert reader_started.wait(5)
            assert not reader_done.wait(0.05)
        finally:
            release_writer.set()
        with pytest.raises(RuntimeError, match="predecessor update failed"):
            writer.result(timeout=5)
        assert reader.result(timeout=5) == 1
    assert [h.id for h in memory.recall("decision", current_only=True)] == [old]


def test_recall_pins_keyword_and_vector_legs_to_one_snapshot(memory, monkeypatch):
    original = memory.remember("decision original")
    hidden = memory.remember("decision newly active", meta={"active": False})
    peer = Memory(memory.store.path)
    keyword_search = memory.store.keyword_search
    def mutate_after_keyword_read(*args, **kwargs):
        rows = keyword_search(*args, **kwargs)
        peer.store.update_meta(hidden, {"active": True})
        return rows
    monkeypatch.setattr(memory.store, "keyword_search", mutate_after_keyword_read)
    try:
        assert {h.id for h in memory.recall("decision", k=10, current_only=True)} == {original}
        assert {h.id for h in peer.recall("decision", k=10, current_only=True)} == {original, hidden}
    finally:
        peer.store.con.close()


class _ConnectionProxy:
    def __init__(self, con):
        self.con = con
    def __getattr__(self, name):
        return getattr(self.con, name)


def test_lost_commit_reply_suspends_without_retry_and_requires_reconciliation(memory):
    class LostReply(_ConnectionProxy):
        attempts = 0
        def commit(self):
            self.attempts += 1
            self.con.commit()
            raise sqlite3.OperationalError("commit reply lost after persistence")
    connection = LostReply(memory.store.con)
    memory.store.con = connection
    with pytest.raises(StoreOutcomeUnknown, match="OUTCOME_UNKNOWN"):
        memory.remember("one durable effect")
    with pytest.raises(StoreOutcomeUnknown, match="SUSPENDED"):
        memory.remember("must not retry")
    with pytest.raises(StoreOutcomeUnknown, match="SUSPENDED"):
        memory.count()
    assert connection.attempts == 1
    with sqlite3.connect(memory.store.path) as fresh:
        assert fresh.execute("SELECT text FROM items").fetchall() == [("one durable effect",)]


def test_failed_rollback_suspends_the_store(memory):
    class BrokenRollback(_ConnectionProxy):
        def rollback(self):
            raise sqlite3.OperationalError("rollback unavailable")
    memory.store.con = BrokenRollback(memory.store.con)
    with pytest.raises(StoreRecoveryFailed, match="ROLLBACK_UNVERIFIED"):
        with memory.store.transaction():
            memory.remember("uncommitted")
            raise RuntimeError("abort body")
    with pytest.raises(StoreOutcomeUnknown, match="SUSPENDED"):
        memory.remember("further write")
    with sqlite3.connect(memory.store.path) as fresh:
        assert fresh.execute("SELECT count(*) FROM items").fetchone()[0] == 0


def test_effect_ceiling_is_rechecked_before_commit(memory, monkeypatch):
    from continuityos import store
    disabled = False
    def check(effect):
        if disabled:
            raise PermissionError("effects disabled before " + effect)
    monkeypatch.setattr(store, "assert_current_effect_allowed", check)
    with pytest.raises(PermissionError, match="memory.store.commit"):
        with memory.store.transaction():
            memory.remember("not authorized at commit")
            disabled = True
    assert memory.count() == 0
    assert not memory.store.con.in_transaction


def test_retired_records_cannot_starve_current_retrieval(memory):
    for _ in range(60):
        memory.remember("decision token token", meta={"status": "REVOKED"})
    current = memory.remember("decision token")
    assert [h.id for h in memory.recall("decision token", k=1, current_only=True)] == [current]


@pytest.mark.parametrize("meta", [{"valid_from": True}, {"valid_from": "0"},
                                  {"valid_to": float("nan")}, {"valid_to": False}])
def test_malformed_temporal_metadata_is_not_current(memory, meta):
    memory.remember("malformed decision", meta=meta)
    assert memory.recall("decision", current_only=True) == []


def test_cost_and_compaction_expose_configuration_without_claiming_calibration(memory):
    estimate = memory.estimate_cost("synthetic context")
    assert estimate["pricing_kind"] == "UNVERIFIED_STATIC_CONFIGURATION"
    assert not estimate["pricing_verified"]
    assert estimate["token_count_kind"] == "LOCAL_CHARACTER_ESTIMATE"
    with pytest.raises(ValueError, match="UNCONFIGURED_MODEL_PRICING"):
        memory.estimate_cost("synthetic context", model_id="unconfigured")
    policy = memory.compaction_policy("caller-model", context_tokens=1000, frac=0.5)
    assert policy["threshold_tokens"] == 500
    assert policy["basis"] == "CALLER_CONTEXT_BUDGET"
    assert not policy["calibrated"] and policy["measurement_receipt"] is None
    assert memory.compaction_policy()["basis"] == "LEGACY_UNCALIBRATED_CONFIGURATION"


@pytest.mark.parametrize("frac", [0, -0.1, 1.1, True, float("nan")])
def test_invalid_compaction_policy_is_rejected(memory, frac):
    with pytest.raises(ValueError, match="frac"):
        memory.compaction_threshold(frac=frac)
