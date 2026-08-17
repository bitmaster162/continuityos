import sqlite3
import time
import pytest

from sct.store.sqlite import SQLiteEvidenceStore
from sct.store.testing import run_conformance


def test_store_conformance(tmp_path):
    store=SQLiteEvidenceStore(tmp_path/"evidence.db")
    checks=run_conformance(store)
    assert all(checks.values()), checks


def test_append_only_trigger_blocks_mutation(tmp_path):
    store=SQLiteEvidenceStore(tmp_path/"evidence.db")
    store.append("A",{"x":1},ts=1)
    with pytest.raises(sqlite3.IntegrityError):
        store._conn.execute("UPDATE event SET kind='B' WHERE seq=1")
    assert store.verify().ok


def test_10000_batched_appends_are_linear_and_fast(tmp_path):
    store=SQLiteEvidenceStore(tmp_path/"evidence.db")
    start=time.perf_counter()
    with store.transaction():
        for i in range(10_000): store.append("BENCH",{"i":i},ts=1+i/10000)
    elapsed=time.perf_counter()-start
    assert store.head().seq==10_000
    assert store.verify().ok
    # Generous local guard; CI target receipt will report the actual timing separately.
    assert elapsed < 10.0
