"""Tests: bi-temporal memory (Zep pattern), auto-extraction (Mem0 ADD-only),
headroom-style tool-output compression."""
import json, os, tempfile, time
import pytest
from continuityos import Memory
from continuityos.extract import extract, extract_and_store
from continuityos.gc import compress_tool_output


@pytest.fixture
def m():
    return Memory(os.path.join(tempfile.mkdtemp(), "t.db"))


def test_supersede_links_and_hides(m):
    old = m.remember("BTC regime is up_mild", namespace="facts", mtype="fact")
    time.sleep(0.01)
    new = m.supersede(old, "BTC regime is down_strong", mtype="fact")
    om = json.loads(m.store.get(old)["meta"])
    assert om["superseded_by"] == new and om["valid_to"] > 0
    cur = m.recall("BTC regime", k=5, current_only=True)
    ids = [h.id for h in cur]
    assert new in ids and old not in ids


def test_as_of_time_travel(m):
    t0 = time.time()
    old = m.remember("leader is Alice", namespace="facts")
    time.sleep(0.02)
    t1 = time.time()
    time.sleep(0.02)
    m.supersede(old, "leader is Bob")
    then = m.recall("who is leader", as_of=t1, k=5)
    assert [h.id for h in then] == [old]  # Bob not yet valid at t1
    before = m.recall("who is leader", as_of=t0 - 10, k=5)
    assert before == []  # nothing was true before we learned it


def test_mtype_filter(m):
    m.remember("prefers Apache-2.0", mtype="preference", namespace="rules")
    m.remember("Apache released httpd", mtype="fact", namespace="rules")
    hits = m.recall("Apache", mtype="preference", k=5, namespace="rules")
    assert len(hits) == 1 and hits[0].meta["type"] == "preference"


def test_extract_heuristic_types():
    text = ("We decided to park all 1m bots. I prefer market-neutral edges. "
            "The deploy failed with an error yesterday. Nice weather, huh?")
    cands = extract(text)
    types = {c["type"] for c in cands}
    assert "decision" in types and "preference" in types
    assert all(c["confidence"] >= 0.5 for c in cands)


def test_extract_and_store_add_only_dedup(m):
    text = "We decided to lock Inner Circle pricing at $997/mo."
    ids1 = extract_and_store(text, m)
    ids2 = extract_and_store(text, m)  # same text again -> duplicate guard
    assert len(ids1) == 1 and ids2 == []
    assert m.recall("Inner Circle pricing", k=1)[0].meta["source"] == "auto-extract"


def test_compress_json_table():
    rows = [{"sym": "BTC", "pnl": i, "note": None} for i in range(300)]
    out = compress_tool_output(json.dumps(rows), max_chars=800)
    assert len(out) <= 900 and "sym | pnl | note" in out


def test_compress_text_elision():
    out = compress_tool_output("word " * 5000, max_chars=1000)
    assert len(out) < 1200 and "elided" in out


def test_backward_compat_plain_remember(m):
    rid = m.remember("plain old fact")
    assert m.recall("plain old fact", k=1)[0].id == rid
