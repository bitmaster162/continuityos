"""Offline tests for the HMOS upstream: key-based find() + upsert() + meta-index."""
import os, json, tempfile
os.environ["CONTINUITYOS_SILENCE_EMBED_WARN"] = "1"
from continuityos.memory import Memory

def _m():
    return Memory(os.path.join(tempfile.mkdtemp(), "m.db"))

def test_upsert_creates_then_updates():
    m = _m()
    a = m.upsert("v1", "config", key="model")
    b = m.upsert("v2", "config", key="model")
    assert a != b
    hit = m.find("config", "model")
    assert hit is not None and hit.text == "v2"                 # latest wins
    assert "superseded_by" in json.loads(m.store.get(a)["meta"])  # history kept
    print("PASS upsert_creates_then_updates")

def test_find_missing_returns_none():
    assert _m().find("config", "nope") is None
    print("PASS find_missing_returns_none")

def test_find_exact_not_fuzzy():
    m = _m()
    m.upsert("Apache-2.0", "rules", key="license")
    m.remember("a long note that mentions licenses in passing", namespace="rules")
    hit = m.find("rules", "license")
    assert hit.text == "Apache-2.0" and hit.why == "key"
    print("PASS find_exact_not_fuzzy")

def test_single_current_per_key():
    m = _m()
    for v in ["a", "b", "c", "d"]:
        m.upsert(v, "ns", key="k")
    rows = m.store.con.execute("SELECT * FROM items WHERE namespace='ns' AND key='k'").fetchall()
    current = [r for r in rows if "superseded_by" not in json.loads(r["meta"])]
    assert len(rows) == 4 and len(current) == 1 and m.find("ns", "k").text == "d"
    print("PASS single_current_per_key")

def test_key_column_and_index_exist():
    m = _m()
    cols = {r[1] for r in m.store.con.execute("PRAGMA table_info(items)").fetchall()}
    idx = {r[1] for r in m.store.con.execute("PRAGMA index_list(items)").fetchall()}
    assert "key" in cols and "idx_items_key" in idx
    print("PASS key_column_and_index_exist")

def test_remember_still_keyless():
    m = _m()
    assert m.remember("plain", namespace="notes") > 0 and m.find("notes", "x") is None
    print("PASS remember_still_keyless")

def run():
    for n in sorted(x for x in globals() if x.startswith("test_")):
        globals()[n]()
    print("ALL_UPSERT_TESTS_PASS")

if __name__ == "__main__":
    run()
