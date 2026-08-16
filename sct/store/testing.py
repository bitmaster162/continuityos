from __future__ import annotations


def run_conformance(store) -> dict[str, bool]:
    checks: dict[str, bool] = {}
    h0 = store.head(); checks["empty_head"] = h0.seq == 0 and h0.event_hash is None
    a = store.append("TEST_A", {"x": 1}, ts=1.0)
    b = store.append("TEST_B", {"x": 2}, ts=2.0)
    checks["dense_seq"] = (a.seq, b.seq) == (1, 2)
    checks["chain_link"] = b.prev_hash == a.event_hash
    checks["get"] = store.get(a.event_id) == a
    checks["query_order"] = [x.seq for x in store.query()] == [1, 2]
    checks["verify"] = store.verify().ok is True
    blob = store.put_blob(b"sct")
    checks["blob_idempotent"] = store.put_blob(b"sct") == blob and store.get_blob(blob) == b"sct"
    try:
        with store.transaction():
            store.append("TX", {"ok": False}, ts=3.0)
            raise RuntimeError("rollback")
    except RuntimeError:
        pass
    checks["rollback"] = not any(x.kind == "TX" for x in store.query())
    required = {"blob", "transaction", "stream_query", "concurrent_append"}
    checks["capabilities"] = required.issubset(store.capabilities())
    return checks
