import tempfile, os, threading, json, urllib.request, time
os.environ["CONTINUITYOS_SILENCE_EMBED_WARN"] = "1"
from continuityos import ledger_server as L
from continuityos.gate.ledger import Ledger

def _srv(port):
    d = tempfile.mkdtemp(); path = os.path.join(d, "f.db")
    h = L.serve(path, "sec", port=port); threading.Thread(target=h.serve_forever, daemon=True).start()
    time.sleep(0.2); return h, path, d

def test_scopes_and_append_and_verify():
    h, path, d = _srv(8393)
    try:
        wt = L.mint_token("sec", "bitevo", "write"); rt = L.mint_token("sec", "arena", "read")
        good = L.LedgerSink("http://127.0.0.1:8393", wt, buffer=os.path.join(d, "b.jsonl"), timeout=3)
        assert "hash" in good.record("trade", {"sym": "ETH"})
        rw = L.LedgerSink("http://127.0.0.1:8393", rt, buffer=os.path.join(d, "b2.jsonl"), timeout=3)
        assert rw.record("x", {}).get("buffered")            # read scope can't write -> fail-open buffered
        req = urllib.request.Request("http://127.0.0.1:8393/ledger/verify", headers={"Authorization": "Bearer " + rt})
        assert json.loads(urllib.request.urlopen(req, timeout=3).read())["ok"]
    finally:
        h.shutdown()

def test_fail_open_when_server_down():
    d = tempfile.mkdtemp()
    sink = L.LedgerSink("http://127.0.0.1:9", L.mint_token("sec", "x", "write"), buffer=os.path.join(d, "buf.jsonl"), timeout=0.4)
    assert sink.record("trade", {"a": 1}).get("buffered")     # never raises
    assert os.path.exists(os.path.join(d, "buf.jsonl"))

def test_tamper_detected():
    d = tempfile.mkdtemp(); path = os.path.join(d, "t.db"); led = Ledger(path)
    led.append("gate", {"decision": "DENY"}); led.append("trade", {"sym": "BTC"})
    assert Ledger(path).verify()["ok"]
    led2 = Ledger(path); led2.con.execute("UPDATE events SET payload='{}' WHERE id=1"); led2.con.commit()
    assert not Ledger(path).verify()["ok"]
