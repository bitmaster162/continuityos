import hashlib, json, multiprocessing, os, tempfile, threading, time, urllib.request
import pytest
os.environ["CONTINUITYOS_SILENCE_EMBED_WARN"] = "1"
from continuityos import ledger_server as L
from continuityos.gate.ledger import Ledger


def _blocking_flush_worker(buffer, started, release, result_queue):
    class BlockingSink(L.LedgerSink):
        def _post(self, kind, payload):
            started.set()
            if not release.wait(15):
                raise TimeoutError("test release was not signaled")
            return {"hash": "a" * 64}

    sink = BlockingSink("http://unused", "token", buffer=buffer)
    try:
        result_queue.put({"sent": sink.flush()})
    except Exception as exc:
        result_queue.put({"error": f"{type(exc).__name__}: {exc}"})


def _offline_record_worker(buffer, result_queue):
    class OfflineSink(L.LedgerSink):
        def _post(self, kind, payload):
            raise OSError("injected offline ledger")

    sink = OfflineSink("http://unused", "token", buffer=buffer)
    result_queue.put(sink.record("trade", {"id": "must-survive"}))

def _srv(port=0):
    d = tempfile.mkdtemp(); path = os.path.join(d, "f.db")
    h = L.serve(path, "sec", port=port); threading.Thread(target=h.serve_forever, daemon=True).start()
    time.sleep(0.2); return h, path, d, h.server_address[1]

def test_scopes_and_append_and_verify():
    h, path, d, port = _srv()
    try:
        wt = L.mint_token("sec", "bitevo", "write"); rt = L.mint_token("sec", "arena", "read")
        url = f"http://127.0.0.1:{port}"
        good = L.LedgerSink(url, wt, buffer=os.path.join(d, "b.jsonl"), timeout=3)
        assert "hash" in good.record("trade", {"sym": "ETH"})
        rw = L.LedgerSink(url, rt, buffer=os.path.join(d, "b2.jsonl"), timeout=3)
        assert rw.record("x", {}).get("buffered")            # read scope can't write -> fail-open buffered
        req = urllib.request.Request(url + "/ledger/verify", headers={"Authorization": "Bearer " + rt})
        assert json.loads(urllib.request.urlopen(req, timeout=3).read())["ok"]
    finally:
        h.shutdown()
        h.server_close()

def test_fail_open_when_server_down():
    d = tempfile.mkdtemp()
    sink = L.LedgerSink("http://127.0.0.1:9", L.mint_token("sec", "x", "write"), buffer=os.path.join(d, "buf.jsonl"), timeout=0.4)
    assert sink.record("trade", {"a": 1}).get("buffered")     # never raises
    assert os.path.exists(os.path.join(d, "buf.jsonl"))

def test_tamper_detected():
    d = tempfile.mkdtemp(); path = os.path.join(d, "t.db")
    with Ledger(path) as led:
        led.append("gate", {"decision": "DENY"}); led.append("trade", {"sym": "BTC"})
    with Ledger(path) as check:
        assert check.verify()["ok"]
    with Ledger(path) as led2:
        led2.con.execute("UPDATE events SET payload='{}' WHERE id=1"); led2.con.commit()
    with Ledger(path) as check:
        assert not check.verify()["ok"]


def test_export_contains_self_sufficient_full_hash_chain(tmp_path):
    path = str(tmp_path / "export.db")
    with Ledger(path) as ledger:
        ledger.append("first", {"value": "spaced history"})
        ledger.append("second", {"value": 2})
        events = sorted(ledger.export(20), key=lambda item: item["id"])
    previous = "0" * 64
    for event in events:
        assert event["prev_hash"] == previous
        assert len(event["hash"]) == 64
        assert event["hash_scheme"] == "sha256-prev-kind-ts6-payload-v1"
        recomputed = hashlib.sha256(
            (
                event["prev_hash"]
                + event["kind"]
                + event["ts_text"]
                + event["payload_json"]
            ).encode("utf-8")
        ).hexdigest()
        assert recomputed == event["hash"]
        assert json.loads(event["payload_json"]) == event["payload"]
        previous = event["hash"]


def test_cross_process_flush_preserves_concurrent_buffered_record(tmp_path):
    buffer = str(tmp_path / "race.jsonl")
    with open(buffer, "w", encoding="utf-8", newline="\n") as stream:
        stream.write(json.dumps({
            "kind": "seed",
            "payload": {"id": "old"},
            "ts": 1,
        }) + "\n")
    ctx = multiprocessing.get_context("spawn")
    started = ctx.Event()
    release = ctx.Event()
    results = ctx.Queue()
    flusher = ctx.Process(
        target=_blocking_flush_worker,
        args=(buffer, started, release, results),
    )
    writer = ctx.Process(
        target=_offline_record_worker,
        args=(buffer, results),
    )
    flusher.start()
    assert started.wait(10), "flusher never reached the forced network interleaving"
    writer.start()
    writer.join(10)
    writer_completed_while_flush_inflight = not writer.is_alive()
    release.set()
    flusher.join(10)
    if writer.is_alive():
        writer.terminate()
        writer.join(5)
    if flusher.is_alive():
        flusher.terminate()
        flusher.join(5)
    assert writer_completed_while_flush_inflight
    assert writer.exitcode == 0
    assert flusher.exitcode == 0
    results_seen = [results.get(timeout=5), results.get(timeout=5)]
    assert any(result.get("buffered") is True for result in results_seen)
    assert any(result.get("sent") == 1 for result in results_seen)
    with open(buffer, encoding="utf-8") as stream:
        buffered = [json.loads(line) for line in stream if line.strip()]
    assert [
        event["payload"]["id"] for event in buffered
    ].count("must-survive") == 1
    assert not os.path.exists(buffer + ".inflight")


def test_atomic_merge_failure_preserves_active_and_inflight_bytes(
    tmp_path, monkeypatch
):
    buffer = str(tmp_path / "atomic.jsonl")
    inflight = buffer + ".inflight"
    old = json.dumps({"kind": "old", "payload": {"id": 1}, "ts": 1}) + "\n"
    new = json.dumps({"kind": "new", "payload": {"id": 2}, "ts": 2}) + "\n"
    with open(inflight, "w", encoding="utf-8", newline="\n") as stream:
        stream.write(old)
    with open(buffer, "w", encoding="utf-8", newline="\n") as stream:
        stream.write(new)

    sink = L.LedgerSink("http://unused", "token", buffer=buffer)

    def offline(kind, payload):
        raise OSError("injected offline ledger")

    sink._post = offline

    def replace_failure(source, destination):
        raise OSError("injected replace failure")

    monkeypatch.setattr(L.os, "replace", replace_failure)
    with pytest.raises(OSError, match="replace failure"):
        sink.flush()
    with open(inflight, encoding="utf-8") as stream:
        assert stream.read() == old
    with open(buffer, encoding="utf-8") as stream:
        assert stream.read() == new


@pytest.mark.parametrize(
    "bad_ack",
    [{}, {"hash": "abc"}, [], {"hash": "A" * 64}],
)
def test_flush_keeps_event_when_server_ack_has_no_valid_hash(tmp_path, bad_ack):
    buffer = str(tmp_path / "invalid-ack.jsonl")
    event = json.dumps({"kind": "event", "payload": {"id": 1}, "ts": 1}) + "\n"
    with open(buffer, "w", encoding="utf-8", newline="\n") as stream:
        stream.write(event)
    sink = L.LedgerSink("http://unused", "token", buffer=buffer)
    sink._post = lambda kind, payload: bad_ack
    assert sink.flush() == 0
    with open(buffer, encoding="utf-8") as stream:
        assert stream.read() == event
    assert not os.path.exists(buffer + ".inflight")


def test_record_replays_stale_and_active_generations_before_current(tmp_path):
    buffer = str(tmp_path / "generation-order.jsonl")
    inflight = buffer + ".inflight"
    old = {"kind": "event", "payload": {"id": "old-inflight"}, "ts": 1}
    active = {"kind": "event", "payload": {"id": "older-active"}, "ts": 2}
    with open(inflight, "w", encoding="utf-8", newline="\n") as stream:
        stream.write(json.dumps(old) + "\n")
    with open(buffer, "w", encoding="utf-8", newline="\n") as stream:
        stream.write(json.dumps(active) + "\n")
    remote_order = []
    sink = L.LedgerSink("http://unused", "token", buffer=buffer)

    def accepted(kind, payload):
        remote_order.append(payload["id"])
        return {"hash": "a" * 64}

    sink._post = accepted
    result = sink.record("event", {"id": "current"})
    assert result["hash"] == "a" * 64
    assert remote_order == ["old-inflight", "older-active", "current"]
    assert not os.path.exists(buffer)
    assert not os.path.exists(inflight)


def test_torn_buffer_line_is_quarantined_without_blocking_valid_events(tmp_path):
    buffer = str(tmp_path / "torn.jsonl")
    valid = {"kind": "event", "payload": {"id": "valid"}, "ts": 2}
    with open(buffer, "w", encoding="utf-8", newline="\n") as stream:
        stream.write('{"kind":"torn"\n')
        stream.write(json.dumps(valid) + "\n")
    delivered = []
    sink = L.LedgerSink("http://unused", "token", buffer=buffer)

    def accepted(kind, payload):
        delivered.append(payload["id"])
        return {"hash": "b" * 64}

    sink._post = accepted
    assert sink.flush() == 1
    assert delivered == ["valid"]
    assert not os.path.exists(buffer)
    assert not os.path.exists(buffer + ".inflight")
    with open(buffer + ".corrupt.jsonl", encoding="utf-8") as stream:
        quarantined = [json.loads(line) for line in stream if line.strip()]
    assert len(quarantined) == 1
    assert quarantined[0]["raw"] == '{"kind":"torn"'
    assert len(quarantined[0]["raw_sha256"]) == 64
    assert quarantined[0]["error_type"] == "JSONDecodeError"
