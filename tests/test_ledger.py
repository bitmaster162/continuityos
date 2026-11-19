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


def test_failed_direct_record_is_restored_before_concurrent_buffered_record(
    tmp_path,
):
    buffer = str(tmp_path / "direct-failure-order.jsonl")
    older = L.LedgerSink("http://unused", "token", buffer=buffer)
    newer = L.LedgerSink("http://unused", "token", buffer=buffer)
    post_started = threading.Event()
    release_post = threading.Event()
    older_result = []
    newer_direct_posts = []

    def blocked_failure(kind, payload):
        post_started.set()
        if not release_post.wait(10):
            raise TimeoutError("test release was not signaled")
        raise OSError("injected direct append failure")

    def must_not_post(kind, payload):
        newer_direct_posts.append(payload["id"])
        return {"hash": "1" * 64}

    older._post = blocked_failure
    newer._post = must_not_post
    owner = threading.Thread(
        target=lambda: older_result.append(
            older.record("event", {"id": "older"})
        )
    )
    owner.start()
    try:
        assert post_started.wait(10), "older record never reached its POST"
        assert newer.record("event", {"id": "newer"}) == {"buffered": True}
        assert newer_direct_posts == []
    finally:
        release_post.set()
        owner.join(10)

    assert not owner.is_alive()
    assert older_result == [{"buffered": True}]
    with open(buffer, encoding="utf-8") as stream:
        queued = [json.loads(line) for line in stream if line.strip()]
    assert [event["payload"]["id"] for event in queued] == ["older", "newer"]

    delivered = []

    def accepted(kind, payload):
        delivered.append(payload["id"])
        return {"hash": "2" * 64}

    older._post = accepted
    assert older.flush() == 2
    assert delivered == ["older", "newer"]


def test_record_queues_behind_backlog_when_replay_stalls(tmp_path):
    buffer = str(tmp_path / "stalled-order.jsonl")
    with open(buffer, "w", encoding="utf-8", newline="\n") as stream:
        stream.write(json.dumps({
            "kind": "event",
            "payload": {"id": "older"},
            "ts": 1,
        }) + "\n")

    sink = L.LedgerSink("http://unused", "token", buffer=buffer)
    attempts = []

    def transient_failure(kind, payload):
        attempts.append(payload["id"])
        if payload["id"] == "older":
            raise OSError("injected replay stall")
        return {"hash": "e" * 64}

    sink._post = transient_failure
    assert sink.record("event", {"id": "newer"}) == {"buffered": True}
    assert attempts == ["older"]
    with open(buffer, encoding="utf-8") as stream:
        queued = [json.loads(line) for line in stream if line.strip()]
    assert [event["payload"]["id"] for event in queued] == ["older", "newer"]

    delivered = []

    def accepted(kind, payload):
        delivered.append(payload["id"])
        return {"hash": "f" * 64}

    sink._post = accepted
    assert sink.flush() == 2
    assert delivered == ["older", "newer"]


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
    inflight_snapshots = []
    sink = L.LedgerSink("http://unused", "token", buffer=buffer)

    def accepted(kind, payload):
        remote_order.append(payload["id"])
        with open(inflight, encoding="utf-8") as stream:
            generation = [
                json.loads(line)["payload"]["id"]
                for line in stream
                if line.strip()
            ]
        inflight_snapshots.append(generation)
        receipt_char = {
            "old-inflight": "a",
            "older-active": "b",
            "current": "c",
        }[payload["id"]]
        return {"hash": receipt_char * 64}

    sink._post = accepted
    result = sink.record("event", {"id": "current"})
    assert result["hash"] == "c" * 64
    assert remote_order == ["old-inflight", "older-active", "current"]
    assert inflight_snapshots[0] == remote_order
    assert inflight_snapshots == [remote_order] * 3
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


def _single_attempt_fixture(ledger):
    action = {
        "tool": "exec",
        "command": "python --version",
        "args": ["python", "--version"],
        "paths": [],
        "cwd": os.getcwd(),
        "agent": "test",
        "meta": {},
    }
    rollback_plan = {}
    preflight_hash = ledger.append("preflight", {
        "action": action,
        "decision": "ALLOW",
        "rollback_plan": rollback_plan,
    })
    binding = "b" * 64
    claim = ledger.claim_execution_attempt(
        preflight_hash=preflight_hash,
        binding_sha256=binding,
        expected_action=action,
        expected_rollback_plan=rollback_plan,
        expected_decision="ALLOW",
    )
    assert claim["status"] == "CLAIMED_NEW"
    return preflight_hash, binding, action, rollback_plan


def _single_attempt_claim_worker(path, preflight_hash, binding, action, rollback_plan, out):
    try:
        with Ledger(path) as ledger:
            result = ledger.claim_execution_attempt(
                preflight_hash=preflight_hash,
                binding_sha256=binding,
                expected_action=action,
                expected_rollback_plan=rollback_plan,
                expected_decision="ALLOW",
            )
        out.put(("ok", result["status"]))
    except Exception as exc:
        out.put(("error", f"{type(exc).__name__}: {exc}"))


def test_attempt_start_bad_payload_preflight_rolls_back(tmp_path):
    path = str(tmp_path / "bad-start.db")
    with Ledger(path) as ledger:
        preflight_hash, binding, _, _ = _single_attempt_fixture(ledger)
        with pytest.raises(ValueError, match="preflight hash mismatch"):
            ledger.start_execution_attempt(
                preflight_hash=preflight_hash,
                binding_sha256=binding,
                payload={"preflight_hash": "f" * 64, "execution_attempted": True},
            )
        row = dict(ledger._attempt_row(preflight_hash))
        assert row["phase"] == "CLAIMED"
        assert row["execution_started_hash"] is None
        assert not any(e["kind"] == "execution_started" for e in ledger.export(100))


def _start_single_attempt(ledger, preflight_hash, binding):
    return ledger.start_execution_attempt(
        preflight_hash=preflight_hash,
        binding_sha256=binding,
        payload={
            "preflight_hash": preflight_hash,
            "execution_attempted": True,
            "executed": False,
            "mode": "exec",
        },
    )


def test_attempt_finish_bad_payload_preflight_rolls_back(tmp_path):
    path = str(tmp_path / "bad-finish.db")
    with Ledger(path) as ledger:
        preflight_hash, binding, _, _ = _single_attempt_fixture(ledger)
        started_hash = _start_single_attempt(ledger, preflight_hash, binding)
        with pytest.raises(ValueError, match="preflight hash mismatch"):
            ledger.finish_execution_attempt(
                preflight_hash=preflight_hash,
                binding_sha256=binding,
                terminal_kind="execution_completed",
                payload={
                    "preflight_hash": "f" * 64,
                    "execution_attempted": True,
                    "executed": True,
                    "execution_started_hash": started_hash,
                    "exit_code": 0,
                },
            )
        row = dict(ledger._attempt_row(preflight_hash))
        assert row["phase"] == "ATTEMPT_STARTED"
        assert row["terminal_hash"] is None
        assert not any(e["kind"] in ("execution_completed", "execution_failed") for e in ledger.export(100))


@pytest.mark.parametrize("terminal_kind,fields", [
    ("execution_completed", {"execution_attempted": False, "executed": False}),
    ("execution_failed", {"executed": False}),
    ("execution_failed", {"execution_attempted": None, "executed": False}),
    ("execution_failed", {"execution_attempted": True, "executed": False}),
    ("execution_failed", {"execution_attempted": False, "executed": True}),
])
def test_claimed_rejects_invalid_terminal_transitions(tmp_path, terminal_kind, fields):
    path = str(tmp_path / "claimed-invalid.db")
    with Ledger(path) as ledger:
        preflight_hash, binding, _, _ = _single_attempt_fixture(ledger)
        payload = {"preflight_hash": preflight_hash, "exit_code": None, **fields}
        with pytest.raises(ValueError, match="invalid CLAIMED"):
            ledger.finish_execution_attempt(
                preflight_hash=preflight_hash,
                binding_sha256=binding,
                terminal_kind=terminal_kind,
                payload=payload,
            )
        row = dict(ledger._attempt_row(preflight_hash))
        assert row["phase"] == "CLAIMED"
        assert row["terminal_hash"] is None


def test_claimed_preexecution_failure_terminalizes_and_is_cached(tmp_path):
    path = str(tmp_path / "claimed-failed.db")
    with Ledger(path) as ledger:
        preflight_hash, binding, action, rollback_plan = _single_attempt_fixture(ledger)
        terminal_hash = ledger.finish_execution_attempt(
            preflight_hash=preflight_hash,
            binding_sha256=binding,
            terminal_kind="execution_failed",
            payload={
                "preflight_hash": preflight_hash,
                "execution_attempted": False,
                "executed": False,
                "exit_code": None,
                "error_type": "RollbackMaterializationError",
                "error": "injected",
            },
        )
        row = ledger._validate_attempt_row(ledger._attempt_row(preflight_hash))
        assert row["phase"] == "TERMINAL"
        assert row["terminal_hash"] == terminal_hash
        cached = ledger.claim_execution_attempt(
            preflight_hash=preflight_hash,
            binding_sha256=binding,
            expected_action=action,
            expected_rollback_plan=rollback_plan,
            expected_decision="ALLOW",
        )
        assert cached["status"] == "TERMINAL"
        assert cached["terminal_hash"] == terminal_hash


@pytest.mark.parametrize("attempted,started_value", [
    (False, "exact"),
    (None, "exact"),
    (True, "wrong"),
])
def test_started_rejects_invalid_terminal_binding(tmp_path, attempted, started_value):
    path = str(tmp_path / "started-invalid.db")
    with Ledger(path) as ledger:
        preflight_hash, binding, _, _ = _single_attempt_fixture(ledger)
        started_hash = _start_single_attempt(ledger, preflight_hash, binding)
        terminal_started = started_hash if started_value == "exact" else "f" * 64
        with pytest.raises(ValueError):
            ledger.finish_execution_attempt(
                preflight_hash=preflight_hash,
                binding_sha256=binding,
                terminal_kind="execution_failed",
                payload={
                    "preflight_hash": preflight_hash,
                    "execution_attempted": attempted,
                    "executed": True,
                    "execution_started_hash": terminal_started,
                    "exit_code": 7,
                },
            )
        row = dict(ledger._attempt_row(preflight_hash))
        assert row["phase"] == "ATTEMPT_STARTED"
        assert row["terminal_hash"] is None


def test_terminal_started_pointer_corruption_fails_closed(tmp_path):
    path = str(tmp_path / "terminal-corrupt.db")
    with Ledger(path) as ledger:
        preflight_hash, binding, _, _ = _single_attempt_fixture(ledger)
        started_hash = _start_single_attempt(ledger, preflight_hash, binding)
        terminal_hash = ledger.finish_execution_attempt(
            preflight_hash=preflight_hash,
            binding_sha256=binding,
            terminal_kind="execution_completed",
            payload={
                "preflight_hash": preflight_hash,
                "execution_attempted": True,
                "executed": True,
                "execution_started_hash": started_hash,
                "exit_code": 0,
            },
        )
        terminal = ledger.event(terminal_hash)
        corrupt = dict(terminal["payload"])
        corrupt["execution_started_hash"] = "f" * 64
        body = json.dumps(corrupt, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
        ledger.con.execute("UPDATE events SET payload=? WHERE hash=?", (body, terminal_hash))
        ledger.con.commit()
        with pytest.raises(ValueError, match="execution_started_hash mismatch"):
            ledger._validate_attempt_row(ledger._attempt_row(preflight_hash))


def test_cross_process_attempt_claim_has_single_winner(tmp_path):
    path = str(tmp_path / "claim-race.db")
    action = {"tool": "exec", "command": "python --version", "args": ["python", "--version"],
              "paths": [], "cwd": os.getcwd(), "agent": "test", "meta": {}}
    rollback_plan = {}
    with Ledger(path) as ledger:
        preflight_hash = ledger.append("preflight", {
            "action": action, "decision": "ALLOW", "rollback_plan": rollback_plan,
        })
    binding = "c" * 64
    ctx = multiprocessing.get_context("spawn")
    out = ctx.Queue()
    workers = [ctx.Process(target=_single_attempt_claim_worker,
                           args=(path, preflight_hash, binding, action, rollback_plan, out))
               for _ in range(8)]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(30)
        if worker.is_alive():
            worker.terminate()
            worker.join(5)
        assert worker.exitcode == 0
    results = [out.get(timeout=10) for _ in workers]
    assert not [item for item in results if item[0] == "error"]
    statuses = [item[1] for item in results]
    assert statuses.count("CLAIMED_NEW") == 1
    assert statuses.count("CLAIMED") == 7
    with Ledger(path) as ledger:
        assert ledger.con.execute(
            "SELECT COUNT(*) FROM execution_attempts WHERE preflight_hash=?", (preflight_hash,)
        ).fetchone()[0] == 1
        assert ledger.con.execute(
            "SELECT COUNT(*) FROM events WHERE kind='attempt_claimed'"
        ).fetchone()[0] == 1


def test_historical_db_migrates_without_rewriting_event_chain(tmp_path):
    import sqlite3
    path = str(tmp_path / "historical.db")
    payload = json.dumps({"legacy": True}, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    ts = 123.456789
    digest = hashlib.sha256((("0" * 64) + "legacy" + ("%.6f" % ts) + payload).encode("utf-8")).hexdigest()
    con = sqlite3.connect(path)
    con.execute("CREATE TABLE events(id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, kind TEXT, payload TEXT, prev_hash TEXT, hash TEXT)")
    con.execute("INSERT INTO events(ts,kind,payload,prev_hash,hash) VALUES(?,?,?,?,?)",
                (ts, "legacy", payload, "0" * 64, digest))
    con.commit()
    before = con.execute("SELECT ts,kind,payload,prev_hash,hash FROM events").fetchone()
    con.close()
    with Ledger(path) as ledger:
        assert ledger.verify() == {"ok": True, "verified": 1}
        after = ledger.con.execute("SELECT ts,kind,payload,prev_hash,hash FROM events").fetchone()
        assert tuple(after) == tuple(before)
        assert ledger.con.execute("SELECT COUNT(*) FROM execution_attempts").fetchone()[0] == 0

def test_corrupt_claim_payload_phase_fails_closed(tmp_path):
    path = str(tmp_path / "corrupt-phase.db")
    with Ledger(path) as ledger:
        action = {"tool":"exec","command":"x","args":[],"paths":[],"cwd":".","agent":"t","meta":{}}
        rollback_plan = {}
        preflight_hash = ledger.append("preflight", {"action":action,"decision":"ALLOW","rollback_plan":rollback_plan})
        binding = "a"*64
        claim = ledger.claim_execution_attempt(
            preflight_hash=preflight_hash, binding_sha256=binding,
            expected_action=action, expected_rollback_plan=rollback_plan, expected_decision="ALLOW")
        claim_hash = claim["claim_hash"]
        # corrupt phase in claim event payload
        event = ledger.event(claim_hash)
        corrupt = dict(event["payload"])
        corrupt["phase"] = "WRONG"
        body = json.dumps(corrupt, sort_keys=True, ensure_ascii=False, separators=(",",":"))
        ledger.con.execute("UPDATE events SET payload=? WHERE hash=?", (body, claim_hash))
        ledger.con.commit()
        with pytest.raises(ValueError, match="phase is not CLAIMED"):
            ledger._validate_attempt_row(ledger._attempt_row(preflight_hash))


def test_claimed_preexecution_failure_nonnull_started_hash_raises(tmp_path):
    path = str(tmp_path / "claimed-start-hash.db")
    with Ledger(path) as ledger:
        action = {"tool":"exec","command":"x","args":[],"paths":[],"cwd":".","agent":"t","meta":{}}
        rollback_plan = {}
        preflight_hash = ledger.append("preflight", {"action":action,"decision":"ALLOW","rollback_plan":rollback_plan})
        binding = "b"*64
        ledger.claim_execution_attempt(
            preflight_hash=preflight_hash, binding_sha256=binding,
            expected_action=action, expected_rollback_plan=rollback_plan, expected_decision="ALLOW")
        with pytest.raises(ValueError, match="execution_started_hash"):
            ledger.finish_execution_attempt(
                preflight_hash=preflight_hash, binding_sha256=binding,
                terminal_kind="execution_failed",
                payload={
                    "preflight_hash": preflight_hash,
                    "execution_attempted": False,
                    "executed": False,
                    "execution_started_hash": "f"*64,
                    "exit_code": None,
                })
        row = dict(ledger._attempt_row(preflight_hash))
        assert row["phase"] == "CLAIMED"
        assert row["terminal_hash"] is None
        assert not any(e["kind"] in ("execution_completed","execution_failed") for e in ledger.export(100))


def test_orphaned_claim_after_attempt_row_deletion_fails_closed(tmp_path):
    path = str(tmp_path / "r11-orphaned-claim.db")
    with Ledger(path) as ledger:
        preflight_hash, binding, action, rollback_plan = _single_attempt_fixture(ledger)
        started_hash = _start_single_attempt(ledger, preflight_hash, binding)
        ledger.finish_execution_attempt(
            preflight_hash=preflight_hash,
            binding_sha256=binding,
            terminal_kind="execution_completed",
            payload={
                "preflight_hash": preflight_hash,
                "execution_attempted": True,
                "executed": True,
                "execution_started_hash": started_hash,
                "exit_code": 0,
            },
        )
        assert ledger.con.execute(
            "SELECT COUNT(*) FROM events WHERE kind='attempt_claimed'"
        ).fetchone()[0] == 1
        ledger.con.execute(
            "DELETE FROM execution_attempts WHERE preflight_hash=?", (preflight_hash,)
        )
        ledger.con.commit()
        with pytest.raises(ValueError, match="orphaned prior claim found with missing registry state"):
            ledger.claim_execution_attempt(
                preflight_hash=preflight_hash,
                binding_sha256=binding,
                expected_action=action,
                expected_rollback_plan=rollback_plan,
                expected_decision="ALLOW",
            )
        assert ledger.con.execute(
            "SELECT COUNT(*) FROM events WHERE kind='attempt_claimed'"
        ).fetchone()[0] == 1
        assert ledger._attempt_row(preflight_hash) is None


def test_fresh_preflight_without_claim_history_still_claims(tmp_path):
    path = str(tmp_path / "r11-fresh-claim.db")
    with Ledger(path) as ledger:
        action = {
            "tool": "exec", "command": "echo fresh", "args": ["echo", "fresh"],
            "paths": [], "cwd": os.getcwd(), "agent": "test", "meta": {},
        }
        rollback_plan = {}
        preflight_hash = ledger.append("preflight", {
            "action": action, "decision": "ALLOW", "rollback_plan": rollback_plan,
        })
        binding = "b" * 64
        claim = ledger.claim_execution_attempt(
            preflight_hash=preflight_hash,
            binding_sha256=binding,
            expected_action=action,
            expected_rollback_plan=rollback_plan,
            expected_decision="ALLOW",
        )
        assert claim["status"] == "CLAIMED_NEW"
        assert claim["preflight_hash"] == preflight_hash
        row = ledger._attempt_row(preflight_hash)
        assert row is not None
        assert row["phase"] == "CLAIMED"
        assert row["binding_sha256"] == binding
        assert ledger.con.execute(
            "SELECT COUNT(*) FROM execution_attempts WHERE preflight_hash=?",
            (preflight_hash,)
        ).fetchone()[0] == 1
        events = ledger.export(100)
        claim_events = [e for e in events if e["kind"] == "attempt_claimed"]
        assert len(claim_events) == 1
        assert claim_events[0]["payload"]["phase"] == "CLAIMED"

def test_malformed_attempt_claimed_event_fails_closed_and_does_not_create_new_claim(tmp_path):
    path = str(tmp_path / "r11-malformed.db")
    with Ledger(path) as ledger:
        # Create a fresh preflight
        action = {"tool":"exec","command":"echo malformed","args":["echo","malformed"],"paths":[],"cwd":".","agent":"test","meta":{}}
        rollback_plan = {}
        preflight_hash = ledger.append("preflight", {"action":action,"decision":"ALLOW","rollback_plan":rollback_plan})
        # Inject malformed attempt_claimed event with structurally invalid payload
        # that passes hash chain but fails structural validation in claim_execution_attempt
        prev_row = ledger.con.execute("SELECT hash FROM events ORDER BY id DESC LIMIT 1").fetchone()
        prev_hash = prev_row["hash"] if prev_row else "0"*64
        # Payload with bad binding_sha256 length (not 64 hex chars)
        bad_body = {"phase":"CLAIMED", "preflight_hash":"a"*64, "binding_sha256":"b"*20}
        bad_payload_str = json.dumps(bad_body, sort_keys=True, ensure_ascii=False, separators=(",",":"))
        bad_ts = time.time()
        bad_digest = hashlib.sha256((prev_hash + "attempt_claimed" + ("%.6f" % bad_ts) + bad_payload_str).encode("utf-8")).hexdigest()
        ledger.con.execute("INSERT INTO events(ts,kind,payload,prev_hash,hash) VALUES(?,?,?,?,?)",
                           (bad_ts, "attempt_claimed", bad_payload_str, prev_hash, bad_digest))
        ledger.con.commit()
        # Now the hash chain is intact but event payload is malformed.
        # claim_execution_attempt for a fresh preflight must fail closed on the malformed event.
        fresh_preflight_hash = ledger.append("preflight", {"action":{"tool":"exec","command":"echo fresh","args":["echo","fresh"],"paths":[],"cwd":".","agent":"test","meta":{}},"decision":"ALLOW","rollback_plan":{}})
        with pytest.raises(ValueError, match="malformed attempt_claimed payload"):
            ledger.claim_execution_attempt(
                preflight_hash=fresh_preflight_hash,
                binding_sha256="b"*64,
                expected_action={"tool":"exec","command":"echo fresh","args":["echo","fresh"],"paths":[],"cwd":".","agent":"test","meta":{}},
                expected_rollback_plan={},
                expected_decision="ALLOW",
            )
        # Must not append a new execution_attempts row for the fresh preflight
        fresh_attempt_count = ledger.con.execute("SELECT COUNT(*) FROM execution_attempts WHERE preflight_hash=?", (fresh_preflight_hash,)).fetchone()[0]
        assert fresh_attempt_count == 0
        # Must not create a new attempt_claimed event for the requested fresh preflight
        claim_events = ledger.export(100)
        fresh_claim_events = [e for e in claim_events if e["kind"] == "attempt_claimed" and e["payload"].get("preflight_hash") == fresh_preflight_hash]
        assert len(fresh_claim_events) == 0
