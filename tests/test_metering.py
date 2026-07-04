"""Offline tests for the RaaS metering/quota layer (cos usage)."""
import os, tempfile, time
from continuityos.metering import Meter, PLANS

def _m():
    d = tempfile.mkdtemp()
    return Meter(os.path.join(d, "u.db"))

def test_free_quota_blocks_and_upgrade_hint():
    m = _m(); k = "c1"
    lim = PLANS["free"]["gate.decision"]
    for _ in range(lim):
        assert m.charge(k, "gate.decision")["allowed"] is True
    r = m.charge(k, "gate.decision")
    assert r["allowed"] is False and r["usage"] == lim and "upgrade" in r["action"]
    assert m.usage(k, "gate.decision") == lim   # blocked call NOT recorded
    print("PASS free_quota_blocks_and_upgrade_hint")

def test_set_plan_lifts_limit():
    m = _m(); k = "c2"
    for _ in range(PLANS["free"]["gate.decision"]):
        m.charge(k, "gate.decision")
    assert m.allow(k, "gate.decision") is False
    m.set_plan(k, "pro")
    assert m.allow(k, "gate.decision") is True
    assert m.limit(k, "gate.decision") == PLANS["pro"]["gate.decision"]
    print("PASS set_plan_lifts_limit")

def test_enterprise_unlimited():
    m = _m(); k = "c3"; m.set_plan(k, "enterprise")
    assert m.limit(k, "gate.decision") is None
    for _ in range(50):
        assert m.charge(k, "gate.decision")["allowed"] is True
    assert m.allow(k, "anything.new") is True   # unlimited covers unknown events
    print("PASS enterprise_unlimited")

def test_unknown_event_fails_closed():
    m = _m(); k = "c4"                            # free plan, undefined event => deny
    assert m.limit(k, "mystery.event") == 0
    assert m.allow(k, "mystery.event") is False
    assert m.charge(k, "mystery.event")["allowed"] is False
    print("PASS unknown_event_fails_closed")

def test_window_expires_old_usage():
    d = tempfile.mkdtemp(); m = Meter(os.path.join(d, "u.db"), window=1000.0); k = "c5"
    m.record(k, "gate.decision")                 # fresh
    # backdate one event beyond the window
    m.db.execute("INSERT INTO usage(key,event,ts) VALUES(?,?,?)",
                 (k, "gate.decision", time.time() - 5000))
    m.db.commit()
    assert m.usage(k, "gate.decision") == 1      # only the fresh one counts
    print("PASS window_expires_old_usage")

def test_report_shape():
    m = _m(); k = "c6"; m.charge(k, "twin.call")
    rep = m.report(k)
    assert rep["plan"] == "free" and rep["usage"]["twin.call"]["used"] == 1
    assert rep["usage"]["twin.call"]["limit"] == PLANS["free"]["twin.call"]
    print("PASS report_shape")

def run():
    for n in sorted(x for x in globals() if x.startswith("test_")):
        globals()[n]()
    print("ALL_METERING_TESTS_PASS")

if __name__ == "__main__":
    run()
