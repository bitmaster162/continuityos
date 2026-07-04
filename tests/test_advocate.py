import tempfile, os
os.environ["CONTINUITYOS_SILENCE_EMBED_WARN"]="1"
from continuityos.memory import Memory
from continuityos.twin import Twin
from continuityos.advocate import DevilsAdvocate

def _m():
    m=Memory(os.path.join(tempfile.mkdtemp(),"t.db"))
    m.remember("Canon: ship honest numbers.", namespace="canon")
    m.remember("The gate pass rate is 0 of 29 backtests.", namespace="facts")
    oid=m.remember("version 0.8.8", namespace="facts", key="ver")
    m.supersede(oid,"version 0.9.0", namespace="facts", key="ver")
    return m

def test_contradiction_stops_inflated_claim():
    m=_m(); da=DevilsAdvocate(m, Twin(m))
    r=da.challenge("The gate passed all 29 backtests successfully.")
    assert any(c["angle"]=="contradiction" and c["flag"] for c in r["checks"])

def test_staleness_flags_superseded():
    m=_m(); da=DevilsAdvocate(m, Twin(m))
    r=da.challenge("The project is on version 0.8.8.")
    assert any(c["angle"]=="staleness" and c["flag"] for c in r["checks"])

def test_irreversible_action_stops():
    m=_m(); da=DevilsAdvocate(m, Twin(m))
    r=da.challenge("Force-push and delete the branch.", action=True)
    assert r["verdict"].startswith("STOP")

def test_record_is_append_only():
    m=_m(); da=DevilsAdvocate(m, Twin(m))
    rid=da.record(da.challenge("x claim"))
    assert isinstance(rid,int) and any(row["namespace"]=="audit" for row in m.store.all_with_vecs(namespace="audit"))
