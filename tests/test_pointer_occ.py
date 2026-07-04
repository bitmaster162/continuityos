import os, tempfile
os.environ["CONTINUITYOS_SILENCE_EMBED_WARN"]="1"
from continuityos.memory import Memory, Conflict

def _m(): return Memory(os.path.join(tempfile.mkdtemp(),"m.db"))

def test_version_increments():
    m=_m()
    m.upsert("v1","cfg",key="model"); m.upsert("v2","cfg",key="model")
    assert m.store.current_version("cfg","model")==2
    assert m.pointer("cfg","model")=={"namespace":"cfg","key":"model","version":2}
    print("PASS version_increments")

def test_pointer_resolve_roundtrip():
    m=_m(); m.upsert("gpt-5.5","cfg",key="model")
    ptr=m.pointer("cfg","model")
    assert m.resolve(ptr).text=="gpt-5.5"
    assert m.pointer("cfg","missing") is None
    print("PASS pointer_resolve_roundtrip")

def test_occ_conflict():
    m=_m(); m.upsert("v1","cfg",key="model")   # version 1
    # correct expected version -> ok
    m.write_checked("v2","cfg",key="model",expected_version=1)
    assert m.find("cfg","model").text=="v2" and m.store.current_version("cfg","model")==2
    # stale expected version -> Conflict
    try:
        m.write_checked("v3","cfg",key="model",expected_version=1)
        assert False, "should have raised"
    except Conflict:
        pass
    assert m.find("cfg","model").text=="v2"   # not overwritten
    print("PASS occ_conflict")

def test_fresh_key_version0():
    m=_m()
    assert m.store.current_version("cfg","new")==0
    m.write_checked("first","cfg",key="new",expected_version=0)
    assert m.find("cfg","new").text=="first"
    print("PASS fresh_key_version0")

def run():
    for n in sorted(x for x in globals() if x.startswith("test_")): globals()[n]()
    print("ALL_POINTER_OCC_TESTS_PASS")
if __name__=="__main__": run()
