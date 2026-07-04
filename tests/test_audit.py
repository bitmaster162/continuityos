import tempfile, os
os.environ["CONTINUITYOS_SILENCE_EMBED_WARN"]="1"
from continuityos.memory import Memory
from continuityos.audit import SystemAudit

def test_clean_audit_passes_core_invariants():
    m=Memory(os.path.join(tempfile.mkdtemp(),"t.db"))
    m.remember("Canon: honest.", namespace="canon")
    oid=m.remember("v1", namespace="facts", key="k"); m.supersede(oid,"v2", namespace="facts", key="k")
    rep=SystemAudit(m).run()
    checks={x["check"]:x["ok"] for x in rep["findings"]}
    assert checks["no_dangling_pointers"] and checks["bitemporal_ordering"] and checks["canon_present"]

def test_dangling_pointer_detected():
    m=Memory(os.path.join(tempfile.mkdtemp(),"t.db"))
    m.remember("Canon: honest.", namespace="canon")
    m.remember("orphan", namespace="facts", meta={"superseded_by":9999})
    rep=SystemAudit(m).run(devil=True)
    assert not {x["check"]:x["ok"] for x in rep["findings"]}["no_dangling_pointers"]
    assert "devil" in rep and rep["devil_summary"]["challenged"]>=1
