import os, tempfile, json
os.environ["CONTINUITYOS_SILENCE_EMBED_WARN"]="1"
from continuityos.mcp_server import Server, TOOLS

def test_tools_present():
    names={t["name"] for t in TOOLS}
    assert {"srd_status","memory_pointer","memory_write_checked"} <= names, names
    print("PASS tools_present")

def test_srd_counter_and_reinject():
    srv=Server(os.path.join(tempfile.mkdtemp(),"m.db"))
    srv.call("checkpoint",{"summary":"s","next_action":"n"})  # seed canon? no; add canon
    srv.c.add_canon("LLM never controls capital.")
    # not due early
    r=json.loads(srv.call("srd_status",{}))
    assert r["reinject_due"] is False and r["turns"]>0
    # drive to STD
    for _ in range(12): srv.call("list_namespaces",{})
    r=json.loads(srv.call("srd_status",{}))
    assert r["reinject_due"] is True and "never controls capital" in " ".join(r["canon_reminder"])
    # counter resets after due
    r2=json.loads(srv.call("srd_status",{}))
    assert r2["reinject_due"] is False
    print("PASS srd_counter_and_reinject")

def test_pointer_and_occ_over_mcp():
    srv=Server(os.path.join(tempfile.mkdtemp(),"m.db"))
    srv.call("upsert",{"text":"gpt-5.5","namespace":"cfg","key":"model"})
    ptr=json.loads(srv.call("memory_pointer",{"namespace":"cfg","key":"model"}))
    assert ptr["version"]==1
    # correct OCC write
    out=srv.call("memory_write_checked",{"text":"opus","namespace":"cfg","key":"model","expected_version":1})
    assert "wrote" in out
    # stale OCC write -> conflict
    conf=json.loads(srv.call("memory_write_checked",{"text":"x","namespace":"cfg","key":"model","expected_version":1}))
    assert conf.get("error")=="conflict"
    print("PASS pointer_and_occ_over_mcp")

def run():
    for n in sorted(x for x in globals() if x.startswith("test_")): globals()[n]()
    print("ALL_SRD_A2A_TESTS_PASS")
if __name__=="__main__": run()
