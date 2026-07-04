"""MCP server exposes the v0.9 key primitives (find/upsert)."""
import os, tempfile, json
os.environ["CONTINUITYOS_SILENCE_EMBED_WARN"] = "1"
from continuityos.mcp_server import Server, TOOLS

def test_tools_list_has_find_upsert():
    names = {t["name"] for t in TOOLS}
    assert {"find", "upsert"} <= names, names
    print("PASS tools_list_has_find_upsert")

def test_upsert_then_find_via_mcp():
    srv = Server(os.path.join(tempfile.mkdtemp(), "m.db"))
    srv.call("upsert", {"text": "gpt-5.5", "namespace": "config", "key": "model"})
    srv.call("upsert", {"text": "claude-opus-4-8", "namespace": "config", "key": "model"})
    out = srv.call("find", {"namespace": "config", "key": "model"})
    assert json.loads(out)["text"] == "claude-opus-4-8"        # latest wins
    assert srv.call("find", {"namespace": "config", "key": "nope"}) == "null"
    print("PASS upsert_then_find_via_mcp")

def run():
    for n in sorted(x for x in globals() if x.startswith("test_")):
        globals()[n]()
    print("ALL_MCP_UPSERT_TESTS_PASS")

if __name__ == "__main__":
    run()
