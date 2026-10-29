import json
import pytest
from continuityos.central_memory_mcp_adapter import CentralMemoryMCPAdapter, REGISTRY_SCHEMA, TOOLS

class FakeCore:
    def __init__(self): self.calls = []; self.deleted = []
    def call(self, name, args):
        self.calls.append((name, args))
        if name == "forget": self.deleted.append(args["id"]); return "deleted"
        if name == "preflight_exec": return json.dumps({"decision":"HELD","state":"HELD"})
        return "[]"

def make_registry(path):
    path.write_text(json.dumps({"schema":REGISTRY_SCHEMA,"records":[{
        "line":"CENTRAL_MEMORY","executor_chat":"План CENTRAL MEMORY R2","bucket":"active",
        "current_state":"HOLD","next_turn":"adapter integration","evidence":"source receipt pending",
        "updated_at":"2026-10-29T00:00:00Z"}]}), encoding="utf-8")

def test_tool_list_excludes_forget_delete_and_execute():
    names = {t["name"] for t in TOOLS}
    assert names == {"registry_read","memory_recall","memory_find","memory_namespaces","journal_append","gate_request"}
    assert "forget" not in names and "execute_preflight" not in names
    assert not any("delete" in n.lower() or "remove" in n.lower() for n in names)

def test_direct_delete_without_robert_signature_rejected_before_core_dispatch(tmp_path):
    core = FakeCore()
    adapter = CentralMemoryMCPAdapter(core, str(tmp_path/"registry.json"), str(tmp_path/"journal.jsonl"))
    with pytest.raises(PermissionError, match="TOOL_NOT_EXPOSED"):
        adapter.call("forget", {"id": 7})
    assert core.calls == [] and core.deleted == []

def test_registry_read_is_bounded_projection_without_promotion(tmp_path):
    p = tmp_path/"registry.json"; make_registry(p)
    result = json.loads(CentralMemoryMCPAdapter(FakeCore(), str(p), str(tmp_path/"journal.jsonl")).call("registry_read", {}))
    assert result["canonical_truth_promoted"] is False
    assert result["records"][0]["line"] == "CENTRAL_MEMORY"
    assert set(result["records"][0]) == {"line","executor_chat","bucket","current_state","next_turn","evidence","updated_at"}

def test_registry_schema_mismatch_fails_closed(tmp_path):
    p = tmp_path/"registry.json"; p.write_text('{"schema":"wrong","records":[]}', encoding="utf-8")
    adapter = CentralMemoryMCPAdapter(FakeCore(), str(p), str(tmp_path/"journal.jsonl"))
    with pytest.raises(ValueError, match="SCHEMA_MISMATCH"): adapter.call("registry_read", {})

def test_journal_appends_without_core_writes(tmp_path):
    core = FakeCore(); journal = tmp_path/"journal.jsonl"
    adapter = CentralMemoryMCPAdapter(core, str(tmp_path/"registry.json"), str(journal))
    assert json.loads(adapter.call("journal_append", {"event":"readback"}))["appended"]
    assert json.loads(adapter.call("journal_append", {"event":"gate_held"}))["appended"]
    assert len(journal.read_text(encoding="utf-8").splitlines()) == 2
    assert core.calls == []

def test_gate_request_only_calls_preflight_not_execution():
    core = FakeCore(); adapter = CentralMemoryMCPAdapter(core, "/unused/registry.json", "/unused/journal.jsonl")
    result = json.loads(adapter.call("gate_request", {"request_id":"adapter-test-1","argv":["echo","no-execution"],"cwd":"."}))
    assert result["decision"] == "HELD"
    assert [name for name, _ in core.calls] == ["preflight_exec"]
