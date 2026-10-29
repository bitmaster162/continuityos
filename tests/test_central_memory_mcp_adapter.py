"""R6.1 status-only MCP adapter: no writes, client admission or legacy dispatch."""
import hashlib
import io
import json
import sys
from pathlib import Path

import pytest

from continuityos import central_memory_mcp_adapter as mod


def make_view(tmp_path, policy_changes=None, receipt_changes=None):
    root = tmp_path / "agent_view"
    root.mkdir(parents=True)
    sources = {name: {"sha256": name + "-digest"} for name in ("rozi", "shaytan", "sharmanka")}
    policy = {
        "schema": mod.POLICY_SCHEMA,
        "release_status": "OFFLINE_DRAFT_NOT_DEPLOYED",
        "agent_access": "DENY",
        "effect_authority": "NONE",
        "clients_connected": False,
        "source_binding": {key: dict(value) for key, value in sources.items()},
        "policies": [{"id": str(i), "guidance": "synthetic"} for i in range(10)],
    }
    policy.update(policy_changes or {})
    policy_bytes = json.dumps(policy, sort_keys=True).encode("utf-8")
    (root / "AGENT_POLICY_R61.json").write_bytes(policy_bytes)
    receipt = {
        "schema": mod.RECEIPT_SCHEMA,
        "projection_sha256": hashlib.sha256(policy_bytes).hexdigest(),
        "client_connected": False,
        "owner_sqlite_changed": False,
        "sources": sources,
    }
    receipt.update(receipt_changes or {})
    (root / "R61_LOCAL_REVIEW_RECEIPT.json").write_text(json.dumps(receipt), encoding="utf-8")
    return root


def test_only_readonly_status_tool_is_exposed():
    assert len(mod.TOOLS) == 1
    assert {t["name"] for t in mod.TOOLS} == {"agent_view_status"}
    assert mod.TOOLS[0]["inputSchema"]["additionalProperties"] is False


@pytest.mark.parametrize("name", [
    "forget", "delete", "remove", "upsert", "remember", "journal_append",
    "gate_request", "preflight_exec", "execute_preflight", "memory_recall",
    "memory_find", "memory_namespaces", "registry_read", "__getattr__",
])
def test_forbidden_tool_denied_before_filesystem_or_core(tmp_path, name, monkeypatch):
    def no_read(*args, **kwargs):
        raise AssertionError("DENIED TOOL TOUCHED DISK")
    monkeypatch.setattr(Path, "read_bytes", no_read)
    adapter = mod.CentralMemoryMCPAdapter(str(tmp_path / "nonexistent"))
    with pytest.raises(PermissionError, match="TOOL_NOT_EXPOSED"):
        adapter.call(name, {"id": 7})


def test_status_matches_verified_readonly_snapshot_without_policy_leak(tmp_path):
    root = make_view(tmp_path)
    before = {p.name: (p.stat().st_size, p.stat().st_mtime_ns)
              for p in root.iterdir()}
    result = json.loads(mod.CentralMemoryMCPAdapter(str(root)).call("agent_view_status", {}))
    assert result == {
        "schema": mod.STATUS_SCHEMA,
        "agent_access": "DENY",
        "effect_authority": "NONE",
        "release_status": "OFFLINE_DRAFT_NOT_DEPLOYED",
        "canonical_truth_promoted": False,
        "clients_connected": False,
        "policy_count": 10,
        "projection_sha256": hashlib.sha256(
            (root / "AGENT_POLICY_R61.json").read_bytes()).hexdigest(),
    }
    assert before == {p.name: (p.stat().st_size, p.stat().st_mtime_ns)
                      for p in root.iterdir()}
    assert "synthetic" not in json.dumps(result)
    assert "rozi" not in json.dumps(result)


def test_checksum_mismatch_fails_closed(tmp_path):
    root = make_view(tmp_path, receipt_changes={"projection_sha256": "wrong"})
    with pytest.raises(ValueError, match="SHA256_MISMATCH"):
        mod.CentralMemoryMCPAdapter(str(root)).call("agent_view_status", {})


@pytest.mark.parametrize("change", [
    {"agent_access": "ALLOW"}, {"effect_authority": "EXECUTE"},
    {"release_status": "PRODUCTION"}, {"clients_connected": True},
])
def test_denied_admission_cannot_be_promoted(tmp_path, change):
    root = make_view(tmp_path, policy_changes=change)
    with pytest.raises(PermissionError, match="ADMISSION_GUARD_FAILED"):
        mod.CentralMemoryMCPAdapter(str(root)).call("agent_view_status", {})


def test_source_mismatch_fails_closed(tmp_path):
    root = make_view(tmp_path, receipt_changes={"sources": {}})
    with pytest.raises(ValueError, match="PROVENANCE_INVALID"):
        mod.CentralMemoryMCPAdapter(str(root)).call("agent_view_status", {})


def test_missing_and_linked_view_fail_closed(tmp_path):
    root = tmp_path / "agent_view"
    with pytest.raises(ValueError, match="DIRECTORY_INVALID"):
        mod.CentralMemoryMCPAdapter(str(root)).call("agent_view_status", {})
    real = make_view(tmp_path / "real")
    alias = tmp_path / "alias" / "agent_view"
    alias.parent.mkdir()
    try:
        alias.symlink_to(real, target_is_directory=True)
    except OSError:
        pytest.skip("symlinks unavailable on this host")
    with pytest.raises(ValueError, match="DIRECTORY_INVALID"):
        mod.CentralMemoryMCPAdapter(str(alias)).call("agent_view_status", {})


def test_stdio_lists_only_status_and_denies_forget(tmp_path, monkeypatch):
    root = make_view(tmp_path)
    requests = [
        {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
         "params": {"name": "forget", "arguments": {"id": 42}}},
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
         "params": {"name": "agent_view_status", "arguments": {}}},
    ]
    output = io.StringIO()
    monkeypatch.setattr(sys, "argv", ["adapter", "--agent-view", str(root)])
    monkeypatch.setattr(sys, "stdin", io.StringIO("".join(json.dumps(req) + "\n" for req in requests)))
    monkeypatch.setattr(sys, "stdout", output)
    mod.main()
    results = [json.loads(line) for line in output.getvalue().splitlines()]
    assert [v["name"] for v in results[0]["result"]["tools"]] == ["agent_view_status"]
    assert results[1]["result"]["isError"] is True
    assert "TOOL_NOT_EXPOSED" in results[1]["result"]["content"][0]["text"]
    assert json.loads(results[2]["result"]["content"][0]["text"])["agent_access"] == "DENY"


def test_adapter_never_imports_legacy_core_or_writes_to_disk():
    source = Path(mod.__file__).read_text(encoding="utf-8")
    for forbidden in ("from .mcp_server", "CoreServer", "sqlite3", "write_bytes(",
                      "write_text(", "os.open(", "os.O_CREAT", "preflight_exec",
                      "journal_append", "execute_preflight", "self._core.call("):
        assert forbidden not in source, forbidden

def test_oversized_policy_fails_closed(tmp_path):
    root = make_view(tmp_path)
    (root / "AGENT_POLICY_R61.json").write_bytes(b"x" * (mod.MAX_FILE_BYTES + 1))
    with pytest.raises(ValueError, match="TOO_LARGE"):
        mod.CentralMemoryMCPAdapter(str(root)).call("agent_view_status", {})


def test_duplicate_json_keys_fail_closed(tmp_path):
    root = make_view(tmp_path)
    (root / "AGENT_POLICY_R61.json").write_text(
        '{"schema":"x","schema":"y"}', encoding="utf-8"
    )
    with pytest.raises(ValueError, match="DUPLICATE_JSON_FIELD"):
        mod.CentralMemoryMCPAdapter(str(root)).call("agent_view_status", {})


def test_policy_schema_mismatch_fails_closed(tmp_path):
    root = make_view(tmp_path, policy_changes={"schema": "wrong"})
    with pytest.raises(ValueError, match="SCHEMA_MISMATCH"):
        mod.CentralMemoryMCPAdapter(str(root)).call("agent_view_status", {})


def test_unapproved_receipt_state_fails_closed(tmp_path):
    root = make_view(tmp_path, receipt_changes={"owner_sqlite_changed": True})
    with pytest.raises(PermissionError, match="ADMISSION_GUARD_FAILED"):
        mod.CentralMemoryMCPAdapter(str(root)).call("agent_view_status", {})
