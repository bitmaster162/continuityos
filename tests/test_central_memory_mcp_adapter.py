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


# COS-ORCH-05: synthetic security regression tests, C-drive pytest fixtures only.

def test_mcp_exception_text_and_private_path_redacted_after_json(monkeypatch, tmp_path):
    root = make_view(tmp_path)
    marker = "SYNTHETIC_PRIVATE_CREDENTIAL_MARKER"
    def raise_private(*args, **kwargs):
        raise PermissionError("C:\\\\SYNTHETIC_PRIVATE\\\\" + marker)
    monkeypatch.setattr(mod, "read_bounded_file", raise_private)
    req = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
           "params": {"name": "agent_view_status", "arguments": {}}}
    output = io.StringIO()
    monkeypatch.setattr(sys, "argv", ["adapter", "--agent-view", str(root)])
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(req) + "\n"))
    monkeypatch.setattr(sys, "stdout", output)
    mod.main()
    decoded = json.loads(output.getvalue().splitlines()[0])
    message = decoded["result"]["content"][0]["text"]
    assert decoded["result"]["isError"] is True
    assert marker not in message
    assert "SYNTHETIC_PRIVATE" not in message
    assert message == "STATUS_READ_FAILED"


def test_parent_junction_escape_denied_windows(tmp_path):
    import os
    import subprocess
    if sys.platform != "win32":
        pytest.skip("Windows junction test")
    external = make_view(tmp_path / "external")
    junction = tmp_path / "linked_parent"
    result = subprocess.run(
        ["cmd", "/d", "/c", "mklink", "/J", str(junction), str(external.parent)],
        capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    try:
        with pytest.raises(ValueError, match="DIRECTORY_INVALID"):
            mod.CentralMemoryMCPAdapter(str(junction / "agent_view")).call("agent_view_status", {})
    finally:
        os.rmdir(junction)


def test_file_symlink_or_reparse_attribute_denied(tmp_path, monkeypatch):
    import os
    from continuityos import _offline_path_guard as guard
    real_root = make_view(tmp_path / "real")
    root = tmp_path / "normal" / "agent_view"
    root.mkdir(parents=True)
    (root / "R61_LOCAL_REVIEW_RECEIPT.json").write_bytes(
        (real_root / "R61_LOCAL_REVIEW_RECEIPT.json").read_bytes())
    victim = root / "AGENT_POLICY_R61.json"
    try:
        victim.symlink_to(real_root / "AGENT_POLICY_R61.json")
    except OSError:
        # Privilege-free synthetic reparse attribute from an actual opened handle.
        from types import SimpleNamespace
        victim.write_bytes((real_root / "AGENT_POLICY_R61.json").read_bytes())
        actual_info = guard._kernel32.GetFileInformationByHandle
        def synthetic_reparse(handle, pointer):
            ok = actual_info(handle, pointer)
            if ok and guard._win_handle_path(handle).casefold() == str(victim).casefold():
                pointer._obj.attributes |= 0x400
            return ok
        monkeypatch.setattr(guard._kernel32, "GetFileInformationByHandle",
                            synthetic_reparse)
    with pytest.raises(ValueError, match="FILE_MISSING_OR_LINKED"):
        mod.CentralMemoryMCPAdapter(str(root)).call("agent_view_status", {})


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only native handle regression")
def test_anchored_parent_swap_does_not_follow_replaced_absolute_path(tmp_path, monkeypatch):
    import os
    import subprocess
    from continuityos import _offline_path_guard as guard
    root = make_view(tmp_path)
    external = make_view(tmp_path / "external", policy_changes={"synthetic": "outside"})
    moved = tmp_path / "moved_agent_view"
    original = guard._win_open_relative
    swapped = []
    def replace_parent_with_junction(parent, name, *, directory):
        if name == "AGENT_POLICY_R61.json" and not swapped:
            try:
                os.rename(root, moved)
            except OSError as exc:
                assert getattr(exc, "winerror", None) == 32
                swapped.append("rename_blocked")
            else:
                command = subprocess.run(
                    ["cmd", "/d", "/c", "mklink", "/J", str(root), str(external)],
                    capture_output=True, text=True, timeout=5)
                assert command.returncode == 0, command.stderr
                swapped.append("junction_created")
        return original(parent, name, directory=directory)
    monkeypatch.setattr(guard, "_win_open_relative", replace_parent_with_junction)
    try:
        # Both are fail-closed: the OS blocks rename, or the handle-bound
        # reader rejects a successfully substituted external path.
        try:
            result = mod.CentralMemoryMCPAdapter(str(root)).call("agent_view_status", {})
        except ValueError as exc:
            assert swapped == ["junction_created"]
            assert "FILE_MISSING_OR_LINKED" in str(exc)
        else:
            assert swapped == ["rename_blocked"]
            assert json.loads(result)["agent_access"] == "DENY"
        assert len(swapped) == 1
    finally:
        if moved.exists() and root.exists():
            assert root.lstat().st_file_attributes & 0x400, "non-junction at attack path"
            os.rmdir(root)
        if moved.exists():
            os.rename(moved, root)


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only native handle regression")
def test_windows_open_handle_final_path_mismatch_denied(tmp_path, monkeypatch):
    """Second guardrail: a handle whose final path differs must fail closed."""
    from continuityos import _offline_path_guard as guard

    root = make_view(tmp_path)
    original_path = guard._win_handle_path
    mismatches = []

    def substitute_final_path(handle):
        actual = original_path(handle)
        if actual.casefold().endswith("\\AGENT_POLICY_R61.json".casefold()):
            mismatches.append(actual)
            return str(tmp_path / "synthetic_other_parent" / "AGENT_POLICY_R61.json")
        return actual

    monkeypatch.setattr(guard, "_win_handle_path", substitute_final_path)
    with pytest.raises(ValueError, match="AGENT_VIEW_FILE_MISSING_OR_LINKED"):
        mod.CentralMemoryMCPAdapter(str(root)).call("agent_view_status", {})
    assert mismatches, "test never exercised the open-handle final-path check"


@pytest.mark.skipif(sys.platform != "win32", reason="Windows junction race")
def test_concurrent_parent_junction_swap_never_reads_external(tmp_path):
    import os
    import subprocess
    import threading
    import time

    parent = tmp_path / "switch_parent"
    safe = make_view(parent)
    outside = make_view(tmp_path / "outside", policy_changes={"custom": "external-data"})
    original_digest = json.loads(
        mod.CentralMemoryMCPAdapter(str(safe)).call("agent_view_status", {})
    )["projection_sha256"]
    external_digest = json.loads(
        mod.CentralMemoryMCPAdapter(str(outside)).call("agent_view_status", {})
    )["projection_sha256"]
    assert original_digest != external_digest

    # Pre-create the real synthetic junction before concurrency begins.
    # Repeated cmd/mklink inside a race was non-atomic on Windows CI.
    staged_link = tmp_path / "staged_attack_junction"
    result = subprocess.run(
        ["cmd", "/d", "/c", "mklink", "/J", str(staged_link), str(outside.parent)],
        capture_output=True, text=True, timeout=5)
    assert result.returncode == 0, "synthetic junction could not be prepared"
    assert staged_link.lstat().st_file_attributes & 0x400

    parked = tmp_path / "parked_parent"
    stop = threading.Event()
    attempts = []
    errors = []

    # Prove at least one REAL junction substitution deterministically before
    # stressing concurrent readers. Under the hardened Windows directory
    # handles, in-race renames can all be correctly blocked (WinError 32),
    # which must not make the fixture claim an untested junction existed.
    try:
        os.rename(parent, parked)
        os.rename(staged_link, parent)
        assert parent.lstat().st_file_attributes & 0x400, "no actual junction installed"
        attempts.append("junction")
        with pytest.raises(ValueError, match="AGENT_VIEW_DIRECTORY_INVALID"):
            mod.CentralMemoryMCPAdapter(
                str(parent / "agent_view")).call("agent_view_status", {})
    finally:
        if parked.exists():
            if os.path.lexists(parent):
                assert parent.lstat().st_file_attributes & 0x400
                os.rename(parent, staged_link)
            os.rename(parked, parent)

    def restore_fixture():
        for _retry in range(500):
            try:
                if parked.exists():
                    if os.path.lexists(parent):
                        # Only move the test's junction; never touch a real dir.
                        assert parent.lstat().st_file_attributes & 0x400
                        assert not os.path.lexists(staged_link)
                        os.rename(parent, staged_link)
                    os.rename(parked, parent)
                return True
            except OSError:
                time.sleep(0.01)
        return False

    def changer():
        for _ in range(20):
            if stop.is_set():
                break
            try:
                os.rename(parent, parked)
            except OSError as exc:
                if getattr(exc, "winerror", None) not in (5, 32):
                    errors.append("unexpected-rename-denial")
                    break
                attempts.append("rename-blocked")
                time.sleep(0.001)
                continue
            attempts.append("rename-succeeded")
            try:
                try:
                    os.rename(staged_link, parent)
                except OSError as exc:
                    if getattr(exc, "winerror", None) not in (5, 32):
                        errors.append("unexpected-junction-move-denial")
                    attempts.append("junction-move-blocked")
                else:
                    attempts.append("junction")
                    time.sleep(0.008)
            except Exception:
                errors.append("junction-transition-error")
            finally:
                if not restore_fixture():
                    errors.append("restore-pending")
                    break

    thread = threading.Thread(target=changer, daemon=True)
    thread.start()
    seen = []
    try:
        for _ in range(180):
            try:
                response = json.loads(
                    mod.CentralMemoryMCPAdapter(
                        str(parent / "agent_view")).call("agent_view_status", {}))
                seen.append(response["projection_sha256"])
            except ValueError:
                pass  # fail closed during a rename/junction window
            time.sleep(0.0004)
    finally:
        stop.set()
        thread.join(timeout=30)
        if parked.exists() and restore_fixture():
            errors[:] = [error for error in errors if error != "restore-pending"]
        if staged_link.exists():
            assert staged_link.lstat().st_file_attributes & 0x400
            os.rmdir(staged_link)

    assert not thread.is_alive(), "attacker fixture did not terminate"
    assert not errors, "adversary fixture incomplete: " + ",".join(errors)
    assert attempts, "attacker did not attempt a rename"
    assert "junction" in attempts, "no adversarial junction was actually installed"
    assert ("rename-blocked" in attempts or "rename-succeeded" in attempts)
    assert all(d == original_digest for d in seen), "external junction data was accepted"
    assert external_digest not in seen
    restored = json.loads(
        mod.CentralMemoryMCPAdapter(str(parent / "agent_view")).call("agent_view_status", {}))
    assert restored["projection_sha256"] == original_digest



def test_source_guard_still_rejects_effect_tool_without_disk(tmp_path, monkeypatch):
    from continuityos import _offline_path_guard as guard
    def no_open(*args, **kwargs):
        raise AssertionError("FORBIDDEN_TOOL_TOUCHED_FILE")
    monkeypatch.setattr(guard.os, "open", no_open)
    with pytest.raises(PermissionError, match="TOOL_NOT_EXPOSED"):
        mod.CentralMemoryMCPAdapter(str(tmp_path / "agent_view")).call("forget", {"id": 1})

@pytest.mark.parametrize("unsafe_path", [
    r"\\server\share\agent_view",      # genuine UNC, two leading backslashes
    r"\\?\C:\outside\agent_view",      # genuine Win32 device namespace
    r"\\.\C:\outside\agent_view",      # alternate Win32 device namespace
    r"\??\C:\outside\agent_view",      # NT namespace spelling
    r"C:\temp\..\outside\agent_view",
    r"C:\temp\special:stream\agent_view",
])
def test_windows_adversarial_path_forms_denied(unsafe_path):
    import os
    if os.name != "nt":
        pytest.skip("Windows path semantics")
    from continuityos._offline_path_guard import require_plain_dir
    if unsafe_path.startswith("\\\\"):
        assert not unsafe_path.startswith("\\\\\\"), "not a genuine two-slash UNC/NT prefix"
    with pytest.raises(ValueError, match="OFFLINE_PATH_UNSAFE"):
        require_plain_dir(Path(unsafe_path))


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only native handle regression")
def test_windows_fdopen_failure_closes_transferred_crt_descriptor(tmp_path, monkeypatch):
    import os
    import msvcrt
    from continuityos import _offline_path_guard as guard
    root = make_view(tmp_path)
    captured = []
    def synthetic_fdopen_failure(fd, *args, **kwargs):
        captured.append(fd)
        # Ensure the CRT descriptor owns an actual Windows HANDLE first.
        assert msvcrt.get_osfhandle(fd) != -1
        raise OSError("SYNTHETIC_FDOPEN_FAILURE")
    monkeypatch.setattr(guard.os, "fdopen", synthetic_fdopen_failure)
    with pytest.raises(ValueError, match="FILE_MISSING_OR_LINKED"):
        mod.CentralMemoryMCPAdapter(str(root)).call("agent_view_status", {})
    assert len(captured) == 1
    with pytest.raises(OSError):
        msvcrt.get_osfhandle(captured[0])

def test_stdio_drops_oversized_line_in_bounded_chunks_and_resumes(monkeypatch, tmp_path):
    import io
    import sys

    class BoundedStdin(io.StringIO):
        def readline(self, size=-1):
            assert 0 < size <= mod.MAX_FILE_BYTES + 1, "unbounded stdin read"
            return super().readline(size)

    huge = '{"jsonrpc":"2.0","id":91,"method":"initialize","pad":"' + (
        "x" * (2 * mod.MAX_FILE_BYTES)) + '"}\n'
    valid = json.dumps({"jsonrpc": "2.0", "id": 92, "method": "initialize"}) + "\n"
    output = io.StringIO()
    monkeypatch.setattr(sys, "stdin", BoundedStdin(huge + valid))
    monkeypatch.setattr(sys, "stdout", output)
    monkeypatch.setattr(sys, "argv", [
        "central_memory_mcp_adapter", "--agent-view", str(tmp_path / "agent_view")])
    mod.main()
    responses = [json.loads(line) for line in output.getvalue().splitlines()]
    assert [item["id"] for item in responses] == [92]
    assert responses[0]["result"]["serverInfo"]["name"] == "continuityos-r61-status-only"


@pytest.mark.skipif(sys.platform != "win32", reason="Windows native handle semantics")
def test_windows_directory_handle_denies_rename_while_held(tmp_path):
    import os
    from continuityos import _offline_path_guard as guard
    root = make_view(tmp_path)
    moved = tmp_path / "moved_agent_view"
    with guard._win_anchored(root / "AGENT_POLICY_R61.json", directory=False):
        with pytest.raises(OSError) as denied:
            os.rename(root, moved)
        assert denied.value.winerror == 32
    assert root.is_dir()
    assert not moved.exists()


@pytest.mark.skipif(sys.platform != "win32", reason="Windows hardlink semantics")
def test_windows_hardlinked_projection_file_denied(tmp_path):
    import os
    root = make_view(tmp_path)
    source = root / "AGENT_POLICY_R61.json"
    alias = tmp_path / "synthetic_hardlink.json"
    os.link(source, alias)
    with pytest.raises(ValueError, match="FILE_MISSING_OR_LINKED"):
        mod.CentralMemoryMCPAdapter(str(root)).call("agent_view_status", {})
    assert alias.is_file()


@pytest.mark.skipif(sys.platform != "win32", reason="Windows path semantics")
@pytest.mark.parametrize("suffix", [".", " "])
def test_windows_trailing_dot_or_space_component_denied(tmp_path, suffix):
    from continuityos._offline_path_guard import require_plain_dir
    root = tmp_path / "agent_view"
    root.mkdir()
    with pytest.raises(ValueError, match="OFFLINE_PATH_UNSAFE"):
        require_plain_dir(Path(str(root) + suffix))
