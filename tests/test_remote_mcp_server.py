import json

import pytest

from continuityos.remote_mcp_server import RemoteSurface, TOOLS


def _tool_names():
    return {tool["name"] for tool in TOOLS}


def test_remote_tools_extend_existing_governed_exec_surface():
    names = _tool_names()
    assert {"capability_status", "system_info", "fs_list", "fs_read"} <= names
    assert {"preflight_exec", "execute_preflight"} <= names


def test_remote_surface_is_disabled_by_default_when_explicitly_disabled(tmp_path):
    surface = RemoteSurface(enabled=False, roots=[tmp_path])
    with pytest.raises(PermissionError, match="remote commander disabled"):
        surface.list_dir(".")


def test_list_and_read_are_root_bounded_and_hide_sensitive_files(tmp_path):
    (tmp_path / "notes.txt").write_text("hello continuity", encoding="utf-8")
    (tmp_path / ".env").write_text("TOKEN=secret", encoding="utf-8")
    nested = tmp_path / "nested"
    nested.mkdir()

    surface = RemoteSurface(enabled=True, roots=[tmp_path])
    listing = surface.list_dir(".")
    names = {entry["name"] for entry in listing["entries"]}
    assert "notes.txt" in names
    assert "nested" in names
    assert ".env" not in names
    assert listing["omitted_sensitive"] == 1

    read = surface.read_text("notes.txt")
    assert read["text"] == "hello continuity"
    assert read["truncated"] is False

    with pytest.raises(PermissionError, match="sensitive file denied"):
        surface.read_text(".env")


def test_path_escape_is_denied(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("outside", encoding="utf-8")

    surface = RemoteSurface(enabled=True, roots=[root])
    with pytest.raises(PermissionError, match="outside configured remote roots"):
        surface.read_text(outside)


def test_binary_and_oversized_limits_are_rejected(tmp_path):
    (tmp_path / "binary.dat").write_bytes(b"abc\x00def")
    (tmp_path / "text.txt").write_text("abcdef", encoding="utf-8")
    surface = RemoteSurface(enabled=True, roots=[tmp_path])

    with pytest.raises(ValueError, match="binary file refused"):
        surface.read_text("binary.dat")
    with pytest.raises(ValueError, match="max_bytes"):
        surface.read_text("text.txt", max_bytes=0)


def test_status_declares_no_direct_shell(tmp_path):
    surface = RemoteSurface(enabled=True, roots=[tmp_path])
    status = surface.status()
    assert status["enabled"] is True
    assert status["mutating_execution"]["direct_shell"] is False
    assert status["mutating_execution"]["path"] == ["preflight_exec", "execute_preflight"]
    json.dumps(status)
