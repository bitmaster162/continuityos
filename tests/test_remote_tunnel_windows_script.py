from __future__ import annotations

from pathlib import Path


SCRIPT = (
    Path(__file__).resolve().parents[1]
    / "scripts"
    / "windows"
    / "ContinuityOS-RemoteTunnel.ps1"
)


def test_windows_tunnel_launcher_keeps_key_out_of_command_line():
    source = SCRIPT.read_text(encoding="utf-8")
    assert "CONTROL_PLANE_API_KEY" in source
    assert "--api-key" not in source
    assert "--token" not in source
    assert "Set-Content" not in source
    assert "Add-Content" not in source


def test_windows_tunnel_launcher_uses_stdio_and_pro_readonly_profile():
    source = SCRIPT.read_text(encoding="utf-8")
    assert "sample_mcp_stdio_local" in source
    assert "-m continuityos.remote_mcp_server" in source
    assert "--enable-remote" in source
    assert "--tool-profile chatgpt-pro-readonly" in source
    assert 'mcp_transport = "stdio"' in source
    assert "inbound_listener = $false" in source


def test_windows_tunnel_launcher_accepts_no_arbitrary_mcp_command():
    source = SCRIPT.read_text(encoding="utf-8")
    assert "[string]$McpCommand" not in source
    assert "[string]$Command" not in source
    assert "The child MCP is deliberately fixed" in source
