from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess

import pytest


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


def test_windows_tunnel_launcher_bounds_profile_identifier():
    source = SCRIPT.read_text(encoding="utf-8")
    assert "Profile has an invalid format." in source
    assert "^[A-Za-z0-9][A-Za-z0-9._-]*$" in source


@pytest.mark.skipif(os.name != "nt", reason="Windows PowerShell smoke test")
def test_windows_tunnel_launcher_plan_executes_without_credentials(tmp_path: Path):
    env = os.environ.copy()
    env.pop("CONTROL_PLANE_API_KEY", None)
    env.pop("CONTROL_PLANE_TUNNEL_ID", None)
    completed = subprocess.run(
        [
            "powershell",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(SCRIPT),
            "-Mode",
            "Plan",
            "-RemoteRoot",
            str(tmp_path),
        ],
        check=False,
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stderr
    plan = json.loads(completed.stdout)
    assert plan["mcp_transport"] == "stdio"
    assert plan["mcp_tool_profile"] == "chatgpt-pro-readonly"
    assert plan["inbound_listener"] is False
    assert plan["direct_shell"] is False
    assert plan["control_plane_key_present"] is False


def test_windows_tunnel_launcher_binds_official_tunnel_id_format():
    source = SCRIPT.read_text(encoding="utf-8")
    assert "^tunnel_[0-9a-f]{32}$" in source
    assert "TunnelId has an invalid format." in source
