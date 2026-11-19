from __future__ import annotations

from pathlib import Path

import pytest


SCRIPT = (
    Path(__file__).resolve().parents[1]
    / "scripts"
    / "windows"
    / "Test-ContinuityOS-RemoteRuntime.ps1"
)


def _source() -> str:
    if not SCRIPT.is_file():
        pytest.skip("source-tree-only Windows runtime harness is not shipped in the wheel")
    return SCRIPT.read_text(encoding="utf-8")


def test_runtime_harness_requires_clean_git_baseline():
    source = _source()
    assert "git rev-parse HEAD" in source
    assert "git status --porcelain" in source
    assert "ExpectedHead" in source
    assert "Runtime qualification requires a clean Git worktree." in source


def test_runtime_harness_proves_readonly_tool_boundary():
    source = _source()
    assert "--tool-profile" in source
    assert "chatgpt-pro-readonly" in source
    assert '@("capability_status", "system_info", "fs_list", "fs_read")' in source
    assert 'name="remember"' in source
    assert "tool hidden by remote tool profile" in source
    assert "LOCAL_READONLY_RUNTIME_GREEN" in source


def test_runtime_harness_does_not_claim_live_tunnel():
    source = _source()
    assert "live_tunnel_qualified = $false" in source
    assert "control_plane_key_present" in source
    assert "tunnel_id_present" in source
    assert "CONTROL_PLANE_API_KEY" in source
    assert "CONTROL_PLANE_TUNNEL_ID" in source


def test_runtime_harness_keeps_public_surface_closed():
    source = _source()
    assert "public_mcp_listener" in source
    assert "health_listener_scope" in source
    assert '"loopback"' in source
    assert "direct_shell" in source
