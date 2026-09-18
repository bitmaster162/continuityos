from __future__ import annotations

import json
from pathlib import Path

import pytest

from continuityos.remote_mcp_server import (
    TOOL_PROFILE_CHATGPT_PRO_READONLY,
    RemoteServer,
)


def _server(tmp_path: Path, *, profile: str = TOOL_PROFILE_CHATGPT_PRO_READONLY):
    return RemoteServer(
        db=":memory:",
        remote_enabled=True,
        remote_roots=[tmp_path],
        tool_profile=profile,
    )


def test_pro_profile_advertises_only_bounded_host_read_tools(tmp_path: Path):
    server = _server(tmp_path)
    assert [tool["name"] for tool in server.tools] == [
        "capability_status",
        "system_info",
        "fs_list",
        "fs_read",
    ]


def test_pro_profile_tools_are_annotated_read_only(tmp_path: Path):
    server = _server(tmp_path)
    assert server.tools
    for tool in server.tools:
        annotations = tool["annotations"]
        assert annotations["readOnlyHint"] is True
        assert annotations["destructiveHint"] is False
        assert annotations["idempotentHint"] is True
        assert annotations["openWorldHint"] is False

@pytest.mark.parametrize(
    "name,args",
    [
        ("remember", {"text": "must not write"}),
        ("upsert", {"text": "x", "key": "k"}),
        ("forget", {"id": 1}),
        (
            "preflight_exec",
            {"request_id": "r1", "argv": ["echo", "x"], "cwd": "."},
        ),
        ("execute_preflight", {"request_id": "r1"}),
    ],
)
def test_pro_profile_rejects_hidden_write_or_execution_tools(
    tmp_path: Path, name: str, args: dict
):
    server = _server(tmp_path)
    with pytest.raises(PermissionError, match="tool hidden by remote tool profile"):
        server.call(name, args)


def test_capability_status_reports_effective_profile(tmp_path: Path):
    server = _server(tmp_path)
    value = json.loads(server.call("capability_status", {}))
    assert value["tool_profile"] == TOOL_PROFILE_CHATGPT_PRO_READONLY
    assert value["advertised_tools"] == [
        "capability_status",
        "system_info",
        "fs_list",
        "fs_read",
    ]
    assert value["mutating_execution"]["direct_shell"] is False


def test_unknown_profile_fails_closed(tmp_path: Path):
    with pytest.raises(ValueError, match="unknown remote tool profile"):
        _server(tmp_path, profile="anything-goes")
