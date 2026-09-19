from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys


def test_pro_readonly_stdio_protocol_hides_and_rejects_write_tools(tmp_path: Path):
    requests = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": "remember", "arguments": {"text": "no"}},
        },
        {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {"name": "capability_status", "arguments": {}},
        },
    ]
    payload = "".join(json.dumps(item) + "\n" for item in requests)
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "continuityos.remote_mcp_server",
            "--db",
            ":memory:",
            "--enable-remote",
            "--tool-profile",
            "chatgpt-pro-readonly",
            "--remote-root",
            str(tmp_path),
        ],
        input=payload,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stderr
    responses = {item["id"]: item for item in map(json.loads, completed.stdout.splitlines())}

    tools = responses[2]["result"]["tools"]
    assert [tool["name"] for tool in tools] == [
        "capability_status",
        "system_info",
        "fs_list",
        "fs_read",
    ]
    assert all(tool["annotations"]["readOnlyHint"] is True for tool in tools)

    denied = responses[3]["result"]
    assert denied["isError"] is True
    assert "tool hidden by remote tool profile" in denied["content"][0]["text"]

    status_text = responses[4]["result"]["content"][0]["text"]
    status = json.loads(status_text)
    assert status["tool_profile"] == "chatgpt-pro-readonly"
    assert status["mutating_execution"]["available"] is False
