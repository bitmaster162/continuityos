import io
import json
from types import SimpleNamespace

import pytest

import gate_hook


def _run(monkeypatch, capsys, response, returncode=0, payload=None):
    captured = {}

    def fake_run(argv, **kwargs):
        captured["argv"] = argv
        captured["env"] = kwargs.get("env")
        return SimpleNamespace(stdout=response, stderr="", returncode=returncode)

    monkeypatch.setattr(gate_hook.subprocess, "run", fake_run)
    monkeypatch.setattr(gate_hook.sys, "stdin", io.StringIO(json.dumps(
        payload if payload is not None else {
            "tool_name": "terminal",
            "tool_input": {"command": "rm target.txt"},
        }
    )))
    gate_hook.main()
    return capsys.readouterr().out.strip(), captured


def test_bridge_uses_structured_preflight_and_blocks_confirmation(monkeypatch, capsys):
    output, captured = _run(monkeypatch, capsys, json.dumps({
        "decision": "REQUIRE_CONFIRMATION",
        "reasons": ["filesystem delete"],
    }))
    assert captured["argv"][-1] == "--json"
    assert "--db" not in captured["argv"]
    assert captured["argv"][captured["argv"].index("--cwd") + 1] == ""
    assert json.loads(output)["decision"] == "block"
    assert "REQUIRE_CONFIRMATION" in json.loads(output)["reason"]


def test_bridge_fails_closed_on_nonzero_or_invalid_response(monkeypatch, capsys):
    output, _ = _run(monkeypatch, capsys, "", returncode=1)
    assert json.loads(output)["decision"] == "block"
    output, _ = _run(monkeypatch, capsys, "not-json")
    assert json.loads(output)["decision"] == "block"


def test_bridge_allows_only_explicit_allow_or_warn(monkeypatch, capsys):
    output, _ = _run(monkeypatch, capsys, json.dumps({"decision": "ALLOW", "reasons": []}))
    assert output == ""
    output, _ = _run(monkeypatch, capsys, json.dumps({"decision": "MAYBE", "reasons": []}))
    assert json.loads(output)["decision"] == "block"


def test_bridge_preserves_authoritative_payload_cwd(monkeypatch, capsys, tmp_path):
    output, captured = _run(
        monkeypatch,
        capsys,
        json.dumps({"decision": "ALLOW", "reasons": []}),
        payload={
            "tool_name": "terminal",
            "tool_input": {"command": "touch relative.txt"},
            "cwd": str(tmp_path),
        },
    )
    assert output == ""
    assert captured["argv"][captured["argv"].index("--cwd") + 1] == str(tmp_path)


def test_bridge_prefers_terminal_workdir_over_session_cwd(
    monkeypatch, capsys, tmp_path
):
    session = tmp_path / "session"
    workdir = tmp_path / "protected"
    session.mkdir()
    workdir.mkdir()
    output, captured = _run(
        monkeypatch,
        capsys,
        json.dumps({"decision": "ALLOW", "reasons": []}),
        payload={
            "tool_name": "terminal",
            "tool_input": {
                "command": "rm relative.db",
                "workdir": str(workdir),
            },
            "cwd": str(session),
        },
    )
    assert output == ""
    assert captured["argv"][captured["argv"].index("--cwd") + 1] == str(workdir)


@pytest.mark.parametrize("workdir", ["", ".", "relative/path", 7])
def test_bridge_blocks_non_authoritative_terminal_workdir(
    monkeypatch, capsys, workdir
):
    called = []
    monkeypatch.setattr(
        gate_hook.subprocess,
        "run",
        lambda *args, **kwargs: called.append((args, kwargs)),
    )
    monkeypatch.setattr(
        gate_hook.sys,
        "stdin",
        io.StringIO(json.dumps({
            "tool_name": "terminal",
            "tool_input": {"command": "rm relative.db", "workdir": workdir},
        })),
    )
    gate_hook.main()
    output = json.loads(capsys.readouterr().out)
    assert output["decision"] == "block"
    assert "workdir" in output["reason"]
    assert called == []


@pytest.mark.parametrize(
    "payload",
    [
        [],
        {"tool_name": "terminal", "tool_input": []},
        {"tool_name": "terminal", "tool_input": None},
        {"tool_name": "terminal", "tool_input": "rm -rf /"},
        {"tool_name": "terminal", "tool_input": {"command": ["rm", "-rf", "/"]}},
    ],
)
def test_bridge_blocks_malformed_payload_shapes(
    monkeypatch, capsys, payload
):
    monkeypatch.setattr(
        gate_hook.sys,
        "stdin",
        io.StringIO(json.dumps(payload)),
    )
    gate_hook.main()
    output = json.loads(capsys.readouterr().out)
    assert output["decision"] == "block"
    assert "fail-closed" in output["reason"]


def test_bridge_blocks_execute_code_instead_of_treating_missing_command_as_allow(
    monkeypatch, capsys
):
    called = []
    monkeypatch.setattr(
        gate_hook.subprocess,
        "run",
        lambda *args, **kwargs: called.append((args, kwargs)),
    )
    monkeypatch.setattr(
        gate_hook.sys,
        "stdin",
        io.StringIO(json.dumps({
            "tool_name": "execute_code",
            "tool_input": {"code": "terminal('rm -rf /')"},
        })),
    )
    gate_hook.main()
    output = json.loads(capsys.readouterr().out)
    assert output["decision"] == "block"
    assert "execute_code" in output["reason"]
    assert called == []
