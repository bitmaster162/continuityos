from __future__ import annotations

import json
from pathlib import Path

import continuityos.windows_control_center_entry as entry
from continuityos.control_center import ControlCenterConfig


class _FakeProcess:
    def __init__(self, pid: int = 4242):
        self.pid = pid
        self.returncode = None
        self.terminated = False

    def poll(self):
        return self.returncode

    def terminate(self):
        self.terminated = True
        self.returncode = 0

    def wait(self, timeout=None):
        return self.returncode

    def kill(self):
        self.returncode = -9


def _config(tmp_path: Path) -> ControlCenterConfig:
    return ControlCenterConfig(
        runtime_root=tmp_path,
        twin_url="http://127.0.0.1:8765",
        lm_studio_url="http://127.0.0.1:1234",
    )


def test_health_contract_is_exact_read_only():
    assert entry._health_is_exact_read_only(
        {
            "ok": True,
            "read_only": True,
            "execution_authority": "NONE",
            "can_execute": False,
        }
    )
    assert not entry._health_is_exact_read_only(
        {
            "ok": True,
            "read_only": True,
            "execution_authority": "LOCAL",
            "can_execute": False,
        }
    )
    assert not entry._health_is_exact_read_only(
        {
            "ok": True,
            "read_only": True,
            "execution_authority": "NONE",
            "can_execute": True,
        }
    )


def test_occupied_port_fails_closed_before_spawn(tmp_path: Path, capsys):
    spawned = []

    def never_spawn(*args, **kwargs):
        spawned.append((args, kwargs))
        raise AssertionError("must not spawn on occupied port")

    rc = entry.open_control_center(
        host="127.0.0.1",
        port=8766,
        config=_config(tmp_path),
        popen_factory=never_spawn,
        port_checker=lambda *_args, **_kwargs: True,
    )

    assert rc == 2
    assert spawned == []
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is False
    assert payload["execution_authority"] == "NONE"
    assert payload["can_execute"] is False


def test_entry_uses_current_packaged_python_waits_for_health_then_opens(tmp_path: Path, monkeypatch, capsys):
    proc = _FakeProcess()
    captured = {}
    browser_calls = []

    def fake_popen(command, **kwargs):
        captured["command"] = command
        captured["kwargs"] = kwargs
        return proc

    health_calls = []

    def healthy(url: str, *, timeout: float):
        health_calls.append((url, timeout))
        return {
            "ok": True,
            "read_only": True,
            "execution_authority": "NONE",
            "can_execute": False,
        }

    monkeypatch.delenv(entry.SUPPRESS_BROWSER_ENV, raising=False)
    rc = entry.open_control_center(
        host="127.0.0.1",
        port=8766,
        config=_config(tmp_path),
        health_getter=healthy,
        popen_factory=fake_popen,
        browser_open=lambda url, **kwargs: browser_calls.append((url, kwargs)) or True,
        port_checker=lambda *_args, **_kwargs: False,
        sleep=lambda _value: None,
        monotonic=iter((0.0, 0.1, 0.2)).__next__,
    )

    assert rc == 0
    command = captured["command"]
    assert command[0] == entry.sys.executable
    assert command[1:5] == ["-B", "-I", "-m", "continuityos.control_center"]
    assert "serve" in command
    assert command[command.index("--host") + 1] == "127.0.0.1"
    assert command[command.index("--port") + 1] == "8766"
    assert command[command.index("--runtime-root") + 1] == str(tmp_path)
    assert command[command.index("--twin-url") + 1] == "http://127.0.0.1:8765"
    assert command[command.index("--lm-studio-url") + 1] == "http://127.0.0.1:1234"
    assert health_calls == [("http://127.0.0.1:8766/health", 0.5)]
    assert browser_calls == [("http://127.0.0.1:8766/", {"new": 2})]
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is True
    assert payload["pid"] == 4242
    assert payload["read_only"] is True
    assert payload["execution_authority"] == "NONE"
    assert payload["can_execute"] is False


def test_browser_is_never_opened_before_valid_health(tmp_path: Path, capsys):
    proc = _FakeProcess()
    browser_calls = []

    rc = entry.open_control_center(
        host="127.0.0.1",
        port=8766,
        config=_config(tmp_path),
        health_getter=lambda *_args, **_kwargs: {
            "ok": True,
            "read_only": True,
            "execution_authority": "NONE",
            "can_execute": True,
        },
        popen_factory=lambda *_args, **_kwargs: proc,
        browser_open=lambda *args, **kwargs: browser_calls.append((args, kwargs)) or True,
        port_checker=lambda *_args, **_kwargs: False,
        sleep=lambda _value: None,
        monotonic=iter((0.0, 0.1, 0.2)).__next__,
    )

    assert rc == 2
    assert browser_calls == []
    assert proc.terminated is True
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is False


def test_ci_browser_suppression_keeps_health_gate(tmp_path: Path, monkeypatch, capsys):
    proc = _FakeProcess()
    browser_calls = []
    monkeypatch.setenv(entry.SUPPRESS_BROWSER_ENV, "1")

    rc = entry.open_control_center(
        host="127.0.0.1",
        port=8766,
        config=_config(tmp_path),
        health_getter=lambda *_args, **_kwargs: {
            "ok": True,
            "read_only": True,
            "execution_authority": "NONE",
            "can_execute": False,
        },
        popen_factory=lambda *_args, **_kwargs: proc,
        browser_open=lambda *args, **kwargs: browser_calls.append((args, kwargs)) or True,
        port_checker=lambda *_args, **_kwargs: False,
        sleep=lambda _value: None,
        monotonic=iter((0.0, 0.1, 0.2)).__next__,
    )

    assert rc == 0
    assert browser_calls == []
    payload = json.loads(capsys.readouterr().out)
    assert payload["pid"] == 4242
