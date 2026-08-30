from __future__ import annotations

import hashlib
import json
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.error import URLError
from urllib.request import Request, urlopen

import continuityos.control_center as cc


def _config(root: Path) -> cc.ControlCenterConfig:
    return cc.ControlCenterConfig(
        runtime_root=root,
        twin_url="http://127.0.0.1:8765",
        lm_studio_url="http://127.0.0.1:1234",
    )


def test_build_status_is_read_only_and_reports_runtime_memory_models(tmp_path: Path):
    db = tmp_path / "memory.db"
    db.write_bytes(b"canonical-memory")
    admissions = tmp_path / "admissions.jsonl"
    admissions.write_text('{"id":1}\n\n{"id":2}\n', encoding="utf-8")
    (tmp_path / "runtime-venv").mkdir()
    (tmp_path / "rollback-r21h-cutover-test").mkdir()
    (tmp_path / "runtime-source.json").write_text(
        json.dumps(
            {
                "source_sha": "65a7eec8004d9de3b55b06c20ad38863825c1dd3",
                "python": "candidate/python.exe",
                "twin_executable": "candidate/sovereign-twin.exe",
                "memory_db": str(db),
                "admissions_path": str(admissions),
                "execution_authority": "NONE",
                "can_execute": False,
            }
        ),
        encoding="utf-8",
    )

    def fake_get(url: str, *, timeout: float = 2.0):
        assert timeout == 2.0
        if url.endswith("/health"):
            return {
                "ok": True,
                "mode": "LOCAL_SHADOW",
                "execution_authority": "NONE",
                "can_execute": False,
                "memory_db": str(db),
            }
        if url.endswith("/api/v1/models"):
            return {
                "models": [
                    {
                        "key": "qwen3.5-4b",
                        "loaded_instances": [{"id": "fast-1"}],
                    },
                    {
                        "key": "qwen3.6-35b-a3b",
                        "loaded_instances": [],
                    },
                    {
                        "key": "text-embedding-nomic-embed-text-v1.5",
                        "loaded_instances": [],
                    },
                ]
            }
        raise AssertionError(url)

    status = cc.build_status(_config(tmp_path), get_json=fake_get)

    assert status["ok"] is True
    assert status["read_only"] is True
    assert status["product"]["twin_baseline"] == "R21H"
    assert status["twin"] == {
        "reachable": True,
        "error": None,
        "ok": True,
        "mode": "LOCAL_SHADOW",
        "execution_authority": "NONE",
        "can_execute": False,
        "url": "http://127.0.0.1:8765",
    }
    assert status["memory"]["path"] == str(db)
    assert status["memory"]["size_bytes"] == len(b"canonical-memory")
    assert status["memory"]["sha256"] == hashlib.sha256(b"canonical-memory").hexdigest()
    assert status["admissions"]["exists"] is True
    assert status["admissions"]["count"] == 2
    assert status["models"]["fast"]["resident_instances"] == 1
    assert status["models"]["fast"]["instance_ids"] == ["fast-1"]
    assert status["models"]["deep"]["resident_instances"] == 0
    assert status["models"]["embedding"]["resident_instances"] == 0
    assert status["runtime_source"]["source_sha"].startswith("65a7eec8")
    assert status["rollback"]["old_venv_exists"] is True
    assert status["rollback"]["backup_count"] == 1
    assert status["governance"] == {
        "execution_authority": "NONE",
        "can_execute": False,
        "can_trade": False,
        "capital_permission": "DENY",
    }


def test_build_status_degrades_when_local_services_are_unreachable(tmp_path: Path):
    (tmp_path / "runtime-source.json").write_text(
        json.dumps({"execution_authority": "NONE", "can_execute": False}),
        encoding="utf-8",
    )

    def offline(_url: str, *, timeout: float = 2.0):
        raise URLError("offline")

    status = cc.build_status(_config(tmp_path), get_json=offline)

    assert status["ok"] is True
    assert status["twin"]["reachable"] is False
    assert status["models"]["reachable"] is False
    assert "URLError" in status["twin"]["error"]
    assert "URLError" in status["models"]["error"]
    assert status["governance"]["execution_authority"] == "NONE"
    assert status["governance"]["can_execute"] is False


def test_absent_admissions_are_reported_without_creating_file(tmp_path: Path):
    admissions = tmp_path / "never-created.jsonl"
    (tmp_path / "runtime-source.json").write_text(
        json.dumps({"admissions_path": str(admissions)}),
        encoding="utf-8",
    )

    def empty_services(url: str, *, timeout: float = 2.0):
        return {"models": []} if url.endswith("/api/v1/models") else {}

    status = cc.build_status(_config(tmp_path), get_json=empty_services)

    assert admissions.exists() is False
    assert status["admissions"] == {
        "path": str(admissions),
        "exists": False,
        "count": 0,
    }


def test_loopback_guard_rejects_remote_binds_and_upstreams():
    for host in ("127.0.0.1", "::1", "localhost"):
        assert cc._is_loopback_host(host) is True
    for host in ("0.0.0.0", "::", "192.168.1.2", "control.example"):
        assert cc._is_loopback_host(host) is False

    assert cc._is_loopback_url("http://127.0.0.1:8765") is True
    assert cc._is_loopback_url("http://localhost:1234") is True
    assert cc._is_loopback_url("http://192.168.1.2:8765") is False
    assert cc._is_loopback_url("https://example.com") is False

    assert cc.main(["serve", "--host", "0.0.0.0"]) == 2
    assert (
        cc.main(
            [
                "serve",
                "--twin-url",
                "http://192.168.1.2:8765",
            ]
        )
        == 2
    )


def test_ui_is_observability_only_and_uses_safe_dom_text():
    text = cc._UI
    assert "READ ONLY" in text
    assert "Sovereign Twin R21H" in text
    assert "fetch('/api/status'" in text
    assert "textContent" in text
    assert "innerHTML" not in text
    assert "method:'POST'" not in text
    assert 'method:"POST"' not in text
    assert "/api/chat" not in text
    assert "/models/load" not in text
    assert "/models/unload" not in text
    assert "can_trade" in text
    assert "capital_permission" in text


def test_http_surface_has_only_read_routes(tmp_path: Path):
    server = ThreadingHTTPServer(("127.0.0.1", 0), cc._make_handler(_config(tmp_path)))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        with urlopen(f"{base}/health", timeout=5.0) as response:
            payload = json.loads(response.read().decode("utf-8"))
        assert payload["ok"] is True
        assert payload["read_only"] is True
        assert payload["execution_authority"] == "NONE"
        assert payload["can_execute"] is False

        with urlopen(f"{base}/", timeout=5.0) as response:
            body = response.read().decode("utf-8")
        assert "ContinuityOS Control Center" in body

        request = Request(f"{base}/api/status", data=b"{}", method="POST")
        try:
            urlopen(request, timeout=5.0)
        except Exception as exc:
            assert getattr(exc, "code", None) == 405
        else:
            raise AssertionError("POST unexpectedly succeeded")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2.0)


def test_control_center_console_script_is_packaged():
    project = Path(__file__).resolve().parents[1] / "pyproject.toml"
    expected = 'continuityos-control-center = "continuityos.control_center:main"'
    if project.is_file():
        assert expected in project.read_text(encoding="utf-8")
        return

    from importlib.metadata import distribution

    scripts = {
        entry.name: entry.value
        for entry in distribution("continuityos").entry_points
        if entry.group == "console_scripts"
    }
    assert scripts.get("continuityos-control-center") == "continuityos.control_center:main"
