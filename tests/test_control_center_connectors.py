from __future__ import annotations

import json
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import continuityos.connector_preview as cp
import continuityos.control_center as cc


def _config(root: Path) -> cc.ControlCenterConfig:
    return cc.ControlCenterConfig(
        runtime_root=root,
        twin_url="http://127.0.0.1:8765",
        lm_studio_url="http://127.0.0.1:1234",
    )


def _runtime(root: Path, db: Path) -> None:
    (root / "runtime-source.json").write_text(
        json.dumps(
            {
                "memory_db": str(db),
                "execution_authority": "NONE",
                "can_execute": False,
            }
        ),
        encoding="utf-8",
    )


def _json_get(base: str, path: str) -> tuple[int, dict]:
    try:
        with urlopen(base + path, timeout=5.0) as response:
            return response.status, json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8"))


def test_connector_status_reads_only_and_redacts_user_owned_config(tmp_path: Path, monkeypatch):
    db = tmp_path / "memory.db"
    db.write_bytes(b"memory")
    config = tmp_path / "mcp.json"
    original = {
        "mcpServers": {
            "continuityos": {
                "command": "old-python",
                "args": ["old"],
                "env": {"PRIVATE_TOKEN": "never-return-this"},
            },
            "other": {"command": "other", "env": {"API_KEY": "also-private"}},
        },
        "unrelated": {"secret": "third-private-value"},
    }
    config.write_text(json.dumps(original) + "\n", encoding="utf-8")
    before = config.read_bytes()
    monkeypatch.setenv("CONTINUITYOS_CLAUDE_CONFIG", str(config))
    monkeypatch.setenv("CONTINUITYOS_CURSOR_CONFIG", str(config))

    payload = cp.build_connector_status(str(db))

    assert payload["ok"] is True
    assert payload["read_only"] is True
    assert payload["execution_authority"] == "NONE"
    assert payload["can_execute"] is False
    assert payload["can_trade"] is False
    assert payload["capital_permission"] == "DENY"
    assert [item["client"] for item in payload["clients"]] == ["claude", "cursor", "hermes", "generic-mcp"]
    assert config.read_bytes() == before
    encoded = json.dumps(payload, sort_keys=True)
    for forbidden in ("never-return-this", "also-private", "third-private-value", "API_KEY", "PRIVATE_TOKEN", '"other"'):
        assert forbidden not in encoded


def test_managed_preview_is_byte_exact_and_does_not_expose_patched_config(tmp_path: Path, monkeypatch):
    db = tmp_path / "memory.db"
    db.write_bytes(b"memory")
    config = tmp_path / "cursor.json"
    config.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "other": {"command": "other", "env": {"SECRET": "hidden"}},
                },
                "private": "do-not-leak",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    before = config.read_bytes()
    monkeypatch.setenv("CONTINUITYOS_CURSOR_CONFIG", str(config))

    payload = cp.build_connector_preview("cursor", str(db))

    assert payload["ok"] is True
    assert payload["mode"] == "PREVIEW_ONLY"
    assert payload["managed"] is True
    assert payload["would_change"] is True
    assert payload["read_only"] is True
    assert payload["execution_authority"] == "NONE"
    assert "patched_config" not in payload
    assert "SECRET" not in json.dumps(payload)
    assert "do-not-leak" not in json.dumps(payload)
    assert config.read_bytes() == before
    assert list(tmp_path.glob("*.continuityos-backup-*")) == []
    assert not (tmp_path / "connect_state.json").exists()


def test_preview_missing_managed_config_does_not_create_it(tmp_path: Path, monkeypatch):
    db = tmp_path / "memory.db"
    db.write_bytes(b"memory")
    missing = tmp_path / "missing.json"
    monkeypatch.setenv("CONTINUITYOS_CURSOR_CONFIG", str(missing))

    payload = cp.build_connector_preview("cursor", str(db))

    assert payload["ok"] is True
    assert payload["config_exists"] is False
    assert payload["would_change"] is True
    assert missing.exists() is False


def test_manual_previews_contain_only_generated_continuityos_guidance(tmp_path: Path):
    db = tmp_path / "memory.db"
    hermes = cp.build_connector_preview("hermes", str(db))
    generic = cp.build_connector_preview("generic-mcp", str(db))

    assert hermes["managed"] is False
    assert hermes["reason"] == "MANUAL_COMMAND_REQUIRED"
    assert hermes["manual_command"].startswith("hermes mcp add continuityos ")
    assert generic["managed"] is False
    assert generic["reason"] == "MANUAL_CONFIG_REQUIRED"
    assert set(generic["config_snippet"]["mcpServers"]) == {"continuityos"}
    assert hermes["read_only"] is True
    assert generic["read_only"] is True


def test_invalid_connector_client_fails_closed():
    try:
        cp.build_connector_preview("not-a-client", "memory.db")
    except cp.ConnectorPreviewError as exc:
        assert exc.status == 400
        assert "unsupported" in exc.message
    else:
        raise AssertionError("unsupported client unexpectedly accepted")


def test_control_center_connector_routes_are_get_only_bounded_and_byte_exact(tmp_path: Path, monkeypatch):
    db = tmp_path / "memory.db"
    db.write_bytes(b"memory")
    _runtime(tmp_path, db)
    config = tmp_path / "cursor.json"
    config.write_text(
        json.dumps({"mcpServers": {"other": {"env": {"TOP_SECRET": "hidden-value"}}}}) + "\n",
        encoding="utf-8",
    )
    before = config.read_bytes()
    monkeypatch.setenv("CONTINUITYOS_CURSOR_CONFIG", str(config))
    monkeypatch.setenv("CONTINUITYOS_CLAUDE_CONFIG", str(config))

    server = ThreadingHTTPServer(("127.0.0.1", 0), cc._make_handler(_config(tmp_path)))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        status, inventory = _json_get(base, "/api/connectors")
        assert status == 200
        assert inventory["ok"] is True
        assert inventory["read_only"] is True
        assert "hidden-value" not in json.dumps(inventory)

        status, preview = _json_get(base, "/api/connectors/preview?client=cursor")
        assert status == 200
        assert preview["client"] == "cursor"
        assert preview["mode"] == "PREVIEW_ONLY"
        assert "patched_config" not in preview
        assert "hidden-value" not in json.dumps(preview)

        for path in (
            "/api/connectors?unexpected=1",
            "/api/connectors/preview",
            "/api/connectors/preview?client=cursor&client=claude",
            "/api/connectors/preview?client=cursor&unexpected=1",
            "/api/connectors/preview?client=invalid",
        ):
            code, payload = _json_get(base, path)
            assert code == 400
            assert payload["read_only"] is True
            assert payload["execution_authority"] == "NONE"
            assert payload["can_execute"] is False

        for method in ("POST", "PUT", "PATCH", "DELETE"):
            request = Request(base + "/api/connectors/preview?client=cursor", data=b"{}", method=method)
            try:
                urlopen(request, timeout=5.0)
            except HTTPError as exc:
                assert exc.code == 405
                payload = json.loads(exc.read().decode("utf-8"))
                assert payload["execution_authority"] == "NONE"
                assert payload["can_execute"] is False
            else:
                raise AssertionError(f"{method} unexpectedly succeeded")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2.0)

    assert config.read_bytes() == before
    assert list(tmp_path.glob("*.continuityos-backup-*")) == []


def test_connector_ui_is_preview_only_and_safe_dom():
    text = cc._UI
    assert "Connectors" in text
    assert "/api/connectors" in text
    assert "/api/connectors/preview" in text
    assert "Preview only" in text
    assert "textContent" in text
    assert "document.createElement" in text
    assert "replaceChildren" in text
    assert "innerHTML" not in text
    assert "method:'POST'" not in text
    assert 'method:"POST"' not in text
    assert "--yes" not in text
    assert "--rollback" not in text
