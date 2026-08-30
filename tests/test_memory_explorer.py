from __future__ import annotations

import hashlib
import json
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import continuityos.control_center as cc
from continuityos.store import Store


def _config(root: Path) -> cc.ControlCenterConfig:
    return cc.ControlCenterConfig(
        runtime_root=root,
        twin_url="http://127.0.0.1:8765",
        lm_studio_url="http://127.0.0.1:1234",
    )


def _seed_memory(root: Path) -> tuple[Path, int, int]:
    db = root / "memory.db"
    store = Store(str(db))
    first = store.add(
        "alpha project memory",
        namespace="project",
        tags=["alpha", "bounded"],
        meta={"source": "test"},
        vec=[0.1, 0.2],
        key="alpha",
    )
    second = store.add(
        "beta rule memory",
        namespace="rules",
        tags=["beta"],
        meta={"source": "test"},
        key="beta",
    )
    store.con.close()
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
    return db, first, second


def _sidecars(db: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for suffix in ("-wal", "-shm", "-journal"):
        path = Path(str(db) + suffix)
        if path.exists():
            result[suffix] = hashlib.sha256(path.read_bytes()).hexdigest()
    return result


def _json_get(base: str, path: str) -> tuple[int, dict]:
    try:
        with urlopen(base + path, timeout=5.0) as response:
            return response.status, json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8"))


def _serve(config: cc.ControlCenterConfig):
    server = ThreadingHTTPServer(("127.0.0.1", 0), cc._make_handler(config))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread, f"http://127.0.0.1:{server.server_port}"


def test_memory_explorer_http_reads_are_byte_exact_and_create_no_sqlite_sidecars(
    tmp_path: Path,
    monkeypatch,
):
    db, first, second = _seed_memory(tmp_path)

    def fake_get(url: str, *, timeout: float = 2.0):
        assert timeout == 2.0
        if url.endswith("/health"):
            return {
                "ok": True,
                "execution_authority": "NONE",
                "can_execute": False,
                "memory_db": str(db),
            }
        raise AssertionError(url)

    monkeypatch.setattr(cc, "_json_get", fake_get)
    before_bytes = db.read_bytes()
    before_sidecars = _sidecars(db)

    server, thread, base = _serve(_config(tmp_path))
    try:
        status, recent = _json_get(base, "/api/memory?limit=10")
        assert status == 200
        assert recent["ok"] is True
        assert recent["read_only"] is True
        assert recent["execution_authority"] == "NONE"
        assert recent["can_execute"] is False
        assert recent["count"] == 2
        assert [item["id"] for item in recent["items"]] == [second, first]
        assert all("vec" not in item for item in recent["items"])

        status, search = _json_get(
            base,
            "/api/memory?query=alpha&namespace=project&limit=10",
        )
        assert status == 200
        assert [item["id"] for item in search["items"]] == [first]
        assert search["items"][0]["tags"] == ["alpha", "bounded"]

        status, detail = _json_get(base, f"/api/memory/item?id={first}")
        assert status == 200
        assert detail["item"]["id"] == first
        assert detail["item"]["namespace"] == "project"
        assert detail["item"]["meta"] == {"source": "test"}
        assert "vec" not in detail["item"]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2.0)

    assert db.read_bytes() == before_bytes
    assert _sidecars(db) == before_sidecars


def test_memory_explorer_missing_database_fails_closed_without_creation(
    tmp_path: Path,
    monkeypatch,
):
    missing = tmp_path / "missing.db"
    (tmp_path / "runtime-source.json").write_text(
        json.dumps({"memory_db": str(missing)}),
        encoding="utf-8",
    )

    def fake_get(url: str, *, timeout: float = 2.0):
        return {"memory_db": str(missing)} if url.endswith("/health") else {}

    monkeypatch.setattr(cc, "_json_get", fake_get)
    server, thread, base = _serve(_config(tmp_path))
    try:
        status, payload = _json_get(base, "/api/memory")
        assert status == 503
        assert payload["ok"] is False
        assert payload["read_only"] is True
        assert payload["execution_authority"] == "NONE"
        assert payload["can_execute"] is False
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2.0)

    assert missing.exists() is False
    assert _sidecars(missing) == {}


def test_memory_explorer_validates_query_envelope_and_rejects_mutation_methods(
    tmp_path: Path,
    monkeypatch,
):
    db, _, _ = _seed_memory(tmp_path)

    def fake_get(url: str, *, timeout: float = 2.0):
        return {"memory_db": str(db)} if url.endswith("/health") else {}

    monkeypatch.setattr(cc, "_json_get", fake_get)
    server, thread, base = _serve(_config(tmp_path))
    try:
        for path in (
            "/api/memory?limit=0",
            "/api/memory?limit=101",
            "/api/memory?limit=nope",
            "/api/memory?query=a&query=b",
            "/api/memory?unexpected=1",
            "/api/memory/item?id=0",
            "/api/memory/item?id=nope",
            "/api/memory/item?id=1&id=2",
        ):
            status, payload = _json_get(base, path)
            assert status == 400
            assert payload["read_only"] is True

        for method in ("POST", "PUT", "PATCH", "DELETE"):
            request = Request(base + "/api/memory", data=b"{}", method=method)
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


def test_memory_explorer_ui_uses_get_only_safe_dom_rendering():
    text = cc._UI
    assert "Memory Explorer" in text
    assert "/api/memory" in text
    assert "textContent" in text
    assert "document.createElement" in text
    assert "innerHTML" not in text
    assert "method:'POST'" not in text
    assert 'method:"POST"' not in text
    assert "vectors are not exposed" in text


def test_memory_explorer_nonempty_wal_fails_closed_without_touching_sidecars(
    tmp_path: Path,
    monkeypatch,
):
    db, _, _ = _seed_memory(tmp_path)
    wal = Path(str(db) + "-wal")
    wal.write_bytes(b"uncheckpointed")

    def fake_get(url: str, *, timeout: float = 2.0):
        return {"memory_db": str(db)} if url.endswith("/health") else {}

    monkeypatch.setattr(cc, "_json_get", fake_get)
    before_db = db.read_bytes()
    before_sidecars = _sidecars(db)
    server, thread, base = _serve(_config(tmp_path))
    try:
        status, payload = _json_get(base, "/api/memory")
        assert status == 409
        assert "fails closed" in payload["error"]
        assert payload["execution_authority"] == "NONE"
        assert payload["can_execute"] is False
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2.0)

    assert db.read_bytes() == before_db
    assert _sidecars(db) == before_sidecars
