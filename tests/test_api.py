import json
import os
import tempfile
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

from continuityos import Memory
from continuityos.api import _assert_bind_allowed, make_handler


def _server(token=None):
    db = os.path.join(tempfile.mkdtemp(), "api.db")
    mem = Memory(db)
    srv = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(mem, token=token))
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    return srv, f"http://127.0.0.1:{srv.server_port}"


def _request(url, data=None, headers=None):
    req = urllib.request.Request(url, data=data, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=3) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode())


def test_http_rejects_remote_bind_without_explicit_opt_in(monkeypatch):
    monkeypatch.delenv("CONTINUITYOS_ALLOW_REMOTE", raising=False)
    with pytest.raises(RuntimeError):
        _assert_bind_allowed("0.0.0.0")

    monkeypatch.setenv("CONTINUITYOS_ALLOW_REMOTE", "1")
    _assert_bind_allowed("0.0.0.0")


def test_http_remember_rejects_bad_json():
    srv, base = _server()
    try:
        status, body = _request(
            base + "/remember",
            data=b"{bad json",
            headers={"Content-Type": "application/json"},
        )
        assert status == 400
        assert body["error"] == "invalid json"
    finally:
        srv.shutdown()


def test_http_remember_requires_text():
    srv, base = _server()
    try:
        status, body = _request(
            base + "/remember",
            data=json.dumps({"namespace": "notes"}).encode(),
            headers={"Content-Type": "application/json"},
        )
        assert status == 400
        assert body["error"] == "text is required"
    finally:
        srv.shutdown()


def test_http_optional_bearer_auth():
    srv, base = _server(token="secret")
    try:
        status, body = _request(base + "/health")
        assert status == 401
        assert body["error"] == "unauthorized"

        status, body = _request(base + "/health", headers={"Authorization": "Bearer secret"})
        assert status == 200
        assert body["ok"] is True
    finally:
        srv.shutdown()


def test_http_remember_and_recall_roundtrip_without_token():
    srv, base = _server()
    try:
        status, body = _request(
            base + "/remember",
            data=json.dumps({"text": "ContinuityOS HTTP smoke memory", "namespace": "facts"}).encode(),
            headers={"Content-Type": "application/json"},
        )
        assert status == 200
        assert body["id"] > 0

        status, body = _request(base + "/recall?q=HTTP%20smoke&k=1")
        assert status == 200
        assert body["hits"]
        assert body["hits"][0]["namespace"] == "facts"
    finally:
        srv.shutdown()
