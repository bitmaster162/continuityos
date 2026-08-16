from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import subprocess
import sys
import threading

import pytest

from sct.runner.openai_compat import call_openai_compatible


class _Handler(BaseHTTPRequestHandler):
    seen = None
    response_content = json.dumps({
        "option_probabilities": {"A": 0.41, "B": 0.34, "C": 0.25},
        "reasons": ["mock real-provider contract"],
        "change_conditions": [],
        "would_escalate": False,
    })

    def do_POST(self):
        n = int(self.headers["Content-Length"])
        body = json.loads(self.rfile.read(n))
        type(self).seen = {
            "path": self.path,
            "body": body,
            "authorization": self.headers.get("Authorization"),
        }
        payload = {"choices": [{"message": {"content": type(self).response_content}}]}
        raw = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, *args):
        pass


@pytest.fixture
def server(monkeypatch):
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    monkeypatch.setenv("SCT_OPENAI_COMPAT_API_KEY", "secret-test-key")
    monkeypatch.setenv("SCT_OPENAI_COMPAT_BASE_URL", f"http://127.0.0.1:{httpd.server_port}/v1")
    monkeypatch.setenv("SCT_OPENAI_COMPAT_JSON_MODE", "1")
    try:
        yield httpd
    finally:
        httpd.shutdown()
        thread.join(timeout=2)


def _request():
    return {
        "provider": "openai-compatible",
        "model": "example/model",
        "model_version": "v1",
        "token_budget": 512,
        "temperature": 0.0,
        "messages": [
            {"role": "system", "content": "predict"},
            {"role": "user", "content": "{}"},
        ],
    }


def test_openai_compatible_runner_calls_exact_endpoint_without_arm(server):
    out = call_openai_compatible(_request())
    assert out["option_probabilities"]["A"] == pytest.approx(.41)
    assert _Handler.seen["path"] == "/v1/chat/completions"
    assert _Handler.seen["body"]["model"] == "example/model"
    assert _Handler.seen["body"]["response_format"] == {"type": "json_object"}
    assert "arm" not in _Handler.seen["body"]
    assert _Handler.seen["authorization"] == "Bearer secret-test-key"


def test_module_subprocess_contract_emits_only_prediction_json(server):
    env = os.environ.copy()
    proc = subprocess.run(
        [sys.executable, "-m", "sct.runner.openai_compat"],
        input=json.dumps(_request()),
        text=True,
        capture_output=True,
        env=env,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    obj = json.loads(proc.stdout)
    assert set(obj["option_probabilities"]) == {"A", "B", "C"}
    assert proc.stderr == ""


def test_missing_key_fails_without_echoing_secret(monkeypatch):
    monkeypatch.delenv("SCT_OPENAI_COMPAT_API_KEY", raising=False)
    proc = subprocess.run(
        [sys.executable, "-m", "sct.runner.openai_compat"],
        input=json.dumps(_request()),
        text=True,
        capture_output=True,
        env={k: v for k, v in os.environ.items() if k != "SCT_OPENAI_COMPAT_API_KEY"},
        check=False,
    )
    assert proc.returncode == 2
    assert "SCT_OPENAI_COMPAT_API_KEY" in proc.stderr
    assert "secret-test-key" not in proc.stderr
