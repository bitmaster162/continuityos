from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import subprocess
import sys
import threading

import pytest

from sct.runner.openai_compat import call_openai_compatible
from sct.runner.provider import (
    ProviderHTTP429Error,
    ProviderResponseMalformedJsonError,
    ProviderResponseTruncatedError,
    SubprocessJsonRunner,
)


_DEFAULT_RESPONSE = json.dumps({
    "option_probabilities": {"A": 0.41, "B": 0.34, "C": 0.25},
    "reasons": ["mock real-provider contract"],
    "change_conditions": [],
    "would_escalate": False,
})


class _Handler(BaseHTTPRequestHandler):
    seen = None
    response_content = _DEFAULT_RESPONSE
    response_payload = None

    def do_POST(self):
        n = int(self.headers["Content-Length"])
        body = json.loads(self.rfile.read(n))
        type(self).seen = {
            "path": self.path,
            "body": body,
            "authorization": self.headers.get("Authorization"),
        }
        payload = type(self).response_payload
        if payload is None:
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
    _Handler.seen = None
    _Handler.response_content = _DEFAULT_RESPONSE
    _Handler.response_payload = None
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    monkeypatch.setenv("SCT_OPENAI_COMPAT_API_KEY", "secret-test-key")
    monkeypatch.setenv("SCT_OPENAI_COMPAT_BASE_URL", f"http://127.0.0.1:{httpd.server_port}/v1")
    monkeypatch.setenv("SCT_OPENAI_COMPAT_JSON_MODE", "1")
    monkeypatch.delenv("SCT_OPENROUTER_REQUIRE_PARAMETERS", raising=False)
    try:
        yield httpd
    finally:
        httpd.shutdown()
        thread.join(timeout=2)
        _Handler.response_content = _DEFAULT_RESPONSE
        _Handler.response_payload = None


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


def _runner():
    return SubprocessJsonRunner(
        command=(sys.executable, "-m", "sct.runner.openai_compat"),
        timeout_seconds=10,
    )


def test_openai_compatible_runner_calls_exact_endpoint_without_arm(server):
    out = call_openai_compatible(_request())
    assert out["option_probabilities"]["A"] == pytest.approx(.41)
    assert _Handler.seen["path"] == "/v1/chat/completions"
    assert _Handler.seen["body"]["model"] == "example/model"
    assert _Handler.seen["body"]["response_format"] == {"type": "json_object"}
    assert "provider" not in _Handler.seen["body"]
    assert "arm" not in _Handler.seen["body"]
    assert _Handler.seen["authorization"] == "Bearer secret-test-key"


def test_openrouter_require_parameters_enables_zero_price_same_model_fallback_routing(server, monkeypatch):
    monkeypatch.setenv("SCT_OPENROUTER_REQUIRE_PARAMETERS", "1")
    out = call_openai_compatible(_request())
    assert out["option_probabilities"]["A"] == pytest.approx(.41)
    assert _Handler.seen["body"]["provider"] == {
        "require_parameters": True,
        "allow_fallbacks": True,
        "max_price": {"prompt": 0, "completion": 0},
    }
    assert _Handler.seen["body"]["response_format"] == {"type": "json_object"}
    assert "arm" not in _Handler.seen["body"]


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
    assert "SCT_PROVIDER_ERROR" not in proc.stderr


def test_embedded_http200_provider_429_is_exposed_as_typed_429(server):
    _Handler.response_payload = {
        "choices": [
            {
                "message": {"role": "assistant", "content": "partial output"},
                "finish_reason": "error",
                "error": {
                    "code": 429,
                    "message": "Provider temporarily rate limited",
                    "metadata": {
                        "error_type": "rate_limited",
                        "provider_name": "NVIDIA",
                        "limit_source": "upstream_provider_shared_pool",
                        "raw": "MUST_NOT_BE_EXPOSED",
                    },
                },
            }
        ]
    }
    with pytest.raises(ProviderHTTP429Error) as caught:
        _runner().predict(_request(), arm="generic")
    detail = str(caught.value)
    assert "provider HTTP 429" in detail
    assert "provider_name=NVIDIA" in detail
    assert "limit_source=upstream_provider_shared_pool" in detail
    assert "MUST_NOT_BE_EXPOSED" not in detail


def test_non_json_content_is_typed_malformed_without_raw_content(server):
    secretish_output = "analysis before object SECRET_OUTPUT {\"option_probabilities\":{}}"
    _Handler.response_payload = {
        "choices": [
            {
                "message": {"role": "assistant", "content": secretish_output},
                "finish_reason": "stop",
            }
        ]
    }
    with pytest.raises(ProviderResponseMalformedJsonError) as caught:
        _runner().predict(_request(), arm="sct")
    detail = str(caught.value)
    assert "finish_reason='stop'" in detail
    assert "content_shape=other" in detail
    assert "content_chars=" in detail
    assert "SECRET_OUTPUT" not in detail


def test_length_finish_reason_is_typed_truncated_without_raw_content(server):
    _Handler.response_payload = {
        "choices": [
            {
                "message": {"role": "assistant", "content": '{"option_probabilities":'},
                "finish_reason": "length",
            }
        ]
    }
    with pytest.raises(ProviderResponseTruncatedError) as caught:
        _runner().predict(_request(), arm="profile_rag")
    detail = str(caught.value)
    assert "finish_reason='length'" in detail
    assert "content_shape=object_like" in detail
    assert "option_probabilities" not in detail


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
