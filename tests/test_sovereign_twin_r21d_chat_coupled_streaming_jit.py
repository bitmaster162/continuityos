from __future__ import annotations

import json
from threading import RLock

import pytest

import continuityos.sovereign_twin_runtime as runtime_module
from continuityos.sovereign_twin_runtime import (
    DEFAULT_PROFILES,
    LmStudioClient,
    LocalChatResult,
    LocalModelEndpointError,
    SovereignTwinRuntime,
)


class StreamingClient:
    base_url = "http://127.0.0.1:1234"
    load_timeout = 600.0

    def __init__(self, *, unload_mode: str = "success", deep_context: int = 4096):
        self.fast_loaded = True
        self.deep_ids: list[str] = []
        self.deep_context = deep_context
        self.unload_mode = unload_mode
        self.events: list[tuple[object, ...]] = []
        self.explicit_load_calls = 0

    def models(self):
        fast = (
            [{"id": "fast-1", "config": {"context_length": 8192}}]
            if self.fast_loaded
            else []
        )
        deep = [
            {"id": value, "config": {"context_length": self.deep_context}}
            for value in self.deep_ids
        ]
        return [
            {"key": "qwen3.5-4b", "loaded_instances": fast},
            {"key": "qwen3.6-35b-a3b", "loaded_instances": deep},
        ]

    def load(self, *, model, context_length):
        self.explicit_load_calls += 1
        self.events.append(("load", model, context_length))
        if model == "qwen3.5-4b":
            self.fast_loaded = True
            return "fast-1"
        raise AssertionError("R21D production DEEP path must not call explicit load")

    def load_for_acquisition(self, **kwargs):
        self.explicit_load_calls += 1
        raise AssertionError("R21D production DEEP path must not call load_for_acquisition")

    def unload(self, instance_id):
        self.events.append(("unload", instance_id))
        if instance_id == "fast-1":
            self.fast_loaded = False
            return
        if not instance_id.startswith("deep"):
            return
        if self.unload_mode == "success":
            self.deep_ids = [value for value in self.deep_ids if value != instance_id]
            return
        if self.unload_mode == "404_absent":
            self.deep_ids = [value for value in self.deep_ids if value != instance_id]
            raise LocalModelEndpointError(
                "LM Studio/llmster request failed: HTTPError: HTTP Error 404: "
                "Not Found: Model with instance identifier 'deep-r21d-1' is not loaded."
            )
        if self.unload_mode == "404_still_present":
            raise LocalModelEndpointError(
                "LM Studio/llmster request failed: HTTPError: HTTP Error 404: "
                "Not Found: Model with instance identifier 'deep-r21d-1' is not loaded."
            )
        raise AssertionError(self.unload_mode)

    def chat_streaming_jit(self, *, on_model_load_end, **kwargs):
        self.events.append(("stream_chat", kwargs["model"], kwargs["context_length"]))
        assert self.deep_ids == []
        self.deep_ids = ["deep-r21d-1"]
        on_model_load_end("deep-r21d-1", 10.75)
        return (
            LocalChatResult(
                text="DEEP_STREAM_OK",
                model_instance_id="deep-r21d-1",
                stats={"tokens_per_second": 7.5, "total_output_tokens": 12},
                reasoning="internal",
            ),
            {
                "model_instance_id": "deep-r21d-1",
                "model_load_time_seconds": 10.75,
                "event_types": (
                    "chat.start",
                    "model_load.start",
                    "model_load.end",
                    "prompt_processing.start",
                    "message.start",
                    "message.end",
                    "chat.end",
                ),
            },
        )


def make_runtime(client: StreamingClient) -> SovereignTwinRuntime:
    runtime = object.__new__(SovereignTwinRuntime)
    runtime.client = client
    runtime.profiles = dict(DEFAULT_PROFILES)
    runtime._model_lock = RLock()
    runtime.evidence = lambda query: ()
    return runtime


def test_native_deep_uses_one_streaming_jit_transaction_and_no_explicit_load():
    client = StreamingClient()
    answer = make_runtime(client).ask("x", mode="deep")

    assert answer.text == "DEEP_STREAM_OK"
    assert answer.model == "qwen3.6-35b-a3b"
    assert answer.mode == "deep"
    assert answer.execution_authority == "NONE"
    assert answer.can_execute is False
    assert client.explicit_load_calls == 0
    assert client.events[0] == ("unload", "fast-1")
    assert ("stream_chat", "qwen3.6-35b-a3b", 4096) in client.events
    assert client.events[-1] == ("unload", "deep-r21d-1")
    assert client.fast_loaded is False
    assert client.deep_ids == []
    assert answer.stats["deep_jit_load_time_seconds"] == 10.75
    assert "model_load.end" in answer.stats["deep_jit_stream_event_types"]
    assert set(answer.stats["deep_phase_timings_ms"]) == {
        "model_lock_wait",
        "fast_release",
        "evidence_retrieval",
        "deep_pre_acquire_proof",
        "deep_load",
        "deep_acquisition_proof",
        "deep_chat",
        "deep_unload",
        "deep_post_unload_proof",
        "total_request",
    }


def test_model_load_end_exact_context_is_proven_before_stream_continues():
    client = StreamingClient(deep_context=2048)
    with pytest.raises(LocalModelEndpointError, match="context_length mismatch"):
        make_runtime(client).ask("x", mode="deep")
    assert client.explicit_load_calls == 0
    assert client.deep_ids == []


def test_cleanup_404_is_idempotent_only_when_catalog_proves_deep_absent():
    client = StreamingClient(unload_mode="404_absent")
    answer = make_runtime(client).ask("x", mode="deep")
    assert answer.text == "DEEP_STREAM_OK"
    assert client.deep_ids == []


def test_cleanup_404_fails_closed_when_deep_is_still_resident():
    client = StreamingClient(unload_mode="404_still_present")
    with pytest.raises(LocalModelEndpointError, match="remains resident"):
        make_runtime(client).ask("x", mode="deep")


class FakeSseResponse:
    def __init__(self, events: list[tuple[str, dict]]):
        self._lines: list[bytes] = []
        for event_type, payload in events:
            self._lines.append(f"event: {event_type}\n".encode())
            self._lines.append(("data: " + json.dumps(payload) + "\n").encode())
            self._lines.append(b"\n")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def __iter__(self):
        return iter(self._lines)


def success_events(*, chat_end_id: str = "deep-r21d-1", include_load_end: bool = True):
    rows = [
        ("chat.start", {"type": "chat.start", "model_instance_id": "deep-r21d-1"}),
        ("model_load.start", {"type": "model_load.start", "model_instance_id": "deep-r21d-1"}),
    ]
    if include_load_end:
        rows.append((
            "model_load.end",
            {
                "type": "model_load.end",
                "model_instance_id": "deep-r21d-1",
                "load_time_seconds": 10.81,
            },
        ))
    rows.extend([
        ("prompt_processing.start", {"type": "prompt_processing.start"}),
        ("message.start", {"type": "message.start"}),
        ("message.delta", {"type": "message.delta", "content": "DEEP_SERIAL_OK"}),
        ("message.end", {"type": "message.end"}),
        (
            "chat.end",
            {
                "type": "chat.end",
                "result": {
                    "model_instance_id": chat_end_id,
                    "output": [
                        {"type": "reasoning", "content": "internal"},
                        {"type": "message", "content": "DEEP_SERIAL_OK"},
                    ],
                    "stats": {
                        "input_tokens": 100,
                        "total_output_tokens": 20,
                        "reasoning_output_tokens": 5,
                        "tokens_per_second": 6.9,
                    },
                },
            },
        ),
    ])
    return rows


def test_lmstudio_stream_parser_requires_load_end_and_binds_same_instance(monkeypatch):
    callback = []
    requests = []

    def fake_urlopen(req, timeout):
        requests.append((req, timeout))
        return FakeSseResponse(success_events())

    monkeypatch.setattr(runtime_module, "urlopen", fake_urlopen)
    client = LmStudioClient(timeout=300.0)
    result, meta = client.chat_streaming_jit(
        model="qwen3.6-35b-a3b",
        system_prompt="system",
        input_text="x",
        context_length=4096,
        reasoning="on",
        max_output_tokens=2200,
        temperature=0.15,
        on_model_load_end=lambda instance_id, seconds: callback.append((instance_id, seconds)),
    )
    assert result.text == "DEEP_SERIAL_OK"
    assert result.model_instance_id == "deep-r21d-1"
    assert result.reasoning == "internal"
    assert callback == [("deep-r21d-1", 10.81)]
    assert len(requests) == 1
    req, timeout = requests[0]
    assert timeout == 300.0
    assert req.full_url.endswith("/api/v1/chat")
    request_payload = json.loads(req.data.decode("utf-8"))
    assert request_payload["model"] == "qwen3.6-35b-a3b"
    assert request_payload["context_length"] == 4096
    assert request_payload["reasoning"] == "on"
    assert request_payload["stream"] is True
    assert request_payload["store"] is False
    assert meta["model_load_time_seconds"] == 10.81
    assert meta["event_types"][0] == "chat.start"
    assert meta["event_types"][-1] == "chat.end"


def test_lmstudio_stream_parser_fails_without_model_load_end_after_cold_contract(monkeypatch):
    monkeypatch.setattr(
        runtime_module,
        "urlopen",
        lambda req, timeout: FakeSseResponse(success_events(include_load_end=False)),
    )
    client = LmStudioClient()
    with pytest.raises(LocalModelEndpointError, match="no model_load.end"):
        client.chat_streaming_jit(
            model="qwen3.6-35b-a3b",
            system_prompt="system",
            input_text="x",
            context_length=4096,
            reasoning="on",
            max_output_tokens=2200,
            temperature=0.15,
        )


def test_lmstudio_stream_parser_fails_on_chat_end_instance_mismatch(monkeypatch):
    monkeypatch.setattr(
        runtime_module,
        "urlopen",
        lambda req, timeout: FakeSseResponse(success_events(chat_end_id="deep-other")),
    )
    client = LmStudioClient()
    with pytest.raises(LocalModelEndpointError, match="chat.end instance mismatch"):
        client.chat_streaming_jit(
            model="qwen3.6-35b-a3b",
            system_prompt="system",
            input_text="x",
            context_length=4096,
            reasoning="on",
            max_output_tokens=2200,
            temperature=0.15,
        )
