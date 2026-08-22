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


TIMING_KEYS = {
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


class ReconciledStreamingClient:
    base_url = "http://127.0.0.1:1234"
    load_timeout = 600.0

    def __init__(
        self,
        *,
        path: str = "fallback",
        deep_context: int = 4096,
        deep_id: str = "deep-r21e-1",
        transient_catalog_errors: int = 0,
        duplicate_deep: bool = False,
    ):
        self.fast_loaded = True
        self.deep_ids: list[str] = []
        self.deep_context = deep_context
        self.deep_id = deep_id
        self.path = path
        self.transient_catalog_errors = transient_catalog_errors
        self.duplicate_deep = duplicate_deep
        self.events: list[tuple[object, ...]] = []
        self.explicit_load_calls = 0
        self._stream_active = False

    def models(self):
        if self._stream_active and self.transient_catalog_errors > 0 and self.deep_ids:
            self.transient_catalog_errors -= 1
            raise LocalModelEndpointError(
                "LM Studio/llmster request failed: HTTPError: HTTP Error 500: "
                'Internal Server Error: {"error":{"message":"Model does not exist."}}'
            )
        fast = (
            [{"id": "fast-1", "config": {"context_length": 8192}}]
            if self.fast_loaded
            else []
        )
        deep_ids = list(self.deep_ids)
        if self.duplicate_deep and deep_ids:
            deep_ids.append("deep-r21e-2")
        deep = [
            {"id": value, "config": {"context_length": self.deep_context}}
            for value in deep_ids
        ]
        return [
            {"key": "qwen3.5-4b", "loaded_instances": fast},
            {"key": "qwen3.6-35b-a3b", "loaded_instances": deep},
        ]

    def load(self, *, model, context_length):
        self.explicit_load_calls += 1
        if model == "qwen3.5-4b":
            self.fast_loaded = True
            return "fast-1"
        raise AssertionError("R21E production DEEP path must not call explicit load")

    def load_for_acquisition(self, **kwargs):
        self.explicit_load_calls += 1
        raise AssertionError("R21E production DEEP path must not call load_for_acquisition")

    def unload(self, instance_id):
        self.events.append(("unload", instance_id))
        if instance_id == "fast-1":
            self.fast_loaded = False
            return
        self.deep_ids = [value for value in self.deep_ids if value != instance_id]

    def chat_streaming_jit_reconciled(
        self,
        *,
        on_model_load_end,
        on_residency_reconcile,
        **kwargs,
    ):
        self.events.append(("stream_chat", kwargs["model"], kwargs["context_length"]))
        assert self.deep_ids == []
        self._stream_active = True
        self.deep_ids = [self.deep_id]
        try:
            if self.path == "load_end":
                on_model_load_end(self.deep_id, 10.75)
                signal = "model_load.end"
                event_type = "model_load.end"
                load_seen = True
                load_seconds = 10.75
                events = ("chat.start", "model_load.start", "model_load.end", "message.start", "chat.end")
            else:
                proven = on_residency_reconcile(self.deep_id, "prompt_processing.start")
                assert proven == self.deep_id
                signal = "inference_event_residency"
                event_type = "prompt_processing.start"
                load_seen = False
                load_seconds = None
                events = ("chat.start", "model_load.start", "prompt_processing.start", "message.start", "chat.end")
            return (
                LocalChatResult(
                    text="DEEP_STREAM_OK",
                    model_instance_id=self.deep_id,
                    stats={"tokens_per_second": 7.5, "total_output_tokens": 12},
                    reasoning="internal",
                ),
                {
                    "model_instance_id": self.deep_id,
                    "model_load_time_seconds": load_seconds,
                    "model_load_end_seen": load_seen,
                    "acquisition_signal": signal,
                    "acquisition_event_type": event_type,
                    "event_types": events,
                },
            )
        finally:
            self._stream_active = False


def make_runtime(client: ReconciledStreamingClient) -> SovereignTwinRuntime:
    runtime = object.__new__(SovereignTwinRuntime)
    runtime.client = client
    runtime.profiles = dict(DEFAULT_PROFILES)
    runtime._model_lock = RLock()
    runtime.evidence = lambda query: ()
    return runtime


def test_fallback_reconciles_chat_start_identity_without_second_load():
    client = ReconciledStreamingClient(path="fallback")
    answer = make_runtime(client).ask("x", mode="deep")

    assert answer.text == "DEEP_STREAM_OK"
    assert answer.model == "qwen3.6-35b-a3b"
    assert answer.mode == "deep"
    assert answer.execution_authority == "NONE"
    assert answer.can_execute is False
    assert client.explicit_load_calls == 0
    assert client.events[0] == ("unload", "fast-1")
    assert ("stream_chat", "qwen3.6-35b-a3b", 4096) in client.events
    assert client.events[-1] == ("unload", "deep-r21e-1")
    assert client.fast_loaded is False
    assert client.deep_ids == []
    assert answer.stats["deep_acquisition_signal"] == "inference_event_residency"
    assert answer.stats["deep_acquisition_event_type"] == "prompt_processing.start"
    assert answer.stats["deep_model_load_end_seen"] is False
    assert "deep_jit_load_time_seconds" not in answer.stats
    assert set(answer.stats["deep_phase_timings_ms"]) == TIMING_KEYS


def test_original_model_load_end_path_remains_supported():
    client = ReconciledStreamingClient(path="load_end")
    answer = make_runtime(client).ask("x", mode="deep")
    assert answer.stats["deep_acquisition_signal"] == "model_load.end"
    assert answer.stats["deep_acquisition_event_type"] == "model_load.end"
    assert answer.stats["deep_model_load_end_seen"] is True
    assert answer.stats["deep_jit_load_time_seconds"] == 10.75
    assert client.explicit_load_calls == 0
    assert client.deep_ids == []


def test_fallback_tolerates_transient_catalog_500_then_proves_exact_residency(monkeypatch):
    client = ReconciledStreamingClient(path="fallback", transient_catalog_errors=2)
    clock = {"value": 0.0}

    def fake_perf_counter():
        clock["value"] += 0.05
        return clock["value"]

    monkeypatch.setattr(runtime_module, "perf_counter", fake_perf_counter)
    monkeypatch.setattr(runtime_module, "sleep", lambda seconds: None)
    answer = make_runtime(client).ask("x", mode="deep")
    assert answer.text == "DEEP_STREAM_OK"
    assert answer.stats["deep_acquisition_signal"] == "inference_event_residency"
    assert client.transient_catalog_errors == 0


def test_fallback_wrong_context_fails_closed_and_cleans_up():
    client = ReconciledStreamingClient(path="fallback", deep_context=2048)
    with pytest.raises(LocalModelEndpointError, match="context_length mismatch"):
        make_runtime(client).ask("x", mode="deep")
    assert client.explicit_load_calls == 0
    assert client.deep_ids == []


def test_fallback_duplicate_deep_fails_closed_and_cleans_up():
    client = ReconciledStreamingClient(path="fallback", duplicate_deep=True)
    with pytest.raises(LocalModelEndpointError, match="exactly one resident instance"):
        make_runtime(client).ask("x", mode="deep")
    assert client.deep_ids == []


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


def stream_events(
    *,
    include_load_end: bool,
    chat_end_id: str = "deep-r21e-1",
    load_end_id: str = "deep-r21e-1",
    late_load_end: bool = False,
):
    rows = [
        ("chat.start", {"type": "chat.start", "model_instance_id": "deep-r21e-1"}),
        ("model_load.start", {"type": "model_load.start", "model_instance_id": "deep-r21e-1"}),
    ]
    if include_load_end and not late_load_end:
        rows.append((
            "model_load.end",
            {
                "type": "model_load.end",
                "model_instance_id": load_end_id,
                "load_time_seconds": 10.81,
            },
        ))
    rows.extend([
        ("prompt_processing.start", {"type": "prompt_processing.start"}),
        ("message.start", {"type": "message.start"}),
    ])
    if include_load_end and late_load_end:
        rows.append((
            "model_load.end",
            {
                "type": "model_load.end",
                "model_instance_id": load_end_id,
                "load_time_seconds": 10.81,
            },
        ))
    rows.extend([
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


def call_client(client: LmStudioClient, *, on_reconcile=None, on_load=None):
    return client.chat_streaming_jit_reconciled(
        model="qwen3.6-35b-a3b",
        system_prompt="system",
        input_text="x",
        context_length=4096,
        reasoning="on",
        max_output_tokens=2200,
        temperature=0.15,
        on_model_load_end=on_load,
        on_residency_reconcile=on_reconcile,
    )


def test_parser_fallback_uses_first_inference_event_and_one_chat_request(monkeypatch):
    requests = []
    reconciles = []

    def fake_urlopen(req, timeout):
        requests.append((req, timeout))
        return FakeSseResponse(stream_events(include_load_end=False))

    monkeypatch.setattr(runtime_module, "urlopen", fake_urlopen)

    def reconcile(instance_id, event_type):
        reconciles.append((instance_id, event_type))
        return instance_id

    client = LmStudioClient(timeout=300.0)
    result, meta = call_client(client, on_reconcile=reconcile)
    assert result.text == "DEEP_SERIAL_OK"
    assert result.model_instance_id == "deep-r21e-1"
    assert reconciles == [("deep-r21e-1", "prompt_processing.start")]
    assert len(requests) == 1
    req, timeout = requests[0]
    assert timeout == 300.0
    payload = json.loads(req.data.decode("utf-8"))
    assert payload["model"] == "qwen3.6-35b-a3b"
    assert payload["context_length"] == 4096
    assert payload["reasoning"] == "on"
    assert payload["stream"] is True
    assert payload["store"] is False
    assert meta["model_load_end_seen"] is False
    assert meta["acquisition_signal"] == "inference_event_residency"
    assert meta["acquisition_event_type"] == "prompt_processing.start"
    assert meta["model_load_time_seconds"] is None


def test_parser_without_load_end_or_reconciliation_fails_closed(monkeypatch):
    monkeypatch.setattr(
        runtime_module,
        "urlopen",
        lambda req, timeout: FakeSseResponse(stream_events(include_load_end=False)),
    )
    client = LmStudioClient()
    with pytest.raises(LocalModelEndpointError, match="no exact acquisition proof"):
        call_client(client)


def test_parser_keeps_documented_model_load_end_path(monkeypatch):
    loads = []
    monkeypatch.setattr(
        runtime_module,
        "urlopen",
        lambda req, timeout: FakeSseResponse(stream_events(include_load_end=True)),
    )
    client = LmStudioClient()
    result, meta = call_client(
        client,
        on_reconcile=lambda *_: pytest.fail("fallback must not run"),
        on_load=lambda instance_id, seconds: loads.append((instance_id, seconds)),
    )
    assert result.text == "DEEP_SERIAL_OK"
    assert loads == [("deep-r21e-1", 10.81)]
    assert meta["model_load_end_seen"] is True
    assert meta["acquisition_signal"] == "model_load.end"
    assert meta["model_load_time_seconds"] == 10.81


def test_parser_late_load_end_must_match_reconciled_identity(monkeypatch):
    monkeypatch.setattr(
        runtime_module,
        "urlopen",
        lambda req, timeout: FakeSseResponse(
            stream_events(
                include_load_end=True,
                late_load_end=True,
                load_end_id="deep-other",
            )
        ),
    )
    client = LmStudioClient()
    with pytest.raises(LocalModelEndpointError, match="late model_load.end instance mismatch|model_load.end instance mismatch"):
        call_client(client, on_reconcile=lambda instance_id, event_type: instance_id)


def test_parser_chat_end_identity_mismatch_fails_closed(monkeypatch):
    monkeypatch.setattr(
        runtime_module,
        "urlopen",
        lambda req, timeout: FakeSseResponse(
            stream_events(include_load_end=False, chat_end_id="deep-other")
        ),
    )
    client = LmStudioClient()
    with pytest.raises(LocalModelEndpointError, match="chat.end instance mismatch"):
        call_client(client, on_reconcile=lambda instance_id, event_type: instance_id)


def test_public_overlay_preserves_r21d_nondunder_import_surface():
    missing = [
        name
        for name in vars(runtime_module._r21d)
        if not name.startswith("__") and name not in vars(runtime_module)
    ]
    assert missing == []


def test_retained_r21d_urlopen_monkeypatch_bridge(monkeypatch):
    seen = []

    def fake_urlopen(*args, **kwargs):
        seen.append((args, kwargs))
        return "sentinel"

    monkeypatch.setattr(runtime_module, "urlopen", fake_urlopen)
    assert runtime_module._r21d.urlopen("req", timeout=3.0) == "sentinel"
    assert seen == [(("req",), {"timeout": 3.0})]
