from __future__ import annotations

from threading import RLock
from types import SimpleNamespace

import pytest

import continuityos.sovereign_twin_api as api
import continuityos.sovereign_twin_runtime as runtime_module
import continuityos.sovereign_twin_runtime_r21g as retained_r21g
from continuityos.sovereign_twin_runtime import (
    DEFAULT_PROFILES,
    LocalChatResult,
    LocalModelEndpointError,
    SovereignTwinRuntime,
    _FastResidencyUnsafeError,
)

FAST = DEFAULT_PROFILES["fast"]


@pytest.fixture(autouse=True)
def reset_r21h_process_startup_prewarm_guard(monkeypatch):
    """Keep process-once production state isolated between pytest cases."""
    monkeypatch.setattr(api, "_R21H_STARTUP_PREWARM_STATE", "NOT_STARTED")
    monkeypatch.setattr(api, "_R21H_STARTUP_PREWARM_RESULT", None)
    monkeypatch.setattr(api, "_R21H_STARTUP_PREWARM_ERROR", None)


def model_row(instances):
    return [{"key": FAST.model, "loaded_instances": instances}]


def instance(i="fast-1", ctx=8192):
    return {"id": i, "config": {"context_length": ctx, "parallel": 1}}


class FakeClient:
    def __init__(self, states):
        self.states = list(states)
        self.stream_calls = []
        self.explicit_load_calls = []
        self.chat_calls = []
        self.embedding_calls = []
        self.events = []

    def models(self):
        self.events.append("models")
        value = self.states.pop(0) if len(self.states) > 1 else self.states[0]
        if isinstance(value, BaseException):
            raise value
        return value

    def embed(self, text, *, model, task):
        self.events.append("embed")
        self.embedding_calls.append({"text": text, "model": model, "task": task})
        return [0.1, 0.2, 0.3]

    def load_fast_for_acquisition(self, **kwargs):
        self.explicit_load_calls.append(kwargs)
        raise AssertionError("R21H must never explicitly load FAST")

    def chat(self, **kwargs):
        self.chat_calls.append(kwargs)
        raise AssertionError("cold startup prewarm must use R21G streaming JIT")

    def chat_fast_streaming_jit_reconciled(self, **kwargs):
        self.events.append("stream")
        self.stream_calls.append(kwargs)
        iid = "fast-1"
        kwargs["on_model_load_end"](iid, 42.0)
        return (
            LocalChatResult(
                text="FAST_PREWARM_OK",
                model_instance_id=iid,
                stats={},
                reasoning=None,
            ),
            {
                "model_instance_id": iid,
                "model_load_time_seconds": 42.0,
                "model_load_end_seen": True,
                "acquisition_signal": "model_load.end",
                "acquisition_event_type": "model_load.end",
                "event_types": (
                    "chat.start",
                    "model_load.end",
                    "message.delta",
                    "chat.end",
                ),
            },
        )


def runtime_with(client):
    rt = SovereignTwinRuntime.__new__(SovereignTwinRuntime)
    rt.client = client
    rt.profiles = dict(DEFAULT_PROFILES)
    rt.embedding_model = runtime_module.DEFAULT_EMBEDDING_MODEL
    rt.recall_k = 8
    rt.memory_db = "test.db"
    rt._model_lock = RLock()
    rt.evidence = lambda query: (_ for _ in ()).throw(
        AssertionError("startup prewarm must not retrieve memory evidence")
    )
    return rt


def request_runtime_with(client, *, events):
    rt = SovereignTwinRuntime.__new__(SovereignTwinRuntime)
    rt.client = client
    rt.profiles = dict(DEFAULT_PROFILES)
    rt.embedding_model = runtime_module.DEFAULT_EMBEDDING_MODEL
    rt.recall_k = 8
    rt.memory_db = "test.db"
    rt._model_lock = RLock()

    def evidence(query):
        events.append("evidence")
        return ()

    rt.evidence = evidence
    return rt


def test_cold_startup_embedding_readiness_precedes_final_fast_stream_and_zero_explicit_loads():
    c = FakeClient(
        [
            model_row([]),
            model_row([]),
            model_row([instance()]),
            model_row([instance()]),
            model_row([instance()]),
        ]
    )
    result = runtime_with(c).prewarm_fast_startup()

    assert result["ok"] is True
    assert result["already_resident"] is False
    assert result["embedding_readiness_performed"] is True
    assert result["embedding_dimensions"] == 3
    assert result["model_instance_id"] == "fast-1"
    assert result["acquisition_signal"] == "model_load.end"
    assert result["model_load_end_seen"] is True
    assert result["jit_load_time_seconds"] == 42.0
    assert len(c.embedding_calls) == 1
    assert len(c.stream_calls) == 1
    assert c.explicit_load_calls == []
    assert c.chat_calls == []
    assert c.events[:4] == ["models", "embed", "models", "stream"]
    assert c.embedding_calls[0]["text"] == runtime_module.EMBEDDING_STARTUP_READINESS_QUERY
    assert c.embedding_calls[0]["model"] == runtime_module.DEFAULT_EMBEDDING_MODEL
    assert c.embedding_calls[0]["task"] == runtime_module.NOMIC_QUERY_TASK
    assert c.stream_calls[0]["input_text"] == runtime_module.FAST_STARTUP_PREWARM_QUERY
    assert c.stream_calls[0]["context_length"] == 8192
    assert c.stream_calls[0]["reasoning"] == "off"


def test_already_resident_startup_prewarm_is_zero_call_noop():
    c = FakeClient([model_row([instance()])])
    result = runtime_with(c).prewarm_fast_startup()

    assert result["already_resident"] is True
    assert result["embedding_readiness_performed"] is False
    assert result["model_instance_id"] == "fast-1"
    assert result["acquisition_signal"] == "already_resident"
    assert c.embedding_calls == []
    assert c.stream_calls == []
    assert c.explicit_load_calls == []
    assert c.chat_calls == []


def test_startup_prewarm_refuses_missing_stream_transport_instead_of_fallback():
    c = FakeClient([model_row([])])
    c.chat_fast_streaming_jit_reconciled = None

    with pytest.raises(LocalModelEndpointError, match="streaming-JIT"):
        runtime_with(c).prewarm_fast_startup()

    assert len(c.embedding_calls) == 1
    assert c.explicit_load_calls == []
    assert c.chat_calls == []


def test_startup_prewarm_wrong_context_fails_before_embedding_or_stream():
    c = FakeClient([model_row([instance(ctx=4096)])])

    with pytest.raises(_FastResidencyUnsafeError, match="context_length mismatch"):
        runtime_with(c).prewarm_fast_startup()

    assert c.embedding_calls == []
    assert c.stream_calls == []
    assert c.explicit_load_calls == []


class RequestClient:
    def __init__(self, states, *, events):
        self.states = list(states)
        self.events = events
        self.stream_calls = []
        self.explicit_load_calls = []
        self.chat_calls = []

    def models(self):
        self.events.append("models")
        value = self.states.pop(0) if len(self.states) > 1 else self.states[0]
        if isinstance(value, BaseException):
            raise value
        return value

    def load_fast_for_acquisition(self, **kwargs):
        self.events.append("explicit_load")
        self.explicit_load_calls.append(kwargs)
        raise AssertionError("R21H production FAST path must never explicitly load FAST")

    def chat_fast_streaming_jit_reconciled(self, **kwargs):
        self.events.append("stream")
        self.stream_calls.append(kwargs)
        iid = "fast-1"
        kwargs["on_model_load_end"](iid, 0.5)
        return (
            LocalChatResult(
                text="stream answer",
                model_instance_id=iid,
                stats={},
                reasoning=None,
            ),
            {
                "model_instance_id": iid,
                "model_load_time_seconds": 0.5,
                "model_load_end_seen": True,
                "acquisition_signal": "model_load.end",
                "acquisition_event_type": "model_load.end",
                "event_types": (
                    "chat.start",
                    "model_load.end",
                    "message.delta",
                    "chat.end",
                ),
            },
        )

    def chat(self, **kwargs):
        self.events.append("chat")
        self.chat_calls.append(kwargs)
        return LocalChatResult(
            text="warm answer",
            model_instance_id="fast-1",
            stats={"tokens": 1},
            reasoning=None,
        )


def test_fast_request_evidence_first_reprobes_and_stream_reacquires_after_embedding_eviction():
    events = []
    c = RequestClient(
        [
            model_row([]),
            model_row([instance()]),
            model_row([instance()]),
        ],
        events=events,
    )
    rt = request_runtime_with(c, events=events)

    answer = rt.ask("hello", mode="fast")

    assert answer.text == "stream answer"
    assert answer.mode == "fast"
    assert events[:3] == ["evidence", "models", "stream"]
    assert len(c.stream_calls) == 1
    assert c.chat_calls == []
    assert c.explicit_load_calls == []


def test_fast_request_evidence_first_then_exact_resident_uses_ordinary_chat():
    events = []
    c = RequestClient([model_row([instance()])], events=events)
    rt = request_runtime_with(c, events=events)

    answer = rt.ask("hello", mode="fast")

    assert answer.text == "warm answer"
    assert answer.mode == "fast"
    assert events == ["evidence", "models", "chat"]
    assert c.stream_calls == []
    assert len(c.chat_calls) == 1
    assert c.explicit_load_calls == []


def test_fast_request_refuses_explicit_loader_when_stream_transport_missing_after_evidence():
    events = []
    c = RequestClient([model_row([])], events=events)
    c.chat_fast_streaming_jit_reconciled = None
    rt = request_runtime_with(c, events=events)

    with pytest.raises(LocalModelEndpointError, match="streaming-JIT"):
        rt.ask("hello", mode="fast")

    assert events == ["evidence", "models"]
    assert c.explicit_load_calls == []
    assert c.chat_calls == []


def test_r21h_overrides_fast_ask_but_preserves_deep_behavior():
    assert SovereignTwinRuntime.ask is not retained_r21g.SovereignTwinRuntime.ask
    assert SovereignTwinRuntime._ask_deep is retained_r21g.SovereignTwinRuntime._ask_deep


def test_api_prewarm_occurs_before_socket_construction(monkeypatch):
    events = []

    class FakeRuntime:
        def __init__(self, *args, **kwargs):
            events.append("runtime")
            self.memory_db = "C:/memory.db"

        def prewarm_fast_startup(self):
            events.append("prewarm")
            return {"ok": True, "model_instance_id": "fast-1"}

        def close(self):
            events.append("runtime.close")

    class FakeServer:
        def __init__(self, address, handler):
            events.append("server.bind")
            self.address = address
            self.handler = handler

        def serve_forever(self):
            events.append("serve")

        def server_close(self):
            events.append("server.close")

    monkeypatch.setattr(api, "SovereignTwinRuntime", FakeRuntime)
    monkeypatch.setattr(api, "LmStudioClient", lambda base_url: object())
    monkeypatch.setattr(api._r21g_api, "_TwinServer", FakeServer)
    monkeypatch.setattr(
        api._r21g_api,
        "ShadowMemoryAdmissionQueue",
        lambda path: SimpleNamespace(path=path),
    )

    api.serve(memory_db="C:/memory.db")

    assert events == [
        "runtime",
        "prewarm",
        "server.bind",
        "serve",
        "server.close",
        "runtime.close",
    ]


def test_api_prewarm_runs_at_most_once_per_process(monkeypatch):
    events = []
    startup_results = []

    class FakeRuntime:
        def __init__(self, *args, **kwargs):
            events.append("runtime")
            self.memory_db = "C:/memory.db"
            self.profiles = dict(DEFAULT_PROFILES)

        def prewarm_fast_startup(self):
            events.append("prewarm")
            return {"ok": True, "model_instance_id": "fast-1"}

        def _probe_exact_fast_residency(self, profile, *, expected_id=None):
            events.append("revalidate")
            assert profile.model == DEFAULT_PROFILES["fast"].model
            assert profile.context_length == DEFAULT_PROFILES["fast"].context_length
            assert expected_id == "fast-1"
            return expected_id

        def close(self):
            events.append("runtime.close")

    class FakeServer:
        def __init__(self, address, handler):
            events.append("server.bind")

        def serve_forever(self):
            startup_results.append(dict(self.startup_prewarm))
            events.append("serve")

        def server_close(self):
            events.append("server.close")

    monkeypatch.setattr(api, "SovereignTwinRuntime", FakeRuntime)
    monkeypatch.setattr(api, "LmStudioClient", lambda base_url: object())
    monkeypatch.setattr(api._r21g_api, "_TwinServer", FakeServer)
    monkeypatch.setattr(
        api._r21g_api,
        "ShadowMemoryAdmissionQueue",
        lambda path: SimpleNamespace(path=path),
    )

    api.serve(memory_db="C:/memory.db")
    api.serve(memory_db="C:/memory.db")

    assert events.count("prewarm") == 1
    assert events.count("revalidate") == 1
    assert events.count("server.bind") == 2
    assert events.count("serve") == 2
    assert startup_results == [
        {"ok": True, "model_instance_id": "fast-1"},
        {"ok": True, "model_instance_id": "fast-1"},
    ]


def test_api_prewarm_failure_prevents_socket_bind_and_closes_runtime(monkeypatch):
    events = []

    class FakeRuntime:
        def __init__(self, *args, **kwargs):
            events.append("runtime")

        def prewarm_fast_startup(self):
            events.append("prewarm")
            raise LocalModelEndpointError("prewarm failed")

        def close(self):
            events.append("runtime.close")

    def fail_server(*args, **kwargs):
        raise AssertionError("socket must not bind after failed startup prewarm")

    monkeypatch.setattr(api, "SovereignTwinRuntime", FakeRuntime)
    monkeypatch.setattr(api, "LmStudioClient", lambda base_url: object())
    monkeypatch.setattr(api._r21g_api, "_TwinServer", fail_server)

    with pytest.raises(LocalModelEndpointError, match="prewarm failed"):
        api.serve(memory_db="C:/memory.db")
    with pytest.raises(LocalModelEndpointError, match="retry refused"):
        api.serve(memory_db="C:/memory.db")

    assert events == [
        "runtime",
        "prewarm",
        "runtime.close",
        "runtime",
        "runtime.close",
    ]


def test_api_explicit_prewarm_disable_preserves_r21g_startup_shape(monkeypatch):
    events = []

    class FakeRuntime:
        def __init__(self, *args, **kwargs):
            events.append("runtime")

        def prewarm_fast_startup(self):
            raise AssertionError("prewarm explicitly disabled")

        def close(self):
            events.append("runtime.close")

    class FakeServer:
        def __init__(self, address, handler):
            events.append("server.bind")

        def serve_forever(self):
            events.append("serve")

        def server_close(self):
            events.append("server.close")

    monkeypatch.setattr(api, "SovereignTwinRuntime", FakeRuntime)
    monkeypatch.setattr(api, "LmStudioClient", lambda base_url: object())
    monkeypatch.setattr(api._r21g_api, "_TwinServer", FakeServer)
    monkeypatch.setattr(
        api._r21g_api,
        "ShadowMemoryAdmissionQueue",
        lambda path: SimpleNamespace(path=path),
    )

    api.serve(memory_db="C:/memory.db", fast_startup_prewarm=False)

    assert events == [
        "runtime",
        "server.bind",
        "serve",
        "server.close",
        "runtime.close",
    ]
