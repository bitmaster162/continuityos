from __future__ import annotations

import json

import pytest

import continuityos.sovereign_twin_runtime as runtime_module
import continuityos.sovereign_twin_runtime_r21f as retained_r21f
from continuityos.sovereign_twin_runtime import (
    DEFAULT_PROFILES,
    LmStudioClient,
    LocalChatResult,
    LocalModelEndpointError,
    SovereignTwinRuntime,
    _FastResidencyUnsafeError,
)

FAST = DEFAULT_PROFILES["fast"]


def model_row(instances):
    return [{"key": FAST.model, "loaded_instances": instances}]


def instance(i="fast-1", ctx=8192):
    return {"id": i, "config": {"context_length": ctx, "parallel": 1}}


class FakeClient:
    def __init__(self, states, *, mode="load_end", legacy=False):
        self.states = list(states)
        self.mode = mode
        self.stream_calls = []
        self.load_calls = []
        self.chat_calls = []
        if legacy:
            self.chat_fast_streaming_jit_reconciled = None

    def models(self):
        value = self.states.pop(0) if len(self.states) > 1 else self.states[0]
        if isinstance(value, BaseException):
            raise value
        return value

    def load_fast_for_acquisition(self, **kwargs):
        self.load_calls.append(kwargs)
        raise AssertionError("R21G cold production path must not explicitly load FAST")

    def chat(self, **kwargs):
        self.chat_calls.append(kwargs)
        return LocalChatResult(
            text="WARM_OK",
            model_instance_id="fast-1",
            stats={},
            reasoning=None,
        )

    def chat_fast_streaming_jit_reconciled(self, **kwargs):
        self.stream_calls.append(kwargs)
        iid = "fast-1"
        if self.mode == "load_end":
            kwargs["on_model_load_end"](iid, 42.0)
            metadata = {
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
            }
        elif self.mode == "fallback":
            proven = kwargs["on_residency_reconcile"](iid, "message.delta")
            assert proven == iid
            metadata = {
                "model_instance_id": iid,
                "model_load_time_seconds": None,
                "model_load_end_seen": False,
                "acquisition_signal": "inference_event_residency",
                "acquisition_event_type": "message.delta",
                "event_types": ("chat.start", "message.delta", "chat.end"),
            }
        else:
            raise AssertionError(self.mode)
        return (
            LocalChatResult(
                text="FAST_OK",
                model_instance_id=iid,
                stats={"tokens": 1},
                reasoning=None,
            ),
            metadata,
        )


def runtime_with(client):
    rt = SovereignTwinRuntime.__new__(SovereignTwinRuntime)
    rt.client = client
    rt.profiles = dict(DEFAULT_PROFILES)
    rt.embedding_model = runtime_module.DEFAULT_EMBEDDING_MODEL
    rt.recall_k = 8
    rt.memory_db = "test.db"
    rt.evidence = lambda query: ()
    from threading import RLock

    rt._model_lock = RLock()
    return rt


def test_cold_fast_model_load_end_uses_one_stream_and_zero_explicit_loads():
    c = FakeClient(
        [
            model_row([]),
            model_row([instance()]),
            model_row([instance()]),
        ],
        mode="load_end",
    )
    answer = runtime_with(c).ask("q", mode="fast")

    assert answer.text == "FAST_OK"
    assert len(c.stream_calls) == 1
    assert c.load_calls == []
    assert c.chat_calls == []
    assert answer.stats["fast_acquisition_signal"] == "model_load.end"
    assert answer.stats["fast_model_load_end_seen"] is True
    assert answer.stats["fast_jit_load_time_seconds"] == 42.0


def test_cold_fast_fallback_uses_one_stream_and_zero_explicit_loads():
    c = FakeClient(
        [
            model_row([]),
            model_row([instance()]),
            model_row([instance()]),
        ],
        mode="fallback",
    )
    answer = runtime_with(c).ask("q", mode="fast")

    assert answer.text == "FAST_OK"
    assert len(c.stream_calls) == 1
    assert c.load_calls == []
    assert c.chat_calls == []
    assert answer.stats["fast_acquisition_signal"] == "inference_event_residency"
    assert answer.stats["fast_acquisition_event_type"] == "message.delta"
    assert answer.stats["fast_model_load_end_seen"] is False


def test_warm_fast_preserves_inherited_resident_chat_behavior():
    c = FakeClient([model_row([instance()]), model_row([instance()])])
    answer = runtime_with(c).ask("q", mode="fast")

    assert answer.text == "WARM_OK"
    assert c.stream_calls == []
    assert c.load_calls == []
    assert len(c.chat_calls) == 1


def test_legacy_client_without_r21g_stream_method_preserves_r21f_fallback():
    class LegacyClient(FakeClient):
        def __init__(self):
            super().__init__([model_row([])], legacy=True)
            self.load_fast_for_acquisition = None

        def load(self, **kwargs):
            self.load_calls.append(kwargs)
            return "legacy-fast"

    c = LegacyClient()
    rt = runtime_with(c)
    # The retained R21F/base path will ask for residency again; provide the
    # resulting exact warm row for the inherited post-load behavior.
    c.states = [model_row([]), model_row([instance("legacy-fast")])]
    answer = rt.ask("q", mode="fast")
    assert answer.text == "WARM_OK"
    assert c.stream_calls == []


def test_wrong_context_fails_closed_before_stream():
    c = FakeClient([model_row([instance(ctx=4096)])])
    with pytest.raises(_FastResidencyUnsafeError, match="context_length mismatch"):
        runtime_with(c).ask("q", mode="fast")
    assert c.stream_calls == []
    assert c.load_calls == []


def test_duplicate_fast_fails_closed_before_stream():
    c = FakeClient([model_row([instance("a"), instance("b")])])
    with pytest.raises(_FastResidencyUnsafeError, match="exactly one"):
        runtime_with(c).ask("q", mode="fast")
    assert c.stream_calls == []
    assert c.load_calls == []


class FakeResponse:
    def __init__(self, lines):
        self.lines = lines

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def __iter__(self):
        return iter(self.lines)


def sse(event, data):
    return [
        f"event: {event}\n".encode(),
        f"data: {json.dumps(data)}\n".encode(),
        b"\n",
    ]


def final_payload(iid="fast-1"):
    return {
        "model_instance_id": iid,
        "stats": {"x": 1},
        "output": [{"type": "message", "content": "OK"}],
    }


def run_transport(monkeypatch, events, *, reconcile=None, onload=None):
    payload = []
    for event, data in events:
        payload.extend(sse(event, data))
    monkeypatch.setattr(
        runtime_module,
        "urlopen",
        lambda req, timeout=None: FakeResponse(payload),
    )
    client = LmStudioClient()
    return client.chat_fast_streaming_jit_reconciled(
        model=FAST.model,
        system_prompt="s",
        input_text="q",
        context_length=8192,
        reasoning="off",
        max_output_tokens=1200,
        temperature=0.2,
        on_model_load_end=onload,
        on_residency_reconcile=reconcile,
    )


def test_transport_model_load_end_identity(monkeypatch):
    seen = []
    result, metadata = run_transport(
        monkeypatch,
        [
            ("chat.start", {"type": "chat.start", "model_instance_id": "fast-1"}),
            (
                "model_load.end",
                {
                    "type": "model_load.end",
                    "model_instance_id": "fast-1",
                    "load_time_seconds": 5,
                },
            ),
            ("chat.end", {"type": "chat.end", "result": final_payload()}),
        ],
        onload=lambda iid, seconds: seen.append((iid, seconds)),
    )
    assert result.text == "OK"
    assert metadata["model_instance_id"] == "fast-1"
    assert metadata["acquisition_signal"] == "model_load.end"
    assert seen == [("fast-1", 5.0)]


def test_transport_residency_fallback_identity(monkeypatch):
    result, metadata = run_transport(
        monkeypatch,
        [
            ("chat.start", {"type": "chat.start", "model_instance_id": "fast-1"}),
            ("message.delta", {"type": "message.delta", "content": "x"}),
            ("chat.end", {"type": "chat.end", "result": final_payload()}),
        ],
        reconcile=lambda iid, event_type: iid,
    )
    assert result.text == "OK"
    assert metadata["acquisition_signal"] == "inference_event_residency"
    assert metadata["acquisition_event_type"] == "message.delta"


def test_transport_late_model_load_end_identity_mismatch_fails(monkeypatch):
    with pytest.raises(LocalModelEndpointError, match="instance mismatch"):
        run_transport(
            monkeypatch,
            [
                ("chat.start", {"type": "chat.start", "model_instance_id": "fast-1"}),
                ("message.delta", {"type": "message.delta", "content": "x"}),
                (
                    "model_load.end",
                    {
                        "type": "model_load.end",
                        "model_instance_id": "other",
                        "load_time_seconds": 5,
                    },
                ),
                ("chat.end", {"type": "chat.end", "result": final_payload()}),
            ],
            reconcile=lambda iid, event_type: iid,
        )


def test_transport_chat_end_identity_mismatch_fails(monkeypatch):
    with pytest.raises(LocalModelEndpointError, match="chat.end instance mismatch"):
        run_transport(
            monkeypatch,
            [
                ("chat.start", {"type": "chat.start", "model_instance_id": "fast-1"}),
                (
                    "model_load.end",
                    {
                        "type": "model_load.end",
                        "model_instance_id": "fast-1",
                        "load_time_seconds": 5,
                    },
                ),
                (
                    "chat.end",
                    {"type": "chat.end", "result": final_payload("other")},
                ),
            ],
            onload=lambda iid, seconds: None,
        )


def test_r21f_retained_surface_and_deep_behavior_unchanged():
    assert (
        SovereignTwinRuntime._ask_deep
        is retained_r21f.SovereignTwinRuntime._ask_deep
    )
    assert hasattr(retained_r21f.LmStudioClient, "load_fast_for_acquisition")


def test_default_fast_profile_unchanged():
    assert FAST.model == "qwen3.5-4b"
    assert FAST.context_length == 8192
    assert FAST.reasoning == "off"
    assert FAST.max_output_tokens == 1200
    assert FAST.temperature == 0.2
    assert FAST.unload_after_answer is False
