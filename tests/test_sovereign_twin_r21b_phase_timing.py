from __future__ import annotations

from threading import RLock

import continuityos.sovereign_twin_runtime as runtime_module
from continuityos.sovereign_twin_runtime import (
    DEFAULT_PROFILES,
    LocalChatResult,
    SovereignTwinRuntime,
)


class StepClock:
    def __init__(self, step: float = 0.001):
        self.value = 0.0
        self.step = step
        self.calls = 0

    def __call__(self) -> float:
        current = self.value
        self.value += self.step
        self.calls += 1
        return current


class Client:
    base_url = "http://127.0.0.1:1234"

    def __init__(self, *, fast_loaded: bool = True):
        self.fast_loaded = fast_loaded
        self.deep_loaded = False
        self.events: list[tuple[object, ...]] = []

    def models(self):
        fast = []
        if self.fast_loaded:
            fast = [{"id": "fast-1", "config": {"context_length": 8192}}]
        deep = []
        if self.deep_loaded:
            deep = [{"id": "deep-1", "config": {"context_length": 4096}}]
        return [
            {"key": "qwen3.5-4b", "loaded_instances": fast},
            {"key": "qwen3.6-35b-a3b", "loaded_instances": deep},
        ]

    def load(self, *, model, context_length):
        self.events.append(("load", model, context_length))
        if model == "qwen3.5-4b":
            self.fast_loaded = True
            return "fast-1"
        self.deep_loaded = True
        return "deep-1"

    def unload(self, instance_id):
        self.events.append(("unload", instance_id))
        if instance_id == "fast-1":
            self.fast_loaded = False
        if instance_id == "deep-1":
            self.deep_loaded = False

    def chat(self, **kwargs):
        self.events.append(("chat", kwargs["model"], kwargs["context_length"]))
        is_deep = kwargs["model"] == "qwen3.6-35b-a3b"
        return LocalChatResult(
            text="DEEP_OK" if is_deep else "FAST_OK",
            model_instance_id="deep-1" if is_deep else "fast-1",
            stats={"total_output_tokens": 7, "tokens_per_second": 6.9},
            reasoning="internal" if is_deep else None,
        )


def make_runtime(client: Client) -> SovereignTwinRuntime:
    runtime = object.__new__(SovereignTwinRuntime)
    runtime.client = client
    runtime.profiles = dict(DEFAULT_PROFILES)
    runtime._model_lock = RLock()
    runtime.evidence = lambda query: ()
    return runtime


def test_native_deep_success_reports_complete_phase_timings(monkeypatch):
    clock = StepClock()
    monkeypatch.setattr(runtime_module, "perf_counter", clock)
    client = Client()

    answer = make_runtime(client).ask("x", mode="deep")

    assert answer.text == "DEEP_OK"
    assert answer.stats["total_output_tokens"] == 7
    assert answer.stats["tokens_per_second"] == 6.9
    timings = answer.stats["deep_phase_timings_ms"]
    assert set(timings) == {
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
    for key in set(timings) - {"total_request"}:
        assert timings[key] == 1.0
    assert timings["total_request"] == 18.0
    assert clock.calls == 19
    assert client.events == [
        ("unload", "fast-1"),
        ("load", "qwen3.6-35b-a3b", 4096),
        ("chat", "qwen3.6-35b-a3b", 4096),
        ("unload", "deep-1"),
    ]
    assert client.fast_loaded is False
    assert client.deep_loaded is False


def test_fast_mode_does_not_touch_phase_clock_or_stats(monkeypatch):
    def forbidden_clock():
        raise AssertionError("FAST must not invoke R21B phase timing clock")

    monkeypatch.setattr(runtime_module, "perf_counter", forbidden_clock)
    client = Client(fast_loaded=True)

    answer = make_runtime(client).ask("x", mode="fast")

    assert answer.text == "FAST_OK"
    assert answer.stats == {"total_output_tokens": 7, "tokens_per_second": 6.9}
    assert "deep_phase_timings_ms" not in answer.stats
    assert client.fast_loaded is True
    assert client.deep_loaded is False


def test_deep_profile_and_authority_contract_are_unchanged(monkeypatch):
    clock = StepClock()
    monkeypatch.setattr(runtime_module, "perf_counter", clock)
    client = Client()

    answer = make_runtime(client).ask("x", mode="deep")

    assert answer.execution_authority == "NONE"
    assert answer.can_execute is False
    assert answer.model == "qwen3.6-35b-a3b"
    assert answer.mode == "deep"
    assert answer.reasoning_present is True
    assert DEFAULT_PROFILES["deep"].context_length == 4096
    assert DEFAULT_PROFILES["deep"].reasoning == "on"
    assert DEFAULT_PROFILES["deep"].max_output_tokens == 2200
    assert DEFAULT_PROFILES["deep"].temperature == 0.15
