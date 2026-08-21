from __future__ import annotations

from threading import RLock
from urllib.error import HTTPError

import pytest

import continuityos.sovereign_twin_runtime as runtime_module
from continuityos.sovereign_twin_runtime import (
    DEFAULT_PROFILES,
    DEEP_CAPACITY_BLOCKED_MESSAGE,
    DEEP_LOAD_ACK_TIMEOUT_SECONDS,
    DeepCapacityBlockedError,
    LmStudioClient,
    LocalChatResult,
    LocalModelEndpointError,
    SovereignTwinRuntime,
)



class Client:
    base_url = "http://127.0.0.1:1234"
    load_timeout = 600.0

    def __init__(
        self,
        *,
        outcome: str = "timeout_resident",
        deep_context: int = 4096,
    ):
        self.outcome = outcome
        self.deep_context = deep_context
        self.fast_loaded = True
        self.deep_ids: list[str] = []
        self.events: list[tuple[object, ...]] = []
        self.after_timeout = False
        self.transient_reads = 0

    def models(self):
        if self.after_timeout and self.outcome == "timeout_transient_then_resident":
            if self.transient_reads == 0:
                self.transient_reads += 1
                raise LocalModelEndpointError(
                    "LM Studio/llmster request failed: HTTPError: HTTP Error 500: "
                    "Internal Server Error: Model does not exist."
                )
            self.deep_ids = ["deep-r21c-1"]
            self.after_timeout = False

        fast = []
        if self.fast_loaded:
            fast = [{"id": "fast-1", "config": {"context_length": 8192}}]
        deep = [
            {"id": value, "config": {"context_length": self.deep_context}}
            for value in self.deep_ids
        ]
        return [
            {"key": "qwen3.5-4b", "loaded_instances": fast},
            {"key": "qwen3.6-35b-a3b", "loaded_instances": deep},
        ]

    def load(self, *, model, context_length):
        self.events.append(("legacy_load", model, context_length))
        if model == "qwen3.5-4b":
            self.fast_loaded = True
            return "fast-1"
        raise AssertionError("R21C native DEEP must not use a second/legacy load path")

    def load_for_acquisition(self, *, model, context_length, ack_timeout):
        self.events.append(("load_for_acquisition", model, context_length, ack_timeout))
        assert model == "qwen3.6-35b-a3b"
        assert context_length == 4096

        if self.outcome == "ack_success":
            self.deep_ids = ["deep-r21c-1"]
            return "deep-r21c-1"

        if self.outcome == "timeout_resident":
            self.deep_ids = ["deep-r21c-1"]
            self._raise_timeout()

        if self.outcome == "timeout_transient_then_resident":
            self.after_timeout = True
            self._raise_timeout()

        if self.outcome == "timeout_duplicate":
            self.deep_ids = ["deep-r21c-1", "deep-r21c-2"]
            self._raise_timeout()

        if self.outcome == "timeout_wrong_context":
            self.deep_ids = ["deep-r21c-1"]
            self._raise_timeout()

        if self.outcome == "http_error_resident":
            self.deep_ids = ["deep-r21c-1"]
            http = HTTPError(
                "http://127.0.0.1:1234/api/v1/models/load",
                500,
                "Internal Server Error",
                None,
                None,
            )
            raise LocalModelEndpointError(
                "LM Studio model load failed with load_ack_timeout=20s: "
                "LM Studio/llmster request failed: HTTPError: HTTP Error 500: "
                "Internal Server Error"
            ) from http

        if self.outcome == "capacity":
            self.deep_ids = ["deep-r21c-1"]
            raise LocalModelEndpointError(
                "LM Studio model load failed: insufficient system resources"
            )

        raise AssertionError(self.outcome)

    @staticmethod
    def _raise_timeout():
        try:
            raise TimeoutError("timed out")
        except TimeoutError as cause:
            raise LocalModelEndpointError(
                "LM Studio model load failed with load_ack_timeout=20s: "
                "LM Studio/llmster request failed: TimeoutError: timed out"
            ) from cause

    def unload(self, instance_id):
        self.events.append(("unload", instance_id))
        if instance_id == "fast-1":
            self.fast_loaded = False
        if instance_id.startswith("deep"):
            self.deep_ids = [value for value in self.deep_ids if value != instance_id]

    def chat(self, **kwargs):
        self.events.append(("chat", kwargs["model"], kwargs["context_length"]))
        return LocalChatResult(
            text="DEEP_OK",
            model_instance_id="deep-r21c-1",
            stats={"tokens_per_second": 7.0},
            reasoning="internal",
        )


def make_runtime(client: Client) -> SovereignTwinRuntime:
    runtime = object.__new__(SovereignTwinRuntime)
    runtime.client = client
    runtime.profiles = dict(DEFAULT_PROFILES)
    runtime._model_lock = RLock()
    runtime.evidence = lambda query: ()
    return runtime


def chats(client: Client):
    return [event for event in client.events if event[0] == "chat"]


def test_ack_timeout_accepts_only_exact_proven_residency_then_chats_and_unloads():
    client = Client(outcome="timeout_resident")
    answer = make_runtime(client).ask("x", mode="deep")

    assert answer.text == "DEEP_OK"
    assert answer.execution_authority == "NONE"
    assert answer.can_execute is False
    assert client.events[0] == ("unload", "fast-1")
    assert client.events[1] == (
        "load_for_acquisition",
        "qwen3.6-35b-a3b",
        4096,
        DEEP_LOAD_ACK_TIMEOUT_SECONDS,
    )
    assert not any(event[0] == "legacy_load" and event[1] == "qwen3.6-35b-a3b" for event in client.events)
    assert ("chat", "qwen3.6-35b-a3b", 4096) in client.events
    assert client.events[-1] == ("unload", "deep-r21c-1")
    assert client.fast_loaded is False
    assert client.deep_ids == []
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


def test_transient_catalog_error_after_ack_timeout_is_retried_until_exact_residency(monkeypatch):
    monkeypatch.setattr(runtime_module, "sleep", lambda _: None)
    client = Client(outcome="timeout_transient_then_resident")

    answer = make_runtime(client).ask("x", mode="deep")

    assert answer.text == "DEEP_OK"
    assert client.transient_reads == 1
    assert len([event for event in client.events if event[0] == "load_for_acquisition"]) == 1
    assert chats(client) == [("chat", "qwen3.6-35b-a3b", 4096)]
    assert client.deep_ids == []


def test_http_error_never_uses_residency_fallback_and_cleans_any_resident_deep():
    client = Client(outcome="http_error_resident")
    with pytest.raises(LocalModelEndpointError, match="DEEP explicit load failed before chat"):
        make_runtime(client).ask("x", mode="deep")
    assert chats(client) == []
    assert client.deep_ids == []
    assert len([event for event in client.events if event[0] == "load_for_acquisition"]) == 1


def test_capacity_error_remains_blocked_and_cleans_any_resident_deep():
    client = Client(outcome="capacity")
    with pytest.raises(DeepCapacityBlockedError) as exc:
        make_runtime(client).ask("x", mode="deep")
    assert str(exc.value) == DEEP_CAPACITY_BLOCKED_MESSAGE
    assert chats(client) == []
    assert client.deep_ids == []


def test_duplicate_deep_after_ack_timeout_fails_closed_and_cleans_all():
    client = Client(outcome="timeout_duplicate")
    with pytest.raises(LocalModelEndpointError, match="exactly one"):
        make_runtime(client).ask("x", mode="deep")
    assert chats(client) == []
    assert client.deep_ids == []


def test_wrong_context_after_ack_timeout_fails_closed_and_cleans():
    client = Client(outcome="timeout_wrong_context", deep_context=2048)
    with pytest.raises(LocalModelEndpointError, match="context_length mismatch"):
        make_runtime(client).ask("x", mode="deep")
    assert chats(client) == []
    assert client.deep_ids == []


def test_normal_load_ack_still_requires_matching_exact_resident_id():
    client = Client(outcome="ack_success")
    answer = make_runtime(client).ask("x", mode="deep")
    assert answer.text == "DEEP_OK"
    assert client.deep_ids == []


def test_lmstudio_default_load_timeout_is_unchanged_and_acquisition_ack_is_bounded():
    client = LmStudioClient(load_timeout=600.0)
    calls = []

    def fake_request(method, path, payload=None, *, timeout=None):
        calls.append((method, path, payload, timeout))
        return {
            "status": "loaded",
            "instance_id": "instance-1",
            "load_config": {"context_length": 4096},
        }

    client._request = fake_request
    assert client.load(model="qwen3.6-35b-a3b", context_length=4096) == "instance-1"
    assert calls[-1][3] == 600.0

    assert client.load_for_acquisition(
        model="qwen3.6-35b-a3b",
        context_length=4096,
        ack_timeout=DEEP_LOAD_ACK_TIMEOUT_SECONDS,
    ) == "instance-1"
    assert calls[-1][3] == DEEP_LOAD_ACK_TIMEOUT_SECONDS
    assert client.load_timeout == 600.0

    client.load_for_acquisition(
        model="qwen3.6-35b-a3b",
        context_length=4096,
        ack_timeout=900.0,
    )
    assert calls[-1][3] == 600.0


def test_fast_mode_never_uses_deep_acquisition_loader():
    client = Client(outcome="timeout_resident")
    client.fast_loaded = False
    answer = make_runtime(client).ask("x", mode="fast")
    assert answer.text == "DEEP_OK"  # fake client text is irrelevant to routing contract
    assert ("legacy_load", "qwen3.5-4b", 8192) in client.events
    assert not any(event[0] == "load_for_acquisition" for event in client.events)
