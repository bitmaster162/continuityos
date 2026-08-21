from __future__ import annotations

from threading import RLock
import pytest

from continuityos.sovereign_twin_runtime import (
    DEFAULT_PROFILES,
    DEEP_CAPACITY_BLOCKED_MESSAGE,
    DeepCapacityBlockedError,
    LocalChatResult,
    LocalModelEndpointError,
    SovereignTwinRuntime,
)


class Client:
    base_url = "http://127.0.0.1:1234"

    def __init__(
        self,
        *,
        fast_loaded=True,
        fail_fast_unload=False,
        retain_fast=False,
        load_error=None,
        deep_instances_after_load=None,
        deep_context=4096,
        chat_error=None,
        chat_result_id="deep-1",
        fail_deep_unload=False,
        retain_deep=False,
    ):
        self.fast_loaded = fast_loaded
        self.fail_fast_unload = fail_fast_unload
        self.retain_fast = retain_fast
        self.load_error = load_error
        self.deep_instances_after_load = deep_instances_after_load
        self.deep_context = deep_context
        self.chat_error = chat_error
        self.chat_result_id = chat_result_id
        self.fail_deep_unload = fail_deep_unload
        self.retain_deep = retain_deep
        self.deep_ids = []
        self.events = []

    def models(self):
        fast = []
        if self.fast_loaded:
            fast = [{
                "id": "fast-1",
                "config": {
                    "context_length": 8192,
                    "parallel": 1,
                    "flash_attention": True,
                    "offload_kv_cache_to_gpu": True,
                },
            }]
        deep = [
            {"id": x, "config": {"context_length": self.deep_context}}
            for x in self.deep_ids
        ]
        return [
            {"key": "qwen3.5-4b", "loaded_instances": fast},
            {"key": "qwen3.6-35b-a3b", "loaded_instances": deep},
        ]

    def load(self, *, model, context_length):
        self.events.append(("load", model, context_length))
        if model == "qwen3.5-4b":
            self.fast_loaded = True
            return "fast-1"
        if self.load_error is not None:
            raise LocalModelEndpointError(self.load_error)
        if self.deep_instances_after_load is None:
            self.deep_ids = ["deep-1"]
        else:
            self.deep_ids = list(self.deep_instances_after_load)
        return "deep-1"

    def unload(self, instance_id):
        self.events.append(("unload", instance_id))
        if instance_id == "fast-1":
            if self.fail_fast_unload:
                raise LocalModelEndpointError("FAST unload simulated")
            if not self.retain_fast:
                self.fast_loaded = False
            return
        if instance_id.startswith("deep"):
            if self.fail_deep_unload and instance_id == "deep-1":
                raise LocalModelEndpointError("DEEP unload simulated")
            if not self.retain_deep:
                self.deep_ids = [x for x in self.deep_ids if x != instance_id]

    def chat(self, **kwargs):
        self.events.append(("chat", kwargs["model"], kwargs["context_length"], kwargs["reasoning"]))
        if self.chat_error:
            raise LocalModelEndpointError(self.chat_error)
        return LocalChatResult(
            text="DEEP_OK" if kwargs["model"] == "qwen3.6-35b-a3b" else "FAST_OK",
            model_instance_id=self.chat_result_id if kwargs["model"] == "qwen3.6-35b-a3b" else "fast-1",
            stats={},
            reasoning="internal" if kwargs["reasoning"] == "on" else None,
        )


def runtime(client):
    r = object.__new__(SovereignTwinRuntime)
    r.client = client
    r.profiles = dict(DEFAULT_PROFILES)
    r._model_lock = RLock()
    r.evidence = lambda query: ()
    return r


def chats(client):
    return [x for x in client.events if x[0] == "chat"]


def test_success_is_fast_unload_then_explicit_deep_load_then_chat_then_exact_unload():
    c = Client()
    answer = runtime(c).ask("x", mode="deep")
    assert answer.text == "DEEP_OK"
    assert c.events == [
        ("unload", "fast-1"),
        ("load", "qwen3.6-35b-a3b", 4096),
        ("chat", "qwen3.6-35b-a3b", 4096, "on"),
        ("unload", "deep-1"),
    ]
    assert c.fast_loaded is False
    assert c.deep_ids == []


def test_fast_unload_failure_means_no_deep_load_or_chat():
    c = Client(fail_fast_unload=True)
    with pytest.raises(LocalModelEndpointError, match="FAST unload failed"):
        runtime(c).ask("x", mode="deep")
    assert not any(x[0] == "load" and x[1] == "qwen3.6-35b-a3b" for x in c.events)
    assert chats(c) == []


def test_capacity_failure_is_bounded_and_never_chats():
    c = Client(load_error="Model loading was stopped due to insufficient system resources")
    with pytest.raises(DeepCapacityBlockedError) as exc:
        runtime(c).ask("x", mode="deep")
    assert str(exc.value) == DEEP_CAPACITY_BLOCKED_MESSAGE
    assert chats(c) == []
    assert c.fast_loaded is False
    assert c.deep_ids == []


def test_non_capacity_explicit_load_failure_never_chats():
    c = Client(load_error="simulated load transport failure")
    with pytest.raises(LocalModelEndpointError, match="DEEP explicit load failed before chat"):
        runtime(c).ask("x", mode="deep")
    assert chats(c) == []


def test_duplicate_deep_after_explicit_load_fails_closed_and_cleans_all():
    c = Client(deep_instances_after_load=["deep-1", "deep-2"])
    with pytest.raises(LocalModelEndpointError, match="exactly one"):
        runtime(c).ask("x", mode="deep")
    assert chats(c) == []
    assert c.deep_ids == []


def test_wrong_deep_context_fails_closed_and_cleans():
    c = Client(deep_context=2048)
    with pytest.raises(LocalModelEndpointError, match="context_length mismatch"):
        runtime(c).ask("x", mode="deep")
    assert chats(c) == []
    assert c.deep_ids == []


def test_chat_instance_mismatch_fails_closed_and_unloads_acquired_instance():
    c = Client(chat_result_id="deep-jit-2")
    with pytest.raises(LocalModelEndpointError, match="chat instance mismatch"):
        runtime(c).ask("x", mode="deep")
    assert ("unload", "deep-1") in c.events
    assert c.deep_ids == []


def test_chat_failure_unloads_exact_acquired_instance():
    c = Client(chat_error="simulated inference failure")
    with pytest.raises(LocalModelEndpointError, match="simulated inference failure"):
        runtime(c).ask("x", mode="deep")
    assert ("unload", "deep-1") in c.events
    assert c.deep_ids == []


def test_exact_unload_failure_is_surfaced():
    c = Client(fail_deep_unload=True, retain_deep=True)
    with pytest.raises(LocalModelEndpointError, match="DEEP exact unload failed"):
        runtime(c).ask("x", mode="deep")
    assert c.fast_loaded is False


def test_residual_deep_after_successful_unload_is_surfaced_and_best_effort_cleaned():
    class Residual(Client):
        def unload(self, instance_id):
            self.events.append(("unload", instance_id))
            if instance_id == "fast-1":
                self.fast_loaded = False
                return
            if instance_id == "deep-1":
                self.deep_ids = ["deep-2"]
                return
            if instance_id == "deep-2":
                self.deep_ids = []
    c = Residual()
    with pytest.raises(LocalModelEndpointError, match="DEEP remains resident"):
        runtime(c).ask("x", mode="deep")
    assert c.deep_ids == []


def test_preexisting_deep_refuses_new_acquisition_and_chat():
    c = Client()
    c.deep_ids = ["deep-old"]
    with pytest.raises(LocalModelEndpointError, match="already resident"):
        runtime(c).ask("x", mode="deep")
    assert chats(c) == []
    assert not any(x[0] == "load" and x[1] == "qwen3.6-35b-a3b" for x in c.events)


def test_fast_contract_stays_resident_and_profile_unchanged():
    c = Client(fast_loaded=False)
    answer = runtime(c).ask("x", mode="fast")
    assert answer.model == "qwen3.5-4b"
    assert ("load", "qwen3.5-4b", 8192) in c.events
    assert c.fast_loaded is True
    assert DEFAULT_PROFILES["deep"].model == "qwen3.6-35b-a3b"
    assert DEFAULT_PROFILES["deep"].context_length == 4096
    assert DEFAULT_PROFILES["deep"].reasoning == "on"
    assert DEFAULT_PROFILES["deep"].max_output_tokens == 2200
    assert DEFAULT_PROFILES["deep"].temperature == 0.15
