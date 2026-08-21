from __future__ import annotations

from threading import RLock

import pytest

import continuityos.sovereign_twin_api as api
from continuityos.sovereign_twin_runtime import (
    DEFAULT_PROFILES,
    EXECUTION_AUTHORITY,
    LocalChatResult,
    LocalModelEndpointError,
    SovereignTwinRuntime,
)


class _SerialResidencyClient:
    base_url = "http://127.0.0.1:1234"

    def __init__(
        self,
        *,
        fast_loaded: bool = False,
        fast_visible: bool = True,
        raw_fast_instances=None,
        fail_fast_unload: bool = False,
        retain_fast_after_unload: bool = False,
        deep_error: bool = False,
        deep_error_has_instance_id: bool = True,
    ):
        self.fast_visible = fast_visible
        self.fast_loaded = fast_loaded
        self.raw_fast_instances = raw_fast_instances
        self.fail_fast_unload = fail_fast_unload
        self.retain_fast_after_unload = retain_fast_after_unload
        self.deep_error = deep_error
        self.deep_error_has_instance_id = deep_error_has_instance_id
        self.deep_loaded = False
        self.events: list[tuple] = []

    def models(self):
        rows = []
        if self.fast_visible:
            if self.raw_fast_instances is not None:
                fast_instances = self.raw_fast_instances
            elif self.fast_loaded:
                fast_instances = [{
                    "id": "fast-r20-1",
                    "config": {
                        "context_length": 8192,
                        "parallel": 1,
                        "flash_attention": True,
                        "offload_kv_cache_to_gpu": True,
                    },
                }]
            else:
                fast_instances = []
            rows.append({"key": "qwen3.5-4b", "loaded_instances": fast_instances})
        rows.append({
            "key": "qwen3.6-35b-a3b",
            "loaded_instances": ([{"id": "deep-r20-1", "config": {}}] if self.deep_loaded else []),
        })
        return rows

    def load(self, *, model: str, context_length: int):
        self.events.append(("load", model, context_length))
        if model == "qwen3.5-4b":
            self.fast_loaded = True
            return "fast-r20-1"
        raise AssertionError(f"unexpected explicit load: {model}")

    def unload(self, instance_id: str):
        self.events.append(("unload", instance_id))
        if instance_id == "fast-r20-1":
            if self.fail_fast_unload:
                raise LocalModelEndpointError("simulated FAST unload failure")
            if not self.retain_fast_after_unload:
                self.fast_loaded = False
            return
        if instance_id == "deep-r20-1":
            self.deep_loaded = False

    def chat(self, **kwargs):
        self.events.append(("chat", kwargs["model"], kwargs["context_length"], kwargs["reasoning"]))
        if kwargs["model"] == "qwen3.6-35b-a3b":
            self.deep_loaded = True
            if self.deep_error:
                raise LocalModelEndpointError(
                    "simulated DEEP inference failure",
                    model_instance_id="deep-r20-1" if self.deep_error_has_instance_id else None,
                )
            return LocalChatResult(
                text="DEEP_OK",
                model_instance_id="deep-r20-1",
                stats={"tokens_per_second": 1.0},
                reasoning="internal",
            )
        return LocalChatResult(
            text="FAST_OK",
            model_instance_id="fast-r20-1",
            stats={"tokens_per_second": 10.0},
            reasoning=None,
        )


def _runtime(client: _SerialResidencyClient) -> SovereignTwinRuntime:
    runtime = object.__new__(SovereignTwinRuntime)
    runtime.client = client
    runtime.profiles = dict(DEFAULT_PROFILES)
    runtime._model_lock = RLock()
    runtime.evidence = lambda query: ()
    return runtime


def _chat_events(client):
    return [event for event in client.events if event[0] == "chat"]


def test_r20_deep_with_fast_already_cold_does_not_unload_fast_and_cleans_deep():
    client = _SerialResidencyClient(fast_loaded=False)
    runtime = _runtime(client)

    answer = runtime.ask("deep", mode="deep")

    assert answer.text == "DEEP_OK"
    assert answer.execution_authority == "NONE"
    assert answer.can_execute is False
    assert ("unload", "fast-r20-1") not in client.events
    assert client.events[-1] == ("unload", "deep-r20-1")
    assert client.fast_loaded is False
    assert client.deep_loaded is False


def test_r20_deep_releases_fast_before_chat_then_leaves_fast_cold():
    client = _SerialResidencyClient(fast_loaded=True)
    runtime = _runtime(client)

    runtime.ask("deep", mode="deep")

    fast_unload = client.events.index(("unload", "fast-r20-1"))
    deep_chat = client.events.index(("chat", "qwen3.6-35b-a3b", 4096, "on"))
    deep_unload = client.events.index(("unload", "deep-r20-1"))
    assert fast_unload < deep_chat < deep_unload
    assert client.fast_loaded is False
    assert client.deep_loaded is False


def test_r20_deep_refuses_to_chat_if_fast_unload_fails():
    client = _SerialResidencyClient(fast_loaded=True, fail_fast_unload=True)
    runtime = _runtime(client)

    with pytest.raises(LocalModelEndpointError, match="FAST unload failed before native DEEP"):
        runtime.ask("deep", mode="deep")

    assert _chat_events(client) == []
    assert client.fast_loaded is True


def test_r20_deep_refuses_to_chat_if_fast_remains_resident_after_unload():
    client = _SerialResidencyClient(fast_loaded=True, retain_fast_after_unload=True)
    runtime = _runtime(client)

    with pytest.raises(LocalModelEndpointError, match="FAST remains resident"):
        runtime.ask("deep", mode="deep")

    assert _chat_events(client) == []
    assert client.fast_loaded is True


def test_r20_deep_refuses_malformed_fast_residency_state():
    client = _SerialResidencyClient(raw_fast_instances="not-a-list")
    runtime = _runtime(client)

    with pytest.raises(LocalModelEndpointError, match="loaded_instances is invalid"):
        runtime.ask("deep", mode="deep")

    assert _chat_events(client) == []


def test_r20_deep_refuses_fast_instance_without_id():
    client = _SerialResidencyClient(raw_fast_instances=[{"config": {"context_length": 8192}}])
    runtime = _runtime(client)

    with pytest.raises(LocalModelEndpointError, match="missing id"):
        runtime.ask("deep", mode="deep")

    assert _chat_events(client) == []


def test_r20_deep_refuses_when_configured_fast_model_is_not_visible():
    client = _SerialResidencyClient(fast_visible=False)
    runtime = _runtime(client)

    with pytest.raises(LocalModelEndpointError, match="FAST model is not visible"):
        runtime.ask("deep", mode="deep")

    assert _chat_events(client) == []


def test_r20_deep_failure_with_instance_id_cleans_deep_and_keeps_fast_cold():
    client = _SerialResidencyClient(fast_loaded=True, deep_error=True)
    runtime = _runtime(client)

    with pytest.raises(LocalModelEndpointError, match="simulated DEEP inference failure"):
        runtime.ask("deep", mode="deep")

    assert ("unload", "fast-r20-1") in client.events
    assert ("unload", "deep-r20-1") in client.events
    assert client.fast_loaded is False
    assert client.deep_loaded is False


def test_r20_deep_failure_without_instance_id_uses_existing_cleanup_path():
    client = _SerialResidencyClient(
        fast_loaded=True,
        deep_error=True,
        deep_error_has_instance_id=False,
    )
    runtime = _runtime(client)

    with pytest.raises(LocalModelEndpointError, match="simulated DEEP inference failure"):
        runtime.ask("deep", mode="deep")

    assert ("unload", "fast-r20-1") in client.events
    assert ("unload", "deep-r20-1") in client.events
    assert client.fast_loaded is False
    assert client.deep_loaded is False


def test_r20_fast_mode_keeps_r18_r19_cold_load_and_residency_contract():
    client = _SerialResidencyClient(fast_loaded=False)
    runtime = _runtime(client)

    answer = runtime.ask("fast", mode="fast")

    assert answer.text == "FAST_OK"
    assert ("load", "qwen3.5-4b", 8192) in client.events
    assert ("unload", "fast-r20-1") not in client.events
    assert client.fast_loaded is True


def test_r20_ui_explains_deep_fast_release_and_preserves_deep_lite_route():
    text = api._UI

    assert "Releasing FAST, then running DEEP locally..." in text
    assert "mode==='deep'&&state==='READY'" in text
    assert "postAsk('/ask/deep-lite',{query:q},'DEEP-LITE')" in text
    assert "fetch('/readiness',{method:'GET'})" in text
    assert "fetch('/readiness',{method:'POST'})" not in text
    assert "/api/v1/models/unload" not in text
    assert ".innerHTML" not in text


def test_r20_authority_constant_remains_none():
    assert EXECUTION_AUTHORITY == "NONE"
