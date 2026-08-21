from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

from continuityos.memory import Memory
from continuityos.sovereign_twin_runtime import (
    DEFAULT_EMBEDDING_MODEL,
    LmStudioClient,
    LocalChatResult,
    LocalModelEndpointError,
    LocalModelProfile,
    SovereignTwinRuntime,
)


class ColdFastClient:
    base_url = "http://127.0.0.1:1234"

    def __init__(self, *, loaded: bool = False):
        self.fast_loaded = loaded
        self.deep_loaded = False
        self.loads: list[tuple[str, int]] = []
        self.chats: list[dict] = []
        self.unloaded: list[str] = []

    def embed(self, text, *, model=DEFAULT_EMBEDDING_MODEL, task=None):
        return [1.0, 0.0, 0.0]

    def models(self):
        fast_instances = []
        if self.fast_loaded:
            fast_instances = [{
                "id": "fast-r18-1",
                "config": {
                    "context_length": 8192,
                    "parallel": 1,
                    "flash_attention": True,
                    "offload_kv_cache_to_gpu": True,
                },
            }]
        deep_instances = []
        if self.deep_loaded:
            deep_instances = [{
                "id": "deep-r18-1",
                "config": {"context_length": 4096},
            }]
        return [
            {"key": "qwen3.5-4b", "loaded_instances": fast_instances},
            {"key": "qwen3.6-35b-a3b", "loaded_instances": deep_instances},
            {"key": DEFAULT_EMBEDDING_MODEL, "loaded_instances": []},
        ]

    def load(self, *, model: str, context_length: int):
        self.loads.append((model, context_length))
        if model == "qwen3.6-35b-a3b":
            self.deep_loaded = True
            return "deep-r18-1"
        self.fast_loaded = True
        return "fast-r18-1"

    def chat(self, **kwargs):
        self.chats.append(kwargs)
        model_instance_id = (
            "deep-r18-1" if kwargs["model"] == "qwen3.6-35b-a3b" else "fast-r18-1"
        )
        return LocalChatResult(
            text="LOCAL_TWIN_OK",
            model_instance_id=model_instance_id,
            stats={"tokens_per_second": 38.9},
            reasoning="internal" if kwargs["reasoning"] == "on" else None,
        )

    def unload(self, instance_id: str):
        self.unloaded.append(instance_id)
        if instance_id == "deep-r18-1":
            self.deep_loaded = False


class RecordingRequestClient(LmStudioClient):
    def __init__(self):
        super().__init__(
            "http://127.0.0.1:1234",
            timeout=300.0,
            load_timeout=600.0,
        )
        self.requests: list[tuple[str, float | None]] = []

    def _request(self, method, path, payload=None, *, timeout=None):
        self.requests.append((path, timeout))
        if path == "/api/v1/models/load":
            return {
                "type": "llm",
                "instance_id": "fast-r18-1",
                "load_time_seconds": 313.65,
                "status": "loaded",
                "load_config": {"context_length": 8192},
            }
        if path == "/api/v1/chat":
            return {
                "model_instance_id": "fast-r18-1",
                "output": [{"type": "message", "content": "LOCAL_TWIN_OK"}],
                "stats": {"tokens_per_second": 38.9},
            }
        raise AssertionError(path)


class MismatchedLoadClient(RecordingRequestClient):
    def _request(self, method, path, payload=None, *, timeout=None):
        if path == "/api/v1/models/load":
            return {
                "type": "llm",
                "instance_id": "fast-r18-1",
                "status": "loaded",
                "load_config": {"context_length": 4096},
            }
        return super()._request(method, path, payload, timeout=timeout)


class WrongLoadedContextClient(ColdFastClient):
    def models(self):
        return [
            {
                "key": "qwen3.5-4b",
                "loaded_instances": [{
                    "id": "fast-wrong-ctx",
                    "config": {"context_length": 4096},
                }],
            },
            {"key": "qwen3.6-35b-a3b", "loaded_instances": []},
            {"key": DEFAULT_EMBEDDING_MODEL, "loaded_instances": []},
        ]


def _seed_db(tmp: str) -> str:
    db = str(Path(tmp) / "memory.db")
    writer = Memory(db, embedder=lambda text: [1.0, 0.0, 0.0])
    writer.remember("ContinuityOS stays local-first.", namespace="facts")
    writer.store.con.close()
    return db


def test_cold_fast_loads_exact_profile_before_chat_and_stays_loaded():
    with TemporaryDirectory() as tmp:
        db = _seed_db(tmp)
        client = ColdFastClient()
        runtime = SovereignTwinRuntime(db, client=client)
        try:
            answer = runtime.ask("smoke", mode="fast")
            assert answer.text == "LOCAL_TWIN_OK"
            assert client.loads == [("qwen3.5-4b", 8192)]
            assert len(client.chats) == 1
            assert client.chats[0]["context_length"] == 8192
            assert client.chats[0]["reasoning"] == "off"
            assert client.unloaded == []
            assert answer.execution_authority == "NONE"
            assert answer.can_execute is False
        finally:
            runtime.close()


def test_already_loaded_fast_skips_load():
    with TemporaryDirectory() as tmp:
        db = _seed_db(tmp)
        client = ColdFastClient(loaded=True)
        runtime = SovereignTwinRuntime(db, client=client)
        try:
            runtime.ask("smoke", mode="fast")
            assert client.loads == []
            assert len(client.chats) == 1
        finally:
            runtime.close()


def test_deep_mode_does_not_use_r18_fast_preloader():
    with TemporaryDirectory() as tmp:
        db = _seed_db(tmp)
        client = ColdFastClient()
        profiles = {
            "deep": LocalModelProfile(
                model="qwen3.6-35b-a3b",
                context_length=4096,
                reasoning="on",
                max_output_tokens=2200,
                temperature=0.15,
                unload_after_answer=True,
            ),
        }
        runtime = SovereignTwinRuntime(db, client=client, profiles=profiles)
        try:
            runtime.ask("deep", mode="deep")
            assert client.loads == [("qwen3.6-35b-a3b", 4096)]
            assert client.unloaded == ["deep-r18-1"]
            assert client.deep_loaded is False
        finally:
            runtime.close()


def test_load_timeout_is_separate_from_inference_timeout():
    client = RecordingRequestClient()
    assert client.timeout == 300.0
    assert client.load_timeout == 600.0

    instance_id = client.load(model="qwen3.5-4b", context_length=8192)
    assert instance_id == "fast-r18-1"
    assert client.requests[0] == ("/api/v1/models/load", 600.0)

    result = client.chat(
        model="qwen3.5-4b",
        system_prompt="system",
        input_text="smoke",
        context_length=8192,
        reasoning="off",
        max_output_tokens=1200,
        temperature=0.2,
    )
    assert result.text == "LOCAL_TWIN_OK"
    assert client.requests[1] == ("/api/v1/chat", None)


def test_load_fails_closed_on_context_mismatch():
    client = MismatchedLoadClient()
    with pytest.raises(LocalModelEndpointError, match="context_length mismatch"):
        client.load(model="qwen3.5-4b", context_length=8192)


def test_loaded_fast_with_wrong_context_fails_closed_without_reload():
    with TemporaryDirectory() as tmp:
        db = _seed_db(tmp)
        client = WrongLoadedContextClient(loaded=True)
        runtime = SovereignTwinRuntime(db, client=client)
        try:
            with pytest.raises(LocalModelEndpointError, match="context_length mismatch"):
                runtime.ask("smoke", mode="fast")
            assert client.loads == []
            assert client.chats == []
        finally:
            runtime.close()
