from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

from continuityos.memory import Memory
from continuityos.sovereign_twin_runtime import (
    DEFAULT_EMBEDDING_MODEL,
    LmStudioClient,
    LocalModelEndpointError,
    NOMIC_DOCUMENT_TASK,
    SovereignTwinRuntime,
)


class ReasoningOnlyClient(LmStudioClient):
    def __init__(self):
        super().__init__("http://127.0.0.1:1234")

    def _request(self, method, path, payload=None):
        assert method == "POST"
        assert path == "/api/v1/chat"
        return {
            "model_instance_id": "deep-lite-1",
            "output": [{"type": "reasoning", "content": "private reasoning"}],
            "stats": {
                "total_output_tokens": 2200,
                "reasoning_output_tokens": 2200,
                "tokens_per_second": 48.0,
            },
        }


class ErrorCleanupClient:
    base_url = "http://127.0.0.1:1234"

    def __init__(self):
        self.unloaded: list[str] = []
        self.deep_loaded = False

    def embed(self, text, *, model=DEFAULT_EMBEDDING_MODEL, task=None):
        return [1.0, 0.0, 0.0]

    def chat(self, **kwargs):
        self.deep_loaded = True
        raise LocalModelEndpointError("simulated timeout")

    def models(self):
        return [
            {"key": "qwen3.5-4b", "loaded_instances": []},
            {
                "key": "qwen3.6-35b-a3b",
                "loaded_instances": ([{"id": "deep-timeout-1", "config": {}}] if self.deep_loaded else []),
            },
            {"key": DEFAULT_EMBEDDING_MODEL, "loaded_instances": []},
        ]

    def unload(self, instance_id):
        self.unloaded.append(instance_id)
        if instance_id == "deep-timeout-1":
            self.deep_loaded = False


def _seed_db(tmp: str) -> str:
    db = str(Path(tmp) / "memory.db")
    writer = Memory(db, embedder=lambda text: [1.0, 0.0, 0.0])
    writer.remember("ContinuityOS is local-first.", namespace="facts")
    writer.store.con.close()
    return db


def test_reasoning_only_response_is_diagnostic_not_user_answer():
    client = ReasoningOnlyClient()
    with pytest.raises(LocalModelEndpointError) as caught:
        client.chat(
            model="qwen3.5-4b",
            system_prompt="system",
            input_text="question",
            context_length=4096,
            reasoning="on",
            max_output_tokens=2200,
            temperature=0.15,
        )
    exc = caught.value
    assert exc.model_instance_id == "deep-lite-1"
    assert exc.output_types == ("reasoning",)
    assert exc.stats["reasoning_output_tokens"] == 2200
    assert "output_types=['reasoning']" in str(exc)
    assert "reasoning_output_tokens=2200" in str(exc)
    assert "private reasoning" not in str(exc)


def test_deep_timeout_best_effort_unloads_loaded_instance_and_preserves_error():
    with TemporaryDirectory() as tmp:
        db = _seed_db(tmp)
        client = ErrorCleanupClient()
        runtime = SovereignTwinRuntime(db, client=client)
        try:
            with pytest.raises(LocalModelEndpointError, match="simulated timeout"):
                runtime.ask("deep test", mode="deep")
            assert client.unloaded == ["deep-timeout-1"]
            assert client.deep_loaded is False
        finally:
            runtime.close()
