from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

from continuityos.memory import Memory
from continuityos.sovereign_twin_deep_lite import (
    DEEP_LITE_CONTEXT_LENGTH,
    DEEP_LITE_DRAFT_MAX_OUTPUT_TOKENS,
    DEEP_LITE_FINAL_MAX_OUTPUT_TOKENS,
    run_deep_lite,
)
from continuityos.sovereign_twin_runtime import (
    DEFAULT_EMBEDDING_MODEL,
    LocalChatResult,
    LocalModelEndpointError,
    NOMIC_DOCUMENT_TASK,
)


class DeepLiteClient:
    base_url = "http://127.0.0.1:1234"

    def __init__(self, *, preloaded: bool = False, fail_second: bool = False):
        self.preloaded = preloaded
        self.loaded = preloaded
        self.fail_second = fail_second
        self.calls: list[dict] = []
        self.unloaded: list[str] = []
        self.embeds: list[tuple[str, str, str | None]] = []

    def embed(self, text, *, model=DEFAULT_EMBEDDING_MODEL, task=None):
        self.embeds.append((text, model, task))
        return [1.0, 0.0, 0.0]

    def models(self):
        return [
            {
                "key": "qwen3.5-4b",
                "loaded_instances": (
                    [{"id": "qwen3.5-4b", "config": {"context_length": 4096, "parallel": 1}}]
                    if self.loaded
                    else []
                ),
            },
            {"key": DEFAULT_EMBEDDING_MODEL, "loaded_instances": []},
        ]

    def chat(self, **kwargs):
        self.loaded = True
        self.calls.append(kwargs)
        index = len(self.calls)
        if self.fail_second and index == 2:
            raise LocalModelEndpointError(
                "second pass failed",
                model_instance_id="qwen3.5-4b",
                stats={"total_output_tokens": 7},
            )
        if index == 1:
            return LocalChatResult(
                text="candidate mem:1",
                model_instance_id="qwen3.5-4b",
                stats={
                    "input_tokens": 100,
                    "total_output_tokens": 40,
                    "reasoning_output_tokens": 0,
                    "tokens_per_second": 50.0,
                },
                reasoning=None,
            )
        return LocalChatResult(
            text="final grounded answer mem:1",
            model_instance_id="qwen3.5-4b",
            stats={
                "input_tokens": 150,
                "total_output_tokens": 55,
                "reasoning_output_tokens": 0,
                "tokens_per_second": 49.0,
            },
            reasoning=None,
        )

    def unload(self, instance_id):
        self.unloaded.append(instance_id)
        if not self.preloaded:
            self.loaded = False


def _seed_db(tmp: str) -> str:
    db = str(Path(tmp) / "memory.db")
    writer = Memory(db, embedder=lambda text: [1.0, 0.0, 0.0])
    writer.remember(
        "ContinuityOS is local-first and has no execution authority.",
        namespace="facts",
    )
    writer.store.con.close()
    return db


def test_deep_lite_is_two_bounded_reasoning_off_passes_and_returns_only_final():
    with TemporaryDirectory() as tmp:
        db = _seed_db(tmp)
        client = DeepLiteClient()
        answer = run_deep_lite("Review the architecture", memory_db=db, client=client)

        assert answer.text == "final grounded answer mem:1"
        assert answer.model == "qwen3.5-4b"
        assert answer.mode == "deep-lite"
        assert answer.reasoning_present is False
        assert answer.execution_authority == "NONE"
        assert answer.can_execute is False
        assert len(client.calls) == 2
        assert all(call["reasoning"] == "off" for call in client.calls)
        assert all(call["context_length"] == DEEP_LITE_CONTEXT_LENGTH for call in client.calls)
        assert client.calls[0]["max_output_tokens"] == DEEP_LITE_DRAFT_MAX_OUTPUT_TOKENS
        assert client.calls[1]["max_output_tokens"] == DEEP_LITE_FINAL_MAX_OUTPUT_TOKENS
        assert "UNTRUSTED_DRAFT_TO_REVIEW" in client.calls[1]["input_text"]
        assert "candidate mem:1" in client.calls[1]["input_text"]
        assert client.unloaded == ["qwen3.5-4b"]

        stats = answer.stats
        assert stats["strategy"] == "bounded_two_pass_reasoning_off"
        assert stats["pass_count"] == 2
        assert stats["total_output_tokens"] == 95
        assert stats["reasoning_output_tokens"] == 0
        assert "candidate mem:1" not in str(stats)


def test_deep_lite_preserves_preexisting_model_residency():
    with TemporaryDirectory() as tmp:
        db = _seed_db(tmp)
        client = DeepLiteClient(preloaded=True)
        answer = run_deep_lite("Review", memory_db=db, client=client)
        assert answer.text == "final grounded answer mem:1"
        assert client.unloaded == []
        assert client.loaded is True


def test_deep_lite_second_pass_failure_unloads_newly_loaded_model_and_preserves_error():
    with TemporaryDirectory() as tmp:
        db = _seed_db(tmp)
        client = DeepLiteClient(fail_second=True)
        with pytest.raises(LocalModelEndpointError, match="second pass failed"):
            run_deep_lite("Review", memory_db=db, client=client)
        assert client.unloaded == ["qwen3.5-4b"]
        assert client.loaded is False


def test_deep_lite_query_recall_uses_runtime_embedding_contract():
    with TemporaryDirectory() as tmp:
        db = _seed_db(tmp)
        client = DeepLiteClient()
        run_deep_lite("architecture", memory_db=db, client=client)
        assert client.embeds
        # Runtime recall prefixes queries as search_query; this verifies the local Nomic path is still used.
        assert client.embeds[0][2] == "search_query"


def test_deep_lite_rejects_empty_query_without_model_call():
    with TemporaryDirectory() as tmp:
        db = _seed_db(tmp)
        client = DeepLiteClient()
        with pytest.raises(ValueError, match="query required"):
            run_deep_lite("   ", memory_db=db, client=client)
        assert client.calls == []
