from __future__ import annotations

import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

from continuityos.memory import Memory
from continuityos.sovereign_twin_admission import ShadowMemoryAdmissionQueue
from continuityos.sovereign_twin_api import _validate_bind
from continuityos.sovereign_twin_cli import _initialize_memory_db
from continuityos.sovereign_twin_memory import import_seed, memory_report
from continuityos.sovereign_twin_runtime import (
    DEFAULT_EMBEDDING_MODEL,
    LocalChatResult,
    LocalModelEndpointError,
    NOMIC_DOCUMENT_TASK,
    NOMIC_QUERY_TASK,
    SovereignTwinRuntime,
    _task_prefixed_text,
    _validate_loopback_url,
)


class FakeClient:
    base_url = "http://127.0.0.1:1234"

    def __init__(self):
        self.calls = []
        self.unloaded = []
        self.embeds = []
        self.fast_loaded = True
        self.deep_loaded = False

    def models(self):
        fast_instances = []
        if self.fast_loaded:
            fast_instances = [{
                "id": "fast-1",
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
                "id": "deep-1",
                "config": {"context_length": 4096},
            }]
        return [
            {
                "key": "qwen3.5-4b",
                "loaded_instances": fast_instances,
            },
            {"key": "qwen3.6-35b-a3b", "loaded_instances": deep_instances},
            {"key": DEFAULT_EMBEDDING_MODEL, "loaded_instances": []},
        ]

    def load(self, *, model, context_length):
        if model == "qwen3.5-4b":
            self.fast_loaded = True
            return "fast-1"
        if model == "qwen3.6-35b-a3b":
            self.deep_loaded = True
            return "deep-1"
        raise LocalModelEndpointError(f"unexpected model load: {model}")

    def embed(self, text, *, model=DEFAULT_EMBEDDING_MODEL, task=None):
        self.embeds.append((text, model, task))
        return [1.0, 0.0, 0.0]

    def chat(self, **kwargs):
        self.calls.append(kwargs)
        return LocalChatResult(
            text="grounded local answer mem:1",
            model_instance_id="deep-1" if kwargs["model"] == "qwen3.6-35b-a3b" else "fast-1",
            stats={"tokens_per_second": 7.5},
            reasoning="internal" if kwargs["reasoning"] == "on" else None,
        )

    def unload(self, instance_id):
        self.unloaded.append(instance_id)
        if instance_id == "fast-1":
            self.fast_loaded = False
        elif instance_id == "deep-1":
            self.deep_loaded = False


def _seed_db(tmp: str) -> tuple[str, int]:
    db = str(Path(tmp) / "memory.db")
    fake = FakeClient()
    writer = Memory(db, embedder=lambda text: fake.embed(text, task=NOMIC_DOCUMENT_TASK))
    rid = writer.remember(
        "The owner prefers local-first AI systems.",
        namespace="rules",
        tags=["privacy"],
    )
    writer.store.con.close()
    return db, rid


def test_local_init_is_idempotent_and_grants_no_authority():
    with TemporaryDirectory() as tmp:
        db = str(Path(tmp) / "nested" / "memory.db")
        first = _initialize_memory_db(db)
        second = _initialize_memory_db(db)
        assert first["ok"] is True
        assert first["created"] is True
        assert second["created"] is False
        assert Path(db).exists()
        assert first["execution_authority"] == "NONE"
        assert first["can_execute"] is False


def test_loopback_policy_rejects_remote_by_default():
    with pytest.raises(LocalModelEndpointError):
        _validate_loopback_url("http://192.168.1.10:1234")
    assert _validate_loopback_url("http://127.0.0.1:1234") == "http://127.0.0.1:1234"
    with pytest.raises(ValueError):
        _validate_bind("0.0.0.0")


def test_nomic_prefix_helper_is_explicit_and_idempotent():
    assert _task_prefixed_text("hello", NOMIC_QUERY_TASK) == "search_query: hello"
    assert _task_prefixed_text("hello", NOMIC_DOCUMENT_TASK) == "search_document: hello"
    assert _task_prefixed_text("search_query: hello", NOMIC_QUERY_TASK) == "search_query: hello"
    with pytest.raises(ValueError):
        _task_prefixed_text("hello", "unknown")


def test_runtime_grounding_fast_uses_query_embedding_and_none_authority():
    with TemporaryDirectory() as tmp:
        db, rid = _seed_db(tmp)
        client = FakeClient()
        runtime = SovereignTwinRuntime(db, client=client, recall_k=4)
        try:
            answer = runtime.ask("How should the AI run?", mode="fast")
            assert answer.can_execute is False
            assert answer.execution_authority == "NONE"
            assert answer.model == "qwen3.5-4b"
            assert answer.stats["tokens_per_second"] == 7.5
            assert client.embeds
            assert client.embeds[0][1] == DEFAULT_EMBEDDING_MODEL
            assert client.embeds[0][2] == NOMIC_QUERY_TASK
            call = client.calls[0]
            assert call["context_length"] == 8192
            assert call["reasoning"] == "off"
            assert f"mem:{rid}" in call["system_prompt"]
            assert "Do not execute actions" in call["system_prompt"]
            assert client.unloaded == []
        finally:
            runtime.close()


def test_deep_mode_uses_4k_reasoning_and_serial_residency_cleanup():
    with TemporaryDirectory() as tmp:
        db, _ = _seed_db(tmp)
        client = FakeClient()
        runtime = SovereignTwinRuntime(db, client=client)
        try:
            answer = runtime.ask("Deep architecture review", mode="deep")
            assert answer.reasoning_present is True
            assert client.calls[0]["context_length"] == 4096
            assert client.calls[0]["reasoning"] == "on"
            assert client.unloaded == ["fast-1", "deep-1"]
            assert client.fast_loaded is False
            assert client.deep_loaded is False
        finally:
            runtime.close()


def test_doctor_reads_native_v1_and_embedding_contract():
    with TemporaryDirectory() as tmp:
        db, _ = _seed_db(tmp)
        runtime = SovereignTwinRuntime(db, client=FakeClient())
        try:
            report = runtime.doctor()
            assert report["ok"] is True
            assert report["api"] == "lm-studio-rest-v1+openai-embeddings"
            assert report["memory_db"] == os.path.realpath(os.path.abspath(db))
            assert report["profiles"]["fast"]["loaded"] is True
            assert report["profiles"]["fast"]["warnings"] == []
            assert report["profiles"]["deep"]["loaded"] is False
            assert report["embedding"]["model"] == DEFAULT_EMBEDDING_MODEL
            assert report["embedding"]["visible_to_server"] is True
            assert report["embedding"]["document_task_prefix"] == NOMIC_DOCUMENT_TASK
            assert report["embedding"]["query_task_prefix"] == NOMIC_QUERY_TASK
            assert report["execution_authority"] == "NONE"
            assert report["can_execute"] is False
        finally:
            runtime.close()


def test_seed_import_is_dry_run_by_default_then_commits_with_embedding_manifest():
    with TemporaryDirectory() as tmp:
        db = str(Path(tmp) / "memory.db")
        _initialize_memory_db(db)
        seed = Path(tmp) / "seed.json"
        seed.write_text(
            json.dumps({
                "schema": "sovereign-twin.memory-seed/v1",
                "entries": [{
                    "text": "The owner prefers local-first systems.",
                    "namespace": "rules",
                    "tags": ["privacy"],
                    "type": "preference",
                    "key": "local-first",
                }],
            }),
            encoding="utf-8",
        )
        client = FakeClient()
        dry = import_seed(db, str(seed), client=client, commit=False)
        assert dry["dry_run"] is True
        assert memory_report(db)["count"] == 0

        committed = import_seed(db, str(seed), client=client, commit=True)
        assert committed["entry_count"] == 1
        assert committed["embedding_dimension"] == 3
        assert committed["memory"]["count"] == 1
        assert committed["memory"]["vector_dimensions"] == [3]
        assert any(call[2] == NOMIC_DOCUMENT_TASK for call in client.embeds)
        assert Path(committed["manifest"]["path"]).exists()
        assert committed["manifest"]["embedding_contract"] == {
            "document_task_prefix": NOMIC_DOCUMENT_TASK,
            "query_task_prefix": NOMIC_QUERY_TASK,
        }
        assert committed["execution_authority"] == "NONE"
        assert committed["can_execute"] is False


def test_shadow_admission_queue_does_not_mutate_memory():
    with TemporaryDirectory() as tmp:
        path = Path(tmp) / "admissions.jsonl"
        queue = ShadowMemoryAdmissionQueue(path)
        event = queue.propose(
            "Candidate preference",
            namespace="rules",
            tags=["candidate"],
            evidence_refs=["mem:1"],
            ts=123.0,
        )
        assert event["payload"]["status"] == "PENDING"
        assert event["payload"]["canonical_memory_mutated"] is False
        assert queue.verify()["ok"] is True
        assert queue.pending()[0]["evidence_refs"] == ["mem:1"]
