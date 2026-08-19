from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

from continuityos.memory import Memory
from continuityos.sovereign_twin_admission import ShadowMemoryAdmissionQueue
from continuityos.sovereign_twin_api import _validate_bind
from continuityos.sovereign_twin_cli import _initialize_memory_db
from continuityos.sovereign_twin_runtime import (
    LocalChatResult,
    LocalModelEndpointError,
    SovereignTwinRuntime,
    _validate_loopback_url,
)


class FakeClient:
    base_url = "http://127.0.0.1:1234"

    def __init__(self):
        self.calls = []
        self.unloaded = []

    def models(self):
        return [
            {
                "key": "qwen3.5-4b",
                "loaded_instances": [{
                    "id": "fast-1",
                    "config": {
                        "context_length": 8192,
                        "parallel": 1,
                        "flash_attention": True,
                        "offload_kv_cache_to_gpu": True,
                    },
                }],
            },
            {
                "key": "qwen3.6-35b-a3b",
                "loaded_instances": [],
            },
        ]

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


def _seed_db(tmp: str) -> tuple[str, int]:
    db = str(Path(tmp) / "memory.db")
    writer = Memory(db)
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


def test_runtime_grounding_fast_uses_v1_profile_and_none_authority():
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
            call = client.calls[0]
            assert call["context_length"] == 8192
            assert call["reasoning"] == "off"
            assert f"mem:{rid}" in call["system_prompt"]
            assert "Do not execute actions" in call["system_prompt"]
            assert client.unloaded == []
        finally:
            runtime.close()


def test_deep_mode_uses_4k_reasoning_and_unloads_after_answer():
    with TemporaryDirectory() as tmp:
        db, _ = _seed_db(tmp)
        client = FakeClient()
        runtime = SovereignTwinRuntime(db, client=client)
        try:
            answer = runtime.ask("Deep architecture review", mode="deep")
            assert answer.reasoning_present is True
            assert client.calls[0]["context_length"] == 4096
            assert client.calls[0]["reasoning"] == "on"
            assert client.unloaded == ["deep-1"]
        finally:
            runtime.close()


def test_doctor_reads_native_v1_model_shape():
    with TemporaryDirectory() as tmp:
        db, _ = _seed_db(tmp)
        runtime = SovereignTwinRuntime(db, client=FakeClient())
        try:
            report = runtime.doctor()
            assert report["ok"] is True
            assert report["api"] == "lm-studio-rest-v1"
            assert report["profiles"]["fast"]["loaded"] is True
            assert report["profiles"]["fast"]["warnings"] == []
            assert report["profiles"]["deep"]["loaded"] is False
            assert report["execution_authority"] == "NONE"
            assert report["can_execute"] is False
        finally:
            runtime.close()


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
