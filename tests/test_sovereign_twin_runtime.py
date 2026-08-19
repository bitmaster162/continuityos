from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

from continuityos.memory import Memory
from continuityos.sovereign_twin_runtime import (
    LocalModelEndpointError,
    SovereignTwinRuntime,
    _validate_loopback_url,
)


class FakeClient:
    base_url = "http://127.0.0.1:1234"

    def __init__(self):
        self.calls = []

    def models(self):
        return [{"id": "qwen3.5-4b"}, {"id": "qwen3.6-35b-a3b"}]

    def chat(self, **kwargs):
        self.calls.append(kwargs)
        return "grounded local answer mem:1"


def test_loopback_policy_rejects_remote_by_default():
    with pytest.raises(LocalModelEndpointError):
        _validate_loopback_url("http://192.168.1.10:1234")
    assert _validate_loopback_url("http://127.0.0.1:1234") == "http://127.0.0.1:1234"


def test_runtime_grounding_and_none_authority():
    with TemporaryDirectory() as tmp:
        db = str(Path(tmp) / "memory.db")
        writer = Memory(db)
        rid = writer.remember(
            "The owner prefers local-first AI systems.",
            namespace="rules",
            tags=["privacy"],
        )
        writer.store.con.close()

        client = FakeClient()
        runtime = SovereignTwinRuntime(db, client=client, recall_k=4)
        try:
            answer = runtime.ask("How should the AI run?", mode="fast")
            assert answer.can_execute is False
            assert answer.execution_authority == "NONE"
            assert answer.model == "qwen3.5-4b"
            assert client.calls[0]["ttl_seconds"] == 1800
            system = client.calls[0]["messages"][0]["content"]
            assert f"mem:{rid}" in system
            assert "Do not execute actions" in system
        finally:
            runtime.close()


def test_doctor_sees_fast_and_deep_profiles():
    with TemporaryDirectory() as tmp:
        db = str(Path(tmp) / "memory.db")
        writer = Memory(db)
        writer.remember("seed", namespace="facts")
        writer.store.con.close()

        runtime = SovereignTwinRuntime(db, client=FakeClient())
        try:
            report = runtime.doctor()
            assert report["ok"] is True
            assert report["profiles"]["fast"]["visible_to_server"] is True
            assert report["profiles"]["deep"]["visible_to_server"] is True
            assert report["execution_authority"] == "NONE"
            assert report["can_execute"] is False
        finally:
            runtime.close()
