from __future__ import annotations

from threading import RLock

import pytest

import continuityos.sovereign_twin_runtime as runtime_module
import continuityos.sovereign_twin_runtime_r21g as retained_r21g
from continuityos.sovereign_twin_runtime import (
    DEFAULT_PROFILES,
    LmStudioClient,
    LocalModelEndpointError,
    SovereignTwinRuntime,
)


def _runtime(client, events):
    rt = SovereignTwinRuntime.__new__(SovereignTwinRuntime)
    rt.client = client
    rt.profiles = dict(DEFAULT_PROFILES)
    rt.embedding_model = runtime_module.DEFAULT_EMBEDDING_MODEL
    rt.recall_k = 8
    rt.memory_db = "test.db"
    rt._model_lock = RLock()

    def evidence(query):
        events.append(("r21h_evidence", query))
        return ()

    rt.evidence = evidence
    return rt


def test_custom_legacy_loader_without_stream_delegates_to_retained_r21g_before_r21h_evidence(
    monkeypatch,
):
    events = []
    sentinel = object()

    class LegacyCustomClient:
        chat_fast_streaming_jit_reconciled = None

        def load(self, **kwargs):
            events.append(("legacy_load", kwargs))
            return "legacy-fast"

    def retained_ask(self, query, *, mode="fast"):
        events.append(("retained_r21g", query, mode))
        return sentinel

    monkeypatch.setattr(retained_r21g.SovereignTwinRuntime, "ask", retained_ask)

    rt = _runtime(LegacyCustomClient(), events)
    result = rt.ask("hello", mode="fast")

    assert result is sentinel
    assert events == [("retained_r21g", "hello", "fast")]


def test_official_lmstudio_subclass_never_uses_legacy_loader_escape_hatch():
    events = []

    class OfficialWithoutStream(LmStudioClient):
        chat_fast_streaming_jit_reconciled = None

        def __init__(self):
            # Avoid any network/setup effect; only isinstance + protocol shape matter.
            self.base_url = "http://127.0.0.1:1234"

        def models(self):
            events.append(("models",))
            return [
                {
                    "key": DEFAULT_PROFILES["fast"].model,
                    "loaded_instances": [],
                }
            ]

        def load(self, **kwargs):
            raise AssertionError(
                "official R21H FAST must not enter historical explicit load fallback"
            )

    rt = _runtime(OfficialWithoutStream(), events)

    with pytest.raises(LocalModelEndpointError, match="streaming-JIT"):
        rt.ask("hello", mode="fast")

    assert events == [
        ("r21h_evidence", "hello"),
        ("models",),
    ]
