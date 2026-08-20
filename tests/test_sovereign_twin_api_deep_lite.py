from __future__ import annotations

from types import SimpleNamespace

import pytest

import continuityos.sovereign_twin_api as api


class _Answer:
    def __init__(self, payload):
        self.payload = payload

    def to_dict(self):
        return dict(self.payload)


def test_ui_exposes_dedicated_deep_lite_button_and_endpoint():
    assert "DEEP-LITE" in api._UI
    assert "askDeepLite()" in api._UI
    assert "'/ask/deep-lite'" in api._UI


def test_deep_lite_request_uses_dedicated_runner(monkeypatch):
    client = object()
    calls = {}

    def fail_runtime_ask(*args, **kwargs):
        raise AssertionError("DEEP-LITE must not be routed through runtime.ask")

    runtime = SimpleNamespace(
        memory_db="C:/memory.db",
        client=client,
        embedding_model="embed-model",
        recall_k=8,
        ask=fail_runtime_ask,
    )
    server = SimpleNamespace(runtime=runtime)

    def fake_run_deep_lite(query, *, memory_db, client, embedding_model, recall_k):
        calls.update(
            query=query,
            memory_db=memory_db,
            client=client,
            embedding_model=embedding_model,
            recall_k=recall_k,
        )
        return _Answer(
            {
                "mode": "deep-lite",
                "execution_authority": "NONE",
                "can_execute": False,
            }
        )

    monkeypatch.setattr(api, "run_deep_lite", fake_run_deep_lite)

    result = api._answer_request(server, "/ask/deep-lite", {"query": "  grounded question  "})

    assert result == {
        "mode": "deep-lite",
        "execution_authority": "NONE",
        "can_execute": False,
    }
    assert calls == {
        "query": "grounded question",
        "memory_db": "C:/memory.db",
        "client": client,
        "embedding_model": "embed-model",
        "recall_k": 8,
    }


def test_standard_ask_contract_is_preserved(monkeypatch):
    calls = {}

    def fake_ask(query, *, mode):
        calls.update(query=query, mode=mode)
        return _Answer({"mode": mode, "can_execute": False})

    runtime = SimpleNamespace(ask=fake_ask)
    server = SimpleNamespace(runtime=runtime)

    def fail_deep_lite(*args, **kwargs):
        raise AssertionError("ordinary /ask must not invoke DEEP-LITE")

    monkeypatch.setattr(api, "run_deep_lite", fail_deep_lite)

    result = api._answer_request(server, "/ask", {"query": "hello", "mode": "fast"})

    assert result == {"mode": "fast", "can_execute": False}
    assert calls == {"query": "hello", "mode": "fast"}


def test_answer_request_rejects_empty_query_for_both_ask_paths():
    server = SimpleNamespace(runtime=SimpleNamespace())

    for path in ("/ask", "/ask/deep-lite"):
        with pytest.raises(ValueError, match="query required"):
            api._answer_request(server, path, {"query": "   "})


def test_answer_request_leaves_unrelated_paths_untouched():
    server = SimpleNamespace(runtime=SimpleNamespace())
    assert api._answer_request(server, "/admissions", {"text": "x"}) is None
