from __future__ import annotations

import inspect

import continuityos.sovereign_twin_api as api
from continuityos.sovereign_twin_runtime import (
    EXECUTION_AUTHORITY,
    LocalModelProfile,
    SovereignTwinRuntime,
)


FAST_PROFILE = LocalModelProfile(
    model="qwen3.5-4b",
    context_length=8192,
    reasoning="off",
    max_output_tokens=1200,
    temperature=0.2,
    unload_after_answer=False,
)


class _ReadinessClient:
    base_url = "http://127.0.0.1:1234"

    def __init__(self, rows):
        self.rows = rows
        self.load_calls = []
        self.unload_calls = []

    def models(self):
        return self.rows

    def load(self, **kwargs):
        self.load_calls.append(kwargs)
        raise AssertionError("readiness inspection must not load FAST")

    def unload(self, instance_id):
        self.unload_calls.append(instance_id)
        raise AssertionError("readiness inspection must not unload FAST")


def _runtime(rows):
    runtime = object.__new__(SovereignTwinRuntime)
    runtime.client = _ReadinessClient(rows)
    runtime.profiles = {"fast": FAST_PROFILE}
    return runtime


def _loaded_row(*, context_length=8192, parallel=1, flash_attention=True, kv_on_gpu=True):
    return {
        "key": "qwen3.5-4b",
        "loaded_instances": [
            {
                "id": "qwen3.5-4b",
                "config": {
                    "context_length": context_length,
                    "parallel": parallel,
                    "flash_attention": flash_attention,
                    "offload_kv_cache_to_gpu": kv_on_gpu,
                },
            }
        ],
    }


def test_r19_visible_unloaded_fast_is_cold_and_read_only():
    runtime = _runtime([{"key": "qwen3.5-4b", "loaded_instances": []}])

    report = runtime.fast_readiness()

    assert report == {
        "ok": True,
        "model": "qwen3.5-4b",
        "expected_context_length": 8192,
        "execution_authority": "NONE",
        "can_execute": False,
        "state": "COLD",
        "ready": False,
        "visible_to_server": True,
        "loaded": False,
        "loaded_context_length": None,
        "warnings": [],
    }
    assert runtime.client.load_calls == []
    assert runtime.client.unload_calls == []


def test_r19_exact_loaded_fast_is_ready():
    runtime = _runtime([_loaded_row()])

    report = runtime.fast_readiness()

    assert report["state"] == "READY"
    assert report["ready"] is True
    assert report["loaded"] is True
    assert report["loaded_context_length"] == 8192
    assert report["warnings"] == []
    assert runtime.client.load_calls == []
    assert runtime.client.unload_calls == []


def test_r19_wrong_loaded_context_is_misconfigured_not_silently_repaired():
    runtime = _runtime([_loaded_row(context_length=4096)])

    report = runtime.fast_readiness()

    assert report["state"] == "MISCONFIGURED"
    assert report["ready"] is False
    assert report["loaded"] is True
    assert report["loaded_context_length"] == 4096
    assert "CONTEXT_LENGTH_MISMATCH" in report["warnings"]
    assert runtime.client.load_calls == []
    assert runtime.client.unload_calls == []


def test_r19_absent_fast_is_unavailable_without_load_attempt():
    runtime = _runtime([{"key": "qwen3.6-35b-a3b", "loaded_instances": []}])

    report = runtime.fast_readiness()

    assert report["state"] == "UNAVAILABLE"
    assert report["ready"] is False
    assert report["visible_to_server"] is False
    assert report["loaded"] is False
    assert report["warnings"] == ["FAST_MODEL_NOT_VISIBLE"]
    assert runtime.client.load_calls == []
    assert runtime.client.unload_calls == []


def test_r19_readiness_preserves_shadow_authority_contract():
    runtime = _runtime([_loaded_row()])

    report = runtime.fast_readiness()

    assert EXECUTION_AUTHORITY == "NONE"
    assert report["execution_authority"] == "NONE"
    assert report["can_execute"] is False


def test_r19_parallel_or_acceleration_mismatch_blocks_ready_state():
    runtime = _runtime([
        _loaded_row(parallel=2, flash_attention=False, kv_on_gpu=False)
    ])

    report = runtime.fast_readiness()

    assert report["state"] == "MISCONFIGURED"
    assert report["ready"] is False
    assert set(report["warnings"]) == {
        "PARALLEL_NOT_1",
        "FLASH_ATTENTION_OFF",
        "KV_CACHE_NOT_ON_GPU",
    }


def test_r19_api_exposes_read_only_readiness_route():
    source = inspect.getsource(api._Handler.do_GET)

    assert 'path == "/readiness"' in source
    assert "self.server.runtime.fast_readiness()" in source
    assert "do_POST" not in source


def test_r19_ui_surfaces_fast_readiness_and_cold_loading_message_safely():
    text = api._UI

    assert 'id="fast-readiness"' in text
    assert "FAST CHECKING" in text
    assert "FAST COLD" in text
    assert "FAST READY" in text
    assert "FAST BLOCKED" in text
    assert "Loading FAST locally, then answering..." in text
    assert "fetch('/readiness',{method:'GET'})" in text
    assert "fetch('/readiness',{method:'POST'})" not in text
    assert "badge.textContent=" in text
    assert ".innerHTML" not in text


def test_r19_ui_refreshes_readiness_after_answer_without_preloading():
    text = api._UI

    assert "refreshReadiness();" in text
    assert "await refreshReadiness();" in text
    assert "/api/v1/models/load" not in text
    assert "/api/v1/models/unload" not in text
