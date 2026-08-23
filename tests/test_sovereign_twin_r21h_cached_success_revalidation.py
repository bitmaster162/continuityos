from __future__ import annotations

from types import SimpleNamespace

import pytest

import continuityos.sovereign_twin_api as api
from continuityos.sovereign_twin_runtime import (
    DEFAULT_PROFILES,
    LocalModelEndpointError,
)


@pytest.fixture(autouse=True)
def reset_r21h_process_startup_prewarm_guard(monkeypatch):
    monkeypatch.setattr(api, "_R21H_STARTUP_PREWARM_STATE", "NOT_STARTED")
    monkeypatch.setattr(api, "_R21H_STARTUP_PREWARM_RESULT", None)
    monkeypatch.setattr(api, "_R21H_STARTUP_PREWARM_ERROR", None)


def _install_server_fakes(monkeypatch, events):
    class FakeServer:
        def __init__(self, address, handler):
            events.append("server.bind")

        def serve_forever(self):
            events.append("serve")

        def server_close(self):
            events.append("server.close")

    monkeypatch.setattr(api, "LmStudioClient", lambda base_url: object())
    monkeypatch.setattr(api._r21g_api, "_TwinServer", FakeServer)
    monkeypatch.setattr(
        api._r21g_api,
        "ShadowMemoryAdmissionQueue",
        lambda path: SimpleNamespace(path=path),
    )


def test_cached_success_revalidates_exact_fast_before_second_bind(monkeypatch):
    events = []
    counts = {"prewarm": 0, "probe": 0}

    class FakeRuntime:
        def __init__(self, *args, **kwargs):
            events.append("runtime")
            self.memory_db = "C:/memory.db"
            self.profiles = dict(DEFAULT_PROFILES)

        def prewarm_fast_startup(self):
            counts["prewarm"] += 1
            events.append("prewarm")
            return {"ok": True, "model_instance_id": "fast-1"}

        def _probe_exact_fast_residency(self, profile, *, expected_id=None):
            counts["probe"] += 1
            events.append("revalidate")
            assert profile.model == DEFAULT_PROFILES["fast"].model
            assert profile.context_length == DEFAULT_PROFILES["fast"].context_length
            assert expected_id == "fast-1"
            return "fast-1"

        def close(self):
            events.append("runtime.close")

    monkeypatch.setattr(api, "SovereignTwinRuntime", FakeRuntime)
    _install_server_fakes(monkeypatch, events)

    api.serve(memory_db="C:/memory.db")
    api.serve(memory_db="C:/memory.db")

    assert counts == {"prewarm": 1, "probe": 1}
    assert events.count("server.bind") == 2
    assert events.count("serve") == 2
    second_runtime = [i for i, value in enumerate(events) if value == "runtime"][1]
    second_bind = [i for i, value in enumerate(events) if value == "server.bind"][1]
    assert second_runtime < events.index("revalidate") < second_bind


def test_stale_cached_success_fails_closed_before_rebind_without_second_prewarm(
    monkeypatch,
):
    events = []
    counts = {"prewarm": 0, "probe": 0}

    class FakeRuntime:
        def __init__(self, *args, **kwargs):
            events.append("runtime")
            self.memory_db = "C:/memory.db"
            self.profiles = dict(DEFAULT_PROFILES)

        def prewarm_fast_startup(self):
            counts["prewarm"] += 1
            events.append("prewarm")
            return {"ok": True, "model_instance_id": "fast-1"}

        def _probe_exact_fast_residency(self, profile, *, expected_id=None):
            counts["probe"] += 1
            events.append("revalidate.missing")
            assert expected_id == "fast-1"
            return None

        def close(self):
            events.append("runtime.close")

    monkeypatch.setattr(api, "SovereignTwinRuntime", FakeRuntime)
    _install_server_fakes(monkeypatch, events)

    api.serve(memory_db="C:/memory.db")

    with pytest.raises(
        LocalModelEndpointError,
        match="cached success no longer proves exact resident FAST",
    ):
        api.serve(memory_db="C:/memory.db")

    # Revalidation failure is sticky: later serve attempts cannot trigger a
    # second startup prewarm/model effect.
    with pytest.raises(LocalModelEndpointError, match="retry refused"):
        api.serve(memory_db="C:/memory.db")

    assert counts == {"prewarm": 1, "probe": 1}
    assert events.count("server.bind") == 1
    assert events.count("serve") == 1
    assert events.count("prewarm") == 1
