from __future__ import annotations

import pytest

import continuityos.sovereign_twin_runtime as runtime_module
from continuityos.sovereign_twin_runtime import (
    DEFAULT_PROFILES,
    LmStudioClient,
    LocalModelEndpointError,
    SovereignTwinRuntime,
    _FastResidencyUnsafeError,
    _looks_like_fast_load_ack_timeout,
)

FAST = DEFAULT_PROFILES["fast"]


def model_row(instances):
    return [{"key": FAST.model, "loaded_instances": instances}]


def instance(i="fast-1", ctx=8192):
    return {"id": i, "config": {"context_length": ctx, "parallel": 1}}


class FakeClient:
    def __init__(self, states, *, load_outcome="fast-1", load_timeout=600.0, legacy=False):
        self.states = list(states)
        self.load_outcome = load_outcome
        self.load_timeout = load_timeout
        self.load_calls = []
        self.models_calls = 0
        if legacy:
            self.load_fast_for_acquisition = None

    def models(self):
        self.models_calls += 1
        if not self.states:
            return model_row([])
        value = self.states.pop(0) if len(self.states) > 1 else self.states[0]
        if isinstance(value, BaseException):
            raise value
        return value

    def load_fast_for_acquisition(self, **kwargs):
        self.load_calls.append(("bounded", kwargs))
        outcome = self.load_outcome
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome

    def load_for_acquisition(self, **kwargs):
        self.load_calls.append(("deep-bounded", kwargs))
        raise AssertionError("FAST must never call historical DEEP load_for_acquisition")

    def load(self, **kwargs):
        self.load_calls.append(("legacy", kwargs))
        outcome = self.load_outcome
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome


def runtime_with(client):
    rt = SovereignTwinRuntime.__new__(SovereignTwinRuntime)
    rt.client = client
    rt.profiles = dict(DEFAULT_PROFILES)
    return rt


def timeout_error():
    low = TimeoutError("timed out")
    high = LocalModelEndpointError(
        "LM Studio/llmster request failed: TimeoutError: timed out"
    )
    high.__cause__ = low
    return high


def http_error_message():
    return LocalModelEndpointError(
        "LM Studio/llmster request failed: HTTPError: HTTP Error 500: Internal Server Error"
    )


def capacity_error():
    return LocalModelEndpointError(
        "LM Studio model load failed: insufficient system resources"
    )


def install_fake_clock(monkeypatch, *, start=100.0, step=0.25):
    now = {"v": start}

    def perf():
        return now["v"]

    def sleep(seconds):
        now["v"] += max(float(seconds), step)

    monkeypatch.setattr(runtime_module, "perf_counter", perf)
    monkeypatch.setattr(runtime_module, "sleep", sleep)
    return now


def test_warm_exact_fast_returns_without_load():
    c = FakeClient([model_row([instance()])])
    rt = runtime_with(c)
    assert rt._ensure_fast_loaded(FAST) == "fast-1"
    assert c.load_calls == []


def test_warm_duplicate_fast_fails_closed():
    c = FakeClient([model_row([instance("a"), instance("b")])])
    rt = runtime_with(c)
    with pytest.raises(_FastResidencyUnsafeError, match="exactly one"):
        rt._ensure_fast_loaded(FAST)
    assert c.load_calls == []


def test_warm_wrong_context_fails_closed():
    c = FakeClient([model_row([instance(ctx=4096)])])
    rt = runtime_with(c)
    with pytest.raises(_FastResidencyUnsafeError, match="context_length mismatch"):
        rt._ensure_fast_loaded(FAST)
    assert c.load_calls == []


def test_cold_normal_ack_requires_matching_exact_residency():
    c = FakeClient(
        [model_row([]), model_row([instance("ack-1")])],
        load_outcome="ack-1",
    )
    rt = runtime_with(c)
    assert rt._ensure_fast_loaded(FAST) == "ack-1"
    assert len(c.load_calls) == 1
    kind, args = c.load_calls[0]
    assert kind == "bounded"
    assert args["model"] == FAST.model
    assert args["context_length"] == 8192
    assert args["ack_timeout"] == runtime_module.FAST_LOAD_ACK_TIMEOUT_SECONDS


def test_cold_normal_ack_identity_mismatch_fails():
    c = FakeClient(
        [model_row([]), model_row([instance("other")])],
        load_outcome="ack-1",
    )
    rt = runtime_with(c)
    with pytest.raises(_FastResidencyUnsafeError, match="instance id mismatch"):
        rt._ensure_fast_loaded(FAST)
    assert len(c.load_calls) == 1


def test_timeout_reconciles_exact_residency_without_second_load(monkeypatch):
    install_fake_clock(monkeypatch)
    transient = LocalModelEndpointError(
        "catalog transient 500 Model does not exist"
    )
    c = FakeClient(
        [
            model_row([]),
            transient,
            model_row([]),
            model_row([instance("fast-timeout")]),
        ],
        load_outcome=timeout_error(),
        load_timeout=10.0,
    )
    rt = runtime_with(c)
    assert rt._ensure_fast_loaded(FAST) == "fast-timeout"
    assert len(c.load_calls) == 1
    assert c.load_calls[0][0] == "bounded"
    assert c.load_calls[0][1]["ack_timeout"] == 10.0


def test_timeout_duplicate_residency_fails_closed(monkeypatch):
    install_fake_clock(monkeypatch)
    c = FakeClient(
        [model_row([]), model_row([instance("a"), instance("b")])],
        load_outcome=timeout_error(),
        load_timeout=5.0,
    )
    rt = runtime_with(c)
    with pytest.raises(_FastResidencyUnsafeError, match="exactly one"):
        rt._ensure_fast_loaded(FAST)
    assert len(c.load_calls) == 1


def test_timeout_wrong_context_fails_closed(monkeypatch):
    install_fake_clock(monkeypatch)
    c = FakeClient(
        [model_row([]), model_row([instance("a", ctx=4096)])],
        load_outcome=timeout_error(),
        load_timeout=5.0,
    )
    rt = runtime_with(c)
    with pytest.raises(_FastResidencyUnsafeError, match="context_length mismatch"):
        rt._ensure_fast_loaded(FAST)
    assert len(c.load_calls) == 1


def test_timeout_budget_expiry_fails_without_second_load(monkeypatch):
    install_fake_clock(monkeypatch, step=0.5)
    c = FakeClient(
        [model_row([])],
        load_outcome=timeout_error(),
        load_timeout=1.0,
    )
    rt = runtime_with(c)
    with pytest.raises(
        LocalModelEndpointError,
        match="original load_timeout budget expired",
    ):
        rt._ensure_fast_loaded(FAST)
    assert len(c.load_calls) == 1


def test_http_error_never_reconciles_as_timeout():
    c = FakeClient([model_row([])], load_outcome=http_error_message())
    rt = runtime_with(c)
    with pytest.raises(
        LocalModelEndpointError,
        match="FAST explicit load failed before chat",
    ):
        rt._ensure_fast_loaded(FAST)
    assert len(c.load_calls) == 1
    assert c.models_calls == 1


def test_capacity_error_never_reconciles_as_timeout():
    c = FakeClient([model_row([])], load_outcome=capacity_error())
    rt = runtime_with(c)
    with pytest.raises(
        LocalModelEndpointError,
        match="FAST explicit load failed before chat",
    ):
        rt._ensure_fast_loaded(FAST)
    assert len(c.load_calls) == 1
    assert c.models_calls == 1


def test_timeout_classifier_transport_only():
    assert _looks_like_fast_load_ack_timeout(timeout_error()) is True
    assert _looks_like_fast_load_ack_timeout(http_error_message()) is False
    assert _looks_like_fast_load_ack_timeout(capacity_error()) is False


def test_custom_legacy_client_falls_back_to_r21e_behavior():
    c = FakeClient(
        [model_row([])],
        load_outcome="legacy-id",
        legacy=True,
    )
    rt = runtime_with(c)
    assert rt._ensure_fast_loaded(FAST) == "legacy-id"
    assert c.load_calls == [
        ("legacy", {"model": FAST.model, "context_length": 8192})
    ]


def test_fast_never_calls_historical_deep_acquisition_loader():
    c = FakeClient(
        [model_row([])],
        load_outcome="legacy-id",
        legacy=True,
    )
    rt = runtime_with(c)
    assert rt._ensure_fast_loaded(FAST) == "legacy-id"
    assert not any(kind == "deep-bounded" for kind, _ in c.load_calls)


def test_lmstudio_fast_loader_bounds_only_ack_wait():
    client = LmStudioClient(load_timeout=600.0)
    calls = []

    def fake_request(method, path, payload=None, *, timeout=None):
        calls.append((method, path, payload, timeout))
        return {
            "status": "loaded",
            "instance_id": "fast-prod-1",
            "load_config": {"context_length": 8192},
        }

    client._request = fake_request
    assert client.load_fast_for_acquisition(
        model=FAST.model,
        context_length=8192,
        ack_timeout=runtime_module.FAST_LOAD_ACK_TIMEOUT_SECONDS,
    ) == "fast-prod-1"
    assert calls[-1][0:2] == ("POST", "/api/v1/models/load")
    assert calls[-1][2] == {
        "model": FAST.model,
        "context_length": 8192,
        "echo_load_config": True,
    }
    assert calls[-1][3] == runtime_module.FAST_LOAD_ACK_TIMEOUT_SECONDS
    assert client.load_timeout == 600.0

    client.load_fast_for_acquisition(
        model=FAST.model,
        context_length=8192,
        ack_timeout=900.0,
    )
    assert calls[-1][3] == 600.0


def test_deep_method_is_inherited_byte_behavior():
    import continuityos.sovereign_twin_runtime_r21e as retained

    assert SovereignTwinRuntime._ask_deep is retained.SovereignTwinRuntime._ask_deep


def test_default_fast_profile_unchanged():
    assert FAST.model == "qwen3.5-4b"
    assert FAST.context_length == 8192
    assert FAST.reasoning == "off"
    assert FAST.max_output_tokens == 1200
    assert FAST.temperature == 0.2
    assert FAST.unload_after_answer is False
    assert FAST.expected_parallel == 1
