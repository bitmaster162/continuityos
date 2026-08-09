from __future__ import annotations

import os
import sys

import pytest

import continuityos.current_effect_boundary as boundary
import continuityos.metering as metering
import continuityos.embedders as embedders


def clear_binding(monkeypatch):
    for name in (
        boundary.ENV_CHALLENGE,
        boundary.ENV_CHALLENGE_SHA,
        boundary.ENV_ACK,
        boundary.ENV_REQUIRED,
    ):
        monkeypatch.delenv(name, raising=False)


def set_current(monkeypatch):
    monkeypatch.setenv(boundary.ENV_CHALLENGE, "challenge.json")
    monkeypatch.setenv(boundary.ENV_CHALLENGE_SHA, "a" * 64)
    monkeypatch.setenv(boundary.ENV_ACK, "ack.json")
    monkeypatch.setattr(
        boundary,
        "verify_current_runtime_binding",
        lambda *args, **kwargs: {
            "terminal": "CURRENT_RUNTIME_BINDING_PASS",
            "binding_verified": True,
            "authority_generation": "R64",
            "challenge_id": "c" * 64,
            "challenge_sha256": "a" * 64,
            "ack_sha256": "b" * 64,
        },
    )


def assert_hold(exc):
    receipt = exc.value.to_dict()
    assert receipt["terminal"] == "CURRENT_EFFECT_HOLD"
    assert receipt["effects"]["filesystem_write"] is False
    assert receipt["effects"]["network_effect"] is False
    assert receipt["effects"]["can_trade"] is False
    assert receipt["effects"]["capital_permission"] == "DENY"


def test_metering_existing_legacy_object_loses_write_after_current_binding(monkeypatch, tmp_path):
    clear_binding(monkeypatch)
    path = tmp_path / "usage.db"
    meter = metering.Meter(str(path))
    assert getattr(meter.__class__, "__continuityos_r29_guarded__", False) is True
    assert meter.read_only is False
    meter.set_plan("alice", "pro")
    meter.record("alice", "gate.decision")
    assert meter.report("alice")["usage"]["gate.decision"]["used"] == 1

    set_current(monkeypatch)
    for call in (
        lambda: meter.set_plan("alice", "team"),
        lambda: meter.record("alice", "gate.decision"),
        lambda: meter.charge("alice", "gate.decision"),
    ):
        with pytest.raises(boundary.CurrentEffectBoundaryError) as exc:
            call()
        assert_hold(exc)

    # Read/report remains available; no hidden mutation occurred.
    report = meter.report("alice")
    assert report["plan"] == "pro"
    assert report["usage"]["gate.decision"]["used"] == 1
    meter.db.close()


def test_metering_current_mode_opens_existing_db_read_only(monkeypatch, tmp_path):
    clear_binding(monkeypatch)
    path = tmp_path / "usage.db"
    seed = metering.Meter(str(path))
    seed.set_plan("alice", "pro")
    seed.record("alice", "gate.decision", units=2)
    seed.db.close()

    set_current(monkeypatch)
    meter = metering.Meter(str(path))
    assert meter.read_only is True
    report = meter.report("alice")
    assert report["plan"] == "pro"
    assert report["usage"]["gate.decision"]["used"] == 2

    with pytest.raises(boundary.CurrentEffectBoundaryError):
        meter.set_plan("alice", "team")
    with pytest.raises(boundary.CurrentEffectBoundaryError):
        meter.record("alice", "gate.decision")
    with pytest.raises(boundary.CurrentEffectBoundaryError):
        meter.charge("alice", "gate.decision")
    meter.db.close()


def test_metering_current_mode_does_not_create_missing_db_or_directory(monkeypatch, tmp_path):
    clear_binding(monkeypatch)
    set_current(monkeypatch)
    path = tmp_path / "missing" / "usage.db"

    with pytest.raises(FileNotFoundError):
        metering.Meter(str(path))
    assert not path.exists()
    assert not path.parent.exists()

    with pytest.raises(boundary.CurrentEffectBoundaryError):
        metering.Meter(":memory:")


def test_meter_opened_read_only_never_becomes_writable_if_binding_is_cleared(monkeypatch, tmp_path):
    clear_binding(monkeypatch)
    path = tmp_path / "usage.db"
    seed = metering.Meter(str(path))
    seed.db.close()

    set_current(monkeypatch)
    meter = metering.Meter(str(path))
    assert meter.read_only is True

    clear_binding(monkeypatch)
    with pytest.raises(RuntimeError, match="opened read-only"):
        meter.record("alice", "gate.decision")
    with pytest.raises(RuntimeError, match="opened read-only"):
        meter.set_plan("alice", "pro")
    with pytest.raises(RuntimeError, match="opened read-only"):
        meter.charge("alice", "gate.decision")
    meter.db.close()


def test_partial_binding_never_falls_back_to_writable_meter(monkeypatch, tmp_path):
    clear_binding(monkeypatch)
    monkeypatch.setenv(boundary.ENV_CHALLENGE, "declared-but-incomplete.json")
    path = tmp_path / "usage.db"

    with pytest.raises(boundary.CurrentEffectBoundaryError) as exc:
        metering.Meter(str(path))
    assert exc.value.to_dict()["terminal"] == "CURRENT_EFFECT_REVISE"
    assert not path.exists()


def test_optional_embedder_constructors_hold_before_optional_loader_or_download(monkeypatch):
    clear_binding(monkeypatch)
    set_current(monkeypatch)

    cases = (
        (embedders.FastEmbedEmbedder, "embedder.fastembed.model_load"),
        (embedders.Model2VecEmbedder, "embedder.model2vec.model_load"),
        (embedders.SentenceTransformerEmbedder, "embedder.sentence_transformer.model_load"),
    )
    for cls, effect in cases:
        assert getattr(cls.__init__, "__continuityos_direct_effect_guarded__", False) is True
        with pytest.raises(boundary.CurrentEffectBoundaryError) as exc:
            cls()
        assert_hold(exc)
        assert exc.value.effect == effect


def test_partial_binding_blocks_optional_embedder_constructor_before_dependency_load(monkeypatch):
    clear_binding(monkeypatch)
    monkeypatch.setenv(boundary.ENV_CHALLENGE, "declared-but-incomplete.json")

    with pytest.raises(boundary.CurrentEffectBoundaryError) as exc:
        embedders.FastEmbedEmbedder()
    assert exc.value.to_dict()["terminal"] == "CURRENT_EFFECT_REVISE"


def test_r29_targets_remain_lazy_on_top_level_package_import():
    env = dict(os.environ)
    for name in (
        boundary.ENV_CHALLENGE,
        boundary.ENV_CHALLENGE_SHA,
        boundary.ENV_ACK,
        boundary.ENV_REQUIRED,
    ):
        env.pop(name, None)
    code = """
import sys, continuityos
names = {'continuityos.metering', 'continuityos.embedders'}
loaded = names.intersection(sys.modules)
assert not loaded, loaded
"""
    import subprocess
    proc = subprocess.run(
        [sys.executable, "-c", code],
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=20,
    )
    assert proc.returncode == 0, proc.stderr
