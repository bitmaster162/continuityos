from __future__ import annotations

import os
from pathlib import Path

import pytest

import continuityos.current_effect_boundary as boundary
import continuityos.api as api
import continuityos.bus as bus
from continuityos.gate.current_ledger import Ledger as CurrentLedger
from continuityos.gate.current_preflight import preflight as current_preflight
from continuityos.gate.ledger import Ledger as LegacyLedger
from continuityos.gate.spec import ActionSpec
from continuityos.store import Store


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


def test_no_binding_is_legacy(monkeypatch):
    clear_binding(monkeypatch)
    state = boundary.inspect_current_session()
    assert state["mode"] == boundary.MODE_LEGACY
    assert boundary.effective_read_only(False) is False
    assert boundary.assert_current_effect_allowed("test.effect") is None


def test_partial_binding_is_revise_and_never_legacy(monkeypatch):
    clear_binding(monkeypatch)
    monkeypatch.setenv(boundary.ENV_CHALLENGE, "challenge.json")
    state = boundary.inspect_current_session()
    assert state["mode"] == boundary.MODE_REVISE
    with pytest.raises(boundary.CurrentEffectBoundaryError):
        boundary.effective_read_only(False)
    with pytest.raises(boundary.CurrentEffectBoundaryError):
        boundary.assert_current_effect_allowed("test.effect")


def test_verified_current_binding_is_read_only_and_effects_hold(monkeypatch):
    clear_binding(monkeypatch)
    set_current(monkeypatch)
    state = boundary.inspect_current_session()
    assert state["mode"] == boundary.MODE_CURRENT
    assert state["binding_verified"] is True
    assert state["authority_generation"] == "R64"
    assert state["session_effect_ceiling"] == "READ_ONLY"
    assert state["authority_ceiling"] == "NO_FURTHER_AGENT_WORK"
    assert boundary.effective_read_only(False) is True
    with pytest.raises(boundary.CurrentEffectBoundaryError) as exc:
        boundary.assert_current_effect_allowed("memory.write")
    receipt = exc.value.to_dict()
    assert receipt["terminal"] == "CURRENT_EFFECT_HOLD"
    assert receipt["effects"]["memory_write"] is False
    assert receipt["effects"]["can_trade"] is False
    assert receipt["effects"]["capital_permission"] == "DENY"


def test_core_store_is_forced_read_only_and_existing_object_cannot_write(monkeypatch, tmp_path):
    clear_binding(monkeypatch)
    db = tmp_path / "memory.db"
    legacy = Store(str(db))
    legacy.add("before", namespace="facts")
    assert legacy.count() == 1

    # Binding appears after this writable object already exists: write methods must
    # still re-check the boundary instead of trusting constructor-time state.
    set_current(monkeypatch)
    with pytest.raises(boundary.CurrentEffectBoundaryError):
        legacy.add("after", namespace="facts")
    assert legacy.count() == 1
    legacy.con.close()

    current = Store(str(db))
    assert current.read_only is True
    assert current.count() == 1
    with pytest.raises(boundary.CurrentEffectBoundaryError):
        current.delete(1)
    assert current.count() == 1
    current.con.close()


def test_current_store_never_creates_missing_database(monkeypatch, tmp_path):
    clear_binding(monkeypatch)
    set_current(monkeypatch)
    db = tmp_path / "missing.db"
    with pytest.raises(Exception):
        Store(str(db))
    assert not db.exists()


def test_public_preflight_holds_before_legacy_policy_or_ledger(monkeypatch):
    clear_binding(monkeypatch)
    set_current(monkeypatch)

    class ExplodingLedger:
        def append(self, *args, **kwargs):
            raise AssertionError("current preflight must not write legacy ledger")

    spec = ActionSpec(tool="shell", command="echo safe", args=[], paths=[], cwd="/tmp")
    result = current_preflight(
        spec,
        policy={"default_decision": "ALLOW", "allowed_tools": ["shell"]},
        ledger=ExplodingLedger(),
        context=None,
    )
    assert result["decision"] == "HOLD"
    assert result["execution_authorized"] is False
    assert result["legacy_policy_evaluated"] is False
    assert result["legacy_ledger_write"] is False
    assert result["current_authority"]["authority_generation"] == "R64"


def test_public_ledger_current_mode_reads_existing_but_never_appends(monkeypatch, tmp_path):
    clear_binding(monkeypatch)
    path = tmp_path / "ledger.db"
    legacy = LegacyLedger(str(path))
    legacy.append("seed", {"x": 1})
    legacy.close()

    set_current(monkeypatch)
    ledger = CurrentLedger(str(path))
    assert ledger.read_only is True
    assert ledger.verify()["ok"] is True
    assert len(ledger.export()) == 1
    with pytest.raises(boundary.CurrentEffectBoundaryError):
        ledger.append("blocked", {"x": 2})
    ledger.close()

    clear_binding(monkeypatch)
    check = LegacyLedger(str(path))
    assert len(check.export()) == 1
    check.close()


def test_public_ledger_current_mode_does_not_create_missing_file(monkeypatch, tmp_path):
    clear_binding(monkeypatch)
    set_current(monkeypatch)
    path = tmp_path / "missing-ledger.db"
    with pytest.raises(FileNotFoundError):
        CurrentLedger(str(path))
    assert not path.exists()


def test_http_server_start_is_blocked_before_server_or_memory(monkeypatch, tmp_path):
    clear_binding(monkeypatch)
    set_current(monkeypatch)
    db = tmp_path / "api.db"
    with pytest.raises(boundary.CurrentEffectBoundaryError):
        api.run(str(db), host="127.0.0.1", port=0)
    assert not db.exists()


def test_bus_write_token_and_write_dispatch_are_blocked_but_read_token_is_pure(monkeypatch):
    clear_binding(monkeypatch)
    set_current(monkeypatch)

    token = bus.mint_token("secret", "reader", scope="read", ttl=60)
    assert token.startswith("reader.read.")
    with pytest.raises(boundary.CurrentEffectBoundaryError):
        bus.mint_token("secret", "writer", scope="write", ttl=60)

    class FakeMemory:
        def __init__(self):
            self.writes = 0
        def upsert(self, *args, **kwargs):
            self.writes += 1
            return 1
        def remember(self, *args, **kwargs):
            self.writes += 1
            return 1

    mem = FakeMemory()
    dispatch = bus.build_dispatch(mem)
    with pytest.raises(boundary.CurrentEffectBoundaryError):
        dispatch["memory.upsert"]({"text": "x", "namespace": "facts", "key": "k"})
    with pytest.raises(boundary.CurrentEffectBoundaryError):
        dispatch["memory.remember"]({"text": "x"})
    assert mem.writes == 0


def test_bus_server_start_is_blocked_before_socket_creation(monkeypatch):
    clear_binding(monkeypatch)
    set_current(monkeypatch)
    with pytest.raises(boundary.CurrentEffectBoundaryError):
        bus.serve(object(), "secret", host="127.0.0.1", port=0)


def test_gate_public_lazy_mapping_points_to_current_adapters():
    import continuityos.gate as gate
    assert gate._LAZY["preflight"] == (".current_preflight", "preflight")
    assert gate._LAZY["Ledger"] == (".current_ledger", "Ledger")
