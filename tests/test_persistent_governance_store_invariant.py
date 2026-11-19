from pathlib import Path

import pytest

from continuityos.durable_approval_replay import SQLiteApprovalReplayGuard
from continuityos.gate.broker import GateBroker
from continuityos.gate.ledger import Ledger
from continuityos.gate.witness import WitnessAuthority
from continuityos.persistent_governance_store import (
    require_persistent_governance_store_path,
    resolve_persistent_governance_store_path,
)


def test_shared_invariant_rejects_non_durable_and_implicit_locations(tmp_path: Path):
    invalid = (None, "", ":memory:", "file:governance.db", "relative/governance.db")
    for value in invalid:
        with pytest.raises(ValueError):
            require_persistent_governance_store_path(value)
    with pytest.raises(ValueError, match="control character"):
        require_persistent_governance_store_path(str(tmp_path / "bad\nname.db"))


def test_lexical_and_resolved_modes_are_separate(tmp_path: Path):
    path = tmp_path / "state" / "governance.db"
    assert require_persistent_governance_store_path(path) == path
    assert resolve_persistent_governance_store_path(path) == path.resolve()


def test_replay_guard_cannot_bypass_shared_invariant():
    with pytest.raises(ValueError, match="absolute path required"):
        SQLiteApprovalReplayGuard("relative-replay.sqlite3")


def test_execution_ledger_requires_explicit_absolute_store_path():
    with pytest.raises(ValueError, match="file-backed path required"):
        Ledger()
    with pytest.raises(ValueError, match="absolute path required"):
        Ledger("relative-ledger.db")


def test_gate_broker_rejects_relative_governance_store_overrides(tmp_path: Path):
    absolute_registry = tmp_path / "registry.db"
    absolute_ledger = tmp_path / "ledger.db"
    with pytest.raises(ValueError, match="absolute path required"):
        GateBroker(registry_path="registry.db", ledger_path=absolute_ledger)
    with pytest.raises(ValueError, match="absolute path required"):
        GateBroker(registry_path=absolute_registry, ledger_path="ledger.db")


def test_witness_preserves_absolute_lexical_authority_requirement(tmp_path: Path):
    absolute_ledger = tmp_path / "ledger.db"
    absolute_registry = tmp_path / "registry.db"
    with pytest.raises(ValueError, match="absolute path required"):
        WitnessAuthority("witness.json", absolute_ledger, absolute_registry)


def test_current_ledger_surface_cannot_restore_relative_path_semantics():
    from continuityos.gate.current_ledger import Ledger as CurrentLedger

    with pytest.raises(ValueError, match="absolute path required"):
        CurrentLedger("relative-current-ledger.db")
