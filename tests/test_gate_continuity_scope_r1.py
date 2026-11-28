"""The gate must evaluate the scope selected by its trusted Continuity object."""
from __future__ import annotations

import pytest

from continuityos.continuity import Continuity
from continuityos.db import (
    CONTEXT_DIGEST_SCHEME,
    SCOPED_CONTEXT_DIGEST_SCHEME,
    context_fingerprint,
    context_identity,
    context_read_snapshot,
)
from continuityos.gate import ActionSpec, preflight
from continuityos.memory import Memory
from continuityos.store import StoreOutcomeUnknown, StoreRecoveryFailed


@pytest.fixture
def memory(tmp_path):
    value = Memory(str(tmp_path / "synthetic-gate-context.db"))
    yield value
    value.store.con.close()


def _action(tmp_path, **meta):
    # Only assess a harmless argv; these tests do not execute a command.
    return ActionSpec(tool="exec", command="echo export archive",
                      args=["echo", "export", "archive"], cwd=str(tmp_path), meta=meta)


def test_gate_preserves_trusted_scope_and_global_canon(memory, tmp_path):
    Continuity(memory).add_canon("Never export the shared archive.")
    selected = Continuity(memory, project="A", subject="robert")
    selected.add_canon("Never export the client archive.")
    Continuity(memory, project="B", subject="robert").add_canon(
        "Never export the foreign project archive.")
    Continuity(memory, project="A", subject="other").add_canon(
        "Never export the foreign subject archive.")

    # Caller-supplied selection metadata cannot override the trusted object.
    result = preflight(_action(tmp_path, project="B", subject="other",
                               context_scope={"project": "B", "subject": "other"}),
                       context=selected)

    assert result["decision"] == "REQUIRE_CONFIRMATION"
    assert result["context"]["error"] is None
    assert set(result["context"]["conflicts"]) == {
        "Never export the shared archive.", "Never export the client archive."}
    assert not any("foreign" in reason for reason in result["reasons"])


def test_preflight_scope_cannot_change_between_digest_and_evaluation(memory, tmp_path, monkeypatch):
    import continuityos.db as db

    context = Continuity(memory, project="A", subject="robert")
    context._context_source = "fixture:trusted-context"
    context.add_canon("Never export the selected archive.")
    Continuity(memory, project="B", subject="other").add_canon(
        "Never export the foreign archive.")
    expected_identity = context_identity(context)
    original_identity = db.context_identity

    def mutate_original_after_digest(selected):
        identity = original_identity(selected)
        context.project = "B"
        context.subject = "other"
        context._context_source = "fixture:changed-context"
        return identity

    monkeypatch.setattr(db, "context_identity", mutate_original_after_digest)
    result = preflight(_action(tmp_path), context=context)

    assert (context.project, context.subject) == ("B", "other")
    assert result["decision"] == "REQUIRE_CONFIRMATION"
    assert result["context"]["error"] is None
    assert result["context"]["identity"] == expected_identity
    assert result["context"]["conflicts"] == ["Never export the selected archive."]


@pytest.mark.parametrize("scope", [
    {"project": "A", "subject": "robert"},
    {"project": "A"},
    {"subject": "robert"},
])
def test_scoped_rule_alone_escalates_an_otherwise_allowed_action(memory, tmp_path, scope):
    selected = Continuity(memory, **scope)
    selected.add_canon("Never export the archive.")
    action = _action(tmp_path)
    assert preflight(action)["decision"] == "ALLOW"

    result = preflight(action, context=selected)

    assert result["decision"] == "REQUIRE_CONFIRMATION"
    assert result["context"]["conflicts"] == ["Never export the archive."]
    assert result["context"]["error"] is None


@pytest.mark.parametrize("context_type", ["continuity", "memory"])
def test_unscoped_gate_retains_legacy_global_rules(memory, tmp_path, context_type):
    unscoped = Continuity(memory)
    unscoped.add_canon("Never export the shared archive.")
    Continuity(memory, project="A", subject="robert").add_canon(
        "Never export the scoped archive.")

    context = unscoped if context_type == "continuity" else memory
    result = preflight(_action(tmp_path), context=context)

    assert result["decision"] == "REQUIRE_CONFIRMATION"
    assert result["context"]["conflicts"] == ["Never export the shared archive."]
    assert result["context"]["error"] is None


@pytest.mark.parametrize(("field", "value"), [("project", ""), ("subject", ["robert"])])
def test_malformed_trusted_scope_holds_instead_of_falling_back(memory, tmp_path, field, value):
    context = Continuity(memory, project="A", subject="robert")
    context.add_canon("Never export the archive.")
    # Constructor validation cannot protect against later in-process corruption.
    setattr(context, field, value)

    with pytest.raises(ValueError, match=f"{field} must be a non-empty string or None"):
        context_identity(context)
    result = preflight(_action(tmp_path), context=context)

    assert result["decision"] == "HOLD"
    assert result["context"]["conflicts"] == []
    assert f"{field} must be a non-empty string or None" in result["context"]["error"]


def test_same_database_different_scopes_have_distinct_context_digests(memory):
    Continuity(memory).add_canon("Never export the shared archive.")
    selections = [
        {"project": "A", "subject": "robert"},
        {"project": "B", "subject": "robert"},
        {"project": "A", "subject": "other"},
        {"project": "A", "subject": None},
        {"project": None, "subject": "robert"},
    ]
    base = context_fingerprint(memory.store.path)
    scoped = [context_identity(Continuity(memory, **scope)) for scope in selections]

    assert len({identity["context_sha256"] for identity in scoped}) == len(selections)
    for scope, identity in zip(selections, scoped):
        assert identity["scope"] == scope
        assert identity["scheme"] == SCOPED_CONTEXT_DIGEST_SCHEME
        assert identity["database_context_scheme"] == CONTEXT_DIGEST_SCHEME
        assert identity["database_context_sha256"] == base["context_sha256"]
        assert identity["context_sha256"] != base["context_sha256"]
        assert identity["path_sha256"] == base["path_sha256"]
        assert identity == context_identity(Continuity(memory, **scope))


@pytest.mark.parametrize("context_type", ["continuity", "memory"])
def test_unscoped_identity_is_unchanged_database_fingerprint(memory, context_type):
    Continuity(memory).add_canon("Never export the shared archive.")
    Continuity(memory, project="A").add_canon("Never export the scoped archive.")
    context = Continuity(memory) if context_type == "continuity" else memory

    assert context_identity(context) == context_fingerprint(memory.store.path)


def test_scoped_preflight_receipt_binds_scope_and_current_database(memory, tmp_path):
    from continuityos.gate import Ledger

    selected = Continuity(memory, project="A", subject="robert")
    selected.add_canon("Never export the archive.")
    before = context_identity(selected)
    selected.add_canon("Never export the second archive.")
    with Ledger(str(tmp_path / "receipt-ledger.db")) as ledger:
        result = preflight(_action(tmp_path), context=selected, ledger=ledger)
        event = ledger.event(result["ledger_hash"])

    after = context_identity(selected)
    assert before["context_sha256"] != after["context_sha256"]
    assert before["database_context_sha256"] != after["database_context_sha256"]
    assert result["context"]["identity"] == after
    assert event["payload"]["context"]["identity"] == after


def test_context_snapshot_prohibits_managed_writes(memory):
    context = Continuity(memory, project="A")
    with context_read_snapshot(context):
        context_identity(context)
        with pytest.raises(PermissionError, match="MEMORY_WRITE_DURING_READ_SNAPSHOT"):
            context.add_canon("Never persist a write from a read snapshot.")

    assert memory.count() == 0
    assert memory.store.con.in_transaction is False


def test_suspended_store_cannot_supply_identity_or_preflight(memory, tmp_path, monkeypatch):
    context = Continuity(memory, project="A")
    # Leave the handle open to prove the suspension guard, not a closed-SQL error.
    monkeypatch.setattr(memory.store, "_suspended", True)

    with pytest.raises(StoreOutcomeUnknown, match="MEMORY_STORE_SUSPENDED"):
        context_identity(context)
    with pytest.raises(StoreOutcomeUnknown, match="MEMORY_STORE_SUSPENDED"):
        with context_read_snapshot(context):
            pytest.fail("suspended store entered a read snapshot")
    result = preflight(_action(tmp_path), context=context)

    assert result["decision"] == "HOLD"
    assert result["context"]["identity"] is None
    assert "MEMORY_STORE_SUSPENDED" in result["context"]["error"]


def test_context_snapshot_recovery_failure_suspends_real_store(memory):
    class FailedRollback:
        def __init__(self, connection):
            self.connection = connection

        def __getattr__(self, name):
            return getattr(self.connection, name)

        def rollback(self):
            raise RuntimeError("injected unavailable rollback")

    memory.store.con = FailedRollback(memory.store.con)
    with pytest.raises(StoreRecoveryFailed, match="MEMORY_READ_SNAPSHOT_RECOVERY_FAILED"):
        with context_read_snapshot(Continuity(memory, project="A")):
            memory.store.con.execute("SELECT 1")

    assert memory.store._suspended is True
    with pytest.raises(StoreOutcomeUnknown, match="MEMORY_STORE_SUSPENDED"):
        context_identity(memory)


@pytest.mark.parametrize("caller_context", ["omitted", "forged_unscoped"])
def test_legacy_executor_rejects_ledger_scoped_receipt_before_effects(
    memory, tmp_path, monkeypatch, capsys, caller_context,
):
    from continuityos.gate import cli
    from continuityos.gate.ledger import Ledger

    action = _action(tmp_path)
    ledger_path = str(tmp_path / "scoped-execution-ledger.db")
    with Ledger(ledger_path) as ledger:
        result = preflight(action, context=Continuity(memory, project="A"), ledger=ledger)
    assert result["decision"] == "ALLOW"
    # The broker omits caller context; a caller can also supply an unscoped copy.
    # Neither may replace the actual identity bound into the ledger event.
    if caller_context == "omitted":
        result.pop("context")
    else:
        result["context"] = {"identity": context_fingerprint(memory.store.path)}

    def forbidden(*args, **kwargs):
        pytest.fail("scoped review receipt reached an execution side effect")

    monkeypatch.setattr(Ledger, "claim_execution_attempt", forbidden)
    monkeypatch.setattr(cli, "_materialize_rollback", forbidden)
    monkeypatch.setattr(cli.subprocess, "call", forbidden)
    outcome = {}

    code = cli._execute_approved(action.command, "exec", result, argv=action.args,
                                 ledger_path=ledger_path, execution_cwd=str(tmp_path),
                                 outcome=outcome)

    assert code == 1
    assert "legacy executor has no scoped execution contract" in capsys.readouterr().out
    assert outcome == {}
    with Ledger(ledger_path) as ledger:
        assert ledger._attempt_row(result["ledger_hash"]) is None
        assert [event["kind"] for event in ledger.export(10)] == ["preflight"]


def test_unscoped_receipt_still_passes_legacy_execution_binding(memory, tmp_path):
    from continuityos.gate import cli
    from continuityos.gate.ledger import Ledger

    action = _action(tmp_path)
    ledger_path = str(tmp_path / "legacy-execution-ledger.db")
    with Ledger(ledger_path) as ledger:
        result = preflight(action, context=Continuity(memory), ledger=ledger)

    assert result["decision"] == "ALLOW"
    assert cli._execution_binding_error(
        action.command, "exec", result, action.args,
        ledger_path=ledger_path, execution_cwd=str(tmp_path),
    ) == ""
