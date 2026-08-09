from __future__ import annotations

import json

import continuityos.operational_memory_apply_cli as cli


def test_cli_pass_returns_zero(monkeypatch, capsys):
    monkeypatch.setattr(
        cli,
        "apply_authorized_memory_delta",
        lambda *args: {
            "schema": "continuityos.operational_memory.apply_receipt/v1",
            "terminal": "CURRENT_MEMORY_APPLY_PASS",
            "reason": "AUTHORIZED_ATOMIC_SHADOW_MEMORY_DELTA_APPLIED",
            "shadow_memory_apply": "APPLIED",
            "accepted_truth_modified": False,
            "execution_authorized": False,
            "can_trade": False,
            "capital_permission": "DENY",
            "deploy_permission": "DENY",
            "effects": {"operational_memory_write": True, "canonical_mutation": False},
        },
    )
    code = cli.main([
        "--operational-db", "memory.db",
        "--proposal", "proposal.json",
        "--authorization", "authorization.json",
    ])
    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["terminal"] == "CURRENT_MEMORY_APPLY_PASS"
    assert payload["accepted_truth_modified"] is False


def test_cli_already_applied_is_idempotent_success(monkeypatch, capsys):
    monkeypatch.setattr(
        cli,
        "apply_authorized_memory_delta",
        lambda *args: {
            "schema": "continuityos.operational_memory.apply_receipt/v1",
            "terminal": "CURRENT_MEMORY_APPLY_ALREADY_APPLIED",
            "reason": "EXACT_PROPOSAL_ALREADY_APPLIED",
            "shadow_memory_apply": "NOT_APPLIED",
            "accepted_truth_modified": False,
            "execution_authorized": False,
            "can_trade": False,
            "capital_permission": "DENY",
            "deploy_permission": "DENY",
            "effects": {"operational_memory_write": False, "canonical_mutation": False},
        },
    )
    assert cli.main([
        "--operational-db", "memory.db",
        "--proposal", "proposal.json",
        "--authorization", "authorization.json",
    ]) == 0
    assert json.loads(capsys.readouterr().out)["terminal"] == "CURRENT_MEMORY_APPLY_ALREADY_APPLIED"


def test_cli_current_hold_returns_three(monkeypatch, capsys):
    monkeypatch.setattr(
        cli,
        "apply_authorized_memory_delta",
        lambda *args: {
            "schema": "continuityos.operational_memory.apply_receipt/v1",
            "terminal": "CURRENT_MEMORY_APPLY_HOLD",
            "reason": "CURRENT_SESSION_EFFECT_FORBIDDEN",
            "shadow_memory_apply": "NOT_APPLIED",
            "accepted_truth_modified": False,
            "execution_authorized": False,
            "can_trade": False,
            "capital_permission": "DENY",
            "deploy_permission": "DENY",
            "effects": {"operational_memory_write": False, "canonical_mutation": False},
        },
    )
    assert cli.main([
        "--operational-db", "memory.db",
        "--proposal", "proposal.json",
        "--authorization", "authorization.json",
    ]) == 3
    assert json.loads(capsys.readouterr().out)["terminal"] == "CURRENT_MEMORY_APPLY_HOLD"


def test_cli_revise_returns_two(monkeypatch, capsys):
    monkeypatch.setattr(
        cli,
        "apply_authorized_memory_delta",
        lambda *args: {
            "schema": "continuityos.operational_memory.apply_receipt/v1",
            "terminal": "CURRENT_MEMORY_APPLY_REVISE",
            "reason": "STALE_OPERATIONAL_MEMORY_BASE",
            "shadow_memory_apply": "NOT_APPLIED",
            "accepted_truth_modified": False,
            "execution_authorized": False,
            "can_trade": False,
            "capital_permission": "DENY",
            "deploy_permission": "DENY",
            "effects": {"operational_memory_write": False, "canonical_mutation": False},
        },
    )
    assert cli.main([
        "--operational-db", "memory.db",
        "--proposal", "proposal.json",
        "--authorization", "authorization.json",
    ]) == 2
    assert json.loads(capsys.readouterr().out)["reason"] == "STALE_OPERATIONAL_MEMORY_BASE"
