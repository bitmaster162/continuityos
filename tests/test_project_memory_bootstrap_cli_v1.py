from __future__ import annotations

import json

import continuityos.project_memory_bootstrap_cli as cli


def test_cli_pass_returns_zero(monkeypatch, capsys):
    monkeypatch.setattr(
        cli,
        "bootstrap_project_memory",
        lambda *args: {
            "schema": "continuityos.operational_memory.project_bootstrap_receipt/v1",
            "terminal": "PROJECT_MEMORY_BOOTSTRAP_PASS",
            "reason": "VERIFIED_PROJECT_MEMORY_PUBLISHED",
            "shadow_memory_bootstrap": "CREATED",
            "accepted_truth_modified": False,
            "execution_authorized": False,
            "can_trade": False,
            "capital_permission": "DENY",
            "deploy_permission": "DENY",
            "effects": {"operational_memory_write": True, "canonical_mutation": False},
        },
    )
    code = cli.main(["--db", "project.db", "--manifest", "manifest.json", "--authorization", "auth.json"])
    assert code == 0
    assert json.loads(capsys.readouterr().out)["terminal"] == "PROJECT_MEMORY_BOOTSTRAP_PASS"


def test_cli_exact_replay_is_zero(monkeypatch, capsys):
    monkeypatch.setattr(
        cli,
        "bootstrap_project_memory",
        lambda *args: {
            "schema": "continuityos.operational_memory.project_bootstrap_receipt/v1",
            "terminal": "PROJECT_MEMORY_BOOTSTRAP_ALREADY_CREATED",
            "reason": "EXACT_BOOTSTRAP_ALREADY_PUBLISHED",
            "shadow_memory_bootstrap": "NOT_CREATED",
            "accepted_truth_modified": False,
            "execution_authorized": False,
            "can_trade": False,
            "capital_permission": "DENY",
            "deploy_permission": "DENY",
            "effects": {"operational_memory_write": False, "canonical_mutation": False},
        },
    )
    assert cli.main(["--db", "project.db", "--manifest", "manifest.json", "--authorization", "auth.json"]) == 0
    assert json.loads(capsys.readouterr().out)["terminal"] == "PROJECT_MEMORY_BOOTSTRAP_ALREADY_CREATED"


def test_cli_current_hold_returns_three(monkeypatch, capsys):
    monkeypatch.setattr(
        cli,
        "bootstrap_project_memory",
        lambda *args: {
            "schema": "continuityos.operational_memory.project_bootstrap_receipt/v1",
            "terminal": "PROJECT_MEMORY_BOOTSTRAP_HOLD",
            "reason": "CURRENT_SESSION_EFFECT_FORBIDDEN",
            "shadow_memory_bootstrap": "NOT_CREATED",
            "accepted_truth_modified": False,
            "execution_authorized": False,
            "can_trade": False,
            "capital_permission": "DENY",
            "deploy_permission": "DENY",
            "effects": {"operational_memory_write": False, "canonical_mutation": False},
        },
    )
    assert cli.main(["--db", "project.db", "--manifest", "manifest.json", "--authorization", "auth.json"]) == 3


def test_cli_revise_returns_two(monkeypatch, capsys):
    monkeypatch.setattr(
        cli,
        "bootstrap_project_memory",
        lambda *args: {
            "schema": "continuityos.operational_memory.project_bootstrap_receipt/v1",
            "terminal": "PROJECT_MEMORY_BOOTSTRAP_REVISE",
            "reason": "BOOTSTRAP_ARTIFACT_INVALID",
            "shadow_memory_bootstrap": "NOT_CREATED",
            "accepted_truth_modified": False,
            "execution_authorized": False,
            "can_trade": False,
            "capital_permission": "DENY",
            "deploy_permission": "DENY",
            "effects": {"operational_memory_write": False, "canonical_mutation": False},
        },
    )
    assert cli.main(["--db", "project.db", "--manifest", "manifest.json", "--authorization", "auth.json"]) == 2
