from __future__ import annotations

import json

import continuityos.project_update_post_preflight_materializer_cli as cli

ARGS = [
    "--packet", "packet.json",
    "--authorization", "authorization.json",
    "--preflight", "preflight.json",
    "--output-dir", "review",
]


def test_cli_pass_returns_zero(monkeypatch, capsys):
    monkeypatch.setattr(
        cli,
        "materialize_project_update_after_preflight",
        lambda *args: {
            "schema": cli.RECEIPT_SCHEMA,
            "terminal": "PROJECT_UPDATE_POST_PREFLIGHT_MATERIALIZATION_PASS",
            "execution_authorized": False,
        },
    )
    assert cli.main(ARGS) == 0
    assert json.loads(capsys.readouterr().out)["terminal"] == "PROJECT_UPDATE_POST_PREFLIGHT_MATERIALIZATION_PASS"


def test_cli_current_hold_returns_three(monkeypatch, capsys):
    monkeypatch.setattr(
        cli,
        "materialize_project_update_after_preflight",
        lambda *args: {
            "schema": cli.RECEIPT_SCHEMA,
            "terminal": "PROJECT_UPDATE_POST_PREFLIGHT_MATERIALIZATION_HOLD",
            "execution_authorized": False,
        },
    )
    assert cli.main(ARGS) == 3
    assert json.loads(capsys.readouterr().out)["terminal"] == "PROJECT_UPDATE_POST_PREFLIGHT_MATERIALIZATION_HOLD"


def test_cli_revise_returns_two(monkeypatch, capsys):
    monkeypatch.setattr(
        cli,
        "materialize_project_update_after_preflight",
        lambda *args: {
            "schema": cli.RECEIPT_SCHEMA,
            "terminal": "PROJECT_UPDATE_POST_PREFLIGHT_MATERIALIZATION_REVISE",
            "execution_authorized": False,
        },
    )
    assert cli.main(ARGS) == 2
