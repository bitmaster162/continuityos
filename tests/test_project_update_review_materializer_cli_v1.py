from __future__ import annotations

import json

import continuityos.project_update_review_materializer_cli as cli


def test_cli_pass_returns_zero(monkeypatch, capsys):
    monkeypatch.setattr(
        cli,
        "materialize_project_update_review",
        lambda packet, out: {
            "schema": cli.RECEIPT_SCHEMA,
            "terminal": "PROJECT_UPDATE_MATERIALIZATION_PASS",
            "authorization_granted": False,
            "execution_authorized": False,
        },
    )
    code = cli.main(["--packet", "packet.json", "--output-dir", "review"])
    assert code == 0
    assert json.loads(capsys.readouterr().out)["terminal"] == "PROJECT_UPDATE_MATERIALIZATION_PASS"


def test_cli_current_hold_returns_three(monkeypatch, capsys):
    monkeypatch.setattr(
        cli,
        "materialize_project_update_review",
        lambda packet, out: {
            "schema": cli.RECEIPT_SCHEMA,
            "terminal": "PROJECT_UPDATE_MATERIALIZATION_HOLD",
            "authorization_granted": False,
            "execution_authorized": False,
        },
    )
    code = cli.main(["--packet", "packet.json", "--output-dir", "review"])
    assert code == 3
    assert json.loads(capsys.readouterr().out)["terminal"] == "PROJECT_UPDATE_MATERIALIZATION_HOLD"


def test_cli_revise_returns_two(monkeypatch, capsys):
    monkeypatch.setattr(
        cli,
        "materialize_project_update_review",
        lambda packet, out: {
            "schema": cli.RECEIPT_SCHEMA,
            "terminal": "PROJECT_UPDATE_MATERIALIZATION_REVISE",
            "authorization_granted": False,
            "execution_authorized": False,
        },
    )
    assert cli.main(["--packet", "packet.json", "--output-dir", "review"]) == 2
