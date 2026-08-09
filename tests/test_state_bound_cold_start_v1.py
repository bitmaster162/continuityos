from __future__ import annotations

import json

import continuityos.state_resolve_cli as cli
from continuityos.gate.state_resolution import CANDIDATE_SCHEMA


def candidate(kind, status, when, artifact_id, **extra):
    row = {
        "schema": CANDIDATE_SCHEMA,
        "subject": "P0_SECURITY",
        "artifact_id": artifact_id,
        "kind": kind,
        "status": status,
        "observed_at_utc": when,
    }
    row.update(extra)
    return row


def write_bundle(path, candidates):
    path.write_text(
        json.dumps({"schema": cli.BUNDLE_SCHEMA, "candidates": candidates}),
        encoding="utf-8",
    )


def test_prepare_cold_start_accepts_later_human_decision_and_calls_preparer(
    tmp_path, monkeypatch
):
    bundle = tmp_path / "bundle.json"
    write_bundle(
        bundle,
        [
            candidate("TEMPLATE", "OPEN", "2026-07-29T21:22:45Z", "P0_TEMPLATE"),
            candidate(
                "AUDIT",
                "PARTIAL",
                "2026-07-31T02:00:00Z",
                "BYTE_AUDIT",
                evidence_debt=True,
            ),
            candidate(
                "HUMAN_DECISION",
                "PASS_WITH_CONDITIONS",
                "2026-07-31T03:00:00Z",
                "OPERATIONAL_CLOSURE",
                evidence_debt=True,
            ),
        ],
    )
    calls = []

    def fake_prepare(boot, spec, output):
        calls.append((boot, spec, output))
        return {
            "schema": "ANTI_AMNESIA_COLD_START_PREPARE_RECEIPT_V1",
            "status": "COLD_START_CHALLENGE_READY",
            "writes_performed": ["COLD_START_CHALLENGE.json"],
            "can_trade": False,
            "capital_permission": "DENY",
        }

    monkeypatch.setattr(cli, "prepare_cold_start_challenge", fake_prepare)
    result = cli.prepare_state_bound_cold_start(
        bundle,
        tmp_path / "boot.json",
        tmp_path / "spec.json",
        tmp_path / "out",
    )

    assert result["terminal"] == "STATE_BOUND_COLD_START_PASS"
    assert result["selected_artifact_id"] == "OPERATIONAL_CLOSURE"
    assert result["current_status"] == "PASS_WITH_CONDITIONS"
    assert result["production_qualified"] is False
    assert result["evidence_debt"] is True
    assert len(calls) == 1
    assert result["effects"]["deployment"] is False
    assert result["effects"]["current_state_apply"] is False


def test_prepare_cold_start_blocks_open_state_without_calling_preparer(tmp_path, monkeypatch):
    bundle = tmp_path / "bundle.json"
    write_bundle(bundle, [candidate("TEMPLATE", "OPEN", "2026-08-09T00:00:00Z", "OPEN")])

    def forbidden(*args, **kwargs):
        raise AssertionError("cold-start preparer must not be called")

    monkeypatch.setattr(cli, "prepare_cold_start_challenge", forbidden)
    result = cli.prepare_state_bound_cold_start(
        bundle,
        tmp_path / "boot.json",
        tmp_path / "spec.json",
        tmp_path / "out",
    )

    assert result["terminal"] == "STATE_BOUND_COLD_START_HOLD"
    assert result["reason"] == "STATE_NOT_OPERATIONALLY_ACCEPTED"
    assert result["writes_performed"] == []


def test_prepare_cold_start_blocks_fresh_provider_contradiction(tmp_path, monkeypatch):
    bundle = tmp_path / "bundle.json"
    write_bundle(
        bundle,
        [
            candidate(
                "HUMAN_DECISION",
                "PASS_WITH_CONDITIONS",
                "2026-07-31T03:00:00Z",
                "DECISION",
                evidence_debt=True,
            ),
            candidate(
                "PROVIDER_READBACK",
                "OPEN",
                "2026-08-09T04:00:00Z",
                "FRESH_READBACK",
                current_observation=True,
            ),
        ],
    )

    def forbidden(*args, **kwargs):
        raise AssertionError("cold-start preparer must not be called")

    monkeypatch.setattr(cli, "prepare_cold_start_challenge", forbidden)
    result = cli.prepare_state_bound_cold_start(
        bundle,
        tmp_path / "boot.json",
        tmp_path / "spec.json",
        tmp_path / "out",
    )

    assert result["terminal"] == "STATE_BOUND_COLD_START_HOLD"
    assert result["reason"] == "STATE_RESOLUTION_NOT_PASS"
    assert result["state_resolution"]["reason"] == "FRESH_CURRENT_CONTRADICTION"
    assert result["writes_performed"] == []


def test_prepare_cold_start_cli_revises_on_invalid_cold_start_input(tmp_path, monkeypatch, capsys):
    bundle = tmp_path / "bundle.json"
    write_bundle(
        bundle,
        [
            candidate(
                "HUMAN_DECISION",
                "PASS",
                "2026-08-09T04:00:00Z",
                "DECISION",
                production_qualified=True,
            )
        ],
    )

    def fail_prepare(*args, **kwargs):
        raise ValueError("bad cold-start spec")

    monkeypatch.setattr(cli, "prepare_cold_start_challenge", fail_prepare)
    code = cli.main(
        [
            "prepare-cold-start",
            "--input",
            str(bundle),
            "--boot-receipt",
            str(tmp_path / "boot.json"),
            "--spec",
            str(tmp_path / "spec.json"),
            "--output",
            str(tmp_path / "out"),
        ]
    )
    result = json.loads(capsys.readouterr().out)

    assert code == 2
    assert result["terminal"] == "STATE_BOUND_COLD_START_REVISE"
    assert result["writes_performed"] == []
    assert result["effects"]["can_trade"] is False
    assert result["effects"]["capital_permission"] == "DENY"
