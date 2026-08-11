from __future__ import annotations

import json

from continuityos.state_resolve_cli import BUNDLE_SCHEMA, main
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
        json.dumps({"schema": BUNDLE_SCHEMA, "candidates": candidates}),
        encoding="utf-8",
    )


def test_cli_selects_later_human_decision_over_stale_open_template(tmp_path, capsys):
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

    assert main(["evaluate", "--input", str(bundle)]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["terminal"] == "STATE_RESOLUTION_PASS"
    assert out["selected"]["artifact_id"] == "OPERATIONAL_CLOSURE"
    assert out["operational_state"] == "ACCEPTED_WITH_CONDITIONS"
    assert out["stale_count"] == 2
    assert out["effects"]["current_state_apply"] is False


def test_cli_hold_exit_code_is_three(tmp_path, capsys):
    bundle = tmp_path / "empty.json"
    write_bundle(bundle, [])

    assert main(["evaluate", "--input", str(bundle)]) == 3
    out = json.loads(capsys.readouterr().out)
    assert out["terminal"] == "STATE_RESOLUTION_HOLD"
    assert out["reason"] == "NO_EVIDENCE"


def test_cli_rejects_duplicate_json_keys_fail_closed(tmp_path, capsys):
    bundle = tmp_path / "duplicate.json"
    bundle.write_text(
        '{"schema":"continuityos.state_resolution.bundle/v1",'
        '"schema":"continuityos.state_resolution.bundle/v1","candidates":[]}',
        encoding="utf-8",
    )

    assert main(["evaluate", "--input", str(bundle)]) == 2
    out = json.loads(capsys.readouterr().out)
    assert out["terminal"] == "STATE_RESOLUTION_REVISE"
    assert out["reason"] == "INPUT_INVALID"
    assert out["effects"]["can_trade"] is False
    assert out["effects"]["capital_permission"] == "DENY"


def test_cli_rejects_unknown_bundle_fields(tmp_path, capsys):
    bundle = tmp_path / "extra.json"
    bundle.write_text(
        json.dumps({"schema": BUNDLE_SCHEMA, "candidates": [], "unexpected": True}),
        encoding="utf-8",
    )

    assert main(["evaluate", "--input", str(bundle)]) == 2
    out = json.loads(capsys.readouterr().out)
    assert out["terminal"] == "STATE_RESOLUTION_REVISE"
    assert out["reason"] == "INPUT_INVALID"
