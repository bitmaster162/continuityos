from __future__ import annotations

import hashlib
import json
from pathlib import Path

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


def write_spec(path, effect_ceiling="READ_ONLY"):
    path.write_text(json.dumps({"effect_ceiling": effect_ceiling}), encoding="utf-8")


def install_success_preparer(monkeypatch, calls):
    def fake_prepare(boot, spec, output):
        output = Path(output)
        output.mkdir(parents=True)
        spec_sha = hashlib.sha256(Path(spec).read_bytes()).hexdigest()
        (output / "COLD_START_CHALLENGE.json").write_text(
            json.dumps({"session_spec": {"sha256": spec_sha}}),
            encoding="utf-8",
        )
        calls.append((Path(boot), Path(spec), output))
        return {
            "schema": "ANTI_AMNESIA_COLD_START_PREPARE_RECEIPT_V1",
            "output_dir": str(output),
            "status": "COLD_START_CHALLENGE_READY",
            "writes_performed": ["COLD_START_CHALLENGE.json"],
            "can_trade": False,
            "capital_permission": "DENY",
        }

    monkeypatch.setattr(cli, "prepare_cold_start_challenge", fake_prepare)


def test_prepare_cold_start_accepts_later_human_decision_read_only(
    tmp_path, monkeypatch
):
    bundle = tmp_path / "bundle.json"
    spec = tmp_path / "spec.json"
    output = tmp_path / "out"
    write_spec(spec, "READ_ONLY")
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
    install_success_preparer(monkeypatch, calls)

    result = cli.prepare_state_bound_cold_start(
        bundle,
        tmp_path / "boot.json",
        spec,
        output,
    )

    assert result["terminal"] == "STATE_BOUND_COLD_START_PASS"
    assert result["selected_artifact_id"] == "OPERATIONAL_CLOSURE"
    assert result["current_status"] == "PASS_WITH_CONDITIONS"
    assert result["requested_effect_ceiling"] == "READ_ONLY"
    assert result["production_qualified"] is False
    assert result["evidence_debt"] is True
    assert len(calls) == 1
    assert calls[0][2] != output
    assert output.is_dir()
    assert result["cold_start"]["output_dir"] == str(output.resolve())
    assert result["effects"]["deployment"] is False
    assert result["effects"]["current_state_apply"] is False


def test_conditional_acceptance_blocks_non_read_only_before_preparer(tmp_path, monkeypatch):
    bundle = tmp_path / "bundle.json"
    spec = tmp_path / "spec.json"
    output = tmp_path / "out"
    write_spec(spec, "REVERSIBLE_LOCAL_IMPLEMENTATION")
    write_bundle(
        bundle,
        [
            candidate(
                "HUMAN_DECISION",
                "PASS_WITH_CONDITIONS",
                "2026-07-31T03:00:00Z",
                "DECISION",
                evidence_debt=True,
            )
        ],
    )

    def forbidden(*args, **kwargs):
        raise AssertionError("cold-start preparer must not be called")

    monkeypatch.setattr(cli, "prepare_cold_start_challenge", forbidden)
    result = cli.prepare_state_bound_cold_start(
        bundle, tmp_path / "boot.json", spec, output
    )

    assert result["terminal"] == "STATE_BOUND_COLD_START_HOLD"
    assert result["reason"] == "CONDITIONAL_STATE_REQUIRES_READ_ONLY"
    assert result["requested_effect_ceiling"] == "REVERSIBLE_LOCAL_IMPLEMENTATION"
    assert result["allowed_effect_ceiling"] == "READ_ONLY"
    assert result["writes_performed"] == []
    assert not output.exists()


def test_full_pass_can_retain_existing_non_read_only_effect_ceiling(tmp_path, monkeypatch):
    bundle = tmp_path / "bundle.json"
    spec = tmp_path / "spec.json"
    output = tmp_path / "out"
    write_spec(spec, "REVERSIBLE_LOCAL_IMPLEMENTATION")
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
    calls = []
    install_success_preparer(monkeypatch, calls)

    result = cli.prepare_state_bound_cold_start(
        bundle, tmp_path / "boot.json", spec, output
    )

    assert result["terminal"] == "STATE_BOUND_COLD_START_PASS"
    assert result["requested_effect_ceiling"] == "REVERSIBLE_LOCAL_IMPLEMENTATION"
    assert len(calls) == 1
    assert output.is_dir()


def test_prepare_cold_start_blocks_open_state_without_calling_preparer(tmp_path, monkeypatch):
    bundle = tmp_path / "bundle.json"
    write_bundle(bundle, [candidate("TEMPLATE", "OPEN", "2026-08-09T00:00:00Z", "OPEN")])

    def forbidden(*args, **kwargs):
        raise AssertionError("cold-start preparer must not be called")

    monkeypatch.setattr(cli, "prepare_cold_start_challenge", forbidden)
    result = cli.prepare_state_bound_cold_start(
        bundle,
        tmp_path / "boot.json",
        tmp_path / "missing-spec.json",
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
        tmp_path / "missing-spec.json",
        tmp_path / "out",
    )

    assert result["terminal"] == "STATE_BOUND_COLD_START_HOLD"
    assert result["reason"] == "STATE_RESOLUTION_NOT_PASS"
    assert result["state_resolution"]["reason"] == "FRESH_CURRENT_CONTRADICTION"
    assert result["writes_performed"] == []


def test_generated_challenge_must_bind_exact_prechecked_spec(tmp_path, monkeypatch, capsys):
    bundle = tmp_path / "bundle.json"
    spec = tmp_path / "spec.json"
    output = tmp_path / "out"
    write_spec(spec, "READ_ONLY")
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

    def mismatched_prepare(boot, spec_path, temp_output):
        temp_output = Path(temp_output)
        temp_output.mkdir(parents=True)
        (temp_output / "COLD_START_CHALLENGE.json").write_text(
            json.dumps({"session_spec": {"sha256": "0" * 64}}),
            encoding="utf-8",
        )
        return {
            "output_dir": str(temp_output),
            "writes_performed": ["COLD_START_CHALLENGE.json"],
        }

    monkeypatch.setattr(cli, "prepare_cold_start_challenge", mismatched_prepare)
    code = cli.main(
        [
            "prepare-cold-start",
            "--input",
            str(bundle),
            "--boot-receipt",
            str(tmp_path / "boot.json"),
            "--spec",
            str(spec),
            "--output",
            str(output),
        ]
    )
    result = json.loads(capsys.readouterr().out)

    assert code == 2
    assert result["terminal"] == "STATE_BOUND_COLD_START_REVISE"
    assert "spec changed" in result["error"]
    assert not output.exists()
    assert not list(tmp_path.glob(".out.state-bound-*"))


def test_prepare_cold_start_cli_revises_on_invalid_cold_start_input(tmp_path, monkeypatch, capsys):
    bundle = tmp_path / "bundle.json"
    spec = tmp_path / "spec.json"
    write_spec(spec, "READ_ONLY")
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
            str(spec),
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
