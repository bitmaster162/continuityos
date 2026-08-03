from __future__ import annotations

from importlib.resources import files
import json
import subprocess
import sys
from pathlib import Path

from continuityos.control_plane_integration import load_effect_ceiling


ROOT = Path(__file__).resolve().parents[1]


EXPECTED_SCHEMA_RESOURCES = {
    "continuityos.work_validation_schemas": {
        "work_validation_evidence_manifest_v1.schema.json",
        "work_validation_evidence_verification_v1.schema.json",
        "work_validation_execution_receipt_v1.schema.json",
        "work_validation_ready_v1.schema.json",
    },
    "continuityos.work_ledger_schemas": {
        "work_ledger_event_v1.schema.json",
        "work_ledger_projection_v1.schema.json",
        "work_semantic_decision_v1.schema.json",
        "work_transport_receipt_v1.schema.json",
    },
    "continuityos.github_candidate_review_schemas": {
        "github_candidate_review_evaluation_v1.schema.json",
        "github_candidate_review_request_v1.schema.json",
        "github_candidate_semantic_decision_v1.schema.json",
        "github_candidate_transport_receipt_v1.schema.json",
    },
}


def _run_help(*args: str) -> str:
    proc = subprocess.run(
        [sys.executable, "-m", "continuityos.gate.cli", *args, "--help"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    return proc.stdout


def test_all_integrated_cli_surfaces_are_present() -> None:
    work_admission = _run_help("work-admission")
    work_ledger = _run_help("work-ledger")
    github_review = _run_help("github-review")

    assert "run-validation" in work_admission
    assert "verify-validation" in work_admission
    assert "verify-delta" in work_admission
    assert "verify-extension" in work_ledger
    assert "append-transport" in work_ledger
    assert "append-semantic" in work_ledger
    assert "evaluate" in github_review


def test_all_integrated_schema_packages_are_shipped() -> None:
    for package, expected_names in EXPECTED_SCHEMA_RESOURCES.items():
        package_root = files(package)
        observed_names = {
            entry.name
            for entry in package_root.iterdir()
            if entry.is_file() and entry.name.endswith(".json")
        }
        assert observed_names == expected_names
        for name in sorted(expected_names):
            payload = json.loads(package_root.joinpath(name).read_text(encoding="utf-8"))
            assert isinstance(payload, dict)
            assert payload.get("$schema") == "https://json-schema.org/draft/2020-12/schema"


def test_integration_document_preserves_effect_ceiling() -> None:
    manifest = load_effect_ceiling()
    assert manifest["schema"] == (
        "continuityos.github_control_plane_integration.effect_ceiling/v1"
    )
    assert manifest["authority_generation"] == "R63"
    assert manifest["terminal"] == "MERGE_CANDIDATE_ELIGIBLE"
    assert manifest["semantic"] == "proposal-only"
    assert manifest["effects"] == {
        "force_push": False,
        "merge_executed": False,
        "auto_merge": False,
        "deployment": False,
        "current_state_apply": False,
        "r63_apply": False,
        "registry_apply": False,
        "wallet_access": False,
        "order_execution": False,
        "trading": False,
        "can_trade": False,
        "capital_permission": "DENY",
        "deploy_permission": "DENY",
        "self_application": False,
    }

    # The installed wheel is validated from the packaged manifest.  In a source
    # checkout, also prove that the human-readable document states the same
    # terminal and effect ceiling.  The document is intentionally absent from
    # the isolated wheel suite.
    doc_path = ROOT / "docs" / "GITHUB_CONTROL_PLANE_INTEGRATION_V1.md"
    if doc_path.is_file():
        doc = doc_path.read_text(encoding="utf-8")
        assert manifest["terminal"] in doc
        assert manifest["semantic"] in doc
        assert "can_trade                       false" in doc
        assert "capital_permission              DENY" in doc
        assert "deploy_permission               DENY" in doc
