from __future__ import annotations

import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


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
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert '"continuityos.work_validation_schemas" = ["*.json"]' in pyproject
    assert '"continuityos.work_ledger_schemas" = ["*.json"]' in pyproject
    assert '"continuityos.github_candidate_review_schemas" = ["*.json"]' in pyproject


def test_integration_document_preserves_effect_ceiling() -> None:
    doc = (ROOT / "docs" / "GITHUB_CONTROL_PLANE_INTEGRATION_V1.md").read_text(
        encoding="utf-8"
    )
    assert "MERGE_CANDIDATE_ELIGIBLE" in doc
    assert "proposal-only" in doc
    assert "can_trade                       false" in doc
    assert "capital_permission              DENY" in doc
    assert "deploy_permission               DENY" in doc
