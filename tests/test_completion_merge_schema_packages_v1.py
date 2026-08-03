from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKAGES = (
    "completion_claim_schemas",
    "control_plane_binding_schemas",
    "merge_authorization_schemas",
)


def test_new_schema_packages_are_parseable_and_strict_at_top_level() -> None:
    files = []
    for package in PACKAGES:
        package_dir = ROOT / "continuityos" / package
        assert (package_dir / "__init__.py").is_file()
        files.extend(sorted(package_dir.glob("*.schema.json")))
    assert len(files) == 11
    ids = set()
    for path in files:
        value = json.loads(path.read_text(encoding="utf-8"))
        assert value["$schema"] == "https://json-schema.org/draft/2020-12/schema"
        assert value["$id"].startswith("continuityos.")
        assert value["$id"] not in ids
        ids.add(value["$id"])
        assert value["type"] == "object"
        assert value.get("additionalProperties") in {False, True}
        assert isinstance(value.get("required"), list) and value["required"]


def test_pyproject_packages_all_new_schemas() -> None:
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    for package in PACKAGES:
        assert f'"continuityos.{package}" = ["*.json"]' in pyproject


def test_new_cli_surfaces_are_importable_and_help_only() -> None:
    commands = (
        ["completion-claim", "verify", "--help"],
        ["control-plane-binding", "evaluate", "--help"],
        ["merge-authorization", "evaluate", "--help"],
    )
    for args in commands:
        result = subprocess.run(
            [sys.executable, "-m", "continuityos.gate.cli", *args],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        assert "usage:" in result.stdout.lower()


def test_docs_preserve_independent_state_axes_and_no_merge_ceiling() -> None:
    completion = (ROOT / "docs" / "COMPLETION_CLAIM_GATE_V1.md").read_text(
        encoding="utf-8"
    )
    authorization = (ROOT / "docs" / "MERGE_AUTHORIZATION_GATE_V1.md").read_text(
        encoding="utf-8"
    )
    assert "independent dimensions" in completion
    assert "GitHub remote verification does not require Google Drive" in completion
    assert "MERGE_EXECUTION_MAY_BE_REQUESTED_ONCE" in authorization
    assert "cannot execute the merge" in authorization
