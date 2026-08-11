from __future__ import annotations

from importlib.resources import files
import json
import subprocess
import sys
from pathlib import Path

from continuityos.control_plane_policy import load_policy, policy_names
from continuityos.gate import (
    completion_claim,
    merge_authorization,
    merge_execution,
    work_ledger_review_binding,
)
from continuityos.gate.evidence_common import fixed_effects


ROOT = Path(__file__).resolve().parents[1]

SCHEMA_PACKAGES = {
    "continuityos.completion_claim_schemas": {
        "completion_claim_evaluation_v1.schema.json",
        "completion_claim_request_v1.schema.json",
        "completion_claim_test_receipt_v1.schema.json",
    },
    "continuityos.control_plane_binding_schemas": {
        "work_ledger_review_binding_evaluation_v1.schema.json",
        "work_ledger_review_binding_request_v1.schema.json",
    },
    "continuityos.merge_authorization_schemas": {
        "merge_authorization_branch_protection_receipt_v1.schema.json",
        "merge_authorization_evaluation_v1.schema.json",
        "merge_authorization_human_decision_v1.schema.json",
        "merge_authorization_pull_request_receipt_v1.schema.json",
        "merge_authorization_request_v1.schema.json",
        "merge_authorization_rollback_receipt_v1.schema.json",
    },
    "continuityos.merge_execution_schemas": {
        "merge_execution_authorization_consumption_v1.schema.json",
        "merge_execution_base_branch_readback_v1.schema.json",
        "merge_execution_branch_protection_readback_v1.schema.json",
        "merge_execution_evaluation_v1.schema.json",
        "merge_execution_host_receipt_v1.schema.json",
        "merge_execution_merge_commit_readback_v1.schema.json",
        "merge_execution_pull_request_readback_v1.schema.json",
        "merge_execution_request_v1.schema.json",
    },
}

POLICY_RESOURCES = {
    "completion_claim_policy_v1.json",
    "merge_authorization_policy_v1.json",
    "merge_execution_policy_v1.json",
    "work_ledger_review_binding_policy_v1.json",
}


def test_new_schema_packages_are_shipped_parseable_and_strict() -> None:
    ids: set[str] = set()
    observed_count = 0
    for package, expected_names in SCHEMA_PACKAGES.items():
        package_root = files(package)
        observed_names = {
            entry.name
            for entry in package_root.iterdir()
            if entry.is_file() and entry.name.endswith(".schema.json")
        }
        assert observed_names == expected_names
        observed_count += len(observed_names)
        for name in sorted(expected_names):
            value = json.loads(package_root.joinpath(name).read_text(encoding="utf-8"))
            assert value["$schema"] == "https://json-schema.org/draft/2020-12/schema"
            assert value["$id"].startswith("continuityos.")
            assert value["$id"] not in ids
            ids.add(value["$id"])
            assert value["type"] == "object"
            assert value.get("additionalProperties") in {False, True}
            assert isinstance(value.get("required"), list) and value["required"]
    assert observed_count == 19


def test_machine_readable_gate_policies_are_shipped_and_match_code() -> None:
    package_root = files("continuityos.control_plane_policy")
    observed_names = {
        entry.name
        for entry in package_root.iterdir()
        if entry.is_file() and entry.name.endswith(".json")
    }
    assert observed_names == POLICY_RESOURCES
    assert policy_names() == (
        "completion_claim",
        "merge_authorization",
        "merge_execution",
        "work_ledger_review_binding",
    )

    completion = load_policy("completion_claim")
    assert completion["schema"] == "continuityos.completion_claim.policy/v1"
    assert completion["authority_generation"] == "R63"
    assert completion["dimensions"] == {
        "work": list(completion_claim.WORK_STATES),
        "artifacts": list(completion_claim.ARTIFACT_STATES),
        "git_provider": list(completion_claim.GIT_STATES),
        "delivery_flags": ["USER_DOWNLOAD_EXPOSED", "DRIVE_READBACK_VERIFIED"],
        "semantic": ["ACCEPTED"],
    }
    assert completion["terminals"] == [
        completion_claim.PASS,
        completion_claim.HOLD,
        completion_claim.REVISE,
    ]
    assert completion["effects"] == fixed_effects()

    binding = load_policy("work_ledger_review_binding")
    assert binding["schema"] == (
        "continuityos.work_ledger_review_binding.policy/v1"
    )
    assert set(binding["required_bindings"]) == work_ledger_review_binding.BINDING_KEYS
    assert binding["pass_terminal"] == work_ledger_review_binding.PASS
    assert binding["pass_outcome"] == work_ledger_review_binding.PASS_OUTCOME
    assert binding["effects"] == fixed_effects()

    authorization = load_policy("merge_authorization")
    assert authorization["schema"] == "continuityos.merge_authorization.policy/v1"
    assert authorization["required_upstream"] == {
        "ledger_review_binding": work_ledger_review_binding.PASS,
        "candidate_review": "GITHUB_CANDIDATE_REVIEW_PASS",
        "candidate_outcome": "MERGE_CANDIDATE_ELIGIBLE",
    }
    assert authorization["supported_merge_method"] == "MERGE_COMMIT"
    assert authorization["pass_terminal"] == merge_authorization.PASS
    assert authorization["pass_outcome"] == merge_authorization.PASS_OUTCOME
    assert authorization["effects"] == fixed_effects()

    execution = load_policy("merge_execution")
    assert execution["schema"] == "continuityos.merge_execution.policy/v1"
    assert execution["required_upstream"] == {
        "merge_authorization": merge_authorization.PASS,
        "authorization_outcome": merge_authorization.PASS_OUTCOME,
    }
    assert execution["supported_merge_method"] == merge_execution.MERGE_METHOD
    assert execution["verified_terminal"] == merge_execution.VERIFIED
    assert execution["verified_outcome"] == merge_execution.VERIFIED_OUTCOME
    assert execution["effects"] == fixed_effects()


def test_source_packaging_policy_matches_installed_resource_contract() -> None:
    """In a checkout, verify pyproject. In a wheel, resource tests above suffice."""

    pyproject_path = ROOT / "pyproject.toml"
    if not pyproject_path.is_file():
        return
    pyproject = pyproject_path.read_text(encoding="utf-8")
    for package in (*SCHEMA_PACKAGES, "continuityos.control_plane_policy"):
        assert f'"{package}" = ["*.json"]' in pyproject


def test_new_cli_surfaces_are_importable_and_help_only() -> None:
    commands = (
        ["completion-claim", "verify", "--help"],
        ["control-plane-binding", "evaluate", "--help"],
        ["merge-authorization", "evaluate", "--help"],
        ["merge-execution", "evaluate", "--help"],
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


def test_source_docs_match_packaged_policy_when_docs_are_present() -> None:
    """Installed wheels use manifests; source checkouts also bind the docs."""

    completion_path = ROOT / "docs" / "COMPLETION_CLAIM_GATE_V1.md"
    binding_path = ROOT / "docs" / "WORK_LEDGER_REVIEW_BINDING_GATE_V1.md"
    authorization_path = ROOT / "docs" / "MERGE_AUTHORIZATION_GATE_V1.md"
    execution_path = ROOT / "docs" / "MERGE_EXECUTION_RECEIPT_GATE_V1.md"
    if not all(
        path.is_file()
        for path in (completion_path, binding_path, authorization_path, execution_path)
    ):
        return

    completion_doc = completion_path.read_text(encoding="utf-8")
    binding_doc = binding_path.read_text(encoding="utf-8")
    authorization_doc = authorization_path.read_text(encoding="utf-8")
    execution_doc = execution_path.read_text(encoding="utf-8")

    completion_policy = load_policy("completion_claim")
    binding_policy = load_policy("work_ledger_review_binding")
    authorization_policy = load_policy("merge_authorization")
    execution_policy = load_policy("merge_execution")

    assert "independent dimensions" in completion_doc
    assert "GitHub remote verification does not require Google Drive" in completion_doc
    for terminal in completion_policy["terminals"]:
        assert terminal in completion_doc
    assert binding_policy["pass_terminal"] in binding_doc
    assert binding_policy["pass_outcome"] in binding_doc
    assert authorization_policy["pass_outcome"] in authorization_doc
    assert "cannot execute the merge" in authorization_doc
    assert execution_policy["verified_terminal"] in execution_doc
    assert execution_policy["verified_outcome"] in execution_doc
    assert "never calls GitHub" in execution_doc
