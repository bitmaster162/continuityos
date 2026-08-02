from __future__ import annotations

import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from continuityos.gate.work_admission import (
    ADMISSION_PASS,
    DELTA_PASS,
    DELTA_REVISE,
    canonical_json_text,
    sha256_bytes,
    sha256_file,
    verify_work_admission,
    verify_work_delta,
)
from continuityos.gate.work_validation import (
    EVIDENCE_PASS,
    EVIDENCE_REVISE,
    EXECUTION_PASS,
    EXECUTION_REVISE,
    execute_work_validation,
    verify_work_validation_evidence,
)


def run(argv: list[str], cwd: Path) -> str:
    return subprocess.run(argv, cwd=cwd, text=True, capture_output=True, check=True).stdout.strip()


class ValidationFixture:
    def __init__(
        self,
        root: Path,
        *,
        command: list[str] | None = None,
        command_overrides: dict | None = None,
        network_access: str = "DENY",
        dependency_install: str = "DENY",
        max_install_attempts: int = 0,
    ):
        self.root = root
        self.repo = root / "repo"
        self.repo.mkdir()
        run(["git", "init", "-b", "gpt/base"], self.repo)
        run(["git", "config", "user.name", "Test"], self.repo)
        run(["git", "config", "user.email", "test@example.invalid"], self.repo)
        (self.repo / "src").mkdir()
        (self.repo / "src" / "base.py").write_text("VALUE = 1\n", encoding="utf-8")
        run(["git", "add", "."], self.repo)
        run(["git", "commit", "-m", "baseline"], self.repo)
        self.base_head = run(["git", "rev-parse", "HEAD"], self.repo)
        self.base_tree = run(["git", "rev-parse", "HEAD^{tree}"], self.repo)
        run(["git", "remote", "add", "origin", "https://github.com/bitmaster162/test-repo.git"], self.repo)

        self.work_order = root / "WORK_ORDER.md"
        self.work_order.write_text("# Validation evidence task\n", encoding="utf-8")
        self.capsule = root / "SESSION_CAPSULE.json"
        self.request = root / "REQUEST.json"
        self.admission = root / "ADMISSION.json"
        self.output = root / "evidence"

        cmd = {
            "id": "focused",
            "argv": command or ["python", "-c", "print('raw-evidence-ok')"],
            "cwd": "repo",
            "kind": "FOCUSED",
            "timeout_seconds": 30,
            "max_stdout_bytes": 1024 * 1024,
            "max_stderr_bytes": 1024 * 1024,
        }
        if command_overrides:
            cmd.update(command_overrides)
        self.command = cmd
        self.network_access = network_access
        self.dependency_install = dependency_install
        self.max_install_attempts = max_install_attempts
        self._write_inputs()

    def _request_obj(self) -> dict:
        return {
            "schema": "continuityos.work_admission.request/v1",
            "authority_generation": "R63",
            "task": {
                "task_id": "TEST_WORK_VALIDATION_EVIDENCE_V1",
                "task_body_sha256": sha256_file(self.work_order),
                "terminal_condition": "Raw evidence verified; stop.",
            },
            "repository": {
                "owner": "bitmaster162",
                "name": "test-repo",
                "remote_url": "https://github.com/bitmaster162/test-repo.git",
                "visibility": "PRIVATE",
                "visibility_change": False,
                "base_branch": "gpt/base",
                "base_head": self.base_head,
                "base_tree": self.base_tree,
                "candidate_branch": "gpt/candidate",
                "default_branch": "main",
                "remote_readback_mode": "DENY",
                "existing_candidate_head": None,
            },
            "scope": {
                "allowed_paths": ["src", "tests", "docs"],
                "forbidden_paths": [],
                "max_changed_files": 5,
                "max_added_bytes": 10000,
                "max_commits": 2,
                "allow_new_files": True,
                "allow_deletions": False,
                "allow_binary_files": False,
                "allow_archive_files": False,
            },
            "workspace": {
                "mode": "DISPOSABLE_CLONE_REQUIRED",
                "allowed_root_prefixes": [str(self.root.resolve())],
                "forbidden_root_prefixes": [],
            },
            "effects": {
                "worktree_write": True,
                "test_execution": True,
                "local_commit": True,
                "candidate_push": False,
                "workflow_changes": False,
                "force_push": False,
                "merge": False,
                "pull_request_merge": False,
                "deployment": False,
                "registry_apply": False,
                "current_state_apply": False,
                "r63_apply": False,
                "trading": False,
                "wallet_access": False,
                "order_execution": False,
                "external_message": False,
                "self_application": False,
                "can_trade": False,
                "capital_permission": "DENY",
                "deploy_permission": "DENY",
            },
            "session": {"required_role": "GPT", "capsule_sha256": "0" * 64},
            "validation": {
                "required_commands": [self.command],
                "network_access": self.network_access,
                "dependency_install": self.dependency_install,
                "max_full_suite_runs": 1,
                "max_install_attempts": self.max_install_attempts,
                "raw_evidence_required": True,
                "continue_on_failure": False,
                "max_total_output_bytes": 2 * 1024 * 1024,
            },
            "evidence": {},
        }

    def _write_inputs(self) -> None:
        request = self._request_obj()
        capsule = {
            "schema": "control.memory.session_capsule.v1",
            "authority_generation": "R63",
            "role": "GPT",
            "active_task": {
                "task_id": request["task"]["task_id"],
                "task_body_sha256": request["task"]["task_body_sha256"],
            },
            "repository": {
                "owner": request["repository"]["owner"],
                "name": request["repository"]["name"],
                "base_branch": request["repository"]["base_branch"],
                "base_head": request["repository"]["base_head"],
                "base_tree": request["repository"]["base_tree"],
                "candidate_branch": request["repository"]["candidate_branch"],
            },
            "allowed_paths": request["scope"]["allowed_paths"],
            "workspace": request["workspace"],
            "terminal_condition": request["task"]["terminal_condition"],
            "effects": request["effects"],
            "can_trade": False,
            "capital_permission": "DENY",
            "deploy_permission": "DENY",
            "self_application": False,
        }
        self.capsule.write_text(json.dumps(capsule), encoding="utf-8")
        request["session"]["capsule_sha256"] = sha256_file(self.capsule)
        self.request.write_text(json.dumps(request), encoding="utf-8")

    def prepare(self) -> dict:
        receipt = verify_work_admission(self.request, self.work_order, self.capsule, self.repo)
        self.assert_status(receipt["status"], ADMISSION_PASS)
        self.admission.write_text(json.dumps(receipt), encoding="utf-8")
        run(["git", "switch", "-c", "gpt/candidate"], self.repo)
        (self.repo / "src" / "feature.py").write_text("FEATURE = 1\n", encoding="utf-8")
        run(["git", "add", "."], self.repo)
        run(["git", "commit", "-m", "candidate"], self.repo)
        return receipt

    @staticmethod
    def assert_status(actual: str, expected: str) -> None:
        if actual != expected:
            raise AssertionError(f"expected {expected}, observed {actual}")


class WorkValidationEvidenceTests(unittest.TestCase):
    def test_execute_and_verify_raw_evidence(self):
        with tempfile.TemporaryDirectory() as td:
            fx = ValidationFixture(Path(td)); fx.prepare()
            result = execute_work_validation(
                fx.admission, fx.repo, fx.output,
                expected_admission_receipt_sha256=sha256_file(fx.admission),
            )
            self.assertEqual(result["status"], EXECUTION_PASS)
            verification = verify_work_validation_evidence(
                fx.output, fx.admission, fx.repo,
                expected_admission_receipt_sha256=sha256_file(fx.admission),
            )
            self.assertEqual(verification["status"], EVIDENCE_PASS)
            self.assertIn(b"raw-evidence-ok", (fx.output / "raw/focused.stdout.bin").read_bytes())

    def test_tampered_raw_output_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            fx = ValidationFixture(Path(td)); fx.prepare()
            execute_work_validation(fx.admission, fx.repo, fx.output, expected_admission_receipt_sha256=sha256_file(fx.admission))
            (fx.output / "raw/focused.stdout.bin").write_bytes(b"tampered")
            verification = verify_work_validation_evidence(
                fx.output, fx.admission, fx.repo,
                expected_admission_receipt_sha256=sha256_file(fx.admission),
            )
            self.assertEqual(verification["status"], EVIDENCE_REVISE)

    def test_missing_raw_output_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            fx = ValidationFixture(Path(td)); fx.prepare()
            execute_work_validation(fx.admission, fx.repo, fx.output, expected_admission_receipt_sha256=sha256_file(fx.admission))
            (fx.output / "raw/focused.stderr.bin").unlink()
            verification = verify_work_validation_evidence(
                fx.output, fx.admission, fx.repo,
                expected_admission_receipt_sha256=sha256_file(fx.admission),
            )
            self.assertEqual(verification["status"], EVIDENCE_REVISE)

    def test_timeout_is_revise(self):
        with tempfile.TemporaryDirectory() as td:
            fx = ValidationFixture(
                Path(td),
                command=["python", "-c", "__import__('time').sleep(2)"],
                command_overrides={"timeout_seconds": 1},
            )
            fx.prepare()
            result = execute_work_validation(
                fx.admission, fx.repo, fx.output,
                expected_admission_receipt_sha256=sha256_file(fx.admission),
            )
            self.assertEqual(result["status"], EXECUTION_REVISE)

    def test_output_limit_is_revise(self):
        with tempfile.TemporaryDirectory() as td:
            fx = ValidationFixture(
                Path(td),
                command=["python", "-c", "print('x'*10000)"],
                command_overrides={"max_stdout_bytes": 100},
            )
            fx.prepare()
            result = execute_work_validation(
                fx.admission, fx.repo, fx.output,
                expected_admission_receipt_sha256=sha256_file(fx.admission),
            )
            self.assertEqual(result["status"], EXECUTION_REVISE)

    def test_output_capture_hard_cap_prevents_file_overshoot(self):
        with tempfile.TemporaryDirectory() as td:
            fx = ValidationFixture(
                Path(td),
                command=["python", "-c", "__import__('sys').stdout.write('x' * (8 * 1024 * 1024))"],
                command_overrides={"max_stdout_bytes": 4096},
            )
            fx.prepare()
            result = execute_work_validation(
                fx.admission, fx.repo, fx.output,
                expected_admission_receipt_sha256=sha256_file(fx.admission),
            )
            self.assertEqual(result["status"], EXECUTION_REVISE)
            self.assertLessEqual((fx.output / "raw/focused.stdout.bin").stat().st_size, 4096)

    def test_raw_evidence_requires_disposable_workspace(self):
        with tempfile.TemporaryDirectory() as td:
            fx = ValidationFixture(Path(td)); fx.prepare()
            admission = json.loads(fx.admission.read_text(encoding="utf-8"))
            admission["request"]["workspace"] = {
                "mode": "ANY_CLEAN_GIT_ROOT",
                "allowed_root_prefixes": [],
                "forbidden_root_prefixes": [],
            }
            # Rebuild binding to make the test exercise request normalization,
            # not a stale binding hash.
            binding = admission["binding"]
            binding["workspace"] = admission["request"]["workspace"]
            admission["admission_binding_sha256"] = sha256_bytes(
                canonical_json_text(binding).encode("utf-8")
            )
            fx.admission.write_text(json.dumps(admission), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "DISPOSABLE_CLONE_REQUIRED"):
                execute_work_validation(
                    fx.admission, fx.repo, fx.output,
                    expected_admission_receipt_sha256=sha256_file(fx.admission),
                )

    def test_candidate_must_be_inside_admitted_disposable_root(self):
        with tempfile.TemporaryDirectory() as td, tempfile.TemporaryDirectory() as outside:
            fx = ValidationFixture(Path(td)); fx.prepare()
            outside_repo = Path(outside) / "candidate"
            subprocess.run(["git", "clone", str(fx.repo), str(outside_repo)], check=True, capture_output=True)
            subprocess.run(["git", "remote", "set-url", "origin", "https://github.com/bitmaster162/continuityos.git"], cwd=outside_repo, check=True)
            with self.assertRaisesRegex(ValueError, "outside every allowed disposable"):
                execute_work_validation(
                    fx.admission, outside_repo, Path(outside) / "evidence",
                    expected_admission_receipt_sha256=sha256_file(fx.admission),
                )

    def test_repo_mutation_by_validation_is_revise(self):
        with tempfile.TemporaryDirectory() as td:
            fx = ValidationFixture(
                Path(td),
                command=[
                    "python", "-c",
                    "__import__('pathlib').Path('src/base.py').write_text('changed')",
                ],
            )
            fx.prepare()
            result = execute_work_validation(
                fx.admission, fx.repo, fx.output,
                expected_admission_receipt_sha256=sha256_file(fx.admission),
            )
            self.assertEqual(result["status"], EXECUTION_REVISE)

    def test_output_inside_repo_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            fx = ValidationFixture(Path(td)); fx.prepare()
            with self.assertRaises(ValueError):
                execute_work_validation(
                    fx.admission, fx.repo, fx.repo / "evidence",
                    expected_admission_receipt_sha256=sha256_file(fx.admission),
                )

    def test_delta_requires_raw_evidence(self):
        with tempfile.TemporaryDirectory() as td:
            fx = ValidationFixture(Path(td)); fx.prepare()
            execute_work_validation(fx.admission, fx.repo, fx.output, expected_admission_receipt_sha256=sha256_file(fx.admission))
            validation = fx.output / "WORK_VALIDATION_RECEIPT.json"
            no_evidence = verify_work_delta(
                fx.admission,
                validation,
                fx.repo,
                expected_admission_receipt_sha256=sha256_file(fx.admission),
            )
            self.assertEqual(no_evidence["status"], DELTA_REVISE)
            with_evidence = verify_work_delta(
                fx.admission,
                validation,
                fx.repo,
                expected_admission_receipt_sha256=sha256_file(fx.admission),
                validation_evidence_dir=fx.output,
            )
            self.assertEqual(with_evidence["status"], DELTA_PASS)


    def test_packaged_validation_schemas_are_parseable(self):
        from importlib import resources

        root = resources.files("continuityos.work_validation_schemas")
        names = sorted(item.name for item in root.iterdir() if item.name.endswith(".json"))
        self.assertEqual(len(names), 4)
        for name in names:
            obj = json.loads(root.joinpath(name).read_text(encoding="utf-8"))
            self.assertEqual(obj.get("$schema"), "https://json-schema.org/draft/2020-12/schema")

    def test_network_capable_command_denied_when_network_is_deny(self):
        with tempfile.TemporaryDirectory() as td:
            fx = ValidationFixture(Path(td), command=["git", "ls-remote", "https://example.invalid/repo.git"])
            fx.prepare()
            result = execute_work_validation(
                fx.admission, fx.repo, fx.output,
                expected_admission_receipt_sha256=sha256_file(fx.admission),
            )
            self.assertEqual(result["status"], EXECUTION_REVISE)

    def _refresh_manifest_ready(self, evidence: Path) -> None:
        rows = []
        for path in sorted(evidence.rglob("*")):
            if path.is_file() and path.name not in {"MANIFEST.json", "READY_FOR_VERIFY.json"}:
                rows.append({
                    "path": path.relative_to(evidence).as_posix(),
                    "bytes": path.stat().st_size,
                    "sha256": sha256_file(path),
                })
        manifest = {
            "schema": "continuityos.work_validation.evidence_manifest/v1",
            "created_at_utc": "2026-08-02T00:00:00+00:00",
            "files": rows,
        }
        (evidence / "MANIFEST.json").write_text(json.dumps(manifest), encoding="utf-8")
        receipt = json.loads((evidence / "WORK_VALIDATION_RECEIPT.json").read_text(encoding="utf-8"))
        ready = {
            "schema": "continuityos.work_validation.ready/v1",
            "created_at_utc": "2026-08-02T00:00:00+00:00",
            "status": receipt["status"],
            "validation_receipt_sha256": sha256_file(evidence / "WORK_VALIDATION_RECEIPT.json"),
            "manifest_sha256": sha256_file(evidence / "MANIFEST.json"),
            "candidate_head": receipt["candidate_head"],
            "candidate_tree": receipt["candidate_tree"],
            "written_last": True,
        }
        (evidence / "READY_FOR_VERIFY.json").write_text(json.dumps(ready), encoding="utf-8")

    def test_command_launch_failure_is_evidenced_revise(self):
        with tempfile.TemporaryDirectory() as td:
            fx = ValidationFixture(Path(td), command=["definitely-missing-executable-xyz"])
            fx.prepare()
            result = execute_work_validation(
                fx.admission, fx.repo, fx.output,
                expected_admission_receipt_sha256=sha256_file(fx.admission),
            )
            self.assertEqual(result["status"], EXECUTION_REVISE)
            self.assertTrue((fx.output / "WORK_VALIDATION_RECEIPT.json").is_file())
            self.assertTrue((fx.output / "READY_FOR_VERIFY.json").is_file())

    def test_ready_status_conflict_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            fx = ValidationFixture(Path(td)); fx.prepare()
            execute_work_validation(fx.admission, fx.repo, fx.output, expected_admission_receipt_sha256=sha256_file(fx.admission))
            ready_path = fx.output / "READY_FOR_VERIFY.json"
            ready = json.loads(ready_path.read_text(encoding="utf-8"))
            ready["status"] = "WORK_VALIDATION_EXECUTION_REVISE"
            ready_path.write_text(json.dumps(ready), encoding="utf-8")
            verification = verify_work_validation_evidence(
                fx.output, fx.admission, fx.repo,
                expected_admission_receipt_sha256=sha256_file(fx.admission),
            )
            self.assertEqual(verification["status"], EVIDENCE_REVISE)

    def test_extra_evidence_file_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            fx = ValidationFixture(Path(td)); fx.prepare()
            execute_work_validation(fx.admission, fx.repo, fx.output, expected_admission_receipt_sha256=sha256_file(fx.admission))
            (fx.output / "unexpected.txt").write_text("x", encoding="utf-8")
            verification = verify_work_validation_evidence(
                fx.output, fx.admission, fx.repo,
                expected_admission_receipt_sha256=sha256_file(fx.admission),
            )
            self.assertEqual(verification["status"], EVIDENCE_REVISE)

    def test_forged_no_effect_rejected_even_with_resealed_manifest(self):
        with tempfile.TemporaryDirectory() as td:
            fx = ValidationFixture(Path(td)); fx.prepare()
            execute_work_validation(fx.admission, fx.repo, fx.output, expected_admission_receipt_sha256=sha256_file(fx.admission))
            no_effect_path = fx.output / "NO_EFFECT_RECEIPT.json"
            no_effect = json.loads(no_effect_path.read_text(encoding="utf-8"))
            no_effect["repository_head_unchanged"] = False
            no_effect_path.write_text(json.dumps(no_effect), encoding="utf-8")
            self._refresh_manifest_ready(fx.output)
            verification = verify_work_validation_evidence(
                fx.output, fx.admission, fx.repo,
                expected_admission_receipt_sha256=sha256_file(fx.admission),
            )
            self.assertEqual(verification["status"], EVIDENCE_REVISE)

    def test_raw_evidence_policy_tamper_rejected_after_reseal(self):
        with tempfile.TemporaryDirectory() as td:
            fx = ValidationFixture(Path(td)); fx.prepare()
            execute_work_validation(fx.admission, fx.repo, fx.output, expected_admission_receipt_sha256=sha256_file(fx.admission))
            receipt_path = fx.output / "WORK_VALIDATION_RECEIPT.json"
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            receipt["raw_evidence_required"] = False
            receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
            self._refresh_manifest_ready(fx.output)
            verification = verify_work_validation_evidence(
                fx.output, fx.admission, fx.repo,
                expected_admission_receipt_sha256=sha256_file(fx.admission),
            )
            self.assertEqual(verification["status"], EVIDENCE_REVISE)


    def test_direct_network_command_denied_even_when_read_only_network_is_admitted(self):
        with tempfile.TemporaryDirectory() as td:
            fx = ValidationFixture(
                Path(td),
                command=["git", "ls-remote", "https://example.invalid/repo.git"],
                network_access="READ_ONLY",
            )
            fx.prepare()
            result = execute_work_validation(
                fx.admission, fx.repo, fx.output,
                expected_admission_receipt_sha256=sha256_file(fx.admission),
            )
            self.assertEqual(result["status"], EXECUTION_REVISE)

    def test_locked_dependency_install_is_not_executed_without_setup_gate(self):
        with tempfile.TemporaryDirectory() as td:
            fx = ValidationFixture(
                Path(td),
                command=["python", "-m", "pip", "install", "example-package"],
                network_access="READ_ONLY",
                dependency_install="LOCKED_ONLY",
                max_install_attempts=1,
            )
            fx.prepare()
            result = execute_work_validation(
                fx.admission, fx.repo, fx.output,
                expected_admission_receipt_sha256=sha256_file(fx.admission),
            )
            self.assertEqual(result["status"], EXECUTION_REVISE)
            receipt = json.loads((fx.output / "WORK_VALIDATION_RECEIPT.json").read_text(encoding="utf-8"))
            self.assertTrue(receipt["dependency_install_command_attempted"])
            self.assertEqual(receipt["dependency_install_used"], "DENY")


if __name__ == "__main__":
    unittest.main()
