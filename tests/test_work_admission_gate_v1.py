from __future__ import annotations

import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from continuityos.gate.work_admission import (
    ADMISSION_HOLD,
    ADMISSION_PASS,
    ADMISSION_REVISE,
    DELTA_PASS,
    DELTA_REVISE,
    VALIDATION_SCHEMA,
    canonical_json_text,
    sha256_bytes,
    sha256_file,
    verify_work_admission,
    verify_work_delta,
)


def run(argv, cwd):
    return subprocess.run(argv, cwd=cwd, text=True, capture_output=True, check=True).stdout.strip()


class WorkFixture:
    def __init__(self, root: Path):
        self.root = root
        self.repo = root / "repo"
        self.repo.mkdir()
        run(["git", "init", "-b", "gpt/base"], self.repo)
        run(["git", "config", "user.name", "Test"], self.repo)
        run(["git", "config", "user.email", "test@example.invalid"], self.repo)
        (self.repo / "src").mkdir()
        (self.repo / "tests").mkdir()
        (self.repo / "src" / "base.py").write_text("VALUE = 1\n", encoding="utf-8")
        run(["git", "add", "."], self.repo)
        run(["git", "commit", "-m", "baseline"], self.repo)
        self.base_head = run(["git", "rev-parse", "HEAD"], self.repo)
        self.base_tree = run(["git", "rev-parse", "HEAD^{tree}"], self.repo)
        run(["git", "remote", "add", "origin", "https://github.com/bitmaster162/test-repo.git"], self.repo)
        self.work_order = root / "WORK_ORDER.md"
        self.work_order.write_text("# Work order\n", encoding="utf-8")
        self.task_sha = sha256_file(self.work_order)
        self.capsule = root / "SESSION_CAPSULE.json"
        self.request = root / "REQUEST.json"
        self.admission = root / "ADMISSION.json"
        self.validation = root / "VALIDATION.json"
        self._write_inputs()

    def _request_obj(self):
        return {
            "schema": "continuityos.work_admission.request/v1",
            "authority_generation": "R63",
            "task": {
                "task_id": "TEST_WORK_ADMISSION_V1",
                "task_body_sha256": self.task_sha,
                "terminal_condition": "Candidate verified; stop.",
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
                "forbidden_paths": ["src/forbidden"],
                "max_changed_files": 5,
                "max_added_bytes": 10000,
                "max_commits": 2,
                "allow_new_files": True,
                "allow_deletions": False,
                "allow_binary_files": False,
                "allow_archive_files": False,
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
                "required_commands": [
                    {"id": "focused", "argv": ["python", "-m", "pytest", "-q", "tests"], "cwd": "repo"}
                ],
                "network_access": "DENY",
                "dependency_install": "DENY",
                "max_full_suite_runs": 1,
                "max_install_attempts": 0,
            },
            "evidence": {},
        }

    def _capsule_obj(self, request):
        return {
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
            "terminal_condition": request["task"]["terminal_condition"],
            "effects": request["effects"],
            "can_trade": False,
            "capital_permission": "DENY",
            "deploy_permission": "DENY",
            "self_application": False,
        }

    def _write_inputs(self, mutate_request=None, mutate_capsule=None):
        request = self._request_obj()
        if mutate_request:
            mutate_request(request)
        capsule = self._capsule_obj(request)
        if mutate_capsule:
            mutate_capsule(capsule)
        self.capsule.write_text(json.dumps(capsule), encoding="utf-8")
        request["session"]["capsule_sha256"] = sha256_file(self.capsule)
        self.request.write_text(json.dumps(request), encoding="utf-8")

    def admit(self, **kwargs):
        receipt = verify_work_admission(self.request, self.work_order, self.capsule, self.repo, **kwargs)
        self.admission.write_text(json.dumps(receipt), encoding="utf-8")
        return receipt

    def create_candidate(self, path="src/feature.py", data="FEATURE = 1\n"):
        run(["git", "switch", "-c", "gpt/candidate"], self.repo)
        target = self.repo / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(data, encoding="utf-8")
        run(["git", "add", "."], self.repo)
        run(["git", "commit", "-m", "candidate"], self.repo)

    def write_validation(self, receipt, *, exit_code=0, argv=None, effects=None):
        head = run(["git", "rev-parse", "HEAD"], self.repo)
        tree = run(["git", "rev-parse", "HEAD^{tree}"], self.repo)
        obj = {
            "schema": VALIDATION_SCHEMA,
            "admission_binding_sha256": receipt["admission_binding_sha256"],
            "admission_receipt_sha256": sha256_file(self.admission),
            "base_head": self.base_head,
            "candidate_head": head,
            "candidate_tree": tree,
            "worktree_clean_after": True,
            "network_access_used": "DENY",
            "dependency_install_used": "DENY",
            "full_suite_runs": 1,
            "install_attempts": 0,
            "commands": [{
                "id": "focused",
                "argv": argv or ["python", "-m", "pytest", "-q", "tests"],
                "cwd": "repo",
                "exit_code": exit_code,
                "stdout_sha256": hashlib.sha256(b"ok").hexdigest(),
                "stderr_sha256": hashlib.sha256(b"").hexdigest(),
            }],
            "effects": effects or {
                "force_push": False, "merge": False, "pull_request_merge": False,
                "deployment": False, "registry_apply": False, "current_state_apply": False,
                "r63_apply": False, "trading": False, "wallet_access": False,
                "order_execution": False, "external_message": False, "self_application": False,
                "can_trade": False, "capital_permission": "DENY", "deploy_permission": "DENY",
            },
        }
        self.validation.write_text(json.dumps(obj), encoding="utf-8")


class AdmissionTests(unittest.TestCase):
    def test_valid_admission(self):
        with tempfile.TemporaryDirectory() as td:
            fx = WorkFixture(Path(td))
            self.assertEqual(fx.admit()["status"], ADMISSION_PASS)

    def test_work_order_sha_mismatch(self):
        with tempfile.TemporaryDirectory() as td:
            fx = WorkFixture(Path(td)); fx.work_order.write_text("changed")
            self.assertEqual(fx.admit()["status"], ADMISSION_REVISE)

    def test_capsule_sha_mismatch(self):
        with tempfile.TemporaryDirectory() as td:
            fx = WorkFixture(Path(td)); fx.capsule.write_text("{}")
            self.assertEqual(fx.admit()["status"], ADMISSION_REVISE)

    def test_capsule_role_mismatch(self):
        with tempfile.TemporaryDirectory() as td:
            fx = WorkFixture(Path(td)); fx._write_inputs(mutate_capsule=lambda c: c.__setitem__("role", "CODEX-01"))
            self.assertEqual(fx.admit()["status"], ADMISSION_REVISE)

    def test_authority_widening_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            fx = WorkFixture(Path(td)); fx._write_inputs(mutate_request=lambda r: r.__setitem__("authority_generation", "R64"))
            self.assertEqual(fx.admit()["status"], ADMISSION_REVISE)

    def test_dangerous_effect_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            fx = WorkFixture(Path(td)); fx._write_inputs(mutate_request=lambda r: r["effects"].__setitem__("merge", True))
            self.assertEqual(fx.admit()["status"], ADMISSION_REVISE)

    def test_candidate_main_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            fx = WorkFixture(Path(td)); fx._write_inputs(mutate_request=lambda r: r["repository"].__setitem__("candidate_branch", "main"))
            self.assertEqual(fx.admit()["status"], ADMISSION_REVISE)

    def test_path_traversal_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            fx = WorkFixture(Path(td)); fx._write_inputs(mutate_request=lambda r: r["scope"].__setitem__("allowed_paths", ["../secret"]))
            self.assertEqual(fx.admit()["status"], ADMISSION_REVISE)

    def test_env_path_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            fx = WorkFixture(Path(td)); fx._write_inputs(mutate_request=lambda r: r["scope"].__setitem__("allowed_paths", [".env"]))
            self.assertEqual(fx.admit()["status"], ADMISSION_REVISE)

    def test_dirty_baseline_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            fx = WorkFixture(Path(td)); (fx.repo / "dirty.txt").write_text("x")
            self.assertEqual(fx.admit()["status"], ADMISSION_REVISE)

    def test_required_remote_without_check_holds(self):
        with tempfile.TemporaryDirectory() as td:
            fx = WorkFixture(Path(td)); fx._write_inputs(mutate_request=lambda r: r["repository"].__setitem__("remote_readback_mode", "REQUIRED"))
            self.assertEqual(fx.admit(check_remote=False)["status"], ADMISSION_HOLD)

    @mock.patch("continuityos.gate.work_admission._ls_remote")
    def test_remote_exact_passes(self, ls_remote):
        with tempfile.TemporaryDirectory() as td:
            fx = WorkFixture(Path(td)); fx._write_inputs(mutate_request=lambda r: r["repository"].__setitem__("remote_readback_mode", "REQUIRED"))
            ls_remote.side_effect = [fx.base_head, None]
            self.assertEqual(fx.admit(check_remote=True)["status"], ADMISSION_PASS)

    @mock.patch("continuityos.gate.work_admission._ls_remote")
    def test_remote_candidate_conflict_rejected(self, ls_remote):
        with tempfile.TemporaryDirectory() as td:
            fx = WorkFixture(Path(td)); fx._write_inputs(mutate_request=lambda r: r["repository"].__setitem__("remote_readback_mode", "REQUIRED"))
            ls_remote.side_effect = [fx.base_head, "f" * 40]
            self.assertEqual(fx.admit(check_remote=True)["status"], ADMISSION_REVISE)


class DeltaTests(unittest.TestCase):
    def _ready(self, td):
        fx = WorkFixture(Path(td)); admission = fx.admit(); self.assertEqual(admission["status"], ADMISSION_PASS)
        fx.create_candidate(); fx.write_validation(admission)
        return fx, admission

    def test_valid_delta(self):
        with tempfile.TemporaryDirectory() as td:
            fx, _ = self._ready(td)
            receipt = verify_work_delta(fx.admission, fx.validation, fx.repo, expected_admission_receipt_sha256=sha256_file(fx.admission))
            self.assertEqual(receipt["status"], DELTA_PASS)

    def test_out_of_scope_path_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            fx = WorkFixture(Path(td)); admission = fx.admit(); fx.create_candidate("outside.txt"); fx.write_validation(admission)
            self.assertEqual(verify_work_delta(fx.admission, fx.validation, fx.repo, expected_admission_receipt_sha256=sha256_file(fx.admission))["status"], DELTA_REVISE)

    def test_deletion_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            fx = WorkFixture(Path(td)); admission = fx.admit(); run(["git", "switch", "-c", "gpt/candidate"], fx.repo); (fx.repo / "src/base.py").unlink(); run(["git", "add", "-A"], fx.repo); run(["git", "commit", "-m", "delete"], fx.repo); fx.write_validation(admission)
            self.assertEqual(verify_work_delta(fx.admission, fx.validation, fx.repo, expected_admission_receipt_sha256=sha256_file(fx.admission))["status"], DELTA_REVISE)

    def test_dirty_candidate_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            fx, _ = self._ready(td); (fx.repo / "dirty.txt").write_text("x")
            self.assertEqual(verify_work_delta(fx.admission, fx.validation, fx.repo, expected_admission_receipt_sha256=sha256_file(fx.admission))["status"], DELTA_REVISE)

    def test_validation_failure_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            fx = WorkFixture(Path(td)); admission = fx.admit(); fx.create_candidate(); fx.write_validation(admission, exit_code=1)
            self.assertEqual(verify_work_delta(fx.admission, fx.validation, fx.repo, expected_admission_receipt_sha256=sha256_file(fx.admission))["status"], DELTA_REVISE)

    def test_validation_argv_mismatch_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            fx = WorkFixture(Path(td)); admission = fx.admit(); fx.create_candidate(); fx.write_validation(admission, argv=["python", "-m", "pytest", "-q", "other"])
            self.assertEqual(verify_work_delta(fx.admission, fx.validation, fx.repo, expected_admission_receipt_sha256=sha256_file(fx.admission))["status"], DELTA_REVISE)

    def test_tampered_admission_binding_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            fx, _ = self._ready(td); original_sha = sha256_file(fx.admission); obj = json.loads(fx.admission.read_text()); obj["binding"]["task_id"] = "TAMPERED"; fx.admission.write_text(json.dumps(obj))
            self.assertEqual(verify_work_delta(fx.admission, fx.validation, fx.repo, expected_admission_receipt_sha256=original_sha)["status"], DELTA_REVISE)

    def test_binary_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            fx = WorkFixture(Path(td)); admission = fx.admit(); run(["git", "switch", "-c", "gpt/candidate"], fx.repo); (fx.repo / "src/binary.bin").write_bytes(b"\x00\x01\x02"); run(["git", "add", "."], fx.repo); run(["git", "commit", "-m", "binary"], fx.repo); fx.write_validation(admission)
            self.assertEqual(verify_work_delta(fx.admission, fx.validation, fx.repo, expected_admission_receipt_sha256=sha256_file(fx.admission))["status"], DELTA_REVISE)

    def test_too_many_files_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            fx = WorkFixture(Path(td)); fx._write_inputs(mutate_request=lambda r: r["scope"].__setitem__("max_changed_files", 1)); admission = fx.admit(); run(["git", "switch", "-c", "gpt/candidate"], fx.repo); (fx.repo / "src/a.py").write_text("a=1\n"); (fx.repo / "src/b.py").write_text("b=1\n"); run(["git", "add", "."], fx.repo); run(["git", "commit", "-m", "two"], fx.repo); fx.write_validation(admission)
            self.assertEqual(verify_work_delta(fx.admission, fx.validation, fx.repo, expected_admission_receipt_sha256=sha256_file(fx.admission))["status"], DELTA_REVISE)

    def test_dangerous_validation_effect_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            fx = WorkFixture(Path(td)); admission = fx.admit(); fx.create_candidate(); effects = {"merge": True, "can_trade": False, "capital_permission": "DENY", "deploy_permission": "DENY"}; fx.write_validation(admission, effects=effects)
            self.assertEqual(verify_work_delta(fx.admission, fx.validation, fx.repo, expected_admission_receipt_sha256=sha256_file(fx.admission))["status"], DELTA_REVISE)


class AdditionalAdmissionTests(unittest.TestCase):
    def test_workflow_path_requires_permission(self):
        with tempfile.TemporaryDirectory() as td:
            fx = WorkFixture(Path(td))
            fx._write_inputs(mutate_request=lambda r: r["scope"].__setitem__("allowed_paths", [".github/workflows"]))
            self.assertEqual(fx.admit()["status"], ADMISSION_REVISE)

    def test_shell_operator_in_validation_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            fx = WorkFixture(Path(td))
            fx._write_inputs(mutate_request=lambda r: r["validation"]["required_commands"][0].__setitem__("argv", ["python", "-m", "pytest", "&&", "echo"]))
            self.assertEqual(fx.admit()["status"], ADMISSION_REVISE)

    def test_archive_path_rejected_by_default(self):
        with tempfile.TemporaryDirectory() as td:
            fx = WorkFixture(Path(td))
            fx._write_inputs(mutate_request=lambda r: r["scope"].__setitem__("allowed_paths", ["artifacts/return.zip"]))
            self.assertEqual(fx.admit()["status"], ADMISSION_REVISE)

    def test_wrong_base_head_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            fx = WorkFixture(Path(td))
            fx._write_inputs(mutate_request=lambda r: r["repository"].__setitem__("base_head", "f" * 40))
            self.assertEqual(fx.admit()["status"], ADMISSION_REVISE)

    @mock.patch("continuityos.gate.work_admission._ls_remote")
    def test_remote_base_mismatch_rejected(self, ls_remote):
        with tempfile.TemporaryDirectory() as td:
            fx = WorkFixture(Path(td))
            fx._write_inputs(mutate_request=lambda r: r["repository"].__setitem__("remote_readback_mode", "REQUIRED"))
            ls_remote.side_effect = ["f" * 40, None]
            self.assertEqual(fx.admit(check_remote=True)["status"], ADMISSION_REVISE)


class AdditionalDeltaTests(unittest.TestCase):
    def test_wrong_candidate_branch_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            fx = WorkFixture(Path(td)); admission = fx.admit()
            run(["git", "switch", "-c", "gpt/wrong"], fx.repo)
            (fx.repo / "src/feature.py").write_text("X=1\n")
            run(["git", "add", "."], fx.repo); run(["git", "commit", "-m", "wrong"], fx.repo)
            fx.write_validation(admission)
            self.assertEqual(verify_work_delta(fx.admission, fx.validation, fx.repo, expected_admission_receipt_sha256=sha256_file(fx.admission))["status"], DELTA_REVISE)

    def test_no_change_holds(self):
        with tempfile.TemporaryDirectory() as td:
            fx = WorkFixture(Path(td)); admission = fx.admit()
            run(["git", "switch", "-c", "gpt/candidate"], fx.repo)
            run(["git", "commit", "--allow-empty", "-m", "empty"], fx.repo)
            fx.write_validation(admission)
            receipt = verify_work_delta(fx.admission, fx.validation, fx.repo, expected_admission_receipt_sha256=sha256_file(fx.admission))
            self.assertNotEqual(receipt["status"], DELTA_PASS)

    def test_max_added_bytes_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            fx = WorkFixture(Path(td))
            fx._write_inputs(mutate_request=lambda r: r["scope"].__setitem__("max_added_bytes", 1))
            admission = fx.admit(); fx.create_candidate(data="FEATURE = 123456789\n"); fx.write_validation(admission)
            self.assertEqual(verify_work_delta(fx.admission, fx.validation, fx.repo, expected_admission_receipt_sha256=sha256_file(fx.admission))["status"], DELTA_REVISE)

    def test_validation_binding_mismatch_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            fx = WorkFixture(Path(td)); admission = fx.admit(); fx.create_candidate(); fx.write_validation(admission)
            obj = json.loads(fx.validation.read_text()); obj["admission_binding_sha256"] = "0" * 64; fx.validation.write_text(json.dumps(obj))
            self.assertEqual(verify_work_delta(fx.admission, fx.validation, fx.repo, expected_admission_receipt_sha256=sha256_file(fx.admission))["status"], DELTA_REVISE)

    def test_multiple_commits_over_budget_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            fx = WorkFixture(Path(td))
            fx._write_inputs(mutate_request=lambda r: r["scope"].__setitem__("max_commits", 1))
            admission = fx.admit(); run(["git", "switch", "-c", "gpt/candidate"], fx.repo)
            (fx.repo / "src/a.py").write_text("a=1\n"); run(["git", "add", "."], fx.repo); run(["git", "commit", "-m", "a"], fx.repo)
            (fx.repo / "src/b.py").write_text("b=1\n"); run(["git", "add", "."], fx.repo); run(["git", "commit", "-m", "b"], fx.repo)
            fx.write_validation(admission)
            self.assertEqual(verify_work_delta(fx.admission, fx.validation, fx.repo, expected_admission_receipt_sha256=sha256_file(fx.admission))["status"], DELTA_REVISE)


class HardeningRegressionTests(unittest.TestCase):
    def test_candidate_ref_with_dotdot_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            fx = WorkFixture(Path(td))
            fx._write_inputs(mutate_request=lambda r: r["repository"].__setitem__("candidate_branch", "gpt/foo..bar"))
            self.assertEqual(fx.admit()["status"], ADMISSION_REVISE)

    def test_missing_deploy_permission_denied(self):
        with tempfile.TemporaryDirectory() as td:
            fx = WorkFixture(Path(td))
            fx._write_inputs(mutate_request=lambda r: r["effects"].pop("deploy_permission", None))
            self.assertEqual(fx.admit()["status"], ADMISSION_REVISE)

    def test_extra_validation_command_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            fx = WorkFixture(Path(td)); admission = fx.admit(); fx.create_candidate(); fx.write_validation(admission)
            obj = json.loads(fx.validation.read_text())
            obj["commands"].append({
                "id":"extra","argv":["python","-c","print(1)"],"cwd":"repo","exit_code":0,
                "stdout_sha256":"0"*64,"stderr_sha256":"0"*64,
            })
            fx.validation.write_text(json.dumps(obj))
            self.assertEqual(verify_work_delta(fx.admission, fx.validation, fx.repo, expected_admission_receipt_sha256=sha256_file(fx.admission))["status"], DELTA_REVISE)

    def test_network_widening_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            fx = WorkFixture(Path(td)); admission = fx.admit(); fx.create_candidate(); fx.write_validation(admission)
            obj = json.loads(fx.validation.read_text()); obj["network_access_used"] = "READ_ONLY"; fx.validation.write_text(json.dumps(obj))
            self.assertEqual(verify_work_delta(fx.admission, fx.validation, fx.repo, expected_admission_receipt_sha256=sha256_file(fx.admission))["status"], DELTA_REVISE)

    def test_install_attempt_budget_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            fx = WorkFixture(Path(td)); admission = fx.admit(); fx.create_candidate(); fx.write_validation(admission)
            obj = json.loads(fx.validation.read_text()); obj["install_attempts"] = 1; fx.validation.write_text(json.dumps(obj))
            self.assertEqual(verify_work_delta(fx.admission, fx.validation, fx.repo, expected_admission_receipt_sha256=sha256_file(fx.admission))["status"], DELTA_REVISE)

    def test_symlink_candidate_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            fx = WorkFixture(Path(td)); admission = fx.admit(); run(["git", "switch", "-c", "gpt/candidate"], fx.repo)
            try:
                (fx.repo / "src/link.py").symlink_to("base.py")
            except (OSError, NotImplementedError):
                self.skipTest("symlink unavailable")
            run(["git", "add", "."], fx.repo); run(["git", "commit", "-m", "symlink"], fx.repo); fx.write_validation(admission)
            self.assertEqual(verify_work_delta(fx.admission, fx.validation, fx.repo, expected_admission_receipt_sha256=sha256_file(fx.admission))["status"], DELTA_REVISE)


if __name__ == "__main__":
    unittest.main()
