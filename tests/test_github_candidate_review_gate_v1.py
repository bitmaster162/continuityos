from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from continuityos.gate.github_candidate_review import (
    REVIEW_HOLD,
    REVIEW_PASS,
    REVIEW_REVISE,
    TRANSPORT_SCHEMA,
    SEMANTIC_SCHEMA,
    canonical_json_text,
    evaluate_github_candidate_review,
    sha256_file,
)


class ReviewFixture:
    def __init__(self, root: Path):
        self.root = root
        self.request = root / "REQUEST.json"
        self.admission = root / "ADMISSION.json"
        self.delta = root / "DELTA.json"
        self.transport = root / "TRANSPORT.json"
        self.semantic = root / "SEMANTIC.json"
        self.base_head = "1" * 40
        self.base_tree = "2" * 40
        self.candidate_head = "3" * 40
        self.candidate_tree = "4" * 40
        self.task_body_sha = "a" * 64
        self.capsule_sha = "b" * 64
        self._write_all()

    @staticmethod
    def _write(path: Path, obj: dict):
        path.write_text(json.dumps(obj, sort_keys=True), encoding="utf-8")

    def _admission_obj(self):
        original_request = {
            "schema": "continuityos.work_admission.request/v1",
            "authority_generation": "R63",
            "task": {
                "task_id": "TEST_GITHUB_CANDIDATE_REVIEW_V1",
                "task_body_sha256": self.task_body_sha,
                "terminal_condition": "Candidate review evaluated; stop.",
            },
            "repository": {
                "owner": "bitmaster162",
                "name": "continuityos",
                "remote_url": "https://github.com/bitmaster162/continuityos.git",
                "visibility": "PRIVATE",
                "visibility_change": False,
                "base_branch": "gpt/base",
                "base_head": self.base_head,
                "base_tree": self.base_tree,
                "candidate_branch": "gpt/candidate",
                "default_branch": "main",
                "remote_readback_mode": "REQUIRED",
                "existing_candidate_head": None,
            },
            "scope": {
                "allowed_paths": ["continuityos", "tests", "docs"],
                "forbidden_paths": [".github/workflows"],
                "max_changed_files": 20,
                "max_added_bytes": 100000,
                "max_commits": 3,
                "allow_new_files": True,
                "allow_deletions": False,
                "allow_binary_files": False,
                "allow_archive_files": False,
            },
            "workspace": {
                "mode": "ANY_CLEAN_GIT_ROOT",
                "allowed_root_prefixes": [],
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
            "session": {"required_role": "GPT", "capsule_sha256": self.capsule_sha},
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
        binding = {
            "schema": "continuityos.work_admission.binding/v1",
            "request_sha256": "c" * 64,
            "work_order_sha256": self.task_body_sha,
            "session_capsule_sha256": self.capsule_sha,
            "task_id": "TEST_GITHUB_CANDIDATE_REVIEW_V1",
            "authority_generation": "R63",
            "repository": {
                "owner": "bitmaster162",
                "name": "continuityos",
                "base_branch": "gpt/base",
                "base_head": self.base_head,
                "base_tree": self.base_tree,
                "candidate_branch": "gpt/candidate",
            },
            "scope": original_request["scope"],
            "workspace": original_request["workspace"],
            "effects": original_request["effects"],
            "validation": original_request["validation"],
            "terminal_condition": original_request["task"]["terminal_condition"],
        }
        binding_sha = hashlib.sha256(canonical_json_text(binding).encode("utf-8")).hexdigest()
        return {
            "schema": "continuityos.work_admission.receipt/v1",
            "status": "WORK_ADMISSION_PASS",
            "outcome": "WOULD_ALLOW",
            "request": original_request,
            "binding": binding,
            "admission_binding_sha256": binding_sha,
            "live_state_modified": False,
            "can_trade": False,
            "capital_permission": "DENY",
            "deploy_permission": "DENY",
            "self_application": False,
        }

    def _delta_obj(self, admission_sha, binding_sha):
        return {
            "schema": "continuityos.work_admission.delta_receipt/v1",
            "status": "WORK_DELTA_PASS",
            "outcome": "WOULD_ALLOW_CANDIDATE_TRANSPORT",
            "task_id": "TEST_GITHUB_CANDIDATE_REVIEW_V1",
            "admission_binding_sha256": binding_sha,
            "admission_receipt_sha256": admission_sha,
            "validation_receipt_sha256": "d" * 64,
            "repository_observed": {
                "branch": "gpt/candidate",
                "head": self.candidate_head,
                "tree": self.candidate_tree,
                "worktree_clean": True,
            },
            "changed_files": [{"status": "A", "path": "continuityos/feature.py"}],
            "live_state_modified": False,
            "can_trade": False,
            "capital_permission": "DENY",
            "deploy_permission": "DENY",
            "self_application": False,
        }

    def _request_obj(self, admission_sha, delta_sha):
        return {
            "schema": "continuityos.github_candidate_review.request/v1",
            "authority_generation": "R63",
            "task": {
                "task_id": "TEST_GITHUB_CANDIDATE_REVIEW_V1",
                "task_body_sha256": self.task_body_sha,
                "terminal_condition": "Merge candidate eligibility evaluated; stop.",
            },
            "repository": {
                "owner": "bitmaster162",
                "name": "continuityos",
                "remote_url": "https://github.com/bitmaster162/continuityos.git",
                "visibility": "PRIVATE",
                "base_branch": "gpt/base",
                "base_head": self.base_head,
                "base_tree": self.base_tree,
                "candidate_branch": "gpt/candidate",
                "candidate_head": self.candidate_head,
                "candidate_tree": self.candidate_tree,
            },
            "bindings": {
                "session_capsule_sha256": self.capsule_sha,
                "admission_receipt_sha256": admission_sha,
                "delta_receipt_sha256": delta_sha,
            },
            "ci_policy": {
                "required_workflows": ["CI", "security"],
                "required_status": "completed",
                "required_conclusion": "success",
            },
            "review_policy": {
                "mode": "CONTROLLER_REVIEW",
                "required_reviewer_role": "GPT",
                "separation_required": True,
                "executor_actor_id": "CODEX-01",
            },
            "pull_request_policy": {"allowed": False, "required": False, "draft_required": False},
            "effects": {
                "candidate_push": True,
                "pull_request_create": False,
                "force_push": False,
                "merge": False,
                "pull_request_merge": False,
                "auto_merge": False,
                "deployment": False,
                "registry_apply": False,
                "current_state_apply": False,
                "r63_apply": False,
                "trading": False,
                "wallet_access": False,
                "order_execution": False,
                "self_application": False,
                "can_trade": False,
                "capital_permission": "DENY",
                "deploy_permission": "DENY",
            },
        }

    def _transport_obj(self):
        return {
            "schema": TRANSPORT_SCHEMA,
            "provider": "GITHUB",
            "authenticated_actor": "bitmaster162",
            "remote_url": "https://github.com/bitmaster162/continuityos.git",
            "remote_readback": True,
            "actions_readback": True,
            "repository": "bitmaster162/continuityos",
            "visibility": "PRIVATE",
            "visibility_changed": False,
            "base_branch": "gpt/base",
            "remote_base_head": self.base_head,
            "remote_base_tree": self.base_tree,
            "candidate_branch": "gpt/candidate",
            "local_candidate_head": self.candidate_head,
            "local_candidate_tree": self.candidate_tree,
            "remote_candidate_head": self.candidate_head,
            "remote_candidate_tree": self.candidate_tree,
            "push_effect": "PUSHED_NEW_BRANCH",
            "workflow_runs": [
                {"workflow_name": "CI", "head_sha": self.candidate_head, "status": "completed", "conclusion": "success", "run_id": 1},
                {"workflow_name": "security", "head_sha": self.candidate_head, "status": "completed", "conclusion": "success", "run_id": 2},
            ],
            "secret_scan": {
                "status": "PASS",
                "candidate_head": self.candidate_head,
                "findings": 0,
                "raw_evidence_leak": False,
            },
            "pull_request_create": False,
            "pull_request": None,
            "force_push": False,
            "merge": False,
            "pull_request_merge": False,
            "auto_merge": False,
            "deployment": False,
            "registry_apply": False,
            "current_state_apply": False,
            "r63_apply": False,
            "trading": False,
            "wallet_access": False,
            "order_execution": False,
            "self_application": False,
            "can_trade": False,
            "capital_permission": "DENY",
            "deploy_permission": "DENY",
        }

    def _semantic_obj(self, request_sha, admission_sha, delta_sha, transport_sha):
        return {
            "schema": SEMANTIC_SCHEMA,
            "request_sha256": request_sha,
            "admission_receipt_sha256": admission_sha,
            "delta_receipt_sha256": delta_sha,
            "transport_receipt_sha256": transport_sha,
            "candidate_head": self.candidate_head,
            "candidate_tree": self.candidate_tree,
            "review_mode": "CONTROLLER_REVIEW",
            "reviewer": {"role": "GPT", "actor_id": "GPT-CONTROLLER"},
            "verdict": "APPROVE_CANDIDATE",
            "human_irreversible_approval": False,
            "merge_authorized": False,
            "self_application": False,
            "conditions": [],
            "findings": [
                {"id": "R-1", "severity": "P2", "status": "RESOLVED"}
            ],
            "effects": {
                "force_push": False,
                "merge": False,
                "pull_request_merge": False,
                "auto_merge": False,
                "deployment": False,
                "registry_apply": False,
                "current_state_apply": False,
                "r63_apply": False,
                "trading": False,
                "wallet_access": False,
                "order_execution": False,
                "self_application": False,
                "can_trade": False,
                "capital_permission": "DENY",
                "deploy_permission": "DENY",
            },
        }

    def _write_all(self, mutate_request=None, mutate_admission=None, mutate_delta=None, mutate_transport=None, mutate_semantic=None):
        admission = self._admission_obj()
        if mutate_admission:
            mutate_admission(admission)
        self._write(self.admission, admission)
        admission_sha = sha256_file(self.admission)
        binding_sha = admission.get("admission_binding_sha256", "0" * 64)

        delta = self._delta_obj(admission_sha, binding_sha)
        if mutate_delta:
            mutate_delta(delta)
        self._write(self.delta, delta)
        delta_sha = sha256_file(self.delta)

        request = self._request_obj(admission_sha, delta_sha)
        if mutate_request:
            mutate_request(request)
        self._write(self.request, request)
        request_sha = sha256_file(self.request)

        transport = self._transport_obj()
        if mutate_transport:
            mutate_transport(transport)
        self._write(self.transport, transport)
        transport_sha = sha256_file(self.transport)

        semantic = self._semantic_obj(request_sha, admission_sha, delta_sha, transport_sha)
        if mutate_semantic:
            mutate_semantic(semantic)
        self._write(self.semantic, semantic)

    def rebind_semantic(self):
        obj = json.loads(self.semantic.read_text())
        obj["request_sha256"] = sha256_file(self.request)
        obj["admission_receipt_sha256"] = sha256_file(self.admission)
        obj["delta_receipt_sha256"] = sha256_file(self.delta)
        obj["transport_receipt_sha256"] = sha256_file(self.transport)
        self._write(self.semantic, obj)

    def evaluate(self):
        return evaluate_github_candidate_review(
            self.request, self.admission, self.delta, self.transport, self.semantic
        )


class ReviewGateTests(unittest.TestCase):
    def test_valid_review_passes(self):
        with tempfile.TemporaryDirectory() as td:
            fx = ReviewFixture(Path(td))
            self.assertEqual(fx.evaluate()["status"], REVIEW_PASS)

    def test_admission_sha_binding_mismatch_revises(self):
        with tempfile.TemporaryDirectory() as td:
            fx = ReviewFixture(Path(td))
            obj = json.loads(fx.request.read_text())
            obj["bindings"]["admission_receipt_sha256"] = "f" * 64
            fx._write(fx.request, obj)
            self.assertEqual(fx.evaluate()["status"], REVIEW_REVISE)

    def test_delta_must_pass(self):
        with tempfile.TemporaryDirectory() as td:
            fx = ReviewFixture(Path(td))
            obj = json.loads(fx.delta.read_text())
            obj["status"] = "WORK_DELTA_REVISE"
            fx._write(fx.delta, obj)
            self.assertEqual(fx.evaluate()["status"], REVIEW_REVISE)

    def test_remote_candidate_mismatch_revises(self):
        with tempfile.TemporaryDirectory() as td:
            fx = ReviewFixture(Path(td))
            obj = json.loads(fx.transport.read_text())
            obj["remote_candidate_head"] = "9" * 40
            fx._write(fx.transport, obj)
            self.assertEqual(fx.evaluate()["status"], REVIEW_REVISE)

    def test_base_drift_holds(self):
        with tempfile.TemporaryDirectory() as td:
            fx = ReviewFixture(Path(td))
            obj = json.loads(fx.transport.read_text())
            obj["remote_base_head"] = "9" * 40
            fx._write(fx.transport, obj)
            fx.rebind_semantic()
            self.assertEqual(fx.evaluate()["status"], REVIEW_HOLD)

    def test_missing_required_workflow_holds(self):
        with tempfile.TemporaryDirectory() as td:
            fx = ReviewFixture(Path(td))
            obj = json.loads(fx.transport.read_text())
            obj["workflow_runs"] = obj["workflow_runs"][:1]
            fx._write(fx.transport, obj)
            fx.rebind_semantic()
            self.assertEqual(fx.evaluate()["status"], REVIEW_HOLD)

    def test_pending_workflow_holds(self):
        with tempfile.TemporaryDirectory() as td:
            fx = ReviewFixture(Path(td))
            obj = json.loads(fx.transport.read_text())
            obj["workflow_runs"][0]["status"] = "in_progress"
            obj["workflow_runs"][0]["conclusion"] = None
            fx._write(fx.transport, obj)
            fx.rebind_semantic()
            self.assertEqual(fx.evaluate()["status"], REVIEW_HOLD)

    def test_failed_workflow_revises(self):
        with tempfile.TemporaryDirectory() as td:
            fx = ReviewFixture(Path(td))
            obj = json.loads(fx.transport.read_text())
            obj["workflow_runs"][0]["conclusion"] = "failure"
            fx._write(fx.transport, obj)
            self.assertEqual(fx.evaluate()["status"], REVIEW_REVISE)

    def test_wrong_workflow_head_revises(self):
        with tempfile.TemporaryDirectory() as td:
            fx = ReviewFixture(Path(td))
            obj = json.loads(fx.transport.read_text())
            obj["workflow_runs"][0]["head_sha"] = "9" * 40
            fx._write(fx.transport, obj)
            self.assertEqual(fx.evaluate()["status"], REVIEW_REVISE)

    def test_force_push_revises(self):
        with tempfile.TemporaryDirectory() as td:
            fx = ReviewFixture(Path(td))
            obj = json.loads(fx.transport.read_text())
            obj["force_push"] = True
            fx._write(fx.transport, obj)
            self.assertEqual(fx.evaluate()["status"], REVIEW_REVISE)

    def test_secret_scan_failure_revises(self):
        with tempfile.TemporaryDirectory() as td:
            fx = ReviewFixture(Path(td))
            obj = json.loads(fx.transport.read_text())
            obj["secret_scan"]["status"] = "FAIL"
            obj["secret_scan"]["findings"] = 1
            fx._write(fx.transport, obj)
            self.assertEqual(fx.evaluate()["status"], REVIEW_REVISE)

    def test_semantic_binding_mismatch_revises(self):
        with tempfile.TemporaryDirectory() as td:
            fx = ReviewFixture(Path(td))
            obj = json.loads(fx.semantic.read_text())
            obj["transport_receipt_sha256"] = "f" * 64
            fx._write(fx.semantic, obj)
            self.assertEqual(fx.evaluate()["status"], REVIEW_REVISE)

    def test_open_p1_revises(self):
        with tempfile.TemporaryDirectory() as td:
            fx = ReviewFixture(Path(td))
            obj = json.loads(fx.semantic.read_text())
            obj["findings"] = [{"id": "P1-X", "severity": "P1", "status": "OPEN"}]
            fx._write(fx.semantic, obj)
            self.assertEqual(fx.evaluate()["status"], REVIEW_REVISE)

    def test_review_separation_revises(self):
        with tempfile.TemporaryDirectory() as td:
            fx = ReviewFixture(Path(td))
            obj = json.loads(fx.semantic.read_text())
            obj["reviewer"]["actor_id"] = "CODEX-01"
            fx._write(fx.semantic, obj)
            self.assertEqual(fx.evaluate()["status"], REVIEW_REVISE)

    def test_approve_with_conditions_requires_condition(self):
        with tempfile.TemporaryDirectory() as td:
            fx = ReviewFixture(Path(td))
            obj = json.loads(fx.semantic.read_text())
            obj["verdict"] = "APPROVE_WITH_CONDITIONS"
            obj["conditions"] = []
            fx._write(fx.semantic, obj)
            self.assertEqual(fx.evaluate()["status"], REVIEW_REVISE)

    def test_semantic_hold_holds(self):
        with tempfile.TemporaryDirectory() as td:
            fx = ReviewFixture(Path(td))
            obj = json.loads(fx.semantic.read_text())
            obj["verdict"] = "HOLD"
            fx._write(fx.semantic, obj)
            self.assertEqual(fx.evaluate()["status"], REVIEW_HOLD)

    def test_semantic_reject_revises(self):
        with tempfile.TemporaryDirectory() as td:
            fx = ReviewFixture(Path(td))
            obj = json.loads(fx.semantic.read_text())
            obj["verdict"] = "REJECT"
            fx._write(fx.semantic, obj)
            self.assertEqual(fx.evaluate()["status"], REVIEW_REVISE)

    def test_pr_created_when_denied_revises(self):
        with tempfile.TemporaryDirectory() as td:
            fx = ReviewFixture(Path(td))
            obj = json.loads(fx.transport.read_text())
            obj["pull_request_create"] = True
            obj["pull_request"] = {
                "base_branch": "gpt/base", "head_branch": "gpt/candidate",
                "head_sha": fx.candidate_head, "state": "OPEN", "merged": False,
                "auto_merge_enabled": False, "draft": True,
            }
            fx._write(fx.transport, obj)
            self.assertEqual(fx.evaluate()["status"], REVIEW_REVISE)

    def test_required_pr_missing_holds(self):
        with tempfile.TemporaryDirectory() as td:
            fx = ReviewFixture(Path(td))
            req = json.loads(fx.request.read_text())
            req["pull_request_policy"] = {"allowed": True, "required": True, "draft_required": True}
            req["effects"]["pull_request_create"] = True
            fx._write(fx.request, req)
            sem = json.loads(fx.semantic.read_text())
            sem["request_sha256"] = sha256_file(fx.request)
            fx._write(fx.semantic, sem)
            self.assertEqual(fx.evaluate()["status"], REVIEW_HOLD)

    def test_wrong_authenticated_actor_revises(self):
        with tempfile.TemporaryDirectory() as td:
            fx = ReviewFixture(Path(td))
            obj = json.loads(fx.transport.read_text())
            obj["authenticated_actor"] = "other-owner"
            fx._write(fx.transport, obj)
            self.assertEqual(fx.evaluate()["status"], REVIEW_REVISE)

    def test_missing_remote_readback_revises(self):
        with tempfile.TemporaryDirectory() as td:
            fx = ReviewFixture(Path(td))
            obj = json.loads(fx.transport.read_text())
            obj["remote_readback"] = False
            fx._write(fx.transport, obj)
            self.assertEqual(fx.evaluate()["status"], REVIEW_REVISE)

    def test_forged_human_approval_revises(self):
        with tempfile.TemporaryDirectory() as td:
            fx = ReviewFixture(Path(td))
            obj = json.loads(fx.semantic.read_text())
            obj["human_irreversible_approval"] = True
            fx._write(fx.semantic, obj)
            self.assertEqual(fx.evaluate()["status"], REVIEW_REVISE)

    def test_exact_draft_pr_passes(self):
        with tempfile.TemporaryDirectory() as td:
            fx = ReviewFixture(Path(td))
            req = json.loads(fx.request.read_text())
            req["pull_request_policy"] = {"allowed": True, "required": True, "draft_required": True}
            req["effects"]["pull_request_create"] = True
            fx._write(fx.request, req)
            transport = json.loads(fx.transport.read_text())
            transport["pull_request_create"] = True
            transport["pull_request"] = {
                "number": 12, "url": "https://github.com/bitmaster162/continuityos/pull/12",
                "base_branch": "gpt/base", "head_branch": "gpt/candidate",
                "head_sha": fx.candidate_head, "state": "OPEN", "merged": False,
                "auto_merge_enabled": False, "draft": True,
            }
            fx._write(fx.transport, transport)
            sem = json.loads(fx.semantic.read_text())
            sem["request_sha256"] = sha256_file(fx.request)
            sem["transport_receipt_sha256"] = sha256_file(fx.transport)
            fx._write(fx.semantic, sem)
            self.assertEqual(fx.evaluate()["status"], REVIEW_PASS)


if __name__ == "__main__":
    unittest.main()
