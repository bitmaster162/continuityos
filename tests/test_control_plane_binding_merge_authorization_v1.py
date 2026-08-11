from __future__ import annotations

from datetime import datetime, timedelta, timezone
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

from continuityos.gate.evidence_common import fixed_effects, sha256_file
from continuityos.gate.github_candidate_review import evaluate_github_candidate_review
from continuityos.gate.merge_authorization import (
    HOLD as MERGE_HOLD,
    PASS as MERGE_PASS,
    REVISE as MERGE_REVISE,
    authorization_subject,
    evaluate_merge_authorization,
    sha256_json,
)
from continuityos.gate.work_ledger import (
    SEMANTIC_SCHEMA,
    TRANSPORT_SCHEMA,
    append_work_delta,
    append_work_semantic_review,
    append_work_transport,
    initialize_work_ledger,
    project_work_ledger,
)
from continuityos.gate.work_ledger_review_binding import (
    HOLD as BINDING_HOLD,
    PASS as BINDING_PASS,
    REVISE as BINDING_REVISE,
    evaluate_work_ledger_review_binding,
)


def load_review_fixture_class():
    path = Path(__file__).with_name("test_github_candidate_review_gate_v1.py")
    spec = importlib.util.spec_from_file_location("_review_fixture_module", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module.ReviewFixture


ReviewFixture = load_review_fixture_class()


def ledger_effects(**extra):
    value = {
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
    }
    value.update(extra)
    return value


class IntegratedFixture:
    def __init__(self, root: Path):
        self.root = root
        review_root = root / "review"
        review_root.mkdir(parents=True, exist_ok=True)
        self.review = ReviewFixture(review_root)

        self.task_id = "TEST_GITHUB_CANDIDATE_REVIEW_V1"
        self.repo_name = "bitmaster162/continuityos"
        self.visibility = "PRIVATE"
        self.branch = "gpt/candidate"
        self.head = self.review.candidate_head
        self.tree = self.review.candidate_tree
        self.base_branch = "gpt/base"
        self.base_head = self.review.base_head
        self.base_tree = self.review.base_tree

        self.l0 = root / "ledger-0.jsonl"
        self.l1 = root / "ledger-1.jsonl"
        self.l2 = root / "ledger-2.jsonl"
        self.l3 = root / "ledger-3.jsonl"
        self.ledger_transport = root / "LEDGER_TRANSPORT.json"
        self.ledger_semantic = root / "LEDGER_SEMANTIC.json"
        self.projection = root / "PROJECTION.json"
        self.review_evaluation = root / "REVIEW_EVALUATION.json"
        self.binding_request = root / "BINDING_REQUEST.json"
        self.binding_evaluation = root / "BINDING_EVALUATION.json"

        self._build_ledger_and_review()

        self.branch_protection = root / "BRANCH_PROTECTION.json"
        self.pull_request = root / "PULL_REQUEST.json"
        self.rollback = root / "ROLLBACK.json"
        self.human = root / "HUMAN_DECISION.json"
        self.merge_request = root / "MERGE_REQUEST.json"
        self._build_merge_inputs()

    @staticmethod
    def write(path: Path, obj: dict) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(obj, sort_keys=True, indent=2) + "\n", encoding="utf-8")

    @staticmethod
    def assert_status(receipt: dict, expected: str) -> None:
        if receipt.get("status") != expected:
            raise AssertionError(receipt)

    def _make_review_inputs_ledger_compatible(self) -> None:
        admission = json.loads(self.review.admission.read_text())
        admission["request_sha256"] = admission["binding"]["request_sha256"]
        admission["work_order_sha256"] = admission["binding"]["work_order_sha256"]
        admission["session_capsule_sha256"] = admission["binding"]["session_capsule_sha256"]
        admission["writes_performed"] = []
        self.write(self.review.admission, admission)

        delta = json.loads(self.review.delta.read_text())
        delta["admission_receipt_sha256"] = sha256_file(self.review.admission)
        delta["writes_performed"] = []
        self.write(self.review.delta, delta)

        request = json.loads(self.review.request.read_text())
        request["bindings"]["admission_receipt_sha256"] = sha256_file(self.review.admission)
        request["bindings"]["delta_receipt_sha256"] = sha256_file(self.review.delta)
        self.write(self.review.request, request)

        semantic = json.loads(self.review.semantic.read_text())
        semantic["request_sha256"] = sha256_file(self.review.request)
        semantic["admission_receipt_sha256"] = sha256_file(self.review.admission)
        semantic["delta_receipt_sha256"] = sha256_file(self.review.delta)
        semantic["transport_receipt_sha256"] = sha256_file(self.review.transport)
        self.write(self.review.semantic, semantic)

    def _build_ledger_and_review(self) -> None:
        self._make_review_inputs_ledger_compatible()
        admission = json.loads(self.review.admission.read_text())
        binding_sha = admission["admission_binding_sha256"]

        self.assert_status(
            initialize_work_ledger(self.review.admission, self.l0),
            "WORK_LEDGER_INIT_PASS",
        )
        self.assert_status(
            append_work_delta(self.l0, self.review.delta, self.l1),
            "WORK_LEDGER_EXTEND_PASS",
        )

        work_transport = {
            "schema": TRANSPORT_SCHEMA,
            "authority_generation": "R63",
            "task_id": self.task_id,
            "admission_binding_sha256": binding_sha,
            "delta_receipt_sha256": sha256_file(self.review.delta),
            "repository": {
                "owner": "bitmaster162",
                "name": "continuityos",
                "remote_url": "https://github.com/bitmaster162/continuityos.git",
                "visibility": self.visibility,
                "candidate_branch": self.branch,
            },
            "candidate": {"head": self.head, "tree": self.tree},
            "remote": {"head": self.head, "tree": self.tree, "visibility": self.visibility},
            "actions": {
                "status": "SUCCESS",
                "run_id": 77,
                "head_sha": self.head,
                "conclusion": "success",
            },
            "executor": {"role": "HOST_EXECUTOR", "id": "SPARK"},
            "terminal": "WORK_TRANSPORT_PASS",
            "effects": ledger_effects(candidate_push=True),
        }
        self.write(self.ledger_transport, work_transport)
        self.assert_status(
            append_work_transport(self.l1, self.ledger_transport, self.l2),
            "WORK_LEDGER_EXTEND_PASS",
        )

        work_semantic = {
            "schema": SEMANTIC_SCHEMA,
            "authority_generation": "R63",
            "task_id": self.task_id,
            "admission_binding_sha256": binding_sha,
            "delta_receipt_sha256": sha256_file(self.review.delta),
            "transport_receipt_sha256": sha256_file(self.ledger_transport),
            "candidate": {"head": self.head, "tree": self.tree},
            "reviewer": {"role": "GPT_CONTROLLER", "id": "GPT"},
            "verdict": "ACCEPT",
            "conditions": [],
            "content_status": "REVIEWED",
            "apply_status": "NOT_APPLIED",
            "effects": ledger_effects(),
        }
        self.write(self.ledger_semantic, work_semantic)
        self.assert_status(
            append_work_semantic_review(self.l2, self.ledger_semantic, self.l3),
            "WORK_LEDGER_EXTEND_PASS",
        )

        projected = project_work_ledger(self.l3)
        self.assert_status(projected, "WORK_LEDGER_PROJECT_PASS")
        self.write(self.projection, projected["projection"])

        review_evaluation = evaluate_github_candidate_review(
            self.review.request,
            self.review.admission,
            self.review.delta,
            self.review.transport,
            self.review.semantic,
        )
        self.assert_status(review_evaluation, "GITHUB_CANDIDATE_REVIEW_PASS")
        self.write(self.review_evaluation, review_evaluation)
        self.rebind_binding_request()

    def rebind_binding_request(self) -> None:
        bindings = {
            "ledger_sha256": sha256_file(self.l3),
            "projection_sha256": sha256_file(self.projection),
            "admission_receipt_sha256": sha256_file(self.review.admission),
            "delta_receipt_sha256": sha256_file(self.review.delta),
            "ledger_transport_receipt_sha256": sha256_file(self.ledger_transport),
            "ledger_semantic_decision_sha256": sha256_file(self.ledger_semantic),
            "review_request_sha256": sha256_file(self.review.request),
            "review_transport_receipt_sha256": sha256_file(self.review.transport),
            "review_semantic_decision_sha256": sha256_file(self.review.semantic),
            "review_evaluation_sha256": sha256_file(self.review_evaluation),
        }
        self.write(
            self.binding_request,
            {
                "schema": "continuityos.work_ledger_review_binding.request/v1",
                "authority_generation": "R63",
                "task_id": self.task_id,
                "candidate": {
                    "repository": self.repo_name,
                    "branch": self.branch,
                    "head": self.head,
                    "tree": self.tree,
                },
                "bindings": bindings,
                "effects": fixed_effects(),
            },
        )

    def evaluate_binding(self) -> dict:
        receipt = evaluate_work_ledger_review_binding(
            self.binding_request,
            self.l3,
            self.projection,
            self.review.admission,
            self.review.delta,
            self.ledger_transport,
            self.ledger_semantic,
            self.review.request,
            self.review.transport,
            self.review.semantic,
            self.review_evaluation,
        )
        self.write(self.binding_evaluation, receipt)
        return receipt

    def _build_merge_inputs(self) -> None:
        required_checks = ["CI", "security"]
        self.write(
            self.branch_protection,
            {
                "schema": "continuityos.merge_authorization.branch_protection_receipt/v1",
                "provider": "GITHUB",
                "readback": True,
                "repository": self.repo_name,
                "branch": self.base_branch,
                "visibility": self.visibility,
                "base_head": self.base_head,
                "base_tree": self.base_tree,
                "force_push_allowed": False,
                "deletion_allowed": False,
                "required_checks": required_checks,
                "required_approvals": 1,
            },
        )
        self.write(
            self.pull_request,
            {
                "schema": "continuityos.merge_authorization.pull_request_receipt/v1",
                "provider": "GITHUB",
                "repository": self.repo_name,
                "number": 42,
                "state": "OPEN",
                "draft": False,
                "merged": False,
                "auto_merge_enabled": False,
                "merge_method": "MERGE_COMMIT",
                "base_branch": self.base_branch,
                "base_head": self.base_head,
                "base_tree": self.base_tree,
                "head_branch": self.branch,
                "head_sha": self.head,
                "head_tree": self.tree,
                "mergeable": True,
                "author_actor_id": "CODEX-01",
                "checks": [
                    {
                        "name": "CI",
                        "head_sha": self.head,
                        "status": "completed",
                        "conclusion": "success",
                    },
                    {
                        "name": "security",
                        "head_sha": self.head,
                        "status": "completed",
                        "conclusion": "success",
                    },
                ],
                "approvals": [
                    {
                        "actor_id": "GPT-CONTROLLER",
                        "state": "APPROVED",
                        "head_sha": self.head,
                    }
                ],
            },
        )
        self.write(
            self.rollback,
            {
                "schema": "continuityos.merge_authorization.rollback_receipt/v1",
                "strategy": "REVERT_MERGE_COMMIT",
                "tested": True,
                "validation_status": "PASS",
                "destructive_reset": False,
                "repository": self.repo_name,
                "base_head": self.base_head,
                "candidate_head": self.head,
                "effects": fixed_effects(),
            },
        )

        binding_result = self.evaluate_binding()
        self.assert_status(binding_result, BINDING_PASS)
        now = datetime.now(timezone.utc)
        self.write(
            self.human,
            {
                "schema": "continuityos.merge_authorization.human_decision/v1",
                "actor_id": "ROBERT",
                "role": "SOVEREIGN",
                "decision": "APPROVE_MERGE_CANDIDATE",
                "authorization_subject_sha256": "0" * 64,
                "nonce": "ROBERT-MERGE-20260803-0001",
                "issued_at_utc": (now - timedelta(minutes=1)).isoformat(),
                "expires_at_utc": (now + timedelta(minutes=30)).isoformat(),
                "consumed": False,
                "self_application": False,
                "effects": fixed_effects(),
            },
        )
        self.rebind_human_subject()
        self.rebind_merge_request()

    def subject_binding(self) -> dict:
        return {
            "repository": self.repo_name,
            "visibility": self.visibility,
            "base_branch": self.base_branch,
            "base_head": self.base_head,
            "base_tree": self.base_tree,
            "candidate_branch": self.branch,
            "candidate_head": self.head,
            "candidate_tree": self.tree,
            "pull_request_number": 42,
            "merge_method": "MERGE_COMMIT",
        }

    def rebind_human_subject(self) -> None:
        hashes = {
            "ledger_review_binding_sha256": sha256_file(self.binding_evaluation),
            "candidate_review_sha256": sha256_file(self.review_evaluation),
            "branch_protection_sha256": sha256_file(self.branch_protection),
            "pull_request_sha256": sha256_file(self.pull_request),
            "rollback_receipt_sha256": sha256_file(self.rollback),
        }
        obj = json.loads(self.human.read_text())
        obj["authorization_subject_sha256"] = sha256_json(
            authorization_subject(self.subject_binding(), hashes)
        )
        self.write(self.human, obj)

    def rebind_merge_request(self) -> None:
        self.write(
            self.merge_request,
            {
                "schema": "continuityos.merge_authorization.request/v1",
                "authority_generation": "R63",
                "repository": {
                    "name_with_owner": self.repo_name,
                    "visibility": self.visibility,
                    "base": {
                        "branch": self.base_branch,
                        "head": self.base_head,
                        "tree": self.base_tree,
                    },
                    "candidate": {
                        "branch": self.branch,
                        "head": self.head,
                        "tree": self.tree,
                    },
                    "pull_request_number": 42,
                },
                "bindings": {
                    "ledger_review_binding_sha256": sha256_file(self.binding_evaluation),
                    "candidate_review_sha256": sha256_file(self.review_evaluation),
                    "branch_protection_sha256": sha256_file(self.branch_protection),
                    "pull_request_sha256": sha256_file(self.pull_request),
                    "human_decision_sha256": sha256_file(self.human),
                    "rollback_receipt_sha256": sha256_file(self.rollback),
                },
                "policy": {
                    "required_checks": ["CI", "security"],
                    "required_approvals": 1,
                    "reviewer_separation_required": True,
                    "max_decision_age_seconds": 3600,
                    "merge_method": "MERGE_COMMIT",
                },
                "effects": fixed_effects(),
            },
        )

    def evaluate_merge(self) -> dict:
        return evaluate_merge_authorization(
            self.merge_request,
            self.binding_evaluation,
            self.review_evaluation,
            self.branch_protection,
            self.pull_request,
            self.human,
            self.rollback,
        )


class BindingTests(unittest.TestCase):
    def test_exact_binding_passes(self):
        with tempfile.TemporaryDirectory() as td:
            fx = IntegratedFixture(Path(td))
            self.assertEqual(fx.evaluate_binding()["status"], BINDING_PASS)

    def test_projection_equivocation_revises_even_when_rebound(self):
        with tempfile.TemporaryDirectory() as td:
            fx = IntegratedFixture(Path(td))
            projection = json.loads(fx.projection.read_text())
            projection["latest_event_sha256"] = "f" * 64
            fx.write(fx.projection, projection)
            fx.rebind_binding_request()
            self.assertEqual(fx.evaluate_binding()["status"], BINDING_REVISE)

    def test_forged_review_evaluation_revises(self):
        with tempfile.TemporaryDirectory() as td:
            fx = IntegratedFixture(Path(td))
            review = json.loads(fx.review_evaluation.read_text())
            review["transport_summary"]["workflow_summary"][0]["run_id"] = 999
            fx.write(fx.review_evaluation, review)
            fx.rebind_binding_request()
            self.assertEqual(fx.evaluate_binding()["status"], BINDING_REVISE)

    def test_review_hold_holds(self):
        with tempfile.TemporaryDirectory() as td:
            fx = IntegratedFixture(Path(td))
            semantic = json.loads(fx.review.semantic.read_text())
            semantic["verdict"] = "HOLD"
            fx.write(fx.review.semantic, semantic)
            review = evaluate_github_candidate_review(
                fx.review.request,
                fx.review.admission,
                fx.review.delta,
                fx.review.transport,
                fx.review.semantic,
            )
            fx.write(fx.review_evaluation, review)
            fx.rebind_binding_request()
            self.assertEqual(fx.evaluate_binding()["status"], BINDING_HOLD)


class MergeAuthorizationTests(unittest.TestCase):
    def test_exact_authorization_passes_without_merging(self):
        with tempfile.TemporaryDirectory() as td:
            fx = IntegratedFixture(Path(td))
            receipt = fx.evaluate_merge()
            self.assertEqual(receipt["status"], MERGE_PASS)
            self.assertEqual(receipt["outcome"], "MERGE_EXECUTION_MAY_BE_REQUESTED_ONCE")
            self.assertFalse(receipt["merge_executed"])

    def test_base_drift_holds(self):
        with tempfile.TemporaryDirectory() as td:
            fx = IntegratedFixture(Path(td))
            obj = json.loads(fx.branch_protection.read_text())
            obj["base_head"] = "9" * 40
            fx.write(fx.branch_protection, obj)
            fx.rebind_human_subject()
            fx.rebind_merge_request()
            self.assertEqual(fx.evaluate_merge()["status"], MERGE_HOLD)

    def test_auto_merge_enabled_revises(self):
        with tempfile.TemporaryDirectory() as td:
            fx = IntegratedFixture(Path(td))
            obj = json.loads(fx.pull_request.read_text())
            obj["auto_merge_enabled"] = True
            fx.write(fx.pull_request, obj)
            fx.rebind_human_subject()
            fx.rebind_merge_request()
            self.assertEqual(fx.evaluate_merge()["status"], MERGE_REVISE)

    def test_self_review_fails_approval_threshold(self):
        with tempfile.TemporaryDirectory() as td:
            fx = IntegratedFixture(Path(td))
            obj = json.loads(fx.pull_request.read_text())
            obj["approvals"][0]["actor_id"] = obj["author_actor_id"]
            fx.write(fx.pull_request, obj)
            fx.rebind_human_subject()
            fx.rebind_merge_request()
            self.assertEqual(fx.evaluate_merge()["status"], MERGE_HOLD)

    def test_failed_required_check_revises(self):
        with tempfile.TemporaryDirectory() as td:
            fx = IntegratedFixture(Path(td))
            obj = json.loads(fx.pull_request.read_text())
            obj["checks"][0]["conclusion"] = "failure"
            fx.write(fx.pull_request, obj)
            fx.rebind_human_subject()
            fx.rebind_merge_request()
            self.assertEqual(fx.evaluate_merge()["status"], MERGE_REVISE)

    def test_expired_human_decision_holds(self):
        with tempfile.TemporaryDirectory() as td:
            fx = IntegratedFixture(Path(td))
            obj = json.loads(fx.human.read_text())
            old = datetime.now(timezone.utc) - timedelta(hours=2)
            obj["issued_at_utc"] = old.isoformat()
            obj["expires_at_utc"] = (old + timedelta(minutes=30)).isoformat()
            fx.write(fx.human, obj)
            fx.rebind_merge_request()
            self.assertEqual(fx.evaluate_merge()["status"], MERGE_HOLD)

    def test_wrong_human_subject_revises(self):
        with tempfile.TemporaryDirectory() as td:
            fx = IntegratedFixture(Path(td))
            obj = json.loads(fx.human.read_text())
            obj["authorization_subject_sha256"] = "f" * 64
            fx.write(fx.human, obj)
            fx.rebind_merge_request()
            self.assertEqual(fx.evaluate_merge()["status"], MERGE_REVISE)

    def test_destructive_rollback_revises(self):
        with tempfile.TemporaryDirectory() as td:
            fx = IntegratedFixture(Path(td))
            obj = json.loads(fx.rollback.read_text())
            obj["destructive_reset"] = True
            fx.write(fx.rollback, obj)
            fx.rebind_human_subject()
            fx.rebind_merge_request()
            self.assertEqual(fx.evaluate_merge()["status"], MERGE_REVISE)


if __name__ == "__main__":
    unittest.main()
