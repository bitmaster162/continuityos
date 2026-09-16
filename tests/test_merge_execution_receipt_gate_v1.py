from __future__ import annotations

from datetime import datetime, timedelta, timezone
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

from continuityos.gate.evidence_common import fixed_effects, sha256_file
from continuityos.gate.merge_execution import (
    HOLD,
    REVISE,
    VERIFIED,
    evaluate_merge_execution,
)
from continuityos.trusted_merge_handoff import build_dual_control_merge_handoff


def load_integrated_fixture():
    path = Path(__file__).with_name(
        "test_control_plane_binding_merge_authorization_v1.py"
    )
    spec = importlib.util.spec_from_file_location("_r14_integrated_fixture", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module.IntegratedFixture


IntegratedFixture = load_integrated_fixture()


def load_r20_fixture():
    path = Path(__file__).with_name("test_trusted_merge_handoff.py")
    spec = importlib.util.spec_from_file_location("_r20_fixture", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


R20 = load_r20_fixture()


class MergeExecutionFixture:
    def __init__(self, root: Path):
        self.root = root
        r14_root = root / "r14"
        r14_root.mkdir(parents=True, exist_ok=True)
        self.r14 = IntegratedFixture(r14_root)

        self.authorization = root / "MERGE_AUTHORIZATION.json"
        self.handoff = root / "DUAL_CONTROL_HANDOFF.json"
        self.registry = root / "TRUSTED_HUMAN_KEY_REGISTRY.json"
        self.host = root / "HOST_EXECUTION.json"
        self.pr = root / "PR_READBACK.json"
        self.commit = root / "MERGE_COMMIT_READBACK.json"
        self.base = root / "BASE_READBACK.json"
        self.protection = root / "PROTECTION_READBACK.json"
        self.consumption = root / "CONSUMPTION.json"
        self.request = root / "MERGE_EXECUTION_REQUEST.json"

        authorization = self.r14.evaluate_merge()
        if authorization.get("status") != "MERGE_AUTHORIZATION_PASS":
            raise AssertionError(authorization)
        self.write(self.authorization, authorization)

        self.repo_name = self.r14.repo_name
        self.visibility = self.r14.visibility
        self.base_branch = self.r14.base_branch
        self.base_head = self.r14.base_head
        self.base_tree = self.r14.base_tree
        self.candidate_branch = self.r14.branch
        self.candidate_head = self.r14.head
        self.candidate_tree = self.r14.tree
        self.pr_number = 42
        self.merge_sha = "a" * 40
        self.merge_tree = "b" * 40
        self.executor = "bitmaster162"
        self.validation_now = datetime.fromtimestamp(R20.R17.NOW, tz=timezone.utc)
        self.executed_at = self.validation_now - timedelta(minutes=2)
        eligibility, registry, registry_pin = R20._r19_eligibility_for(
            repository=self.repo_name, base=self.base_head, base_tree=self.base_tree,
            head=self.candidate_head, tree=self.candidate_tree,
        )
        self.registry_pin = registry_pin
        self.write(self.registry, registry)
        handoff = build_dual_control_merge_handoff(
            eligibility_receipt=eligibility, merge_authorization_receipt=authorization,
            pinned_merge_authorization_sha256=R20._pin(authorization),
            trusted_key_registry=registry, pinned_registry_sha256=registry_pin,
            repository=self.repo_name, current_base_sha=self.base_head,
            current_head_sha=self.candidate_head, current_tree_sha=self.candidate_tree,
            now_unix=R20.R17.NOW, base_branch=self.base_branch,
            candidate_branch=self.candidate_branch, pull_request_number=self.pr_number,
        )
        self.write(self.handoff, handoff)
        self.required_checks = ["CI", "security"]
        self.required_approvals = 1
        self.write_all()

    @staticmethod
    def write(path: Path, value: dict) -> None:
        path.write_text(
            json.dumps(value, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )

    def write_all(self) -> None:
        auth = json.loads(self.authorization.read_text())
        self.write(
            self.host,
            {
                "schema": "continuityos.merge_execution.host_receipt/v2",
                "provider": "GITHUB",
                "repository": self.repo_name,
                "pull_request_number": self.pr_number,
                "authorization_receipt_sha256": sha256_file(self.authorization),
                "dual_control_handoff_sha256": sha256_file(self.handoff),
                "authorization_subject_sha256": auth[
                    "authorization_subject_sha256"
                ],
                "authorization_nonce": auth["authorization_nonce"],
                "merge_method": "MERGE_COMMIT",
                "base_branch": self.base_branch,
                "base_head_before": self.base_head,
                "base_tree_before": self.base_tree,
                "candidate_branch": self.candidate_branch,
                "candidate_head": self.candidate_head,
                "candidate_tree": self.candidate_tree,
                "merge_commit": {
                    "sha": self.merge_sha,
                    "tree": self.merge_tree,
                    "parents": [self.base_head, self.candidate_head],
                },
                "executor_actor_id": self.executor,
                "force_push": False,
                "auto_merge": False,
                "visibility_before": self.visibility,
                "visibility_after": self.visibility,
                "executed_at_utc": self.executed_at.isoformat(),
                "effects": fixed_effects(merge=True),
            },
        )
        self.write(
            self.pr,
            {
                "schema": "continuityos.merge_execution.pull_request_readback/v1",
                "provider": "GITHUB",
                "readback": True,
                "repository": self.repo_name,
                "number": self.pr_number,
                "state": "MERGED",
                "merged": True,
                "merge_method": "MERGE_COMMIT",
                "auto_merge_used": False,
                "base_branch": self.base_branch,
                "base_head_before": self.base_head,
                "head_branch": self.candidate_branch,
                "head_sha": self.candidate_head,
                "head_tree": self.candidate_tree,
                "merge_commit_sha": self.merge_sha,
                "merge_commit_tree": self.merge_tree,
                "merged_by_actor_id": self.executor,
                "merged_at_utc": (self.executed_at + timedelta(seconds=1)).isoformat(),
            },
        )
        self.write(
            self.commit,
            {
                "schema": "continuityos.merge_execution.merge_commit_readback/v1",
                "provider": "GITHUB",
                "readback": True,
                "verified": True,
                "repository": self.repo_name,
                "sha": self.merge_sha,
                "tree": self.merge_tree,
                "parents": [self.base_head, self.candidate_head],
                "read_at_utc": (self.executed_at + timedelta(seconds=2)).isoformat(),
            },
        )
        self.write(
            self.base,
            {
                "schema": "continuityos.merge_execution.base_branch_readback/v1",
                "provider": "GITHUB",
                "readback": True,
                "repository": self.repo_name,
                "branch": self.base_branch,
                "head": self.merge_sha,
                "tree": self.merge_tree,
                "visibility": self.visibility,
                "read_at_utc": (self.executed_at + timedelta(seconds=3)).isoformat(),
            },
        )
        self.write(
            self.protection,
            {
                "schema": "continuityos.merge_execution.branch_protection_readback/v1",
                "provider": "GITHUB",
                "readback": True,
                "repository": self.repo_name,
                "branch": self.base_branch,
                "base_head": self.merge_sha,
                "force_push_allowed": False,
                "deletion_allowed": False,
                "required_checks": self.required_checks,
                "required_approvals": self.required_approvals,
                "visibility": self.visibility,
                "read_at_utc": (self.executed_at + timedelta(seconds=4)).isoformat(),
            },
        )
        self.write(
            self.consumption,
            {
                "schema": "continuityos.merge_execution.authorization_consumption/v2",
                "store_readback": True,
                "authorization_receipt_sha256": sha256_file(self.authorization),
                "dual_control_handoff_sha256": sha256_file(self.handoff),
                "authorization_subject_sha256": auth[
                    "authorization_subject_sha256"
                ],
                "authorization_nonce": auth["authorization_nonce"],
                "consumed": True,
                "use_count": 1,
                "reused": False,
                "merge_commit_sha": self.merge_sha,
                "executor_actor_id": self.executor,
                "consumed_at_utc": (
                    self.executed_at + timedelta(seconds=5)
                ).isoformat(),
                "effects": fixed_effects(merge=True),
            },
        )
        self.rebind_request()

    def rebind_request(self) -> None:
        auth = json.loads(self.authorization.read_text())
        self.write(
            self.request,
            {
                "schema": "continuityos.merge_execution.request/v2",
                "authority_generation": "R63",
                "subject": {
                    "repository": self.repo_name,
                    "visibility_before": self.visibility,
                    "base": {
                        "branch": self.base_branch,
                        "head_before": self.base_head,
                        "tree_before": self.base_tree,
                    },
                    "candidate": {
                        "branch": self.candidate_branch,
                        "head": self.candidate_head,
                        "tree": self.candidate_tree,
                    },
                    "pull_request_number": self.pr_number,
                },
                "authorization": {
                    "receipt_sha256": sha256_file(self.authorization),
                    "subject_sha256": auth["authorization_subject_sha256"],
                    "nonce": auth["authorization_nonce"],
                },
                "bindings": {
                    "authorization_receipt_sha256": sha256_file(
                        self.authorization
                    ),
                    "dual_control_handoff_sha256": sha256_file(self.handoff),
                    "host_execution_receipt_sha256": sha256_file(self.host),
                    "pull_request_readback_sha256": sha256_file(self.pr),
                    "merge_commit_readback_sha256": sha256_file(self.commit),
                    "base_branch_readback_sha256": sha256_file(self.base),
                    "branch_protection_readback_sha256": sha256_file(
                        self.protection
                    ),
                    "authorization_consumption_sha256": sha256_file(
                        self.consumption
                    ),
                },
                "policy": {
                    "merge_method": "MERGE_COMMIT",
                    "required_checks": self.required_checks,
                    "required_approvals": self.required_approvals,
                    "preserve_branch_protection": True,
                    "preserve_visibility": True,
                    "max_clock_skew_seconds": 300,
                },
                "effects": fixed_effects(),
            },
        )

    def evaluate(self, *, registry_pin=None, now=None):
        return evaluate_merge_execution(
            self.request,
            self.authorization,
            self.handoff,
            self.registry,
            self.host,
            self.pr,
            self.commit,
            self.base,
            self.protection,
            self.consumption,
            pinned_registry_sha256=registry_pin or self.registry_pin,
            now=now or self.validation_now,
        )


class MergeExecutionTests(unittest.TestCase):
    def test_exact_external_merge_is_verified_without_gate_execution(self):
        with tempfile.TemporaryDirectory() as td:
            fx = MergeExecutionFixture(Path(td))
            receipt = fx.evaluate()
            self.assertEqual(receipt["status"], VERIFIED)
            self.assertEqual(receipt["outcome"], "MERGE_RESULT_PROVEN")
            self.assertTrue(receipt["external_merge_verified"])
            self.assertFalse(receipt["gate_merge_executed"])

    def test_missing_pr_readback_holds(self):
        with tempfile.TemporaryDirectory() as td:
            fx = MergeExecutionFixture(Path(td))
            fx.pr.unlink()
            self.assertEqual(fx.evaluate()["status"], HOLD)

    def test_authorization_hold_holds(self):
        with tempfile.TemporaryDirectory() as td:
            fx = MergeExecutionFixture(Path(td))
            obj = json.loads(fx.authorization.read_text())
            obj["status"] = "MERGE_AUTHORIZATION_HOLD"
            obj["outcome"] = "WOULD_HOLD"
            fx.write(fx.authorization, obj)
            fx.write_all()
            self.assertEqual(fx.evaluate()["status"], HOLD)

    def test_wrong_merge_parent_order_revises(self):
        with tempfile.TemporaryDirectory() as td:
            fx = MergeExecutionFixture(Path(td))
            obj = json.loads(fx.host.read_text())
            obj["merge_commit"]["parents"] = [fx.candidate_head, fx.base_head]
            fx.write(fx.host, obj)
            fx.rebind_request()
            self.assertEqual(fx.evaluate()["status"], REVISE)

    def test_unmerged_pr_holds(self):
        with tempfile.TemporaryDirectory() as td:
            fx = MergeExecutionFixture(Path(td))
            obj = json.loads(fx.pr.read_text())
            obj["state"] = "OPEN"
            obj["merged"] = False
            fx.write(fx.pr, obj)
            fx.rebind_request()
            self.assertEqual(fx.evaluate()["status"], HOLD)

    def test_base_readback_mismatch_revises(self):
        with tempfile.TemporaryDirectory() as td:
            fx = MergeExecutionFixture(Path(td))
            obj = json.loads(fx.base.read_text())
            obj["head"] = "c" * 40
            fx.write(fx.base, obj)
            fx.rebind_request()
            self.assertEqual(fx.evaluate()["status"], REVISE)

    def test_branch_protection_weakening_revises(self):
        with tempfile.TemporaryDirectory() as td:
            fx = MergeExecutionFixture(Path(td))
            obj = json.loads(fx.protection.read_text())
            obj["force_push_allowed"] = True
            fx.write(fx.protection, obj)
            fx.rebind_request()
            self.assertEqual(fx.evaluate()["status"], REVISE)

    def test_authorization_reuse_revises(self):
        with tempfile.TemporaryDirectory() as td:
            fx = MergeExecutionFixture(Path(td))
            obj = json.loads(fx.consumption.read_text())
            obj["use_count"] = 2
            obj["reused"] = True
            fx.write(fx.consumption, obj)
            fx.rebind_request()
            self.assertEqual(fx.evaluate()["status"], REVISE)

    def test_visibility_change_revises(self):
        with tempfile.TemporaryDirectory() as td:
            fx = MergeExecutionFixture(Path(td))
            obj = json.loads(fx.host.read_text())
            obj["visibility_after"] = "PUBLIC" if fx.visibility == "PRIVATE" else "PRIVATE"
            fx.write(fx.host, obj)
            fx.rebind_request()
            self.assertEqual(fx.evaluate()["status"], REVISE)

    def test_deployment_widening_revises(self):
        with tempfile.TemporaryDirectory() as td:
            fx = MergeExecutionFixture(Path(td))
            obj = json.loads(fx.host.read_text())
            obj["effects"]["deployment"] = True
            fx.write(fx.host, obj)
            fx.rebind_request()
            self.assertEqual(fx.evaluate()["status"], REVISE)

    def test_wrong_authorization_subject_revises(self):
        with tempfile.TemporaryDirectory() as td:
            fx = MergeExecutionFixture(Path(td))
            obj = json.loads(fx.host.read_text())
            obj["authorization_subject_sha256"] = "f" * 64
            fx.write(fx.host, obj)
            fx.rebind_request()
            self.assertEqual(fx.evaluate()["status"], REVISE)

    def test_duplicate_json_key_revises(self):
        with tempfile.TemporaryDirectory() as td:
            fx = MergeExecutionFixture(Path(td))
            original = json.loads(fx.consumption.read_text())
            text = json.dumps(original, sort_keys=True, indent=2)
            text = text.replace(
                '  "consumed": true,',
                '  "consumed": true,\n  "consumed": true,',
                1,
            )
            fx.consumption.write_text(text + "\n", encoding="utf-8")
            fx.rebind_request()
            self.assertEqual(fx.evaluate()["status"], REVISE)

    def test_provider_readback_incomplete_holds(self):
        with tempfile.TemporaryDirectory() as td:
            fx = MergeExecutionFixture(Path(td))
            obj = json.loads(fx.commit.read_text())
            obj["readback"] = False
            obj["verified"] = False
            fx.write(fx.commit, obj)
            fx.rebind_request()
            self.assertEqual(fx.evaluate()["status"], HOLD)

    def test_consumption_before_execution_revises(self):
        with tempfile.TemporaryDirectory() as td:
            fx = MergeExecutionFixture(Path(td))
            obj = json.loads(fx.consumption.read_text())
            obj["consumed_at_utc"] = (
                fx.executed_at - timedelta(seconds=1)
            ).isoformat()
            fx.write(fx.consumption, obj)
            fx.rebind_request()
            self.assertEqual(fx.evaluate()["status"], REVISE)

    def test_request_effect_widening_revises(self):
        with tempfile.TemporaryDirectory() as td:
            fx = MergeExecutionFixture(Path(td))
            obj = json.loads(fx.request.read_text())
            obj["effects"]["merge"] = True
            fx.write(fx.request, obj)
            self.assertEqual(fx.evaluate()["status"], REVISE)


    def test_missing_dual_control_handoff_holds(self):
        with tempfile.TemporaryDirectory() as td:
            fx = MergeExecutionFixture(Path(td))
            fx.handoff.unlink()
            self.assertEqual(fx.evaluate()["status"], HOLD)

    def test_tampered_dual_control_handoff_revises(self):
        with tempfile.TemporaryDirectory() as td:
            fx = MergeExecutionFixture(Path(td))
            obj = json.loads(fx.handoff.read_text())
            obj["pull_request_number"] += 1
            fx.write(fx.handoff, obj)
            fx.rebind_request()
            self.assertEqual(fx.evaluate()["status"], REVISE)

    def test_wrong_trusted_registry_pin_revises(self):
        with tempfile.TemporaryDirectory() as td:
            fx = MergeExecutionFixture(Path(td))
            self.assertEqual(fx.evaluate(registry_pin="0" * 64)["status"], REVISE)

    def test_host_must_bind_dual_control_handoff(self):
        with tempfile.TemporaryDirectory() as td:
            fx = MergeExecutionFixture(Path(td))
            obj = json.loads(fx.host.read_text())
            obj["dual_control_handoff_sha256"] = "f" * 64
            fx.write(fx.host, obj)
            fx.rebind_request()
            self.assertEqual(fx.evaluate()["status"], REVISE)

    def test_consumption_must_bind_dual_control_handoff(self):
        with tempfile.TemporaryDirectory() as td:
            fx = MergeExecutionFixture(Path(td))
            obj = json.loads(fx.consumption.read_text())
            obj["dual_control_handoff_sha256"] = "f" * 64
            fx.write(fx.consumption, obj)
            fx.rebind_request()
            self.assertEqual(fx.evaluate()["status"], REVISE)

    def test_expired_r19_inside_handoff_revises_execution_verification(self):
        with tempfile.TemporaryDirectory() as td:
            fx = MergeExecutionFixture(Path(td))
            expired = datetime.fromtimestamp(R20.R17.NOW + 301, tz=timezone.utc)
            self.assertEqual(fx.evaluate(now=expired)["status"], REVISE)

    def test_v1_execution_request_is_not_admissible_under_r22(self):
        with tempfile.TemporaryDirectory() as td:
            fx = MergeExecutionFixture(Path(td))
            obj = json.loads(fx.request.read_text())
            obj["schema"] = "continuityos.merge_execution.request/v1"
            fx.write(fx.request, obj)
            self.assertEqual(fx.evaluate()["status"], REVISE)



if __name__ == "__main__":
    unittest.main()
