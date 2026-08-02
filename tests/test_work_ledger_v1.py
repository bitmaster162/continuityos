from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from continuityos.gate.work_ledger import (
    EVENT_SCHEMA,
    EXTEND_PASS,
    FINALIZE_PASS,
    INIT_PASS,
    LEDGER_HOLD,
    LEDGER_REVISE,
    PROJECT_PASS,
    SEMANTIC_SCHEMA,
    TRANSPORT_SCHEMA,
    VERIFY_PASS,
    _event_digest,
    append_work_delta,
    append_work_semantic_review,
    append_work_transport,
    canonical_json_text,
    finalize_work_ledger,
    initialize_work_ledger,
    project_work_ledger,
    sha256_file,
    verify_work_ledger,
)


SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
SHA_D = "d" * 64
SHA_E = "e" * 64
HEAD = "1" * 40
TREE = "2" * 40


def no_effects(**extra):
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


class Fixture:
    def __init__(self, root: Path):
        self.root = root
        self.admission = root / "admission.json"
        self.delta = root / "delta.json"
        self.transport = root / "transport.json"
        self.semantic = root / "semantic.json"
        self.l0 = root / "ledger-0.jsonl"
        self.l1 = root / "ledger-1.jsonl"
        self.l2 = root / "ledger-2.jsonl"
        self.l3 = root / "ledger-3.jsonl"
        self.l4 = root / "ledger-4.jsonl"
        self.task_id = "CONTINUITYOS_TEST_WORK_LEDGER_V1"
        self.binding_sha = SHA_A
        self._write_admission()

    def _write(self, path: Path, obj: dict):
        path.write_text(json.dumps(obj, indent=2) + "\n", encoding="utf-8")

    def admission_obj(self):
        effects = no_effects(worktree_write=True, test_execution=True, local_commit=True)
        return {
            "schema": "continuityos.work_admission.receipt/v1",
            "status": "WORK_ADMISSION_PASS",
            "outcome": "WOULD_ALLOW",
            "live_state_modified": False,
            "writes_performed": [],
            "can_trade": False,
            "capital_permission": "DENY",
            "deploy_permission": "DENY",
            "self_application": False,
            "request_sha256": SHA_B,
            "work_order_sha256": SHA_C,
            "session_capsule_sha256": SHA_D,
            "admission_binding_sha256": self.binding_sha,
            "binding": {
                "authority_generation": "R63",
                "task_id": self.task_id,
                "effects": effects,
                "repository": {
                    "owner": "bitmaster162",
                    "name": "continuityos",
                    "base_branch": "gpt/base",
                    "base_head": "3" * 40,
                    "base_tree": "4" * 40,
                    "candidate_branch": "gpt/candidate",
                },
            },
            "request": {
                "task": {"task_body_sha256": SHA_E},
                "repository": {
                    "remote_url": "https://github.com/bitmaster162/continuityos.git",
                    "visibility": "PRIVATE",
                },
            },
        }

    def _write_admission(self, mutate=None):
        obj = self.admission_obj()
        if mutate:
            mutate(obj)
        self._write(self.admission, obj)

    def init(self):
        return initialize_work_ledger(self.admission, self.l0)

    def delta_obj(self):
        return {
            "schema": "continuityos.work_admission.delta_receipt/v1",
            "status": "WORK_DELTA_PASS",
            "outcome": "WOULD_ALLOW_CANDIDATE_TRANSPORT",
            "task_id": self.task_id,
            "admission_binding_sha256": self.binding_sha,
            "admission_receipt_sha256": sha256_file(self.admission),
            "validation_receipt_sha256": "5" * 64,
            "live_state_modified": False,
            "writes_performed": [],
            "can_trade": False,
            "capital_permission": "DENY",
            "deploy_permission": "DENY",
            "self_application": False,
            "repository_observed": {
                "branch": "gpt/candidate",
                "head": HEAD,
                "tree": TREE,
            },
            "changed_files": [
                {
                    "status": "A",
                    "path": "continuityos/gate/work_ledger.py",
                    "positive_byte_delta": 120,
                }
            ],
        }

    def write_delta(self, mutate=None):
        obj = self.delta_obj()
        if mutate:
            mutate(obj)
        self._write(self.delta, obj)

    def append_delta(self, mutate=None):
        self.write_delta(mutate)
        return append_work_delta(self.l0, self.delta, self.l1)

    def transport_obj(self):
        return {
            "schema": TRANSPORT_SCHEMA,
            "authority_generation": "R63",
            "task_id": self.task_id,
            "admission_binding_sha256": self.binding_sha,
            "delta_receipt_sha256": sha256_file(self.delta),
            "repository": {
                "owner": "bitmaster162",
                "name": "continuityos",
                "remote_url": "https://github.com/bitmaster162/continuityos.git",
                "visibility": "PRIVATE",
                "candidate_branch": "gpt/candidate",
            },
            "candidate": {"head": HEAD, "tree": TREE},
            "remote": {"head": HEAD, "tree": TREE, "visibility": "PRIVATE"},
            "actions": {
                "status": "SUCCESS",
                "run_id": 123,
                "head_sha": HEAD,
                "conclusion": "success",
            },
            "executor": {"role": "HOST_EXECUTOR", "id": "ANTIGRAVITY"},
            "terminal": "WORK_TRANSPORT_PASS",
            "effects": no_effects(candidate_push=True),
        }

    def write_transport(self, mutate=None):
        obj = self.transport_obj()
        if mutate:
            mutate(obj)
        self._write(self.transport, obj)

    def append_transport(self, mutate=None):
        self.write_transport(mutate)
        return append_work_transport(self.l1, self.transport, self.l2)

    def semantic_obj(self, verdict="ACCEPT", conditions=None):
        if conditions is None:
            conditions = [] if verdict == "ACCEPT" else ["condition"]
        return {
            "schema": SEMANTIC_SCHEMA,
            "authority_generation": "R63",
            "task_id": self.task_id,
            "admission_binding_sha256": self.binding_sha,
            "delta_receipt_sha256": sha256_file(self.delta),
            "transport_receipt_sha256": sha256_file(self.transport),
            "candidate": {"head": HEAD, "tree": TREE},
            "reviewer": {"role": "GPT_CONTROLLER", "id": "GPT"},
            "verdict": verdict,
            "conditions": conditions,
            "content_status": "REVIEWED",
            "apply_status": "NOT_APPLIED",
            "effects": no_effects(),
        }

    def write_semantic(self, verdict="ACCEPT", conditions=None, mutate=None):
        obj = self.semantic_obj(verdict, conditions)
        if mutate:
            mutate(obj)
        self._write(self.semantic, obj)

    def append_semantic(self, verdict="ACCEPT", conditions=None, mutate=None):
        self.write_semantic(verdict, conditions, mutate)
        return append_work_semantic_review(self.l2, self.semantic, self.l3)

    def full_to_transport(self):
        self.assert_status(self.init(), INIT_PASS)
        self.assert_status(self.append_delta(), EXTEND_PASS)
        self.assert_status(self.append_transport(), EXTEND_PASS)

    @staticmethod
    def assert_status(receipt, status):
        if receipt["status"] != status:
            raise AssertionError(receipt)


class WorkLedgerTests(unittest.TestCase):
    def test_init_verify_and_project(self):
        with tempfile.TemporaryDirectory() as td:
            fx = Fixture(Path(td))
            self.assertEqual(fx.init()["status"], INIT_PASS)
            self.assertEqual(verify_work_ledger(fx.l0)["status"], VERIFY_PASS)
            projected = project_work_ledger(fx.l0)
            self.assertEqual(projected["status"], PROJECT_PASS)
            self.assertEqual(projected["projection"]["state"], "ADMITTED")
            self.assertEqual(projected["projection"]["identity"]["task_id"], fx.task_id)

    def test_init_rejects_non_pass_admission(self):
        with tempfile.TemporaryDirectory() as td:
            fx = Fixture(Path(td))
            fx._write_admission(lambda o: o.__setitem__("status", "WORK_ADMISSION_REVISE"))
            self.assertEqual(fx.init()["status"], LEDGER_REVISE)
            self.assertFalse(fx.l0.exists())

    def test_init_rejects_authority_widening(self):
        with tempfile.TemporaryDirectory() as td:
            fx = Fixture(Path(td))
            fx._write_admission(lambda o: o["binding"].__setitem__("authority_generation", "R64"))
            self.assertEqual(fx.init()["status"], LEDGER_REVISE)

    def test_init_rejects_top_level_trade_widening(self):
        with tempfile.TemporaryDirectory() as td:
            fx = Fixture(Path(td))
            fx._write_admission(lambda o: o.__setitem__("can_trade", True))
            self.assertEqual(fx.init()["status"], LEDGER_REVISE)

    def test_output_must_not_exist(self):
        with tempfile.TemporaryDirectory() as td:
            fx = Fixture(Path(td))
            fx.l0.write_text("occupied\n", encoding="utf-8")
            self.assertEqual(fx.init()["status"], LEDGER_REVISE)

    def test_tampered_hash_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            fx = Fixture(Path(td)); fx.init()
            event = json.loads(fx.l0.read_text())
            event["payload"]["admission_status"] = "WORK_ADMISSION_REVISE"
            fx.l0.write_text(canonical_json_text(event), encoding="utf-8")
            self.assertEqual(verify_work_ledger(fx.l0)["status"], LEDGER_REVISE)

    def test_noncanonical_jsonl_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            fx = Fixture(Path(td)); fx.init()
            event = json.loads(fx.l0.read_text())
            fx.l0.write_text(json.dumps(event, indent=2) + "\n", encoding="utf-8")
            self.assertEqual(verify_work_ledger(fx.l0)["status"], LEDGER_REVISE)

    def test_prev_hash_tamper_rejected_even_with_rehashed_event(self):
        with tempfile.TemporaryDirectory() as td:
            fx = Fixture(Path(td)); fx.init(); fx.append_delta()
            lines = fx.l1.read_text().splitlines()
            second = json.loads(lines[1])
            second["prev_event_sha256"] = "f" * 64
            second["event_sha256"] = _event_digest(second)
            fx.l1.write_text(lines[0] + "\n" + canonical_json_text(second), encoding="utf-8")
            self.assertEqual(verify_work_ledger(fx.l1)["status"], LEDGER_REVISE)

    def test_timestamp_may_not_move_backwards(self):
        with tempfile.TemporaryDirectory() as td:
            fx = Fixture(Path(td)); fx.init(); fx.append_delta()
            lines = fx.l1.read_text().splitlines()
            second = json.loads(lines[1])
            second["recorded_at_utc"] = "2000-01-01T00:00:00+00:00"
            second["event_sha256"] = _event_digest(second)
            fx.l1.write_text(lines[0] + "\n" + canonical_json_text(second), encoding="utf-8")
            self.assertEqual(verify_work_ledger(fx.l1)["status"], LEDGER_REVISE)

    def test_valid_delta(self):
        with tempfile.TemporaryDirectory() as td:
            fx = Fixture(Path(td)); fx.init()
            receipt = fx.append_delta()
            self.assertEqual(receipt["status"], EXTEND_PASS)
            self.assertEqual(receipt["projection"]["state"], "DELTA_VERIFIED")
            self.assertEqual(receipt["projection"]["candidate_head"], HEAD)

    def test_delta_wrong_binding_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            fx = Fixture(Path(td)); fx.init()
            receipt = fx.append_delta(lambda o: o.__setitem__("admission_binding_sha256", "9" * 64))
            self.assertEqual(receipt["status"], LEDGER_REVISE)
            self.assertFalse(fx.l1.exists())

    def test_delta_trade_widening_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            fx = Fixture(Path(td)); fx.init()
            receipt = fx.append_delta(lambda o: o.__setitem__("can_trade", True))
            self.assertEqual(receipt["status"], LEDGER_REVISE)

    def test_second_delta_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            fx = Fixture(Path(td)); fx.init(); fx.append_delta()
            fx.write_delta()
            receipt = append_work_delta(fx.l1, fx.delta, fx.l2)
            self.assertEqual(receipt["status"], LEDGER_REVISE)

    def test_valid_transport(self):
        with tempfile.TemporaryDirectory() as td:
            fx = Fixture(Path(td)); fx.init(); fx.append_delta()
            receipt = fx.append_transport()
            self.assertEqual(receipt["status"], EXTEND_PASS)
            self.assertEqual(receipt["projection"]["state"], "TRANSPORT_VERIFIED")
            self.assertEqual(receipt["projection"]["remote_head"], HEAD)

    def test_transport_force_push_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            fx = Fixture(Path(td)); fx.init(); fx.append_delta()
            receipt = fx.append_transport(lambda o: o["effects"].__setitem__("force_push", True))
            self.assertEqual(receipt["status"], LEDGER_REVISE)

    def test_transport_remote_mismatch_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            fx = Fixture(Path(td)); fx.init(); fx.append_delta()
            receipt = fx.append_transport(lambda o: o["remote"].__setitem__("head", "9" * 40))
            self.assertEqual(receipt["status"], LEDGER_REVISE)

    def test_transport_actions_wrong_head_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            fx = Fixture(Path(td)); fx.init(); fx.append_delta()
            receipt = fx.append_transport(lambda o: o["actions"].__setitem__("head_sha", "9" * 40))
            self.assertEqual(receipt["status"], LEDGER_REVISE)

    def test_transport_without_workflow_is_supported(self):
        with tempfile.TemporaryDirectory() as td:
            fx = Fixture(Path(td)); fx.init(); fx.append_delta()
            def mutate(o):
                o["actions"] = {"status": "NOT_CONFIGURED", "run_id": None, "head_sha": None, "conclusion": "not_configured"}
            receipt = fx.append_transport(mutate)
            self.assertEqual(receipt["status"], EXTEND_PASS)

    def test_transport_unknown_field_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            fx = Fixture(Path(td)); fx.init(); fx.append_delta()
            receipt = fx.append_transport(lambda o: o.__setitem__("surprise", True))
            self.assertEqual(receipt["status"], LEDGER_REVISE)

    def test_valid_semantic_accept_and_finalize(self):
        with tempfile.TemporaryDirectory() as td:
            fx = Fixture(Path(td)); fx.full_to_transport()
            receipt = fx.append_semantic("ACCEPT", [])
            self.assertEqual(receipt["status"], EXTEND_PASS)
            self.assertEqual(receipt["projection"]["state"], "SEMANTIC_ACCEPTED")
            final = finalize_work_ledger(fx.l3, fx.l4)
            self.assertEqual(final["status"], FINALIZE_PASS)
            self.assertEqual(final["projection"]["state"], "CLOSED")
            self.assertTrue(final["projection"]["integration_candidate_eligible"])

    def test_fable_cannot_semantically_accept(self):
        with tempfile.TemporaryDirectory() as td:
            fx = Fixture(Path(td)); fx.full_to_transport()
            receipt = fx.append_semantic(mutate=lambda o: o.__setitem__("reviewer", {"role": "GPT_CONTROLLER", "id": "FABLE-5"}))
            self.assertEqual(receipt["status"], LEDGER_REVISE)

    def test_pass_with_conditions_requires_condition(self):
        with tempfile.TemporaryDirectory() as td:
            fx = Fixture(Path(td)); fx.full_to_transport()
            receipt = fx.append_semantic("PASS_WITH_CONDITIONS", [])
            self.assertEqual(receipt["status"], LEDGER_REVISE)

    def test_hold_can_be_reviewed_again(self):
        with tempfile.TemporaryDirectory() as td:
            fx = Fixture(Path(td)); fx.full_to_transport()
            held = fx.append_semantic("HOLD", ["await human evidence"])
            self.assertEqual(held["projection"]["state"], "HELD")
            finalize = finalize_work_ledger(fx.l3, fx.l4)
            self.assertEqual(finalize["status"], LEDGER_HOLD)
            self.assertFalse(fx.l4.exists())
            second_decision = fx.root / "semantic-2.json"
            obj = fx.semantic_obj("ACCEPT", [])
            second_decision.write_text(json.dumps(obj), encoding="utf-8")
            reviewed = append_work_semantic_review(fx.l3, second_decision, fx.l4)
            self.assertEqual(reviewed["status"], EXTEND_PASS)
            self.assertEqual(reviewed["projection"]["state"], "SEMANTIC_ACCEPTED")

    def test_revise_finalizes_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            fx = Fixture(Path(td)); fx.full_to_transport()
            fx.append_semantic("REVISE", ["material defect"])
            final = finalize_work_ledger(fx.l3, fx.l4)
            self.assertEqual(final["status"], FINALIZE_PASS)
            self.assertEqual(final["projection"]["state"], "REJECTED")
            self.assertFalse(final["projection"]["integration_candidate_eligible"])

    def test_terminal_ledger_cannot_be_extended(self):
        with tempfile.TemporaryDirectory() as td:
            fx = Fixture(Path(td)); fx.full_to_transport(); fx.append_semantic(); finalize_work_ledger(fx.l3, fx.l4)
            extra = fx.root / "extra.jsonl"
            fx.write_semantic("ACCEPT", [])
            receipt = append_work_semantic_review(fx.l4, fx.semantic, extra)
            self.assertEqual(receipt["status"], LEDGER_REVISE)

    def test_semantic_apply_status_must_remain_not_applied(self):
        with tempfile.TemporaryDirectory() as td:
            fx = Fixture(Path(td)); fx.full_to_transport()
            receipt = fx.append_semantic(mutate=lambda o: o.__setitem__("apply_status", "APPLIED"))
            self.assertEqual(receipt["status"], LEDGER_REVISE)

    def test_semantic_candidate_mismatch_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            fx = Fixture(Path(td)); fx.full_to_transport()
            receipt = fx.append_semantic(mutate=lambda o: o["candidate"].__setitem__("tree", "9" * 40))
            self.assertEqual(receipt["status"], LEDGER_REVISE)

    def test_semantic_unknown_field_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            fx = Fixture(Path(td)); fx.full_to_transport()
            receipt = fx.append_semantic(mutate=lambda o: o.__setitem__("surprise", True))
            self.assertEqual(receipt["status"], LEDGER_REVISE)

    def test_semantic_hidden_effect_field_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            fx = Fixture(Path(td)); fx.full_to_transport()
            receipt = fx.append_semantic(mutate=lambda o: o["effects"].__setitem__("merge_to_main", True))
            self.assertEqual(receipt["status"], LEDGER_REVISE)

    def test_held_review_cannot_replay_same_decision_bytes(self):
        with tempfile.TemporaryDirectory() as td:
            fx = Fixture(Path(td)); fx.full_to_transport()
            fx.append_semantic("HOLD", ["await evidence"])
            replay = fx.root / "replay.jsonl"
            receipt = append_work_semantic_review(fx.l3, fx.semantic, replay)
            self.assertEqual(receipt["status"], LEDGER_REVISE)

    def test_original_ledgers_are_never_mutated(self):
        with tempfile.TemporaryDirectory() as td:
            fx = Fixture(Path(td)); fx.init()
            before = fx.l0.read_bytes()
            fx.append_delta()
            self.assertEqual(fx.l0.read_bytes(), before)

    def test_verify_rejects_unknown_event_field(self):
        with tempfile.TemporaryDirectory() as td:
            fx = Fixture(Path(td)); fx.init()
            event = json.loads(fx.l0.read_text())
            event["extra"] = True
            event["event_sha256"] = _event_digest(event)
            fx.l0.write_text(canonical_json_text(event), encoding="utf-8")
            self.assertEqual(verify_work_ledger(fx.l0)["status"], LEDGER_REVISE)


if __name__ == "__main__":
    unittest.main()
