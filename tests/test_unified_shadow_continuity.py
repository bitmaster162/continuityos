from __future__ import annotations

import copy
import unittest

from continuityos.unified_shadow_continuity import (
    MODERN_SOURCE_BRANCH,
    MODERN_SOURCE_HEAD,
    MODERN_SOURCE_REPO,
    R52_LOCAL_ADOPTION_HEAD,
    ShadowContinuityError,
    build_shadow_continuity_receipt,
    sha256_obj,
    validate_unified_transaction,
)


def make_transaction() -> dict:
    tx = {
        "schema": "bitevo.unified_shadow_transaction.v2",
        "frozen_at": "2026-08-19T16:32:00Z",
        "case_id": "trade-continuity-001",
        "trade_case_sha256": "a" * 64,
        "decision_packet_sha256": "b" * 64,
        "federation_sha256": "c" * 64,
        "route_sha256": "d" * 64,
        "control_plane_sha256": "e" * 64,
        "registered_node_count": 63,
        "system_recommendation": "LONG",
        "control_gate": "HOLD",
        "control_plane_action": "WAIT",
        "hanri_freshness": "STALE",
        "hanri_attention_required": True,
        "twin_prediction_status": "UNIQUE",
        "divergence": True,
        "effect_boundary": {
            "executor_enabled": False,
            "current_truth_apply": False,
            "continuity_write": False,
            "runtime_registration": False,
            "external_model_call": False,
            "exchange_call": False,
            "signal": False,
            "order": False,
            "credential_mutation": False,
            "merge": False,
            "deploy": False,
        },
        "semantics": {
            "one_transaction_one_case": True,
            "route_federation_and_control_are_hash_bound": True,
            "prediction_is_not_permission": True,
            "federation_accounting_is_not_runtime_invocation": True,
            "shadow_projection_is_not_current_truth": True,
            "stale_control_evidence_can_block_without_mutation": True,
        },
        "safety": {
            "mode": "SHADOW",
            "execution_authority": "NONE",
            "can_trade": False,
            "capital_permission": "DENY",
            "orders_allowed": False,
            "signals_allowed": False,
        },
    }
    tx["transaction_sha256"] = sha256_obj(tx)
    return tx


def build(tx: dict | None = None, **kwargs):
    return build_shadow_continuity_receipt(
        make_transaction() if tx is None else tx,
        modern_source_repo=kwargs.pop("modern_source_repo", MODERN_SOURCE_REPO),
        modern_source_branch=kwargs.pop("modern_source_branch", MODERN_SOURCE_BRANCH),
        modern_source_head=kwargs.pop("modern_source_head", MODERN_SOURCE_HEAD),
        **kwargs,
    )


class UnifiedShadowContinuityTests(unittest.TestCase):
    def test_stale_control_transaction_becomes_hold_no_write_receipt(self):
        receipt = build()
        self.assertEqual(receipt["disposition"], "HOLD_SHADOW_NO_WRITE")
        self.assertEqual(receipt["modern_source"]["head_sha"], MODERN_SOURCE_HEAD)
        self.assertEqual(receipt["modern_source"]["claim_ceiling"], "MODERN_GITHUB_SOURCE_ONLY")
        self.assertFalse(receipt["modern_source"]["proves_live_runtime"])
        self.assertEqual(receipt["historical_lineage"]["live_host_state"], "UNVERIFIED")
        self.assertFalse(receipt["checkpoint_candidate"]["write_allowed"])
        self.assertFalse(receipt["replay_candidate"]["apply_allowed"])
        self.assertEqual(receipt["return_candidate"]["semantic_acceptance"], "NOT_PERFORMED")
        self.assertTrue(all(value is False for value in receipt["writes"].values()))
        self.assertEqual(receipt["authority"]["execution_authority"], "NONE")
        self.assertFalse(receipt["authority"]["apply_authorized"])
        self.assertFalse(receipt["safety"]["can_trade"])
        self.assertEqual(receipt["safety"]["capital_permission"], "DENY")

    def test_modern_github_source_and_historical_r52_cannot_be_conflated(self):
        self.assertNotEqual(MODERN_SOURCE_HEAD, R52_LOCAL_ADOPTION_HEAD)
        with self.assertRaisesRegex(ShadowContinuityError, "modern_source_head_mismatch"):
            build(modern_source_head=R52_LOCAL_ADOPTION_HEAD)

    def test_live_host_cannot_be_promoted_without_fresh_host_evidence(self):
        with self.assertRaisesRegex(ShadowContinuityError, "p0_live_host_state_must_remain_unverified"):
            build(live_host_state="VERIFIED")

    def test_effectful_transaction_is_rejected_before_continuity_receipt(self):
        tx = make_transaction()
        tx["effect_boundary"]["continuity_write"] = True
        tx["transaction_sha256"] = sha256_obj({k: v for k, v in tx.items() if k != "transaction_sha256"})
        errors = validate_unified_transaction(tx)
        self.assertIn("effect_boundary_not_false:continuity_write", errors)
        with self.assertRaises(ShadowContinuityError):
            build(tx)

    def test_transaction_tamper_is_rejected(self):
        tx = make_transaction()
        tx["system_recommendation"] = "WAIT"
        with self.assertRaisesRegex(ShadowContinuityError, "transaction_hash_mismatch"):
            build(tx)

    def test_hold_must_force_wait(self):
        tx = make_transaction()
        tx["control_plane_action"] = "LONG"
        tx["transaction_sha256"] = sha256_obj({k: v for k, v in tx.items() if k != "transaction_sha256"})
        with self.assertRaisesRegex(ShadowContinuityError, "hold_must_force_wait"):
            build(tx)

    def test_pass_shadow_is_still_read_only(self):
        tx = make_transaction()
        tx["control_gate"] = "PASS_SHADOW"
        tx["control_plane_action"] = "LONG"
        tx["hanri_freshness"] = "FRESH"
        tx["hanri_attention_required"] = False
        tx["transaction_sha256"] = sha256_obj({k: v for k, v in tx.items() if k != "transaction_sha256"})
        receipt = build(tx)
        self.assertEqual(receipt["disposition"], "READY_FOR_READ_ONLY_REVIEW")
        self.assertTrue(all(value is False for value in receipt["writes"].values()))
        self.assertFalse(receipt["authority"]["apply_authorized"])

    def test_receipt_and_candidates_are_deterministic_and_hash_bound(self):
        first = build()
        second = build()
        self.assertEqual(first, second)
        self.assertEqual(first["continuity_receipt_sha256"], second["continuity_receipt_sha256"])

        tampered = copy.deepcopy(first)
        tampered["checkpoint_candidate"]["write_allowed"] = True
        self.assertNotEqual(
            tampered["continuity_receipt_sha256"],
            sha256_obj({k: v for k, v in tampered.items() if k != "continuity_receipt_sha256"}),
        )


if __name__ == "__main__":
    unittest.main()
