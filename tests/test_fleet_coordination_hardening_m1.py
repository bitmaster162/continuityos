from __future__ import annotations

from continuityos.gate.fleet_coordination import (
    Decision, M1_AUTHORITY, project_fleet_current, validate_fanin,
    validate_verification_receipt, work_order_digest,
)

DG = "b" * 64
NOW = "2026-08-22T06:20:00Z"
BASE = "e499f54cc658604e29464fefc5694f68532cef75"
TREE = "c1a92361fc1939f34986b811248eb59329e74555"


def _wo():
    return {
        "schema": "continuityos.work_order/v2.2", "work_order_id": "WO-HARDEN",
        "work_order_version": "2.2", "project_id": "continuityos", "lane_id": "M1",
        "goal": "hardening", "frozen_input_digest": DG, "input_artifact_ids": ["a"],
        "repo": "bitmaster162/continuityos", "base_branch": "master", "base_sha": BASE,
        "base_tree": TREE, "git_object_format": "SHA1", "read_set": ["a"],
        "write_set": ["b"], "conflict_keys": ["semantic:continuityos:m1"], "effect_set": [],
        "dependencies": [], "allowed_tools": ["test"], "forbidden_effects": ["merge"],
        "acceptance_contract": {"terminal": "TEST"}, "rollback_or_compensation_class": "NO_EFFECT",
        "output_schema": "o", "receipt_schema": "r", "created_at": NOW,
        "authority": dict(M1_AUTHORITY), "digest_contract": "CANONICAL_JSON_UTF8_SHA256_FULL_DOCUMENT_V1",
    }


def _receipt(work):
    return {
        "schema": "continuityos.agent_verification_receipt/v1.2", "verification_id": "V1",
        "work_order_id": work["work_order_id"], "work_order_digest": work_order_digest(work),
        "worker_run_id": "W", "verifier_run_id": "V", "worker_output_digest": DG,
        "verifier_context_isolated": True, "worker_hidden_scratch_shared": False,
        "worker_conclusion_inherited_as_fact": False, "status": "PASS",
        "authority": dict(M1_AUTHORITY), "observed_at": NOW, "evidence_digest": "c" * 64,
        "findings_digest": "d" * 64, "conditions": [],
    }


def test_verifier_ids_are_nonempty():
    work = _wo(); receipt = _receipt(work); receipt["verifier_run_id"] = ""
    assert validate_verification_receipt(receipt, work, worker_output_digest=DG).decision is Decision.HOLD


def test_fanin_rejects_unexpected_shard():
    result = validate_fanin(["a"], [
        {"shard_id": "a", "output_digest": DG},
        {"shard_id": "extra", "output_digest": "c" * 64},
    ])
    assert (result.decision, result.reason) == (Decision.HOLD, "JOIN_WITH_UNEXPECTED_SHARD")


def test_projection_is_order_independent_for_row_sets():
    a, b = {"id": "a"}, {"id": "b"}
    common = dict(
        handoff_revision=2, provider_observed_at=NOW, active_work_orders=[], active_leases=[],
        dependency_dag=[], run_output_index=[], verification_queue=[], integration_queue=[],
    )
    p1 = project_fleet_current(agent_registry=[b, a], **common)
    p2 = project_fleet_current(agent_registry=[a, b], **common)
    assert p1 == p2
