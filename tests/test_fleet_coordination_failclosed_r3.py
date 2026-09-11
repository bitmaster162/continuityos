from __future__ import annotations

from copy import deepcopy

from continuityos.gate.fleet_coordination import (
    Decision,
    M1_AUTHORITY,
    coordinate_m1_admission,
    validate_fanout_group,
    validate_lease_against_work_order,
    validate_verification_receipt,
    work_order_digest,
)

BASE = "e499f54cc658604e29464fefc5694f68532cef75"
TREE = "c1a92361fc1939f34986b811248eb59329e74555"
DG = "b" * 64
NOW = "2026-08-22T06:20:00Z"


def _wo(identifier: str = "WO-R3", **changes):
    value = {
        "schema": "continuityos.work_order/v2.2",
        "work_order_id": identifier,
        "work_order_version": "2.2",
        "project_id": "continuityos",
        "lane_id": "M1-R3",
        "goal": "fail-closed hardening",
        "frozen_input_digest": DG,
        "input_artifact_ids": ["artifact:r3"],
        "repo": "bitmaster162/continuityos",
        "base_branch": "master",
        "base_sha": BASE,
        "base_tree": TREE,
        "git_object_format": "SHA1",
        "read_set": ["continuityos/gate/work_admission.py"],
        "write_set": ["continuityos/gate/fleet_coordination.py"],
        "conflict_keys": ["semantic:continuityos:fleet-m1"],
        "effect_set": [],
        "dependencies": [],
        "allowed_tools": ["test-only"],
        "forbidden_effects": ["merge", "deployment", "runtime", "trading", "capital"],
        "acceptance_contract": {"terminal": "M1_CANDIDATE_READY_FOR_INDEPENDENT_REVIEW"},
        "rollback_or_compensation_class": "NO_EFFECT",
        "output_schema": "continuityos.fleet.output/v1",
        "receipt_schema": "continuityos.fleet.receipt/v1",
        "created_at": NOW,
        "authority": dict(M1_AUTHORITY),
        "digest_contract": "CANONICAL_JSON_UTF8_SHA256_FULL_DOCUMENT_V1",
    }
    value.update(changes)
    return value


def _lease(work, **changes):
    value = {
        "schema": "continuityos.work_lease/v1.2",
        "lease_id": "LEASE-R3",
        "work_order_id": work["work_order_id"],
        "agent_run_id": "RUN-R3",
        "resource_scope": sorted(set(work["read_set"]) | set(work["write_set"])),
        "conflict_keys": list(work["conflict_keys"]),
        "mode": "CANDIDATE_WRITE" if work["write_set"] else "READ",
        "acquired_at": "2026-08-22T06:00:00Z",
        "expires_at": "2026-08-22T07:00:00Z",
        "status": "ACTIVE",
        "work_order_digest": work_order_digest(work),
        "git_object_format": work["git_object_format"],
        "base_sha": work["base_sha"],
        "last_observed_activity_at": None,
        "last_activity_evidence_digest": None,
        "checkpoint_ref": None,
        "checkpoint_digest": None,
        "checkpoint_observed_at": None,
    }
    value.update(changes)
    return value


def _fanout(work, **changes):
    shard = {
        "shard_id": "S1",
        "work_order_id": work["work_order_id"],
        "work_order_digest": work_order_digest(work),
        "scope": sorted(set(work["read_set"]) | set(work["write_set"])),
        "worker_run_id": "RUN-S1",
        "output_digest": "c" * 64,
    }
    value = {
        "schema": "continuityos.fanout_group/v1.2",
        "fanout_group_id": "FG-R3",
        "common_input_digest": work["frozen_input_digest"],
        "expected_shards": 1,
        "shards": [shard],
        "join_key": "JOIN-R3",
        "conflict_policy": "SERIALIZE",
        "missing_shard_policy": "HOLD",
        "duplicate_shard_policy": "EXACT_DUPLICATE_COLLAPSE",
        "fanin_acceptance_schema": "continuityos.fleet.output/v1",
        "status": "FANIN_READY",
    }
    value.update(changes)
    return value


def test_invalid_active_lease_evidence_holds_instead_of_being_ignored():
    current = _wo("WO-CURRENT")
    other = _wo("WO-OTHER")
    bad = _lease(other, agent_run_id="")
    result = coordinate_m1_admission(
        current,
        existing_work_admission_passed=True,
        baseline_verified=True,
        provider_base_sha=BASE,
        active_leases=[(bad, other)],
    )
    assert (result.decision, result.reason) == (
        Decision.HOLD,
        "ACTIVE_LEASE_EVIDENCE_INVALID",
    )


def test_admission_and_baseline_flags_require_literal_true():
    work = _wo()
    assert coordinate_m1_admission(
        work,
        existing_work_admission_passed=1,
        baseline_verified=True,
        provider_base_sha=BASE,
    ).decision is Decision.HOLD
    assert coordinate_m1_admission(
        work,
        existing_work_admission_passed=True,
        baseline_verified="yes",
        provider_base_sha=BASE,
    ).decision is Decision.HOLD


def test_lease_status_and_checkpoint_ref_are_fail_closed():
    work = _wo()
    assert validate_lease_against_work_order(
        _lease(work, status="UNKNOWN"), work
    ).decision is Decision.HOLD
    bad_cp = _lease(
        work,
        checkpoint_ref="",
        checkpoint_digest="d" * 64,
        checkpoint_observed_at="2026-08-22T06:10:00Z",
    )
    assert validate_lease_against_work_order(bad_cp, work).decision is Decision.HOLD


def test_fanout_rejects_missing_shard_identity_and_bad_materialized_digest():
    work = _wo()
    missing_id = _fanout(work)
    missing_id["shards"][0]["shard_id"] = ""
    assert validate_fanout_group(missing_id, [work]).decision is Decision.HOLD

    bad_digest = _fanout(work)
    bad_digest["shards"][0]["output_digest"] = "not-a-digest"
    assert validate_fanout_group(bad_digest, [work]).decision is Decision.HOLD


def test_fanout_rejects_duplicate_work_order_identity_input():
    work = _wo()
    result = validate_fanout_group(_fanout(work), [work, deepcopy(work)])
    assert (result.decision, result.reason) == (
        Decision.HOLD,
        "FANOUT_DUPLICATE_WORK_ORDER_ID",
    )


def test_verification_with_malformed_work_order_holds_not_raises():
    work = _wo()
    receipt = {
        "schema": "continuityos.agent_verification_receipt/v1.2",
        "verification_id": "V-R3",
        "work_order_id": work["work_order_id"],
        "work_order_digest": work_order_digest(work),
        "worker_run_id": "RUN-W",
        "verifier_run_id": "RUN-V",
        "worker_output_digest": DG,
        "verifier_context_isolated": True,
        "worker_hidden_scratch_shared": False,
        "worker_conclusion_inherited_as_fact": False,
        "status": "PASS",
        "authority": dict(M1_AUTHORITY),
        "observed_at": NOW,
        "evidence_digest": "c" * 64,
        "findings_digest": "d" * 64,
        "conditions": [],
    }
    malformed = dict(work)
    malformed.pop("work_order_id")
    result = validate_verification_receipt(
        receipt, malformed, worker_output_digest=DG
    )
    assert result.decision is Decision.HOLD
