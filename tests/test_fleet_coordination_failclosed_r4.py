from __future__ import annotations

from continuityos.gate.fleet_coordination import (
    Decision,
    M1_AUTHORITY,
    coordinate_m1_admission,
    dependencies_satisfied,
    validate_fanout_group,
    validate_scope_observation,
    verify_coordination_event,
    work_order_digest,
)

BASE = "e499f54cc658604e29464fefc5694f68532cef75"
TREE = "c1a92361fc1939f34986b811248eb59329e74555"
DG = "b" * 64
NOW = "2026-08-22T06:20:00Z"


def _wo(identifier: str = "WO-R4", **changes):
    value = {
        "schema": "continuityos.work_order/v2.2",
        "work_order_id": identifier,
        "work_order_version": "2.2",
        "project_id": "continuityos",
        "lane_id": "M1-R4",
        "goal": "fail-closed hardening",
        "frozen_input_digest": DG,
        "input_artifact_ids": ["artifact:r4"],
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
        "lease_id": "LEASE-" + work["work_order_id"],
        "work_order_id": work["work_order_id"],
        "agent_run_id": "RUN-" + work["work_order_id"],
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


def _fanout(work):
    return {
        "schema": "continuityos.fanout_group/v1.2",
        "fanout_group_id": "FG-R4",
        "common_input_digest": work["frozen_input_digest"],
        "expected_shards": 1,
        "shards": [{
            "shard_id": "S1",
            "work_order_id": work["work_order_id"],
            "work_order_digest": work_order_digest(work),
            "scope": sorted(set(work["read_set"]) | set(work["write_set"])),
            "worker_run_id": "RUN-S1",
            "output_digest": "c" * 64,
        }],
        "join_key": "JOIN-R4",
        "conflict_policy": "SERIALIZE",
        "missing_shard_policy": "HOLD",
        "duplicate_shard_policy": "EXACT_DUPLICATE_COLLAPSE",
        "fanin_acceptance_schema": "continuityos.fleet.output/v1",
        "status": "FANIN_READY",
    }


def test_m1_serializes_distinct_candidate_writers_even_without_conflict_key_overlap():
    current = _wo(
        "WO-CURRENT",
        write_set=["a.py"],
        conflict_keys=["semantic:continuityos:a"],
    )
    other = _wo(
        "WO-OTHER",
        write_set=["b.py"],
        conflict_keys=["semantic:continuityos:b"],
    )
    result = coordinate_m1_admission(
        current,
        existing_work_admission_passed=True,
        baseline_verified=True,
        provider_base_sha=BASE,
        active_leases=[(_lease(other), other)],
    )
    assert (result.decision, result.reason) == (
        Decision.SERIALIZE,
        "M1_CANDIDATE_WRITES_SERIAL",
    )


def test_malformed_active_lease_pair_holds_not_raises():
    result = coordinate_m1_admission(
        _wo(),
        existing_work_admission_passed=True,
        baseline_verified=True,
        provider_base_sha=BASE,
        active_leases=[("not-a-pair",)],
    )
    assert result.decision is Decision.HOLD


def test_dependency_receipt_must_be_structurally_bound():
    parent = _wo("WO-PARENT")
    child = _wo(
        "WO-CHILD",
        dependencies=[{
            "work_order_id": parent["work_order_id"],
            "work_order_digest": work_order_digest(parent),
            "required_terminal": "OUTPUT_FROZEN",
        }],
    )
    assert dependencies_satisfied(child, [None]).decision is Decision.HOLD
    assert dependencies_satisfied(
        child,
        [{
            "work_order_id": parent["work_order_id"],
            "work_order_digest": "not-a-digest",
            "terminal": "OUTPUT_FROZEN",
        }],
    ).decision is Decision.HOLD
    assert dependencies_satisfied(
        child,
        [{
            "work_order_id": parent["work_order_id"],
            "work_order_digest": work_order_digest(parent),
            "terminal": "OUTPUT_FROZEN",
        }],
    ).decision is Decision.ALLOW


def test_fanout_output_cannot_exist_without_worker_identity():
    work = _wo()
    fanout = _fanout(work)
    fanout["shards"][0]["worker_run_id"] = None
    assert (
        validate_fanout_group(fanout, [work]).reason
        == "FANOUT_OUTPUT_WITHOUT_WORKER"
    )


def test_invalid_scope_observation_holds_not_raises():
    result = validate_scope_observation(
        _wo(),
        observed_writes="not-a-sequence-of-path-items",
        observed_effects=[],
    )
    assert result.decision is Decision.HOLD


def test_non_object_coordination_event_holds_not_raises():
    result = verify_coordination_event(None)
    assert (result.decision, result.reason) == (Decision.HOLD, "EVENT_INVALID")
