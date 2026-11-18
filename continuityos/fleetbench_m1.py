"""Deterministic Governed Fleet M1 adversarial benchmark.

The benchmark is source/test evidence only.  It performs no provider I/O or
persistent writes and every case preserves the no-effect authority ceiling.
"""
from __future__ import annotations

from typing import Any

from continuityos.gate.fleet_coordination import (
    M1_AUTHORITY,
    Decision,
    checkpoint_recovery_guard,
    coordinate_m1_admission,
    future_effect_currentness_guard,
    lease_currentness,
    staging_visibility_guard,
    validate_fanin,
    validate_scope_observation,
    validate_verification_receipt,
    work_order_digest,
)

BASE = "e499f54cc658604e29464fefc5694f68532cef75"
TREE = "c1a92361fc1939f34986b811248eb59329e74555"
DG = "b" * 64
NOW = "2026-08-22T06:20:00Z"

EXPECTED = {
    "DUPLICATE_PR_RACE": "SERIALIZE",
    "STALE_BASE_AFTER_LEASE": "HOLD",
    "SAME_PATH_TWO_WRITERS": "SERIALIZE",
    "DIFFERENT_FILES_SAME_SEMANTIC_RESOURCE": "SERIALIZE",
    "LEASE_EXPIRED_DURING_RUN": "HOLD",
    "AGENT_DISAPPEARS_BEFORE_CHECKPOINT": "HOLD",
    "SELF_VERIFICATION_ATTEMPT": "REJECT",
    "OUTPUT_FROM_WRONG_BASE": "HOLD",
    "JOIN_WITH_MISSING_SHARD": "HOLD",
    "DUPLICATE_INCOMPATIBLE_SHARD": "HOLD",
    "EFFECT_SCOPE_ESCALATION": "REJECT",
    "PROVIDER_STATE_CHANGED_BEFORE_EFFECT": "HOLD",
    "STAGING_VISIBILITY_REVERSAL": "HOLD",
    "STALE_OWNER_GATE_AFTER_CAPABILITY_CHANGE": "HOLD",
    "PARALLEL_READ_ONLY_NO_WRITE_LEAK": "REJECT",
}


def _wo(identifier: str, *, writes=None, conflicts=None, effects=None) -> dict[str, Any]:
    return {
        "schema": "continuityos.work_order/v2.2",
        "work_order_id": identifier,
        "work_order_version": "2.2",
        "project_id": "continuityos",
        "lane_id": "FLEETBENCH-M1",
        "goal": "FleetBench fixture",
        "frozen_input_digest": DG,
        "input_artifact_ids": ["fleetbench:fixture"],
        "repo": "bitmaster162/continuityos",
        "base_branch": "master",
        "base_sha": BASE,
        "base_tree": TREE,
        "git_object_format": "SHA1",
        "read_set": ["continuityos/gate/work_admission.py"],
        "write_set": list(["continuityos/gate/fleet_coordination.py"] if writes is None else writes),
        "conflict_keys": list(["semantic:continuityos:fleetbench"] if conflicts is None else conflicts),
        "effect_set": list([] if effects is None else effects),
        "dependencies": [],
        "allowed_tools": ["test-only"],
        "forbidden_effects": ["merge", "deployment", "runtime", "trading", "capital"],
        "acceptance_contract": {"fixture": identifier},
        "rollback_or_compensation_class": "NO_EFFECT",
        "output_schema": "continuityos.fleetbench.output/v1",
        "receipt_schema": "continuityos.fleetbench.receipt/v1",
        "created_at": NOW,
        "authority": dict(M1_AUTHORITY),
        "digest_contract": "CANONICAL_JSON_UTF8_SHA256_FULL_DOCUMENT_V1",
    }


def _lease(work_order: dict[str, Any], **changes) -> dict[str, Any]:
    value = {
        "schema": "continuityos.work_lease/v1.2",
        "lease_id": "LEASE-" + work_order["work_order_id"],
        "work_order_id": work_order["work_order_id"],
        "agent_run_id": "RUN-" + work_order["work_order_id"],
        "resource_scope": sorted(set(work_order["read_set"]) | set(work_order["write_set"])),
        "conflict_keys": list(work_order["conflict_keys"]),
        "mode": "CANDIDATE_WRITE" if work_order["write_set"] else "READ",
        "acquired_at": "2026-08-22T06:00:00Z",
        "expires_at": "2026-08-22T07:00:00Z",
        "status": "ACTIVE",
        "work_order_digest": work_order_digest(work_order),
        "git_object_format": work_order["git_object_format"],
        "base_sha": work_order["base_sha"],
        "last_observed_activity_at": None,
        "last_activity_evidence_digest": None,
        "checkpoint_ref": None,
        "checkpoint_digest": None,
        "checkpoint_observed_at": None,
    }
    value.update(changes)
    return value


def _verification(work_order: dict[str, Any], **changes) -> dict[str, Any]:
    value = {
        "schema": "continuityos.agent_verification_receipt/v1.2",
        "verification_id": "VERIFY-1",
        "work_order_id": work_order["work_order_id"],
        "work_order_digest": work_order_digest(work_order),
        "worker_run_id": "RUN-WORKER",
        "verifier_run_id": "RUN-VERIFIER",
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
    value.update(changes)
    return value


def run_fleetbench() -> dict[str, Any]:
    rows: list[dict[str, Any]] = []

    def record(fid: str, decision: Decision, reason: str) -> None:
        expected = EXPECTED[fid]
        rows.append({
            "fixture_id": fid,
            "expected": expected,
            "observed": decision.value,
            "reason": reason,
            "pass": decision.value == expected,
            "authority": dict(M1_AUTHORITY),
        })

    # 1 DUPLICATE_PR_RACE
    work = _wo("WO-DUP-PR", conflicts=["git-branch:bitmaster162/continuityos:agent/fleet-m1"])
    other = _wo("WO-DUP-PR-OTHER", conflicts=["git-branch:bitmaster162/continuityos:agent/fleet-m1"])
    r = coordinate_m1_admission(work, existing_work_admission_passed=True, baseline_verified=True,
        provider_base_sha=BASE, active_leases=[(_lease(other), other)])
    record("DUPLICATE_PR_RACE", r.decision, r.reason)

    # 2 STALE_BASE_AFTER_LEASE
    work = _wo("WO-STALE")
    r = lease_currentness(_lease(work), work, observed_at="2026-08-22T06:30:00Z", provider_base_sha="a" * 40)
    record("STALE_BASE_AFTER_LEASE", r.decision, r.reason)

    # 3 SAME_PATH_TWO_WRITERS
    work = _wo("WO-PATH-A", conflicts=["repo-path:bitmaster162/continuityos:continuityos/gate"])
    other = _wo("WO-PATH-B", conflicts=["repo-path:bitmaster162/continuityos:continuityos/gate/fleet_coordination.py"])
    r = coordinate_m1_admission(work, existing_work_admission_passed=True, baseline_verified=True,
        provider_base_sha=BASE, active_leases=[(_lease(other), other)])
    record("SAME_PATH_TWO_WRITERS", r.decision, r.reason)

    # 4 DIFFERENT_FILES_SAME_SEMANTIC_RESOURCE
    work = _wo("WO-SEM-A", writes=["a.py"], conflicts=["semantic:continuityos:fleet"])
    other = _wo("WO-SEM-B", writes=["b.py"], conflicts=["semantic:continuityos:fleet"])
    r = coordinate_m1_admission(work, existing_work_admission_passed=True, baseline_verified=True,
        provider_base_sha=BASE, active_leases=[(_lease(other), other)])
    record("DIFFERENT_FILES_SAME_SEMANTIC_RESOURCE", r.decision, r.reason)

    # 5 LEASE_EXPIRED_DURING_RUN
    work = _wo("WO-EXPIRE")
    r = lease_currentness(_lease(work, expires_at="2026-08-22T06:10:00Z"), work,
        observed_at="2026-08-22T06:30:00Z", provider_base_sha=BASE)
    record("LEASE_EXPIRED_DURING_RUN", r.decision, r.reason)

    # 6 AGENT_DISAPPEARS_BEFORE_CHECKPOINT
    work = _wo("WO-GONE")
    r = checkpoint_recovery_guard(_lease(work), worker_observed=False, frozen_output_digest=None)
    record("AGENT_DISAPPEARS_BEFORE_CHECKPOINT", r.decision, r.reason)

    # 7 SELF_VERIFICATION_ATTEMPT
    work = _wo("WO-SELF")
    receipt = _verification(work, verifier_run_id="RUN-WORKER")
    r = validate_verification_receipt(receipt, work, worker_output_digest=DG)
    record("SELF_VERIFICATION_ATTEMPT", r.decision, r.reason)

    # 8 OUTPUT_FROM_WRONG_BASE
    work = _wo("WO-WRONG-BASE")
    r = lease_currentness(_lease(work), work, observed_at="2026-08-22T06:30:00Z", provider_base_sha="f" * 40)
    record("OUTPUT_FROM_WRONG_BASE", r.decision, r.reason)

    # 9 JOIN_WITH_MISSING_SHARD
    r = validate_fanin(["a", "b"], [{"shard_id": "a", "output_digest": DG}])
    record("JOIN_WITH_MISSING_SHARD", r.decision, r.reason)

    # 10 DUPLICATE_INCOMPATIBLE_SHARD
    r = validate_fanin(["a"], [
        {"shard_id": "a", "output_digest": DG},
        {"shard_id": "a", "output_digest": "e" * 64},
    ])
    record("DUPLICATE_INCOMPATIBLE_SHARD", r.decision, r.reason)

    # 11 EFFECT_SCOPE_ESCALATION
    work = _wo("WO-EFFECT")
    r = validate_scope_observation(work, observed_writes=work["write_set"], observed_effects=["deployment"])
    record("EFFECT_SCOPE_ESCALATION", r.decision, r.reason)

    # 12 PROVIDER_STATE_CHANGED_BEFORE_EFFECT
    r = future_effect_currentness_guard(provider_state_unchanged=False, owner_gate_current=True)
    record("PROVIDER_STATE_CHANGED_BEFORE_EFFECT", r.decision, r.reason)

    # 13 STAGING_VISIBILITY_REVERSAL
    r = staging_visibility_guard(previously_visible=True, jit_visible=False)
    record("STAGING_VISIBILITY_REVERSAL", r.decision, r.reason)

    # 14 STALE_OWNER_GATE_AFTER_CAPABILITY_CHANGE
    r = future_effect_currentness_guard(provider_state_unchanged=True, owner_gate_current=False)
    record("STALE_OWNER_GATE_AFTER_CAPABILITY_CHANGE", r.decision, r.reason)

    # 15 PARALLEL_READ_ONLY_NO_WRITE_LEAK
    readonly = _wo("WO-READONLY", writes=[], conflicts=["semantic:continuityos:readonly"])
    r = validate_scope_observation(readonly, observed_writes=["unexpected.txt"], observed_effects=[])
    record("PARALLEL_READ_ONLY_NO_WRITE_LEAK", r.decision, r.reason)

    passed = sum(bool(row["pass"]) for row in rows)
    return {
        "schema": "continuityos.fleetbench.m1_result/v1",
        "baseline": {"sha": BASE, "tree": TREE},
        "total": len(rows),
        "passed": passed,
        "failed": len(rows) - passed,
        "terminal": "M1_FLEETBENCH_PASS" if passed == len(rows) else "M1_FLEETBENCH_FAIL",
        "cases": rows,
        "authority": dict(M1_AUTHORITY),
    }


if __name__ == "__main__":
    import json
    print(json.dumps(run_fleetbench(), indent=2, sort_keys=True))
