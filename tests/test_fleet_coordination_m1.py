from __future__ import annotations

from copy import deepcopy

from continuityos.gate.fleet_coordination import (
    CURRENT_PROJECTION_SCHEMA,
    M1_AUTHORITY,
    PROJECTION_AUTHORITY,
    Decision,
    build_coordination_event,
    conflict_keys_conflict,
    coordinate_m1_admission,
    lease_currentness,
    project_fleet_current,
    sequential_habitat_ready,
    sha256_document,
    validate_fanin,
    validate_scope_observation,
    validate_verification_receipt,
    validate_work_order_m1,
    verify_coordination_event,
    work_order_digest,
)

BASE = "e499f54cc658604e29464fefc5694f68532cef75"
TREE = "c1a92361fc1939f34986b811248eb59329e74555"
DG = "b" * 64
NOW = "2026-08-22T06:20:00Z"


def wo(identifier: str = "WO-M1-A", **changes):
    value = {
        "schema": "continuityos.work_order/v2.2",
        "work_order_id": identifier,
        "work_order_version": "2.2",
        "project_id": "continuityos",
        "lane_id": "P0-CORE-FLEET-M1",
        "goal": "bounded candidate work",
        "frozen_input_digest": DG,
        "input_artifact_ids": ["artifact:fixture"],
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
        "allowed_tools": ["github:contents-write:candidate-only"],
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


def lease(work_order, **changes):
    value = {
        "schema": "continuityos.work_lease/v1.2",
        "lease_id": "LEASE-1",
        "work_order_id": work_order["work_order_id"],
        "agent_run_id": "RUN-WORKER-1",
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


def verification(work_order, worker_output_digest=DG, **changes):
    value = {
        "schema": "continuityos.agent_verification_receipt/v1.2",
        "verification_id": "VERIFY-1",
        "work_order_id": work_order["work_order_id"],
        "work_order_digest": work_order_digest(work_order),
        "worker_run_id": "RUN-WORKER-1",
        "verifier_run_id": "RUN-VERIFIER-1",
        "worker_output_digest": worker_output_digest,
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


def test_work_order_valid_and_effect_free():
    result = validate_work_order_m1(wo())
    assert result.decision is Decision.ALLOW
    assert result.as_dict()["authority"] == M1_AUTHORITY


def test_effect_scope_escalation_rejected():
    result = validate_work_order_m1(wo(effect_set=["deployment"]))
    assert (result.decision, result.reason) == (Decision.REJECT, "M1_EFFECT_SET_NONEMPTY")


def test_authority_escalation_rejected():
    authority = dict(M1_AUTHORITY)
    authority["merge_authority"] = True
    assert validate_work_order_m1(wo(authority=authority)).decision is Decision.REJECT


def test_existing_admission_is_mandatory():
    result = coordinate_m1_admission(
        wo(), existing_work_admission_passed=False, baseline_verified=True,
        provider_base_sha=BASE,
    )
    assert (result.decision, result.reason) == (Decision.HOLD, "EXISTING_WORK_ADMISSION_REQUIRED")


def test_provider_base_mismatch_holds():
    result = coordinate_m1_admission(
        wo(), existing_work_admission_passed=True, baseline_verified=True,
        provider_base_sha="a" * 40,
    )
    assert result.decision is Decision.HOLD


def test_repo_path_prefix_overlap_is_conflict():
    assert conflict_keys_conflict(
        "repo-path:bitmaster162/continuityos:continuityos/gate",
        "repo-path:bitmaster162/continuityos:continuityos/gate/fleet_coordination.py",
    )
    assert not conflict_keys_conflict(
        "repo-path:bitmaster162/continuityos:docs",
        "repo-path:other/repo:docs",
    )


def test_same_semantic_resource_serializes():
    current = wo("WO-A")
    other = wo("WO-B", write_set=["docs/a.md"])
    other_lease = lease(other)
    result = coordinate_m1_admission(
        current,
        existing_work_admission_passed=True,
        baseline_verified=True,
        provider_base_sha=BASE,
        active_leases=[(other_lease, other)],
    )
    assert (result.decision, result.reason) == (Decision.SERIALIZE, "ACTIVE_LEASE_CONFLICT")


def test_stale_base_after_lease_holds():
    work = wo()
    result = lease_currentness(
        lease(work), work, observed_at="2026-08-22T06:30:00Z", provider_base_sha="a" * 40
    )
    assert (result.decision, result.reason) == (Decision.HOLD, "STALE_BASE_AFTER_LEASE")


def test_expired_lease_holds_but_checkpoint_is_not_inferred_away():
    work = wo()
    cp = "e" * 64
    active = lease(
        work,
        checkpoint_ref="artifact:checkpoint-1",
        checkpoint_digest=cp,
        checkpoint_observed_at="2026-08-22T06:10:00Z",
    )
    result = lease_currentness(
        active, work, observed_at="2026-08-22T07:00:00Z", provider_base_sha=BASE
    )
    assert result.decision is Decision.HOLD
    assert active["checkpoint_digest"] == cp


def test_scope_expansion_rejected():
    result = validate_scope_observation(
        wo(), observed_writes=["continuityos/gate/fleet_coordination.py", "README.md"], observed_effects=[]
    )
    assert (result.decision, result.reason) == (Decision.REJECT, "SCOPE_EXPANSION_REQUIRED")


def test_observed_effect_rejected_even_when_write_scope_is_valid():
    result = validate_scope_observation(
        wo(), observed_writes=["continuityos/gate/fleet_coordination.py"], observed_effects=["deployment"]
    )
    assert (result.decision, result.reason) == (Decision.REJECT, "EFFECT_SCOPE_ESCALATION")


def test_self_verification_rejected():
    work = wo()
    receipt = verification(work, verifier_run_id="RUN-WORKER-1")
    result = validate_verification_receipt(receipt, work, worker_output_digest=DG)
    assert (result.decision, result.reason) == (Decision.REJECT, "SELF_VERIFICATION")


def test_pass_with_conditions_must_materialize_conditions():
    work = wo()
    receipt = verification(work, status="PASS_WITH_CONDITIONS", conditions=[])
    result = validate_verification_receipt(receipt, work, worker_output_digest=DG)
    assert result.decision is Decision.HOLD


def test_exact_independent_verification_passes():
    work = wo()
    assert validate_verification_receipt(
        verification(work), work, worker_output_digest=DG
    ).decision is Decision.ALLOW


def test_missing_and_incompatible_fanin_hold():
    assert validate_fanin(["a", "b"], [{"shard_id": "a", "output_digest": DG}]).decision is Decision.HOLD
    assert validate_fanin(
        ["a"],
        [{"shard_id": "a", "output_digest": DG}, {"shard_id": "a", "output_digest": "c" * 64}],
    ).decision is Decision.HOLD


def test_coordination_event_is_content_addressed_and_requires_canonical_ledger():
    event = build_coordination_event(
        event_type="WORK_ORDER_VALIDATED", work_order=wo(), run_id="RUN-1",
        observed_at=NOW, payload={"decision": "ALLOW"}, previous_event_sha256=None,
    )
    assert event["canonical_work_ledger_required"] is True
    assert verify_coordination_event(event).decision is Decision.ALLOW
    tampered = deepcopy(event)
    tampered["payload"]["decision"] = "REJECT"
    assert verify_coordination_event(tampered).decision is Decision.HOLD


def test_current_projection_is_deterministic_non_authority():
    work = wo()
    p1 = project_fleet_current(
        handoff_revision=1, provider_observed_at=NOW, active_work_orders=[work],
        agent_registry=[], active_leases=[], dependency_dag=[], run_output_index=[],
        verification_queue=[], integration_queue=[],
        last_provider_observations=[{"kind": "GIT_BRANCH", "head": BASE}],
    )
    p2 = project_fleet_current(
        handoff_revision=1, provider_observed_at=NOW, active_work_orders=[work],
        agent_registry=[], active_leases=[], dependency_dag=[], run_output_index=[],
        verification_queue=[], integration_queue=[],
        last_provider_observations=[{"kind": "GIT_BRANCH", "head": BASE}],
    )
    assert p1 == p2
    assert p1["schema"] == CURRENT_PROJECTION_SCHEMA
    assert p1["authority"] == PROJECTION_AUTHORITY
    assert p1["effect_queue"] == []


def test_sequential_research_builder_critic_is_digest_bound():
    research = wo("WO-RESEARCH", write_set=[], conflict_keys=["semantic:continuityos:research"])
    build = wo(
        "WO-BUILD",
        dependencies=[{
            "work_order_id": research["work_order_id"],
            "work_order_digest": work_order_digest(research),
            "required_terminal": "OUTPUT_FROZEN",
        }],
    )
    critic = wo(
        "WO-CRITIC", write_set=[], conflict_keys=["semantic:continuityos:critic"],
        dependencies=[{
            "work_order_id": build["work_order_id"],
            "work_order_digest": work_order_digest(build),
            "required_terminal": "OUTPUT_FROZEN",
        }],
    )
    assert sequential_habitat_ready(research, build, critic).decision is Decision.ALLOW
    critic["dependencies"][0]["work_order_digest"] = "f" * 64
    assert sequential_habitat_ready(research, build, critic).decision is Decision.HOLD


def test_digest_changes_on_semantic_mutation():
    a = wo()
    b = deepcopy(a)
    b["goal"] = "changed"
    assert sha256_document(a) != sha256_document(b)
