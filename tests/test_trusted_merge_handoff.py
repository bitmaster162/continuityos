from __future__ import annotations

import ast
import copy
import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

import continuityos.trusted_merge_handoff as trusted_merge_handoff_module
from continuityos.trusted_merge_handoff import (
    OUTCOME,
    STATUS,
    build_dual_control_merge_handoff,
    require_dual_control_merge_handoff_current,
)


def _load_r17_fixture_module():
    path = Path(__file__).with_name("test_trusted_human_approval.py")
    spec = importlib.util.spec_from_file_location("_r17_fixture", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


R17 = _load_r17_fixture_module()
BASE_BRANCH = "master"
CANDIDATE_BRANCH = "agent/r20-candidate"
PR_NUMBER = 42


def _auth_receipt():
    return {
        "schema": "continuityos.merge_authorization.evaluation/v1",
        "generated_at_utc": "2026-09-16T00:00:00+00:00",
        "status": "MERGE_AUTHORIZATION_PASS",
        "outcome": "MERGE_EXECUTION_MAY_BE_REQUESTED_ONCE",
        "binding": {
            "repository": R17.REPOSITORY,
            "visibility": "PRIVATE",
            "base_branch": BASE_BRANCH,
            "base_head": R17.BASE,
            "base_tree": R17.BASE_TREE,
            "candidate_branch": CANDIDATE_BRANCH,
            "candidate_head": R17.HEAD,
            "candidate_tree": R17.TREE,
            "pull_request_number": PR_NUMBER,
            "required_checks": ["CI"],
            "required_approvals": 1,
            "max_decision_age_seconds": 3600,
            "merge_method": "MERGE_COMMIT",
        },
        "authorization_subject_sha256": "e" * 64,
        "authorization_nonce": "ROBERT-MERGE-R20-0001",
        "checks": [],
        "reasons": [],
        "holds": [],
        "effect": "PROPOSAL_ONLY_NO_MERGE",
        "merge_executed": False,
        "deployment": False,
        "registry_apply": False,
        "current_state_apply": False,
        "r63_apply": False,
        "live_state_modified": False,
        "writes_performed": [],
        "can_trade": False,
        "capital_permission": "DENY",
        "deploy_permission": "DENY",
        "self_application": False,
    }


def _pin(value):
    raw = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    return hashlib.sha256(raw).hexdigest()


def _fixture():
    _, _, registry, registry_pin, _, result = R17.approve()
    authorization = _auth_receipt()
    authorization_pin = _pin(authorization)
    return result.eligibility_receipt, registry, registry_pin, authorization, authorization_pin


def _build(*, now=R17.NOW):
    eligibility, registry, registry_pin, authorization, authorization_pin = _fixture()
    receipt = build_dual_control_merge_handoff(
        eligibility_receipt=eligibility,
        merge_authorization_receipt=authorization,
        pinned_merge_authorization_sha256=authorization_pin,
        trusted_key_registry=registry,
        pinned_registry_sha256=registry_pin,
        repository=R17.REPOSITORY,
        current_base_sha=R17.BASE,
        current_head_sha=R17.HEAD,
        current_tree_sha=R17.TREE,
        now_unix=now,
        base_branch=BASE_BRANCH,
        candidate_branch=CANDIDATE_BRANCH,
        pull_request_number=PR_NUMBER,
    )
    return receipt, registry, registry_pin, authorization_pin


def _validate(receipt, registry, registry_pin, authorization_pin, *, now=R17.NOW):
    return require_dual_control_merge_handoff_current(
        receipt,
        pinned_merge_authorization_sha256=authorization_pin,
        trusted_key_registry=registry,
        pinned_registry_sha256=registry_pin,
        repository=R17.REPOSITORY,
        current_base_sha=R17.BASE,
        current_head_sha=R17.HEAD,
        current_tree_sha=R17.TREE,
        now_unix=now,
        base_branch=BASE_BRANCH,
        candidate_branch=CANDIDATE_BRANCH,
        pull_request_number=PR_NUMBER,
    )


def test_exact_dual_control_handoff_passes_and_is_current():
    receipt, registry, registry_pin, authorization_pin = _build()
    assert receipt["status"] == STATUS
    assert receipt["outcome"] == OUTCOME
    assert receipt["can_merge"] is False
    assert receipt["can_execute"] is False
    assert receipt["merge_executed"] is False
    assert receipt["deploy_permission"] == "DENY"
    assert receipt["can_trade"] is False
    assert receipt["capital_permission"] == "DENY"
    validated = _validate(receipt, registry, registry_pin, authorization_pin)
    assert validated["receipt_id"] == receipt["receipt_id"]


def test_r63_candidate_drift_fails_closed():
    eligibility, registry, registry_pin, authorization, _ = _fixture()
    authorization["binding"]["candidate_head"] = "9" * 40
    pin = _pin(authorization)
    with pytest.raises(ValueError, match="subject mismatch for candidate_head"):
        build_dual_control_merge_handoff(
            eligibility_receipt=eligibility,
            merge_authorization_receipt=authorization,
            pinned_merge_authorization_sha256=pin,
            trusted_key_registry=registry,
            pinned_registry_sha256=registry_pin,
            repository=R17.REPOSITORY,
            current_base_sha=R17.BASE,
            current_head_sha=R17.HEAD,
            current_tree_sha=R17.TREE,
            now_unix=R17.NOW,
            base_branch=BASE_BRANCH,
            candidate_branch=CANDIDATE_BRANCH,
            pull_request_number=PR_NUMBER,
        )


def test_authorization_pin_mismatch_fails_closed():
    eligibility, registry, registry_pin, authorization, _ = _fixture()
    with pytest.raises(ValueError, match="authorization receipt pin mismatch"):
        build_dual_control_merge_handoff(
            eligibility_receipt=eligibility,
            merge_authorization_receipt=authorization,
            pinned_merge_authorization_sha256="0" * 64,
            trusted_key_registry=registry,
            pinned_registry_sha256=registry_pin,
            repository=R17.REPOSITORY,
            current_base_sha=R17.BASE,
            current_head_sha=R17.HEAD,
            current_tree_sha=R17.TREE,
            now_unix=R17.NOW,
            base_branch=BASE_BRANCH,
            candidate_branch=CANDIDATE_BRANCH,
            pull_request_number=PR_NUMBER,
        )


def test_expired_r19_eligibility_rejected_at_final_handoff():
    receipt, registry, registry_pin, authorization_pin = _build()
    with pytest.raises(ValueError, match="merge eligibility expired"):
        _validate(
            receipt,
            registry,
            registry_pin,
            authorization_pin,
            now=R17.NOW + 301,
        )


def test_unsafe_r63_authorization_field_rejected_even_with_matching_pin():
    eligibility, registry, registry_pin, authorization, _ = _fixture()
    authorization["merge_executed"] = True
    pin = _pin(authorization)
    with pytest.raises(ValueError, match="unsafe R63 authorization field merge_executed"):
        build_dual_control_merge_handoff(
            eligibility_receipt=eligibility,
            merge_authorization_receipt=authorization,
            pinned_merge_authorization_sha256=pin,
            trusted_key_registry=registry,
            pinned_registry_sha256=registry_pin,
            repository=R17.REPOSITORY,
            current_base_sha=R17.BASE,
            current_head_sha=R17.HEAD,
            current_tree_sha=R17.TREE,
            now_unix=R17.NOW,
            base_branch=BASE_BRANCH,
            candidate_branch=CANDIDATE_BRANCH,
            pull_request_number=PR_NUMBER,
        )


def test_outer_receipt_reseal_cannot_change_pr_subject():
    receipt, registry, registry_pin, authorization_pin = _build()
    tampered = copy.deepcopy(receipt)
    tampered["pull_request_number"] = PR_NUMBER + 1
    unsigned = {key: value for key, value in tampered.items() if key != "receipt_id"}
    tampered["receipt_id"] = "dmh_" + hashlib.sha256(
        json.dumps(unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    ).hexdigest()
    with pytest.raises(ValueError, match="reconstruction mismatch"):
        _validate(tampered, registry, registry_pin, authorization_pin)


def test_only_merge_commit_is_supported():
    eligibility, registry, registry_pin, authorization, authorization_pin = _fixture()
    with pytest.raises(ValueError, match="only MERGE_COMMIT"):
        build_dual_control_merge_handoff(
            eligibility_receipt=eligibility,
            merge_authorization_receipt=authorization,
            pinned_merge_authorization_sha256=authorization_pin,
            trusted_key_registry=registry,
            pinned_registry_sha256=registry_pin,
            repository=R17.REPOSITORY,
            current_base_sha=R17.BASE,
            current_head_sha=R17.HEAD,
            current_tree_sha=R17.TREE,
            now_unix=R17.NOW,
            base_branch=BASE_BRANCH,
            candidate_branch=CANDIDATE_BRANCH,
            pull_request_number=PR_NUMBER,
            merge_method="SQUASH",
        )


def test_module_has_no_network_execution_or_github_surface():
    source_path = Path(trusted_merge_handoff_module.__file__).resolve()
    tree = ast.parse(source_path.read_text(encoding="utf-8"))
    banned_roots = {"subprocess", "socket", "requests", "httpx", "urllib", "github"}
    imports = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module.split(".")[0])
    assert not (imports & banned_roots)


import tempfile

from continuityos.governed_delivery_pipeline import (
    build_code_receipt,
    build_human_merge_gate_request,
    build_plan_receipt,
    build_review_receipt,
    build_test_receipt,
)
from continuityos.trusted_human_approval import (
    InMemoryApprovalReplayGuard,
    verify_and_consume_human_approval,
)


def _load_r63_fixture_module():
    path = Path(__file__).with_name("test_control_plane_binding_merge_authorization_v1.py")
    spec = importlib.util.spec_from_file_location("_r63_fixture", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


R63 = _load_r63_fixture_module()


def _r19_eligibility_for(*, repository, base, base_tree, head, tree):
    plan = build_plan_receipt(
        work_order_id="wo-r20-integration",
        generation=1,
        repository=repository,
        baseline_sha=base,
        baseline_tree_sha=base_tree,
        scope_sha256=R17.sha("scope-r20"),
        acceptance_sha256=R17.sha("acceptance-r20"),
        parity_spec_sha256=R17.sha("parity-r20"),
        parity_mode="PRESERVE",
        expected_delta_sha256=None,
        effect_ceiling="EVIDENCE_ONLY",
        actor=R17.actor("planner", "r20-plan"),
        attempt_nonce="r20-plan-nonce",
    )
    code = build_code_receipt(
        plan,
        actor=R17.actor("coder", "r20-code"),
        candidate_sha=head,
        candidate_tree_sha=tree,
        diff_sha256=R17.sha("diff-r20"),
        attempt_nonce="r20-code-nonce",
    )
    tested = build_test_receipt(
        code,
        actor=R17.actor("tester", "r20-test"),
        tests_passed=True,
        test_suite_sha256=R17.sha("suite-r20"),
        parity_result="PARITY_PASS",
        parity_result_sha256=R17.sha("parity-result-r20"),
        observed_delta_sha256=None,
        attempt_nonce="r20-test-nonce",
    )
    reviewed = build_review_receipt(
        tested,
        actor=R17.actor("reviewer", "r20-review"),
        verdict="PASS",
        review_sha256=R17.sha("review-r20"),
        attempt_nonce="r20-review-nonce",
    )
    request = build_human_merge_gate_request(
        reviewed,
        current_base_sha=base,
        current_head_sha=head,
        current_tree_sha=tree,
        attempt_nonce="r20-human-request",
    )
    private, registry, registry_pin = R17.key_material()
    envelope = R17.signed_envelope(request, private)
    result = verify_and_consume_human_approval(
        request_receipt=request,
        approval_envelope=envelope,
        trusted_key_registry=registry,
        pinned_registry_sha256=registry_pin,
        repository=repository,
        current_base_sha=base,
        current_head_sha=head,
        current_tree_sha=tree,
        now_unix=R17.NOW,
        replay_guard=InMemoryApprovalReplayGuard(),
    )
    return result.eligibility_receipt, registry, registry_pin


def test_real_r63_authorization_receipt_is_compatible_with_r19_subject():
    with tempfile.TemporaryDirectory() as td:
        fx = R63.IntegratedFixture(Path(td))
        authorization = fx.evaluate_merge()
        assert authorization["status"] == "MERGE_AUTHORIZATION_PASS"
        eligibility, registry, registry_pin = _r19_eligibility_for(
            repository=fx.repo_name,
            base=fx.base_head,
            base_tree=fx.base_tree,
            head=fx.head,
            tree=fx.tree,
        )
        authorization_pin = _pin(authorization)
        receipt = build_dual_control_merge_handoff(
            eligibility_receipt=eligibility,
            merge_authorization_receipt=authorization,
            pinned_merge_authorization_sha256=authorization_pin,
            trusted_key_registry=registry,
            pinned_registry_sha256=registry_pin,
            repository=fx.repo_name,
            current_base_sha=fx.base_head,
            current_head_sha=fx.head,
            current_tree_sha=fx.tree,
            now_unix=R17.NOW,
            base_branch=fx.base_branch,
            candidate_branch=fx.branch,
            pull_request_number=42,
        )
        assert receipt["status"] == STATUS
        assert receipt["merge_authorization_subject_sha256"] == authorization["authorization_subject_sha256"]
        assert receipt["can_merge"] is False
