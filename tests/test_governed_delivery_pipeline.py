from __future__ import annotations

import ast
import copy
import hashlib
import inspect

import pytest

import continuityos.governed_delivery_pipeline as gdp


BASE_SHA = "1" * 40
BASE_TREE = "2" * 40
CANDIDATE_SHA = "3" * 40
CANDIDATE_TREE = "4" * 40
SCOPE = "5" * 64
ACCEPTANCE = "6" * 64
PARITY_SPEC = "7" * 64
DIFF = "8" * 64
TEST_SUITE = "9" * 64
PARITY_RESULT = "a" * 64
REVIEW = "b" * 64
APPROVAL = "c" * 64
EXPECTED_DELTA = "d" * 64
REPOSITORY = "bitmaster162/continuityos"


def actor(role: str, *, session: str | None = None, model: str | None = None) -> dict[str, str]:
    chosen_model = model or f"provider/{role}-model"
    return {
        "provider": "provider",
        "declared_model_id": chosen_model,
        "attested_runtime_model_id": chosen_model,
        "session_id": session or f"session-{role}",
        "route_id": f"route-{role}",
    }


def plan(*, parity_mode: str = "PRESERVE") -> dict:
    return gdp.build_plan_receipt(
        work_order_id="R16-TEST-001",
        generation=1,
        repository=REPOSITORY,
        baseline_sha=BASE_SHA,
        baseline_tree_sha=BASE_TREE,
        scope_sha256=SCOPE,
        acceptance_sha256=ACCEPTANCE,
        parity_spec_sha256=PARITY_SPEC,
        parity_mode=parity_mode,
        expected_delta_sha256=(EXPECTED_DELTA if parity_mode == "INTENTIONAL_CHANGE" else None),
        effect_ceiling="SOURCE_TEST_ONLY",
        actor=actor("planner"),
        attempt_nonce="nonce-plan",
    )


def coded(plan_receipt: dict | None = None, *, coder_actor: dict[str, str] | None = None) -> dict:
    return gdp.build_code_receipt(
        plan_receipt or plan(),
        actor=coder_actor or actor("coder"),
        candidate_sha=CANDIDATE_SHA,
        candidate_tree_sha=CANDIDATE_TREE,
        diff_sha256=DIFF,
        attempt_nonce="nonce-code",
    )


def make_tested(code_receipt: dict | None = None, *, tester_actor: dict[str, str] | None = None) -> dict:
    source = code_receipt or coded()
    parity_result = (
        "EXPECTED_DELTA_PASS"
        if source["parity_mode"] == "INTENTIONAL_CHANGE"
        else "PARITY_PASS"
    )
    return gdp.build_test_receipt(
        source,
        actor=tester_actor or actor("tester"),
        tests_passed=True,
        test_suite_sha256=TEST_SUITE,
        parity_result=parity_result,
        parity_result_sha256=PARITY_RESULT,
        attempt_nonce="nonce-test",
    )


def reviewed(test_receipt: dict | None = None, *, reviewer_actor: dict[str, str] | None = None) -> dict:
    return gdp.build_review_receipt(
        test_receipt or make_tested(),
        actor=reviewer_actor or actor("reviewer"),
        verdict="PASS",
        review_sha256=REVIEW,
        attempt_nonce="nonce-review",
    )


def gated(review_receipt: dict | None = None, *, approve_expected_delta: bool = False) -> dict:
    return gdp.build_human_merge_gate_receipt(
        review_receipt or reviewed(),
        human_id="human:robert",
        approval_token_sha256=APPROVAL,
        current_base_sha=BASE_SHA,
        current_head_sha=CANDIDATE_SHA,
        current_tree_sha=CANDIDATE_TREE,
        approve_expected_delta=approve_expected_delta,
        attempt_nonce="nonce-human",
    )


def test_full_preserve_pipeline_reaches_exact_candidate_merge_eligibility_only():
    gate = gated()
    validated = gdp.require_merge_eligible(
        gate,
        repository=REPOSITORY,
        current_base_sha=BASE_SHA,
        current_head_sha=CANDIDATE_SHA,
        current_tree_sha=CANDIDATE_TREE,
    )

    assert validated["status"] == "MERGE_ELIGIBLE_EXACT_CANDIDATE_ONLY"
    assert validated["merge_authority"] == "EXACT_CANDIDATE_ONLY"
    assert validated["can_merge"] is True
    assert validated["execution_authority"] == "NONE"
    assert validated["can_execute"] is False
    assert validated["deploy_permission"] == "DENY"
    assert validated["can_trade"] is False
    assert validated["capital_permission"] == "DENY"
    assert validated["receipt_chain"] == [
        plan()["receipt_id"],
        coded()["receipt_id"],
        make_tested()["receipt_id"],
        reviewed()["receipt_id"],
    ]
    assert set(validated["role_sessions"]) == {"planner", "coder", "tester", "reviewer"}
    assert len(set(validated["role_sessions"].values())) == 4


def test_receipts_are_deterministic_for_identical_inputs():
    first = plan()
    second = plan()
    assert first == second
    assert first["receipt_id"] == second["receipt_id"]
    assert first["receipt_id"].startswith("gdp_")
    assert len(first["receipt_id"]) == 68


def test_declared_model_must_match_attested_runtime_model():
    bad = actor("coder")
    bad["attested_runtime_model_id"] = "provider/different-runtime"
    with pytest.raises(ValueError, match="model/runtime identity mismatch"):
        coded(coder_actor=bad)


def test_machine_session_reuse_fails_closed():
    with pytest.raises(ValueError, match="machine session reuse"):
        coded(coder_actor=actor("coder", session="session-planner"))

    code = coded()
    with pytest.raises(ValueError, match="machine session reuse"):
        make_tested(code, tester_actor=actor("tester", session="session-coder"))


def test_test_failure_never_emits_test_pass_receipt():
    with pytest.raises(ValueError, match="tests did not pass"):
        gdp.build_test_receipt(
            coded(),
            actor=actor("tester"),
            tests_passed=False,
            test_suite_sha256=TEST_SUITE,
            parity_result="PARITY_PASS",
            parity_result_sha256=PARITY_RESULT,
            attempt_nonce="nonce-test-fail",
        )


def test_preserve_mode_requires_parity_pass():
    with pytest.raises(ValueError, match="parity requirement not satisfied"):
        gdp.build_test_receipt(
            coded(),
            actor=actor("tester"),
            tests_passed=True,
            test_suite_sha256=TEST_SUITE,
            parity_result="EXPECTED_DELTA_PASS",
            parity_result_sha256=PARITY_RESULT,
            attempt_nonce="nonce-parity-wrong",
        )


def test_intentional_change_requires_bound_delta_and_explicit_human_approval():
    intentional_plan = plan(parity_mode="INTENTIONAL_CHANGE")
    code = coded(intentional_plan)
    test = make_tested(code)
    review = reviewed(test)

    assert intentional_plan["expected_delta_sha256"] == EXPECTED_DELTA
    assert test["parity_result"] == "EXPECTED_DELTA_PASS"

    with pytest.raises(ValueError, match="intentional delta lacks Human approval"):
        gated(review, approve_expected_delta=False)

    gate = gated(review, approve_expected_delta=True)
    assert gate["approve_expected_delta"] is True
    assert gate["status"] == "MERGE_ELIGIBLE_EXACT_CANDIDATE_ONLY"


def test_preserve_mode_rejects_spurious_delta_approval():
    with pytest.raises(ValueError, match="unexpected delta approval"):
        gated(approve_expected_delta=True)


def test_review_must_pass_before_human_gate():
    with pytest.raises(ValueError, match="review is not merge-eligible"):
        gdp.build_review_receipt(
            make_tested(),
            actor=actor("reviewer"),
            verdict="REVISE",
            review_sha256=REVIEW,
            attempt_nonce="nonce-review-revise",
        )


def test_receipt_tampering_is_detected_before_downstream_progression():
    value = copy.deepcopy(coded())
    value["candidate_sha"] = "e" * 40
    with pytest.raises(ValueError, match="receipt integrity mismatch"):
        make_tested(value)


def test_authority_escalation_tampering_is_detected():
    value = copy.deepcopy(coded())
    value["can_execute"] = True
    unsigned = {key: item for key, item in value.items() if key != "receipt_id"}
    value["receipt_id"] = "gdp_" + hashlib.sha256(gdp._canonical_bytes(unsigned)).hexdigest()

    with pytest.raises(ValueError, match="unsafe authority field can_execute"):
        make_tested(value)


def test_base_head_and_tree_drift_fail_before_human_gate():
    review = reviewed()

    with pytest.raises(ValueError, match="base drift"):
        gdp.build_human_merge_gate_receipt(
            review,
            human_id="human:robert",
            approval_token_sha256=APPROVAL,
            current_base_sha="f" * 40,
            current_head_sha=CANDIDATE_SHA,
            current_tree_sha=CANDIDATE_TREE,
            approve_expected_delta=False,
            attempt_nonce="nonce-human-base-drift",
        )

    with pytest.raises(ValueError, match="candidate drift"):
        gdp.build_human_merge_gate_receipt(
            review,
            human_id="human:robert",
            approval_token_sha256=APPROVAL,
            current_base_sha=BASE_SHA,
            current_head_sha="f" * 40,
            current_tree_sha=CANDIDATE_TREE,
            approve_expected_delta=False,
            attempt_nonce="nonce-human-head-drift",
        )

    with pytest.raises(ValueError, match="candidate tree drift"):
        gdp.build_human_merge_gate_receipt(
            review,
            human_id="human:robert",
            approval_token_sha256=APPROVAL,
            current_base_sha=BASE_SHA,
            current_head_sha=CANDIDATE_SHA,
            current_tree_sha="f" * 40,
            approve_expected_delta=False,
            attempt_nonce="nonce-human-tree-drift",
        )


def test_drift_after_human_gate_invalidates_merge_eligibility():
    gate = gated()
    cases = [
        {"current_base_sha": "f" * 40, "current_head_sha": CANDIDATE_SHA, "current_tree_sha": CANDIDATE_TREE, "match": "base drift"},
        {"current_base_sha": BASE_SHA, "current_head_sha": "f" * 40, "current_tree_sha": CANDIDATE_TREE, "match": "candidate drift"},
        {"current_base_sha": BASE_SHA, "current_head_sha": CANDIDATE_SHA, "current_tree_sha": "f" * 40, "match": "tree drift"},
    ]
    for case in cases:
        with pytest.raises(ValueError, match=case["match"]):
            gdp.require_merge_eligible(
                gate,
                repository=REPOSITORY,
                current_base_sha=case["current_base_sha"],
                current_head_sha=case["current_head_sha"],
                current_tree_sha=case["current_tree_sha"],
            )


def test_raw_human_approval_token_is_not_part_of_public_api_or_receipt():
    signature = inspect.signature(gdp.build_human_merge_gate_receipt)
    assert "approval_token" not in signature.parameters
    assert "approval_token_sha256" in signature.parameters
    gate = gated()
    assert "approval_token" not in gate
    assert gate["approval_token_sha256"] == APPROVAL


def test_module_is_stdlib_only_and_side_effect_free_by_capability():
    source = inspect.getsource(gdp)
    tree = ast.parse(source)
    imports: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imports.add(node.module or "")

    assert imports <= {"__future__", "hashlib", "json", "typing"}
    for token in (
        "subprocess.",
        "socket.",
        "requests.",
        "urllib.",
        "pathlib.",
        "os.environ",
        "os.getenv",
        "open(",
        "git ",
        "merge_pull_request",
    ):
        assert token not in source


def test_all_pre_human_stages_preserve_no_execution_no_deploy_no_capital_authority():
    receipts = [plan(), coded(), make_tested(), reviewed()]
    for value in receipts:
        assert value["execution_authority"] == "NONE"
        assert value["can_execute"] is False
        assert value["can_merge"] is False
        assert value["deploy_permission"] == "DENY"
        assert value["can_trade"] is False
        assert value["capital_permission"] == "DENY"
