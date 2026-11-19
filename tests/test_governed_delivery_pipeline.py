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
        observed_delta_sha256=(EXPECTED_DELTA if source["parity_mode"] == "INTENTIONAL_CHANGE" else None),
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


def merge_request(review_receipt: dict | None = None) -> dict:
    return gdp.build_human_merge_gate_request(
        review_receipt or reviewed(),
        current_base_sha=BASE_SHA,
        current_head_sha=CANDIDATE_SHA,
        current_tree_sha=CANDIDATE_TREE,
        attempt_nonce="nonce-human-request",
    )


def test_full_preserve_pipeline_stops_at_authenticated_human_boundary():
    request = merge_request()
    validated = gdp.require_human_merge_gate_request_current(
        request,
        repository=REPOSITORY,
        current_base_sha=BASE_SHA,
        current_head_sha=CANDIDATE_SHA,
        current_tree_sha=CANDIDATE_TREE,
    )

    assert validated["status"] == "AWAITING_HUMAN_MERGE_GATE"
    assert validated["authenticated_human_approval_present"] is False
    assert validated["approval_boundary"] == "TRUSTED_EXTERNAL_HUMAN_APPROVAL_REQUIRED"
    assert validated["can_merge"] is False
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
            observed_delta_sha256=None,
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
            observed_delta_sha256=None,
            attempt_nonce="nonce-parity-wrong",
        )


def test_intentional_change_requires_observed_delta_to_match_plan():
    code = coded(plan(parity_mode="INTENTIONAL_CHANGE"))
    with pytest.raises(ValueError, match="observed delta does not match plan-bound expected delta"):
        gdp.build_test_receipt(
            code,
            actor=actor("tester"),
            tests_passed=True,
            test_suite_sha256=TEST_SUITE,
            parity_result="EXPECTED_DELTA_PASS",
            parity_result_sha256=PARITY_RESULT,
            observed_delta_sha256="e" * 64,
            attempt_nonce="nonce-delta-mismatch",
        )


def test_preserve_mode_rejects_observed_delta():
    with pytest.raises(ValueError, match="preserve mode cannot report observed delta"):
        gdp.build_test_receipt(
            coded(),
            actor=actor("tester"),
            tests_passed=True,
            test_suite_sha256=TEST_SUITE,
            parity_result="PARITY_PASS",
            parity_result_sha256=PARITY_RESULT,
            observed_delta_sha256=EXPECTED_DELTA,
            attempt_nonce="nonce-unexpected-delta",
        )


def test_intentional_change_is_bound_but_waits_for_trusted_human_approval():
    intentional_plan = plan(parity_mode="INTENTIONAL_CHANGE")
    code = coded(intentional_plan)
    test = make_tested(code)
    review = reviewed(test)
    request = merge_request(review)

    assert intentional_plan["expected_delta_sha256"] == EXPECTED_DELTA
    assert test["parity_result"] == "EXPECTED_DELTA_PASS"
    assert test["observed_delta_sha256"] == EXPECTED_DELTA
    assert request["expected_delta_sha256"] == EXPECTED_DELTA
    assert request["observed_delta_sha256"] == EXPECTED_DELTA
    assert request["test_suite_sha256"] == TEST_SUITE
    assert request["parity_result"] == "EXPECTED_DELTA_PASS"
    assert request["parity_result_sha256"] == PARITY_RESULT
    assert request["verdict"] == "PASS"
    assert request["human_delta_approval_required"] is True
    assert request["authenticated_human_approval_present"] is False
    assert request["can_merge"] is False


def test_review_must_pass_before_human_gate_request():
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


def test_base_head_and_tree_drift_fail_before_human_gate_request():
    review = reviewed()

    with pytest.raises(ValueError, match="base drift"):
        gdp.build_human_merge_gate_request(
            review, current_base_sha="f" * 40, current_head_sha=CANDIDATE_SHA,
            current_tree_sha=CANDIDATE_TREE, attempt_nonce="nonce-base-drift"
        )
    with pytest.raises(ValueError, match="candidate drift"):
        gdp.build_human_merge_gate_request(
            review, current_base_sha=BASE_SHA, current_head_sha="f" * 40,
            current_tree_sha=CANDIDATE_TREE, attempt_nonce="nonce-head-drift"
        )
    with pytest.raises(ValueError, match="candidate tree drift"):
        gdp.build_human_merge_gate_request(
            review, current_base_sha=BASE_SHA, current_head_sha=CANDIDATE_SHA,
            current_tree_sha="f" * 40, attempt_nonce="nonce-tree-drift"
        )


def test_human_gate_request_revalidates_parity_and_delta_evidence():
    request = merge_request(reviewed(make_tested(coded(plan(parity_mode="INTENTIONAL_CHANGE")))))
    request["observed_delta_sha256"] = "e" * 64
    unsigned = {key: item for key, item in request.items() if key != "receipt_id"}
    request["receipt_id"] = "gdp_" + hashlib.sha256(gdp._canonical_bytes(unsigned)).hexdigest()
    with pytest.raises(ValueError, match="Human gate delta evidence mismatch"):
        gdp.require_human_merge_gate_request_current(
            request,
            repository=REPOSITORY,
            current_base_sha=BASE_SHA,
            current_head_sha=CANDIDATE_SHA,
            current_tree_sha=CANDIDATE_TREE,
        )


def test_authority_defaults_are_immutable_values_not_a_mutable_dict():
    assert isinstance(gdp._SAFE_AUTHORITY_ITEMS, tuple)
    assert dict(gdp._SAFE_AUTHORITY_ITEMS)["can_merge"] is False
    assert dict(gdp._SAFE_AUTHORITY_ITEMS)["can_execute"] is False


def test_drift_after_human_gate_request_invalidates_handoff():
    request = merge_request()
    cases = [
        {"current_base_sha": "f" * 40, "current_head_sha": CANDIDATE_SHA, "current_tree_sha": CANDIDATE_TREE, "match": "base drift"},
        {"current_base_sha": BASE_SHA, "current_head_sha": "f" * 40, "current_tree_sha": CANDIDATE_TREE, "match": "candidate drift"},
        {"current_base_sha": BASE_SHA, "current_head_sha": CANDIDATE_SHA, "current_tree_sha": "f" * 40, "match": "tree drift"},
    ]
    for case in cases:
        with pytest.raises(ValueError, match=case["match"]):
            gdp.require_human_merge_gate_request_current(
                request, repository=REPOSITORY,
                current_base_sha=case["current_base_sha"],
                current_head_sha=case["current_head_sha"],
                current_tree_sha=case["current_tree_sha"],
            )


def test_pure_r16_has_no_human_approval_minting_surface():
    source = inspect.getsource(gdp)
    request = merge_request()
    signature = inspect.signature(gdp.build_human_merge_gate_request)

    assert "human_id" not in signature.parameters
    assert "approval_token" not in signature.parameters
    assert "approval_token_sha256" not in signature.parameters
    assert "build_human_merge_gate_receipt" not in gdp.__all__
    assert "require_merge_eligible" not in gdp.__all__
    assert request["can_merge"] is False
    assert request["authenticated_human_approval_present"] is False
    assert '"can_merge": True' not in source


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
    receipts = [plan(), coded(), make_tested(), reviewed(), merge_request()]
    for value in receipts:
        assert value["execution_authority"] == "NONE"
        assert value["can_execute"] is False
        assert value["can_merge"] is False
        assert value["deploy_permission"] == "DENY"
        assert value["can_trade"] is False
        assert value["capital_permission"] == "DENY"
