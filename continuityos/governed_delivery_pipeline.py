"""Deterministic governed delivery receipts for CORE v6.4 / ContinuityOS R16.

This module is intentionally side-effect free. It models and validates the delivery
pipeline:

    PLAN -> CODE -> TEST -> REVIEW -> HUMAN_MERGE_GATE

It never executes subprocesses, touches the filesystem or network, mutates providers,
merges code, deploys software, trades, or grants capital authority.

The Human gate can make one exact reviewed candidate merge-eligible. It does not
perform the merge and does not grant deployment/runtime authority.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping


SCHEMA = "continuityos.governed_delivery_pipeline/v1"
POLICY_VERSION = "CORE_V6_4_RC1"
MERGE_AUTHORITY = "EXACT_CANDIDATE_ONLY"

_MACHINE_ROLES = ("planner", "coder", "tester", "reviewer")
_ALLOWED_EFFECT_CEILINGS = {
    "EVIDENCE_ONLY",
    "SOURCE_ONLY",
    "SOURCE_TEST_ONLY",
}
_ALLOWED_PARITY_MODES = {"PRESERVE", "INTENTIONAL_CHANGE"}
_ALLOWED_PARITY_RESULTS = {"PARITY_PASS", "EXPECTED_DELTA_PASS"}
_SAFE_AUTHORITY = {
    "execution_authority": "NONE",
    "can_execute": False,
    "deploy_permission": "DENY",
    "can_trade": False,
    "capital_permission": "DENY",
}


def _plain_snapshot(value: Any, *, depth: int = 0) -> Any:
    if depth > 12:
        raise ValueError("governed delivery: input nesting too deep")
    if value is None or type(value) in (str, int, bool):
        return value
    if type(value) is list:
        if len(value) > 128:
            raise ValueError("governed delivery: list too large")
        return [_plain_snapshot(item, depth=depth + 1) for item in value]
    if type(value) is dict:
        if len(value) > 128:
            raise ValueError("governed delivery: object too large")
        out: dict[str, Any] = {}
        for key, item in value.items():
            if type(key) is not str or not key:
                raise ValueError("governed delivery: invalid object key")
            out[key] = _plain_snapshot(item, depth=depth + 1)
        return out
    raise ValueError("governed delivery: non-plain input")


def _string(name: str, value: Any, *, maximum: int = 512) -> str:
    if type(value) is not str:
        raise ValueError(f"governed delivery: {name} must be a string")
    if not value or len(value) > maximum:
        raise ValueError(f"governed delivery: invalid {name}")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        raise ValueError(f"governed delivery: control character in {name}")
    return value


def _hex(name: str, value: Any, *, length: int) -> str:
    text = _string(name, value, maximum=length)
    if len(text) != length:
        raise ValueError(f"governed delivery: invalid {name} length")
    if any(ch not in "0123456789abcdef" for ch in text):
        raise ValueError(f"governed delivery: invalid {name} hex")
    return text


def _sha256(name: str, value: Any) -> str:
    return _hex(name, value, length=64)


def _git_sha(name: str, value: Any) -> str:
    return _hex(name, value, length=40)


def _generation(value: Any) -> int:
    if type(value) is not int or value < 1 or value > 1_000_000_000:
        raise ValueError("governed delivery: invalid generation")
    return value


def _canonical_bytes(payload: Mapping[str, Any]) -> bytes:
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def _seal(payload: dict[str, Any]) -> dict[str, Any]:
    snapshot = _plain_snapshot(payload)
    receipt_id = "gdp_" + hashlib.sha256(_canonical_bytes(snapshot)).hexdigest()
    return {**snapshot, "receipt_id": receipt_id}


def _require_safe_authority(receipt: Mapping[str, Any]) -> None:
    for key, expected in _SAFE_AUTHORITY.items():
        if receipt.get(key) != expected:
            raise ValueError(f"governed delivery: unsafe authority field {key}")


def _require_receipt(receipt: Any, *, stage: str) -> dict[str, Any]:
    snapshot = _plain_snapshot(receipt)
    if type(snapshot) is not dict:
        raise ValueError("governed delivery: receipt must be an object")
    if snapshot.get("schema") != SCHEMA:
        raise ValueError("governed delivery: schema mismatch")
    if snapshot.get("policy_version") != POLICY_VERSION:
        raise ValueError("governed delivery: policy mismatch")
    if snapshot.get("stage") != stage:
        raise ValueError("governed delivery: stage mismatch")
    _require_safe_authority(snapshot)
    receipt_id = snapshot.get("receipt_id")
    _string("receipt_id", receipt_id, maximum=68)
    if not receipt_id.startswith("gdp_"):
        raise ValueError("governed delivery: invalid receipt id")
    unsigned = {key: value for key, value in snapshot.items() if key != "receipt_id"}
    expected = "gdp_" + hashlib.sha256(_canonical_bytes(unsigned)).hexdigest()
    if receipt_id != expected:
        raise ValueError("governed delivery: receipt integrity mismatch")
    return snapshot


def _actor(actor: Any, *, role: str) -> dict[str, str]:
    if role not in _MACHINE_ROLES:
        raise ValueError("governed delivery: unsupported role")
    snapshot = _plain_snapshot(actor)
    if type(snapshot) is not dict:
        raise ValueError("governed delivery: actor must be an object")
    expected_keys = {
        "provider",
        "declared_model_id",
        "attested_runtime_model_id",
        "session_id",
        "route_id",
    }
    if set(snapshot) != expected_keys:
        raise ValueError("governed delivery: actor shape mismatch")
    out = {key: _string(key, snapshot[key], maximum=256) for key in expected_keys}
    if out["declared_model_id"] != out["attested_runtime_model_id"]:
        raise ValueError("governed delivery: model/runtime identity mismatch")
    return out


def _shared_from_plan(plan: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "work_order_id": plan["work_order_id"],
        "generation": plan["generation"],
        "repository": plan["repository"],
        "baseline_sha": plan["baseline_sha"],
        "baseline_tree_sha": plan["baseline_tree_sha"],
        "scope_sha256": plan["scope_sha256"],
        "acceptance_sha256": plan["acceptance_sha256"],
        "parity_spec_sha256": plan["parity_spec_sha256"],
        "parity_mode": plan["parity_mode"],
        "expected_delta_sha256": plan["expected_delta_sha256"],
        "effect_ceiling": plan["effect_ceiling"],
    }


def _shared_from_receipt(receipt: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "work_order_id": receipt["work_order_id"],
        "generation": receipt["generation"],
        "repository": receipt["repository"],
        "baseline_sha": receipt["baseline_sha"],
        "baseline_tree_sha": receipt["baseline_tree_sha"],
        "scope_sha256": receipt["scope_sha256"],
        "acceptance_sha256": receipt["acceptance_sha256"],
        "parity_spec_sha256": receipt["parity_spec_sha256"],
        "parity_mode": receipt["parity_mode"],
        "expected_delta_sha256": receipt["expected_delta_sha256"],
        "effect_ceiling": receipt["effect_ceiling"],
    }


def _next_role_sessions(
    previous: Mapping[str, Any],
    *,
    role: str,
    session_id: str,
) -> dict[str, str]:
    sessions = _plain_snapshot(previous.get("role_sessions"))
    if type(sessions) is not dict:
        raise ValueError("governed delivery: missing role session map")
    expected_prior = _MACHINE_ROLES[: _MACHINE_ROLES.index(role)]
    if set(sessions) != set(expected_prior):
        raise ValueError("governed delivery: role session chain mismatch")
    if session_id in sessions.values():
        raise ValueError("governed delivery: machine session reuse")
    sessions[role] = session_id
    return sessions


def _next_chain(previous: Mapping[str, Any]) -> list[str]:
    chain = _plain_snapshot(previous.get("receipt_chain"))
    if type(chain) is not list:
        raise ValueError("governed delivery: missing receipt chain")
    if not all(type(item) is str and item.startswith("gdp_") for item in chain):
        raise ValueError("governed delivery: invalid receipt chain")
    receipt_id = _string("previous receipt id", previous.get("receipt_id"), maximum=68)
    if receipt_id in chain:
        raise ValueError("governed delivery: receipt chain cycle")
    return [*chain, receipt_id]


def build_plan_receipt(
    *,
    work_order_id: str,
    generation: int,
    repository: str,
    baseline_sha: str,
    baseline_tree_sha: str,
    scope_sha256: str,
    acceptance_sha256: str,
    parity_spec_sha256: str,
    parity_mode: str,
    expected_delta_sha256: str | None,
    effect_ceiling: str,
    actor: Mapping[str, str],
    attempt_nonce: str,
) -> dict[str, Any]:
    actor_value = _actor(actor, role="planner")
    mode = _string("parity_mode", parity_mode, maximum=32)
    if mode not in _ALLOWED_PARITY_MODES:
        raise ValueError("governed delivery: unsupported parity mode")
    if mode == "PRESERVE":
        if expected_delta_sha256 is not None:
            raise ValueError("governed delivery: preserve mode cannot bind expected delta")
        expected_delta = None
    else:
        expected_delta = _sha256("expected_delta_sha256", expected_delta_sha256)

    ceiling = _string("effect_ceiling", effect_ceiling, maximum=64)
    if ceiling not in _ALLOWED_EFFECT_CEILINGS:
        raise ValueError("governed delivery: unsupported effect ceiling")

    return _seal(
        {
            "schema": SCHEMA,
            "policy_version": POLICY_VERSION,
            "stage": "PLAN",
            "status": "PLANNED",
            "previous_receipt_id": None,
            "receipt_chain": [],
            "role_sessions": {"planner": actor_value["session_id"]},
            "actor": {"role": "planner", **actor_value},
            "attempt_nonce": _string("attempt_nonce", attempt_nonce, maximum=256),
            "work_order_id": _string("work_order_id", work_order_id, maximum=256),
            "generation": _generation(generation),
            "repository": _string("repository", repository, maximum=256),
            "baseline_sha": _git_sha("baseline_sha", baseline_sha),
            "baseline_tree_sha": _git_sha("baseline_tree_sha", baseline_tree_sha),
            "scope_sha256": _sha256("scope_sha256", scope_sha256),
            "acceptance_sha256": _sha256("acceptance_sha256", acceptance_sha256),
            "parity_spec_sha256": _sha256("parity_spec_sha256", parity_spec_sha256),
            "parity_mode": mode,
            "expected_delta_sha256": expected_delta,
            "effect_ceiling": ceiling,
            **_SAFE_AUTHORITY,
            "can_merge": False,
        }
    )


def build_code_receipt(
    plan_receipt: Mapping[str, Any],
    *,
    actor: Mapping[str, str],
    candidate_sha: str,
    candidate_tree_sha: str,
    diff_sha256: str,
    attempt_nonce: str,
) -> dict[str, Any]:
    plan = _require_receipt(plan_receipt, stage="PLAN")
    actor_value = _actor(actor, role="coder")
    role_sessions = _next_role_sessions(
        plan, role="coder", session_id=actor_value["session_id"]
    )
    return _seal(
        {
            "schema": SCHEMA,
            "policy_version": POLICY_VERSION,
            "stage": "CODE",
            "status": "CODED",
            "previous_receipt_id": plan["receipt_id"],
            "receipt_chain": _next_chain(plan),
            "role_sessions": role_sessions,
            "actor": {"role": "coder", **actor_value},
            "attempt_nonce": _string("attempt_nonce", attempt_nonce, maximum=256),
            **_shared_from_plan(plan),
            "candidate_sha": _git_sha("candidate_sha", candidate_sha),
            "candidate_tree_sha": _git_sha("candidate_tree_sha", candidate_tree_sha),
            "diff_sha256": _sha256("diff_sha256", diff_sha256),
            **_SAFE_AUTHORITY,
            "can_merge": False,
        }
    )


def build_test_receipt(
    code_receipt: Mapping[str, Any],
    *,
    actor: Mapping[str, str],
    tests_passed: bool,
    test_suite_sha256: str,
    parity_result: str,
    parity_result_sha256: str,
    attempt_nonce: str,
) -> dict[str, Any]:
    code = _require_receipt(code_receipt, stage="CODE")
    actor_value = _actor(actor, role="tester")
    role_sessions = _next_role_sessions(
        code, role="tester", session_id=actor_value["session_id"]
    )
    if type(tests_passed) is not bool or not tests_passed:
        raise ValueError("governed delivery: tests did not pass")
    parity = _string("parity_result", parity_result, maximum=64)
    if parity not in _ALLOWED_PARITY_RESULTS:
        raise ValueError("governed delivery: unsupported parity result")
    expected = (
        "PARITY_PASS"
        if code["parity_mode"] == "PRESERVE"
        else "EXPECTED_DELTA_PASS"
    )
    if parity != expected:
        raise ValueError("governed delivery: parity requirement not satisfied")

    return _seal(
        {
            "schema": SCHEMA,
            "policy_version": POLICY_VERSION,
            "stage": "TEST",
            "status": "TEST_PASS",
            "previous_receipt_id": code["receipt_id"],
            "receipt_chain": _next_chain(code),
            "role_sessions": role_sessions,
            "actor": {"role": "tester", **actor_value},
            "attempt_nonce": _string("attempt_nonce", attempt_nonce, maximum=256),
            **_shared_from_receipt(code),
            "candidate_sha": code["candidate_sha"],
            "candidate_tree_sha": code["candidate_tree_sha"],
            "diff_sha256": code["diff_sha256"],
            "tests_passed": True,
            "test_suite_sha256": _sha256("test_suite_sha256", test_suite_sha256),
            "parity_result": parity,
            "parity_result_sha256": _sha256(
                "parity_result_sha256", parity_result_sha256
            ),
            **_SAFE_AUTHORITY,
            "can_merge": False,
        }
    )


def build_review_receipt(
    test_receipt: Mapping[str, Any],
    *,
    actor: Mapping[str, str],
    verdict: str,
    review_sha256: str,
    attempt_nonce: str,
) -> dict[str, Any]:
    tested = _require_receipt(test_receipt, stage="TEST")
    actor_value = _actor(actor, role="reviewer")
    role_sessions = _next_role_sessions(
        tested, role="reviewer", session_id=actor_value["session_id"]
    )
    verdict_value = _string("verdict", verdict, maximum=32)
    if verdict_value != "PASS":
        raise ValueError("governed delivery: review is not merge-eligible")

    return _seal(
        {
            "schema": SCHEMA,
            "policy_version": POLICY_VERSION,
            "stage": "REVIEW",
            "status": "REVIEW_PASS",
            "previous_receipt_id": tested["receipt_id"],
            "receipt_chain": _next_chain(tested),
            "role_sessions": role_sessions,
            "actor": {"role": "reviewer", **actor_value},
            "attempt_nonce": _string("attempt_nonce", attempt_nonce, maximum=256),
            **_shared_from_receipt(tested),
            "candidate_sha": tested["candidate_sha"],
            "candidate_tree_sha": tested["candidate_tree_sha"],
            "diff_sha256": tested["diff_sha256"],
            "test_suite_sha256": tested["test_suite_sha256"],
            "parity_result": tested["parity_result"],
            "parity_result_sha256": tested["parity_result_sha256"],
            "verdict": "PASS",
            "review_sha256": _sha256("review_sha256", review_sha256),
            **_SAFE_AUTHORITY,
            "can_merge": False,
        }
    )


def build_human_merge_gate_receipt(
    review_receipt: Mapping[str, Any],
    *,
    human_id: str,
    approval_token_sha256: str,
    current_base_sha: str,
    current_head_sha: str,
    current_tree_sha: str,
    approve_expected_delta: bool,
    attempt_nonce: str,
) -> dict[str, Any]:
    review = _require_receipt(review_receipt, stage="REVIEW")
    if review["verdict"] != "PASS":
        raise ValueError("governed delivery: review verdict is not PASS")
    base = _git_sha("current_base_sha", current_base_sha)
    head = _git_sha("current_head_sha", current_head_sha)
    tree = _git_sha("current_tree_sha", current_tree_sha)
    if base != review["baseline_sha"]:
        raise ValueError("governed delivery: base drift before Human gate")
    if head != review["candidate_sha"]:
        raise ValueError("governed delivery: candidate drift before Human gate")
    if tree != review["candidate_tree_sha"]:
        raise ValueError("governed delivery: candidate tree drift before Human gate")
    if type(approve_expected_delta) is not bool:
        raise ValueError("governed delivery: invalid expected-delta approval")
    if review["parity_mode"] == "INTENTIONAL_CHANGE" and not approve_expected_delta:
        raise ValueError("governed delivery: intentional delta lacks Human approval")
    if review["parity_mode"] == "PRESERVE" and approve_expected_delta:
        raise ValueError("governed delivery: unexpected delta approval in preserve mode")

    chain = _next_chain(review)
    return _seal(
        {
            "schema": SCHEMA,
            "policy_version": POLICY_VERSION,
            "stage": "HUMAN_MERGE_GATE",
            "status": "MERGE_ELIGIBLE_EXACT_CANDIDATE_ONLY",
            "previous_receipt_id": review["receipt_id"],
            "receipt_chain": chain,
            "role_sessions": review["role_sessions"],
            "human_id": _string("human_id", human_id, maximum=256),
            "approval_token_sha256": _sha256(
                "approval_token_sha256", approval_token_sha256
            ),
            "approve_expected_delta": approve_expected_delta,
            "attempt_nonce": _string("attempt_nonce", attempt_nonce, maximum=256),
            **_shared_from_receipt(review),
            "candidate_sha": review["candidate_sha"],
            "candidate_tree_sha": review["candidate_tree_sha"],
            "diff_sha256": review["diff_sha256"],
            "review_sha256": review["review_sha256"],
            "merge_authority": MERGE_AUTHORITY,
            **_SAFE_AUTHORITY,
            "can_merge": True,
        }
    )


def require_merge_eligible(
    gate_receipt: Mapping[str, Any],
    *,
    repository: str,
    current_base_sha: str,
    current_head_sha: str,
    current_tree_sha: str,
) -> dict[str, Any]:
    gate = _require_receipt(gate_receipt, stage="HUMAN_MERGE_GATE")
    if gate.get("status") != "MERGE_ELIGIBLE_EXACT_CANDIDATE_ONLY":
        raise ValueError("governed delivery: gate status is not merge-eligible")
    if gate.get("merge_authority") != MERGE_AUTHORITY or gate.get("can_merge") is not True:
        raise ValueError("governed delivery: merge authority mismatch")
    if gate["repository"] != _string("repository", repository, maximum=256):
        raise ValueError("governed delivery: repository mismatch")
    if gate["baseline_sha"] != _git_sha("current_base_sha", current_base_sha):
        raise ValueError("governed delivery: base drift after Human gate")
    if gate["candidate_sha"] != _git_sha("current_head_sha", current_head_sha):
        raise ValueError("governed delivery: candidate drift after Human gate")
    if gate["candidate_tree_sha"] != _git_sha("current_tree_sha", current_tree_sha):
        raise ValueError("governed delivery: tree drift after Human gate")
    if len(gate.get("receipt_chain", [])) != 4:
        raise ValueError("governed delivery: incomplete receipt chain")
    if set(gate.get("role_sessions", {})) != set(_MACHINE_ROLES):
        raise ValueError("governed delivery: incomplete role/session chain")
    if len(set(gate["role_sessions"].values())) != len(_MACHINE_ROLES):
        raise ValueError("governed delivery: machine session reuse")
    _require_safe_authority(gate)
    return gate


__all__ = [
    "MERGE_AUTHORITY",
    "POLICY_VERSION",
    "SCHEMA",
    "build_plan_receipt",
    "build_code_receipt",
    "build_test_receipt",
    "build_review_receipt",
    "build_human_merge_gate_receipt",
    "require_merge_eligible",
]
