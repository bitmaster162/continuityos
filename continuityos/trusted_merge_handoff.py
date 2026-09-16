"""R20 dual-control merge handoff for governed delivery.

This module binds a current R19 authenticated Human merge eligibility receipt to
an independently produced R63 merge-authorization receipt.  It is effect-free:
it never calls GitHub, runs subprocesses, mutates Git, merges, deploys, trades,
or grants capital authority.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Mapping

from .trusted_human_approval import require_merge_eligibility_current

SCHEMA = "continuityos.trusted_merge_handoff/v1"
STATUS = "DUAL_CONTROL_MERGE_HANDOFF_READY"
OUTCOME = "R19_REVISION_R63_PR_SCOPE_INTERSECTION"
MERGE_METHOD = "MERGE_COMMIT"
AUTH_STATUS = "MERGE_AUTHORIZATION_PASS"
AUTH_OUTCOME = "MERGE_EXECUTION_MAY_BE_REQUESTED_ONCE"
AUTH_EFFECT = "PROPOSAL_ONLY_NO_MERGE"
NONCE_RE = re.compile(r"^[A-Za-z0-9_-]{16,128}$")
_SAFE_AUTHORITY_ITEMS = (
    ("execution_authority", "NONE"),
    ("can_execute", False),
    ("can_merge", False),
    ("deploy_permission", "DENY"),
    ("can_trade", False),
    ("capital_permission", "DENY"),
)


def _canonical_bytes(value: Mapping[str, Any]) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")


def _sha256_json(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _plain(value: Any, *, depth: int = 0) -> Any:
    if depth > 16:
        raise ValueError("trusted merge handoff: input nesting too deep")
    if value is None or type(value) in (str, int, bool):
        return value
    if type(value) is list:
        if len(value) > 256:
            raise ValueError("trusted merge handoff: list too large")
        return [_plain(item, depth=depth + 1) for item in value]
    if type(value) is dict:
        if len(value) > 256:
            raise ValueError("trusted merge handoff: object too large")
        result: dict[str, Any] = {}
        for key, item in value.items():
            if type(key) is not str or not key:
                raise ValueError("trusted merge handoff: invalid object key")
            result[key] = _plain(item, depth=depth + 1)
        return result
    raise ValueError("trusted merge handoff: non-plain input")


def _string(name: str, value: Any, *, maximum: int = 256) -> str:
    if type(value) is not str or not value or len(value) > maximum:
        raise ValueError(f"trusted merge handoff: invalid {name}")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        raise ValueError(f"trusted merge handoff: control character in {name}")
    return value


def _hex(name: str, value: Any, *, length: int) -> str:
    text = _string(name, value, maximum=length)
    if len(text) != length or any(ch not in "0123456789abcdef" for ch in text):
        raise ValueError(f"trusted merge handoff: invalid {name}")
    return text


def _git_sha(name: str, value: Any) -> str:
    return _hex(name, value, length=40)


def _sha256(name: str, value: Any) -> str:
    return _hex(name, value, length=64)


def _pull_request_number(value: Any) -> int:
    if type(value) is not int or value <= 0:
        raise ValueError("trusted merge handoff: invalid pull_request_number")
    return value


def _safe_authority() -> dict[str, Any]:
    return dict(_SAFE_AUTHORITY_ITEMS)


def _require_authorization_receipt(
    value: Any,
    *,
    pinned_sha256: str,
) -> dict[str, Any]:
    receipt = _plain(value)
    if type(receipt) is not dict:
        raise ValueError("trusted merge handoff: authorization receipt must be dict")
    pin = _sha256("pinned_merge_authorization_sha256", pinned_sha256)
    if _sha256_json(receipt) != pin:
        raise ValueError("trusted merge handoff: authorization receipt pin mismatch")
    if receipt.get("status") != AUTH_STATUS or receipt.get("outcome") != AUTH_OUTCOME:
        raise ValueError("trusted merge handoff: R63 authorization is not PASS")
    if receipt.get("effect") != AUTH_EFFECT:
        raise ValueError("trusted merge handoff: R63 authorization effect widened")
    expected_safe = {
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
    for key, expected in expected_safe.items():
        if receipt.get(key) != expected:
            raise ValueError(f"trusted merge handoff: unsafe R63 authorization field {key}")
    return receipt


def _require_r63_subject_match(
    authorization: Mapping[str, Any],
    *,
    eligibility: Mapping[str, Any],
    base_branch: str,
    candidate_branch: str,
    pull_request_number: int,
    merge_method: str,
) -> tuple[str, str]:
    binding = authorization.get("binding")
    if type(binding) is not dict:
        raise ValueError("trusted merge handoff: R63 authorization binding missing")
    request = eligibility.get("request_receipt")
    if type(request) is not dict:
        raise ValueError("trusted merge handoff: R19 nested request missing")
    expected = {
        "repository": eligibility["repository"],
        "base_branch": base_branch,
        "base_head": eligibility["baseline_sha"],
        "base_tree": request.get("baseline_tree_sha"),
        "candidate_branch": candidate_branch,
        "candidate_head": eligibility["candidate_sha"],
        "candidate_tree": eligibility["candidate_tree_sha"],
        "pull_request_number": pull_request_number,
        "merge_method": merge_method,
    }
    for key, expected_value in expected.items():
        if binding.get(key) != expected_value:
            raise ValueError(f"trusted merge handoff: R19/R63 subject mismatch for {key}")
    subject_sha = _sha256(
        "authorization_subject_sha256",
        authorization.get("authorization_subject_sha256"),
    )
    nonce = _string("authorization_nonce", authorization.get("authorization_nonce"), maximum=128)
    if not NONCE_RE.fullmatch(nonce):
        raise ValueError("trusted merge handoff: invalid R63 authorization nonce")
    return subject_sha, nonce


def build_dual_control_merge_handoff(
    *,
    eligibility_receipt: Any,
    merge_authorization_receipt: Any,
    pinned_merge_authorization_sha256: str,
    trusted_key_registry: Any,
    pinned_registry_sha256: str,
    repository: str,
    current_base_sha: str,
    current_head_sha: str,
    current_tree_sha: str,
    now_unix: int,
    base_branch: str,
    candidate_branch: str,
    pull_request_number: int,
    merge_method: str = MERGE_METHOD,
) -> dict[str, Any]:
    base_branch_value = _string("base_branch", base_branch)
    candidate_branch_value = _string("candidate_branch", candidate_branch)
    pr_number = _pull_request_number(pull_request_number)
    method = _string("merge_method", merge_method, maximum=32)
    if method != MERGE_METHOD:
        raise ValueError("trusted merge handoff: only MERGE_COMMIT is supported")

    eligibility = require_merge_eligibility_current(
        eligibility_receipt,
        trusted_key_registry=trusted_key_registry,
        pinned_registry_sha256=pinned_registry_sha256,
        repository=repository,
        current_base_sha=current_base_sha,
        current_head_sha=current_head_sha,
        current_tree_sha=current_tree_sha,
        now_unix=now_unix,
    )
    authorization = _require_authorization_receipt(
        merge_authorization_receipt,
        pinned_sha256=pinned_merge_authorization_sha256,
    )
    subject_sha, authorization_nonce = _require_r63_subject_match(
        authorization,
        eligibility=eligibility,
        base_branch=base_branch_value,
        candidate_branch=candidate_branch_value,
        pull_request_number=pr_number,
        merge_method=method,
    )
    nested_request = eligibility["request_receipt"]
    baseline_tree_sha = _git_sha(
        "baseline_tree_sha",
        nested_request.get("baseline_tree_sha"),
    )
    auth_pin = _sha256(
        "pinned_merge_authorization_sha256",
        pinned_merge_authorization_sha256,
    )
    payload = {
        "schema": SCHEMA,
        "stage": "MERGE_HANDOFF_COMPATIBILITY",
        "status": STATUS,
        "outcome": OUTCOME,
        "r19_scope": "EXACT_REPOSITORY_REVISION",
        "r63_scope": "EXACT_PR_BRANCH_REVISION",
        "pr_identity_source": "R63_AUTHORIZATION",
        "r63_lifetime": "ONE_TIME_UNTIL_CONSUMED",
        "repository": eligibility["repository"],
        "base_branch": base_branch_value,
        "candidate_branch": candidate_branch_value,
        "pull_request_number": pr_number,
        "merge_method": method,
        "baseline_sha": eligibility["baseline_sha"],
        "baseline_tree_sha": baseline_tree_sha,
        "candidate_sha": eligibility["candidate_sha"],
        "candidate_tree_sha": eligibility["candidate_tree_sha"],
        "eligibility_receipt_id": eligibility["receipt_id"],
        "approval_id": eligibility["approval_id"],
        "approval_expires_at_unix": eligibility["expires_at_unix"],
        "merge_authorization_sha256": auth_pin,
        "merge_authorization_subject_sha256": subject_sha,
        "merge_authorization_nonce": authorization_nonce,
        "eligibility_receipt": _plain(eligibility),
        "merge_authorization_receipt": _plain(authorization),
        "effect": "VERIFY_ONLY_NO_MERGE",
        "merge_executed": False,
        "live_state_modified": False,
        "self_application": False,
        **_safe_authority(),
    }
    payload["receipt_id"] = "dmh_" + _sha256_json(payload)
    return payload


def require_dual_control_merge_handoff_current(
    handoff_receipt: Any,
    *,
    pinned_merge_authorization_sha256: str,
    trusted_key_registry: Any,
    pinned_registry_sha256: str,
    repository: str,
    current_base_sha: str,
    current_head_sha: str,
    current_tree_sha: str,
    now_unix: int,
    base_branch: str,
    candidate_branch: str,
    pull_request_number: int,
    merge_method: str = MERGE_METHOD,
) -> dict[str, Any]:
    receipt = _plain(handoff_receipt)
    if type(receipt) is not dict:
        raise ValueError("trusted merge handoff: receipt must be dict")
    receipt_id = receipt.get("receipt_id")
    if type(receipt_id) is not str or not receipt_id.startswith("dmh_"):
        raise ValueError("trusted merge handoff: invalid receipt id")
    unsigned = {key: value for key, value in receipt.items() if key != "receipt_id"}
    if receipt_id != "dmh_" + _sha256_json(unsigned):
        raise ValueError("trusted merge handoff: receipt integrity mismatch")
    if receipt.get("schema") != SCHEMA or receipt.get("status") != STATUS:
        raise ValueError("trusted merge handoff: receipt contract mismatch")
    if receipt.get("outcome") != OUTCOME or receipt.get("effect") != "VERIFY_ONLY_NO_MERGE":
        raise ValueError("trusted merge handoff: outcome/effect mismatch")
    expected_scope = {
        "r19_scope": "EXACT_REPOSITORY_REVISION",
        "r63_scope": "EXACT_PR_BRANCH_REVISION",
        "pr_identity_source": "R63_AUTHORIZATION",
        "r63_lifetime": "ONE_TIME_UNTIL_CONSUMED",
    }
    for key, expected in expected_scope.items():
        if receipt.get(key) != expected:
            raise ValueError(f"trusted merge handoff: scope contract mismatch for {key}")
    for key, expected in _SAFE_AUTHORITY_ITEMS:
        if receipt.get(key) != expected:
            raise ValueError(f"trusted merge handoff: unsafe authority field {key}")
    if receipt.get("merge_executed") is not False:
        raise ValueError("trusted merge handoff: receipt claims merge execution")
    if receipt.get("live_state_modified") is not False or receipt.get("self_application") is not False:
        raise ValueError("trusted merge handoff: receipt claims live mutation")

    rebuilt = build_dual_control_merge_handoff(
        eligibility_receipt=receipt.get("eligibility_receipt"),
        merge_authorization_receipt=receipt.get("merge_authorization_receipt"),
        pinned_merge_authorization_sha256=pinned_merge_authorization_sha256,
        trusted_key_registry=trusted_key_registry,
        pinned_registry_sha256=pinned_registry_sha256,
        repository=repository,
        current_base_sha=current_base_sha,
        current_head_sha=current_head_sha,
        current_tree_sha=current_tree_sha,
        now_unix=now_unix,
        base_branch=base_branch,
        candidate_branch=candidate_branch,
        pull_request_number=pull_request_number,
        merge_method=merge_method,
    )
    if rebuilt != receipt:
        raise ValueError("trusted merge handoff: current handoff reconstruction mismatch")
    return dict(receipt)


__all__ = [
    "SCHEMA",
    "STATUS",
    "OUTCOME",
    "MERGE_METHOD",
    "build_dual_control_merge_handoff",
    "require_dual_control_merge_handoff_current",
]
