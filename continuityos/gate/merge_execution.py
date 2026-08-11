"""Verify one externally executed GitHub merge against one exact authorization.

The gate is read-only. It never calls GitHub, mutates Git, merges, deploys,
updates R63/current state/registry, accesses wallets, executes orders, or trades.
It consumes immutable receipts produced by an external host/provider path and
fails closed on missing, stale, contradictory, widened, or reused evidence.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
import json
import re

from .evidence_common import (
    MAX_JSON_BYTES,
    add_check,
    canonical_json_text,
    now_utc,
    require_dict,
    require_list,
    require_oid,
    require_repo,
    require_sha,
    require_str,
    sha256_file,
    validate_effects,
)

REQUEST_SCHEMA = "continuityos.merge_execution.request/v1"
HOST_SCHEMA = "continuityos.merge_execution.host_receipt/v1"
PR_SCHEMA = "continuityos.merge_execution.pull_request_readback/v1"
COMMIT_SCHEMA = "continuityos.merge_execution.merge_commit_readback/v1"
BASE_SCHEMA = "continuityos.merge_execution.base_branch_readback/v1"
PROTECTION_SCHEMA = "continuityos.merge_execution.branch_protection_readback/v1"
CONSUMPTION_SCHEMA = "continuityos.merge_execution.authorization_consumption/v1"
EVALUATION_SCHEMA = "continuityos.merge_execution.evaluation/v1"

VERIFIED = "MERGE_EXECUTION_VERIFIED"
HOLD = "MERGE_EXECUTION_HOLD"
REVISE = "MERGE_EXECUTION_REVISE"
VERIFIED_OUTCOME = "MERGE_RESULT_PROVEN"
MERGE_METHOD = "MERGE_COMMIT"
NONCE_RE = re.compile(r"^[A-Za-z0-9_-]{16,128}$")


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _load_json_strict(path: Path, label: str) -> dict[str, Any]:
    path = Path(path)
    if path.is_symlink():
        raise ValueError(f"{label} path may not be a symlink")
    if not path.is_file():
        raise FileNotFoundError(f"{label} file is missing")
    if path.stat().st_size > MAX_JSON_BYTES:
        raise ValueError(f"{label} exceeds {MAX_JSON_BYTES} bytes")
    try:
        value = json.loads(
            path.read_text(encoding="utf-8-sig"),
            object_pairs_hook=_reject_duplicate_keys,
        )
    except FileNotFoundError:
        raise
    except Exception as exc:
        raise ValueError(
            f"{label} is not strict UTF-8 JSON: {type(exc).__name__}: {exc}"
        ) from exc
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    return value


def _time(value: Any, label: str) -> datetime:
    text = require_str(value, label)
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise ValueError(f"{label} is not RFC3339") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{label} must include timezone")
    return parsed.astimezone(timezone.utc)


def _assert_not_too_future(
    value: datetime,
    now_value: datetime,
    max_clock_skew_seconds: int,
    label: str,
) -> None:
    if value > now_value + timedelta(seconds=max_clock_skew_seconds):
        raise ValueError(f"{label} exceeds allowed future clock skew")


def _request(value: dict[str, Any]) -> dict[str, Any]:
    if value.get("schema") != REQUEST_SCHEMA:
        raise ValueError("merge execution request schema mismatch")
    if value.get("authority_generation") != "R63":
        raise ValueError("authority_generation must remain R63")

    subject = require_dict(value.get("subject"), "subject")
    base = require_dict(subject.get("base"), "subject.base")
    candidate = require_dict(subject.get("candidate"), "subject.candidate")
    authorization = require_dict(value.get("authorization"), "authorization")
    bindings = require_dict(value.get("bindings"), "bindings")
    policy = require_dict(value.get("policy"), "policy")

    expected_bindings = {
        "authorization_receipt_sha256",
        "host_execution_receipt_sha256",
        "pull_request_readback_sha256",
        "merge_commit_readback_sha256",
        "base_branch_readback_sha256",
        "branch_protection_readback_sha256",
        "authorization_consumption_sha256",
    }
    if set(bindings) != expected_bindings:
        raise ValueError("merge execution binding fields mismatch")

    pr_number = subject.get("pull_request_number")
    if not isinstance(pr_number, int) or isinstance(pr_number, bool) or pr_number <= 0:
        raise ValueError("pull_request_number must be a positive integer")

    visibility = require_str(subject.get("visibility_before"), "visibility_before")
    if visibility not in {"PRIVATE", "PUBLIC"}:
        raise ValueError("visibility_before must be PRIVATE or PUBLIC")

    required_checks = require_list(policy.get("required_checks"), "required_checks", 128)
    if not required_checks or not all(isinstance(item, str) and item for item in required_checks):
        raise ValueError("required_checks is invalid")
    if len(required_checks) != len(set(required_checks)):
        raise ValueError("required_checks contains duplicates")

    required_approvals = policy.get("required_approvals")
    if (
        not isinstance(required_approvals, int)
        or isinstance(required_approvals, bool)
        or required_approvals < 1
    ):
        raise ValueError("required_approvals must be >= 1")

    if policy.get("merge_method") != MERGE_METHOD:
        raise ValueError("only MERGE_COMMIT is supported in v1")
    if policy.get("preserve_branch_protection") is not True:
        raise ValueError("preserve_branch_protection must be true")
    if policy.get("preserve_visibility") is not True:
        raise ValueError("preserve_visibility must be true")

    max_skew = policy.get("max_clock_skew_seconds", 300)
    if not isinstance(max_skew, int) or isinstance(max_skew, bool) or not 0 <= max_skew <= 3600:
        raise ValueError("max_clock_skew_seconds must be in 0..3600")

    nonce = require_str(authorization.get("nonce"), "authorization.nonce")
    if not NONCE_RE.fullmatch(nonce):
        raise ValueError("authorization nonce is invalid")

    validate_effects(value.get("effects"), "request effects")

    return {
        "repository": require_repo(subject.get("repository"), "subject.repository"),
        "visibility_before": visibility,
        "base_branch": require_str(base.get("branch"), "base.branch"),
        "base_head_before": require_oid(base.get("head_before"), "base.head_before"),
        "base_tree_before": require_oid(base.get("tree_before"), "base.tree_before"),
        "candidate_branch": require_str(candidate.get("branch"), "candidate.branch"),
        "candidate_head": require_oid(candidate.get("head"), "candidate.head"),
        "candidate_tree": require_oid(candidate.get("tree"), "candidate.tree"),
        "pull_request_number": pr_number,
        "authorization_receipt_sha256": require_sha(
            authorization.get("receipt_sha256"), "authorization.receipt_sha256"
        ),
        "authorization_subject_sha256": require_sha(
            authorization.get("subject_sha256"), "authorization.subject_sha256"
        ),
        "authorization_nonce": nonce,
        "bindings": {
            key: require_sha(bindings.get(key), f"bindings.{key}")
            for key in expected_bindings
        },
        "required_checks": required_checks,
        "required_approvals": required_approvals,
        "max_clock_skew_seconds": max_skew,
        "merge_method": MERGE_METHOD,
    }


def _check_authorization(path: Path, binding: dict[str, Any]) -> dict[str, Any]:
    receipt = _load_json_strict(path, "merge authorization receipt")
    if receipt.get("status") == "MERGE_AUTHORIZATION_HOLD":
        raise FileNotFoundError("merge authorization remains HOLD")
    if (
        receipt.get("status") != "MERGE_AUTHORIZATION_PASS"
        or receipt.get("outcome") != "MERGE_EXECUTION_MAY_BE_REQUESTED_ONCE"
    ):
        raise ValueError("merge authorization is not PASS/eligible")
    if receipt.get("authorization_subject_sha256") != binding["authorization_subject_sha256"]:
        raise ValueError("authorization subject SHA mismatch")
    if receipt.get("authorization_nonce") != binding["authorization_nonce"]:
        raise ValueError("authorization nonce mismatch")
    if receipt.get("merge_executed") is not False:
        raise ValueError("authorization receipt already claims merge execution")
    if receipt.get("deployment") is not False:
        raise ValueError("authorization receipt widened deployment")

    authorization_binding = require_dict(receipt.get("binding"), "authorization binding")
    expected = {
        "repository": binding["repository"],
        "visibility": binding["visibility_before"],
        "base_branch": binding["base_branch"],
        "base_head": binding["base_head_before"],
        "base_tree": binding["base_tree_before"],
        "candidate_branch": binding["candidate_branch"],
        "candidate_head": binding["candidate_head"],
        "candidate_tree": binding["candidate_tree"],
        "pull_request_number": binding["pull_request_number"],
        "required_checks": binding["required_checks"],
        "required_approvals": binding["required_approvals"],
        "merge_method": binding["merge_method"],
    }
    for key, expected_value in expected.items():
        if authorization_binding.get(key) != expected_value:
            raise ValueError(f"authorization binding {key} mismatch")
    return {
        "status": receipt.get("status"),
        "outcome": receipt.get("outcome"),
        "subject_sha256": receipt.get("authorization_subject_sha256"),
        "nonce": receipt.get("authorization_nonce"),
    }


def _check_host_execution(
    path: Path,
    binding: dict[str, Any],
    now_value: datetime,
) -> dict[str, Any]:
    receipt = _load_json_strict(path, "host merge execution receipt")
    if receipt.get("schema") != HOST_SCHEMA:
        raise ValueError("host execution receipt schema mismatch")
    if receipt.get("provider") != "GITHUB":
        raise ValueError("host execution provider must be GITHUB")
    if receipt.get("repository") != binding["repository"]:
        raise ValueError("host execution repository mismatch")
    if receipt.get("pull_request_number") != binding["pull_request_number"]:
        raise ValueError("host execution PR mismatch")
    if receipt.get("authorization_receipt_sha256") != binding["authorization_receipt_sha256"]:
        raise ValueError("host execution authorization receipt SHA mismatch")
    if receipt.get("authorization_subject_sha256") != binding["authorization_subject_sha256"]:
        raise ValueError("host execution authorization subject SHA mismatch")
    if receipt.get("authorization_nonce") != binding["authorization_nonce"]:
        raise ValueError("host execution authorization nonce mismatch")
    if receipt.get("merge_method") != MERGE_METHOD:
        raise ValueError("host execution merge method mismatch")

    expected = {
        "base_branch": binding["base_branch"],
        "base_head_before": binding["base_head_before"],
        "base_tree_before": binding["base_tree_before"],
        "candidate_branch": binding["candidate_branch"],
        "candidate_head": binding["candidate_head"],
        "candidate_tree": binding["candidate_tree"],
        "visibility_before": binding["visibility_before"],
        "visibility_after": binding["visibility_before"],
    }
    for key, expected_value in expected.items():
        if receipt.get(key) != expected_value:
            raise ValueError(f"host execution {key} mismatch")

    merge_commit = require_dict(receipt.get("merge_commit"), "host execution merge_commit")
    merge_sha = require_oid(merge_commit.get("sha"), "merge_commit.sha")
    merge_tree = require_oid(merge_commit.get("tree"), "merge_commit.tree")
    parents = require_list(merge_commit.get("parents"), "merge_commit.parents", 2)
    if parents != [binding["base_head_before"], binding["candidate_head"]]:
        raise ValueError("merge commit parents must be [base_before, candidate_head]")

    executor = require_str(receipt.get("executor_actor_id"), "executor_actor_id")
    if receipt.get("force_push") is not False:
        raise ValueError("host execution used or claims force push")
    if receipt.get("auto_merge") is not False:
        raise ValueError("host execution used or claims auto-merge")

    executed_at = _time(receipt.get("executed_at_utc"), "executed_at_utc")
    _assert_not_too_future(
        executed_at,
        now_value,
        binding["max_clock_skew_seconds"],
        "executed_at_utc",
    )
    validate_effects(receipt.get("effects"), "host execution effects", merge=True)

    return {
        "merge_commit_sha": merge_sha,
        "merge_commit_tree": merge_tree,
        "parents": parents,
        "executor_actor_id": executor,
        "executed_at_utc": executed_at.isoformat(),
    }


def _check_pr_readback(
    path: Path,
    binding: dict[str, Any],
    execution: dict[str, Any],
    now_value: datetime,
) -> dict[str, Any]:
    receipt = _load_json_strict(path, "pull request merged readback")
    if receipt.get("schema") != PR_SCHEMA or receipt.get("provider") != "GITHUB":
        raise ValueError("PR readback schema/provider mismatch")
    if receipt.get("readback") is not True:
        raise FileNotFoundError("PR readback is not complete")
    if receipt.get("repository") != binding["repository"]:
        raise ValueError("PR readback repository mismatch")
    if receipt.get("number") != binding["pull_request_number"]:
        raise ValueError("PR readback number mismatch")
    if receipt.get("state") != "MERGED" or receipt.get("merged") is not True:
        raise FileNotFoundError("PR readback does not yet show MERGED")
    if receipt.get("merge_method") != MERGE_METHOD:
        raise ValueError("PR readback merge method mismatch")
    if receipt.get("auto_merge_used") is not False:
        raise ValueError("PR readback indicates auto-merge")

    expected = {
        "base_branch": binding["base_branch"],
        "base_head_before": binding["base_head_before"],
        "head_branch": binding["candidate_branch"],
        "head_sha": binding["candidate_head"],
        "head_tree": binding["candidate_tree"],
        "merge_commit_sha": execution["merge_commit_sha"],
        "merge_commit_tree": execution["merge_commit_tree"],
        "merged_by_actor_id": execution["executor_actor_id"],
    }
    for key, expected_value in expected.items():
        if receipt.get(key) != expected_value:
            raise ValueError(f"PR readback {key} mismatch")

    merged_at = _time(receipt.get("merged_at_utc"), "merged_at_utc")
    executed_at = _time(execution["executed_at_utc"], "executed_at_utc")
    if merged_at < executed_at:
        raise ValueError("PR merged_at predates host execution")
    _assert_not_too_future(
        merged_at,
        now_value,
        binding["max_clock_skew_seconds"],
        "merged_at_utc",
    )
    return {
        "state": "MERGED",
        "merged_by_actor_id": receipt.get("merged_by_actor_id"),
        "merged_at_utc": merged_at.isoformat(),
    }


def _check_merge_commit_readback(
    path: Path,
    binding: dict[str, Any],
    execution: dict[str, Any],
    now_value: datetime,
) -> dict[str, Any]:
    receipt = _load_json_strict(path, "merge commit readback")
    if receipt.get("schema") != COMMIT_SCHEMA or receipt.get("provider") != "GITHUB":
        raise ValueError("merge commit readback schema/provider mismatch")
    if receipt.get("readback") is not True or receipt.get("verified") is not True:
        raise FileNotFoundError("merge commit readback is not complete")
    if receipt.get("repository") != binding["repository"]:
        raise ValueError("merge commit readback repository mismatch")
    if receipt.get("sha") != execution["merge_commit_sha"]:
        raise ValueError("merge commit readback SHA mismatch")
    if receipt.get("tree") != execution["merge_commit_tree"]:
        raise ValueError("merge commit readback tree mismatch")
    if receipt.get("parents") != execution["parents"]:
        raise ValueError("merge commit readback parents mismatch")
    if receipt.get("parents") != [binding["base_head_before"], binding["candidate_head"]]:
        raise ValueError("merge commit readback parent order mismatch")
    read_at = _time(receipt.get("read_at_utc"), "merge_commit.read_at_utc")
    if read_at < _time(execution["executed_at_utc"], "executed_at_utc"):
        raise ValueError("merge commit readback predates execution")
    _assert_not_too_future(
        read_at,
        now_value,
        binding["max_clock_skew_seconds"],
        "merge_commit.read_at_utc",
    )
    return {
        "sha": receipt.get("sha"),
        "tree": receipt.get("tree"),
        "parents": receipt.get("parents"),
        "read_at_utc": read_at.isoformat(),
    }


def _check_base_readback(
    path: Path,
    binding: dict[str, Any],
    execution: dict[str, Any],
    now_value: datetime,
) -> dict[str, Any]:
    receipt = _load_json_strict(path, "base branch readback")
    if receipt.get("schema") != BASE_SCHEMA or receipt.get("provider") != "GITHUB":
        raise ValueError("base readback schema/provider mismatch")
    if receipt.get("readback") is not True:
        raise FileNotFoundError("base branch readback is not complete")
    if receipt.get("repository") != binding["repository"]:
        raise ValueError("base readback repository mismatch")
    if receipt.get("branch") != binding["base_branch"]:
        raise ValueError("base readback branch mismatch")
    if receipt.get("head") != execution["merge_commit_sha"]:
        raise ValueError("base branch does not point to exact merge commit")
    if receipt.get("tree") != execution["merge_commit_tree"]:
        raise ValueError("base branch tree differs from exact merge tree")
    if receipt.get("visibility") != binding["visibility_before"]:
        raise ValueError("repository visibility changed")
    read_at = _time(receipt.get("read_at_utc"), "base.read_at_utc")
    if read_at < _time(execution["executed_at_utc"], "executed_at_utc"):
        raise ValueError("base branch readback predates execution")
    _assert_not_too_future(
        read_at,
        now_value,
        binding["max_clock_skew_seconds"],
        "base.read_at_utc",
    )
    return {
        "head": receipt.get("head"),
        "tree": receipt.get("tree"),
        "visibility": receipt.get("visibility"),
        "read_at_utc": read_at.isoformat(),
    }


def _check_protection(
    path: Path,
    binding: dict[str, Any],
    execution: dict[str, Any],
    now_value: datetime,
) -> dict[str, Any]:
    receipt = _load_json_strict(path, "branch protection readback")
    if receipt.get("schema") != PROTECTION_SCHEMA or receipt.get("provider") != "GITHUB":
        raise ValueError("branch protection readback schema/provider mismatch")
    if receipt.get("readback") is not True:
        raise FileNotFoundError("branch protection readback is not complete")
    if receipt.get("repository") != binding["repository"]:
        raise ValueError("branch protection repository mismatch")
    if receipt.get("branch") != binding["base_branch"]:
        raise ValueError("branch protection branch mismatch")
    if receipt.get("base_head") != execution["merge_commit_sha"]:
        raise ValueError("branch protection readback is for wrong base HEAD")
    if receipt.get("force_push_allowed") is not False:
        raise ValueError("branch protection allows force push")
    if receipt.get("deletion_allowed") is not False:
        raise ValueError("branch protection allows branch deletion")
    if receipt.get("required_checks") != binding["required_checks"]:
        raise ValueError("required checks changed after merge")
    if receipt.get("required_approvals") != binding["required_approvals"]:
        raise ValueError("required approval threshold changed after merge")
    if receipt.get("visibility") != binding["visibility_before"]:
        raise ValueError("branch protection readback visibility changed")
    read_at = _time(receipt.get("read_at_utc"), "protection.read_at_utc")
    if read_at < _time(execution["executed_at_utc"], "executed_at_utc"):
        raise ValueError("branch protection readback predates execution")
    _assert_not_too_future(
        read_at,
        now_value,
        binding["max_clock_skew_seconds"],
        "protection.read_at_utc",
    )
    return {
        "required_checks": receipt.get("required_checks"),
        "required_approvals": receipt.get("required_approvals"),
        "force_push_allowed": False,
        "deletion_allowed": False,
        "read_at_utc": read_at.isoformat(),
    }


def _check_consumption(
    path: Path,
    binding: dict[str, Any],
    execution: dict[str, Any],
    now_value: datetime,
) -> dict[str, Any]:
    receipt = _load_json_strict(path, "authorization consumption record")
    if receipt.get("schema") != CONSUMPTION_SCHEMA:
        raise ValueError("authorization consumption schema mismatch")
    if receipt.get("store_readback") is not True:
        raise FileNotFoundError("authorization consumption store readback is incomplete")
    if receipt.get("authorization_receipt_sha256") != binding["authorization_receipt_sha256"]:
        raise ValueError("consumption authorization receipt SHA mismatch")
    if receipt.get("authorization_subject_sha256") != binding["authorization_subject_sha256"]:
        raise ValueError("consumption subject SHA mismatch")
    if receipt.get("authorization_nonce") != binding["authorization_nonce"]:
        raise ValueError("consumption nonce mismatch")
    if receipt.get("consumed") is not True:
        raise FileNotFoundError("authorization is not marked consumed")
    if receipt.get("use_count") != 1:
        raise ValueError("authorization use_count must be exactly 1")
    if receipt.get("reused") is not False:
        raise ValueError("authorization was reused")
    if receipt.get("merge_commit_sha") != execution["merge_commit_sha"]:
        raise ValueError("consumption merge commit mismatch")
    if receipt.get("executor_actor_id") != execution["executor_actor_id"]:
        raise ValueError("consumption executor mismatch")

    consumed_at = _time(receipt.get("consumed_at_utc"), "consumed_at_utc")
    if consumed_at < _time(execution["executed_at_utc"], "executed_at_utc"):
        raise ValueError("authorization consumption predates merge execution")
    _assert_not_too_future(
        consumed_at,
        now_value,
        binding["max_clock_skew_seconds"],
        "consumed_at_utc",
    )
    validate_effects(receipt.get("effects"), "consumption effects", merge=True)
    return {
        "consumed": True,
        "use_count": 1,
        "reused": False,
        "consumed_at_utc": consumed_at.isoformat(),
    }


def evaluate_merge_execution(
    request_path: Path,
    authorization_receipt_path: Path,
    host_execution_receipt_path: Path,
    pull_request_readback_path: Path,
    merge_commit_readback_path: Path,
    base_branch_readback_path: Path,
    branch_protection_readback_path: Path,
    authorization_consumption_path: Path,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    reasons: list[str] = []
    holds: list[str] = []
    binding: dict[str, Any] = {}
    observed: dict[str, Any] = {}
    now_value = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)

    paths = {
        "authorization_receipt_sha256": Path(authorization_receipt_path),
        "host_execution_receipt_sha256": Path(host_execution_receipt_path),
        "pull_request_readback_sha256": Path(pull_request_readback_path),
        "merge_commit_readback_sha256": Path(merge_commit_readback_path),
        "base_branch_readback_sha256": Path(base_branch_readback_path),
        "branch_protection_readback_sha256": Path(branch_protection_readback_path),
        "authorization_consumption_sha256": Path(authorization_consumption_path),
    }

    try:
        request = _load_json_strict(Path(request_path), "merge execution request")
        binding = _request(request)

        missing = [key for key, path in paths.items() if not path.is_file()]
        if missing:
            holds.extend(f"missing required input: {key}" for key in missing)
            add_check(
                checks,
                "INPUT_PRESENCE",
                "MISSING",
                "One or more merge execution inputs are absent.",
                missing=missing,
            )
        else:
            for key, path in paths.items():
                expected = binding["bindings"][key]
                actual = sha256_file(path)
                if actual != expected:
                    raise ValueError(f"{key} mismatch")
            if binding["bindings"]["authorization_receipt_sha256"] != binding["authorization_receipt_sha256"]:
                raise ValueError("request authorization SHA is internally inconsistent")
            add_check(
                checks,
                "INPUT_SHA_BINDINGS",
                "PASS",
                "All merge execution inputs match exact hashes.",
            )

            try:
                observed["authorization"] = _check_authorization(
                    Path(authorization_receipt_path), binding
                )
                add_check(
                    checks,
                    "AUTHORIZATION",
                    "PASS",
                    "Exact proposal-only merge authorization is valid.",
                )
            except FileNotFoundError as exc:
                holds.append(str(exc))
                add_check(checks, "AUTHORIZATION", "MISSING", str(exc))

            if not holds:
                observed["execution"] = _check_host_execution(
                    Path(host_execution_receipt_path), binding, now_value
                )
                add_check(
                    checks,
                    "HOST_EXECUTION",
                    "PASS",
                    "External host receipt proves one exact two-parent merge commit.",
                )

                provider_checks = (
                    (
                        "pull_request",
                        "PULL_REQUEST_READBACK",
                        _check_pr_readback,
                        Path(pull_request_readback_path),
                        "GitHub PR readback proves exact merged result.",
                    ),
                    (
                        "merge_commit",
                        "MERGE_COMMIT_READBACK",
                        _check_merge_commit_readback,
                        Path(merge_commit_readback_path),
                        "GitHub commit readback proves exact tree and ordered parents.",
                    ),
                    (
                        "base",
                        "BASE_BRANCH_READBACK",
                        _check_base_readback,
                        Path(base_branch_readback_path),
                        "Base branch points to exact merge commit/tree.",
                    ),
                    (
                        "protection",
                        "BRANCH_PROTECTION",
                        _check_protection,
                        Path(branch_protection_readback_path),
                        "Required branch protection remains unchanged.",
                    ),
                    (
                        "consumption",
                        "AUTHORIZATION_CONSUMPTION",
                        _check_consumption,
                        Path(authorization_consumption_path),
                        "Authorization was consumed exactly once and not reused.",
                    ),
                )
                for observed_key, check_id, checker, path, detail in provider_checks:
                    try:
                        observed[observed_key] = checker(
                            path, binding, observed["execution"], now_value
                        )
                        add_check(checks, check_id, "PASS", detail)
                    except FileNotFoundError as exc:
                        holds.append(str(exc))
                        add_check(checks, check_id, "MISSING", str(exc))

    except FileNotFoundError as exc:
        holds.append(str(exc))
        add_check(
            checks,
            "INPUT_PRESENCE",
            "MISSING",
            "Required merge execution evidence is absent.",
        )
    except Exception as exc:
        reasons.append(f"{type(exc).__name__}: {exc}")
        add_check(
            checks,
            "INTERNAL_VALIDATION",
            "FAIL",
            "Merge execution verification failed closed.",
        )

    if reasons:
        status, outcome = REVISE, "WOULD_HOLD"
    elif holds:
        status, outcome = HOLD, "WOULD_HOLD"
    else:
        status, outcome = VERIFIED, VERIFIED_OUTCOME

    public_binding = {key: value for key, value in binding.items() if key != "bindings"}
    return {
        "schema": EVALUATION_SCHEMA,
        "generated_at_utc": now_utc(),
        "status": status,
        "outcome": outcome,
        "binding": public_binding,
        "observed": observed,
        "checks": checks,
        "reasons": reasons,
        "holds": holds,
        "effect": "VERIFY_ONLY_EXTERNAL_MERGE_OBSERVED",
        "gate_merge_executed": False,
        "external_merge_verified": status == VERIFIED,
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


def exit_code_for_merge_execution(receipt: dict[str, Any]) -> int:
    if receipt.get("status") == VERIFIED:
        return 0
    if receipt.get("status") == HOLD:
        return 3
    return 2


__all__ = [
    "BASE_SCHEMA",
    "COMMIT_SCHEMA",
    "CONSUMPTION_SCHEMA",
    "EVALUATION_SCHEMA",
    "HOLD",
    "HOST_SCHEMA",
    "MERGE_METHOD",
    "PR_SCHEMA",
    "PROTECTION_SCHEMA",
    "REQUEST_SCHEMA",
    "REVISE",
    "VERIFIED",
    "VERIFIED_OUTCOME",
    "canonical_json_text",
    "evaluate_merge_execution",
    "exit_code_for_merge_execution",
]
