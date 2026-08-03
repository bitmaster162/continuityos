"""Proposal-only, one-time merge authorization gate.

A PASS permits only a separate external merge request.  This module has no Git
push, pull-request merge, deployment, state apply, wallet, order or trading
path.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any
import hashlib
import re

from .evidence_common import (
    add_check,
    canonical_json_text,
    load_json,
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

REQUEST_SCHEMA = "continuityos.merge_authorization.request/v1"
PROTECTION_SCHEMA = "continuityos.merge_authorization.branch_protection_receipt/v1"
PR_SCHEMA = "continuityos.merge_authorization.pull_request_receipt/v1"
HUMAN_SCHEMA = "continuityos.merge_authorization.human_decision/v1"
ROLLBACK_SCHEMA = "continuityos.merge_authorization.rollback_receipt/v1"
EVALUATION_SCHEMA = "continuityos.merge_authorization.evaluation/v1"

PASS = "MERGE_AUTHORIZATION_PASS"
HOLD = "MERGE_AUTHORIZATION_HOLD"
REVISE = "MERGE_AUTHORIZATION_REVISE"
PASS_OUTCOME = "MERGE_EXECUTION_MAY_BE_REQUESTED_ONCE"
NONCE_RE = re.compile(r"^[A-Za-z0-9_-]{16,128}$")


def sha256_json(value: Any) -> str:
    return hashlib.sha256(canonical_json_text(value).encode("utf-8")).hexdigest()


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


def _request(request: dict[str, Any]) -> dict[str, Any]:
    if request.get("schema") != REQUEST_SCHEMA:
        raise ValueError("merge authorization request schema mismatch")
    if request.get("authority_generation") != "R63":
        raise ValueError("authority_generation must remain R63")
    repository = require_dict(request.get("repository"), "repository")
    base = require_dict(repository.get("base"), "repository.base")
    candidate = require_dict(repository.get("candidate"), "repository.candidate")
    pr_number = repository.get("pull_request_number")
    if not isinstance(pr_number, int) or isinstance(pr_number, bool) or pr_number <= 0:
        raise ValueError("pull_request_number must be positive integer")
    bindings = require_dict(request.get("bindings"), "bindings")
    expected = {
        "ledger_review_binding_sha256",
        "candidate_review_sha256",
        "branch_protection_sha256",
        "pull_request_sha256",
        "human_decision_sha256",
        "rollback_receipt_sha256",
    }
    if set(bindings) != expected:
        raise ValueError("bindings fields mismatch")
    policy = require_dict(request.get("policy"), "policy")
    checks = require_list(policy.get("required_checks"), "required_checks", 128)
    if not checks or not all(isinstance(item, str) and item for item in checks):
        raise ValueError("required_checks is invalid")
    if len(checks) != len(set(checks)):
        raise ValueError("required_checks contains duplicates")
    approvals = policy.get("required_approvals")
    if not isinstance(approvals, int) or isinstance(approvals, bool) or approvals < 1:
        raise ValueError("required_approvals must be >=1")
    max_age = policy.get("max_decision_age_seconds", 3600)
    if not isinstance(max_age, int) or isinstance(max_age, bool) or not 60 <= max_age <= 86400:
        raise ValueError("max_decision_age_seconds is invalid")
    if policy.get("reviewer_separation_required") is not True:
        raise ValueError("reviewer_separation_required must be true")
    if policy.get("merge_method") != "MERGE_COMMIT":
        raise ValueError("only MERGE_COMMIT is supported")
    validate_effects(request.get("effects"), "effects")
    return {
        "repository": require_repo(repository.get("name_with_owner"), "repository.name_with_owner"),
        "visibility": require_str(repository.get("visibility"), "repository.visibility"),
        "base_branch": require_str(base.get("branch"), "base.branch"),
        "base_head": require_oid(base.get("head"), "base.head"),
        "base_tree": require_oid(base.get("tree"), "base.tree"),
        "candidate_branch": require_str(candidate.get("branch"), "candidate.branch"),
        "candidate_head": require_oid(candidate.get("head"), "candidate.head"),
        "candidate_tree": require_oid(candidate.get("tree"), "candidate.tree"),
        "pull_request_number": pr_number,
        "required_checks": checks,
        "required_approvals": approvals,
        "max_decision_age_seconds": max_age,
        "merge_method": policy.get("merge_method"),
        "bindings": {
            key: require_sha(bindings.get(key), f"bindings.{key}") for key in expected
        },
    }


def authorization_subject(binding: dict[str, Any], hashes: dict[str, str]) -> dict[str, Any]:
    return {
        "repository": binding["repository"],
        "visibility": binding["visibility"],
        "base_branch": binding["base_branch"],
        "base_head": binding["base_head"],
        "base_tree": binding["base_tree"],
        "candidate_branch": binding["candidate_branch"],
        "candidate_head": binding["candidate_head"],
        "candidate_tree": binding["candidate_tree"],
        "pull_request_number": binding["pull_request_number"],
        "merge_method": binding["merge_method"],
        "ledger_review_binding_sha256": hashes["ledger_review_binding_sha256"],
        "candidate_review_sha256": hashes["candidate_review_sha256"],
        "branch_protection_sha256": hashes["branch_protection_sha256"],
        "pull_request_sha256": hashes["pull_request_sha256"],
        "rollback_receipt_sha256": hashes["rollback_receipt_sha256"],
    }


def evaluate_merge_authorization(
    request_path: Path,
    ledger_review_binding_path: Path,
    candidate_review_path: Path,
    branch_protection_path: Path,
    pull_request_path: Path,
    human_decision_path: Path,
    rollback_receipt_path: Path,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    reasons: list[str] = []
    holds: list[str] = []
    binding: dict[str, Any] = {}
    subject_sha: str | None = None
    nonce: str | None = None
    now_value = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)

    paths = {
        "ledger_review_binding_sha256": Path(ledger_review_binding_path),
        "candidate_review_sha256": Path(candidate_review_path),
        "branch_protection_sha256": Path(branch_protection_path),
        "pull_request_sha256": Path(pull_request_path),
        "human_decision_sha256": Path(human_decision_path),
        "rollback_receipt_sha256": Path(rollback_receipt_path),
    }

    try:
        request = load_json(Path(request_path), "merge authorization request")
        binding = _request(request)
        for key, path in paths.items():
            if not path.is_file():
                holds.append(f"missing required input: {key}")
            elif sha256_file(path) != binding["bindings"][key]:
                raise ValueError(f"{key} mismatch")
        if holds:
            add_check(checks, "INPUT_PRESENCE", "MISSING", "Authorization inputs are incomplete.")
        else:
            add_check(checks, "INPUT_SHA_BINDINGS", "PASS", "All authorization inputs match exact hashes.")

            ledger = load_json(Path(ledger_review_binding_path), "ledger/review binding")
            if ledger.get("status") == "WORK_LEDGER_REVIEW_BINDING_HOLD":
                holds.append("ledger/review binding is HOLD")
            elif ledger.get("status") != "WORK_LEDGER_REVIEW_BINDING_PASS" or ledger.get("outcome") != "CONTROL_PLANE_BINDING_PASS":
                raise ValueError("ledger/review binding is not PASS")
            ledger_binding = require_dict(ledger.get("binding"), "ledger binding")
            for key, expected in {
                "repository": binding["repository"],
                "branch": binding["candidate_branch"],
                "head": binding["candidate_head"],
                "tree": binding["candidate_tree"],
            }.items():
                if ledger_binding.get(key) != expected:
                    raise ValueError(f"ledger binding {key} mismatch")
            add_check(checks, "LEDGER_REVIEW_BINDING", "WARN" if holds else "PASS", "Ledger/review continuity evaluated.")

            review = load_json(Path(candidate_review_path), "candidate review")
            if review.get("status") == "GITHUB_CANDIDATE_REVIEW_HOLD":
                holds.append("candidate review is HOLD")
            elif review.get("status") != "GITHUB_CANDIDATE_REVIEW_PASS" or review.get("outcome") != "MERGE_CANDIDATE_ELIGIBLE":
                raise ValueError("candidate review is not PASS/eligible")
            review_binding = require_dict(review.get("binding"), "review binding")
            for key, expected in {
                "repository": binding["repository"],
                "visibility": binding["visibility"],
                "base_branch": binding["base_branch"],
                "base_head": binding["base_head"],
                "base_tree": binding["base_tree"],
                "candidate_branch": binding["candidate_branch"],
                "candidate_head": binding["candidate_head"],
                "candidate_tree": binding["candidate_tree"],
            }.items():
                if review_binding.get(key) != expected:
                    raise ValueError(f"candidate review {key} mismatch")
            if review.get("merge_executed") is not False or review.get("human_irreversible_approval") is not False:
                raise ValueError("candidate review widened merge/human authority")
            add_check(checks, "CANDIDATE_REVIEW", "WARN" if holds else "PASS", "Candidate review evaluated.")

            protection = load_json(Path(branch_protection_path), "branch protection")
            if protection.get("schema") != PROTECTION_SCHEMA or protection.get("provider") != "GITHUB" or protection.get("readback") is not True:
                raise ValueError("branch protection schema/provider/readback mismatch")
            if protection.get("repository") != binding["repository"] or protection.get("branch") != binding["base_branch"]:
                raise ValueError("branch protection subject mismatch")
            if protection.get("visibility") != binding["visibility"]:
                raise ValueError("branch protection visibility mismatch")
            if protection.get("base_head") != binding["base_head"] or protection.get("base_tree") != binding["base_tree"]:
                holds.append("base branch drifted after review")
            if protection.get("force_push_allowed") is not False or protection.get("deletion_allowed") is not False:
                raise ValueError("branch protection allows force push or deletion")
            if protection.get("required_checks") != binding["required_checks"]:
                raise ValueError("required checks differ from policy")
            if protection.get("required_approvals") != binding["required_approvals"]:
                raise ValueError("required approvals differ from policy")
            add_check(checks, "BRANCH_PROTECTION", "WARN" if holds else "PASS", "Branch protection evaluated.")

            pr = load_json(Path(pull_request_path), "pull request")
            if pr.get("schema") != PR_SCHEMA or pr.get("provider") != "GITHUB":
                raise ValueError("pull request schema/provider mismatch")
            if pr.get("repository") != binding["repository"] or pr.get("number") != binding["pull_request_number"]:
                raise ValueError("pull request identity mismatch")
            if pr.get("state") != "OPEN" or pr.get("draft") is not False or pr.get("merged") is not False:
                holds.append("pull request is not open/non-draft/unmerged")
            if pr.get("auto_merge_enabled") is not False:
                raise ValueError("auto-merge is enabled")
            if pr.get("merge_method") != binding["merge_method"]:
                raise ValueError("pull request merge method mismatch")
            expected_pr = {
                "base_branch": binding["base_branch"],
                "base_head": binding["base_head"],
                "base_tree": binding["base_tree"],
                "head_branch": binding["candidate_branch"],
                "head_sha": binding["candidate_head"],
                "head_tree": binding["candidate_tree"],
            }
            for key, expected in expected_pr.items():
                if pr.get(key) != expected:
                    raise ValueError(f"pull request {key} mismatch")
            if pr.get("mergeable") is not True:
                holds.append("pull request is not mergeable")
            author = require_str(pr.get("author_actor_id"), "PR author")
            check_rows = require_list(pr.get("checks"), "PR checks", 128)
            check_map = {row.get("name"): row for row in check_rows if isinstance(row, dict)}
            for name in binding["required_checks"]:
                row = check_map.get(name)
                if not row:
                    holds.append(f"missing required check: {name}")
                elif row.get("head_sha") != binding["candidate_head"]:
                    raise ValueError(f"required check {name} is for wrong HEAD")
                elif row.get("status") != "completed":
                    holds.append(f"required check pending: {name}")
                elif row.get("conclusion") != "success":
                    raise ValueError(f"required check failed: {name}")
            approval_rows = require_list(pr.get("approvals"), "PR approvals", 64)
            valid_approvers = {
                row.get("actor_id")
                for row in approval_rows
                if isinstance(row, dict)
                and row.get("state") == "APPROVED"
                and row.get("head_sha") == binding["candidate_head"]
                and isinstance(row.get("actor_id"), str)
                and row.get("actor_id") != author
            }
            if len(valid_approvers) < binding["required_approvals"]:
                holds.append("independent approval threshold is not met")
            add_check(checks, "PULL_REQUEST", "WARN" if holds else "PASS", "Exact PR/checks/approvals evaluated.")

            rollback = load_json(Path(rollback_receipt_path), "rollback receipt")
            if rollback.get("schema") != ROLLBACK_SCHEMA:
                raise ValueError("rollback receipt schema mismatch")
            if rollback.get("strategy") != "REVERT_MERGE_COMMIT" or rollback.get("tested") is not True or rollback.get("validation_status") != "PASS":
                holds.append("tested non-destructive rollback is not proven")
            if rollback.get("destructive_reset") is not False:
                raise ValueError("rollback uses destructive reset")
            if rollback.get("repository") != binding["repository"] or rollback.get("base_head") != binding["base_head"] or rollback.get("candidate_head") != binding["candidate_head"]:
                raise ValueError("rollback subject mismatch")
            validate_effects(rollback.get("effects"), "rollback effects")
            add_check(checks, "ROLLBACK", "WARN" if holds else "PASS", "Rollback evidence evaluated.")

            hashes_without_human = {
                key: binding["bindings"][key]
                for key in (
                    "ledger_review_binding_sha256",
                    "candidate_review_sha256",
                    "branch_protection_sha256",
                    "pull_request_sha256",
                    "rollback_receipt_sha256",
                )
            }
            subject = authorization_subject(binding, hashes_without_human)
            subject_sha = sha256_json(subject)
            human = load_json(Path(human_decision_path), "human decision")
            if human.get("schema") != HUMAN_SCHEMA or human.get("actor_id") != "ROBERT" or human.get("role") != "SOVEREIGN":
                raise ValueError("human decision identity mismatch")
            if human.get("decision") != "APPROVE_MERGE_CANDIDATE":
                holds.append("Robert did not approve this merge candidate")
            if human.get("authorization_subject_sha256") != subject_sha:
                raise ValueError("human decision subject SHA mismatch")
            nonce = require_str(human.get("nonce"), "human nonce")
            if not NONCE_RE.fullmatch(nonce):
                raise ValueError("human nonce is invalid")
            issued = _time(human.get("issued_at_utc"), "issued_at_utc")
            expires = _time(human.get("expires_at_utc"), "expires_at_utc")
            if expires <= issued:
                raise ValueError("human decision expiry is invalid")
            if now_value < issued:
                holds.append("human decision is not yet active")
            if now_value > expires:
                holds.append("human decision expired")
            if (now_value - issued).total_seconds() > binding["max_decision_age_seconds"]:
                holds.append("human decision is older than allowed")
            if human.get("consumed") is not False or human.get("self_application") is not False:
                raise ValueError("human decision is already consumed or self-applying")
            validate_effects(human.get("effects"), "human decision effects")
            add_check(
                checks,
                "HUMAN_DECISION",
                "WARN" if holds else "PASS",
                "Exact bounded Robert decision evaluated.",
                subject_sha256=subject_sha,
            )

    except FileNotFoundError as exc:
        holds.append(str(exc))
        add_check(checks, "INPUT_PRESENCE", "MISSING", "Required authorization evidence is absent.")
    except Exception as exc:
        reasons.append(f"{type(exc).__name__}: {exc}")
        add_check(checks, "INTERNAL_VALIDATION", "FAIL", "Merge authorization validation failed.")

    if reasons:
        status, outcome = REVISE, "WOULD_HOLD"
    elif holds:
        status, outcome = HOLD, "WOULD_HOLD"
    else:
        status, outcome = PASS, PASS_OUTCOME

    return {
        "schema": EVALUATION_SCHEMA,
        "generated_at_utc": now_utc(),
        "status": status,
        "outcome": outcome,
        "binding": {key: value for key, value in binding.items() if key != "bindings"},
        "authorization_subject_sha256": subject_sha,
        "authorization_nonce": nonce,
        "checks": checks,
        "reasons": reasons,
        "holds": holds,
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


def exit_code_for_merge_authorization(receipt: dict[str, Any]) -> int:
    if receipt.get("status") == PASS:
        return 0
    if receipt.get("status") == HOLD:
        return 3
    return 2
