"""Bind one immutable Work Ledger state to one exact candidate review."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from .evidence_common import (
    add_check,
    canonical_json_text,
    load_json,
    now_utc,
    require_dict,
    require_oid,
    require_repo,
    require_sha,
    require_str,
    sha256_file,
    validate_effects,
)
from .github_candidate_review import evaluate_github_candidate_review
from .work_ledger import PROJECT_PASS, VERIFY_PASS, project_work_ledger, verify_work_ledger

REQUEST_SCHEMA = "continuityos.work_ledger_review_binding.request/v1"
EVALUATION_SCHEMA = "continuityos.work_ledger_review_binding.evaluation/v1"
PASS = "WORK_LEDGER_REVIEW_BINDING_PASS"
HOLD = "WORK_LEDGER_REVIEW_BINDING_HOLD"
REVISE = "WORK_LEDGER_REVIEW_BINDING_REVISE"
PASS_OUTCOME = "CONTROL_PLANE_BINDING_PASS"

BINDING_KEYS = {
    "ledger_sha256",
    "projection_sha256",
    "admission_receipt_sha256",
    "delta_receipt_sha256",
    "ledger_transport_receipt_sha256",
    "ledger_semantic_decision_sha256",
    "review_request_sha256",
    "review_transport_receipt_sha256",
    "review_semantic_decision_sha256",
    "review_evaluation_sha256",
}


def _request(request: dict[str, Any]) -> dict[str, Any]:
    if request.get("schema") != REQUEST_SCHEMA:
        raise ValueError("binding request schema mismatch")
    if request.get("authority_generation") != "R63":
        raise ValueError("authority_generation must remain R63")
    candidate = require_dict(request.get("candidate"), "candidate")
    bindings = require_dict(request.get("bindings"), "bindings")
    if set(bindings) != BINDING_KEYS:
        raise ValueError("binding request fields mismatch")
    validate_effects(request.get("effects"), "effects")
    return {
        "task_id": require_str(request.get("task_id"), "task_id"),
        "repository": require_repo(candidate.get("repository"), "candidate.repository"),
        "branch": require_str(candidate.get("branch"), "candidate.branch"),
        "head": require_oid(candidate.get("head"), "candidate.head"),
        "tree": require_oid(candidate.get("tree"), "candidate.tree"),
        "bindings": {
            key: require_sha(bindings.get(key), f"bindings.{key}") for key in BINDING_KEYS
        },
    }


def _repo_name(identity: dict[str, Any]) -> str:
    repository = require_dict(identity.get("repository"), "projection repository")
    owner = require_str(repository.get("owner"), "projection repository.owner").lower()
    name = require_str(repository.get("name"), "projection repository.name").lower()
    return f"{owner}/{name}"


def _without_generated_at(value: dict[str, Any]) -> dict[str, Any]:
    return {key: item for key, item in value.items() if key != "generated_at_utc"}


def evaluate_work_ledger_review_binding(
    request_path: Path,
    ledger_path: Path,
    projection_path: Path,
    admission_receipt_path: Path,
    delta_receipt_path: Path,
    ledger_transport_receipt_path: Path,
    ledger_semantic_decision_path: Path,
    review_request_path: Path,
    review_transport_receipt_path: Path,
    review_semantic_decision_path: Path,
    review_evaluation_path: Path,
) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    reasons: list[str] = []
    holds: list[str] = []
    binding: dict[str, Any] = {}
    projection: dict[str, Any] = {}

    paths = {
        "ledger_sha256": Path(ledger_path),
        "projection_sha256": Path(projection_path),
        "admission_receipt_sha256": Path(admission_receipt_path),
        "delta_receipt_sha256": Path(delta_receipt_path),
        "ledger_transport_receipt_sha256": Path(ledger_transport_receipt_path),
        "ledger_semantic_decision_sha256": Path(ledger_semantic_decision_path),
        "review_request_sha256": Path(review_request_path),
        "review_transport_receipt_sha256": Path(review_transport_receipt_path),
        "review_semantic_decision_sha256": Path(review_semantic_decision_path),
        "review_evaluation_sha256": Path(review_evaluation_path),
    }

    try:
        request_path = Path(request_path)
        request = load_json(request_path, "binding request")
        binding = _request(request)
        missing = [key for key, path in paths.items() if not path.is_file()]
        if missing:
            holds.extend(f"missing required input: {key}" for key in missing)
            add_check(
                checks,
                "INPUT_PRESENCE",
                "MISSING",
                "One or more binding inputs are absent.",
                missing=missing,
            )
        else:
            for key, path in paths.items():
                if sha256_file(path) != binding["bindings"][key]:
                    raise ValueError(f"{key} mismatch")
            add_check(checks, "INPUT_SHA_BINDINGS", "PASS", "All binding inputs match exact hashes.")

            ledger_verify = verify_work_ledger(Path(ledger_path))
            if ledger_verify.get("status") != VERIFY_PASS:
                raise ValueError("work ledger verification did not pass")
            projected = project_work_ledger(Path(ledger_path))
            if projected.get("status") != PROJECT_PASS:
                raise ValueError("work ledger projection did not pass")
            expected_projection = projected["projection"]
            projection = load_json(Path(projection_path), "projection")
            if projection != expected_projection:
                raise ValueError("provided projection differs from exact ledger projection")
            if projected.get("ledger_sha256") != binding["bindings"]["ledger_sha256"]:
                raise ValueError("ledger projection SHA mismatch")
            add_check(checks, "LEDGER_CHAIN", "PASS", "Ledger hash chain and exact projection are valid.")

            identity = require_dict(projection.get("identity"), "projection identity")
            if identity.get("authority_generation") != "R63" or identity.get("task_id") != binding["task_id"]:
                raise ValueError("projection authority/task mismatch")
            if _repo_name(identity) != binding["repository"]:
                raise ValueError("projection repository mismatch")
            repository = require_dict(identity.get("repository"), "projection repository")
            if repository.get("candidate_branch") != binding["branch"]:
                raise ValueError("projection candidate branch mismatch")
            if projection.get("candidate_head") != binding["head"]:
                raise ValueError("projection candidate HEAD mismatch")
            if projection.get("candidate_tree") != binding["tree"]:
                raise ValueError("projection candidate tree mismatch")
            if projection.get("transport_receipt_sha256") != binding["bindings"]["ledger_transport_receipt_sha256"]:
                raise ValueError("projection ledger transport SHA mismatch")
            if projection.get("semantic_decision_sha256") != binding["bindings"]["ledger_semantic_decision_sha256"]:
                raise ValueError("projection semantic decision SHA mismatch")
            if projection.get("delta_receipt_sha256") != binding["bindings"]["delta_receipt_sha256"]:
                raise ValueError("projection delta receipt SHA mismatch")
            if identity.get("admission_receipt_sha256") != binding["bindings"]["admission_receipt_sha256"]:
                raise ValueError("projection admission receipt SHA mismatch")
            if projection.get("apply_status") != "NOT_APPLIED":
                raise ValueError("projection apply_status must remain NOT_APPLIED")
            add_check(
                checks,
                "PROJECTION_IDENTITY",
                "PASS",
                "Projection binds exact task/repository/candidate/receipt hashes.",
            )

            admission = load_json(Path(admission_receipt_path), "admission receipt")
            delta = load_json(Path(delta_receipt_path), "delta receipt")
            ledger_transport = load_json(Path(ledger_transport_receipt_path), "ledger transport receipt")
            ledger_semantic = load_json(Path(ledger_semantic_decision_path), "ledger semantic decision")
            if admission.get("status") != "WORK_ADMISSION_PASS":
                raise ValueError("admission receipt is not WORK_ADMISSION_PASS")
            if delta.get("status") != "WORK_DELTA_PASS":
                raise ValueError("delta receipt is not WORK_DELTA_PASS")
            if ledger_transport.get("terminal") != "WORK_TRANSPORT_PASS":
                raise ValueError("ledger transport terminal mismatch")
            if ledger_semantic.get("verdict") not in {"ACCEPT", "PASS_WITH_CONDITIONS", "HOLD"}:
                raise ValueError("ledger semantic verdict is invalid")
            if ledger_semantic.get("apply_status") != "NOT_APPLIED":
                raise ValueError("ledger semantic apply_status must remain NOT_APPLIED")
            if projection.get("semantic_verdict") == "HOLD":
                holds.append("immutable ledger semantic verdict is HOLD")
            elif projection.get("semantic_verdict") not in {"ACCEPT", "PASS_WITH_CONDITIONS"}:
                raise ValueError("immutable ledger semantic verdict is not positive")
            add_check(
                checks,
                "LEDGER_RECEIPTS",
                "WARN" if holds else "PASS",
                "Admission, delta, transport and semantic receipts are admissible.",
            )

            provided_review = load_json(Path(review_evaluation_path), "review evaluation")
            recomputed_review = evaluate_github_candidate_review(
                Path(review_request_path),
                Path(admission_receipt_path),
                Path(delta_receipt_path),
                Path(review_transport_receipt_path),
                Path(review_semantic_decision_path),
            )
            if _without_generated_at(provided_review) != _without_generated_at(recomputed_review):
                raise ValueError("provided candidate-review evaluation is not reproducible")
            review_status = provided_review.get("status")
            if review_status == "GITHUB_CANDIDATE_REVIEW_HOLD":
                holds.append("candidate review is HOLD")
            elif review_status != "GITHUB_CANDIDATE_REVIEW_PASS" or provided_review.get("outcome") != "MERGE_CANDIDATE_ELIGIBLE":
                raise ValueError("candidate review is not PASS/eligible")
            review_binding = require_dict(provided_review.get("binding"), "review binding")
            expected_review = {
                "task_id": binding["task_id"],
                "repository": binding["repository"],
                "candidate_branch": binding["branch"],
                "candidate_head": binding["head"],
                "candidate_tree": binding["tree"],
                "admission_receipt_sha256": binding["bindings"]["admission_receipt_sha256"],
                "delta_receipt_sha256": binding["bindings"]["delta_receipt_sha256"],
            }
            for key, expected in expected_review.items():
                if review_binding.get(key) != expected:
                    raise ValueError(f"candidate review {key} mismatch")
            semantic_summary = require_dict(provided_review.get("semantic_summary"), "semantic summary")
            if semantic_summary.get("semantic_decision_sha256") != binding["bindings"]["review_semantic_decision_sha256"]:
                raise ValueError("candidate review semantic SHA mismatch")
            add_check(
                checks,
                "REVIEW_BINDING",
                "WARN" if holds else "PASS",
                "Candidate review is reproducible and bound to the exact ledger candidate.",
            )

    except FileNotFoundError as exc:
        holds.append(str(exc))
        add_check(checks, "INPUT_PRESENCE", "MISSING", "Required binding evidence is absent.")
    except Exception as exc:
        reasons.append(f"{type(exc).__name__}: {exc}")
        add_check(checks, "INTERNAL_VALIDATION", "FAIL", "Ledger/review binding validation failed.")

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
        "ledger_head": {
            "ledger_sha256": binding.get("bindings", {}).get("ledger_sha256"),
            "latest_event_sha256": projection.get("latest_event_sha256"),
            "event_count": projection.get("event_count"),
            "semantic_verdict": projection.get("semantic_verdict"),
        },
        "checks": checks,
        "reasons": reasons,
        "holds": holds,
        "effect": "VERIFY_ONLY_NO_WRITE",
        "merge_executed": False,
        "live_state_modified": False,
        "writes_performed": [],
        "can_trade": False,
        "capital_permission": "DENY",
        "deploy_permission": "DENY",
        "self_application": False,
    }


def exit_code_for_work_ledger_review_binding(receipt: dict[str, Any]) -> int:
    if receipt.get("status") == PASS:
        return 0
    if receipt.get("status") == HOLD:
        return 3
    return 2
