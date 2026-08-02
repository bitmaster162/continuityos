"""Proposal-only GitHub candidate review gate.

This gate closes the gap between a locally verified work delta and any later
merge decision.  It binds the exact admission receipt, exact delta receipt,
exact GitHub transport/CI readback, and exact semantic review decision.

The evaluator is effect-free.  It cannot push, create or merge a pull request,
change branch protection, deploy, apply R63/current state/registry, access a
wallet, place an order, or trade.  A PASS means only that the candidate is
eligible for a separate human-controlled merge decision.
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REQUEST_SCHEMA = "continuityos.github_candidate_review.request/v1"
TRANSPORT_SCHEMA = "continuityos.github_candidate_review.transport_receipt/v1"
SEMANTIC_SCHEMA = "continuityos.github_candidate_review.semantic_decision/v1"
EVALUATION_SCHEMA = "continuityos.github_candidate_review.evaluation/v1"

REVIEW_PASS = "GITHUB_CANDIDATE_REVIEW_PASS"
REVIEW_HOLD = "GITHUB_CANDIDATE_REVIEW_HOLD"
REVIEW_REVISE = "GITHUB_CANDIDATE_REVIEW_REVISE"

MERGE_ELIGIBLE = "MERGE_CANDIDATE_ELIGIBLE"
WOULD_HOLD = "WOULD_HOLD"

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
GIT_OID_RE = re.compile(r"^[0-9a-f]{40}$")
TASK_ID_RE = re.compile(r"^[A-Z0-9][A-Z0-9_.:-]{2,127}$")
BRANCH_RE = re.compile(
    r"^(?:gpt|agent|codex|spark|claude|fable|work|controller|candidate)/[A-Za-z0-9._/-]+$"
)
MAX_JSON_BYTES = 4 * 1024 * 1024
MAX_WORKFLOWS = 64
MAX_FINDINGS = 512
MAX_CONDITIONS = 256

SEMANTIC_VERDICTS = {
    "APPROVE_CANDIDATE",
    "APPROVE_WITH_CONDITIONS",
    "HOLD",
    "REVISE",
    "REJECT",
}
FINDING_SEVERITIES = {"P0", "P1", "P2", "P3"}
FINDING_STATUSES = {"OPEN", "RESOLVED", "ACCEPTED_RISK", "NOT_APPLICABLE"}
PUSH_EFFECTS = {"PUSHED_NEW_BRANCH", "FAST_FORWARD_EXACT", "NO_OP_BRANCH_ALREADY_EXACT"}
REVIEW_MODES = {"CONTROLLER_REVIEW", "INDEPENDENT_REVIEW"}

FORBIDDEN_EFFECT_FIELDS = (
    "force_push",
    "merge",
    "pull_request_merge",
    "auto_merge",
    "deployment",
    "registry_apply",
    "current_state_apply",
    "r63_apply",
    "trading",
    "wallet_access",
    "order_execution",
    "self_application",
)


def canonical_json_text(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _check(
    checks: list[dict[str, Any]],
    check_id: str,
    status: str,
    detail: str,
    **evidence: Any,
) -> None:
    row: dict[str, Any] = {"id": check_id, "status": status, "detail": detail}
    if evidence:
        row["evidence"] = evidence
    checks.append(row)


def _load_json(path: Path, label: str) -> dict[str, Any]:
    if not path.is_file():
        raise ValueError(f"{label} file is missing")
    if path.stat().st_size > MAX_JSON_BYTES:
        raise ValueError(f"{label} exceeds {MAX_JSON_BYTES} bytes")
    try:
        value = json.loads(path.read_text(encoding="utf-8-sig"))
    except Exception as exc:
        raise ValueError(f"{label} is not valid UTF-8 JSON: {type(exc).__name__}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    return value


def _require_dict(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    return value


def _require_list(value: Any, label: str, *, maximum: int) -> list[Any]:
    if not isinstance(value, list) or len(value) > maximum:
        raise ValueError(f"{label} must be a list with at most {maximum} entries")
    return value


def _require_str(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} must be a non-empty string")
    return value


def _require_bool(value: Any, label: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{label} must be boolean")
    return value


def _require_sha(value: Any, label: str) -> str:
    text = _require_str(value, label)
    if not SHA256_RE.fullmatch(text):
        raise ValueError(f"{label} must be a lowercase SHA-256")
    return text


def _require_oid(value: Any, label: str) -> str:
    text = _require_str(value, label)
    if not GIT_OID_RE.fullmatch(text):
        raise ValueError(f"{label} must be a lowercase 40-hex Git object ID")
    return text


def _require_candidate_branch(value: Any, label: str) -> str:
    text = _require_str(value, label)
    if not BRANCH_RE.fullmatch(text):
        raise ValueError(f"{label} is not an admitted candidate branch")
    if text.endswith("/") or "//" in text or ".." in text:
        raise ValueError(f"{label} is malformed")
    return text


def _require_base_branch(value: Any, label: str) -> str:
    text = _require_str(value, label)
    if not re.fullmatch(r"[A-Za-z0-9._/-]{1,200}", text):
        raise ValueError(f"{label} is not a safe Git branch")
    if text.startswith(("/", ".")) or text.endswith(("/", ".")) or "//" in text or ".." in text:
        raise ValueError(f"{label} is malformed")
    return text


def _github_repo(owner: Any, name: Any) -> str:
    owner_text = _require_str(owner, "repository.owner")
    name_text = _require_str(name, "repository.name")
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", owner_text):
        raise ValueError("repository.owner is invalid")
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", name_text):
        raise ValueError("repository.name is invalid")
    return f"{owner_text.lower()}/{name_text.lower()}"


def _canonical_github_remote(value: Any) -> str:
    text = _require_str(value, "repository.remote_url").strip()
    patterns = (
        r"^https://github\.com/([^/]+)/([^/]+?)(?:\.git)?/?$",
        r"^git@github\.com:([^/]+)/([^/]+?)(?:\.git)?$",
        r"^ssh://git@github\.com/([^/]+)/([^/]+?)(?:\.git)?/?$",
    )
    for pattern in patterns:
        match = re.match(pattern, text, re.IGNORECASE)
        if match:
            return f"{match.group(1).lower()}/{match.group(2).lower()}"
    raise ValueError("repository.remote_url must be a canonical github.com URL")


def _request_binding(request: dict[str, Any]) -> dict[str, Any]:
    if request.get("schema") != REQUEST_SCHEMA:
        raise ValueError("request schema mismatch")
    if request.get("authority_generation") != "R63":
        raise ValueError("authority_generation must remain R63")

    task = _require_dict(request.get("task"), "task")
    task_id = _require_str(task.get("task_id"), "task.task_id")
    if not TASK_ID_RE.fullmatch(task_id):
        raise ValueError("task.task_id is invalid")

    repository = _require_dict(request.get("repository"), "repository")
    repo_name = _github_repo(repository.get("owner"), repository.get("name"))
    remote_repo = _canonical_github_remote(repository.get("remote_url"))
    if remote_repo != repo_name:
        raise ValueError("repository.remote_url does not match owner/name")
    visibility = _require_str(repository.get("visibility"), "repository.visibility")
    if visibility not in {"PRIVATE", "PUBLIC"}:
        raise ValueError("repository.visibility must be PRIVATE or PUBLIC")
    base_branch = _require_base_branch(repository.get("base_branch"), "repository.base_branch")
    candidate_branch = _require_candidate_branch(
        repository.get("candidate_branch"), "repository.candidate_branch"
    )
    if base_branch == candidate_branch:
        raise ValueError("candidate branch must differ from base branch")
    base_head = _require_oid(repository.get("base_head"), "repository.base_head")
    base_tree = _require_oid(repository.get("base_tree"), "repository.base_tree")
    candidate_head = _require_oid(repository.get("candidate_head"), "repository.candidate_head")
    candidate_tree = _require_oid(repository.get("candidate_tree"), "repository.candidate_tree")

    bindings = _require_dict(request.get("bindings"), "bindings")
    binding = {
        "task_id": task_id,
        "task_body_sha256": _require_sha(task.get("task_body_sha256"), "task.task_body_sha256"),
        "session_capsule_sha256": _require_sha(
            bindings.get("session_capsule_sha256"), "bindings.session_capsule_sha256"
        ),
        "admission_receipt_sha256": _require_sha(
            bindings.get("admission_receipt_sha256"), "bindings.admission_receipt_sha256"
        ),
        "delta_receipt_sha256": _require_sha(
            bindings.get("delta_receipt_sha256"), "bindings.delta_receipt_sha256"
        ),
        "repository": repo_name,
        "remote_url": _require_str(repository.get("remote_url"), "repository.remote_url"),
        "visibility": visibility,
        "base_branch": base_branch,
        "base_head": base_head,
        "base_tree": base_tree,
        "candidate_branch": candidate_branch,
        "candidate_head": candidate_head,
        "candidate_tree": candidate_tree,
    }

    ci = _require_dict(request.get("ci_policy"), "ci_policy")
    required_workflows = _require_list(
        ci.get("required_workflows"), "ci_policy.required_workflows", maximum=MAX_WORKFLOWS
    )
    if not required_workflows:
        raise ValueError("ci_policy.required_workflows must not be empty")
    if not all(isinstance(item, str) and 1 <= len(item) <= 128 for item in required_workflows):
        raise ValueError("ci_policy.required_workflows contains invalid names")
    if len(set(required_workflows)) != len(required_workflows):
        raise ValueError("ci_policy.required_workflows contains duplicates")
    if ci.get("required_conclusion") != "success":
        raise ValueError("ci_policy.required_conclusion must be success")
    if ci.get("required_status") != "completed":
        raise ValueError("ci_policy.required_status must be completed")

    review = _require_dict(request.get("review_policy"), "review_policy")
    mode = _require_str(review.get("mode"), "review_policy.mode")
    if mode not in REVIEW_MODES:
        raise ValueError("review_policy.mode is invalid")
    required_role = _require_str(review.get("required_reviewer_role"), "review_policy.required_reviewer_role")
    separation_required = _require_bool(
        review.get("separation_required"), "review_policy.separation_required"
    )
    executor_actor_id = _require_str(
        review.get("executor_actor_id"), "review_policy.executor_actor_id"
    )

    pr = _require_dict(request.get("pull_request_policy"), "pull_request_policy")
    pr_allowed = _require_bool(pr.get("allowed"), "pull_request_policy.allowed")
    pr_required = _require_bool(pr.get("required"), "pull_request_policy.required")
    if pr_required and not pr_allowed:
        raise ValueError("pull_request_policy.required implies allowed")
    draft_required = _require_bool(pr.get("draft_required"), "pull_request_policy.draft_required")

    effects = _require_dict(request.get("effects"), "effects")
    if effects.get("candidate_push") is not True:
        raise ValueError("effects.candidate_push must be true for post-transport review")
    if effects.get("pull_request_create") is not pr_allowed:
        raise ValueError("effects.pull_request_create must match pull_request_policy.allowed")
    for field in FORBIDDEN_EFFECT_FIELDS:
        if effects.get(field) is not False:
            raise ValueError(f"effects.{field} must be false")
    if effects.get("can_trade") is not False:
        raise ValueError("effects.can_trade must be false")
    if effects.get("capital_permission") != "DENY":
        raise ValueError("effects.capital_permission must be DENY")
    if effects.get("deploy_permission") != "DENY":
        raise ValueError("effects.deploy_permission must be DENY")

    binding["required_workflows"] = required_workflows
    binding["review_mode"] = mode
    binding["required_reviewer_role"] = required_role
    binding["separation_required"] = separation_required
    binding["executor_actor_id"] = executor_actor_id
    binding["pull_request_allowed"] = pr_allowed
    binding["pull_request_required"] = pr_required
    binding["draft_required"] = draft_required
    binding["base_drift_policy"] = "HOLD_ON_DRIFT"
    return binding


def _validate_admission(
    admission: dict[str, Any], expected_sha: str, binding: dict[str, Any], reasons: list[str]
) -> None:
    if admission.get("schema") != "continuityos.work_admission.receipt/v1":
        reasons.append("admission receipt schema mismatch")
    if admission.get("status") != "WORK_ADMISSION_PASS":
        reasons.append("admission receipt is not WORK_ADMISSION_PASS")
    if admission.get("outcome") != "WOULD_ALLOW":
        reasons.append("admission receipt outcome is not WOULD_ALLOW")
    if admission.get("live_state_modified") is not False:
        reasons.append("admission receipt modified live state")
    if admission.get("can_trade") is not False or admission.get("capital_permission") != "DENY":
        reasons.append("admission receipt widens trading/capital permissions")
    if admission.get("deploy_permission") != "DENY":
        reasons.append("admission receipt deploy_permission is not DENY")
    if admission.get("self_application") is not False:
        reasons.append("admission receipt self_application is not false")
    if expected_sha != binding["admission_receipt_sha256"]:
        reasons.append("request admission receipt SHA binding mismatch")

    receipt_binding = admission.get("binding")
    if not isinstance(receipt_binding, dict):
        reasons.append("admission receipt binding is missing")
        return
    observed_binding_sha = admission.get("admission_binding_sha256")
    actual_binding_sha = hashlib.sha256(
        canonical_json_text(receipt_binding).encode("utf-8")
    ).hexdigest()
    if observed_binding_sha != actual_binding_sha:
        reasons.append("admission receipt internal binding SHA mismatch")
    else:
        binding["admission_binding_sha256"] = actual_binding_sha

    if receipt_binding.get("task_id") != binding["task_id"]:
        reasons.append("admission receipt binding mismatch: task_id")
    if receipt_binding.get("work_order_sha256") != binding["task_body_sha256"]:
        reasons.append("admission receipt binding mismatch: work_order_sha256")
    if receipt_binding.get("session_capsule_sha256") != binding["session_capsule_sha256"]:
        reasons.append("admission receipt binding mismatch: session_capsule_sha256")
    if receipt_binding.get("authority_generation") != "R63":
        reasons.append("admission receipt authority_generation is not R63")

    repo = receipt_binding.get("repository")
    if not isinstance(repo, dict):
        reasons.append("admission receipt repository binding is missing")
    else:
        expected_repo = {
            "owner": binding["repository"].split("/", 1)[0],
            "name": binding["repository"].split("/", 1)[1],
            "base_branch": binding["base_branch"],
            "base_head": binding["base_head"],
            "base_tree": binding["base_tree"],
            "candidate_branch": binding["candidate_branch"],
        }
        for key, expected in expected_repo.items():
            observed = repo.get(key)
            if isinstance(observed, str) and key in {"owner", "name"}:
                observed = observed.lower()
            if observed != expected:
                reasons.append(f"admission receipt repository binding mismatch: {key}")

    original_request = admission.get("request")
    if not isinstance(original_request, dict):
        reasons.append("admission receipt original request is missing")
    else:
        if original_request.get("authority_generation") != "R63":
            reasons.append("admission original request authority_generation is not R63")
        task = original_request.get("task")
        if not isinstance(task, dict) or task.get("task_body_sha256") != binding["task_body_sha256"]:
            reasons.append("admission original request task body mismatch")


def _validate_delta(
    delta: dict[str, Any], expected_sha: str, binding: dict[str, Any], reasons: list[str]
) -> None:
    if delta.get("schema") != "continuityos.work_admission.delta_receipt/v1":
        reasons.append("delta receipt schema mismatch")
    if delta.get("status") != "WORK_DELTA_PASS":
        reasons.append("delta receipt is not WORK_DELTA_PASS")
    if delta.get("outcome") != "WOULD_ALLOW_CANDIDATE_TRANSPORT":
        reasons.append("delta receipt outcome does not allow candidate transport")
    if delta.get("task_id") != binding["task_id"]:
        reasons.append("delta receipt task_id mismatch")
    if delta.get("admission_receipt_sha256") != binding["admission_receipt_sha256"]:
        reasons.append("delta receipt is not bound to exact admission receipt")
    if binding.get("admission_binding_sha256") and delta.get("admission_binding_sha256") != binding["admission_binding_sha256"]:
        reasons.append("delta receipt admission binding SHA mismatch")
    if expected_sha != binding["delta_receipt_sha256"]:
        reasons.append("request delta receipt SHA binding mismatch")

    observed = delta.get("repository_observed")
    if not isinstance(observed, dict):
        reasons.append("delta receipt repository_observed is missing")
    else:
        if observed.get("branch") != binding["candidate_branch"]:
            reasons.append("delta receipt candidate branch mismatch")
        if observed.get("head") != binding["candidate_head"]:
            reasons.append("delta receipt candidate HEAD mismatch")
        if observed.get("tree") != binding["candidate_tree"]:
            reasons.append("delta receipt candidate tree mismatch")
        if observed.get("worktree_clean") is not True:
            reasons.append("delta receipt candidate worktree is not clean")

    if delta.get("live_state_modified") is not False:
        reasons.append("delta receipt modified live state")
    if delta.get("can_trade") is not False or delta.get("capital_permission") != "DENY":
        reasons.append("delta receipt widens trading/capital permissions")
    if delta.get("deploy_permission") != "DENY":
        reasons.append("delta receipt deploy_permission is not DENY")
    if delta.get("self_application") is not False:
        reasons.append("delta receipt self_application is not false")


def _validate_transport(
    transport: dict[str, Any], binding: dict[str, Any], reasons: list[str], holds: list[str]
) -> dict[str, Any]:
    if transport.get("schema") != TRANSPORT_SCHEMA:
        reasons.append("transport receipt schema mismatch")
    if transport.get("provider") != "GITHUB":
        reasons.append("transport provider must be GITHUB")
    if transport.get("authenticated_actor", "").lower() != binding["repository"].split("/", 1)[0]:
        reasons.append("transport authenticated actor does not match repository owner")
    try:
        if _canonical_github_remote(transport.get("remote_url")) != binding["repository"]:
            reasons.append("transport remote_url mismatch")
    except Exception as exc:
        reasons.append(f"transport remote_url invalid: {exc}")
    if transport.get("remote_readback") is not True:
        reasons.append("transport remote_readback must be true")
    if transport.get("actions_readback") is not True:
        reasons.append("transport actions_readback must be true")
    if transport.get("repository") != binding["repository"]:
        reasons.append("transport repository mismatch")
    if transport.get("visibility") != binding["visibility"]:
        reasons.append("transport visibility mismatch")
    if transport.get("visibility_changed") is not False:
        reasons.append("transport changed repository visibility")
    if transport.get("base_branch") != binding["base_branch"]:
        reasons.append("transport base branch mismatch")
    if transport.get("candidate_branch") != binding["candidate_branch"]:
        reasons.append("transport candidate branch mismatch")
    if transport.get("local_candidate_head") != binding["candidate_head"]:
        reasons.append("transport local candidate HEAD mismatch")
    if transport.get("local_candidate_tree") != binding["candidate_tree"]:
        reasons.append("transport local candidate tree mismatch")
    if transport.get("remote_candidate_head") != binding["candidate_head"]:
        reasons.append("transport remote candidate HEAD mismatch")
    if transport.get("remote_candidate_tree") != binding["candidate_tree"]:
        reasons.append("transport remote candidate tree mismatch")

    remote_base_head = transport.get("remote_base_head")
    remote_base_tree = transport.get("remote_base_tree")
    if remote_base_head != binding["base_head"] or remote_base_tree != binding["base_tree"]:
        holds.append("remote base drifted after admission; create a new admission from the new base")

    if transport.get("push_effect") not in PUSH_EFFECTS:
        reasons.append("transport push_effect is invalid")
    for field in FORBIDDEN_EFFECT_FIELDS:
        if transport.get(field) is not False:
            reasons.append(f"transport forbidden effect: {field}")
    if transport.get("pull_request_create") not in {False, True}:
        reasons.append("transport pull_request_create must be boolean")
    if transport.get("can_trade") is not False:
        reasons.append("transport can_trade must be false")
    if transport.get("capital_permission") != "DENY":
        reasons.append("transport capital_permission must be DENY")
    if transport.get("deploy_permission") != "DENY":
        reasons.append("transport deploy_permission must be DENY")

    secret = transport.get("secret_scan")
    if not isinstance(secret, dict):
        reasons.append("transport secret_scan receipt is missing")
    else:
        if secret.get("status") != "PASS":
            reasons.append("secret scan did not PASS")
        if secret.get("candidate_head") != binding["candidate_head"]:
            reasons.append("secret scan is not bound to exact candidate HEAD")
        if secret.get("findings") != 0 and secret.get("findings") != []:
            reasons.append("secret scan reports findings")
        if secret.get("raw_evidence_leak") is not False:
            reasons.append("secret scan reports raw-evidence leakage")

    runs = transport.get("workflow_runs")
    by_name: dict[str, dict[str, Any]] = {}
    if not isinstance(runs, list) or len(runs) > MAX_WORKFLOWS:
        reasons.append("transport workflow_runs is missing or oversized")
        runs = []
    for index, raw in enumerate(runs):
        if not isinstance(raw, dict):
            reasons.append(f"workflow_runs[{index}] must be an object")
            continue
        name = raw.get("workflow_name")
        if not isinstance(name, str) or not name:
            reasons.append(f"workflow_runs[{index}] workflow_name is invalid")
            continue
        if name in by_name:
            reasons.append(f"duplicate selected workflow receipt: {name}")
            continue
        by_name[name] = raw

    workflow_summary: list[dict[str, Any]] = []
    for name in binding["required_workflows"]:
        row = by_name.get(name)
        if row is None:
            holds.append(f"required workflow receipt missing: {name}")
            workflow_summary.append({"workflow_name": name, "status": "MISSING"})
            continue
        if row.get("head_sha") != binding["candidate_head"]:
            reasons.append(f"{name}: workflow run HEAD mismatch")
        if row.get("status") != "completed":
            holds.append(f"{name}: workflow run is not completed")
        elif row.get("conclusion") != "success":
            reasons.append(f"{name}: workflow conclusion is not success")
        if not isinstance(row.get("run_id"), (str, int)):
            reasons.append(f"{name}: workflow run_id is missing")
        workflow_summary.append(
            {
                "workflow_name": name,
                "head_sha": row.get("head_sha"),
                "status": row.get("status"),
                "conclusion": row.get("conclusion"),
                "run_id": row.get("run_id"),
            }
        )

    pr = transport.get("pull_request")
    pr_created = transport.get("pull_request_create") is True
    if pr_created and not binding["pull_request_allowed"]:
        reasons.append("pull request was created although policy denied it")
    if binding["pull_request_required"] and not pr_created:
        holds.append("required pull request is not present")
    if pr_created:
        if not isinstance(pr, dict):
            reasons.append("pull_request receipt is missing")
        else:
            if pr.get("base_branch") != binding["base_branch"]:
                reasons.append("pull request base branch mismatch")
            if pr.get("head_branch") != binding["candidate_branch"]:
                reasons.append("pull request head branch mismatch")
            if pr.get("head_sha") != binding["candidate_head"]:
                reasons.append("pull request HEAD mismatch")
            if pr.get("state") != "OPEN":
                reasons.append("pull request state must remain OPEN")
            if pr.get("merged") is not False:
                reasons.append("pull request is already merged")
            if pr.get("auto_merge_enabled") is not False:
                reasons.append("pull request auto-merge must be disabled")
            if binding["draft_required"] and pr.get("draft") is not True:
                reasons.append("pull request must remain draft")
    elif pr is not None and pr != {}:
        reasons.append("pull_request object is present without pull_request_create")

    return {"workflow_summary": workflow_summary, "pull_request": pr}


def _validate_semantic(
    decision: dict[str, Any],
    decision_sha: str,
    request_sha: str,
    admission_sha: str,
    delta_sha: str,
    transport_sha: str,
    binding: dict[str, Any],
    reasons: list[str],
    holds: list[str],
) -> dict[str, Any]:
    if decision.get("schema") != SEMANTIC_SCHEMA:
        reasons.append("semantic decision schema mismatch")
    expected_bindings = {
        "request_sha256": request_sha,
        "admission_receipt_sha256": admission_sha,
        "delta_receipt_sha256": delta_sha,
        "transport_receipt_sha256": transport_sha,
        "candidate_head": binding["candidate_head"],
        "candidate_tree": binding["candidate_tree"],
    }
    for key, expected in expected_bindings.items():
        if decision.get(key) != expected:
            reasons.append(f"semantic decision binding mismatch: {key}")

    reviewer = decision.get("reviewer")
    reviewer_actor_id = None
    if not isinstance(reviewer, dict):
        reasons.append("semantic reviewer is missing")
    else:
        if reviewer.get("role") != binding["required_reviewer_role"]:
            reasons.append("semantic reviewer role mismatch")
        reviewer_actor_id = reviewer.get("actor_id")
        if not isinstance(reviewer_actor_id, str) or not reviewer_actor_id:
            reasons.append("semantic reviewer actor_id is missing")
    if binding["separation_required"] and reviewer_actor_id == binding["executor_actor_id"]:
        reasons.append("reviewer separation policy was violated")

    if decision.get("review_mode") != binding["review_mode"]:
        reasons.append("semantic review mode mismatch")
    verdict = decision.get("verdict")
    if verdict not in SEMANTIC_VERDICTS:
        reasons.append("semantic verdict is invalid")
        verdict = "REVISE"

    conditions = decision.get("conditions")
    if not isinstance(conditions, list) or len(conditions) > MAX_CONDITIONS:
        reasons.append("semantic conditions must be a bounded list")
        conditions = []
    elif not all(isinstance(item, str) and item for item in conditions):
        reasons.append("semantic conditions contain invalid entries")
    if verdict == "APPROVE_WITH_CONDITIONS" and not conditions:
        reasons.append("APPROVE_WITH_CONDITIONS requires at least one condition")
    if verdict == "APPROVE_CANDIDATE" and conditions:
        reasons.append("APPROVE_CANDIDATE must not carry unresolved conditions")

    findings = decision.get("findings")
    if not isinstance(findings, list) or len(findings) > MAX_FINDINGS:
        reasons.append("semantic findings must be a bounded list")
        findings = []
    finding_summary: list[dict[str, Any]] = []
    for index, raw in enumerate(findings):
        if not isinstance(raw, dict):
            reasons.append(f"findings[{index}] must be an object")
            continue
        finding_id = raw.get("id")
        severity = raw.get("severity")
        status = raw.get("status")
        if not isinstance(finding_id, str) or not finding_id:
            reasons.append(f"findings[{index}] id is invalid")
        if severity not in FINDING_SEVERITIES:
            reasons.append(f"findings[{index}] severity is invalid")
        if status not in FINDING_STATUSES:
            reasons.append(f"findings[{index}] status is invalid")
        if severity in {"P0", "P1"} and status == "OPEN":
            reasons.append(f"unresolved {severity} finding: {finding_id}")
        finding_summary.append({"id": finding_id, "severity": severity, "status": status})

    if decision.get("human_irreversible_approval") is not False:
        reasons.append("semantic decision cannot record human irreversible approval")
    if decision.get("merge_authorized") is not False:
        reasons.append("semantic decision merge_authorized must be false")
    if decision.get("self_application") is not False:
        reasons.append("semantic decision self_application must be false")

    effects = decision.get("effects")
    if not isinstance(effects, dict):
        reasons.append("semantic decision effects receipt is missing")
    else:
        for field in FORBIDDEN_EFFECT_FIELDS:
            if effects.get(field) is not False:
                reasons.append(f"semantic decision forbidden effect: {field}")
        if effects.get("can_trade") is not False:
            reasons.append("semantic decision can_trade must be false")
        if effects.get("capital_permission") != "DENY":
            reasons.append("semantic decision capital_permission must be DENY")
        if effects.get("deploy_permission") != "DENY":
            reasons.append("semantic decision deploy_permission must be DENY")

    if verdict == "HOLD":
        holds.append("semantic reviewer returned HOLD")
    elif verdict in {"REVISE", "REJECT"}:
        reasons.append(f"semantic reviewer returned {verdict}")

    return {
        "semantic_decision_sha256": decision_sha,
        "verdict": verdict,
        "conditions": conditions,
        "findings": finding_summary,
        "reviewer_actor_id": reviewer_actor_id,
    }


def evaluate_github_candidate_review(
    request_path: Path,
    admission_receipt_path: Path,
    delta_receipt_path: Path,
    transport_receipt_path: Path,
    semantic_decision_path: Path,
) -> dict[str, Any]:
    request_path = Path(request_path)
    admission_receipt_path = Path(admission_receipt_path)
    delta_receipt_path = Path(delta_receipt_path)
    transport_receipt_path = Path(transport_receipt_path)
    semantic_decision_path = Path(semantic_decision_path)

    checks: list[dict[str, Any]] = []
    reasons: list[str] = []
    holds: list[str] = []
    binding: dict[str, Any] = {}
    transport_summary: dict[str, Any] = {}
    semantic_summary: dict[str, Any] = {}

    try:
        request = _load_json(request_path, "review request")
        admission = _load_json(admission_receipt_path, "admission receipt")
        delta = _load_json(delta_receipt_path, "delta receipt")
        transport = _load_json(transport_receipt_path, "transport receipt")
        decision = _load_json(semantic_decision_path, "semantic decision")
        request_sha = sha256_file(request_path)
        admission_sha = sha256_file(admission_receipt_path)
        delta_sha = sha256_file(delta_receipt_path)
        transport_sha = sha256_file(transport_receipt_path)
        decision_sha = sha256_file(semantic_decision_path)
        _check(checks, "INPUTS", "PASS", "All five bounded JSON inputs loaded.")

        binding = _request_binding(request)
        _check(checks, "REQUEST_BINDING", "PASS", "Request schema and immutable binding are valid.")

        _validate_admission(admission, admission_sha, binding, reasons)
        _check(
            checks,
            "ADMISSION_RECEIPT",
            "PASS" if not reasons else "FAIL",
            "Admission receipt evaluated.",
            sha256=admission_sha,
        )

        before_delta = len(reasons)
        _validate_delta(delta, delta_sha, binding, reasons)
        _check(
            checks,
            "DELTA_RECEIPT",
            "PASS" if len(reasons) == before_delta else "FAIL",
            "Delta receipt evaluated.",
            sha256=delta_sha,
        )

        before_transport_reasons = len(reasons)
        before_transport_holds = len(holds)
        transport_summary = _validate_transport(transport, binding, reasons, holds)
        transport_status = (
            "FAIL"
            if len(reasons) > before_transport_reasons
            else "WARN"
            if len(holds) > before_transport_holds
            else "PASS"
        )
        _check(
            checks,
            "TRANSPORT_AND_CI",
            transport_status,
            "Remote branch, CI, secret boundary and optional PR evaluated.",
            sha256=transport_sha,
        )

        before_semantic_reasons = len(reasons)
        before_semantic_holds = len(holds)
        semantic_summary = _validate_semantic(
            decision,
            decision_sha,
            request_sha,
            admission_sha,
            delta_sha,
            transport_sha,
            binding,
            reasons,
            holds,
        )
        semantic_status = (
            "FAIL"
            if len(reasons) > before_semantic_reasons
            else "WARN"
            if len(holds) > before_semantic_holds
            else "PASS"
        )
        _check(
            checks,
            "SEMANTIC_REVIEW",
            semantic_status,
            "Exact semantic review decision evaluated.",
            sha256=decision_sha,
        )

    except Exception as exc:
        reasons.append(f"{type(exc).__name__}: {exc}")
        _check(checks, "INTERNAL_VALIDATION", "FAIL", "Candidate review validation failed.")

    if reasons:
        status = REVIEW_REVISE
        outcome = WOULD_HOLD
    elif holds:
        status = REVIEW_HOLD
        outcome = WOULD_HOLD
    else:
        status = REVIEW_PASS
        outcome = MERGE_ELIGIBLE

    return {
        "schema": EVALUATION_SCHEMA,
        "generated_at_utc": _now(),
        "status": status,
        "outcome": outcome,
        "binding": binding,
        "checks": checks,
        "reasons": reasons,
        "holds": holds,
        "transport_summary": transport_summary,
        "semantic_summary": semantic_summary,
        "effect": "VERIFY_ONLY_NO_WRITE",
        "merge_executed": False,
        "pull_request_merge": False,
        "deployment": False,
        "registry_apply": False,
        "current_state_apply": False,
        "r63_apply": False,
        "human_irreversible_approval": False,
        "live_state_modified": False,
        "writes_performed": [],
        "can_trade": False,
        "capital_permission": "DENY",
        "deploy_permission": "DENY",
        "self_application": False,
    }


def exit_code_for_github_candidate_review(receipt: dict[str, Any]) -> int:
    status = receipt.get("status")
    if status == REVIEW_PASS:
        return 0
    if status == REVIEW_HOLD:
        return 3
    return 2
