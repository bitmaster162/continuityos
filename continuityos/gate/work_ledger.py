"""Content-addressed, append-only work lifecycle ledger for GitHub-bound work.

The R11.1 work-admission gate proves that one run started from the right task,
session capsule, Git baseline, scope and effect ceiling.  This module preserves
what happens *after* admission as an immutable hash chain:

    admission -> delta -> transport -> GPT semantic review -> terminal close

Every extension writes a new ledger file and leaves the input ledger untouched.
The module has no Git push, merge, deployment, registry/current-state/R63 apply,
wallet, order or trading path.
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

EVENT_SCHEMA = "continuityos.work_ledger.event/v1"
OPERATION_SCHEMA = "continuityos.work_ledger.operation_receipt/v1"
PROJECTION_SCHEMA = "continuityos.work_ledger.projection/v1"
TRANSPORT_SCHEMA = "continuityos.work_transport.receipt/v1"
SEMANTIC_SCHEMA = "continuityos.work_semantic_decision/v1"

ADMISSION_RECEIPT_SCHEMA = "continuityos.work_admission.receipt/v1"
DELTA_RECEIPT_SCHEMA = "continuityos.work_admission.delta_receipt/v1"

VERIFY_PASS = "WORK_LEDGER_VERIFY_PASS"
INIT_PASS = "WORK_LEDGER_INIT_PASS"
EXTEND_PASS = "WORK_LEDGER_EXTEND_PASS"
FINALIZE_PASS = "WORK_LEDGER_FINALIZE_PASS"
PROJECT_PASS = "WORK_LEDGER_PROJECT_PASS"
LEDGER_HOLD = "WORK_LEDGER_HOLD"
LEDGER_REVISE = "WORK_LEDGER_REVISE"

EVENT_ADMISSION = "ADMISSION_VERIFIED"
EVENT_DELTA = "DELTA_VERIFIED"
EVENT_TRANSPORT = "TRANSPORT_VERIFIED"
EVENT_SEMANTIC = "SEMANTIC_REVIEWED"
EVENT_CLOSED = "WORK_CLOSED"
EVENT_REJECTED = "WORK_REJECTED"

STATE_ADMITTED = "ADMITTED"
STATE_DELTA = "DELTA_VERIFIED"
STATE_TRANSPORT = "TRANSPORT_VERIFIED"
STATE_ACCEPTED = "SEMANTIC_ACCEPTED"
STATE_HELD = "HELD"
STATE_REJECTABLE = "SEMANTIC_REJECTED"
STATE_CLOSED = "CLOSED"
STATE_REJECTED = "REJECTED"

SEMANTIC_VERDICTS = {
    "ACCEPT",
    "PASS_WITH_CONDITIONS",
    "HOLD",
    "REVISE",
    "REJECT",
}
TERMINAL_STATES = {STATE_CLOSED, STATE_REJECTED}

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
GIT_OID_RE = re.compile(r"^[0-9a-f]{40}$")
TASK_ID_RE = re.compile(r"^[A-Z0-9][A-Z0-9_.:-]{2,127}$")
LEDGER_ID_RE = re.compile(r"^wl-[0-9a-f]{32}$")
SAFE_ID_RE = re.compile(r"^[A-Za-z0-9_.:@/-]{1,128}$")

MAX_JSON_BYTES = 4 * 1024 * 1024
MAX_LEDGER_BYTES = 16 * 1024 * 1024
MAX_EVENT_BYTES = 512 * 1024
MAX_EVENTS = 1000
MAX_CONDITIONS = 100
MAX_CONDITION_BYTES = 4096

EVENT_KEYS = {
    "schema",
    "ledger_id",
    "sequence",
    "event_type",
    "recorded_at_utc",
    "actor",
    "prev_event_sha256",
    "payload",
    "effects",
    "event_sha256",
}
TRANSPORT_RECEIPT_KEYS = {
    "schema", "authority_generation", "task_id", "admission_binding_sha256",
    "delta_receipt_sha256", "repository", "candidate", "remote", "actions",
    "executor", "terminal", "effects",
}
SEMANTIC_DECISION_KEYS = {
    "schema", "authority_generation", "task_id", "admission_binding_sha256",
    "delta_receipt_sha256", "transport_receipt_sha256", "candidate", "reviewer",
    "verdict", "conditions", "content_status", "apply_status", "effects",
}

DANGEROUS_EFFECTS = (
    "force_push",
    "merge",
    "pull_request_merge",
    "deployment",
    "registry_apply",
    "current_state_apply",
    "r63_apply",
    "trading",
    "wallet_access",
    "order_execution",
    "external_message",
    "self_application",
)
NO_EFFECT_KEYS = set(DANGEROUS_EFFECTS) | {
    "can_trade", "capital_permission", "deploy_permission"
}


def canonical_json_text(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_time(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} must be a non-empty RFC3339 string")
    text = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise ValueError(f"{label} is not valid RFC3339/ISO-8601") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{label} must include a timezone")
    return parsed.astimezone(timezone.utc)


def _load_json(path: Path, label: str, *, maximum: int = MAX_JSON_BYTES) -> dict[str, Any]:
    if path.is_symlink():
        raise ValueError(f"{label} path may not be a symlink")
    if not path.is_file():
        raise ValueError(f"{label} file is missing")
    if path.stat().st_size > maximum:
        raise ValueError(f"{label} exceeds {maximum} bytes")
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


def _require_str(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} must be a non-empty string")
    return value


def _require_sha(value: Any, label: str) -> str:
    text = _require_str(value, label).lower()
    if not SHA256_RE.fullmatch(text):
        raise ValueError(f"{label} must be 64 lowercase hex")
    return text


def _require_oid(value: Any, label: str) -> str:
    text = _require_str(value, label).lower()
    if not GIT_OID_RE.fullmatch(text):
        raise ValueError(f"{label} must be a 40-character Git object ID")
    return text


def _require_bool(value: Any, label: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{label} must be boolean")
    return value


def _require_exact_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    observed = set(value)
    if observed != expected:
        missing = sorted(expected - observed)
        extra = sorted(observed - expected)
        raise ValueError(f"{label} fields mismatch: missing={missing}, extra={extra}")


def _fixed_effects() -> dict[str, Any]:
    return {
        "force_push": False,
        "merge": False,
        "pull_request_merge": False,
        "deployment": False,
        "registry_apply": False,
        "current_state_apply": False,
        "r63_apply": False,
        "trading": False,
        "wallet_access": False,
        "order_execution": False,
        "external_message": False,
        "self_application": False,
        "can_trade": False,
        "capital_permission": "DENY",
        "deploy_permission": "DENY",
    }


def _validate_no_effect(
    value: Any,
    label: str,
    *,
    exact_keys: set[str] | None = None,
) -> dict[str, Any]:
    effects = _require_dict(value, label)
    if exact_keys is not None:
        _require_exact_keys(effects, exact_keys, label)
    for key in DANGEROUS_EFFECTS:
        if _require_bool(effects.get(key), f"{label}.{key}") is not False:
            raise ValueError(f"{label}.{key} must be false")
    if effects.get("can_trade") is not False:
        raise ValueError(f"{label}.can_trade must be false")
    if effects.get("capital_permission") != "DENY":
        raise ValueError(f"{label}.capital_permission must be DENY")
    if effects.get("deploy_permission") != "DENY":
        raise ValueError(f"{label}.deploy_permission must be DENY")
    return _fixed_effects()


def _safe_actor(role: str, actor_id: str) -> dict[str, str]:
    if role not in {"CONTINUITY_GATE", "HOST_EXECUTOR", "GPT_CONTROLLER"}:
        raise ValueError(f"actor role {role!r} is not admitted")
    if not SAFE_ID_RE.fullmatch(actor_id):
        raise ValueError("actor.id has invalid syntax")
    return {"role": role, "id": actor_id}


def _event_digest(event: dict[str, Any]) -> str:
    body = dict(event)
    body.pop("event_sha256", None)
    return sha256_bytes(canonical_json_text(body).encode("utf-8"))


def _make_event(
    *,
    ledger_id: str,
    sequence: int,
    event_type: str,
    actor: dict[str, str],
    prev_event_sha256: str | None,
    payload: dict[str, Any],
) -> dict[str, Any]:
    event = {
        "schema": EVENT_SCHEMA,
        "ledger_id": ledger_id,
        "sequence": sequence,
        "event_type": event_type,
        "recorded_at_utc": _now(),
        "actor": actor,
        "prev_event_sha256": prev_event_sha256,
        "payload": payload,
        "effects": _fixed_effects(),
    }
    event["event_sha256"] = _event_digest(event)
    return event


def _operation_receipt(
    *,
    status: str,
    outcome: str,
    operation: str,
    ledger_path: Path | None,
    output_path: Path | None,
    projection: dict[str, Any] | None,
    detail: str,
    writes: list[str] | None = None,
    source_sha256: str | None = None,
    output_sha256: str | None = None,
) -> dict[str, Any]:
    return {
        "schema": OPERATION_SCHEMA,
        "generated_at_utc": _now(),
        "status": status,
        "outcome": outcome,
        "operation": operation,
        "detail": detail,
        "ledger_path": str(ledger_path) if ledger_path else None,
        "output_path": str(output_path) if output_path else None,
        "source_ledger_sha256": source_sha256,
        "output_ledger_sha256": output_sha256,
        "projection": projection,
        "effect": "EXPLICIT_OUTPUT_FILE_ONLY" if writes else "VERIFY_ONLY_NO_WRITE",
        "live_state_modified": False,
        "writes_performed": writes or [],
        "can_trade": False,
        "capital_permission": "DENY",
        "deploy_permission": "DENY",
        "self_application": False,
    }


def _identity_from_admission(receipt: dict[str, Any], receipt_sha: str) -> dict[str, Any]:
    if receipt.get("schema") != ADMISSION_RECEIPT_SCHEMA:
        raise ValueError("admission receipt schema mismatch")
    if receipt.get("status") != "WORK_ADMISSION_PASS":
        raise ValueError("admission receipt status must be WORK_ADMISSION_PASS")
    if receipt.get("outcome") != "WOULD_ALLOW":
        raise ValueError("admission receipt outcome must be WOULD_ALLOW")
    if receipt.get("live_state_modified") is not False or receipt.get("writes_performed") not in ([], None):
        raise ValueError("admission receipt has an unexpected effect")
    if receipt.get("can_trade") is not False or receipt.get("capital_permission") != "DENY" or receipt.get("deploy_permission") != "DENY" or receipt.get("self_application") is not False:
        raise ValueError("admission receipt effect ceiling is invalid")
    binding = _require_dict(receipt.get("binding"), "admission.binding")
    if binding.get("authority_generation") != "R63":
        raise ValueError("admission authority_generation must remain R63")
    _validate_no_effect(binding.get("effects"), "admission.binding.effects")
    task_id = _require_str(binding.get("task_id"), "admission.binding.task_id")
    if not TASK_ID_RE.fullmatch(task_id):
        raise ValueError("admission task_id has invalid syntax")
    request = _require_dict(receipt.get("request"), "admission.request")
    task = _require_dict(request.get("task"), "admission.request.task")
    task_body_sha = _require_sha(task.get("task_body_sha256"), "admission task_body_sha256")
    binding_sha = _require_sha(receipt.get("admission_binding_sha256"), "admission_binding_sha256")
    repository = _require_dict(binding.get("repository"), "admission.binding.repository")
    request_repo = _require_dict(request.get("repository"), "admission.request.repository")
    identity = {
        "authority_generation": "R63",
        "task_id": task_id,
        "task_body_sha256": task_body_sha,
        "admission_binding_sha256": binding_sha,
        "admission_receipt_sha256": receipt_sha,
        "repository": {
            "owner": _require_str(repository.get("owner"), "repository.owner"),
            "name": _require_str(repository.get("name"), "repository.name"),
            "remote_url": _require_str(request_repo.get("remote_url"), "repository.remote_url"),
            "visibility": _require_str(request_repo.get("visibility"), "repository.visibility"),
            "base_branch": _require_str(repository.get("base_branch"), "repository.base_branch"),
            "base_head": _require_oid(repository.get("base_head"), "repository.base_head"),
            "base_tree": _require_oid(repository.get("base_tree"), "repository.base_tree"),
            "candidate_branch": _require_str(repository.get("candidate_branch"), "repository.candidate_branch"),
        },
    }
    if identity["repository"]["visibility"] not in {"PRIVATE", "PUBLIC"}:
        raise ValueError("repository visibility is invalid")
    return identity


def _ledger_id(identity: dict[str, Any]) -> str:
    return "wl-" + sha256_bytes(canonical_json_text(identity).encode("utf-8"))[:32]


def _validate_identity(identity: Any) -> dict[str, Any]:
    value = _require_dict(identity, "ledger identity")
    if value.get("authority_generation") != "R63":
        raise ValueError("ledger authority_generation must remain R63")
    task_id = _require_str(value.get("task_id"), "ledger task_id")
    if not TASK_ID_RE.fullmatch(task_id):
        raise ValueError("ledger task_id has invalid syntax")
    normalized = {
        "authority_generation": "R63",
        "task_id": task_id,
        "task_body_sha256": _require_sha(value.get("task_body_sha256"), "ledger task_body_sha256"),
        "admission_binding_sha256": _require_sha(value.get("admission_binding_sha256"), "ledger admission_binding_sha256"),
        "admission_receipt_sha256": _require_sha(value.get("admission_receipt_sha256"), "ledger admission_receipt_sha256"),
    }
    repo = _require_dict(value.get("repository"), "ledger repository")
    normalized["repository"] = {
        "owner": _require_str(repo.get("owner"), "ledger repository.owner"),
        "name": _require_str(repo.get("name"), "ledger repository.name"),
        "remote_url": _require_str(repo.get("remote_url"), "ledger repository.remote_url"),
        "visibility": _require_str(repo.get("visibility"), "ledger repository.visibility"),
        "base_branch": _require_str(repo.get("base_branch"), "ledger repository.base_branch"),
        "base_head": _require_oid(repo.get("base_head"), "ledger repository.base_head"),
        "base_tree": _require_oid(repo.get("base_tree"), "ledger repository.base_tree"),
        "candidate_branch": _require_str(repo.get("candidate_branch"), "ledger repository.candidate_branch"),
    }
    if normalized["repository"]["visibility"] not in {"PRIVATE", "PUBLIC"}:
        raise ValueError("ledger repository.visibility is invalid")
    return normalized


def _normalize_conditions(value: Any, label: str, *, require_nonempty: bool) -> list[str]:
    if not isinstance(value, list) or len(value) > MAX_CONDITIONS:
        raise ValueError(f"{label} must be a list with at most {MAX_CONDITIONS} rows")
    out: list[str] = []
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item or len(item.encode("utf-8")) > MAX_CONDITION_BYTES:
            raise ValueError(f"{label}[{index}] is invalid or too large")
        out.append(item)
    if require_nonempty and not out:
        raise ValueError(f"{label} must be non-empty")
    return out


def _validate_admission_event(event: dict[str, Any]) -> tuple[dict[str, Any], str]:
    if event["actor"] != {"role": "CONTINUITY_GATE", "id": "continuityos"}:
        raise ValueError("admission event actor must be the ContinuityOS gate")
    payload = _require_dict(event["payload"], "admission payload")
    _require_exact_keys(payload, {"identity", "admission_receipt_sha256", "admission_status", "request_sha256", "work_order_sha256", "session_capsule_sha256"}, "admission payload")
    identity = _validate_identity(payload.get("identity"))
    expected_ledger_id = _ledger_id(identity)
    if event["ledger_id"] != expected_ledger_id:
        raise ValueError("ledger_id does not match the canonical identity")
    if payload.get("admission_status") != "WORK_ADMISSION_PASS":
        raise ValueError("admission payload status must be WORK_ADMISSION_PASS")
    if payload.get("admission_receipt_sha256") != identity["admission_receipt_sha256"]:
        raise ValueError("admission payload receipt SHA mismatches identity")
    _require_sha(payload.get("request_sha256"), "admission request_sha256")
    _require_sha(payload.get("work_order_sha256"), "admission work_order_sha256")
    _require_sha(payload.get("session_capsule_sha256"), "admission session_capsule_sha256")
    return identity, STATE_ADMITTED


def _validate_delta_event(event: dict[str, Any], projection: dict[str, Any]) -> str:
    if projection["state"] != STATE_ADMITTED:
        raise ValueError("DELTA_VERIFIED requires ADMITTED state")
    if event["actor"] != {"role": "CONTINUITY_GATE", "id": "continuityos"}:
        raise ValueError("delta event actor must be the ContinuityOS gate")
    payload = _require_dict(event["payload"], "delta payload")
    _require_exact_keys(payload, {"delta_receipt_sha256", "delta_status", "admission_binding_sha256", "admission_receipt_sha256", "validation_receipt_sha256", "candidate_head", "candidate_tree", "changed_file_count", "positive_byte_delta"}, "delta payload")
    identity = projection["identity"]
    if payload.get("delta_status") != "WORK_DELTA_PASS":
        raise ValueError("delta_status must be WORK_DELTA_PASS")
    if _require_sha(payload.get("admission_binding_sha256"), "delta admission binding") != identity["admission_binding_sha256"]:
        raise ValueError("delta admission binding mismatch")
    if _require_sha(payload.get("admission_receipt_sha256"), "delta admission receipt SHA") != identity["admission_receipt_sha256"]:
        raise ValueError("delta admission receipt SHA mismatch")
    _require_sha(payload.get("delta_receipt_sha256"), "delta receipt SHA")
    _require_sha(payload.get("validation_receipt_sha256"), "validation receipt SHA")
    candidate_head = _require_oid(payload.get("candidate_head"), "candidate_head")
    candidate_tree = _require_oid(payload.get("candidate_tree"), "candidate_tree")
    changed_file_count = payload.get("changed_file_count")
    positive_byte_delta = payload.get("positive_byte_delta")
    if not isinstance(changed_file_count, int) or isinstance(changed_file_count, bool) or changed_file_count < 1:
        raise ValueError("changed_file_count must be a positive integer")
    if not isinstance(positive_byte_delta, int) or isinstance(positive_byte_delta, bool) or positive_byte_delta < 0:
        raise ValueError("positive_byte_delta must be a non-negative integer")
    projection["candidate_head"] = candidate_head
    projection["candidate_tree"] = candidate_tree
    projection["delta_receipt_sha256"] = payload["delta_receipt_sha256"]
    projection["validation_receipt_sha256"] = payload["validation_receipt_sha256"]
    return STATE_DELTA


def _validate_transport_event(event: dict[str, Any], projection: dict[str, Any]) -> str:
    if projection["state"] != STATE_DELTA:
        raise ValueError("TRANSPORT_VERIFIED requires DELTA_VERIFIED state")
    actor = _require_dict(event["actor"], "transport actor")
    _require_exact_keys(actor, {"role", "id"}, "transport actor")
    if actor.get("role") != "HOST_EXECUTOR" or not SAFE_ID_RE.fullmatch(str(actor.get("id", ""))):
        raise ValueError("transport actor must be a bounded HOST_EXECUTOR")
    payload = _require_dict(event["payload"], "transport payload")
    _require_exact_keys(payload, {"transport_receipt_sha256", "transport_status", "admission_binding_sha256", "delta_receipt_sha256", "candidate_head", "candidate_tree", "remote_head", "remote_tree", "visibility", "actions"}, "transport payload")
    identity = projection["identity"]
    if payload.get("transport_status") != "WORK_TRANSPORT_PASS":
        raise ValueError("transport_status must be WORK_TRANSPORT_PASS")
    if _require_sha(payload.get("admission_binding_sha256"), "transport admission binding") != identity["admission_binding_sha256"]:
        raise ValueError("transport admission binding mismatch")
    if _require_sha(payload.get("delta_receipt_sha256"), "transport delta receipt SHA") != projection["delta_receipt_sha256"]:
        raise ValueError("transport delta receipt SHA mismatch")
    _require_sha(payload.get("transport_receipt_sha256"), "transport receipt SHA")
    head = _require_oid(payload.get("candidate_head"), "transport candidate_head")
    tree = _require_oid(payload.get("candidate_tree"), "transport candidate_tree")
    if head != projection["candidate_head"] or tree != projection["candidate_tree"]:
        raise ValueError("transport candidate identity differs from the verified delta")
    if payload.get("remote_head") != head or payload.get("remote_tree") != tree:
        raise ValueError("remote readback does not match the candidate")
    if payload.get("visibility") != identity["repository"]["visibility"]:
        raise ValueError("transport visibility differs from admitted repository visibility")
    actions = _require_dict(payload.get("actions"), "transport actions")
    status = actions.get("status")
    if status == "SUCCESS":
        run_id = actions.get("run_id")
        if not isinstance(run_id, int) or isinstance(run_id, bool) or run_id <= 0:
            raise ValueError("actions.run_id must be a positive integer")
        if actions.get("head_sha") != head or actions.get("conclusion") != "success":
            raise ValueError("GitHub Actions must succeed on the exact candidate HEAD")
    elif status == "NOT_CONFIGURED":
        if actions.get("run_id") is not None or actions.get("head_sha") is not None or actions.get("conclusion") != "not_configured":
            raise ValueError("NOT_CONFIGURED Actions receipt is inconsistent")
    else:
        raise ValueError("transport actions.status must be SUCCESS or NOT_CONFIGURED")
    projection["transport_receipt_sha256"] = payload["transport_receipt_sha256"]
    projection["remote_head"] = payload["remote_head"]
    projection["remote_tree"] = payload["remote_tree"]
    projection["actions"] = actions
    return STATE_TRANSPORT


def _validate_semantic_event(event: dict[str, Any], projection: dict[str, Any]) -> str:
    if projection["state"] not in {STATE_TRANSPORT, STATE_HELD}:
        raise ValueError("SEMANTIC_REVIEWED requires TRANSPORT_VERIFIED or HELD state")
    if event["actor"] != {"role": "GPT_CONTROLLER", "id": "GPT"}:
        raise ValueError("semantic review actor must be GPT_CONTROLLER/GPT")
    payload = _require_dict(event["payload"], "semantic payload")
    _require_exact_keys(payload, {"semantic_decision_sha256", "admission_binding_sha256", "delta_receipt_sha256", "transport_receipt_sha256", "candidate_head", "candidate_tree", "verdict", "conditions", "content_status", "apply_status"}, "semantic payload")
    identity = projection["identity"]
    if _require_sha(payload.get("admission_binding_sha256"), "semantic admission binding") != identity["admission_binding_sha256"]:
        raise ValueError("semantic admission binding mismatch")
    if _require_sha(payload.get("delta_receipt_sha256"), "semantic delta receipt SHA") != projection["delta_receipt_sha256"]:
        raise ValueError("semantic delta receipt SHA mismatch")
    if _require_sha(payload.get("transport_receipt_sha256"), "semantic transport receipt SHA") != projection["transport_receipt_sha256"]:
        raise ValueError("semantic transport receipt SHA mismatch")
    _require_sha(payload.get("semantic_decision_sha256"), "semantic decision SHA")
    head = _require_oid(payload.get("candidate_head"), "semantic candidate_head")
    tree = _require_oid(payload.get("candidate_tree"), "semantic candidate_tree")
    if head != projection["candidate_head"] or tree != projection["candidate_tree"]:
        raise ValueError("semantic review is not bound to the verified candidate")
    verdict = payload.get("verdict")
    if verdict not in SEMANTIC_VERDICTS:
        raise ValueError("semantic verdict is invalid")
    require_conditions = verdict != "ACCEPT"
    conditions = _normalize_conditions(payload.get("conditions"), "semantic conditions", require_nonempty=require_conditions)
    if verdict == "ACCEPT" and conditions:
        raise ValueError("ACCEPT must not carry conditions; use PASS_WITH_CONDITIONS")
    projection["semantic_decision_sha256"] = payload["semantic_decision_sha256"]
    projection["semantic_verdict"] = verdict
    projection["conditions"] = conditions
    if verdict in {"ACCEPT", "PASS_WITH_CONDITIONS"}:
        return STATE_ACCEPTED
    if verdict == "HOLD":
        return STATE_HELD
    return STATE_REJECTABLE


def _validate_terminal_event(event: dict[str, Any], projection: dict[str, Any]) -> str:
    if event["actor"] != {"role": "CONTINUITY_GATE", "id": "continuityos"}:
        raise ValueError("terminal event actor must be the ContinuityOS gate")
    payload = _require_dict(event["payload"], "terminal payload")
    _require_exact_keys(payload, {"terminal", "semantic_decision_sha256", "semantic_verdict", "apply_status"}, "terminal payload")
    if payload.get("apply_status") != "NOT_APPLIED":
        raise ValueError("terminal apply_status must remain NOT_APPLIED")
    if payload.get("semantic_verdict") != projection.get("semantic_verdict"):
        raise ValueError("terminal semantic_verdict mismatch")
    if _require_sha(payload.get("semantic_decision_sha256"), "terminal semantic decision SHA") != projection.get("semantic_decision_sha256"):
        raise ValueError("terminal event semantic-decision binding mismatch")
    if event["event_type"] == EVENT_CLOSED:
        if projection["state"] != STATE_ACCEPTED:
            raise ValueError("WORK_CLOSED requires an accepted semantic verdict")
        if payload.get("terminal") != "WORK_CLOSED":
            raise ValueError("WORK_CLOSED payload terminal mismatch")
        return STATE_CLOSED
    if event["event_type"] == EVENT_REJECTED:
        if projection["state"] != STATE_REJECTABLE:
            raise ValueError("WORK_REJECTED requires REVISE or REJECT semantic verdict")
        if payload.get("terminal") != "WORK_REJECTED":
            raise ValueError("WORK_REJECTED payload terminal mismatch")
        return STATE_REJECTED
    raise ValueError("unknown terminal event type")


def _initial_projection() -> dict[str, Any]:
    return {
        "schema": PROJECTION_SCHEMA,
        "ledger_id": None,
        "authority_generation": "R63",
        "identity": None,
        "state": None,
        "terminal": None,
        "event_count": 0,
        "latest_sequence": None,
        "latest_event_sha256": None,
        "candidate_head": None,
        "candidate_tree": None,
        "delta_receipt_sha256": None,
        "validation_receipt_sha256": None,
        "transport_receipt_sha256": None,
        "remote_head": None,
        "remote_tree": None,
        "actions": None,
        "semantic_decision_sha256": None,
        "semantic_verdict": None,
        "conditions": [],
        "receipt_sha256s": [],
        "integration_candidate_eligible": False,
        "apply_status": "NOT_APPLIED",
        "can_trade": False,
        "capital_permission": "DENY",
        "deploy_permission": "DENY",
        "self_application": False,
    }


def _validate_event(event: Any, index: int, previous: dict[str, Any] | None, projection: dict[str, Any]) -> None:
    if not isinstance(event, dict) or set(event) != EVENT_KEYS:
        raise ValueError(f"event {index} must contain exactly the v1 event fields")
    if event.get("schema") != EVENT_SCHEMA:
        raise ValueError(f"event {index} schema mismatch")
    ledger_id = _require_str(event.get("ledger_id"), f"event {index} ledger_id")
    if not LEDGER_ID_RE.fullmatch(ledger_id):
        raise ValueError(f"event {index} ledger_id has invalid syntax")
    actor = _require_dict(event.get("actor"), f"event {index} actor")
    _require_exact_keys(actor, {"role", "id"}, f"event {index} actor")
    sequence = event.get("sequence")
    if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence != index:
        raise ValueError(f"event {index} sequence mismatch")
    recorded = _parse_time(event.get("recorded_at_utc"), f"event {index} recorded_at_utc")
    _validate_no_effect(event.get("effects"), f"event {index} effects", exact_keys=NO_EFFECT_KEYS)
    event_hash = _require_sha(event.get("event_sha256"), f"event {index} event_sha256")
    if event_hash != _event_digest(event):
        raise ValueError(f"event {index} hash mismatch")
    if previous is None:
        if event.get("prev_event_sha256") is not None:
            raise ValueError("first event prev_event_sha256 must be null")
        if event.get("event_type") != EVENT_ADMISSION:
            raise ValueError("first event must be ADMISSION_VERIFIED")
    else:
        if event.get("ledger_id") != previous.get("ledger_id"):
            raise ValueError(f"event {index} ledger_id changed")
        if event.get("prev_event_sha256") != previous.get("event_sha256"):
            raise ValueError(f"event {index} prev_event_sha256 mismatch")
        previous_time = _parse_time(previous.get("recorded_at_utc"), "previous recorded_at_utc")
        if recorded < previous_time:
            raise ValueError(f"event {index} timestamp moved backwards")
        if projection["state"] in TERMINAL_STATES:
            raise ValueError("terminal work ledger may not be extended")

    event_type = event.get("event_type")
    if event_type == EVENT_ADMISSION:
        identity, state = _validate_admission_event(event)
        projection["identity"] = identity
        projection["ledger_id"] = ledger_id
    elif event_type == EVENT_DELTA:
        state = _validate_delta_event(event, projection)
    elif event_type == EVENT_TRANSPORT:
        state = _validate_transport_event(event, projection)
    elif event_type == EVENT_SEMANTIC:
        state = _validate_semantic_event(event, projection)
    elif event_type in {EVENT_CLOSED, EVENT_REJECTED}:
        state = _validate_terminal_event(event, projection)
    else:
        raise ValueError(f"event {index} event_type is not supported")

    receipt_key = {
        EVENT_ADMISSION: "admission_receipt_sha256",
        EVENT_DELTA: "delta_receipt_sha256",
        EVENT_TRANSPORT: "transport_receipt_sha256",
        EVENT_SEMANTIC: "semantic_decision_sha256",
    }.get(event_type)
    if receipt_key is not None:
        receipt_sha = event["payload"].get(receipt_key)
        if receipt_sha in projection["receipt_sha256s"]:
            raise ValueError(f"event {index} replays an already-recorded receipt")
        projection["receipt_sha256s"].append(receipt_sha)

    projection["state"] = state
    projection["terminal"] = event_type if state in TERMINAL_STATES else None
    projection["event_count"] = index + 1
    projection["latest_sequence"] = index
    projection["latest_event_sha256"] = event_hash
    projection["integration_candidate_eligible"] = state == STATE_CLOSED


def _read_ledger(path: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if path.is_symlink():
        raise ValueError("ledger path may not be a symlink")
    if not path.is_file():
        raise ValueError("ledger file is missing")
    size = path.stat().st_size
    if size <= 0 or size > MAX_LEDGER_BYTES:
        raise ValueError(f"ledger size must be in [1, {MAX_LEDGER_BYTES}] bytes")
    raw = path.read_bytes()
    if raw.startswith(b"\xef\xbb\xbf"):
        raise ValueError("ledger must not contain a UTF-8 BOM")
    lines = raw.splitlines(keepends=True)
    if not lines or len(lines) > MAX_EVENTS:
        raise ValueError(f"ledger must contain 1..{MAX_EVENTS} events")
    if not raw.endswith(b"\n"):
        raise ValueError("ledger must end with a newline")

    events: list[dict[str, Any]] = []
    projection = _initial_projection()
    previous = None
    for index, line in enumerate(lines):
        if len(line) > MAX_EVENT_BYTES:
            raise ValueError(f"event {index} exceeds {MAX_EVENT_BYTES} bytes")
        if not line.endswith(b"\n") or line in {b"\n", b"\r\n"}:
            raise ValueError(f"event {index} line is empty or unterminated")
        try:
            event = json.loads(line.decode("utf-8"))
        except Exception as exc:
            raise ValueError(f"event {index} is not valid UTF-8 JSON: {type(exc).__name__}: {exc}") from exc
        canonical = canonical_json_text(event).encode("utf-8")
        if canonical != line:
            raise ValueError(f"event {index} is not canonical JSONL")
        _validate_event(event, index, previous, projection)
        events.append(event)
        previous = event
    return events, projection


def verify_work_ledger(path: Path) -> dict[str, Any]:
    try:
        _, projection = _read_ledger(path)
        return _operation_receipt(
            status=VERIFY_PASS,
            outcome="VALID",
            operation="verify",
            ledger_path=path,
            output_path=None,
            projection=projection,
            detail="Work ledger hash chain, state transitions and effect ceiling are valid.",
            source_sha256=sha256_file(path),
        )
    except Exception as exc:
        return _operation_receipt(
            status=LEDGER_REVISE,
            outcome="WOULD_HOLD",
            operation="verify",
            ledger_path=path,
            output_path=None,
            projection=None,
            detail=f"{type(exc).__name__}: {exc}",
        )


def project_work_ledger(path: Path) -> dict[str, Any]:
    try:
        _, projection = _read_ledger(path)
        return {
            "schema": OPERATION_SCHEMA,
            "generated_at_utc": _now(),
            "status": PROJECT_PASS,
            "outcome": "PROJECTED",
            "operation": "project",
            "ledger_path": str(path),
            "ledger_sha256": sha256_file(path),
            "projection": projection,
            "effect": "VERIFY_ONLY_NO_WRITE",
            "live_state_modified": False,
            "writes_performed": [],
            "can_trade": False,
            "capital_permission": "DENY",
            "deploy_permission": "DENY",
            "self_application": False,
        }
    except Exception as exc:
        return _operation_receipt(
            status=LEDGER_REVISE,
            outcome="WOULD_HOLD",
            operation="project",
            ledger_path=path,
            output_path=None,
            projection=None,
            detail=f"{type(exc).__name__}: {exc}",
        )


def _prepare_output(output_path: Path, *, input_path: Path | None = None) -> None:
    if output_path.exists() or output_path.is_symlink():
        raise ValueError("output path already exists")
    if not output_path.parent.is_dir():
        raise ValueError("output parent directory does not exist")
    if input_path is not None and output_path.resolve() == input_path.resolve():
        raise ValueError("output path must differ from the input ledger")


def _write_initial(output_path: Path, event: dict[str, Any]) -> None:
    _prepare_output(output_path)
    output_path.write_text(canonical_json_text(event), encoding="utf-8", newline="\n")


def _write_successor(input_path: Path, output_path: Path, event: dict[str, Any]) -> None:
    _prepare_output(output_path, input_path=input_path)
    source = input_path.read_bytes()
    output_path.write_bytes(source + canonical_json_text(event).encode("utf-8"))


def initialize_work_ledger(admission_receipt_path: Path, output_path: Path) -> dict[str, Any]:
    try:
        receipt = _load_json(admission_receipt_path, "admission receipt")
        receipt_sha = sha256_file(admission_receipt_path)
        identity = _identity_from_admission(receipt, receipt_sha)
        ledger_id = _ledger_id(identity)
        event = _make_event(
            ledger_id=ledger_id,
            sequence=0,
            event_type=EVENT_ADMISSION,
            actor=_safe_actor("CONTINUITY_GATE", "continuityos"),
            prev_event_sha256=None,
            payload={
                "identity": identity,
                "admission_receipt_sha256": receipt_sha,
                "admission_status": "WORK_ADMISSION_PASS",
                "request_sha256": _require_sha(receipt.get("request_sha256"), "request_sha256"),
                "work_order_sha256": _require_sha(receipt.get("work_order_sha256"), "work_order_sha256"),
                "session_capsule_sha256": _require_sha(receipt.get("session_capsule_sha256"), "session_capsule_sha256"),
            },
        )
        _write_initial(output_path, event)
        _, projection = _read_ledger(output_path)
        return _operation_receipt(
            status=INIT_PASS,
            outcome="LEDGER_CREATED",
            operation="init",
            ledger_path=None,
            output_path=output_path,
            projection=projection,
            detail="Initialized an immutable work ledger from an exact WORK_ADMISSION_PASS receipt.",
            writes=[str(output_path)],
            output_sha256=sha256_file(output_path),
        )
    except Exception as exc:
        return _operation_receipt(
            status=LEDGER_REVISE,
            outcome="WOULD_HOLD",
            operation="init",
            ledger_path=None,
            output_path=output_path,
            projection=None,
            detail=f"{type(exc).__name__}: {exc}",
        )


def _append_event(
    ledger_path: Path,
    output_path: Path,
    *,
    operation: str,
    builder: Callable[[dict[str, Any], dict[str, Any]], tuple[str, dict[str, str], dict[str, Any]]],
) -> dict[str, Any]:
    try:
        events, projection = _read_ledger(ledger_path)
        event_type, actor, payload = builder(events[-1], projection)
        event = _make_event(
            ledger_id=projection["ledger_id"],
            sequence=len(events),
            event_type=event_type,
            actor=actor,
            prev_event_sha256=events[-1]["event_sha256"],
            payload=payload,
        )
        _write_successor(ledger_path, output_path, event)
        _, new_projection = _read_ledger(output_path)
        return _operation_receipt(
            status=EXTEND_PASS,
            outcome="SUCCESSOR_LEDGER_CREATED",
            operation=operation,
            ledger_path=ledger_path,
            output_path=output_path,
            projection=new_projection,
            detail=f"Appended {event_type} to a new immutable successor ledger.",
            writes=[str(output_path)],
            source_sha256=sha256_file(ledger_path),
            output_sha256=sha256_file(output_path),
        )
    except Exception as exc:
        return _operation_receipt(
            status=LEDGER_REVISE,
            outcome="WOULD_HOLD",
            operation=operation,
            ledger_path=ledger_path,
            output_path=output_path,
            projection=None,
            detail=f"{type(exc).__name__}: {exc}",
        )


def append_work_delta(ledger_path: Path, delta_receipt_path: Path, output_path: Path) -> dict[str, Any]:
    def build(_: dict[str, Any], projection: dict[str, Any]) -> tuple[str, dict[str, str], dict[str, Any]]:
        receipt = _load_json(delta_receipt_path, "delta receipt")
        if receipt.get("schema") != DELTA_RECEIPT_SCHEMA:
            raise ValueError("delta receipt schema mismatch")
        if receipt.get("status") != "WORK_DELTA_PASS" or receipt.get("outcome") != "WOULD_ALLOW_CANDIDATE_TRANSPORT":
            raise ValueError("delta receipt must be WORK_DELTA_PASS")
        if receipt.get("task_id") != projection["identity"]["task_id"]:
            raise ValueError("delta receipt task_id mismatch")
        if receipt.get("admission_binding_sha256") != projection["identity"]["admission_binding_sha256"]:
            raise ValueError("delta receipt admission binding mismatch")
        if receipt.get("admission_receipt_sha256") != projection["identity"]["admission_receipt_sha256"]:
            raise ValueError("delta receipt admission receipt SHA mismatch")
        if receipt.get("live_state_modified") is not False or receipt.get("writes_performed") not in ([], None):
            raise ValueError("delta receipt has an unexpected live effect")
        if receipt.get("can_trade") is not False or receipt.get("capital_permission") != "DENY" or receipt.get("deploy_permission") != "DENY" or receipt.get("self_application") is not False:
            raise ValueError("delta receipt effect ceiling is invalid")
        observed = _require_dict(receipt.get("repository_observed"), "delta repository_observed")
        if observed.get("branch") != projection["identity"]["repository"]["candidate_branch"]:
            raise ValueError("delta candidate branch mismatch")
        changed = receipt.get("changed_files")
        if not isinstance(changed, list) or not changed:
            raise ValueError("delta receipt must contain changed_files")
        positive = 0
        for index, row in enumerate(changed):
            if not isinstance(row, dict):
                raise ValueError(f"delta changed_files[{index}] must be an object")
            value = row.get("positive_byte_delta", 0)
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise ValueError(f"delta changed_files[{index}].positive_byte_delta is invalid")
            positive += value
        return (
            EVENT_DELTA,
            _safe_actor("CONTINUITY_GATE", "continuityos"),
            {
                "delta_receipt_sha256": sha256_file(delta_receipt_path),
                "delta_status": "WORK_DELTA_PASS",
                "admission_binding_sha256": projection["identity"]["admission_binding_sha256"],
                "admission_receipt_sha256": projection["identity"]["admission_receipt_sha256"],
                "validation_receipt_sha256": _require_sha(receipt.get("validation_receipt_sha256"), "validation_receipt_sha256"),
                "candidate_head": _require_oid(observed.get("head"), "delta candidate_head"),
                "candidate_tree": _require_oid(observed.get("tree"), "delta candidate_tree"),
                "changed_file_count": len(changed),
                "positive_byte_delta": positive,
            },
        )

    return _append_event(ledger_path, output_path, operation="append-delta", builder=build)


def _normalize_transport_receipt(receipt: dict[str, Any], projection: dict[str, Any], receipt_sha: str) -> tuple[dict[str, str], dict[str, Any]]:
    _require_exact_keys(receipt, TRANSPORT_RECEIPT_KEYS, "transport receipt")
    if receipt.get("schema") != TRANSPORT_SCHEMA:
        raise ValueError("transport receipt schema mismatch")
    if receipt.get("authority_generation") != "R63":
        raise ValueError("transport authority_generation must remain R63")
    if receipt.get("terminal") != "WORK_TRANSPORT_PASS":
        raise ValueError("transport terminal must be WORK_TRANSPORT_PASS")
    identity = projection["identity"]
    if receipt.get("task_id") != identity["task_id"]:
        raise ValueError("transport task_id mismatch")
    if _require_sha(receipt.get("admission_binding_sha256"), "transport admission binding") != identity["admission_binding_sha256"]:
        raise ValueError("transport admission binding mismatch")
    if _require_sha(receipt.get("delta_receipt_sha256"), "transport delta receipt SHA") != projection["delta_receipt_sha256"]:
        raise ValueError("transport delta receipt SHA mismatch")
    repository = _require_dict(receipt.get("repository"), "transport repository")
    _require_exact_keys(repository, {"owner", "name", "remote_url", "visibility", "candidate_branch"}, "transport repository")
    expected_repo = identity["repository"]
    for key in ("owner", "name", "remote_url", "visibility", "candidate_branch"):
        if repository.get(key) != expected_repo[key]:
            raise ValueError(f"transport repository.{key} mismatch")
    candidate = _require_dict(receipt.get("candidate"), "transport candidate")
    _require_exact_keys(candidate, {"head", "tree"}, "transport candidate")
    head = _require_oid(candidate.get("head"), "transport candidate.head")
    tree = _require_oid(candidate.get("tree"), "transport candidate.tree")
    if head != projection["candidate_head"] or tree != projection["candidate_tree"]:
        raise ValueError("transport candidate differs from the verified delta")
    remote = _require_dict(receipt.get("remote"), "transport remote")
    _require_exact_keys(remote, {"head", "tree", "visibility"}, "transport remote")
    remote_head = _require_oid(remote.get("head"), "transport remote.head")
    remote_tree = _require_oid(remote.get("tree"), "transport remote.tree")
    if remote_head != head or remote_tree != tree:
        raise ValueError("transport remote readback differs from the candidate")
    if remote.get("visibility") != expected_repo["visibility"]:
        raise ValueError("transport remote visibility changed")
    actions = _require_dict(receipt.get("actions"), "transport actions")
    _require_exact_keys(actions, {"status", "run_id", "head_sha", "conclusion"}, "transport actions")
    action_status = actions.get("status")
    normalized_actions: dict[str, Any]
    if action_status == "SUCCESS":
        run_id = actions.get("run_id")
        if not isinstance(run_id, int) or isinstance(run_id, bool) or run_id <= 0:
            raise ValueError("transport actions.run_id must be a positive integer")
        if actions.get("head_sha") != head or actions.get("conclusion") != "success":
            raise ValueError("transport Actions did not succeed on the exact candidate HEAD")
        normalized_actions = {"status": "SUCCESS", "run_id": run_id, "head_sha": head, "conclusion": "success"}
    elif action_status == "NOT_CONFIGURED":
        if actions.get("run_id") is not None or actions.get("head_sha") is not None or actions.get("conclusion") != "not_configured":
            raise ValueError("transport NOT_CONFIGURED Actions receipt is inconsistent")
        normalized_actions = {"status": "NOT_CONFIGURED", "run_id": None, "head_sha": None, "conclusion": "not_configured"}
    else:
        raise ValueError("transport actions.status must be SUCCESS or NOT_CONFIGURED")
    effects = _require_dict(receipt.get("effects"), "transport effects")
    if effects.get("candidate_push") is not True:
        raise ValueError("transport effects.candidate_push must be true")
    _validate_no_effect(effects, "transport effects", exact_keys=NO_EFFECT_KEYS | {"candidate_push"})
    executor = _require_dict(receipt.get("executor"), "transport executor")
    _require_exact_keys(executor, {"role", "id"}, "transport executor")
    actor = _safe_actor(_require_str(executor.get("role"), "transport executor.role"), _require_str(executor.get("id"), "transport executor.id"))
    payload = {
        "transport_receipt_sha256": receipt_sha,
        "transport_status": "WORK_TRANSPORT_PASS",
        "admission_binding_sha256": identity["admission_binding_sha256"],
        "delta_receipt_sha256": projection["delta_receipt_sha256"],
        "candidate_head": head,
        "candidate_tree": tree,
        "remote_head": remote_head,
        "remote_tree": remote_tree,
        "visibility": remote["visibility"],
        "actions": normalized_actions,
    }
    return actor, payload


def append_work_transport(ledger_path: Path, transport_receipt_path: Path, output_path: Path) -> dict[str, Any]:
    def build(_: dict[str, Any], projection: dict[str, Any]) -> tuple[str, dict[str, str], dict[str, Any]]:
        receipt = _load_json(transport_receipt_path, "transport receipt")
        actor, payload = _normalize_transport_receipt(receipt, projection, sha256_file(transport_receipt_path))
        return EVENT_TRANSPORT, actor, payload

    return _append_event(ledger_path, output_path, operation="append-transport", builder=build)


def _normalize_semantic_decision(decision: dict[str, Any], projection: dict[str, Any], decision_sha: str) -> tuple[dict[str, str], dict[str, Any]]:
    _require_exact_keys(decision, SEMANTIC_DECISION_KEYS, "semantic decision")
    if decision.get("schema") != SEMANTIC_SCHEMA:
        raise ValueError("semantic decision schema mismatch")
    if decision.get("authority_generation") != "R63":
        raise ValueError("semantic authority_generation must remain R63")
    identity = projection["identity"]
    if decision.get("task_id") != identity["task_id"]:
        raise ValueError("semantic decision task_id mismatch")
    if _require_sha(decision.get("admission_binding_sha256"), "semantic admission binding") != identity["admission_binding_sha256"]:
        raise ValueError("semantic admission binding mismatch")
    if _require_sha(decision.get("delta_receipt_sha256"), "semantic delta receipt SHA") != projection["delta_receipt_sha256"]:
        raise ValueError("semantic delta receipt SHA mismatch")
    if _require_sha(decision.get("transport_receipt_sha256"), "semantic transport receipt SHA") != projection["transport_receipt_sha256"]:
        raise ValueError("semantic transport receipt SHA mismatch")
    candidate = _require_dict(decision.get("candidate"), "semantic candidate")
    _require_exact_keys(candidate, {"head", "tree"}, "semantic candidate")
    head = _require_oid(candidate.get("head"), "semantic candidate.head")
    tree = _require_oid(candidate.get("tree"), "semantic candidate.tree")
    if head != projection["candidate_head"] or tree != projection["candidate_tree"]:
        raise ValueError("semantic decision candidate mismatch")
    reviewer = _require_dict(decision.get("reviewer"), "semantic reviewer")
    _require_exact_keys(reviewer, {"role", "id"}, "semantic reviewer")
    actor = _safe_actor(_require_str(reviewer.get("role"), "semantic reviewer.role"), _require_str(reviewer.get("id"), "semantic reviewer.id"))
    if actor != {"role": "GPT_CONTROLLER", "id": "GPT"}:
        raise ValueError("semantic reviewer must be GPT_CONTROLLER/GPT")
    verdict = decision.get("verdict")
    if verdict not in SEMANTIC_VERDICTS:
        raise ValueError("semantic decision verdict is invalid")
    conditions = _normalize_conditions(decision.get("conditions"), "semantic conditions", require_nonempty=verdict != "ACCEPT")
    if verdict == "ACCEPT" and conditions:
        raise ValueError("ACCEPT must not carry conditions")
    if decision.get("content_status") != "REVIEWED":
        raise ValueError("semantic content_status must be REVIEWED")
    if decision.get("apply_status") != "NOT_APPLIED":
        raise ValueError("semantic apply_status must remain NOT_APPLIED")
    _validate_no_effect(decision.get("effects"), "semantic effects", exact_keys=NO_EFFECT_KEYS)
    payload = {
        "semantic_decision_sha256": decision_sha,
        "admission_binding_sha256": identity["admission_binding_sha256"],
        "delta_receipt_sha256": projection["delta_receipt_sha256"],
        "transport_receipt_sha256": projection["transport_receipt_sha256"],
        "candidate_head": head,
        "candidate_tree": tree,
        "verdict": verdict,
        "conditions": conditions,
        "content_status": "REVIEWED",
        "apply_status": "NOT_APPLIED",
    }
    return actor, payload


def append_work_semantic_review(ledger_path: Path, semantic_decision_path: Path, output_path: Path) -> dict[str, Any]:
    def build(_: dict[str, Any], projection: dict[str, Any]) -> tuple[str, dict[str, str], dict[str, Any]]:
        decision = _load_json(semantic_decision_path, "semantic decision")
        actor, payload = _normalize_semantic_decision(decision, projection, sha256_file(semantic_decision_path))
        return EVENT_SEMANTIC, actor, payload

    return _append_event(ledger_path, output_path, operation="append-semantic", builder=build)


def finalize_work_ledger(ledger_path: Path, output_path: Path) -> dict[str, Any]:
    try:
        events, projection = _read_ledger(ledger_path)
        if projection["state"] == STATE_HELD:
            return _operation_receipt(
                status=LEDGER_HOLD,
                outcome="WOULD_HOLD",
                operation="finalize",
                ledger_path=ledger_path,
                output_path=output_path,
                projection=projection,
                detail="A HOLD semantic verdict must be reviewed again before finalization.",
                source_sha256=sha256_file(ledger_path),
            )
        if projection["state"] in TERMINAL_STATES:
            return _operation_receipt(
                status=LEDGER_HOLD,
                outcome="ALREADY_TERMINAL",
                operation="finalize",
                ledger_path=ledger_path,
                output_path=output_path,
                projection=projection,
                detail="Ledger is already terminal and was not rewritten.",
                source_sha256=sha256_file(ledger_path),
            )
        if projection["state"] == STATE_ACCEPTED:
            event_type = EVENT_CLOSED
            terminal = "WORK_CLOSED"
        elif projection["state"] == STATE_REJECTABLE:
            event_type = EVENT_REJECTED
            terminal = "WORK_REJECTED"
        else:
            return _operation_receipt(
                status=LEDGER_HOLD,
                outcome="WOULD_HOLD",
                operation="finalize",
                ledger_path=ledger_path,
                output_path=output_path,
                projection=projection,
                detail=f"Ledger state {projection['state']} is not ready for finalization.",
                source_sha256=sha256_file(ledger_path),
            )
        event = _make_event(
            ledger_id=projection["ledger_id"],
            sequence=len(events),
            event_type=event_type,
            actor=_safe_actor("CONTINUITY_GATE", "continuityos"),
            prev_event_sha256=events[-1]["event_sha256"],
            payload={
                "terminal": terminal,
                "semantic_decision_sha256": projection["semantic_decision_sha256"],
                "semantic_verdict": projection["semantic_verdict"],
                "apply_status": "NOT_APPLIED",
            },
        )
        _write_successor(ledger_path, output_path, event)
        _, new_projection = _read_ledger(output_path)
        return _operation_receipt(
            status=FINALIZE_PASS,
            outcome=terminal,
            operation="finalize",
            ledger_path=ledger_path,
            output_path=output_path,
            projection=new_projection,
            detail=f"Created terminal successor ledger {terminal} without applying or merging anything.",
            writes=[str(output_path)],
            source_sha256=sha256_file(ledger_path),
            output_sha256=sha256_file(output_path),
        )
    except Exception as exc:
        return _operation_receipt(
            status=LEDGER_REVISE,
            outcome="WOULD_HOLD",
            operation="finalize",
            ledger_path=ledger_path,
            output_path=output_path,
            projection=None,
            detail=f"{type(exc).__name__}: {exc}",
        )


def exit_code_for_work_ledger(receipt: dict[str, Any]) -> int:
    status = receipt.get("status")
    if status in {VERIFY_PASS, INIT_PASS, EXTEND_PASS, FINALIZE_PASS, PROJECT_PASS}:
        return 0
    if status == LEDGER_HOLD:
        return 1
    return 2
