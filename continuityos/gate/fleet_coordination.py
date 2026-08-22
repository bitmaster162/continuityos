"""Effect-free coordination for Governed Fleet M1.

Fleet M1 is a deterministic serialization/verification layer over the existing
ContinuityOS work_admission, work_validation, work_ledger and current_work
primitives.  It is not an executor or a second authority plane.  This module
has no network/subprocess/Git/storage writer and no merge/deploy/runtime/send/
trading/wallet/order/capital path.  ALLOW is a coordination result only.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
import re
from typing import Any, Iterable, Mapping, Sequence

WORK_ORDER_SCHEMA = "continuityos.work_order/v2.2"
WORK_LEASE_SCHEMA = "continuityos.work_lease/v1.2"
FANOUT_SCHEMA = "continuityos.fanout_group/v1.2"
VERIFICATION_SCHEMA = "continuityos.agent_verification_receipt/v1.2"
CURRENT_PROJECTION_SCHEMA = "continuityos.current_projection/v2.2"
COORDINATION_EVENT_SCHEMA = "continuityos.fleet.coordination_event/v1"
DIGEST_CONTRACT = "CANONICAL_JSON_UTF8_SHA256_FULL_DOCUMENT_V1"
RESOLVER_CONTRACT = "DETERMINISTIC_APPEND_ONLY_INPUTS_PROVIDER_READBACK_WINS_V1"
SHA40 = re.compile(r"^[0-9a-f]{40}$")
SHA64 = re.compile(r"^[0-9a-f]{64}$")
CONFLICT = re.compile(r"^(repo-path|git-branch|semantic|db|library-family|drive-object-set|deploy-target|runtime-service|authority-decision|effect-resource):([^\s]+)$")

M1_AUTHORITY: dict[str, Any] = {
    "execution_authority": "NONE", "can_trade": False,
    "capital_permission": "DENY", "merge_authority": False,
    "deploy_authority": False, "deploy_permission": "DENY",
    "destructive_storage_authority": False, "external_send_authority": False,
}
PROJECTION_AUTHORITY = {
    **M1_AUTHORITY, "projection_is_authority": False,
    "provider_readback_precedence": True,
}

WORK_ORDER_REQUIRED = {
    "schema", "work_order_id", "work_order_version", "project_id", "lane_id", "goal",
    "frozen_input_digest", "input_artifact_ids", "repo", "base_branch", "base_sha",
    "base_tree", "git_object_format", "read_set", "write_set", "conflict_keys",
    "effect_set", "dependencies", "allowed_tools", "forbidden_effects",
    "acceptance_contract", "rollback_or_compensation_class", "output_schema",
    "receipt_schema", "created_at", "authority", "digest_contract",
}
LEASE_REQUIRED = {
    "schema", "lease_id", "work_order_id", "agent_run_id", "resource_scope",
    "conflict_keys", "mode", "acquired_at", "expires_at", "status",
    "work_order_digest", "git_object_format", "base_sha", "last_observed_activity_at",
    "last_activity_evidence_digest", "checkpoint_ref", "checkpoint_digest",
    "checkpoint_observed_at",
}
VERIFICATION_REQUIRED = {
    "schema", "verification_id", "work_order_id", "work_order_digest",
    "worker_run_id", "verifier_run_id", "worker_output_digest",
    "verifier_context_isolated", "worker_hidden_scratch_shared",
    "worker_conclusion_inherited_as_fact", "status", "authority", "observed_at",
    "evidence_digest", "findings_digest", "conditions",
}


class Decision(str, Enum):
    ALLOW = "ALLOW"
    SERIALIZE = "SERIALIZE"
    HOLD = "HOLD"
    REJECT = "REJECT"


@dataclass(frozen=True)
class Result:
    decision: Decision
    reason: str
    details: tuple[str, ...] = ()

    @property
    def ok(self) -> bool:
        return self.decision is Decision.ALLOW

    def as_dict(self) -> dict[str, Any]:
        return {"decision": self.decision.value, "reason": self.reason,
                "details": list(self.details), "authority": dict(M1_AUTHORITY)}


def canonical_json_text(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False) + "\n"


def sha256_document(value: Any) -> str:
    return hashlib.sha256(canonical_json_text(value).encode("utf-8")).hexdigest()


def work_order_digest(work_order: Mapping[str, Any]) -> str:
    return sha256_document(dict(work_order))


def _time(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} must be RFC3339")
    text = value[:-1] + "+00:00" if value.endswith("Z") else value
    dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        raise ValueError(f"{label} timezone required")
    return dt.astimezone(timezone.utc)


def _text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be non-empty")
    return value.strip()


def _list(value: Any, label: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(x, str) and x for x in value):
        raise ValueError(f"{label} must be string array")
    if len(value) != len(set(value)):
        raise ValueError(f"{label} duplicates")
    return list(value)


def _digest(value: Any, label: str, width: int = 64) -> str:
    pattern = SHA40 if width == 40 else SHA64
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise ValueError(f"{label} invalid")
    return value


def normalized_work_scope(work_order: Mapping[str, Any]) -> list[str]:
    return sorted(set(_list(work_order.get("read_set"), "read_set")) |
                  set(_list(work_order.get("write_set"), "write_set")))


def validate_conflict_key(key: Any) -> tuple[str, str]:
    match = CONFLICT.fullmatch(_text(key, "conflict_key"))
    if not match:
        raise ValueError("unsupported conflict key")
    namespace, payload = match.groups()
    if namespace == "repo-path":
        if ":" not in payload:
            raise ValueError("repo-path requires repo:path")
        repo, path = payload.split(":", 1)
        if not repo or not path.strip("/") or ".." in path.split("/"):
            raise ValueError("invalid repo-path")
    return namespace, payload


def conflict_keys_conflict(left: str, right: str) -> bool:
    ln, lp = validate_conflict_key(left); rn, rp = validate_conflict_key(right)
    if ln != rn:
        return False
    if ln != "repo-path":
        return lp == rp
    lr, lpath = lp.split(":", 1); rr, rpath = rp.split(":", 1)
    if lr != rr:
        return False
    a, b = lpath.strip("/"), rpath.strip("/")
    return a == b or a.startswith(b + "/") or b.startswith(a + "/")


def conflict_sets_overlap(left: Iterable[str], right: Iterable[str]) -> bool:
    return any(conflict_keys_conflict(a, b) for a in left for b in right)


def validate_work_order_m1(work_order: Mapping[str, Any]) -> Result:
    if not isinstance(work_order, Mapping):
        return Result(Decision.HOLD, "WORK_ORDER_NOT_OBJECT")
    if set(work_order) != WORK_ORDER_REQUIRED:
        return Result(Decision.HOLD, "WORK_ORDER_FIELDS")
    try:
        if work_order["schema"] != WORK_ORDER_SCHEMA or work_order["work_order_version"] != "2.2":
            return Result(Decision.HOLD, "WORK_ORDER_VERSION")
        if work_order["digest_contract"] != DIGEST_CONTRACT:
            return Result(Decision.HOLD, "DIGEST_CONTRACT")
        for key in ("work_order_id", "project_id", "lane_id", "goal", "output_schema", "receipt_schema"):
            _text(work_order[key], key)
        _digest(work_order["frozen_input_digest"], "frozen_input_digest")
        _time(work_order["created_at"], "created_at")
        for key in ("input_artifact_ids", "read_set", "write_set", "allowed_tools", "forbidden_effects"):
            _list(work_order[key], key)
        for key in _list(work_order["conflict_keys"], "conflict_keys"):
            validate_conflict_key(key)
        if work_order["effect_set"] != []:
            return Result(Decision.REJECT, "M1_EFFECT_SET_NONEMPTY")
        if dict(work_order["authority"]) != M1_AUTHORITY:
            return Result(Decision.REJECT, "AUTHORITY_ESCALATION")
        if not isinstance(work_order["acceptance_contract"], Mapping) or not work_order["acceptance_contract"]:
            return Result(Decision.HOLD, "ACCEPTANCE_CONTRACT")
        if work_order["rollback_or_compensation_class"] not in {"REVERSIBLE", "COMPENSATABLE", "IRREVERSIBLE", "NO_EFFECT"}:
            return Result(Decision.HOLD, "ROLLBACK_CLASS")
        if not isinstance(work_order["dependencies"], list):
            return Result(Decision.HOLD, "DEPENDENCIES_TYPE")
        seen = set()
        for dep in work_order["dependencies"]:
            if not isinstance(dep, Mapping) or set(dep) != {"work_order_id", "work_order_digest", "required_terminal"}:
                return Result(Decision.HOLD, "DEPENDENCY_FIELDS")
            row = (_text(dep["work_order_id"], "dependency.id"),
                   _digest(dep["work_order_digest"], "dependency.digest"),
                   _text(dep["required_terminal"], "dependency.terminal"))
            if row in seen:
                return Result(Decision.HOLD, "DUPLICATE_DEPENDENCY")
            seen.add(row)
        bound = ("base_branch", "git_object_format", "base_sha", "base_tree")
        if work_order["repo"] is None:
            if any(work_order[x] is not None for x in bound):
                return Result(Decision.HOLD, "NONREPO_BASE_BINDING")
        else:
            _text(work_order["repo"], "repo"); _text(work_order["base_branch"], "base_branch")
            fmt = work_order["git_object_format"]
            if fmt not in {"SHA1", "SHA256"}:
                return Result(Decision.HOLD, "GIT_OBJECT_FORMAT")
            width = 40 if fmt == "SHA1" else 64
            _digest(work_order["base_sha"], "base_sha", width)
            _digest(work_order["base_tree"], "base_tree", width)
    except (TypeError, ValueError) as exc:
        return Result(Decision.HOLD, "WORK_ORDER_INVALID", (str(exc),))
    return Result(Decision.ALLOW, "WORK_ORDER_VALID")


def validate_lease_against_work_order(lease: Mapping[str, Any], work_order: Mapping[str, Any], *, observed_at: str | None = None) -> Result:
    base = validate_work_order_m1(work_order)
    if not base.ok:
        return base
    if not isinstance(lease, Mapping) or set(lease) != LEASE_REQUIRED:
        return Result(Decision.HOLD, "LEASE_FIELDS")
    try:
        if lease["schema"] != WORK_LEASE_SCHEMA:
            return Result(Decision.HOLD, "LEASE_VERSION")
        if lease["work_order_id"] != work_order["work_order_id"]:
            return Result(Decision.HOLD, "LEASE_WORK_ORDER_ID_MISMATCH")
        if lease["work_order_digest"] != work_order_digest(work_order):
            return Result(Decision.HOLD, "LEASE_WORK_ORDER_DIGEST_MISMATCH")
        if sorted(lease["resource_scope"]) != normalized_work_scope(work_order):
            return Result(Decision.HOLD, "LEASE_SCOPE_MISMATCH")
        if sorted(lease["conflict_keys"]) != sorted(work_order["conflict_keys"]):
            return Result(Decision.HOLD, "LEASE_CONFLICT_KEYS_MISMATCH")
        if lease["base_sha"] != work_order["base_sha"] or lease["git_object_format"] != work_order["git_object_format"]:
            return Result(Decision.HOLD, "LEASE_BASE_MISMATCH")
        if lease["mode"] == "EFFECT":
            return Result(Decision.REJECT, "M1_EFFECT_LEASE_DENY")
        if lease["mode"] not in {"READ", "CANDIDATE_WRITE"}:
            return Result(Decision.HOLD, "LEASE_MODE")
        if lease["mode"] == "READ" and work_order["write_set"]:
            return Result(Decision.HOLD, "READ_LEASE_FOR_WRITE_WORK")
        if lease["mode"] == "CANDIDATE_WRITE" and (not work_order["write_set"] or work_order["repo"] is None):
            return Result(Decision.HOLD, "WRITE_LEASE_BINDING")
        acquired, expires = _time(lease["acquired_at"], "acquired_at"), _time(lease["expires_at"], "expires_at")
        if acquired >= expires:
            return Result(Decision.HOLD, "LEASE_TIME_ORDER")
        activity = (lease["last_observed_activity_at"], lease["last_activity_evidence_digest"])
        if (activity[0] is None) != (activity[1] is None):
            return Result(Decision.HOLD, "ACTIVITY_EVIDENCE_PAIR")
        if activity[0] is not None:
            if not acquired <= _time(activity[0], "activity") <= expires:
                return Result(Decision.HOLD, "ACTIVITY_OUTSIDE_LEASE")
            _digest(activity[1], "activity_digest")
        checkpoint = (lease["checkpoint_ref"], lease["checkpoint_digest"], lease["checkpoint_observed_at"])
        if len({x is None for x in checkpoint}) != 1:
            return Result(Decision.HOLD, "CHECKPOINT_BINDING_TRIPLE")
        if checkpoint[0] is not None:
            _digest(checkpoint[1], "checkpoint_digest")
            if not acquired <= _time(checkpoint[2], "checkpoint_time") <= expires:
                return Result(Decision.HOLD, "CHECKPOINT_OUTSIDE_LEASE")
        if observed_at is not None and lease["status"] == "ACTIVE" and _time(observed_at, "observed_at") >= expires:
            return Result(Decision.HOLD, "ACTIVE_LEASE_EXPIRED_AT_OBSERVATION")
    except (TypeError, ValueError) as exc:
        return Result(Decision.HOLD, "LEASE_INVALID", (str(exc),))
    return Result(Decision.ALLOW, "LEASE_VALID")


def lease_currentness(lease: Mapping[str, Any], work_order: Mapping[str, Any], *, observed_at: str, provider_base_sha: str | None) -> Result:
    relation = validate_lease_against_work_order(lease, work_order, observed_at=observed_at)
    if not relation.ok:
        return relation
    if lease["status"] != "ACTIVE":
        return Result(Decision.HOLD, "LEASE_NOT_ACTIVE")
    if work_order["base_sha"] is not None and provider_base_sha != work_order["base_sha"]:
        return Result(Decision.HOLD, "STALE_BASE_AFTER_LEASE")
    return Result(Decision.ALLOW, "LEASE_CURRENT")


def dependencies_satisfied(work_order: Mapping[str, Any], receipts: Sequence[Mapping[str, Any]]) -> Result:
    observed: dict[tuple[str, str], set[str]] = {}
    for row in receipts:
        key = (str(row.get("work_order_id") or ""), str(row.get("work_order_digest") or ""))
        observed.setdefault(key, set()).add(str(row.get("terminal") or ""))
    for dep in work_order.get("dependencies", []):
        key = (dep["work_order_id"], dep["work_order_digest"])
        if dep["required_terminal"] not in observed.get(key, set()):
            return Result(Decision.HOLD, "DEPENDENCY_UNSATISFIED", (dep["work_order_id"],))
    return Result(Decision.ALLOW, "DEPENDENCIES_SATISFIED")


def coordinate_m1_admission(work_order: Mapping[str, Any], *, existing_work_admission_passed: bool,
                            baseline_verified: bool, provider_base_sha: str | None,
                            terminal_dependency_receipts: Sequence[Mapping[str, Any]] = (),
                            active_leases: Sequence[tuple[Mapping[str, Any], Mapping[str, Any]]] = ()) -> Result:
    valid = validate_work_order_m1(work_order)
    if not valid.ok:
        return valid
    if not existing_work_admission_passed:
        return Result(Decision.HOLD, "EXISTING_WORK_ADMISSION_REQUIRED")
    if not baseline_verified:
        return Result(Decision.HOLD, "BASELINE_NOT_VERIFIED")
    if work_order["base_sha"] is not None and provider_base_sha != work_order["base_sha"]:
        return Result(Decision.HOLD, "PROVIDER_BASE_MISMATCH")
    deps = dependencies_satisfied(work_order, terminal_dependency_receipts)
    if not deps.ok:
        return deps
    for lease, leased_wo in active_leases:
        relation = validate_lease_against_work_order(lease, leased_wo)
        if relation.ok and lease.get("status") == "ACTIVE" and conflict_sets_overlap(work_order["conflict_keys"], lease["conflict_keys"]):
            return Result(Decision.SERIALIZE, "ACTIVE_LEASE_CONFLICT", (str(lease.get("lease_id")),))
    return Result(Decision.ALLOW, "M1_COORDINATION_ALLOW")


def validate_scope_observation(work_order: Mapping[str, Any], *, observed_writes: Sequence[str], observed_effects: Sequence[str]) -> Result:
    valid = validate_work_order_m1(work_order)
    if not valid.ok:
        return valid
    extra = sorted(set(observed_writes) - set(work_order["write_set"]))
    if extra:
        return Result(Decision.REJECT, "SCOPE_EXPANSION_REQUIRED", tuple(extra))
    if observed_effects:
        return Result(Decision.REJECT, "EFFECT_SCOPE_ESCALATION", tuple(sorted(set(observed_effects))))
    return Result(Decision.ALLOW, "OBSERVED_SCOPE_WITHIN_CONTRACT")


def validate_verification_receipt(receipt: Mapping[str, Any], work_order: Mapping[str, Any], *, worker_output_digest: str) -> Result:
    if not isinstance(receipt, Mapping) or set(receipt) != VERIFICATION_REQUIRED:
        return Result(Decision.HOLD, "VERIFICATION_FIELDS")
    try:
        if receipt["schema"] != VERIFICATION_SCHEMA:
            return Result(Decision.HOLD, "VERIFICATION_VERSION")
        if receipt["work_order_id"] != work_order["work_order_id"] or receipt["work_order_digest"] != work_order_digest(work_order):
            return Result(Decision.HOLD, "VERIFY_WORK_ORDER_MISMATCH")
        _digest(worker_output_digest, "worker_output_digest")
        if receipt["worker_output_digest"] != worker_output_digest:
            return Result(Decision.HOLD, "VERIFY_OUTPUT_DIGEST_MISMATCH")
        if receipt["worker_run_id"] == receipt["verifier_run_id"]:
            return Result(Decision.REJECT, "SELF_VERIFICATION")
        if receipt["verifier_context_isolated"] is not True or receipt["worker_hidden_scratch_shared"] is not False:
            return Result(Decision.REJECT, "VERIFIER_NOT_ISOLATED")
        if receipt["worker_conclusion_inherited_as_fact"] is not False or dict(receipt["authority"]) != M1_AUTHORITY:
            return Result(Decision.REJECT, "VERIFIER_AUTHORITY_OR_CONCLUSION_INHERITANCE")
        _time(receipt["observed_at"], "observed_at"); _digest(receipt["evidence_digest"], "evidence_digest"); _digest(receipt["findings_digest"], "findings_digest")
        conditions = _list(receipt["conditions"], "conditions")
        status = receipt["status"]
        if status == "PASS" and conditions:
            return Result(Decision.HOLD, "PASS_CONDITIONS_MUST_BE_EMPTY")
        if status == "PASS_WITH_CONDITIONS" and not conditions:
            return Result(Decision.HOLD, "PASS_WITH_CONDITIONS_MISSING_CONDITIONS")
        if status == "REJECT":
            return Result(Decision.REJECT, "VERIFIER_REJECT")
        if status == "REVISE":
            return Result(Decision.HOLD, "VERIFIER_REVISE")
        if status not in {"PASS", "PASS_WITH_CONDITIONS"}:
            return Result(Decision.HOLD, "VERIFICATION_STATUS")
    except (TypeError, ValueError) as exc:
        return Result(Decision.HOLD, "VERIFICATION_INVALID", (str(exc),))
    return Result(Decision.ALLOW, "INDEPENDENT_VERIFICATION_ACCEPTED")


def validate_fanin(required_shards: Sequence[str], outputs: Sequence[Mapping[str, Any]]) -> Result:
    seen: dict[str, str] = {}
    for row in outputs:
        sid, digest = str(row.get("shard_id") or ""), str(row.get("output_digest") or row.get("digest") or "")
        if not sid or not SHA64.fullmatch(digest):
            return Result(Decision.HOLD, "INVALID_SHARD_OUTPUT")
        if sid in seen and seen[sid] != digest:
            return Result(Decision.HOLD, "DUPLICATE_INCOMPATIBLE_SHARD", (sid,))
        seen[sid] = digest
    missing = sorted(set(required_shards) - set(seen))
    return Result(Decision.HOLD, "JOIN_WITH_MISSING_SHARD", tuple(missing)) if missing else Result(Decision.ALLOW, "FANIN_COMPLETE")


def validate_fanout_group(fanout: Mapping[str, Any], work_orders: Sequence[Mapping[str, Any]]) -> Result:
    if not isinstance(fanout, Mapping) or fanout.get("schema") != FANOUT_SCHEMA:
        return Result(Decision.HOLD, "FANOUT_VERSION")
    by_id = {str(w.get("work_order_id")): w for w in work_orders}
    shards = fanout.get("shards")
    if not isinstance(shards, list) or fanout.get("expected_shards") != len({s.get("shard_id") for s in shards}):
        return Result(Decision.HOLD, "EXPECTED_SHARDS_MISMATCH")
    seen = {}
    for shard in shards:
        wo = by_id.get(str(shard.get("work_order_id")))
        if wo is None or shard.get("work_order_digest") != work_order_digest(wo):
            return Result(Decision.HOLD, "SHARD_WORK_ORDER_BINDING")
        if sorted(shard.get("scope") or []) != normalized_work_scope(wo) or wo["frozen_input_digest"] != fanout.get("common_input_digest"):
            return Result(Decision.HOLD, "SHARD_SCOPE_OR_INPUT_BINDING")
        ident = (shard.get("work_order_id"), shard.get("work_order_digest"), tuple(sorted(shard.get("scope") or [])), shard.get("worker_run_id"), shard.get("output_digest"))
        sid = str(shard.get("shard_id"))
        if sid in seen and (fanout.get("duplicate_shard_policy") != "EXACT_DUPLICATE_COLLAPSE" or seen[sid] != ident):
            return Result(Decision.HOLD, "DUPLICATE_SHARD_INCOMPATIBLE")
        seen[sid] = ident
    if fanout.get("status") in {"FANIN_READY", "COMPLETE"} and any(s.get("worker_run_id") is None or s.get("output_digest") is None for s in shards):
        return Result(Decision.HOLD, "FANIN_OUTPUT_BINDING_MISSING")
    return Result(Decision.ALLOW, "FANOUT_RELATIONS_VALID")


def build_coordination_event(*, event_type: str, work_order: Mapping[str, Any], run_id: str,
                             observed_at: str, payload: Mapping[str, Any], previous_event_sha256: str | None) -> dict[str, Any]:
    if not validate_work_order_m1(work_order).ok:
        raise ValueError("invalid work order")
    _text(event_type, "event_type"); _text(run_id, "run_id"); _time(observed_at, "observed_at")
    if previous_event_sha256 is not None:
        _digest(previous_event_sha256, "previous_event_sha256")
    event = {
        "schema": COORDINATION_EVENT_SCHEMA, "event_type": event_type,
        "work_order_id": work_order["work_order_id"], "work_order_digest": work_order_digest(work_order),
        "run_id": run_id, "observed_at": observed_at, "previous_event_sha256": previous_event_sha256,
        "payload": dict(payload), "payload_digest": sha256_document(dict(payload)),
        "canonical_work_ledger_required": True, "authority": dict(M1_AUTHORITY),
    }
    event["event_sha256"] = sha256_document(event)
    return event


def verify_coordination_event(event: Mapping[str, Any]) -> Result:
    try:
        if event.get("schema") != COORDINATION_EVENT_SCHEMA or event.get("canonical_work_ledger_required") is not True:
            return Result(Decision.REJECT, "SECOND_LEDGER_AUTHORITY_ATTEMPT")
        if dict(event.get("authority") or {}) != M1_AUTHORITY:
            return Result(Decision.REJECT, "EVENT_AUTHORITY_ESCALATION")
        if event.get("payload_digest") != sha256_document(event.get("payload")):
            return Result(Decision.HOLD, "EVENT_PAYLOAD_DIGEST_MISMATCH")
        body = dict(event); digest = body.pop("event_sha256")
        if not SHA64.fullmatch(str(digest)) or digest != sha256_document(body):
            return Result(Decision.HOLD, "EVENT_DIGEST_MISMATCH")
    except (TypeError, ValueError, KeyError) as exc:
        return Result(Decision.HOLD, "EVENT_INVALID", (str(exc),))
    return Result(Decision.ALLOW, "EVENT_VALID")


def project_fleet_current(*, handoff_revision: int, provider_observed_at: str,
                          active_work_orders: Sequence[Mapping[str, Any]], agent_registry: Sequence[Mapping[str, Any]],
                          active_leases: Sequence[Mapping[str, Any]], dependency_dag: Sequence[Mapping[str, Any]],
                          run_output_index: Sequence[Mapping[str, Any]], verification_queue: Sequence[Mapping[str, Any]],
                          integration_queue: Sequence[Mapping[str, Any]], stale_base_events: Sequence[Mapping[str, Any]] = (),
                          conflict_events: Sequence[Mapping[str, Any]] = (), supersession_events: Sequence[Mapping[str, Any]] = (),
                          last_provider_observations: Sequence[Mapping[str, Any]] = ()) -> dict[str, Any]:
    if not isinstance(handoff_revision, int) or isinstance(handoff_revision, bool) or handoff_revision < 1:
        raise ValueError("handoff_revision invalid")
    _time(provider_observed_at, "provider_observed_at")
    source = {"active_work_orders": list(active_work_orders), "agent_registry": list(agent_registry),
              "active_leases": list(active_leases), "dependency_dag": list(dependency_dag),
              "run_output_index": list(run_output_index), "verification_queue": list(verification_queue),
              "integration_queue": list(integration_queue), "stale_base_events": list(stale_base_events),
              "conflict_events": list(conflict_events), "supersession_events": list(supersession_events),
              "last_provider_observations": list(last_provider_observations)}
    keys = sorted({k for w in active_work_orders if isinstance(w, Mapping) for k in w.get("conflict_keys", []) if isinstance(k, str)})
    return {"schema": CURRENT_PROJECTION_SCHEMA, "handoff_revision": handoff_revision,
            "provider_observed_at": provider_observed_at, "projection_source_digest": sha256_document(source),
            **source, "conflict_keys": keys, "effect_queue": [], "authority": dict(PROJECTION_AUTHORITY),
            "resolver_contract": RESOLVER_CONTRACT}


def sequential_habitat_ready(researcher: Mapping[str, Any], builder: Mapping[str, Any], critic: Mapping[str, Any]) -> Result:
    for name, work in (("RESEARCHER", researcher), ("BUILDER", builder), ("CRITIC", critic)):
        result = validate_work_order_m1(work)
        if not result.ok:
            return Result(result.decision, name + "_" + result.reason)
    pairs = ((builder, researcher, "BUILDER_NOT_BOUND_TO_RESEARCHER"), (critic, builder, "CRITIC_NOT_BOUND_TO_BUILDER"))
    for child, parent, reason in pairs:
        if not any(d["work_order_id"] == parent["work_order_id"] and d["work_order_digest"] == work_order_digest(parent) for d in child["dependencies"]):
            return Result(Decision.HOLD, reason)
    return Result(Decision.ALLOW, "SEQUENTIAL_HABITAT_READY")


def checkpoint_recovery_guard(lease: Mapping[str, Any], *, worker_observed: bool, frozen_output_digest: str | None) -> Result:
    if not worker_observed:
        cp = lease.get("checkpoint_digest") if isinstance(lease, Mapping) else None
        details = ("preserved_checkpoint=" + cp,) if isinstance(cp, str) and SHA64.fullmatch(cp) else ()
        return Result(Decision.HOLD, "WORKER_NOT_OBSERVED_NO_OUTPUT_INFERENCE", details)
    if frozen_output_digest is None or not SHA64.fullmatch(frozen_output_digest):
        return Result(Decision.HOLD, "OUTPUT_NOT_FROZEN")
    return Result(Decision.ALLOW, "RECOVERY_INPUTS_EXPLICIT")


def future_effect_currentness_guard(*, provider_state_unchanged: bool, owner_gate_current: bool) -> Result:
    if not provider_state_unchanged:
        return Result(Decision.HOLD, "PROVIDER_STATE_CHANGED_BEFORE_EFFECT")
    if not owner_gate_current:
        return Result(Decision.HOLD, "STALE_OWNER_GATE_AFTER_CAPABILITY_CHANGE")
    return Result(Decision.HOLD, "M1_EFFECTS_NOT_AVAILABLE")


def staging_visibility_guard(*, previously_visible: bool, jit_visible: bool) -> Result:
    if previously_visible and not jit_visible:
        return Result(Decision.HOLD, "STAGING_VISIBILITY_REVERSAL")
    return Result(Decision.HOLD, "M1_DESTRUCTIVE_STORAGE_NOT_AVAILABLE")
