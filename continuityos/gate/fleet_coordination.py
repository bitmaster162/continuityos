"""Public Governed Fleet M1 API with fail-closed relational hardening.

The implementation base is private and is not an authority surface.  This
facade is the supported API.  It strengthens lease evidence, verifier identity,
fan-out/fan-in exactness and order-independent CURRENT projection while
preserving the same effect-free authority ceiling.
"""
from __future__ import annotations

from typing import Any, Mapping, Sequence

from ._fleet_coordination_impl import *  # noqa: F403
from . import _fleet_coordination_impl as _base

__all__ = [
    "WORK_ORDER_SCHEMA", "WORK_LEASE_SCHEMA", "FANOUT_SCHEMA",
    "VERIFICATION_SCHEMA", "CURRENT_PROJECTION_SCHEMA",
    "COORDINATION_EVENT_SCHEMA", "DIGEST_CONTRACT", "RESOLVER_CONTRACT",
    "M1_AUTHORITY", "PROJECTION_AUTHORITY", "Decision", "Result",
    "canonical_json_text", "sha256_document", "work_order_digest",
    "normalized_work_scope", "validate_conflict_key", "conflict_keys_conflict",
    "conflict_sets_overlap", "validate_work_order_m1",
    "validate_lease_against_work_order", "lease_currentness",
    "dependencies_satisfied", "coordinate_m1_admission",
    "validate_scope_observation", "validate_verification_receipt",
    "validate_fanin", "validate_fanout_group", "build_coordination_event",
    "verify_coordination_event", "project_fleet_current",
    "sequential_habitat_ready", "checkpoint_recovery_guard",
    "future_effect_currentness_guard", "staging_visibility_guard",
]

_LEASE_STATUSES = {
    "REQUESTED", "ACTIVE", "EXPIRED", "RELEASED", "REVOKED", "CONFLICTED"
}
_FANOUT_STATUSES = {"PLANNED", "ADMITTED", "RUNNING", "FANIN_READY", "COMPLETE", "HOLD"}
_FANOUT_CONFLICT_POLICIES = {"REJECT", "SERIALIZE", "EXPLICIT_COMPATIBLE_JOIN_ONLY"}
_FANOUT_DUPLICATE_POLICIES = {"REJECT_INCOMPATIBLE", "EXACT_DUPLICATE_COLLAPSE"}
_FANOUT_REQUIRED = {
    "schema", "fanout_group_id", "common_input_digest", "expected_shards",
    "shards", "join_key", "conflict_policy", "missing_shard_policy",
    "duplicate_shard_policy", "fanin_acceptance_schema", "status",
}
_SHARD_REQUIRED = {
    "shard_id", "work_order_id", "work_order_digest", "scope",
    "worker_run_id", "output_digest",
}


def validate_lease_against_work_order(
    lease: Mapping[str, Any],
    work_order: Mapping[str, Any],
    *,
    observed_at: str | None = None,
) -> Result:  # noqa: F405
    work_result = _base.validate_work_order_m1(work_order)
    if not work_result.ok:
        return work_result
    if not isinstance(lease, Mapping) or set(lease) != _base.LEASE_REQUIRED:
        return Result(Decision.HOLD, "LEASE_FIELDS")  # noqa: F405
    try:
        _base._text(lease.get("lease_id"), "lease_id")
        _base._text(lease.get("work_order_id"), "work_order_id")
        _base._text(lease.get("agent_run_id"), "agent_run_id")
        status = _base._text(lease.get("status"), "status")
        if status not in _LEASE_STATUSES:
            return Result(Decision.HOLD, "LEASE_STATUS")  # noqa: F405

        scope = _base._list(lease.get("resource_scope"), "resource_scope")
        if not scope:
            return Result(Decision.HOLD, "LEASE_SCOPE_EMPTY")  # noqa: F405
        conflicts = _base._list(lease.get("conflict_keys"), "conflict_keys")
        for key in conflicts:
            _base.validate_conflict_key(key)

        checkpoint_ref = lease.get("checkpoint_ref")
        if checkpoint_ref is not None:
            _base._text(checkpoint_ref, "checkpoint_ref")
    except (TypeError, ValueError) as exc:
        return Result(Decision.HOLD, "LEASE_INVALID", (str(exc),))  # noqa: F405

    return _base.validate_lease_against_work_order(
        lease, work_order, observed_at=observed_at
    )


def lease_currentness(
    lease: Mapping[str, Any],
    work_order: Mapping[str, Any],
    *,
    observed_at: str,
    provider_base_sha: str | None,
) -> Result:  # noqa: F405
    relation = validate_lease_against_work_order(
        lease, work_order, observed_at=observed_at
    )
    if not relation.ok:
        return relation
    if lease["status"] != "ACTIVE":
        return Result(Decision.HOLD, "LEASE_NOT_ACTIVE")  # noqa: F405
    if work_order["base_sha"] is not None and provider_base_sha != work_order["base_sha"]:
        return Result(Decision.HOLD, "STALE_BASE_AFTER_LEASE")  # noqa: F405
    return Result(Decision.ALLOW, "LEASE_CURRENT")  # noqa: F405


def coordinate_m1_admission(
    work_order: Mapping[str, Any],
    *,
    existing_work_admission_passed: bool,
    baseline_verified: bool,
    provider_base_sha: str | None,
    terminal_dependency_receipts: Sequence[Mapping[str, Any]] = (),
    active_leases: Sequence[tuple[Mapping[str, Any], Mapping[str, Any]]] = (),
) -> Result:  # noqa: F405
    valid = _base.validate_work_order_m1(work_order)
    if not valid.ok:
        return valid
    if existing_work_admission_passed is not True:
        return Result(Decision.HOLD, "EXISTING_WORK_ADMISSION_REQUIRED")  # noqa: F405
    if baseline_verified is not True:
        return Result(Decision.HOLD, "BASELINE_NOT_VERIFIED")  # noqa: F405
    if work_order["base_sha"] is not None and provider_base_sha != work_order["base_sha"]:
        return Result(Decision.HOLD, "PROVIDER_BASE_MISMATCH")  # noqa: F405

    deps = _base.dependencies_satisfied(work_order, terminal_dependency_receipts)
    if not deps.ok:
        return deps

    for lease, leased_wo in active_leases:
        relation = validate_lease_against_work_order(lease, leased_wo)
        if not relation.ok:
            lease_id = ""
            if isinstance(lease, Mapping):
                lease_id = str(lease.get("lease_id") or "")
            details = tuple(x for x in (lease_id, relation.reason) if x)
            return Result(
                Decision.HOLD, "ACTIVE_LEASE_EVIDENCE_INVALID", details
            )  # noqa: F405
        if (
            lease["status"] == "ACTIVE"
            and _base.conflict_sets_overlap(
                work_order["conflict_keys"], lease["conflict_keys"]
            )
        ):
            return Result(
                Decision.SERIALIZE,
                "ACTIVE_LEASE_CONFLICT",
                (str(lease["lease_id"]),),
            )  # noqa: F405
    return Result(Decision.ALLOW, "M1_COORDINATION_ALLOW")  # noqa: F405


def validate_verification_receipt(
    receipt: Mapping[str, Any],
    work_order: Mapping[str, Any],
    *,
    worker_output_digest: str,
) -> Result:  # noqa: F405
    work_result = _base.validate_work_order_m1(work_order)
    if not work_result.ok:
        return work_result
    try:
        if isinstance(receipt, Mapping):
            _base._text(receipt.get("verification_id"), "verification_id")
            _base._text(receipt.get("worker_run_id"), "worker_run_id")
            _base._text(receipt.get("verifier_run_id"), "verifier_run_id")
    except (TypeError, ValueError) as exc:
        return Result(
            Decision.HOLD, "VERIFICATION_INVALID", (str(exc),)
        )  # noqa: F405
    try:
        return _base.validate_verification_receipt(
            receipt, work_order, worker_output_digest=worker_output_digest
        )
    except (KeyError, TypeError, ValueError) as exc:
        return Result(
            Decision.HOLD, "VERIFICATION_INVALID", (str(exc),)
        )  # noqa: F405


def validate_fanin(
    required_shards: Sequence[str],
    outputs: Sequence[Mapping[str, Any]],
) -> Result:  # noqa: F405
    required = list(required_shards)
    if not required or not all(isinstance(item, str) and item for item in required):
        return Result(Decision.HOLD, "INVALID_REQUIRED_SHARDS")  # noqa: F405
    if len(required) != len(set(required)):
        return Result(Decision.HOLD, "DUPLICATE_REQUIRED_SHARD")  # noqa: F405
    seen: dict[str, str] = {}
    for row in outputs:
        if not isinstance(row, Mapping):
            return Result(Decision.HOLD, "INVALID_SHARD_OUTPUT")  # noqa: F405
        sid = str(row.get("shard_id") or "")
        digest = str(row.get("output_digest") or row.get("digest") or "")
        if not sid or not _base.SHA64.fullmatch(digest):
            return Result(Decision.HOLD, "INVALID_SHARD_OUTPUT")  # noqa: F405
        if sid in seen and seen[sid] != digest:
            return Result(
                Decision.HOLD, "DUPLICATE_INCOMPATIBLE_SHARD", (sid,)
            )  # noqa: F405
        seen[sid] = digest
    missing = sorted(set(required) - set(seen))
    if missing:
        return Result(
            Decision.HOLD, "JOIN_WITH_MISSING_SHARD", tuple(missing)
        )  # noqa: F405
    unexpected = sorted(set(seen) - set(required))
    if unexpected:
        return Result(
            Decision.HOLD, "JOIN_WITH_UNEXPECTED_SHARD", tuple(unexpected)
        )  # noqa: F405
    return Result(Decision.ALLOW, "FANIN_COMPLETE")  # noqa: F405


def validate_fanout_group(
    fanout: Mapping[str, Any],
    work_orders: Sequence[Mapping[str, Any]],
) -> Result:  # noqa: F405
    if not isinstance(fanout, Mapping) or set(fanout) != _FANOUT_REQUIRED:
        return Result(Decision.HOLD, "FANOUT_FIELDS")  # noqa: F405
    try:
        if fanout.get("schema") != _base.FANOUT_SCHEMA:
            return Result(Decision.HOLD, "FANOUT_VERSION")  # noqa: F405
        _base._text(fanout.get("fanout_group_id"), "fanout_group_id")
        _base._digest(fanout.get("common_input_digest"), "common_input_digest")
        _base._text(fanout.get("join_key"), "join_key")
        _base._text(fanout.get("fanin_acceptance_schema"), "fanin_acceptance_schema")
        if fanout.get("missing_shard_policy") != "HOLD":
            return Result(Decision.HOLD, "FANOUT_MISSING_SHARD_POLICY")  # noqa: F405
        if fanout.get("conflict_policy") not in _FANOUT_CONFLICT_POLICIES:
            return Result(Decision.HOLD, "FANOUT_CONFLICT_POLICY")  # noqa: F405
        if fanout.get("duplicate_shard_policy") not in _FANOUT_DUPLICATE_POLICIES:
            return Result(Decision.HOLD, "FANOUT_DUPLICATE_POLICY")  # noqa: F405
        if fanout.get("status") not in _FANOUT_STATUSES:
            return Result(Decision.HOLD, "FANOUT_STATUS")  # noqa: F405

        expected = fanout.get("expected_shards")
        if (
            not isinstance(expected, int)
            or isinstance(expected, bool)
            or expected < 1
        ):
            return Result(Decision.HOLD, "EXPECTED_SHARDS_INVALID")  # noqa: F405

        shards = fanout.get("shards")
        if not isinstance(shards, list) or not shards:
            return Result(Decision.HOLD, "FANOUT_SHARDS")  # noqa: F405

        by_id: dict[str, Mapping[str, Any]] = {}
        for work_order in work_orders:
            work_result = _base.validate_work_order_m1(work_order)
            if not work_result.ok:
                return Result(
                    Decision.HOLD,
                    "FANOUT_WORK_ORDER_INVALID",
                    (work_result.reason,),
                )  # noqa: F405
            wid = work_order["work_order_id"]
            if wid in by_id:
                return Result(
                    Decision.HOLD, "FANOUT_DUPLICATE_WORK_ORDER_ID", (wid,)
                )  # noqa: F405
            by_id[wid] = work_order

        seen: dict[str, tuple[Any, ...]] = {}
        for shard in shards:
            if not isinstance(shard, Mapping) or set(shard) != _SHARD_REQUIRED:
                return Result(Decision.HOLD, "SHARD_FIELDS")  # noqa: F405
            sid = _base._text(shard.get("shard_id"), "shard_id")
            wid = _base._text(shard.get("work_order_id"), "shard.work_order_id")
            digest = _base._digest(
                shard.get("work_order_digest"), "shard.work_order_digest"
            )
            scope = _base._list(shard.get("scope"), "shard.scope")
            if not scope:
                return Result(Decision.HOLD, "SHARD_SCOPE_EMPTY", (sid,))  # noqa: F405

            worker_run_id = shard.get("worker_run_id")
            if worker_run_id is not None:
                worker_run_id = _base._text(worker_run_id, "worker_run_id")
            output_digest = shard.get("output_digest")
            if output_digest is not None:
                output_digest = _base._digest(output_digest, "output_digest")

            work_order = by_id.get(wid)
            if work_order is None or digest != _base.work_order_digest(work_order):
                return Result(
                    Decision.HOLD, "SHARD_WORK_ORDER_BINDING", (sid,)
                )  # noqa: F405
            if (
                sorted(scope) != _base.normalized_work_scope(work_order)
                or work_order["frozen_input_digest"] != fanout["common_input_digest"]
            ):
                return Result(
                    Decision.HOLD, "SHARD_SCOPE_OR_INPUT_BINDING", (sid,)
                )  # noqa: F405

            ident = (
                wid, digest, tuple(sorted(scope)), worker_run_id, output_digest
            )
            if sid in seen:
                if (
                    fanout["duplicate_shard_policy"] != "EXACT_DUPLICATE_COLLAPSE"
                    or seen[sid] != ident
                ):
                    return Result(
                        Decision.HOLD, "DUPLICATE_SHARD_INCOMPATIBLE", (sid,)
                    )  # noqa: F405
            else:
                seen[sid] = ident

        if expected != len(seen):
            return Result(Decision.HOLD, "EXPECTED_SHARDS_MISMATCH")  # noqa: F405

        if fanout["status"] in {"FANIN_READY", "COMPLETE"}:
            for shard in shards:
                if shard["worker_run_id"] is None or shard["output_digest"] is None:
                    return Result(
                        Decision.HOLD, "FANIN_OUTPUT_BINDING_MISSING",
                        (str(shard["shard_id"]),),
                    )  # noqa: F405
    except (KeyError, TypeError, ValueError) as exc:
        return Result(Decision.HOLD, "FANOUT_INVALID", (str(exc),))  # noqa: F405

    return Result(Decision.ALLOW, "FANOUT_RELATIONS_VALID")  # noqa: F405


def _canonical_rows(rows: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    normalized = [dict(row) for row in rows]
    return sorted(normalized, key=_base.canonical_json_text)


def project_fleet_current(
    *,
    handoff_revision: int,
    provider_observed_at: str,
    active_work_orders: Sequence[Mapping[str, Any]],
    agent_registry: Sequence[Mapping[str, Any]],
    active_leases: Sequence[Mapping[str, Any]],
    dependency_dag: Sequence[Mapping[str, Any]],
    run_output_index: Sequence[Mapping[str, Any]],
    verification_queue: Sequence[Mapping[str, Any]],
    integration_queue: Sequence[Mapping[str, Any]],
    stale_base_events: Sequence[Mapping[str, Any]] = (),
    conflict_events: Sequence[Mapping[str, Any]] = (),
    supersession_events: Sequence[Mapping[str, Any]] = (),
    last_provider_observations: Sequence[Mapping[str, Any]] = (),
) -> dict[str, Any]:
    if (
        not isinstance(handoff_revision, int)
        or isinstance(handoff_revision, bool)
        or handoff_revision < 1
    ):
        raise ValueError("handoff_revision invalid")
    _base._time(provider_observed_at, "provider_observed_at")
    source = {
        "active_work_orders": _canonical_rows(active_work_orders),
        "agent_registry": _canonical_rows(agent_registry),
        "active_leases": _canonical_rows(active_leases),
        "dependency_dag": _canonical_rows(dependency_dag),
        "run_output_index": _canonical_rows(run_output_index),
        "verification_queue": _canonical_rows(verification_queue),
        "integration_queue": _canonical_rows(integration_queue),
        "stale_base_events": _canonical_rows(stale_base_events),
        "conflict_events": _canonical_rows(conflict_events),
        "supersession_events": _canonical_rows(supersession_events),
        "last_provider_observations": _canonical_rows(last_provider_observations),
    }
    keys = sorted({
        key
        for work in active_work_orders
        if isinstance(work, Mapping)
        for key in work.get("conflict_keys", [])
        if isinstance(key, str)
    })
    return {
        "schema": CURRENT_PROJECTION_SCHEMA,  # noqa: F405
        "handoff_revision": handoff_revision,
        "provider_observed_at": provider_observed_at,
        "projection_source_digest": _base.sha256_document(source),
        **source,
        "conflict_keys": keys,
        "effect_queue": [],
        "authority": dict(PROJECTION_AUTHORITY),  # noqa: F405
        "resolver_contract": RESOLVER_CONTRACT,  # noqa: F405
    }
