"""Public Governed Fleet M1 API with fail-closed relational hardening.

The implementation base is private.  This facade strengthens verifier identity,
fan-in exactness and order-independent CURRENT projection while preserving the
same effect-free authority ceiling.
"""
from __future__ import annotations

from typing import Any, Mapping, Sequence

from ._fleet_coordination_impl import *  # noqa: F403
from . import _fleet_coordination_impl as _base


def validate_verification_receipt(
    receipt: Mapping[str, Any], work_order: Mapping[str, Any], *, worker_output_digest: str
) -> Result:  # noqa: F405
    try:
        if isinstance(receipt, Mapping):
            _base._text(receipt.get("verification_id"), "verification_id")
            _base._text(receipt.get("worker_run_id"), "worker_run_id")
            _base._text(receipt.get("verifier_run_id"), "verifier_run_id")
    except (TypeError, ValueError) as exc:
        return Result(Decision.HOLD, "VERIFICATION_INVALID", (str(exc),))  # noqa: F405
    return _base.validate_verification_receipt(
        receipt, work_order, worker_output_digest=worker_output_digest
    )


def validate_fanin(
    required_shards: Sequence[str], outputs: Sequence[Mapping[str, Any]]
) -> Result:  # noqa: F405
    required = list(required_shards)
    if not required or not all(isinstance(item, str) and item for item in required):
        return Result(Decision.HOLD, "INVALID_REQUIRED_SHARDS")  # noqa: F405
    if len(required) != len(set(required)):
        return Result(Decision.HOLD, "DUPLICATE_REQUIRED_SHARD")  # noqa: F405
    seen: dict[str, str] = {}
    for row in outputs:
        sid = str(row.get("shard_id") or "")
        digest = str(row.get("output_digest") or row.get("digest") or "")
        if not sid or not _base.SHA64.fullmatch(digest):
            return Result(Decision.HOLD, "INVALID_SHARD_OUTPUT")  # noqa: F405
        if sid in seen and seen[sid] != digest:
            return Result(Decision.HOLD, "DUPLICATE_INCOMPATIBLE_SHARD", (sid,))  # noqa: F405
        seen[sid] = digest
    missing = sorted(set(required) - set(seen))
    if missing:
        return Result(Decision.HOLD, "JOIN_WITH_MISSING_SHARD", tuple(missing))  # noqa: F405
    unexpected = sorted(set(seen) - set(required))
    if unexpected:
        return Result(Decision.HOLD, "JOIN_WITH_UNEXPECTED_SHARD", tuple(unexpected))  # noqa: F405
    return Result(Decision.ALLOW, "FANIN_COMPLETE")  # noqa: F405


def _canonical_rows(rows: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    normalized = [dict(row) for row in rows]
    return sorted(normalized, key=_base.canonical_json_text)


def project_fleet_current(
    *, handoff_revision: int, provider_observed_at: str,
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
    if not isinstance(handoff_revision, int) or isinstance(handoff_revision, bool) or handoff_revision < 1:
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
