"""Canonical Governed Fleet M1 facade with fail-closed semantic hardening.

The implementation core is byte-stable across the initial M1 candidate.  This
facade strengthens verifier identity, fan-in exactness, and CURRENT projection
order determinism without adding any execution/effect capability.
"""
from __future__ import annotations

from typing import Any, Mapping, Sequence

from . import fleet_coordination_core as _core
from .fleet_coordination_core import *  # noqa: F401,F403


def validate_verification_receipt(
    receipt: Mapping[str, Any],
    work_order: Mapping[str, Any],
    *,
    worker_output_digest: str,
) -> Result:
    for key in ("verification_id", "worker_run_id", "verifier_run_id"):
        value = receipt.get(key) if isinstance(receipt, Mapping) else None
        if not isinstance(value, str) or not value.strip():
            return Result(Decision.HOLD, "VERIFICATION_INVALID", (f"{key} must be non-empty",))
    return _core.validate_verification_receipt(
        receipt, work_order, worker_output_digest=worker_output_digest
    )


def validate_fanin(
    required_shards: Sequence[str], outputs: Sequence[Mapping[str, Any]]
) -> Result:
    required = set(required_shards)
    observed = {
        str(row.get("shard_id") or "")
        for row in outputs
        if isinstance(row, Mapping)
    }
    unexpected = sorted(observed - required)
    if unexpected:
        return Result(Decision.HOLD, "JOIN_WITH_UNEXPECTED_SHARD", tuple(unexpected))
    return _core.validate_fanin(required_shards, outputs)


def _canonical_rows(rows: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    normalized = [dict(row) for row in rows]
    return sorted(normalized, key=canonical_json_text)


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
    return _core.project_fleet_current(
        handoff_revision=handoff_revision,
        provider_observed_at=provider_observed_at,
        active_work_orders=_canonical_rows(active_work_orders),
        agent_registry=_canonical_rows(agent_registry),
        active_leases=_canonical_rows(active_leases),
        dependency_dag=_canonical_rows(dependency_dag),
        run_output_index=_canonical_rows(run_output_index),
        verification_queue=_canonical_rows(verification_queue),
        integration_queue=_canonical_rows(integration_queue),
        stale_base_events=_canonical_rows(stale_base_events),
        conflict_events=_canonical_rows(conflict_events),
        supersession_events=_canonical_rows(supersession_events),
        last_provider_observations=_canonical_rows(last_provider_observations),
    )
