"""Production bindings for authenticated Human merge approvals.

R19 keeps the strict single-host SQLite binding. R23 adds a separate PostgreSQL
multi-host replay authority. Neither path falls back to memory or executes merge,
deploy, runtime, trading, capital, or other external effects.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from .durable_approval_replay import SQLiteApprovalReplayGuard
from .multi_host_approval_replay import MULTI_HOST, PostgresApprovalReplayAuthority
from .witnessed_approval_replay import (
    ROLLBACK_PROTECTION, PostgresWitnessedApprovalReplayAuthority,
)
from .persistent_governance_store import resolve_persistent_governance_store_path
from .trusted_human_approval import HumanApprovalResult, verify_and_consume_human_approval

DEFAULT_BUSY_TIMEOUT_MS = 30_000
SINGLE_HOST = "SINGLE_HOST"


def _production_replay_path(value: str | Path) -> Path:
    return resolve_persistent_governance_store_path(
        value, label="production human approval", field="replay_db_path"
    )


def _execution_host_count(value: object) -> int:
    if type(value) is not int or value < 1 or value > 1_000_000:
        raise ValueError("production human approval: invalid execution_host_count")
    return value


def build_production_replay_guard(
    *, replay_db_path: str | Path, busy_timeout_ms: int = DEFAULT_BUSY_TIMEOUT_MS,
) -> SQLiteApprovalReplayGuard:
    """Build the R19 SINGLE_HOST replay backend only."""
    replay_path = _production_replay_path(replay_db_path)
    guard = SQLiteApprovalReplayGuard(replay_path, busy_timeout_ms=busy_timeout_ms)
    if guard.replay_scope != SINGLE_HOST:
        raise RuntimeError("production human approval: SQLite replay scope drift")
    return guard


def build_multi_host_production_replay_authority(
    *, replay_dsn: str, replay_namespace: str = "human-approval",
) -> PostgresApprovalReplayAuthority:
    """Build the R23 MULTI_HOST PostgreSQL replay authority only."""
    authority = PostgresApprovalReplayAuthority(
        replay_dsn, namespace=replay_namespace
    )
    if authority.replay_scope != MULTI_HOST:
        raise RuntimeError("production human approval: multi-host replay scope drift")
    return authority


def build_witnessed_multi_host_production_replay_authority(
    *, replay_dsn: str, replay_witness: Any, replay_namespace: str = "human-approval",
) -> PostgresWitnessedApprovalReplayAuthority:
    """Build the R24 rollback/tamper-aware MULTI_HOST replay authority."""
    authority = PostgresWitnessedApprovalReplayAuthority(
        replay_dsn, witness=replay_witness, namespace=replay_namespace
    )
    if authority.replay_scope != MULTI_HOST:
        raise RuntimeError("production human approval: multi-host replay scope drift")
    if authority.rollback_protection != ROLLBACK_PROTECTION:
        raise RuntimeError("production human approval: rollback protection drift")
    return authority


def verify_and_consume_human_approval_production(
    *,
    replay_db_path: str | Path,
    request_receipt: Any,
    approval_envelope: Any,
    trusted_key_registry: Any,
    pinned_registry_sha256: str,
    repository: str,
    current_base_sha: str,
    current_head_sha: str,
    current_tree_sha: str,
    now_unix: int,
    busy_timeout_ms: int = DEFAULT_BUSY_TIMEOUT_MS,
    execution_host_count: int = 1,
) -> HumanApprovalResult:
    """Verify one approval with explicit SINGLE_HOST replay state."""
    if _execution_host_count(execution_host_count) != 1:
        raise ValueError(
            "production human approval: MULTI_HOST replay required for topology > 1"
        )
    guard = build_production_replay_guard(
        replay_db_path=replay_db_path, busy_timeout_ms=busy_timeout_ms
    )
    return verify_and_consume_human_approval(
        request_receipt=request_receipt,
        approval_envelope=approval_envelope,
        trusted_key_registry=trusted_key_registry,
        pinned_registry_sha256=pinned_registry_sha256,
        repository=repository,
        current_base_sha=current_base_sha,
        current_head_sha=current_head_sha,
        current_tree_sha=current_tree_sha,
        now_unix=now_unix,
        replay_guard=guard,
    )


def verify_and_consume_human_approval_production_multi_host(
    *,
    replay_dsn: str,
    replay_namespace: str,
    execution_host_count: int,
    request_receipt: Any,
    approval_envelope: Any,
    trusted_key_registry: Any,
    pinned_registry_sha256: str,
    repository: str,
    current_base_sha: str,
    current_head_sha: str,
    current_tree_sha: str,
    now_unix: int,
) -> HumanApprovalResult:
    """Verify one approval with shared MULTI_HOST PostgreSQL replay state."""
    if _execution_host_count(execution_host_count) < 2:
        raise ValueError(
            "production human approval: multi-host binding requires topology > 1"
        )
    authority = build_multi_host_production_replay_authority(
        replay_dsn=replay_dsn, replay_namespace=replay_namespace
    )
    return verify_and_consume_human_approval(
        request_receipt=request_receipt,
        approval_envelope=approval_envelope,
        trusted_key_registry=trusted_key_registry,
        pinned_registry_sha256=pinned_registry_sha256,
        repository=repository,
        current_base_sha=current_base_sha,
        current_head_sha=current_head_sha,
        current_tree_sha=current_tree_sha,
        now_unix=now_unix,
        replay_guard=authority,
    )


def verify_and_consume_human_approval_production_multi_host_witnessed(
    *, replay_dsn: str, replay_witness: Any, replay_namespace: str,
    execution_host_count: int, request_receipt: Any, approval_envelope: Any,
    trusted_key_registry: Any, pinned_registry_sha256: str, repository: str,
    current_base_sha: str, current_head_sha: str, current_tree_sha: str,
    now_unix: int,
) -> HumanApprovalResult:
    """Verify one approval with R24 external-witness rollback protection."""
    if _execution_host_count(execution_host_count) < 2:
        raise ValueError(
            "production human approval: witnessed multi-host binding requires topology > 1"
        )
    authority = build_witnessed_multi_host_production_replay_authority(
        replay_dsn=replay_dsn, replay_witness=replay_witness,
        replay_namespace=replay_namespace,
    )
    return verify_and_consume_human_approval(
        request_receipt=request_receipt, approval_envelope=approval_envelope,
        trusted_key_registry=trusted_key_registry,
        pinned_registry_sha256=pinned_registry_sha256, repository=repository,
        current_base_sha=current_base_sha, current_head_sha=current_head_sha,
        current_tree_sha=current_tree_sha, now_unix=now_unix,
        replay_guard=authority,
    )


__all__ = [
    "DEFAULT_BUSY_TIMEOUT_MS", "SINGLE_HOST", "MULTI_HOST",
    "build_production_replay_guard", "build_multi_host_production_replay_authority",
    "build_witnessed_multi_host_production_replay_authority",
    "verify_and_consume_human_approval_production",
    "verify_and_consume_human_approval_production_multi_host",
    "verify_and_consume_human_approval_production_multi_host_witnessed",
]
