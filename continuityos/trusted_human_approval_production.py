"""Durable production binding for authenticated Human merge approvals.

R19 composes the R17 verifier with the R18 file-backed SQLite replay guard.
It deliberately has no in-memory fallback and does not execute merge, deploy,
runtime, trading, capital, or other external effects.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from .durable_approval_replay import SQLiteApprovalReplayGuard
from .persistent_governance_store import resolve_persistent_governance_store_path
from .trusted_human_approval import HumanApprovalResult, verify_and_consume_human_approval

DEFAULT_BUSY_TIMEOUT_MS = 30_000


def _production_replay_path(value: str | Path) -> Path:
    return resolve_persistent_governance_store_path(
        value, label="production human approval", field="replay_db_path"
    )


def build_production_replay_guard(
    *,
    replay_db_path: str | Path,
    busy_timeout_ms: int = DEFAULT_BUSY_TIMEOUT_MS,
) -> SQLiteApprovalReplayGuard:
    """Build the only replay backend accepted by the R19 production binding."""
    replay_path = _production_replay_path(replay_db_path)
    return SQLiteApprovalReplayGuard(
        replay_path,
        busy_timeout_ms=busy_timeout_ms,
    )


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
) -> HumanApprovalResult:
    """Verify one approval using durable file-backed replay state."""
    guard = build_production_replay_guard(
        replay_db_path=replay_db_path,
        busy_timeout_ms=busy_timeout_ms,
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


__all__ = [
    "DEFAULT_BUSY_TIMEOUT_MS",
    "build_production_replay_guard",
    "verify_and_consume_human_approval_production",
]
