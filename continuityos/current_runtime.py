"""Monotonic runtime clamp for a verified ContinuityOS current session.

A current cold-start challenge proves context; it is not an execution grant.  This
module therefore never upgrades legacy policy decisions and never executes work.
For the current R23 protocol the session is READ_ONLY and was admitted only while
the exact authority pointer carried ``NO_FURTHER_AGENT_WORK=true``.  Runtime
binding can consequently do two safe things:

* verify the exact current challenge + controller-pinned SHA-256 + BOOT_ACK;
* report that an execution request is held before legacy policy/ledger/executor.

The pure preflight path is allowed to describe the request and the clamp because
preflight itself has no execution effect.  It does not append to the legacy ledger.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from .current_cold_start import verify_current_cold_start_ack

SCHEMA = "continuityos.current_runtime.monotonic_clamp/v1"


def _effects() -> dict[str, Any]:
    return {
        "legacy_engine_called": False,
        "legacy_ledger_write": False,
        "execution_attempted": False,
        "executed": False,
        "force_push": False,
        "merge": False,
        "deployment": False,
        "registry_apply": False,
        "current_state_apply": False,
        "canonical_mutation": False,
        "trading": False,
        "wallet_access": False,
        "order_execution": False,
        "external_message": False,
        "self_application": False,
        "auto_dispatch": False,
        "can_trade": False,
        "capital_permission": "DENY",
        "deploy_permission": "DENY",
    }


def verify_current_runtime_binding(
    challenge_path: Path,
    ack_path: Path,
    *,
    expected_challenge_sha256: str,
) -> dict[str, Any]:
    """Verify one current session without creating or mutating runtime state."""
    verdict = verify_current_cold_start_ack(
        Path(challenge_path),
        Path(ack_path),
        expected_challenge_sha256=expected_challenge_sha256,
    )
    if verdict.get("outcome") != "PASS":
        return {
            "schema": SCHEMA,
            "terminal": "CURRENT_RUNTIME_BINDING_REVISE",
            "reason": "CURRENT_COLD_START_ACK_NOT_VERIFIED",
            "binding_verified": False,
            "cold_start_verdict": verdict,
            "effects": _effects(),
        }
    return {
        "schema": SCHEMA,
        "terminal": "CURRENT_RUNTIME_BINDING_PASS",
        "reason": "EXACT_CURRENT_COLD_START_VERIFIED",
        "binding_verified": True,
        "challenge_id": verdict.get("challenge_id"),
        "challenge_sha256": verdict.get("challenge_sha256"),
        "ack_sha256": verdict.get("ack_sha256"),
        "authority_generation": verdict.get("authority_generation"),
        "effects": _effects(),
    }


def evaluate_current_preflight(
    challenge_path: Path,
    ack_path: Path,
    *,
    expected_challenge_sha256: str,
    tool: str,
    command: str,
    cwd: str | None,
) -> dict[str, Any]:
    """Describe the monotonic current-session clamp for one proposed action.

    The preflight operation itself succeeds when the binding is valid, but its
    ``execution_decision`` remains HOLD.  This is intentional: an R23 current
    session carries context-only READ_ONLY authority and cannot become an
    execution grant by passing through legacy policy.
    """
    try:
        binding = verify_current_runtime_binding(
            challenge_path,
            ack_path,
            expected_challenge_sha256=expected_challenge_sha256,
        )
    except Exception as exc:
        return {
            "schema": SCHEMA,
            "terminal": "CURRENT_RUNTIME_PREFLIGHT_REVISE",
            "reason": "CURRENT_SESSION_BINDING_INVALID",
            "error_type": type(exc).__name__,
            "error": str(exc),
            "binding_verified": False,
            "execution_decision": "HOLD",
            "execution_authorized": False,
            "requested_action": {"tool": tool, "command": command, "cwd": cwd},
            "effects": _effects(),
        }

    if binding.get("binding_verified") is not True:
        return {
            "schema": SCHEMA,
            "terminal": "CURRENT_RUNTIME_PREFLIGHT_REVISE",
            "reason": "CURRENT_SESSION_ACK_NOT_VERIFIED",
            "binding_verified": False,
            "binding": binding,
            "execution_decision": "HOLD",
            "execution_authorized": False,
            "requested_action": {"tool": tool, "command": command, "cwd": cwd},
            "effects": _effects(),
        }

    return {
        "schema": SCHEMA,
        "terminal": "CURRENT_RUNTIME_PREFLIGHT_PASS",
        "reason": "CURRENT_SESSION_CONTEXT_VERIFIED_EXECUTION_REMAINS_HELD",
        "binding_verified": True,
        "authority_generation": binding.get("authority_generation"),
        "challenge_id": binding.get("challenge_id"),
        "challenge_sha256": binding.get("challenge_sha256"),
        "ack_sha256": binding.get("ack_sha256"),
        "requested_action": {"tool": tool, "command": command, "cwd": cwd},
        "session_effect_ceiling": "READ_ONLY",
        "authority_ceiling": "NO_FURTHER_AGENT_WORK",
        "execution_decision": "HOLD",
        "execution_authorized": False,
        "monotonic_rule": "current authority may only make a legacy decision stricter; it never grants execution",
        "legacy_decision_evaluated": False,
        "effects": _effects(),
    }


def block_current_run(
    challenge_path: Path,
    ack_path: Path,
    *,
    expected_challenge_sha256: str,
    tool: str,
    argv: list[str],
) -> dict[str, Any]:
    """Fail closed before legacy engine, ledger, rollback or subprocess execution."""
    try:
        binding = verify_current_runtime_binding(
            challenge_path,
            ack_path,
            expected_challenge_sha256=expected_challenge_sha256,
        )
    except Exception as exc:
        return {
            "schema": SCHEMA,
            "terminal": "CURRENT_RUNTIME_RUN_REVISE",
            "reason": "CURRENT_SESSION_BINDING_INVALID",
            "error_type": type(exc).__name__,
            "error": str(exc),
            "binding_verified": False,
            "decision": "HOLD",
            "requested_action": {"tool": tool, "argv": list(argv)},
            "effects": _effects(),
        }

    if binding.get("binding_verified") is not True:
        return {
            "schema": SCHEMA,
            "terminal": "CURRENT_RUNTIME_RUN_REVISE",
            "reason": "CURRENT_SESSION_ACK_NOT_VERIFIED",
            "binding_verified": False,
            "binding": binding,
            "decision": "HOLD",
            "requested_action": {"tool": tool, "argv": list(argv)},
            "effects": _effects(),
        }

    return {
        "schema": SCHEMA,
        "terminal": "CURRENT_RUNTIME_RUN_HOLD",
        "reason": "CURRENT_R64_SESSION_IS_READ_ONLY_AND_NO_FURTHER_AGENT_WORK",
        "binding_verified": True,
        "authority_generation": binding.get("authority_generation"),
        "challenge_id": binding.get("challenge_id"),
        "challenge_sha256": binding.get("challenge_sha256"),
        "ack_sha256": binding.get("ack_sha256"),
        "session_effect_ceiling": "READ_ONLY",
        "authority_ceiling": "NO_FURTHER_AGENT_WORK",
        "decision": "HOLD",
        "requested_action": {"tool": tool, "argv": list(argv)},
        "legacy_engine_called": False,
        "legacy_ledger_write": False,
        "execution_attempted": False,
        "executed": False,
        "effects": _effects(),
    }
