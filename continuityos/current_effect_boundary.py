"""Pure current-session effect boundary shared below CLI dispatchers.

The current-session environment binding is context authority, never an execution or
write grant.  This module intentionally has no dependency on the legacy policy,
ledger, memory store, HTTP server or message bus, so those lower-level surfaces can
consult it without creating a circular authority path.

No current binding means legacy/product behavior is unchanged.  Once any current
binding is declared, it must be complete and must verify the exact R23/R64
challenge + controller-pinned SHA-256 + BOOT_ACK.  The present current contour is
READ_ONLY with NO_FURTHER_AGENT_WORK; effectful product operations therefore fail
closed.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Mapping

from .current_runtime import verify_current_runtime_binding

SCHEMA = "continuityos.current_effect_boundary/v1"
MODE_LEGACY = "LEGACY"
MODE_CURRENT = "CURRENT"
MODE_REVISE = "REVISE"

ENV_CHALLENGE = "CONTINUITYOS_CURRENT_CHALLENGE"
ENV_CHALLENGE_SHA = "CONTINUITYOS_CURRENT_CHALLENGE_SHA256"
ENV_ACK = "CONTINUITYOS_CURRENT_ACK"
ENV_REQUIRED = "CONTINUITYOS_CURRENT_SESSION_REQUIRED"


def _truthy(value: str | None) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def _effects() -> dict[str, Any]:
    return {
        "legacy_fallback": False,
        "memory_write": False,
        "ledger_write": False,
        "filesystem_write": False,
        "network_effect": False,
        "server_started": False,
        "subprocess_execution": False,
        "deployment": False,
        "current_state_apply": False,
        "canonical_mutation": False,
        "external_message": False,
        "auto_dispatch": False,
        "trading": False,
        "wallet_access": False,
        "order_execution": False,
        "can_trade": False,
        "capital_permission": "DENY",
        "deploy_permission": "DENY",
    }


def inspect_current_session(env: Mapping[str, str] | None = None) -> dict[str, Any]:
    """Inspect current-session binding without causing product effects.

    Returns LEGACY when no binding is declared, CURRENT only for one exact verified
    binding, and REVISE for partial/invalid declared bindings.  REVISE must never be
    treated as legacy fallback by callers.
    """
    source = os.environ if env is None else env
    values = {
        "challenge": str(source.get(ENV_CHALLENGE, "") or "").strip(),
        "challenge_sha256": str(source.get(ENV_CHALLENGE_SHA, "") or "").strip(),
        "ack": str(source.get(ENV_ACK, "") or "").strip(),
    }
    required = _truthy(source.get(ENV_REQUIRED))
    declared = required or any(values.values())
    if not declared:
        return {
            "schema": SCHEMA,
            "mode": MODE_LEGACY,
            "declared": False,
            "binding_verified": False,
            "effects": _effects(),
        }

    missing = [name for name, value in values.items() if not value]
    if missing:
        return {
            "schema": SCHEMA,
            "mode": MODE_REVISE,
            "declared": True,
            "binding_verified": False,
            "reason": "CURRENT_SESSION_BINDING_INCOMPLETE",
            "missing": missing,
            "effects": _effects(),
        }

    try:
        verdict = verify_current_runtime_binding(
            Path(values["challenge"]).expanduser(),
            Path(values["ack"]).expanduser(),
            expected_challenge_sha256=values["challenge_sha256"],
        )
    except Exception as exc:
        return {
            "schema": SCHEMA,
            "mode": MODE_REVISE,
            "declared": True,
            "binding_verified": False,
            "reason": "CURRENT_SESSION_BINDING_INVALID",
            "error_type": type(exc).__name__,
            "error": str(exc),
            "effects": _effects(),
        }

    if verdict.get("binding_verified") is not True:
        return {
            "schema": SCHEMA,
            "mode": MODE_REVISE,
            "declared": True,
            "binding_verified": False,
            "reason": "CURRENT_SESSION_ACK_NOT_VERIFIED",
            "binding_terminal": verdict.get("terminal"),
            "effects": _effects(),
        }

    return {
        "schema": SCHEMA,
        "mode": MODE_CURRENT,
        "declared": True,
        "binding_verified": True,
        "reason": "EXACT_CURRENT_SESSION_VERIFIED",
        "authority_generation": verdict.get("authority_generation"),
        "challenge_id": verdict.get("challenge_id"),
        "challenge_sha256": verdict.get("challenge_sha256"),
        "ack_sha256": verdict.get("ack_sha256"),
        "session_effect_ceiling": "READ_ONLY",
        "authority_ceiling": "NO_FURTHER_AGENT_WORK",
        "effects": _effects(),
    }


class CurrentEffectBoundaryError(RuntimeError):
    """Raised before a product effect when current authority does not permit it."""

    def __init__(self, effect: str, state: Mapping[str, Any]):
        self.effect = effect
        self.state = dict(state)
        mode = self.state.get("mode")
        reason = self.state.get("reason") or "CURRENT_SESSION_EFFECT_HELD"
        super().__init__(f"{effect}: {mode}: {reason}")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA,
            "terminal": "CURRENT_EFFECT_HOLD" if self.state.get("mode") == MODE_CURRENT else "CURRENT_EFFECT_REVISE",
            "effect": self.effect,
            "reason": self.state.get("reason"),
            "binding_verified": bool(self.state.get("binding_verified")),
            "authority_generation": self.state.get("authority_generation"),
            "challenge_id": self.state.get("challenge_id"),
            "challenge_sha256": self.state.get("challenge_sha256"),
            "session_effect_ceiling": self.state.get("session_effect_ceiling"),
            "authority_ceiling": self.state.get("authority_ceiling"),
            "effects": _effects(),
        }


def assert_current_effect_allowed(effect: str, env: Mapping[str, str] | None = None) -> dict[str, Any] | None:
    """Allow only legacy/no-binding mode; CURRENT and REVISE fail closed."""
    state = inspect_current_session(env)
    if state["mode"] == MODE_LEGACY:
        return None
    raise CurrentEffectBoundaryError(effect, state)


def effective_read_only(requested: bool = False, env: Mapping[str, str] | None = None) -> bool:
    """Monotonically force storage read-only for an exact current session.

    Invalid/partial current binding fails closed instead of silently opening a
    writable legacy database.
    """
    state = inspect_current_session(env)
    if state["mode"] == MODE_LEGACY:
        return bool(requested)
    if state["mode"] == MODE_CURRENT:
        return True
    raise CurrentEffectBoundaryError("storage.open", state)


def current_hold_for_action(action: Mapping[str, Any], env: Mapping[str, str] | None = None) -> dict[str, Any] | None:
    """Return a pure HOLD receipt for public legacy preflight, or None in legacy mode."""
    state = inspect_current_session(env)
    if state["mode"] == MODE_LEGACY:
        return None
    verified = state["mode"] == MODE_CURRENT
    return {
        "decision": "HOLD",
        "reasons": [
            "verified current session is READ_ONLY and NO_FURTHER_AGENT_WORK"
            if verified
            else f"declared current session is invalid: {state.get('reason')}"
        ],
        "severity": None,
        "action": dict(action),
        "assessed_paths": [],
        "rollback_plan": {"restorable": False, "snapshot_required": False, "targets": []},
        "policy": {"version": None, "sha256": None, "evaluated": False},
        "context": {
            "supplied": False,
            "conflicts": [],
            "error": None if verified else state.get("reason"),
            "identity": None,
        },
        "current_authority": {
            "binding_verified": bool(state.get("binding_verified")),
            "authority_generation": state.get("authority_generation"),
            "challenge_id": state.get("challenge_id"),
            "challenge_sha256": state.get("challenge_sha256"),
            "session_effect_ceiling": state.get("session_effect_ceiling"),
            "authority_ceiling": state.get("authority_ceiling"),
        },
        "execution_authorized": False,
        "legacy_policy_evaluated": False,
        "legacy_ledger_write": False,
        "invariant": "current authority may make legacy execution stricter but never grant execution",
        "effects": _effects(),
    }
