"""Pure current-session environment export for operator shell setup.

The exporter never mutates ``os.environ``. It first verifies one exact current
challenge + controller-pinned SHA-256 + BOOT_ACK, then renders copy/paste-only
bindings for a requested shell or returns a machine-readable JSON environment map.
"""
from __future__ import annotations

import os
from pathlib import Path
import shlex
from typing import Any

from .current_runtime import verify_current_runtime_binding

SCHEMA = "continuityos.current_runtime.env_export/v1"
ENV_CHALLENGE = "CONTINUITYOS_CURRENT_CHALLENGE"
ENV_CHALLENGE_SHA = "CONTINUITYOS_CURRENT_CHALLENGE_SHA256"
ENV_ACK = "CONTINUITYOS_CURRENT_ACK"
ENV_REQUIRED = "CONTINUITYOS_CURRENT_SESSION_REQUIRED"
FORMATS = {"json", "powershell", "posix"}


def _effects() -> dict[str, Any]:
    return {
        "environment_mutated": False,
        "filesystem_write": False,
        "network_effect": False,
        "subprocess_execution": False,
        "deployment": False,
        "current_state_apply": False,
        "canonical_mutation": False,
        "auto_dispatch": False,
        "trading": False,
        "wallet_access": False,
        "order_execution": False,
        "can_trade": False,
        "capital_permission": "DENY",
        "deploy_permission": "DENY",
    }


def _stable_path(value: str) -> str:
    text = str(value or "")
    if not text.strip():
        raise ValueError("path is empty")
    if any(ch in text for ch in ("\x00", "\r", "\n")):
        raise ValueError("path contains a control character that cannot be rendered safely")
    return os.path.abspath(os.path.expanduser(text))


def _powershell_quote(value: str) -> str:
    if any(ch in value for ch in ("\x00", "\r", "\n")):
        raise ValueError("environment value contains an unsafe control character")
    return "'" + value.replace("'", "''") + "'"


def _render(environment: dict[str, str], output_format: str) -> str | None:
    if output_format == "json":
        return None
    if output_format == "powershell":
        return "\n".join(
            f"$env:{name} = {_powershell_quote(value)}"
            for name, value in environment.items()
        ) + "\n"
    if output_format == "posix":
        return "\n".join(
            f"export {name}={shlex.quote(value)}"
            for name, value in environment.items()
        ) + "\n"
    raise ValueError(f"unsupported output format: {output_format}")


def build_current_env_export(
    challenge: str,
    challenge_sha256: str,
    ack: str,
    *,
    output_format: str = "json",
) -> dict[str, Any]:
    """Verify an exact current session and render copy/paste environment bindings."""
    fmt = str(output_format or "").strip().lower()
    if fmt not in FORMATS:
        return {
            "schema": SCHEMA,
            "terminal": "CURRENT_ENV_EXPORT_REVISE",
            "reason": "OUTPUT_FORMAT_UNSUPPORTED",
            "output_format": fmt,
            "supported_formats": sorted(FORMATS),
            "effects": _effects(),
        }

    try:
        challenge_path = _stable_path(challenge)
        ack_path = _stable_path(ack)
        expected_sha = str(challenge_sha256 or "").strip().lower()
        verdict = verify_current_runtime_binding(
            Path(challenge_path),
            Path(ack_path),
            expected_challenge_sha256=expected_sha,
        )
    except Exception as exc:
        return {
            "schema": SCHEMA,
            "terminal": "CURRENT_ENV_EXPORT_REVISE",
            "reason": "CURRENT_SESSION_BINDING_INVALID",
            "error_type": type(exc).__name__,
            "error": str(exc),
            "output_format": fmt,
            "effects": _effects(),
        }

    if verdict.get("binding_verified") is not True:
        return {
            "schema": SCHEMA,
            "terminal": "CURRENT_ENV_EXPORT_REVISE",
            "reason": "CURRENT_COLD_START_ACK_NOT_VERIFIED",
            "binding_verdict": verdict,
            "output_format": fmt,
            "effects": _effects(),
        }

    environment = {
        ENV_CHALLENGE: challenge_path,
        ENV_CHALLENGE_SHA: str(verdict.get("challenge_sha256") or expected_sha),
        ENV_ACK: ack_path,
        ENV_REQUIRED: "1",
    }
    try:
        rendered = _render(environment, fmt)
    except Exception as exc:
        return {
            "schema": SCHEMA,
            "terminal": "CURRENT_ENV_EXPORT_REVISE",
            "reason": "ENVIRONMENT_RENDER_FAILED",
            "error_type": type(exc).__name__,
            "error": str(exc),
            "output_format": fmt,
            "effects": _effects(),
        }

    return {
        "schema": SCHEMA,
        "terminal": "CURRENT_ENV_EXPORT_PASS",
        "reason": "EXACT_CURRENT_COLD_START_VERIFIED",
        "binding_verified": True,
        "authority_generation": verdict.get("authority_generation"),
        "challenge_id": verdict.get("challenge_id"),
        "challenge_sha256": verdict.get("challenge_sha256"),
        "ack_sha256": verdict.get("ack_sha256"),
        "output_format": fmt,
        "environment": environment,
        "rendered": rendered,
        "session_effect_ceiling": "READ_ONLY",
        "authority_ceiling": "NO_FURTHER_AGENT_WORK",
        "execution_decision": "HOLD",
        "effects": _effects(),
    }
