"""Installed ``continuity`` dispatcher with current-session runtime clamping.

The R23 safe CLI remains the compatibility implementation for commands outside the
current runtime surface when no current runtime binding is declared. A caller
declares a current session through an exact environment binding:

``CONTINUITYOS_CURRENT_CHALLENGE``
``CONTINUITYOS_CURRENT_CHALLENGE_SHA256``
``CONTINUITYOS_CURRENT_ACK``

If any one of those variables is present (or
``CONTINUITYOS_CURRENT_SESSION_REQUIRED`` is true), ``preflight`` and ``run`` can
no longer fall back silently to the legacy policy/memory/ledger execution plane.

``current-status`` is a pure read-only operator surface that reports whether that
binding is absent, incomplete, invalid, or exactly verified and exposes the
resulting runtime ceilings without evaluating legacy policy or executing work.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
from typing import Mapping, Sequence

from .current_runtime import (
    block_current_run,
    evaluate_current_preflight,
    verify_current_runtime_binding,
)
from .safe_cli import main as r23_safe_main

ENV_CHALLENGE = "CONTINUITYOS_CURRENT_CHALLENGE"
ENV_CHALLENGE_SHA = "CONTINUITYOS_CURRENT_CHALLENGE_SHA256"
ENV_ACK = "CONTINUITYOS_CURRENT_ACK"
ENV_REQUIRED = "CONTINUITYOS_CURRENT_SESSION_REQUIRED"
SCHEMA = "continuityos.current_runtime.dispatch/v1"
STATUS_SCHEMA = "continuityos.current_runtime.status/v1"
_TRUE = {"1", "true", "yes", "on"}


def _effects() -> dict[str, object]:
    return {
        "legacy_engine_called": False,
        "legacy_ledger_write": False,
        "execution_attempted": False,
        "executed": False,
        "deployment": False,
        "current_state_apply": False,
        "canonical_mutation": False,
        "auto_dispatch": False,
        "can_trade": False,
        "capital_permission": "DENY",
        "deploy_permission": "DENY",
    }


def _emit(value: Mapping[str, object]) -> None:
    print(json.dumps(dict(value), ensure_ascii=False, sort_keys=True, separators=(",", ":")))


def _command_index(argv: Sequence[str]) -> int | None:
    if not argv:
        return None
    if argv[0] == "--db":
        return 2 if len(argv) >= 3 else None
    if argv[0].startswith("--db="):
        return 1 if len(argv) >= 2 else None
    return 0


def _required(env: Mapping[str, str]) -> bool:
    return str(env.get(ENV_REQUIRED, "")).strip().lower() in _TRUE


def current_binding_from_env(env: Mapping[str, str]) -> tuple[dict[str, str] | None, list[str]]:
    values = {
        "challenge": str(env.get(ENV_CHALLENGE, "")).strip(),
        "challenge_sha256": str(env.get(ENV_CHALLENGE_SHA, "")).strip(),
        "ack": str(env.get(ENV_ACK, "")).strip(),
    }
    active = _required(env) or any(values.values())
    if not active:
        return None, []
    missing = [
        name
        for name, key in (
            (ENV_CHALLENGE, "challenge"),
            (ENV_CHALLENGE_SHA, "challenge_sha256"),
            (ENV_ACK, "ack"),
        )
        if not values[key]
    ]
    return values, missing


def _binding_error(missing: list[str], command: str) -> int:
    _emit({
        "schema": SCHEMA,
        "terminal": "CURRENT_RUNTIME_BINDING_REVISE",
        "reason": "CURRENT_SESSION_BINDING_INCOMPLETE",
        "command": command,
        "missing": missing,
        "legacy_fallback": False,
        "effects": _effects(),
    })
    return 2


def _status_capabilities(*, bound: bool) -> dict[str, str]:
    if not bound:
        return {
            "current_binding_verification": "NOT_ACTIVE",
            "read_only_inspection": "AVAILABLE",
            "current_preflight": "NOT_BOUND",
            "effectful_continuityos_calls": "LEGACY_MODE",
            "execution": "LEGACY_MODE",
        }
    return {
        "current_binding_verification": "PASS",
        "read_only_inspection": "ALLOW",
        "current_preflight": "ALLOW_READ_ONLY",
        "effectful_continuityos_calls": "HOLD",
        "execution": "HOLD",
    }


def _route_current_status(
    binding: Mapping[str, str] | None,
    missing: list[str],
) -> int:
    if binding is None:
        _emit({
            "schema": STATUS_SCHEMA,
            "terminal": "CURRENT_RUNTIME_STATUS_UNBOUND",
            "reason": "NO_CURRENT_SESSION_BINDING_DECLARED",
            "mode": "LEGACY_UNBOUND",
            "current_session_declared": False,
            "binding_complete": False,
            "binding_verified": False,
            "legacy_fallback": True,
            "capabilities": _status_capabilities(bound=False),
            "effects": _effects(),
        })
        return 0

    inputs = {
        "challenge": binding.get("challenge", ""),
        "challenge_sha256": binding.get("challenge_sha256", ""),
        "ack": binding.get("ack", ""),
    }
    if missing:
        _emit({
            "schema": STATUS_SCHEMA,
            "terminal": "CURRENT_RUNTIME_STATUS_REVISE",
            "reason": "CURRENT_SESSION_BINDING_INCOMPLETE",
            "mode": "CURRENT_DECLARED_INVALID",
            "current_session_declared": True,
            "binding_complete": False,
            "binding_verified": False,
            "missing": missing,
            "binding_inputs": inputs,
            "legacy_fallback": False,
            "execution_decision": "HOLD",
            "effects": _effects(),
        })
        return 2

    try:
        verdict = verify_current_runtime_binding(
            Path(binding["challenge"]).expanduser(),
            Path(binding["ack"]).expanduser(),
            expected_challenge_sha256=binding["challenge_sha256"],
        )
    except Exception as exc:
        _emit({
            "schema": STATUS_SCHEMA,
            "terminal": "CURRENT_RUNTIME_STATUS_REVISE",
            "reason": "CURRENT_SESSION_BINDING_INVALID",
            "mode": "CURRENT_DECLARED_INVALID",
            "current_session_declared": True,
            "binding_complete": True,
            "binding_verified": False,
            "error_type": type(exc).__name__,
            "error": str(exc),
            "binding_inputs": inputs,
            "legacy_fallback": False,
            "execution_decision": "HOLD",
            "effects": _effects(),
        })
        return 2

    if verdict.get("binding_verified") is not True:
        _emit({
            "schema": STATUS_SCHEMA,
            "terminal": "CURRENT_RUNTIME_STATUS_REVISE",
            "reason": "CURRENT_COLD_START_ACK_NOT_VERIFIED",
            "mode": "CURRENT_DECLARED_INVALID",
            "current_session_declared": True,
            "binding_complete": True,
            "binding_verified": False,
            "binding_inputs": inputs,
            "binding_verdict": verdict,
            "legacy_fallback": False,
            "execution_decision": "HOLD",
            "effects": _effects(),
        })
        return 2

    _emit({
        "schema": STATUS_SCHEMA,
        "terminal": "CURRENT_RUNTIME_STATUS_PASS",
        "reason": "EXACT_CURRENT_COLD_START_VERIFIED",
        "mode": "CURRENT_BOUND_READ_ONLY",
        "current_session_declared": True,
        "binding_complete": True,
        "binding_verified": True,
        "authority_generation": verdict.get("authority_generation"),
        "challenge_id": verdict.get("challenge_id"),
        "challenge_sha256": verdict.get("challenge_sha256"),
        "ack_sha256": verdict.get("ack_sha256"),
        "binding_inputs": inputs,
        "session_effect_ceiling": "READ_ONLY",
        "authority_ceiling": "NO_FURTHER_AGENT_WORK",
        "execution_decision": "HOLD",
        "execution_authorized": False,
        "legacy_fallback": False,
        "capabilities": _status_capabilities(bound=True),
        "effects": _effects(),
    })
    return 0


def _preflight_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="continuity preflight")
    parser.add_argument("tool")
    parser.add_argument("command")
    parser.add_argument("--cwd", default=None)
    parser.add_argument("--json", action="store_true")
    return parser


def _route_current_preflight(
    argv: list[str], command_index: int, binding: Mapping[str, str]
) -> int:
    parser = _preflight_parser()
    try:
        args = parser.parse_args(argv[command_index + 1 :])
    except SystemExit as exc:
        return int(exc.code or 0)
    result = evaluate_current_preflight(
        Path(binding["challenge"]).expanduser(),
        Path(binding["ack"]).expanduser(),
        expected_challenge_sha256=binding["challenge_sha256"],
        tool=args.tool,
        command=args.command,
        cwd=args.cwd,
    )
    _emit(result)
    return 0 if result.get("terminal") == "CURRENT_RUNTIME_PREFLIGHT_PASS" else 2


def _route_current_run(
    argv: list[str], command_index: int, binding: Mapping[str, str]
) -> int:
    tail = list(argv[command_index + 1 :])
    if not tail:
        _emit({
            "schema": SCHEMA,
            "terminal": "CURRENT_RUNTIME_RUN_REVISE",
            "reason": "RUN_TOOL_REQUIRED",
            "legacy_fallback": False,
            "effects": _effects(),
        })
        return 2
    tool = tail[0]
    rest = tail[1:]
    if rest and rest[0] == "--":
        rest = rest[1:]
    if not rest:
        _emit({
            "schema": SCHEMA,
            "terminal": "CURRENT_RUNTIME_RUN_REVISE",
            "reason": "RUN_COMMAND_REQUIRED",
            "tool": tool,
            "legacy_fallback": False,
            "effects": _effects(),
        })
        return 2
    result = block_current_run(
        Path(binding["challenge"]).expanduser(),
        Path(binding["ack"]).expanduser(),
        expected_challenge_sha256=binding["challenge_sha256"],
        tool=tool,
        argv=rest,
    )
    _emit(result)
    if result.get("terminal") == "CURRENT_RUNTIME_RUN_HOLD":
        return 3
    return 2


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    command_index = _command_index(args)
    if command_index is None or command_index >= len(args):
        return int(r23_safe_main(args) or 0)

    command = args[command_index]
    binding, missing = current_binding_from_env(os.environ)

    if command == "current-status":
        if len(args[command_index + 1 :]) != 0:
            _emit({
                "schema": STATUS_SCHEMA,
                "terminal": "CURRENT_RUNTIME_STATUS_REVISE",
                "reason": "CURRENT_STATUS_TAKES_NO_ARGUMENTS",
                "legacy_fallback": False,
                "effects": _effects(),
            })
            return 2
        return _route_current_status(binding, missing)

    if command not in {"preflight", "run"}:
        return int(r23_safe_main(args) or 0)

    if binding is None:
        return int(r23_safe_main(args) or 0)
    if missing:
        return _binding_error(missing, command)

    if command == "preflight":
        return _route_current_preflight(args, command_index, binding)
    return _route_current_run(args, command_index, binding)


if __name__ == "__main__":
    raise SystemExit(main())
