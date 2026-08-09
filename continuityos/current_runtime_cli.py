"""Installed ``continuity`` dispatcher with current-session runtime clamping.

The R23 safe CLI remains the compatibility implementation for all commands when no
current runtime binding is declared.  A caller declares a current session through
an exact environment binding:

``CONTINUITYOS_CURRENT_CHALLENGE``
``CONTINUITYOS_CURRENT_CHALLENGE_SHA256``
``CONTINUITYOS_CURRENT_ACK``

If any one of those variables is present (or
``CONTINUITYOS_CURRENT_SESSION_REQUIRED`` is true), ``preflight`` and ``run`` can
no longer fall back silently to the legacy policy/memory/ledger execution plane.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
from typing import Mapping, Sequence

from .current_runtime import block_current_run, evaluate_current_preflight
from .safe_cli import main as r23_safe_main

ENV_CHALLENGE = "CONTINUITYOS_CURRENT_CHALLENGE"
ENV_CHALLENGE_SHA = "CONTINUITYOS_CURRENT_CHALLENGE_SHA256"
ENV_ACK = "CONTINUITYOS_CURRENT_ACK"
ENV_REQUIRED = "CONTINUITYOS_CURRENT_SESSION_REQUIRED"
SCHEMA = "continuityos.current_runtime.dispatch/v1"
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
    if command not in {"preflight", "run"}:
        return int(r23_safe_main(args) or 0)

    binding, missing = current_binding_from_env(os.environ)
    if binding is None:
        return int(r23_safe_main(args) or 0)
    if missing:
        return _binding_error(missing, command)

    if command == "preflight":
        return _route_current_preflight(args, command_index, binding)
    return _route_current_run(args, command_index, binding)


if __name__ == "__main__":
    raise SystemExit(main())
