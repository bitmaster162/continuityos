"""Fail-closed containment for packaged sibling entrypoints in a current session.

R24 protects the installed ``continuity`` runtime entrypoint, but ContinuityOS also
ships historical/product entrypoints (``cos``, ``continuity-memory``,
``continuity-context``, ``continuity-session`` and ``continuity-state``).  Those
surfaces remain available unchanged for ordinary installations.  Once a caller
explicitly declares a current session through the R24 environment binding, however,
they must not silently bypass the verified current authority boundary.

For the current R64 contour the verified session is READ_ONLY and carries
NO_FURTHER_AGENT_WORK.  Therefore sibling entrypoints are held before their legacy
implementation is imported/called.  The sole exception is
``continuity-state evaluate``, which is already a pure read-only state resolver.
Historical ``continuity-state prepare-cold-start`` is specifically blocked because
it is the old R63-bound preparer path.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import sys
from typing import Callable, Mapping, Sequence

from .current_runtime import verify_current_runtime_binding
from .current_runtime_cli import current_binding_from_env

SCHEMA = "continuityos.current_entrypoint_containment/v1"


def _effects() -> dict[str, object]:
    return {
        "legacy_entrypoint_called": False,
        "legacy_engine_called": False,
        "legacy_ledger_write": False,
        "filesystem_write": False,
        "memory_write": False,
        "server_started": False,
        "network_effect": False,
        "subprocess_execution": False,
        "self_update": False,
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


def _emit(value: Mapping[str, object]) -> None:
    print(json.dumps(dict(value), ensure_ascii=False, sort_keys=True, separators=(",", ":")))


def _args(argv: Sequence[str] | None) -> list[str]:
    return list(sys.argv[1:] if argv is None else argv)


def _command(surface: str, args: Sequence[str]) -> str | None:
    if not args:
        return None
    if surface == "cos":
        if args[0] == "--db":
            return args[2] if len(args) >= 3 else None
        if args[0].startswith("--db="):
            return args[1] if len(args) >= 2 else None
    for item in args:
        if item not in {"-h", "--help"} and not item.startswith("-"):
            return item
    return None


def _binding_error(surface: str, command: str | None, missing: Sequence[str]) -> int:
    _emit(
        {
            "schema": SCHEMA,
            "terminal": "CURRENT_ENTRYPOINT_BINDING_REVISE",
            "reason": "CURRENT_SESSION_BINDING_INCOMPLETE",
            "surface": surface,
            "command": command,
            "missing": list(missing),
            "legacy_fallback": False,
            "effects": _effects(),
        }
    )
    return 2


def _verify_binding(binding: Mapping[str, str], surface: str, command: str | None) -> tuple[dict[str, object] | None, int | None]:
    try:
        verdict = verify_current_runtime_binding(
            Path(binding["challenge"]).expanduser(),
            Path(binding["ack"]).expanduser(),
            expected_challenge_sha256=binding["challenge_sha256"],
        )
    except Exception as exc:
        _emit(
            {
                "schema": SCHEMA,
                "terminal": "CURRENT_ENTRYPOINT_BINDING_REVISE",
                "reason": "CURRENT_SESSION_BINDING_INVALID",
                "surface": surface,
                "command": command,
                "error_type": type(exc).__name__,
                "error": str(exc),
                "legacy_fallback": False,
                "effects": _effects(),
            }
        )
        return None, 2
    if verdict.get("binding_verified") is not True:
        _emit(
            {
                "schema": SCHEMA,
                "terminal": "CURRENT_ENTRYPOINT_BINDING_REVISE",
                "reason": "CURRENT_SESSION_ACK_NOT_VERIFIED",
                "surface": surface,
                "command": command,
                "binding_terminal": verdict.get("terminal"),
                "legacy_fallback": False,
                "effects": _effects(),
            }
        )
        return None, 2
    return dict(verdict), None


def _hold(surface: str, command: str | None, verdict: Mapping[str, object]) -> int:
    _emit(
        {
            "schema": SCHEMA,
            "terminal": "CURRENT_ENTRYPOINT_HOLD",
            "reason": "CURRENT_R64_SESSION_IS_READ_ONLY_AND_NO_FURTHER_AGENT_WORK",
            "surface": surface,
            "command": command,
            "binding_verified": True,
            "authority_generation": verdict.get("authority_generation"),
            "challenge_id": verdict.get("challenge_id"),
            "challenge_sha256": verdict.get("challenge_sha256"),
            "session_effect_ceiling": "READ_ONLY",
            "authority_ceiling": "NO_FURTHER_AGENT_WORK",
            "legacy_fallback": False,
            "effects": _effects(),
        }
    )
    return 3


def _dispatch(
    surface: str,
    argv: Sequence[str] | None,
    legacy_loader: Callable[[], Callable[[Sequence[str] | None], int | None]],
    *,
    allow_state_evaluate: bool = False,
    env: Mapping[str, str] | None = None,
) -> int:
    args = _args(argv)
    command = _command(surface, args)
    binding, missing = current_binding_from_env(os.environ if env is None else env)
    if binding is None:
        legacy_main = legacy_loader()
        return int(legacy_main(args) or 0)
    if missing:
        return _binding_error(surface, command, missing)

    verdict, error_code = _verify_binding(binding, surface, command)
    if error_code is not None:
        return error_code
    assert verdict is not None

    if allow_state_evaluate and command == "evaluate":
        legacy_main = legacy_loader()
        return int(legacy_main(args) or 0)
    return _hold(surface, command, verdict)


def _product_args(args: Sequence[str], command: str) -> list[str]:
    """Strip an outer ``cos <product-command>`` while preserving top-level --db."""
    values = list(args)
    db_arg: str | None = None
    if values[:1] == ["--db"]:
        if len(values) < 3:
            return values
        db_arg = values[1]
        values = values[2:]
    elif values and values[0].startswith("--db="):
        db_arg = values[0].split("=", 1)[1]
        values = values[1:]

    if values[:1] == [command]:
        values = values[1:]
    if db_arg is not None and not any(v == "--db" or v.startswith("--db=") for v in values):
        values = ["--db", db_arg, *values]
    return values


def _connect_args(args: Sequence[str]) -> list[str]:
    return _product_args(args, "connect")


def _status_args(args: Sequence[str]) -> list[str]:
    return _product_args(args, "status")


def _demo_args(args: Sequence[str]) -> list[str]:
    return _product_args(args, "demo")


def cos_main(argv: Sequence[str] | None = None) -> int:
    args = _args(argv)
    command = _command("cos", args)

    def load():
        if command == "connect":
            from .connect import main as connect_main

            def routed(passed: Sequence[str] | None = None) -> int:
                return int(connect_main(_connect_args(_args(passed))) or 0)

            return routed
        if command == "status":
            from .status import main as status_main

            def routed(passed: Sequence[str] | None = None) -> int:
                return int(status_main(_status_args(_args(passed))) or 0)

            return routed
        if command == "demo":
            from .demo import main as demo_main

            def routed(passed: Sequence[str] | None = None) -> int:
                return int(demo_main(_demo_args(_args(passed))) or 0)

            return routed
        from .cli import main
        return main

    # Deliberately route product commands through _dispatch. A verified R64 current
    # session therefore keeps the same READ_ONLY HOLD and cannot use `cos connect`,
    # `cos status`, or `cos demo` as a sibling-entrypoint escape hatch.
    return _dispatch("cos", args, load)


def operational_memory_main(argv: Sequence[str] | None = None) -> int:
    def load():
        from .operational_memory import main
        return main
    return _dispatch("continuity-memory", argv, load)


def operational_context_main(argv: Sequence[str] | None = None) -> int:
    def load():
        from .operational_context import main
        return main
    return _dispatch("continuity-context", argv, load)


def session_input_main(argv: Sequence[str] | None = None) -> int:
    def load():
        from .session_input import main
        return main
    return _dispatch("continuity-session", argv, load)


def state_main(argv: Sequence[str] | None = None) -> int:
    def load():
        from .state_resolve_cli import main
        return main
    return _dispatch("continuity-state", argv, load, allow_state_evaluate=True)
