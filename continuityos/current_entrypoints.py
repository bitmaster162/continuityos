"""Fail-closed containment for packaged sibling entrypoints in a current session.

Ordinary installations retain their historical/product entrypoints. Once a caller
binds a verified current session, sibling surfaces may not bypass the current
authority boundary. The canonical-payload consumer is an explicit GET-only exception:
its five read-only commands may run inside a verified READ_ONLY session.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import sys
from typing import Callable, Collection, Mapping, Sequence

from .current_runtime import verify_current_runtime_binding
from .current_runtime_cli import current_binding_from_env

SCHEMA = "continuityos.current_entrypoint_containment/v1"
EMBEDDER_POLICY_SCHEMA = "continuityos.product.embedder_policy/v1"
EMBEDDER_ENV = "CONTINUITYOS_EMBEDDER"
_DEFAULT_EMBEDDER_MODES = {"", "hash", "hashing", "offline", "local"}
_FAST_EMBEDDER_MODES = {"fast", "fastembed"}
_LEGACY_NO_SHARED_MEMORY_COMMANDS = {None, "sim", "serve", "api", "update", "usage"}
_CANONICAL_READ_COMMANDS = frozenset({"health", "snapshot", "decision", "project", "context"})

PRODUCT_HELP = """usage: cos [--db DB] <command> [options]

ContinuityOS — local-first durable memory + continuity for AI agents and humans.

Start here:
  setup                    guided local onboarding
  import <path>            import ChatGPT/Claude/Gemini/Grok/Mistral/Perplexity history
  connect [client]         connect Claude, Cursor, Hermes, or a generic MCP client
  status                   read-only product health and continuity status
  demo continuity          prove fresh-process continuity on an isolated temporary DB
  boot                     offline handoff + doctor; --check-updates opts into PyPI
  backup                   create a local quiescent memory snapshot; no restore

Core memory:
  remember | find | recall | namespaces | extract
  default embedder: local HashingEmbedder (no model/network path)
  opt in to FastEmbed: CONTINUITYOS_EMBEDDER=fast

Continuity:
  canon | frontier | loop | checkpoint | doctor | handoff | close | rules | scan

Advanced / operator surfaces:
  serve | api | alignment | advocate | audit | bus | epoch | scout | ledger | sim

Useful commands:
  cos connect --status
  cos connect claude --dry-run
  cos status --json
  cos demo continuity --json
  cos boot
  cos boot --check-updates
  cos backup --json
  cos --version

Product commands are routed through the same current-session containment boundary as
legacy commands. In a verified READ_ONLY current session they HOLD instead of bypassing
authority controls.
"""


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
    _emit({
        "schema": SCHEMA,
        "terminal": "CURRENT_ENTRYPOINT_BINDING_REVISE",
        "reason": "CURRENT_SESSION_BINDING_INCOMPLETE",
        "surface": surface,
        "command": command,
        "missing": list(missing),
        "legacy_fallback": False,
        "effects": _effects(),
    })
    return 2


def _verify_binding(binding: Mapping[str, str], surface: str, command: str | None) -> tuple[dict[str, object] | None, int | None]:
    try:
        verdict = verify_current_runtime_binding(
            Path(binding["challenge"]).expanduser(),
            Path(binding["ack"]).expanduser(),
            expected_challenge_sha256=binding["challenge_sha256"],
        )
    except Exception as exc:
        _emit({
            "schema": SCHEMA,
            "terminal": "CURRENT_ENTRYPOINT_BINDING_REVISE",
            "reason": "CURRENT_SESSION_BINDING_INVALID",
            "surface": surface,
            "command": command,
            "error_type": type(exc).__name__,
            "error": str(exc),
            "legacy_fallback": False,
            "effects": _effects(),
        })
        return None, 2
    if verdict.get("binding_verified") is not True:
        _emit({
            "schema": SCHEMA,
            "terminal": "CURRENT_ENTRYPOINT_BINDING_REVISE",
            "reason": "CURRENT_SESSION_ACK_NOT_VERIFIED",
            "surface": surface,
            "command": command,
            "binding_terminal": verdict.get("terminal"),
            "legacy_fallback": False,
            "effects": _effects(),
        })
        return None, 2
    return dict(verdict), None


def _hold(surface: str, command: str | None, verdict: Mapping[str, object]) -> int:
    _emit({
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
    })
    return 3


def _dispatch(
    surface: str,
    argv: Sequence[str] | None,
    legacy_loader: Callable[[], Callable[[Sequence[str] | None], int | None]],
    *,
    allow_state_evaluate: bool = False,
    allow_commands: Collection[str] | None = None,
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

    allowed = (allow_state_evaluate and command == "evaluate") or (
        allow_commands is not None and command in allow_commands
    )
    if allowed:
        legacy_main = legacy_loader()
        return int(legacy_main(args) or 0)
    return _hold(surface, command, verdict)


def _product_args(args: Sequence[str], command: str) -> list[str]:
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


def _boot_args(args: Sequence[str]) -> list[str]:
    return _product_args(args, "boot")


def _backup_args(args: Sequence[str]) -> list[str]:
    return _product_args(args, "backup")


def _help_main(argv: Sequence[str] | None = None) -> int:
    print(PRODUCT_HELP.rstrip())
    return 0


def _version_main(argv: Sequence[str] | None = None) -> int:
    from ._version import __version__
    print(f"continuityos {__version__}")
    return 0


def _embedder_policy_hold(command: str | None, mode: str) -> int:
    _emit({
        "schema": EMBEDDER_POLICY_SCHEMA,
        "terminal": "COS_EMBEDDER_POLICY_HOLD",
        "reason": "UNSUPPORTED_EMBEDDER_MODE",
        "command": command,
        "environment_variable": EMBEDDER_ENV,
        "requested": mode,
        "allowed": ["hash", "fast"],
        "effects": _effects(),
    })
    return 2


def _legacy_cos_loader(command: str | None) -> Callable[[Sequence[str] | None], int | None]:
    if command in _LEGACY_NO_SHARED_MEMORY_COMMANDS:
        from .cli import main
        return main
    mode = os.environ.get(EMBEDDER_ENV, "").strip().lower()
    if mode in _FAST_EMBEDDER_MODES:
        from .cli import main
        return main
    if mode not in _DEFAULT_EMBEDDER_MODES:
        def hold(argv: Sequence[str] | None = None) -> int:
            return _embedder_policy_hold(command, mode)
        return hold

    def offline_main(argv: Sequence[str] | None = None) -> int:
        from . import embedders
        original = embedders.FastEmbedEmbedder

        class _OfflineFastEmbed:
            def __init__(self, *args: object, **kwargs: object) -> None:
                raise RuntimeError("FastEmbed disabled by offline-first cos policy")

        embedders.FastEmbedEmbedder = _OfflineFastEmbed
        try:
            from .cli import main
            return int(main(_args(argv)) or 0)
        finally:
            embedders.FastEmbedEmbedder = original

    return offline_main


def cos_main(argv: Sequence[str] | None = None) -> int:
    args = _args(argv)
    command = _command("cos", args)
    top_help = args in (["-h"], ["--help"])
    top_version = args == ["--version"]

    def load():
        if top_help:
            return _help_main
        if top_version:
            return _version_main
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
        if command == "boot":
            from .boot import main as boot_main
            def routed(passed: Sequence[str] | None = None) -> int:
                return int(boot_main(_boot_args(_args(passed))) or 0)
            return routed
        if command == "backup":
            from .memory_backup import main as backup_main
            def routed(passed: Sequence[str] | None = None) -> int:
                return int(backup_main(_backup_args(_args(passed))) or 0)
            return routed
        return _legacy_cos_loader(command)

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


def canonical_payload_main(argv: Sequence[str] | None = None) -> int:
    def load():
        from .canonical_payload_consumer_cli import main
        return main
    return _dispatch("continuity-canon", argv, load, allow_commands=_CANONICAL_READ_COMMANDS)
