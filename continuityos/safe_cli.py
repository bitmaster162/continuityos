"""Safe installed dispatcher for the ``continuity`` command.

All commands except ``cold-start prepare`` delegate unchanged to the historical
``continuityos.gate.cli`` implementation. Current cold-start preparation is fail-
closed: callers must either provide a state-resolution bundle or explicitly opt
into the historical R63-unbound path.

This module does not deploy, mutate Control Center/current state, trade, change
capital permissions, activate memory, or send external messages.
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import Sequence

from .gate.cli import main as legacy_main
from .state_resolve_cli import main as state_main

GUARD_SCHEMA = "continuityos.safe_cli.cold_start_guard/v1"


def _effects() -> dict[str, object]:
    return {
        "force_push": False,
        "merge": False,
        "pull_request_merge": False,
        "auto_merge": False,
        "deployment": False,
        "registry_apply": False,
        "current_state_apply": False,
        "r63_apply": False,
        "trading": False,
        "wallet_access": False,
        "order_execution": False,
        "external_message": False,
        "self_application": False,
        "can_trade": False,
        "capital_permission": "DENY",
        "deploy_permission": "DENY",
    }


def _guard_result(reason: str, *, detail: str | None = None) -> dict[str, object]:
    result: dict[str, object] = {
        "schema": GUARD_SCHEMA,
        "terminal": "CURRENT_COLD_START_HOLD",
        "reason": reason,
        "legacy_r63_unbound_executed": False,
        "state_bound_executed": False,
        "effects": _effects(),
    }
    if detail:
        result["detail"] = detail
    return result


def _emit(value: dict[str, object]) -> None:
    print(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")))


def _cold_start_index(argv: Sequence[str]) -> int | None:
    """Locate the command after the only supported legacy global option, --db."""
    if not argv:
        return None
    index = 0
    first = argv[0]
    if first == "--db":
        if len(argv) < 2:
            return None
        index = 2
    elif first.startswith("--db="):
        index = 1
    if list(argv[index:index + 2]) == ["cold-start", "prepare"]:
        return index
    return None


def _prepare_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="continuity cold-start prepare",
        description=(
            "Prepare a current cold-start through state resolution, or explicitly "
            "opt into the historical unbound R63 path."
        ),
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--state-bundle",
        help="continuityos.state_resolution.bundle/v1 used by the guarded path",
    )
    mode.add_argument(
        "--legacy-r63-unbound",
        action="store_true",
        help="explicitly use the historical R63-bound preparer without state binding",
    )
    parser.add_argument("--boot-receipt", required=True)
    parser.add_argument("--spec", required=True)
    parser.add_argument("--output", required=True)
    return parser


def _route_prepare(argv: list[str], command_index: int) -> int:
    prefix = argv[:command_index]
    prepare_args = argv[command_index + 2:]
    parser = _prepare_parser()
    try:
        args = parser.parse_args(prepare_args)
    except SystemExit as exc:
        # argparse help keeps its normal zero exit; malformed input fails closed.
        return int(exc.code or 0)

    if args.state_bundle:
        return state_main([
            "prepare-cold-start",
            "--input", args.state_bundle,
            "--boot-receipt", args.boot_receipt,
            "--spec", args.spec,
            "--output", args.output,
        ])

    if args.legacy_r63_unbound:
        print(
            "[LEGACY R63 UNBOUND] explicit compatibility override selected; "
            "state-resolution guard is not applied.",
            file=sys.stderr,
        )
        legacy_args = [
            *prefix,
            "cold-start", "prepare",
            "--boot-receipt", args.boot_receipt,
            "--spec", args.spec,
            "--output", args.output,
        ]
        return int(legacy_main(legacy_args) or 0)

    _emit(_guard_result(
        "STATE_BUNDLE_REQUIRED",
        detail=(
            "Use --state-bundle for the current guarded path. "
            "Historical R63 compatibility requires explicit --legacy-r63-unbound."
        ),
    ))
    return 3


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    command_index = _cold_start_index(args)
    if command_index is None:
        return int(legacy_main(args) or 0)
    return _route_prepare(args, command_index)


if __name__ == "__main__":
    raise SystemExit(main())
