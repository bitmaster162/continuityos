"""Safe installed dispatcher for the ``continuity`` command.

All commands except current cold-start preparation/verification delegate unchanged
to the historical ``continuityos.gate.cli`` implementation.

Current preparation is fail-closed and requires:
- one state-resolution bundle,
- one exact ACTIVE current authority pointer plus controller-pinned SHA-256,
- the three stable roots hash-bound by that pointer,
- one read-only current session spec.

Historical R63 preparation remains available only through an explicit compatibility
override. Current challenge verification is auto-detected by schema and is read-only.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Sequence

from .current_cold_start import (
    SCHEMA_CHALLENGE as CURRENT_CHALLENGE_SCHEMA,
    json_text as current_json_text,
    peek_challenge_schema,
    prepare_current_cold_start,
    verify_current_cold_start_ack,
)
from .gate.cli import main as legacy_main

GUARD_SCHEMA = "continuityos.safe_cli.cold_start_guard/v2"


def _effects() -> dict[str, object]:
    return {
        "force_push": False,
        "merge": False,
        "pull_request_merge": False,
        "auto_merge": False,
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


def _guard_result(reason: str, *, detail: str | None = None) -> dict[str, object]:
    result: dict[str, object] = {
        "schema": GUARD_SCHEMA,
        "terminal": "CURRENT_COLD_START_HOLD",
        "reason": reason,
        "legacy_r63_unbound_executed": False,
        "current_authority_executed": False,
        "effects": _effects(),
    }
    if detail:
        result["detail"] = detail
    return result


def _emit(value: dict[str, object]) -> None:
    print(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")))


def _command_index(argv: Sequence[str]) -> int | None:
    """Locate ``cold-start`` after the only supported legacy global option, --db."""
    if not argv:
        return None
    index = 0
    first = argv[0]
    if first == "--db":
        if len(argv) < 3:
            return None
        index = 2
    elif first.startswith("--db="):
        index = 1
    if index < len(argv) and argv[index] == "cold-start":
        return index
    return None


def _prepare_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="continuity cold-start prepare",
        description=(
            "Prepare a current R64+ read-only cold-start from exact authority roots, "
            "or explicitly opt into historical R63-unbound compatibility."
        ),
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--state-bundle",
        help="continuityos.state_resolution.bundle/v1 used by the current guarded path",
    )
    mode.add_argument(
        "--legacy-r63-unbound",
        action="store_true",
        help="explicitly use the historical R63-bound preparer without current authority binding",
    )
    parser.add_argument("--authority-pointer")
    parser.add_argument("--authority-pointer-sha256")
    parser.add_argument("--current-state")
    parser.add_argument("--role-index")
    parser.add_argument("--role-views")
    parser.add_argument("--boot-receipt")
    parser.add_argument("--spec", required=True)
    parser.add_argument("--output", required=True)
    return parser


def _require_current(args: argparse.Namespace) -> list[str]:
    missing: list[str] = []
    for attr, label in (
        ("authority_pointer", "--authority-pointer"),
        ("authority_pointer_sha256", "--authority-pointer-sha256"),
        ("current_state", "--current-state"),
        ("role_index", "--role-index"),
        ("role_views", "--role-views"),
    ):
        if not getattr(args, attr):
            missing.append(label)
    return missing


def _route_prepare(argv: list[str], command_index: int) -> int:
    prefix = argv[:command_index]
    prepare_args = argv[command_index + 2 :]
    parser = _prepare_parser()
    try:
        args = parser.parse_args(prepare_args)
    except SystemExit as exc:
        return int(exc.code or 0)

    if args.state_bundle:
        missing = _require_current(args)
        if missing:
            _emit(
                _guard_result(
                    "CURRENT_AUTHORITY_INPUTS_REQUIRED",
                    detail="Missing: " + ", ".join(missing),
                )
            )
            return 3
        if args.boot_receipt:
            _emit(
                _guard_result(
                    "LEGACY_BOOT_RECEIPT_NOT_USED_BY_CURRENT_PROTOCOL",
                    detail=(
                        "Current cold-start binds CURRENT_POINTER + CURRENT_STATE + "
                        "ROLE_INDEX + ROLE_VIEWS directly. Remove --boot-receipt."
                    ),
                )
            )
            return 3
        try:
            result = prepare_current_cold_start(
                authority_pointer_path=Path(args.authority_pointer).expanduser(),
                expected_authority_pointer_sha256=args.authority_pointer_sha256,
                current_state_path=Path(args.current_state).expanduser(),
                role_index_path=Path(args.role_index).expanduser(),
                role_views_path=Path(args.role_views).expanduser(),
                state_bundle_path=Path(args.state_bundle).expanduser(),
                spec_path=Path(args.spec).expanduser(),
                output_dir=Path(args.output).expanduser(),
            )
        except Exception as exc:
            _emit(
                {
                    "schema": GUARD_SCHEMA,
                    "terminal": "CURRENT_COLD_START_REVISE",
                    "reason": "CURRENT_AUTHORITY_INPUT_INVALID",
                    "error_type": type(exc).__name__,
                    "error": str(exc),
                    "legacy_r63_unbound_executed": False,
                    "current_authority_executed": False,
                    "writes_performed": [],
                    "effects": _effects(),
                }
            )
            return 2
        print(current_json_text(result), end="")
        return 0 if result.get("terminal") == "CURRENT_COLD_START_PASS" else 3

    if args.legacy_r63_unbound:
        if any(
            (
                args.authority_pointer,
                args.authority_pointer_sha256,
                args.current_state,
                args.role_index,
                args.role_views,
            )
        ):
            _emit(
                _guard_result(
                    "LEGACY_AND_CURRENT_INPUTS_MIXED",
                    detail="Do not combine current authority roots with --legacy-r63-unbound.",
                )
            )
            return 3
        if not args.boot_receipt:
            _emit(
                _guard_result(
                    "LEGACY_BOOT_RECEIPT_REQUIRED",
                    detail="Historical R63 compatibility requires --boot-receipt.",
                )
            )
            return 3
        print(
            "[LEGACY R63 UNBOUND] explicit compatibility override selected; "
            "current authority/root guard is not applied.",
            file=sys.stderr,
        )
        legacy_args = [
            *prefix,
            "cold-start",
            "prepare",
            "--boot-receipt",
            args.boot_receipt,
            "--spec",
            args.spec,
            "--output",
            args.output,
        ]
        return int(legacy_main(legacy_args) or 0)

    _emit(
        _guard_result(
            "STATE_BUNDLE_REQUIRED",
            detail=(
                "Use --state-bundle plus exact current authority/root inputs for the "
                "current read-only protocol. Historical R63 compatibility requires "
                "explicit --legacy-r63-unbound."
            ),
        )
    )
    return 3


def _verify_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="continuity cold-start verify")
    parser.add_argument("--challenge", required=True)
    parser.add_argument("--challenge-sha256", required=True)
    parser.add_argument("--ack", required=True)
    return parser


def _route_verify(argv: list[str], command_index: int) -> int:
    prefix = argv[:command_index]
    parser = _verify_parser()
    try:
        args = parser.parse_args(argv[command_index + 2 :])
    except SystemExit as exc:
        return int(exc.code or 0)

    try:
        schema = peek_challenge_schema(Path(args.challenge).expanduser())
    except Exception as exc:
        _emit(
            {
                "schema": GUARD_SCHEMA,
                "terminal": "CURRENT_COLD_START_REVISE",
                "reason": "CHALLENGE_UNREADABLE",
                "error_type": type(exc).__name__,
                "error": str(exc),
                "current_authority_executed": False,
                "writes_performed": [],
                "effects": _effects(),
            }
        )
        return 2

    if schema == CURRENT_CHALLENGE_SCHEMA:
        try:
            result = verify_current_cold_start_ack(
                Path(args.challenge).expanduser(),
                Path(args.ack).expanduser(),
                expected_challenge_sha256=args.challenge_sha256,
            )
        except Exception as exc:
            _emit(
                {
                    "schema": GUARD_SCHEMA,
                    "terminal": "CURRENT_COLD_START_REVISE",
                    "reason": "CURRENT_CHALLENGE_INVALID",
                    "error_type": type(exc).__name__,
                    "error": str(exc),
                    "current_authority_executed": False,
                    "writes_performed": [],
                    "effects": _effects(),
                }
            )
            return 2
        print(current_json_text(result), end="")
        return 0 if result.get("outcome") == "PASS" else 2

    legacy_args = [
        *prefix,
        "cold-start",
        "verify",
        "--challenge",
        args.challenge,
        "--challenge-sha256",
        args.challenge_sha256,
        "--ack",
        args.ack,
    ]
    return int(legacy_main(legacy_args) or 0)


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    command_index = _command_index(args)
    if command_index is None or command_index + 1 >= len(args):
        return int(legacy_main(args) or 0)
    subcommand = args[command_index + 1]
    if subcommand == "prepare":
        return _route_prepare(args, command_index)
    if subcommand == "verify":
        return _route_verify(args, command_index)
    return int(legacy_main(args) or 0)


if __name__ == "__main__":
    raise SystemExit(main())
