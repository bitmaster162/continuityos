"""Verified current-session CLI for proposal-only OperationalMemory deltas."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any

from .current_effect_boundary import MODE_CURRENT, inspect_current_session
from .current_memory_delta import (
    PROPOSAL_SCHEMA,
    REQUEST_SCHEMA,
    build_memory_delta_proposal_from_db,
)
from .operational_memory import strict_json_load

CLI_SCHEMA = "continuityos.current_memory_delta.cli/v1"


def _effects() -> dict[str, Any]:
    return {
        "operational_memory_write": False,
        "filesystem_write": False,
        "network_effect": False,
        "subprocess_execution": False,
        "agent_dispatch": False,
        "external_message": False,
        "deployment": False,
        "current_state_apply": False,
        "canonical_mutation": False,
        "trading": False,
        "wallet_access": False,
        "order_execution": False,
        "can_trade": False,
        "capital_permission": "DENY",
        "deploy_permission": "DENY",
    }


def _emit(value: dict[str, Any]) -> None:
    print(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="continuity-memory-delta",
        description=(
            "Compile a base-bound NOT_APPLIED OperationalMemory delta proposal. "
            "Requires a verified current session and never writes memory."
        ),
    )
    parser.add_argument("--operational-db", required=True)
    parser.add_argument("--request", required=True, help=f"JSON file with schema {REQUEST_SCHEMA}")
    try:
        args = parser.parse_args(sys.argv[1:] if argv is None else argv)
    except SystemExit as exc:
        return int(exc.code or 0)

    state = inspect_current_session()
    if state.get("mode") != MODE_CURRENT or state.get("binding_verified") is not True:
        _emit({
            "schema": CLI_SCHEMA,
            "terminal": "CURRENT_MEMORY_DELTA_PROPOSAL_REVISE",
            "reason": "VERIFIED_CURRENT_SESSION_REQUIRED",
            "current_session": state,
            "legacy_fallback": False,
            "apply_status": "NOT_APPLIED",
            "apply_implemented": False,
            "execution_decision": "HOLD",
            "execution_authorized": False,
            "effects": _effects(),
        })
        return 2

    request_path = Path(args.request).expanduser().absolute()
    if not request_path.is_file():
        _emit({
            "schema": CLI_SCHEMA,
            "terminal": "CURRENT_MEMORY_DELTA_PROPOSAL_REVISE",
            "reason": "DELTA_REQUEST_MISSING",
            "request_path": str(request_path),
            "apply_status": "NOT_APPLIED",
            "apply_implemented": False,
            "execution_decision": "HOLD",
            "execution_authorized": False,
            "effects": _effects(),
        })
        return 2
    try:
        request = strict_json_load(request_path)
    except Exception as exc:
        _emit({
            "schema": CLI_SCHEMA,
            "terminal": "CURRENT_MEMORY_DELTA_PROPOSAL_REVISE",
            "reason": "DELTA_REQUEST_INVALID_JSON",
            "error_type": type(exc).__name__,
            "error": str(exc),
            "request_path": str(request_path),
            "apply_status": "NOT_APPLIED",
            "apply_implemented": False,
            "execution_decision": "HOLD",
            "execution_authorized": False,
            "effects": _effects(),
        })
        return 2

    result = build_memory_delta_proposal_from_db(args.operational_db, request)
    result["current_session"] = {
        "binding_verified": True,
        "authority_generation": state.get("authority_generation"),
        "challenge_id": state.get("challenge_id"),
        "challenge_sha256": state.get("challenge_sha256"),
        "session_effect_ceiling": state.get("session_effect_ceiling"),
        "authority_ceiling": state.get("authority_ceiling"),
    }
    result["request_input"] = {
        "path": str(request_path),
        "schema": request.get("schema") if isinstance(request, dict) else None,
    }
    _emit(result)
    return 0 if result.get("schema") == PROPOSAL_SCHEMA and result.get("terminal") == "CURRENT_MEMORY_DELTA_PROPOSAL_PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
