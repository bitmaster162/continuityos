"""Verified read-only CLI for one project's OperationalMemory work capsule."""
from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from .current_effect_boundary import MODE_CURRENT, inspect_current_session
from .current_work import build_current_work_from_db

CLI_SCHEMA = "continuityos.current_work.cli/v1"


def _effects() -> dict[str, Any]:
    return {
        "operational_memory_write": False,
        "filesystem_write": False,
        "network_effect": False,
        "subprocess_execution": False,
        "agent_dispatch": False,
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
        prog="continuity-work",
        description=(
            "Compile one deterministic read-only project work capsule from an existing "
            "Common Operational Memory database. Requires a verified current session."
        ),
    )
    parser.add_argument("--project", required=True, help="exact OperationalMemory subject_id")
    parser.add_argument("--operational-db", required=True, help="existing Common Operational Memory SQLite file")
    try:
        args = parser.parse_args(sys.argv[1:] if argv is None else argv)
    except SystemExit as exc:
        return int(exc.code or 0)

    state = inspect_current_session()
    if state.get("mode") != MODE_CURRENT or state.get("binding_verified") is not True:
        _emit({
            "schema": CLI_SCHEMA,
            "terminal": "CURRENT_WORK_REVISE",
            "reason": "VERIFIED_CURRENT_SESSION_REQUIRED",
            "current_session": state,
            "legacy_fallback": False,
            "execution_decision": "HOLD",
            "execution_authorized": False,
            "effects": _effects(),
        })
        return 2

    result = build_current_work_from_db(args.operational_db, args.project)
    result["current_session"] = {
        "binding_verified": True,
        "authority_generation": state.get("authority_generation"),
        "challenge_id": state.get("challenge_id"),
        "challenge_sha256": state.get("challenge_sha256"),
        "session_effect_ceiling": state.get("session_effect_ceiling"),
        "authority_ceiling": state.get("authority_ceiling"),
    }
    _emit(result)
    terminal = result.get("terminal")
    if terminal == "CURRENT_WORK_PASS":
        return 0
    if terminal == "CURRENT_WORK_HOLD":
        return 3
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
