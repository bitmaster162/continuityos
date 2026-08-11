"""Verified-current CLI for non-authorizing R37 apply review packets."""
from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from .current_effect_boundary import MODE_CURRENT, inspect_current_session
from .current_memory_apply_auth_request import REQUEST_SCHEMA, build_apply_authorization_request

CLI_SCHEMA = "continuityos.current_memory_apply_auth_request.cli/v1"


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
        "accepted_truth_modified": False,
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
        prog="continuity-memory-apply-auth-request",
        description=(
            "Bind an exact current R36 proposal to its current shadow-memory base and emit an "
            "incomplete authorization review skeleton. Never grants or applies authority."
        ),
    )
    parser.add_argument("--operational-db", required=True)
    parser.add_argument("--proposal", required=True)
    try:
        args = parser.parse_args(sys.argv[1:] if argv is None else argv)
    except SystemExit as exc:
        return int(exc.code or 0)

    state = inspect_current_session()
    if state.get("mode") != MODE_CURRENT or state.get("binding_verified") is not True:
        _emit({
            "schema": CLI_SCHEMA,
            "terminal": "CURRENT_MEMORY_APPLY_AUTH_REQUEST_REVISE",
            "reason": "VERIFIED_CURRENT_SESSION_REQUIRED",
            "current_session": state,
            "legacy_fallback": False,
            "authorization_artifact_created": False,
            "authorization_granted": False,
            "authorization_identity_authenticated": False,
            "apply_status": "NOT_APPLIED",
            "execution_decision": "HOLD",
            "execution_authorized": False,
            "effects": _effects(),
        })
        return 2

    result = build_apply_authorization_request(args.operational_db, args.proposal)
    result["current_session"] = {
        "binding_verified": True,
        "authority_generation": state.get("authority_generation"),
        "challenge_id": state.get("challenge_id"),
        "challenge_sha256": state.get("challenge_sha256"),
        "session_effect_ceiling": state.get("session_effect_ceiling"),
        "authority_ceiling": state.get("authority_ceiling"),
    }
    result["legacy_fallback"] = False
    _emit(result)
    ok = result.get("schema") == REQUEST_SCHEMA and result.get("terminal") in {
        "CURRENT_MEMORY_APPLY_AUTH_REQUEST_PASS",
        "CURRENT_MEMORY_APPLY_AUTH_REQUEST_ALREADY_APPLIED",
    }
    return 0 if ok else 2


if __name__ == "__main__":
    raise SystemExit(main())
