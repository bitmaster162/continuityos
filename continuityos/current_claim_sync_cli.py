"""Verified-current CLI for proposal-only project claim synchronization."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
from typing import Any
import argparse

from .current_claim_sync import PLAN_SCHEMA, REQUEST_SCHEMA, build_claim_sync_plan_from_db
from .current_effect_boundary import MODE_CURRENT, inspect_current_session
from .operational_memory import strict_json_loads
from .project_memory_bootstrap import MAX_ARTIFACT_BYTES, _stable_read

CLI_SCHEMA = "continuityos.current_claim_sync.cli/v1"


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


def _revise(reason: str, *, current_session: dict[str, Any] | None = None, **extra: Any) -> dict[str, Any]:
    return {
        "schema": CLI_SCHEMA,
        "terminal": "CURRENT_CLAIM_SYNC_PLAN_REVISE",
        "reason": reason,
        "current_session": current_session,
        "legacy_fallback": False,
        "apply_status": "NOT_APPLIED",
        "semantic_assertions_accepted": False,
        "execution_decision": "HOLD",
        "execution_authorized": False,
        "effects": _effects(),
        **extra,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="continuity-memory-claim-sync-plan",
        description=(
            "Resolve logical project claim selectors against verified shadow memory and emit an R36 "
            "NOT_APPLIED delta proposal. Requires a verified current session and never writes memory."
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
        _emit(_revise("VERIFIED_CURRENT_SESSION_REQUIRED", current_session=state))
        return 2

    request_path = Path(args.request).expanduser().absolute()
    try:
        payload = _stable_read(request_path, "claim-sync request", max_bytes=MAX_ARTIFACT_BYTES)
        request = strict_json_loads(payload.decode("utf-8-sig"))
    except Exception as exc:
        _emit(_revise(
            "CLAIM_SYNC_REQUEST_UNREADABLE",
            current_session={
                "binding_verified": True,
                "authority_generation": state.get("authority_generation"),
                "challenge_id": state.get("challenge_id"),
                "challenge_sha256": state.get("challenge_sha256"),
                "session_effect_ceiling": state.get("session_effect_ceiling"),
                "authority_ceiling": state.get("authority_ceiling"),
            },
            request_path=str(request_path),
            error_type=type(exc).__name__,
            error=str(exc),
        ))
        return 2

    result = build_claim_sync_plan_from_db(args.operational_db, request)
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
        "sha256": hashlib.sha256(payload).hexdigest(),
        "size_bytes": len(payload),
    }
    _emit(result)
    return 0 if result.get("schema") == PLAN_SCHEMA and result.get("terminal") == "CURRENT_CLAIM_SYNC_PLAN_PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
