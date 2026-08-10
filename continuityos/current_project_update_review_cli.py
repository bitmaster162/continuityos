"""Verified-current CLI for the R52 read-only project update review packet."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
from typing import Any

from .current_effect_boundary import MODE_CURRENT, inspect_current_session
from .current_project_update_review import PACKET_SCHEMA, build_project_update_review_packet
from .operational_memory import strict_json_loads
from .project_memory_bootstrap import MAX_ARTIFACT_BYTES, _stable_read

CLI_SCHEMA = "continuityos.current_project_update_review.cli/v1"


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


def _revise(reason: str, *, current_session=None, **extra: Any) -> dict[str, Any]:
    return {
        "schema": CLI_SCHEMA,
        "terminal": "CURRENT_PROJECT_UPDATE_REVIEW_REVISE",
        "reason": reason,
        "current_session": current_session,
        "legacy_fallback": False,
        "apply_status": "NOT_APPLIED",
        "authorization_granted": False,
        "execution_decision": "HOLD",
        "execution_authorized": False,
        "effects": _effects(),
        **extra,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="continuity-project-update-review",
        description=(
            "Compile one read-only project claim-update review packet: current-work, "
            "target-bound proposal bytes/SHA and an incomplete authorization skeleton."
        ),
    )
    parser.add_argument("--db", required=True, help="existing shadow OperationalMemory SQLite DB")
    parser.add_argument("--request", required=True, help="R43 claim-sync request JSON")
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
        payload = _stable_read(request_path, "project-update request", max_bytes=MAX_ARTIFACT_BYTES)
        request = strict_json_loads(payload.decode("utf-8-sig"))
        if not isinstance(request, dict):
            raise ValueError("request root must be an object")
    except Exception as exc:
        _emit(_revise(
            "PROJECT_UPDATE_REQUEST_UNREADABLE",
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

    result = build_project_update_review_packet(args.db, request)
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
        "sha256": hashlib.sha256(payload).hexdigest(),
        "size_bytes": len(payload),
    }
    _emit(result)
    return 0 if result.get("schema") == PACKET_SCHEMA and result.get("terminal") == "CURRENT_PROJECT_UPDATE_REVIEW_PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
