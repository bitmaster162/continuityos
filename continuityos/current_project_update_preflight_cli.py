"""Verified-current CLI for R54 packet-aware project update preflight."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
from typing import Any

from .current_effect_boundary import MODE_CURRENT, inspect_current_session
from .current_project_update_preflight import PREFLIGHT_SCHEMA, preflight_project_update_packet
from .operational_memory import strict_json_loads
from .project_memory_bootstrap import MAX_ARTIFACT_BYTES, _stable_read

CLI_SCHEMA = "continuityos.current_project_update_preflight.cli/v1"


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
        "terminal": "CURRENT_PROJECT_UPDATE_PREFLIGHT_REVISE",
        "reason": reason,
        "current_session": current_session,
        "legacy_fallback": False,
        "apply_status": "NOT_APPLIED",
        "apply_ready": False,
        "execution_decision": "HOLD",
        "execution_authorized": False,
        "effects": _effects(),
        **extra,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="continuity-project-update-preflight",
        description=(
            "Validate an exact R52 review packet plus a separately completed R37 "
            "authorization against immutable project memory without materializing proposal bytes."
        ),
    )
    parser.add_argument("--db", required=True, help="existing exact shadow OperationalMemory SQLite DB")
    parser.add_argument("--packet", required=True, help="R52 project update review packet JSON")
    parser.add_argument("--authorization", required=True, help="separately completed R37 authorization JSON")
    try:
        args = parser.parse_args(sys.argv[1:] if argv is None else argv)
    except SystemExit as exc:
        return int(exc.code or 0)

    state = inspect_current_session()
    if state.get("mode") != MODE_CURRENT or state.get("binding_verified") is not True:
        _emit(_revise("VERIFIED_CURRENT_SESSION_REQUIRED", current_session=state))
        return 2

    packet_path = Path(args.packet).expanduser().absolute()
    auth_path = Path(args.authorization).expanduser().absolute()
    try:
        packet_bytes = _stable_read(packet_path, "project-update packet", max_bytes=MAX_ARTIFACT_BYTES)
        auth_bytes = _stable_read(auth_path, "project-update authorization", max_bytes=MAX_ARTIFACT_BYTES)
        packet = strict_json_loads(packet_bytes.decode("utf-8-sig"))
        if not isinstance(packet, dict):
            raise ValueError("packet root must be an object")
    except Exception as exc:
        _emit(_revise(
            "PROJECT_UPDATE_PREFLIGHT_INPUT_UNREADABLE",
            current_session={
                "binding_verified": True,
                "authority_generation": state.get("authority_generation"),
                "challenge_id": state.get("challenge_id"),
                "challenge_sha256": state.get("challenge_sha256"),
                "session_effect_ceiling": state.get("session_effect_ceiling"),
                "authority_ceiling": state.get("authority_ceiling"),
            },
            error_type=type(exc).__name__,
            error=str(exc),
        ))
        return 2

    result = preflight_project_update_packet(args.db, packet, auth_bytes)
    result["current_session"] = {
        "binding_verified": True,
        "authority_generation": state.get("authority_generation"),
        "challenge_id": state.get("challenge_id"),
        "challenge_sha256": state.get("challenge_sha256"),
        "session_effect_ceiling": state.get("session_effect_ceiling"),
        "authority_ceiling": state.get("authority_ceiling"),
    }
    result["inputs"] = {
        "packet_path": str(packet_path),
        "packet_file_sha256": hashlib.sha256(packet_bytes).hexdigest(),
        "packet_file_size_bytes": len(packet_bytes),
        "authorization_path": str(auth_path),
        "authorization_file_sha256": hashlib.sha256(auth_bytes).hexdigest(),
        "authorization_file_size_bytes": len(auth_bytes),
    }
    _emit(result)
    if result.get("schema") != PREFLIGHT_SCHEMA:
        return 2
    if result.get("terminal") in {
        "CURRENT_PROJECT_UPDATE_PREFLIGHT_READY",
        "CURRENT_PROJECT_UPDATE_PREFLIGHT_ALREADY_APPLIED",
    }:
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
