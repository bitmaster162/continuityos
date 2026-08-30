"""Bounded read-only connector status/preview adapter for Control Center.

This module deliberately reuses the product ``cos connect`` discovery and preview
logic without exposing its write, rollback, state-record, or subprocess-verification
paths.  Payloads are reduced to ContinuityOS-only fields so unrelated client config,
environment values, and other MCP server entries are never returned by Control Center.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import connect


SCHEMA = "continuityos.control_center_connectors/v1"


@dataclass(frozen=True)
class ConnectorPreviewError(Exception):
    status: int
    message: str

    def __str__(self) -> str:
        return self.message


def _governance() -> dict[str, Any]:
    return {
        "read_only": True,
        "execution_authority": "NONE",
        "can_execute": False,
        "can_trade": False,
        "capital_permission": "DENY",
    }


def validate_client(value: str | None) -> str:
    if value is None or not value.strip():
        raise ConnectorPreviewError(400, "client is required")
    client = value.strip()
    if client not in connect.SUPPORTED_CLIENTS:
        raise ConnectorPreviewError(400, "unsupported connector client")
    return client


def _managed_status(client: str, db_path: str) -> dict[str, Any]:
    path = connect._config_path(client)
    if path is None:
        raise ConnectorPreviewError(503, "managed connector path is unavailable")
    status = connect._status(client, path, connect._server(db_path))
    # Never return status["server"]: it came from user-owned config and may contain
    # env/secrets or other fields beyond the ContinuityOS-owned comparison surface.
    result: dict[str, Any] = {
        "client": client,
        "managed": True,
        "config_path": str(path),
        "config_exists": bool(status.get("config_exists", False)),
        "configured": bool(status.get("configured", False)),
        "connected": bool(status.get("connected", False)),
        "drift": bool(status.get("drift", False)),
    }
    if status.get("error"):
        result["error"] = "CONFIG_READ_FAILED"
    return result


def build_connector_status(db_path: str) -> dict[str, Any]:
    clients: list[dict[str, Any]] = []
    for client in connect.SUPPORTED_CLIENTS:
        if client in connect.MANAGED:
            clients.append(_managed_status(client, db_path))
        else:
            clients.append(
                {
                    "client": client,
                    "managed": False,
                    "configured": False,
                    "connected": False,
                    "drift": False,
                    "reason": (
                        "MANUAL_COMMAND_REQUIRED"
                        if client == "hermes"
                        else "MANUAL_CONFIG_REQUIRED"
                    ),
                }
            )
    return {
        "schema": SCHEMA,
        "ok": True,
        "mode": "STATUS_ONLY",
        "memory_db": db_path,
        "memory_exists": db_path == ":memory:" or Path(db_path).is_file(),
        "clients": clients,
        **_governance(),
    }


def build_connector_preview(client_value: str | None, db_path: str) -> dict[str, Any]:
    client = validate_client(client_value)
    server = connect._server(db_path)
    path = connect._config_path(client)
    try:
        raw = connect._preview(client, db_path, path, server)
    except Exception as exc:
        raise ConnectorPreviewError(409, "connector config preview failed") from exc

    if not raw.get("managed"):
        result: dict[str, Any] = {
            "schema": SCHEMA,
            "ok": True,
            "mode": "PREVIEW_ONLY",
            "client": client,
            "managed": False,
            "would_change": False,
            "reason": raw.get("reason"),
            "memory_db": db_path,
        }
        # These fields are generated solely from ContinuityOS-owned desired server
        # data. They do not contain user config or environment values.
        if isinstance(raw.get("manual_command"), str):
            result["manual_command"] = raw["manual_command"]
        if isinstance(raw.get("config_snippet"), dict):
            result["config_snippet"] = raw["config_snippet"]
        return {**result, **_governance()}

    return {
        "schema": SCHEMA,
        "ok": True,
        "mode": "PREVIEW_ONLY",
        "client": client,
        "managed": True,
        "config_path": raw.get("config_path"),
        "config_exists": bool(raw.get("config_exists", False)),
        "before_sha256": raw.get("before_sha256"),
        "after_sha256": raw.get("after_sha256"),
        "would_change": bool(raw.get("would_change", False)),
        "memory_db": db_path,
        "server": server,
        **_governance(),
    }


def error_payload(error: ConnectorPreviewError) -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "ok": False,
        "error": error.message,
        **_governance(),
    }
