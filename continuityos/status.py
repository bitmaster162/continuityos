"""Read-only product status for ContinuityOS.

This is deliberately distinct from the R64/current-runtime control-plane status.
It answers a product user's operational questions without creating or mutating
memory, client config, or external services.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import importlib.util
import json
import os
from pathlib import Path
import time
from typing import Any, Mapping, Sequence

from .db import open_existing_context, resolve_memory_db

SCHEMA = "continuityos.product_status/v1"


def _effects() -> dict[str, object]:
    return {
        "filesystem_write": False,
        "memory_write": False,
        "network_effect": False,
        "subprocess_execution": False,
        "server_started": False,
        "client_config_write": False,
        "deployment": False,
        "agent_dispatch": False,
        "trading": False,
        "wallet_access": False,
        "can_trade": False,
        "capital_permission": "DENY",
        "deploy_permission": "DENY",
    }


def _canon_path(path: str | Path) -> str:
    return os.path.normcase(os.path.realpath(os.path.abspath(os.path.expanduser(str(path)))))


def _age(seconds: float | None) -> str:
    if seconds is None:
        return "never"
    value = max(0.0, float(seconds))
    if value < 60:
        return f"{int(value)}s ago"
    if value < 3600:
        return f"{int(value // 60)}m ago"
    if value < 86400:
        return f"{value / 3600:.1f}h ago"
    return f"{value / 86400:.1f}d ago"


def _checkpoint(last: Mapping[str, Any] | None, now: float) -> dict[str, Any] | None:
    if not last:
        return None
    meta = last.get("meta") if isinstance(last.get("meta"), dict) else {}
    ts = meta.get("ts")
    age_seconds = max(0.0, now - float(ts)) if isinstance(ts, (int, float)) else None
    return {
        "id": last.get("id"),
        "recorded_at": datetime.fromtimestamp(float(ts), timezone.utc).isoformat() if isinstance(ts, (int, float)) else None,
        "age_seconds": age_seconds,
        "summary": meta.get("summary"),
        "next_action": meta.get("next"),
        "proof_present": bool(meta.get("proof")),
    }


def _client_statuses(db_path: str) -> list[dict[str, Any]]:
    # Product status intentionally checks configuration only. It does not spawn an
    # MCP server merely to render a dashboard/status command.
    from .connect import _config_path, _server, _status

    server = _server(db_path)
    result: list[dict[str, Any]] = []
    for client in ("claude", "cursor"):
        path = _config_path(client)
        if path is None:
            continue
        result.append(_status(client, path, server))
    return result


def collect(db: str | None = None) -> tuple[dict[str, Any], int]:
    try:
        resolved = resolve_memory_db(db)
    except Exception as exc:
        return ({
            "schema": SCHEMA,
            "terminal": "COS_STATUS_HOLD",
            "reason": "MEMORY_DB_RESOLUTION_FAILED",
            "error": f"{type(exc).__name__}: {exc}",
            "effects": _effects(),
        }, 2)

    db_path = resolved["path"]
    if db_path == ":memory:" or not os.path.isfile(db_path):
        return ({
            "schema": SCHEMA,
            "terminal": "COS_STATUS_HOLD",
            "reason": "MEMORY_DB_NOT_FOUND",
            "memory": {
                "state": "MISSING",
                "path": db_path,
                "source": resolved["source"],
            },
            "effects": _effects(),
        }, 2)

    try:
        context, identity = open_existing_context(db_path, source=resolved["source"])
    except Exception as exc:
        return ({
            "schema": SCHEMA,
            "terminal": "COS_STATUS_HOLD",
            "reason": "MEMORY_DB_INVALID_OR_UNREADABLE",
            "memory": {
                "state": "ERROR",
                "path": db_path,
                "source": resolved["source"],
            },
            "error": f"{type(exc).__name__}: {exc}",
            "effects": _effects(),
        }, 2)

    try:
        now = time.time()
        m = context.m
        namespaces = m.namespaces()
        memory_count = m.count()
        loops = context.open_loops()
        last = context.last_checkpoint()
        checkpoint = _checkpoint(last, now)
        doctor = context.doctor()
        frontiers = context.frontiers()
        canon_count = len(context._dump("canon"))
        clients = _client_statuses(db_path)
    except Exception as exc:
        return ({
            "schema": SCHEMA,
            "terminal": "COS_STATUS_HOLD",
            "reason": "STATUS_READ_FAILED",
            "memory": {
                "state": "ERROR",
                "path": db_path,
                "source": resolved["source"],
            },
            "error": f"{type(exc).__name__}: {exc}",
            "effects": _effects(),
        }, 2)
    finally:
        context.m.store.con.close()

    connected = sum(1 for client in clients if client.get("connected") is True)
    drifted = sum(1 for client in clients if client.get("drift") is True)
    configured = sum(1 for client in clients if client.get("configured") is True)
    if drifted:
        mcp_state = "DRIFT"
    elif connected:
        mcp_state = "CONFIGURED"
    else:
        mcp_state = "NOT_CONNECTED"

    continuity_state = "HEALTHY" if doctor.get("healthy") else "ATTENTION"
    advocate_available = importlib.util.find_spec("continuityos.advocate") is not None
    governance_state = "ARMED" if canon_count > 0 and advocate_available else "UNCONFIGURED"
    next_action = checkpoint.get("next_action") if checkpoint else None

    value = {
        "schema": SCHEMA,
        "terminal": "COS_STATUS_PASS",
        "state": "READY" if continuity_state == "HEALTHY" and drifted == 0 else "ATTENTION",
        "memory": {
            "state": "READY",
            "path": _canon_path(db_path),
            "source": resolved["source"],
            "count": memory_count,
            "namespaces": namespaces,
            "context_sha256": identity.get("context_sha256"),
        },
        "continuity": {
            "state": continuity_state,
            "passed": doctor.get("passed"),
            "total": doctor.get("total"),
            "checks": doctor.get("checks", []),
            "frontiers": frontiers,
            "open_loop_count": len(loops),
            "open_loops": [
                {"id": loop.get("id"), "text": loop.get("text")}
                for loop in loops
            ],
            "last_checkpoint": checkpoint,
            "next_action": next_action,
        },
        "agents": {
            "managed_clients": clients,
            "configured_count": configured,
            "connected_count": connected,
            "drifted_count": drifted,
        },
        "mcp": {
            "state": mcp_state,
            "live_probe_performed": False,
            "note": "configuration status only; no MCP subprocess was started",
        },
        "governance": {
            "state": governance_state,
            "canon_count": canon_count,
            "advocate_available": advocate_available,
        },
        "effects": _effects(),
    }
    return value, 0


def _render(value: Mapping[str, Any], *, verbose: bool = False) -> str:
    if value.get("terminal") != "COS_STATUS_PASS":
        memory = value.get("memory") if isinstance(value.get("memory"), dict) else {}
        lines = ["ContinuityOS status: HOLD"]
        lines.append(f"Reason      {value.get('reason', 'UNKNOWN')}")
        if memory:
            lines.append(f"Memory      {memory.get('state', 'ERROR')}  {memory.get('path', '')}")
        if value.get("error"):
            lines.append(f"Error       {value['error']}")
        return "\n".join(lines)

    memory = value["memory"]
    continuity = value["continuity"]
    agents = value["agents"]
    checkpoint = continuity.get("last_checkpoint")
    mcp = value["mcp"]
    governance = value["governance"]

    lines = [f"ContinuityOS status  {value.get('state')}"]
    lines.append(f"Memory      {memory['state']}  {memory['count']} memories  {memory['path']}")
    lines.append(
        f"Continuity  {continuity['state']}  {continuity['passed']}/{continuity['total']} checks"
    )
    if checkpoint:
        lines.append(
            f"Last state  {_age(checkpoint.get('age_seconds'))}  checkpoint #{checkpoint.get('id')}"
        )
    else:
        lines.append("Last state  never")
    lines.append(f"Open loops  {continuity['open_loop_count']}")
    lines.append(f"Next action {continuity.get('next_action') or '—'}")

    client_bits = []
    for client in agents.get("managed_clients", []):
        name = str(client.get("client", "client")).capitalize()
        if client.get("drift"):
            state = "DRIFT"
        elif client.get("connected"):
            state = "CONNECTED"
        elif client.get("configured"):
            state = "CONFIGURED"
        else:
            state = "NOT_CONNECTED"
        client_bits.append(f"{name} {state}")
    lines.append("Agents      " + (" | ".join(client_bits) if client_bits else "none detected"))
    lines.append(f"MCP         {mcp['state']}  (config only; no live probe)")
    lines.append(f"Governance  {governance['state']}  {governance['canon_count']} canon item(s)")

    if verbose:
        frontiers = continuity.get("frontiers") or {}
        if frontiers:
            lines.append("Frontiers")
            for kind, text in sorted(frontiers.items()):
                lines.append(f"  {kind:<8} {text}")
        lines.append("Doctor")
        for check in continuity.get("checks", []):
            mark = "ok" if check.get("ok") else "x"
            lines.append(f"  {mark:<2} {check.get('check')} — {check.get('detail')}")
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="cos status",
        description="Read-only product status for memory, continuity and connected AI clients",
    )
    parser.add_argument("--db", default=None, help="existing ContinuityOS memory DB")
    parser.add_argument("--json", action="store_true", dest="as_json")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args(list(argv) if argv is not None else None)

    value, code = collect(args.db)
    if args.as_json:
        print(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True))
    else:
        print(_render(value, verbose=args.verbose))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
