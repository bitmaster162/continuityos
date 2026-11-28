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
import math
import os
from pathlib import Path
import sqlite3
import time
from typing import Any, Mapping, Sequence

from .db import _fingerprint_connection, resolve_memory_db
from .continuity import (Continuity, _current_record, _matches_scope, _scope_value,
                         _unreviewed_record, assess_continuity_health)

SCHEMA = "continuityos.product_status/v1"


class _NonQuiescentMemory(RuntimeError):
    pass


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


def _json_value(raw: str, expected: type, default: Any) -> Any:
    try:
        value = json.loads(raw)
    except Exception:
        return default
    return value if isinstance(value, expected) else default


def _record_meta(raw: str, record_id: int) -> dict[str, Any]:
    try:
        value = json.loads(raw)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"INVALID_RECORD_METADATA:{record_id}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"INVALID_RECORD_METADATA:{record_id}")
    return value


def _dump(con: sqlite3.Connection, namespace: str | None) -> list[dict[str, Any]]:
    rows = con.execute(
        "SELECT id,text,namespace,tags,meta,created_at FROM items "
        "WHERE vec IS NOT NULL " + ("AND namespace=? " if namespace is not None else "") + "ORDER BY id",
        (namespace,) if namespace is not None else (),
    ).fetchall()
    return [
        {
            "id": row["id"],
            "text": row["text"],
            "namespace": row["namespace"],
            "tags": _json_value(row["tags"], list, []),
            "meta": _record_meta(row["meta"], row["id"]),
            "created_at": row["created_at"],
        }
        for row in rows
    ]


def _frontiers(rows: Sequence[Mapping[str, Any]]) -> dict[str, str]:
    return {row["meta"].get("kind") or (row["tags"][0] if row["tags"] else "parked"): row["text"]
            for row in Continuity._latest_frontiers(list(rows))}


def _checkpoint(last: Mapping[str, Any] | None, now: float) -> dict[str, Any] | None:
    if not last:
        return None
    meta = last.get("meta") if isinstance(last.get("meta"), dict) else {}
    ts = meta.get("ts", last.get("created_at"))
    valid_ts = isinstance(ts, (int, float)) and not isinstance(ts, bool) and math.isfinite(ts)
    age_seconds = now - ts if valid_ts else None
    proof = meta.get("proof")
    return {
        "id": last.get("id"),
        "recorded_at": datetime.fromtimestamp(ts, timezone.utc).isoformat() if valid_ts else None,
        "age_seconds": age_seconds,
        "summary": meta.get("summary"),
        "next_action": meta.get("next"),
        "proof_present": isinstance(proof, str) and bool(proof.strip()),
        "proof_verification": "NOT_PERFORMED",
        "lifecycle": meta.get("lifecycle", "ACTIVE"),
    }


def _sidecar_state(db_path: str) -> dict[str, int]:
    result: dict[str, int] = {}
    for suffix in ("-wal", "-journal"):
        path = db_path + suffix
        try:
            size = os.path.getsize(path)
        except FileNotFoundError:
            size = 0
        result[suffix] = int(size)
    return result


def _immutable_snapshot(db_path: str, *, project: str | None = None,
                        subject: str | None = None, max_open_loops: int = 7,
                        checkpoint_stale_hours: float = 48) -> dict[str, Any]:
    """Read one quiescent SQLite image with immutable=1 so status cannot create sidecars."""
    before_sidecars = _sidecar_state(db_path)
    if any(before_sidecars.values()):
        raise _NonQuiescentMemory(f"non-empty SQLite sidecar present: {before_sidecars}")
    before_stat = os.stat(db_path)

    uri = Path(db_path).as_uri() + "?mode=ro&immutable=1"
    con = sqlite3.connect(uri, uri=True, timeout=5.0)
    con.row_factory = sqlite3.Row
    try:
        table = con.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='items'"
        ).fetchone()
        if table is None:
            raise ValueError("memory database has no items table")
        identity = _fingerprint_connection(con, db_path)
        memory_count = int(con.execute("SELECT COUNT(*) c FROM items").fetchone()["c"])
        namespace_rows = con.execute(
            "SELECT namespace, COUNT(*) n FROM items GROUP BY namespace ORDER BY n DESC"
        ).fetchall()
        namespaces = [
            {"namespace": row["namespace"], "count": row["n"]}
            for row in namespace_rows
        ]
        all_rows = _dump(con, None)
    finally:
        con.close()

    after_stat = os.stat(db_path)
    after_sidecars = _sidecar_state(db_path)
    if any(after_sidecars.values()):
        raise _NonQuiescentMemory(f"SQLite sidecar appeared during status read: {after_sidecars}")
    if (before_stat.st_size, before_stat.st_mtime_ns) != (after_stat.st_size, after_stat.st_mtime_ns):
        raise _NonQuiescentMemory("memory database changed during immutable status read")

    now = time.time()
    scope = {"project": _scope_value(project, "project"), "subject": _scope_value(subject, "subject")}
    scoped_rows = [row for row in all_rows if _matches_scope(row["meta"], scope)]
    def current(namespace: str) -> list[dict[str, Any]]:
        return [row for row in all_rows if row["namespace"] == namespace
                and _matches_scope(row["meta"], scope, include_global=namespace == "canon")
                and _current_record(row["meta"], row["created_at"], now)
                and not _unreviewed_record(row["meta"])]

    canon = current("canon")
    frontiers = _frontiers(current("frontier"))
    loops = [row for row in current("loop") if not Continuity._closed(row)]
    last = max(
        current("checkpoint"),
        key=lambda row: (row["meta"].get("ts", 0), row["id"]),
        default=None,
    )
    checkpoint = _checkpoint(last, now)
    doctor = assess_continuity_health(
        memory_count=len(scoped_rows), canon_count=len(canon), frontiers=frontiers,
        loops=loops, last_checkpoint=last, now=now, max_open_loops=max_open_loops,
        checkpoint_stale_hours=checkpoint_stale_hours, scope=scope)

    return {
        "identity": identity,
        "memory_count": memory_count,
        "scoped_memory_count": len(scoped_rows),
        "namespaces": namespaces,
        "canon_count": len(canon),
        "frontiers": frontiers,
        "loops": loops,
        "checkpoint": checkpoint,
        "doctor": doctor,
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


def collect(db: str | None = None, *, project: str | None = None,
            subject: str | None = None, max_open_loops: int = 7,
            checkpoint_stale_hours: float = 48) -> tuple[dict[str, Any], int]:
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
        snapshot = _immutable_snapshot(db_path, project=project, subject=subject,
                                       max_open_loops=max_open_loops,
                                       checkpoint_stale_hours=checkpoint_stale_hours)
        clients = _client_statuses(db_path)
    except _NonQuiescentMemory as exc:
        return ({
            "schema": SCHEMA,
            "terminal": "COS_STATUS_HOLD",
            "reason": "MEMORY_DB_NOT_QUIESCENT",
            "memory": {
                "state": "BUSY",
                "path": db_path,
                "source": resolved["source"],
            },
            "error": str(exc),
            "effects": _effects(),
        }, 3)
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

    doctor = snapshot["doctor"]
    checkpoint = snapshot["checkpoint"]
    loops = snapshot["loops"]
    canon_count = snapshot["canon_count"]
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
    next_action = checkpoint.get("next_action") if checkpoint and doctor["lifecycle"] == "ACTIVE" else None

    value = {
        "schema": SCHEMA,
        "terminal": "COS_STATUS_PASS",
        "state": "READY" if continuity_state == "HEALTHY" and drifted == 0 else "ATTENTION",
        "memory": {
            "state": "READY",
            "path": _canon_path(db_path),
            "source": resolved["source"],
            "count": snapshot["memory_count"],
            "scoped_count": snapshot["scoped_memory_count"],
            "namespaces": snapshot["namespaces"],
            "context_sha256": snapshot["identity"].get("context_sha256"),
            "snapshot_mode": "sqlite-immutable-quiescent",
        },
        "continuity": {
            "state": continuity_state,
            "lifecycle": doctor["lifecycle"],
            "scope": doctor["scope"],
            "policy": {"max_open_loops": max_open_loops,
                       "checkpoint_stale_hours": checkpoint_stale_hours,
                       "kind": "CALLER_POLICY_NOT_UNIVERSAL_THRESHOLD"},
            "proof_verification": doctor["proof_verification"],
            "authority_granted": False,
            "passed": doctor.get("passed"),
            "total": doctor.get("total"),
            "checks": doctor.get("checks", []),
            "frontiers": snapshot["frontiers"],
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
    lines.append(f"Lifecycle   {continuity['lifecycle']}  scope={json.dumps(continuity['scope'], ensure_ascii=False, sort_keys=True)}")
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
    parser.add_argument("--project", default=None)
    parser.add_argument("--subject", default=None)
    parser.add_argument("--max-open-loops", type=int, default=7)
    parser.add_argument("--checkpoint-stale-hours", type=float, default=48)
    args = parser.parse_args(list(argv) if argv is not None else None)

    value, code = collect(args.db, project=args.project, subject=args.subject,
                           max_open_loops=args.max_open_loops,
                           checkpoint_stale_hours=args.checkpoint_stale_hours)
    if args.as_json:
        print(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True))
    else:
        print(_render(value, verbose=args.verbose))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
