"""Physically read-only accessors for the Control Center Memory Explorer."""
from __future__ import annotations

import json
import re
import sqlite3
from pathlib import Path
from typing import Any, Mapping

DEFAULT_LIMIT = 50
MAX_LIMIT = 100
MAX_QUERY_CHARS = 500
MAX_NAMESPACE_CHARS = 200
_REQUIRED_COLUMNS = {
    "id",
    "namespace",
    "text",
    "tags",
    "meta",
    "created_at",
    "updated_at",
}


class MemoryExplorerError(RuntimeError):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = int(status)
        self.message = message


def _json_list(value: object) -> list[Any]:
    if not isinstance(value, str):
        return []
    try:
        parsed = json.loads(value)
    except (TypeError, ValueError, json.JSONDecodeError):
        return []
    return parsed if isinstance(parsed, list) else []


def _json_dict(value: object) -> dict[str, Any]:
    if not isinstance(value, str):
        return {}
    try:
        parsed = json.loads(value)
    except (TypeError, ValueError, json.JSONDecodeError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _row_payload(row: Mapping[str, Any]) -> dict[str, Any]:
    keys = set(row.keys())
    return {
        "id": int(row["id"]),
        "namespace": str(row["namespace"]),
        "text": str(row["text"]),
        "tags": _json_list(row["tags"]),
        "meta": _json_dict(row["meta"]),
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
        "key": row["key"] if "key" in keys else None,
        "version": row["version"] if "version" in keys else 0,
    }


def validate_limit(value: str | None) -> int:
    if value in (None, ""):
        return DEFAULT_LIMIT
    try:
        limit = int(value, 10)
    except (TypeError, ValueError) as exc:
        raise MemoryExplorerError(400, "limit must be an integer") from exc
    if not 1 <= limit <= MAX_LIMIT:
        raise MemoryExplorerError(400, f"limit must be between 1 and {MAX_LIMIT}")
    return limit


def validate_query(value: str | None) -> str:
    query = (value or "").strip()
    if len(query) > MAX_QUERY_CHARS:
        raise MemoryExplorerError(400, f"query exceeds {MAX_QUERY_CHARS} characters")
    return query


def validate_namespace(value: str | None) -> str | None:
    namespace = (value or "").strip()
    if not namespace:
        return None
    if len(namespace) > MAX_NAMESPACE_CHARS:
        raise MemoryExplorerError(
            400,
            f"namespace exceeds {MAX_NAMESPACE_CHARS} characters",
        )
    return namespace


def validate_item_id(value: str | None) -> int:
    if value in (None, ""):
        raise MemoryExplorerError(400, "id is required")
    try:
        item_id = int(value, 10)
    except (TypeError, ValueError) as exc:
        raise MemoryExplorerError(400, "id must be a positive integer") from exc
    if item_id <= 0:
        raise MemoryExplorerError(400, "id must be a positive integer")
    return item_id


def _sidecar_path(path: Path, suffix: str) -> Path:
    return Path(str(path) + suffix)


def _preflight_physical_read_only(path: Path) -> None:
    if not path.is_file():
        raise MemoryExplorerError(503, "canonical memory database is unavailable")
    wal = _sidecar_path(path, "-wal")
    journal = _sidecar_path(path, "-journal")
    try:
        if wal.is_file() and wal.stat().st_size > 0:
            raise MemoryExplorerError(
                409,
                "canonical memory has an uncheckpointed WAL; explorer fails closed",
            )
        if journal.is_file() and journal.stat().st_size > 0:
            raise MemoryExplorerError(
                409,
                "canonical memory has an active rollback journal; explorer fails closed",
            )
    except OSError as exc:
        raise MemoryExplorerError(503, "canonical memory sidecar preflight failed") from exc


def _open_connection(path: Path) -> sqlite3.Connection:
    _preflight_physical_read_only(path)
    try:
        normalized = path.expanduser().resolve(strict=True)
        uri = normalized.as_uri() + "?mode=ro&immutable=1"
        con = sqlite3.connect(uri, uri=True, check_same_thread=False)
        con.row_factory = sqlite3.Row
        con.execute("PRAGMA query_only=ON")
        con.execute("PRAGMA temp_store=MEMORY")
        columns = {
            str(row[1])
            for row in con.execute("PRAGMA table_info(items)").fetchall()
        }
        if not _REQUIRED_COLUMNS.issubset(columns):
            con.close()
            raise MemoryExplorerError(503, "canonical memory schema is unsupported")
        return con
    except MemoryExplorerError:
        raise
    except (OSError, sqlite3.Error, ValueError) as exc:
        raise MemoryExplorerError(503, "canonical memory database is unreadable") from exc


def _fts_query(query: str) -> str:
    words = re.findall(r"\w+", query, re.UNICODE)
    return " OR ".join(words) if words else query


def _has_fts(con: sqlite3.Connection) -> bool:
    return (
        con.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='items_fts'"
        ).fetchone()
        is not None
    )


def _keyword_search(
    con: sqlite3.Connection,
    query: str,
    namespace: str | None,
    limit: int,
) -> list[sqlite3.Row]:
    if _has_fts(con):
        sql = (
            "SELECT i.* FROM items_fts f JOIN items i ON i.id=f.rowid "
            "WHERE items_fts MATCH ?"
        )
        args: list[object] = [_fts_query(query)]
        if namespace:
            sql += " AND i.namespace=?"
            args.append(namespace)
        sql += " ORDER BY bm25(items_fts) LIMIT ?"
        args.append(limit)
        try:
            return con.execute(sql, args).fetchall()
        except sqlite3.OperationalError:
            pass
    like = "%" + query.replace("%", "") + "%"
    sql = "SELECT * FROM items WHERE text LIKE ?"
    args = [like]
    if namespace:
        sql += " AND namespace=?"
        args.append(namespace)
    sql += " LIMIT ?"
    args.append(limit)
    return con.execute(sql, args).fetchall()


def _namespaces(con: sqlite3.Connection) -> list[dict[str, Any]]:
    rows = con.execute(
        "SELECT namespace, COUNT(*) n FROM items "
        "GROUP BY namespace ORDER BY n DESC"
    ).fetchall()
    return [{"namespace": row["namespace"], "count": row["n"]} for row in rows]


def _count(con: sqlite3.Connection) -> int:
    return int(con.execute("SELECT COUNT(*) c FROM items").fetchone()["c"])


def browse_memory(
    path: Path,
    *,
    query: str = "",
    namespace: str | None = None,
    limit: int = DEFAULT_LIMIT,
) -> dict[str, Any]:
    con = _open_connection(path)
    try:
        if query:
            rows = _keyword_search(con, query, namespace, limit)
        else:
            sql = "SELECT * FROM items"
            args: list[object] = []
            if namespace:
                sql += " WHERE namespace=?"
                args.append(namespace)
            sql += " ORDER BY id DESC LIMIT ?"
            args.append(limit)
            rows = con.execute(sql, args).fetchall()
        return {
            "ok": True,
            "read_only": True,
            "execution_authority": "NONE",
            "can_execute": False,
            "query": query,
            "namespace": namespace,
            "limit": limit,
            "count": _count(con),
            "namespaces": _namespaces(con),
            "items": [_row_payload(row) for row in rows],
        }
    except (OSError, sqlite3.Error) as exc:
        raise MemoryExplorerError(503, "canonical memory query failed") from exc
    finally:
        con.close()


def get_memory_item(path: Path, item_id: int) -> dict[str, Any]:
    con = _open_connection(path)
    try:
        row = con.execute("SELECT * FROM items WHERE id=?", (item_id,)).fetchone()
        if row is None:
            raise MemoryExplorerError(404, "memory item not found")
        return {
            "ok": True,
            "read_only": True,
            "execution_authority": "NONE",
            "can_execute": False,
            "item": _row_payload(row),
        }
    except MemoryExplorerError:
        raise
    except (OSError, sqlite3.Error) as exc:
        raise MemoryExplorerError(503, "canonical memory query failed") from exc
    finally:
        con.close()
