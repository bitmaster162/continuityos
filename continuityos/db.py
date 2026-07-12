"""Deterministic memory-database resolution and read-only context identity."""
from __future__ import annotations

import contextlib
import hashlib
import json
import os
import sqlite3
from pathlib import Path
from typing import Any, Dict, Mapping, Optional


DEFAULT_MEMORY_DB = "~/.continuityos/memory.db"
CONTEXT_DIGEST_SCHEME = "sha256-canon-rules-logical-v1"
_CONTEXT_COLUMNS = (
    "id", "namespace", "text", "tags", "meta", "vec",
    "created_at", "updated_at", "key", "version",
)


def resolve_memory_db(
    explicit: Optional[str] = None,
    *,
    environ: Optional[Mapping[str, str]] = None,
    default: Optional[str] = None,
) -> Dict[str, Any]:
    """Resolve one DB authority: explicit flag, then environment, then default."""
    env = os.environ if environ is None else environ
    if explicit is not None:
        raw = explicit
        source = "explicit"
    elif "CONTINUITYOS_DB" in env:
        raw = env.get("CONTINUITYOS_DB", "")
        source = "environment"
    else:
        raw = default if default is not None else DEFAULT_MEMORY_DB
        source = "default"
    if not isinstance(raw, str) or not raw.strip():
        raise ValueError(f"{source} memory database path is empty")
    if raw == ":memory:":
        path = raw
    else:
        expanded = os.path.expandvars(os.path.expanduser(raw))
        path = os.path.normcase(os.path.realpath(os.path.abspath(expanded)))
    return {
        "path": path,
        "source": source,
        "configured": source in ("explicit", "environment"),
    }


def _fingerprint_connection(con: sqlite3.Connection, path: str) -> Dict[str, Any]:
    con.row_factory = sqlite3.Row
    table = con.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='items'"
    ).fetchone()
    if table is None:
        raise ValueError("memory database has no items table")
    columns = {row[1] for row in con.execute("PRAGMA table_info(items)")}
    missing = set(_CONTEXT_COLUMNS) - columns
    if missing:
        raise ValueError(
            "memory database items schema is missing: " + ", ".join(sorted(missing))
        )
    rows = con.execute(
        "SELECT " + ",".join(_CONTEXT_COLUMNS)
        + " FROM items WHERE namespace IN ('canon','rules') ORDER BY id"
    ).fetchall()
    logical_rows = []
    for row in rows:
        item = {}
        for name in _CONTEXT_COLUMNS:
            value = row[name]
            if isinstance(value, bytes):
                value = {"encoding": "hex", "value": value.hex()}
            item[name] = value
        logical_rows.append(item)
    body = json.dumps(
        {
            "scheme": CONTEXT_DIGEST_SCHEME,
            "namespaces": ["canon", "rules"],
            "columns": list(_CONTEXT_COLUMNS),
            "rows": logical_rows,
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return {
        "path": path,
        "path_sha256": hashlib.sha256(path.encode("utf-8")).hexdigest(),
        "context_sha256": hashlib.sha256(body.encode("utf-8")).hexdigest(),
        "row_count": len(logical_rows),
        "scheme": CONTEXT_DIGEST_SCHEME,
    }


def context_fingerprint(path: str) -> Dict[str, Any]:
    """Hash logical canon/rules rows through a SQL/content-read-only connection.

    Reading through SQLite (rather than hashing only the main file) includes committed
    WAL state. Canonical JSON makes the receipt independent of page layout, VACUUM,
    and filesystem timestamp changes.
    """
    if path == ":memory:":
        raise ValueError("an in-memory DB requires context_identity() on its live connection")
    normalized = os.path.normcase(os.path.realpath(os.path.abspath(path)))
    if not os.path.isfile(normalized):
        raise FileNotFoundError(f"memory database not found: {normalized}")
    uri = Path(normalized).as_uri() + "?mode=ro"
    con = sqlite3.connect(uri, uri=True, timeout=5.0)
    try:
        return _fingerprint_connection(con, normalized)
    finally:
        con.close()


def context_identity(context) -> Dict[str, Any]:
    """Fingerprint the exact live Memory/Continuity connection used by preflight."""
    memory = context.m if hasattr(context, "m") else context
    store = getattr(memory, "store", None)
    if store is None or not hasattr(store, "con"):
        raise TypeError(f"unsupported context type: {type(context).__name__}")
    lock = getattr(store, "_lock", contextlib.nullcontext())
    with lock:
        databases = store.con.execute("PRAGMA database_list").fetchall()
        main_file = next(
            (row[2] for row in databases if row[1] == "main"),
            "",
        )
        path = (
            os.path.normcase(os.path.realpath(os.path.abspath(main_file)))
            if main_file
            else ":memory:"
        )
        identity = _fingerprint_connection(store.con, path)
    source = getattr(context, "_context_source", None)
    if source:
        identity["source"] = source
    return identity


def open_existing_context(path: str, *, source: str = ""):
    """Open and fingerprint one existing governance context without mutation.

    The SQLite handle uses ``mode=ro`` so a path removed or replaced after DB
    resolution cannot be recreated or migrated by the context constructor.  The
    fingerprint is computed from that exact live handle, closing the
    validate-then-open race of a path-only precheck.
    """
    from .continuity import Continuity

    context = Continuity(db=path, read_only=True)
    try:
        identity = context_identity(context)
    except Exception:
        context.m.store.con.close()
        raise
    if source:
        identity["source"] = source
        context._context_source = source
    return context, identity


@contextlib.contextmanager
def context_read_snapshot(context):
    """Hold one local lock and SQLite read snapshot across digest + evaluation."""
    memory = context.m if hasattr(context, "m") else context
    store = getattr(memory, "store", None)
    if store is None or not hasattr(store, "con"):
        raise TypeError(f"unsupported context type: {type(context).__name__}")
    lock = getattr(store, "_lock", contextlib.nullcontext())
    with lock:
        owns_transaction = not store.con.in_transaction
        if owns_transaction:
            store.con.execute("BEGIN")
        try:
            yield
        finally:
            if owns_transaction and store.con.in_transaction:
                store.con.rollback()
