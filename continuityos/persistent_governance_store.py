"""Shared path invariant for persistent governance stores.

Persistent governance authority must never depend on an implicit working
directory, SQLite in-memory mode, or SQLite URI reinterpretation.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any


def require_persistent_governance_store_path(
    value: Any,
    *,
    label: str = "persistent governance store",
    field: str = "path",
) -> Path:
    """Return an expanded lexical absolute path or fail closed."""
    try:
        raw = os.fspath(value)
    except TypeError as exc:
        raise ValueError(f"{label}: file-backed path required") from exc
    if type(raw) is not str or not raw or raw == ":memory:":
        raise ValueError(f"{label}: file-backed path required")
    if raw.casefold().startswith("file:"):
        raise ValueError(f"{label}: SQLite URI paths are not allowed")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in raw):
        raise ValueError(f"{label}: control character in path")
    path = Path(raw).expanduser()
    if not path.is_absolute():
        raise ValueError(f"{label}: absolute {field} required")
    return path


def resolve_persistent_governance_store_path(
    value: Any,
    *,
    label: str = "persistent governance store",
    field: str = "path",
) -> Path:
    """Apply the shared invariant and then resolve filesystem aliases."""
    return require_persistent_governance_store_path(
        value, label=label, field=field
    ).resolve()


__all__ = [
    "require_persistent_governance_store_path",
    "resolve_persistent_governance_store_path",
]
