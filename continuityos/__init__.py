"""ContinuityOS — durable, hybrid memory + continuity layer.

Public objects are loaded lazily.  This keeps narrow, stdlib-only entry points
usable when optional or unrelated product modules are unavailable, while
preserving the historical package API for callers that request those objects.
"""
from __future__ import annotations

from importlib import import_module
from typing import Dict, Tuple

from ._version import __version__


__all__ = [
    "Memory",
    "MemoryItem",
    "Continuity",
    "Council",
    "Actor",
    "Twin",
    "ControlPlane",
    "OperationalMemory",
    "OperationalMemoryError",
    "IdentityConflict",
    "PolicyViolation",
    "IntegrityFailure",
    "fork",
]

_LAZY: Dict[str, Tuple[str, str | None]] = {
    "Memory": (".memory", "Memory"),
    "MemoryItem": (".memory", "MemoryItem"),
    "Continuity": (".continuity", "Continuity"),
    "Council": (".agents", "Council"),
    "Actor": (".agents", "Actor"),
    "Twin": (".twin", "Twin"),
    "ControlPlane": (".control", "ControlPlane"),
    "OperationalMemory": (".operational_memory", "OperationalMemory"),
    "OperationalMemoryError": (".operational_memory", "OperationalMemoryError"),
    "IdentityConflict": (".operational_memory", "IdentityConflict"),
    "PolicyViolation": (".operational_memory", "PolicyViolation"),
    "IntegrityFailure": (".operational_memory", "IntegrityFailure"),
    "fork": (".fork", None),
}


def __getattr__(name: str):
    try:
        module_name, attribute_name = _LAZY[name]
    except KeyError as exc:
        raise AttributeError(name) from exc
    module = import_module(module_name, __name__)
    value = module if attribute_name is None else getattr(module, attribute_name)
    globals()[name] = value
    return value
