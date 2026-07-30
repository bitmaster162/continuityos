"""ContinuityOS governance and shadow-gate primitives.

Imports are lazy so the read-only ANTI_AMNESIA entry point does not initialize
the legacy ledger, policy, database, or recovery plane.
"""
from __future__ import annotations

from importlib import import_module
from typing import Dict, Tuple


__all__ = [
    "ActionSpec",
    "DECISIONS",
    "preflight",
    "Ledger",
    "load_policy",
    "DEFAULT_POLICY",
    "PolicyError",
]

_LAZY: Dict[str, Tuple[str, str]] = {
    "ActionSpec": (".spec", "ActionSpec"),
    "DECISIONS": (".spec", "DECISIONS"),
    "preflight": (".engine", "preflight"),
    "Ledger": (".ledger", "Ledger"),
    "load_policy": (".policy", "load_policy"),
    "DEFAULT_POLICY": (".policy", "DEFAULT_POLICY"),
    "PolicyError": (".policy", "PolicyError"),
}


def __getattr__(name: str):
    try:
        module_name, attribute_name = _LAZY[name]
    except KeyError as exc:
        raise AttributeError(name) from exc
    value = getattr(import_module(module_name, __name__), attribute_name)
    globals()[name] = value
    return value
