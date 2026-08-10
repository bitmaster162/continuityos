"""ContinuityOS — durable, hybrid memory + continuity layer.

Public objects are loaded lazily.  This keeps narrow, stdlib-only entry points
usable when optional or unrelated product modules are unavailable, while
preserving the historical package API for callers that request those objects.
"""
from __future__ import annotations

from importlib import import_module
from typing import Dict, Tuple

from ._version import __version__
from .current_direct_surface_guard import install_direct_surface_guards
from .project_memory_target_guard import install_project_memory_target_path_guard
from .operational_memory_temporal_guard import install_operational_memory_temporal_guard
from .operational_memory_replay_guard import install_operational_memory_replay_guard
from .operational_memory_target_binding_guard import install_operational_memory_target_binding_guard
from .project_update_snapshot_guard import install_project_update_snapshot_guard

# Install only stdlib meta-path watchers here. They do not import guarded target
# modules and therefore preserve the package's historical lazy-loading property.
# Guards are applied only when a target is later imported.
install_direct_surface_guards()
install_project_memory_target_path_guard()
install_operational_memory_temporal_guard()
install_operational_memory_replay_guard()
install_operational_memory_target_binding_guard()
install_project_update_snapshot_guard()


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
    "verify_context_pack",
    "prepare_context_pack",
    "build_context_pack",
    "OperationalContextError",
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
    "verify_context_pack": (".operational_context", "verify_context_pack"),
    "prepare_context_pack": (".operational_context", "prepare_context_pack"),
    "build_context_pack": (".operational_context", "build_context_pack"),
    "OperationalContextError": (".operational_context", "OperationalContextError"),
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
