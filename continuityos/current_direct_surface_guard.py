"""Lazy direct-import containment for verified current ContinuityOS sessions.

R26 closes the public CLI/package/service adapters, but Python callers can still
address a few historical implementation modules directly.  R27 keeps those
historical modules byte-compatible and lazy while wrapping only their effectful
surfaces after import:

* ``continuityos.operational_memory.OperationalMemory``
* ``continuityos.gate.engine.preflight``
* ``continuityos.gate.ledger.Ledger``
* ``continuityos.mcp_server`` service lifecycle

The import hook itself is stdlib-only and does not import any target module.
Legacy/no-binding behavior delegates unchanged.  Once a current session is
declared, exact R23/R64 binding verification from ``current_effect_boundary``
is authoritative and effectful operations fail closed.
"""
from __future__ import annotations

import contextlib
import os
from pathlib import Path
import sqlite3
import sys
import time
from functools import wraps
from importlib import import_module
from importlib.abc import Loader, MetaPathFinder
from importlib.machinery import PathFinder
from types import ModuleType
from typing import Any

_OPERATIONAL_MEMORY = "continuityos.operational_memory"
_GATE_ENGINE = "continuityos.gate.engine"
_GATE_LEDGER = "continuityos.gate.ledger"
_MCP_SERVER = "continuityos.mcp_server"
_TARGETS = {_OPERATIONAL_MEMORY, _GATE_ENGINE, _GATE_LEDGER, _MCP_SERVER}
_EXECUTION_BLOCK_TARGETS = {_OPERATIONAL_MEMORY, _MCP_SERVER}


def _boundary():
    # Deliberately lazy: importing ``continuityos`` alone must not load current
    # runtime, legacy gate, memory databases, MCP, or service modules.
    return import_module("continuityos.current_effect_boundary")


def _guard_module_execution(fullname: str) -> None:
    """Fail before ``python -m`` can execute a legacy/current-incompatible CLI."""
    if fullname not in _EXECUTION_BLOCK_TARGETS:
        return
    boundary = _boundary()
    state = boundary.inspect_current_session()
    if state["mode"] == boundary.MODE_LEGACY:
        return
    effect = (
        "operational_memory.module_execute"
        if fullname == _OPERATIONAL_MEMORY
        else "mcp.server_start"
    )
    raise boundary.CurrentEffectBoundaryError(effect, state)


def _patch_operational_memory(module: ModuleType) -> None:
    original = module.OperationalMemory
    if getattr(original, "__continuityos_r27_guarded__", False):
        return

    class GuardedOperationalMemory(original):
        __continuityos_r27_guarded__ = True

        def __init__(
            self,
            path: str | None = None,
            *,
            read_only: bool = False,
            immutable: bool = False,
        ):
            boundary = _boundary()
            state = boundary.inspect_current_session()
            if state["mode"] == boundary.MODE_LEGACY:
                super().__init__(path, read_only=read_only, immutable=immutable)
                return
            if state["mode"] != boundary.MODE_CURRENT:
                raise boundary.CurrentEffectBoundaryError(
                    "operational_memory.open", state
                )

            # Force read-only before the historical constructor reaches mkdir,
            # sqlite file creation, WAL setup or schema initialization.
            super().__init__(path, read_only=True, immutable=immutable)

        @contextlib.contextmanager
        def _write_tx(self):
            # Re-check at mutation time so an object created before the current
            # binding cannot remain a writable capability after the binding appears.
            boundary = _boundary()
            boundary.assert_current_effect_allowed("operational_memory.write")
            with super()._write_tx() as con:
                yield con

    GuardedOperationalMemory.__name__ = original.__name__
    GuardedOperationalMemory.__qualname__ = original.__qualname__
    GuardedOperationalMemory.__module__ = module.__name__
    GuardedOperationalMemory.__doc__ = original.__doc__
    module.OperationalMemory = GuardedOperationalMemory


def _patch_gate_engine(module: ModuleType) -> None:
    original = module.preflight
    if getattr(original, "__continuityos_r27_guarded__", False):
        return

    @wraps(original)
    def guarded_preflight(spec, policy=None, ledger=None, context=None):
        boundary = _boundary()
        hold = boundary.current_hold_for_action(spec.to_dict())
        if hold is not None:
            hold["ts"] = time.time()
            hold["context"]["supplied"] = context is not None
            return hold
        return original(spec, policy=policy, ledger=ledger, context=context)

    guarded_preflight.__continuityos_r27_guarded__ = True
    module.preflight = guarded_preflight


def _patch_gate_ledger(module: ModuleType) -> None:
    original = module.Ledger
    if getattr(original, "__continuityos_r27_guarded__", False):
        return

    class GuardedLedger(original):
        __continuityos_r27_guarded__ = True

        def __init__(self, path: str = "continuity_ledger.db"):
            boundary = _boundary()
            state = boundary.inspect_current_session()
            if state["mode"] == boundary.MODE_LEGACY:
                super().__init__(path)
                self.path = path
                self.read_only = False
                return
            if state["mode"] != boundary.MODE_CURRENT:
                raise boundary.CurrentEffectBoundaryError("legacy_gate.ledger.open", state)

            # A direct historical Ledger import may inspect an existing ledger in
            # current mode, but it must not create a path, WAL, table or event.
            normalized = os.path.normcase(
                os.path.realpath(os.path.abspath(os.path.expanduser(path)))
            )
            if not os.path.isfile(normalized):
                raise FileNotFoundError(normalized)
            self.path = normalized
            self.read_only = True
            self.con = sqlite3.connect(
                Path(normalized).as_uri() + "?mode=ro",
                uri=True,
                timeout=30.0,
            )
            self.con.row_factory = sqlite3.Row
            self.con.execute("PRAGMA query_only=ON")

        def append(self, kind: str, payload: dict[str, Any]) -> str:
            boundary = _boundary()
            state = boundary.inspect_current_session()
            if state["mode"] != boundary.MODE_LEGACY:
                raise boundary.CurrentEffectBoundaryError(
                    "legacy_gate.ledger.append", state
                )
            # Monotonic instance clamp: clearing an environment binding later does
            # not convert a connection opened read-only into a write capability.
            if getattr(self, "read_only", False):
                raise RuntimeError("ledger instance was opened read-only")
            return super().append(kind, payload)

    GuardedLedger.__name__ = original.__name__
    GuardedLedger.__qualname__ = original.__qualname__
    GuardedLedger.__module__ = module.__name__
    GuardedLedger.__doc__ = original.__doc__
    module.Ledger = GuardedLedger


def _patch_mcp_server(module: ModuleType) -> None:
    original_main = module.main
    if not getattr(original_main, "__continuityos_r27_guarded__", False):
        @wraps(original_main)
        def guarded_main(*args, **kwargs):
            boundary = _boundary()
            boundary.assert_current_effect_allowed("mcp.server_start")
            return original_main(*args, **kwargs)

        guarded_main.__continuityos_r27_guarded__ = True
        module.main = guarded_main

    original_server = module.Server
    if getattr(original_server, "__continuityos_r27_guarded__", False):
        return

    class GuardedServer(original_server):
        __continuityos_r27_guarded__ = True

        def __init__(self, *args, **kwargs):
            boundary = _boundary()
            boundary.assert_current_effect_allowed("mcp.server_start")
            super().__init__(*args, **kwargs)

    GuardedServer.__name__ = original_server.__name__
    GuardedServer.__qualname__ = original_server.__qualname__
    GuardedServer.__module__ = module.__name__
    GuardedServer.__doc__ = original_server.__doc__
    module.Server = GuardedServer


def _patch_module(fullname: str, module: ModuleType) -> None:
    if fullname == _OPERATIONAL_MEMORY:
        _patch_operational_memory(module)
    elif fullname == _GATE_ENGINE:
        _patch_gate_engine(module)
    elif fullname == _GATE_LEDGER:
        _patch_gate_ledger(module)
    elif fullname == _MCP_SERVER:
        _patch_mcp_server(module)


class _GuardLoader(Loader):
    def __init__(self, fullname: str, wrapped: Loader):
        self.fullname = fullname
        self.wrapped = wrapped

    def create_module(self, spec):
        create = getattr(self.wrapped, "create_module", None)
        return create(spec) if create is not None else None

    def exec_module(self, module):
        self.wrapped.exec_module(module)
        _patch_module(self.fullname, module)

    def get_code(self, fullname):
        # ``runpy`` / ``python -m`` can ask a loader for code without calling our
        # ``exec_module`` wrapper.  Refuse executable legacy surfaces first.
        _guard_module_execution(self.fullname)
        return self.wrapped.get_code(fullname)

    def __getattr__(self, name: str):
        return getattr(self.wrapped, name)


class _DirectSurfaceFinder(MetaPathFinder):
    __continuityos_r27_guard_finder__ = True

    def find_spec(self, fullname, path=None, target=None):
        if fullname not in _TARGETS:
            return None
        spec = PathFinder.find_spec(fullname, path)
        if spec is None or spec.loader is None:
            return spec
        if isinstance(spec.loader, _GuardLoader):
            return spec
        spec.loader = _GuardLoader(fullname, spec.loader)
        return spec


def install_direct_surface_guards() -> None:
    """Install one lazy finder and patch any target already present in-process."""
    if not any(
        getattr(finder, "__continuityos_r27_guard_finder__", False)
        for finder in sys.meta_path
    ):
        sys.meta_path.insert(0, _DirectSurfaceFinder())

    # Supports package reload/upgrade inside a long-running interpreter without
    # importing targets that were not already loaded.
    for fullname in _TARGETS:
        module = sys.modules.get(fullname)
        if module is not None:
            _patch_module(fullname, module)
