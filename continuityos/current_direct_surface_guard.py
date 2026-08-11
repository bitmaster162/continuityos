"""Lazy direct-import containment for verified current ContinuityOS sessions.

R27 closed direct Python/module bypasses left by R26. R28 extended the same
stdlib-only boundary to residual public-library filesystem/network/subprocess/
server/simulation effects. R29 closes the last confirmed raw product effects from
the residual audit: local metering SQLite mutation and optional model-loader
construction that may download/cache model assets.

Guarded implementation modules remain byte-compatible. Importing ``continuityos``
installs only a meta-path watcher; target modules are still loaded lazily.
Legacy/no-binding behavior delegates unchanged. In a declared current session,
exact R23/R64 binding verification from ``current_effect_boundary`` is
authoritative and effectful calls fail closed.

Read-only builders, validators, renderers, verifiers and already-loaded local
inference remain usable. This is an effect boundary, not a blanket import ban.
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
_UPDATER = "continuityos.updater"
_RULES_EXPORT = "continuityos.rules_export"
_OPERATIONAL_CONTEXT = "continuityos.operational_context"
_SESSION_INPUT = "continuityos.session_input"
_WIZARD = "continuityos.wizard"
_SIM_LOOP = "continuityos.sim.loop"
_FORK = "continuityos.fork"
_LEDGER_SERVER = "continuityos.ledger_server"
_METERING = "continuityos.metering"
_EMBEDDERS = "continuityos.embedders"

_TARGETS = {
    _OPERATIONAL_MEMORY,
    _GATE_ENGINE,
    _GATE_LEDGER,
    _MCP_SERVER,
    _UPDATER,
    _RULES_EXPORT,
    _OPERATIONAL_CONTEXT,
    _SESSION_INPUT,
    _WIZARD,
    _SIM_LOOP,
    _FORK,
    _LEDGER_SERVER,
    _METERING,
    _EMBEDDERS,
}

# These modules have no current-safe command when executed with ``python -m``.
_EXECUTION_BLOCK_EFFECTS = {
    _OPERATIONAL_MEMORY: "operational_memory.module_execute",
    _MCP_SERVER: "mcp.server_start",
    _SIM_LOOP: "simulation.run",
}

# These historical modules have a pure verifier plus an effectful ``prepare``
# command. ``python -m ... verify`` stays available; ``prepare`` is held.
_SELECTIVE_EXECUTION_EFFECTS = {
    _OPERATIONAL_CONTEXT: {"prepare": "operational_context.prepare"},
    _SESSION_INPUT: {"prepare": "session_input.prepare"},
}


def _boundary():
    # Deliberately lazy: importing ``continuityos`` alone must not load current
    # runtime, legacy gate, memory databases, services, updater, or product APIs.
    return import_module("continuityos.current_effect_boundary")


def _assert_effect(effect: str) -> None:
    _boundary().assert_current_effect_allowed(effect)


def _guard_function(module: ModuleType, name: str, effect: str) -> None:
    original = getattr(module, name)
    if getattr(original, "__continuityos_direct_effect_guarded__", False):
        return

    @wraps(original)
    def guarded(*args, **kwargs):
        _assert_effect(effect)
        return original(*args, **kwargs)

    guarded.__continuityos_direct_effect_guarded__ = True
    setattr(module, name, guarded)


def _guard_module_execution(fullname: str) -> None:
    """Fail before ``python -m`` can execute a contained effectful command."""
    effect = _EXECUTION_BLOCK_EFFECTS.get(fullname)
    if effect is None:
        commands = _SELECTIVE_EXECUTION_EFFECTS.get(fullname)
        if commands:
            command = sys.argv[1] if len(sys.argv) > 1 else ""
            effect = commands.get(command)
    if effect is None:
        return

    boundary = _boundary()
    state = boundary.inspect_current_session()
    if state["mode"] == boundary.MODE_LEGACY:
        return
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
            _assert_effect("operational_memory.write")
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
            _assert_effect("mcp.server_start")
            return original_main(*args, **kwargs)

        guarded_main.__continuityos_r27_guarded__ = True
        module.main = guarded_main

    original_server = module.Server
    if getattr(original_server, "__continuityos_r27_guarded__", False):
        return

    class GuardedServer(original_server):
        __continuityos_r27_guarded__ = True

        def __init__(self, *args, **kwargs):
            _assert_effect("mcp.server_start")
            super().__init__(*args, **kwargs)

    GuardedServer.__name__ = original_server.__name__
    GuardedServer.__qualname__ = original_server.__qualname__
    GuardedServer.__module__ = module.__name__
    GuardedServer.__doc__ = original_server.__doc__
    module.Server = GuardedServer


def _patch_updater(module: ModuleType) -> None:
    # ``latest_pypi`` performs outbound HTTP. ``check`` may do that plus persist
    # ~/.continuityos/update_check.json. ``apply`` may run git/pip subprocesses.
    _guard_function(module, "latest_pypi", "updater.network_check")
    _guard_function(module, "check", "updater.check")
    _guard_function(module, "apply", "updater.apply")


def _patch_rules_export(module: ModuleType) -> None:
    original = module.export_rules
    if getattr(original, "__continuityos_direct_effect_guarded__", False):
        return

    @wraps(original)
    def guarded_export_rules(*args, **kwargs):
        dry_run = kwargs.get("dry_run", args[3] if len(args) > 3 else False)
        if not bool(dry_run):
            _assert_effect("rules_export.write")
        return original(*args, **kwargs)

    guarded_export_rules.__continuityos_direct_effect_guarded__ = True
    module.export_rules = guarded_export_rules


def _patch_operational_context(module: ModuleType) -> None:
    # build/validate/verify remain read-only. Only prepare creates an output file.
    _guard_function(module, "prepare_context_pack", "operational_context.prepare")


def _patch_session_input(module: ModuleType) -> None:
    # build/validate/verify remain read-only. Only prepare creates an output file.
    _guard_function(module, "prepare_session_input_manifest", "session_input.prepare")


def _patch_wizard(module: ModuleType) -> None:
    _guard_function(module, "run_wizard", "setup.run")
    _guard_function(module, "build_dashboard_only", "setup.dashboard_write")


def _patch_sim_loop(module: ModuleType) -> None:
    _guard_function(module, "run_loop", "simulation.run")
    _guard_function(module, "main", "simulation.run")


def _patch_fork(module: ModuleType) -> None:
    # child()/fork_point() are read/open helpers. snapshot creates a SQLite file;
    # merge_back mutates the parent memory and gets a boundary check here before
    # relying on the lower Store guard.
    _guard_function(module, "snapshot", "fork.snapshot_write")
    _guard_function(module, "merge_back", "fork.merge_back")


def _patch_ledger_server(module: ModuleType) -> None:
    _guard_function(module, "serve", "ledger_server.start")

    original_mint = module.mint_token
    if not getattr(original_mint, "__continuityos_direct_effect_guarded__", False):
        @wraps(original_mint)
        def guarded_mint_token(*args, **kwargs):
            scope = kwargs.get("scope", args[2] if len(args) > 2 else "read")
            if scope == "write":
                _assert_effect("ledger_server.write_token")
            return original_mint(*args, **kwargs)

        guarded_mint_token.__continuityos_direct_effect_guarded__ = True
        module.mint_token = guarded_mint_token

    sink = module.LedgerSink
    for name, effect in (
        ("record", "ledger_sink.record"),
        ("flush", "ledger_sink.flush"),
    ):
        original = getattr(sink, name)
        if getattr(original, "__continuityos_direct_effect_guarded__", False):
            continue

        @wraps(original)
        def guarded(self, *args, __original=original, __effect=effect, **kwargs):
            _assert_effect(__effect)
            return __original(self, *args, **kwargs)

        guarded.__continuityos_direct_effect_guarded__ = True
        setattr(sink, name, guarded)


def _patch_metering(module: ModuleType) -> None:
    original = module.Meter
    if getattr(original, "__continuityos_r29_guarded__", False):
        return

    class GuardedMeter(original):
        __continuityos_r29_guarded__ = True

        def __init__(self, path: str = "usage.db", window: float = module.DAY):
            boundary = _boundary()
            state = boundary.inspect_current_session()
            if state["mode"] == boundary.MODE_LEGACY:
                super().__init__(path, window=window)
                self.path = path
                self.read_only = False
                return
            if state["mode"] != boundary.MODE_CURRENT:
                raise boundary.CurrentEffectBoundaryError("metering.open", state)
            if path == ":memory:":
                raise boundary.CurrentEffectBoundaryError("metering.open", state)

            normalized = os.path.normcase(
                os.path.realpath(
                    os.path.abspath(os.path.expandvars(os.path.expanduser(path)))
                )
            )
            if not os.path.isfile(normalized):
                raise FileNotFoundError(normalized)
            wal = normalized + "-wal"
            if os.path.isfile(wal) and os.path.getsize(wal) > 0:
                raise RuntimeError("metering database is not quiescent")
            self.window = window
            self.path = normalized
            self.read_only = True
            self.db = sqlite3.connect(
                Path(normalized).as_uri() + "?mode=ro&immutable=1",
                uri=True,
            )
            self.db.execute("PRAGMA query_only=ON")

        def _assert_meter_write(self, effect: str) -> None:
            boundary = _boundary()
            state = boundary.inspect_current_session()
            if state["mode"] != boundary.MODE_LEGACY:
                raise boundary.CurrentEffectBoundaryError(effect, state)
            if getattr(self, "read_only", False):
                raise RuntimeError("meter instance was opened read-only")

        def set_plan(self, key: str, plan: str) -> None:
            self._assert_meter_write("metering.set_plan")
            return super().set_plan(key, plan)

        def record(self, key: str, event: str, units: int = 1) -> None:
            self._assert_meter_write("metering.record")
            return super().record(key, event, units=units)

        def charge(self, key: str, event: str, billing=None) -> dict:
            # Charge is effectful even when a particular branch might be over
            # quota, because its API contract includes an atomic count mutation.
            self._assert_meter_write("metering.charge")
            return super().charge(key, event, billing=billing)

    GuardedMeter.__name__ = original.__name__
    GuardedMeter.__qualname__ = original.__qualname__
    GuardedMeter.__module__ = module.__name__
    GuardedMeter.__doc__ = original.__doc__
    module.Meter = GuardedMeter


def _patch_embedders(module: ModuleType) -> None:
    # Optional model constructors may download/cache model assets through their
    # third-party loaders. Existing already-loaded instances remain usable for
    # local read-only inference after a current binding appears.
    for name, effect in (
        ("FastEmbedEmbedder", "embedder.fastembed.model_load"),
        ("Model2VecEmbedder", "embedder.model2vec.model_load"),
        ("SentenceTransformerEmbedder", "embedder.sentence_transformer.model_load"),
    ):
        cls = getattr(module, name)
        original_init = cls.__init__
        if getattr(original_init, "__continuityos_direct_effect_guarded__", False):
            continue

        @wraps(original_init)
        def guarded_init(self, *args, __original=original_init, __effect=effect, **kwargs):
            _assert_effect(__effect)
            return __original(self, *args, **kwargs)

        guarded_init.__continuityos_direct_effect_guarded__ = True
        cls.__init__ = guarded_init


def _patch_module(fullname: str, module: ModuleType) -> None:
    if fullname == _OPERATIONAL_MEMORY:
        _patch_operational_memory(module)
    elif fullname == _GATE_ENGINE:
        _patch_gate_engine(module)
    elif fullname == _GATE_LEDGER:
        _patch_gate_ledger(module)
    elif fullname == _MCP_SERVER:
        _patch_mcp_server(module)
    elif fullname == _UPDATER:
        _patch_updater(module)
    elif fullname == _RULES_EXPORT:
        _patch_rules_export(module)
    elif fullname == _OPERATIONAL_CONTEXT:
        _patch_operational_context(module)
    elif fullname == _SESSION_INPUT:
        _patch_session_input(module)
    elif fullname == _WIZARD:
        _patch_wizard(module)
    elif fullname == _SIM_LOOP:
        _patch_sim_loop(module)
    elif fullname == _FORK:
        _patch_fork(module)
    elif fullname == _LEDGER_SERVER:
        _patch_ledger_server(module)
    elif fullname == _METERING:
        _patch_metering(module)
    elif fullname == _EMBEDDERS:
        _patch_embedders(module)


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
        # ``exec_module`` wrapper. Refuse effectful module commands first.
        _guard_module_execution(self.fullname)
        return self.wrapped.get_code(fullname)

    def __getattr__(self, name: str):
        return getattr(self.wrapped, name)


class _DirectSurfaceFinder(MetaPathFinder):
    # Keep the R27 marker for upgrade/reload compatibility with an already
    # installed finder in a long-lived interpreter.
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
