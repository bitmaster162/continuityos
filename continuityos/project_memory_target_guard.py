"""Lazy target-path canonicalization guard for R38 project-memory bootstrap.

R40 preserves the historical R38 implementation bytes and patches only its
``_safe_parent`` boundary after module import. The authorization binds one exact
``target_db`` pathname, so a lexical target whose physical parent differs because
of a symlink, junction, or reparse ancestor must fail before any SQLite effect.
"""
from __future__ import annotations

from functools import wraps
from importlib.abc import Loader, MetaPathFinder
from importlib.machinery import PathFinder
from pathlib import Path
import sys
from types import ModuleType

_TARGET = "continuityos.project_memory_bootstrap"


def _patch(module: ModuleType) -> None:
    original = module._safe_parent
    if getattr(original, "__continuityos_r40_target_path_guarded__", False):
        return

    @wraps(original)
    def guarded_safe_parent(target):
        target_path = Path(target)
        resolved = original(target_path)
        parent = target_path.parent
        if resolved != parent:
            raise ValueError("target parent path traverses symlink/reparse ancestor")
        return resolved

    guarded_safe_parent.__continuityos_r40_target_path_guarded__ = True
    module._safe_parent = guarded_safe_parent


class _TargetPathGuardLoader(Loader):
    def __init__(self, wrapped: Loader):
        self.wrapped = wrapped

    def create_module(self, spec):
        create = getattr(self.wrapped, "create_module", None)
        return create(spec) if create is not None else None

    def exec_module(self, module):
        self.wrapped.exec_module(module)
        _patch(module)

    def __getattr__(self, name: str):
        return getattr(self.wrapped, name)


class _TargetPathGuardFinder(MetaPathFinder):
    __continuityos_r40_target_path_guard_finder__ = True

    def find_spec(self, fullname, path=None, target=None):
        if fullname != _TARGET:
            return None
        spec = PathFinder.find_spec(fullname, path)
        if spec is None or spec.loader is None:
            return spec
        if isinstance(spec.loader, _TargetPathGuardLoader):
            return spec
        spec.loader = _TargetPathGuardLoader(spec.loader)
        return spec


def install_project_memory_target_path_guard() -> None:
    """Install the lazy R40 guard without eagerly importing R38 bootstrap code."""
    if not any(
        getattr(finder, "__continuityos_r40_target_path_guard_finder__", False)
        for finder in sys.meta_path
    ):
        sys.meta_path.insert(0, _TargetPathGuardFinder())

    module = sys.modules.get(_TARGET)
    if module is not None:
        _patch(module)
