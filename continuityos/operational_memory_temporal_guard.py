"""Lazy temporal-sanity guard for shadow-memory authority timestamps.

R46 preserves the historical R37/R38 implementation bytes. It owns a lazy loader
only for R37. For R38, which is already guarded by R40, R46 composes its temporal
patch into the existing R40 post-import patch instead of installing a competing
meta-path finder. This guarantees target-path canonicalization and temporal sanity
are both active on project-memory bootstrap.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from functools import wraps
from importlib.abc import Loader, MetaPathFinder
from importlib.machinery import PathFinder
import sys
from types import ModuleType

_APPLY_TARGET = "continuityos.operational_memory_apply"
_BOOTSTRAP_TARGET = "continuityos.project_memory_bootstrap"
_R40_GUARD_MODULE = "continuityos.project_memory_target_guard"
_TARGET_FIELDS = {
    _APPLY_TARGET: "apply_recorded_at",
    _BOOTSTRAP_TARGET: "bootstrap_recorded_at",
}
MAX_AUTH_FUTURE_SKEW_SECONDS = 300


def _utc_now() -> datetime:
    """Wall-clock source isolated for deterministic temporal-sanity tests."""
    return datetime.now(timezone.utc)


def _patch(module: ModuleType) -> None:
    field = _TARGET_FIELDS.get(module.__name__)
    if field is None:
        return
    original = module._validate_authorization
    if getattr(original, "__continuityos_r46_temporal_guarded__", False):
        return

    @wraps(original)
    def guarded_validate_authorization(*args, **kwargs):
        authorization = original(*args, **kwargs)
        normalized = module._normalize_time(authorization[field], field=field)
        authority_time = datetime.fromisoformat(normalized.replace("Z", "+00:00"))
        latest = _utc_now() + timedelta(seconds=MAX_AUTH_FUTURE_SKEW_SECONDS)
        if authority_time > latest:
            raise ValueError(
                f"{field} exceeds allowed future clock skew of "
                f"{MAX_AUTH_FUTURE_SKEW_SECONDS} seconds"
            )
        return authorization

    guarded_validate_authorization.__continuityos_r46_temporal_guarded__ = True
    module._validate_authorization = guarded_validate_authorization


class _TemporalGuardLoader(Loader):
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


class _TemporalGuardFinder(MetaPathFinder):
    __continuityos_r46_temporal_guard_finder__ = True

    def find_spec(self, fullname, path=None, target=None):
        # R38 is deliberately not handled here: R40 already owns its loader.
        if fullname != _APPLY_TARGET:
            return None
        spec = PathFinder.find_spec(fullname, path)
        if spec is None or spec.loader is None:
            return spec
        if isinstance(spec.loader, _TemporalGuardLoader):
            return spec
        spec.loader = _TemporalGuardLoader(spec.loader)
        return spec


def _compose_with_r40() -> None:
    """Append R46's R38 patch to R40's existing post-import patch chain."""
    r40 = sys.modules.get(_R40_GUARD_MODULE)
    if r40 is None:
        raise RuntimeError("R40 project-memory target guard must be loaded before R46")
    original = r40._patch
    if getattr(original, "__continuityos_r46_temporal_composed__", False):
        return

    @wraps(original)
    def combined_patch(module):
        original(module)
        _patch(module)

    combined_patch.__continuityos_r46_temporal_composed__ = True
    r40._patch = combined_patch


def install_operational_memory_temporal_guard() -> None:
    """Install R46 while preserving the existing R40 bootstrap loader guard."""
    _compose_with_r40()

    if not any(
        getattr(finder, "__continuityos_r46_temporal_guard_finder__", False)
        for finder in sys.meta_path
    ):
        sys.meta_path.insert(0, _TemporalGuardFinder())

    apply_module = sys.modules.get(_APPLY_TARGET)
    if apply_module is not None:
        _patch(apply_module)

    # If R38 was imported before this installer, R40 has already patched it; add
    # the temporal layer directly. Otherwise R40's composed loader will do both.
    bootstrap_module = sys.modules.get(_BOOTSTRAP_TARGET)
    if bootstrap_module is not None:
        _patch(bootstrap_module)
