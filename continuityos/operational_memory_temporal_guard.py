"""Lazy temporal-sanity guard for shadow-memory authority timestamps.

R46 preserves the historical R37/R38 implementation bytes and wraps only their
shared authorization-validator boundaries after module import. R44 and R41 reuse
those validators, so both read-only preflights and both effectful gates reject
implausibly future authority timestamps before any write can occur.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from functools import wraps
from importlib.abc import Loader, MetaPathFinder
from importlib.machinery import PathFinder
import sys
from types import ModuleType

_TARGET_FIELDS = {
    "continuityos.operational_memory_apply": "apply_recorded_at",
    "continuityos.project_memory_bootstrap": "bootstrap_recorded_at",
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
        normalized = module._normalize_time(
            authorization[field],
            field=field,
        )
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
        if fullname not in _TARGET_FIELDS:
            return None
        spec = PathFinder.find_spec(fullname, path)
        if spec is None or spec.loader is None:
            return spec
        if isinstance(spec.loader, _TemporalGuardLoader):
            return spec
        spec.loader = _TemporalGuardLoader(spec.loader)
        return spec


def install_operational_memory_temporal_guard() -> None:
    """Install lazy R46 guards without eagerly importing R37/R38 code."""
    if not any(
        getattr(finder, "__continuityos_r46_temporal_guard_finder__", False)
        for finder in sys.meta_path
    ):
        sys.meta_path.insert(0, _TemporalGuardFinder())

    for target in _TARGET_FIELDS:
        module = sys.modules.get(target)
        if module is not None:
            _patch(module)
