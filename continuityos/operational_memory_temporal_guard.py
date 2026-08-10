"""Lazy temporal-sanity guard for R37 shadow-memory authorizations.

R46 preserves the historical R37 implementation bytes and wraps only its shared
``_validate_authorization`` boundary after module import. R44 reuses that same
validator, so both point-in-time preflight and the effectful R37 gate reject an
implausibly future ``apply_recorded_at`` before any write can occur.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from functools import wraps
from importlib.abc import Loader, MetaPathFinder
from importlib.machinery import PathFinder
import sys
from types import ModuleType

_TARGET = "continuityos.operational_memory_apply"
MAX_AUTH_FUTURE_SKEW_SECONDS = 300


def _utc_now() -> datetime:
    """Wall-clock source isolated for deterministic temporal-sanity tests."""
    return datetime.now(timezone.utc)


def _patch(module: ModuleType) -> None:
    original = module._validate_authorization
    if getattr(original, "__continuityos_r46_temporal_guarded__", False):
        return

    @wraps(original)
    def guarded_validate_authorization(value, *, proposal, proposal_file_sha256):
        authorization = original(
            value,
            proposal=proposal,
            proposal_file_sha256=proposal_file_sha256,
        )
        normalized = module._normalize_time(
            authorization["apply_recorded_at"],
            field="apply_recorded_at",
        )
        apply_time = datetime.fromisoformat(normalized.replace("Z", "+00:00"))
        latest = _utc_now() + timedelta(seconds=MAX_AUTH_FUTURE_SKEW_SECONDS)
        if apply_time > latest:
            raise ValueError(
                "apply_recorded_at exceeds allowed future clock skew of "
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
        if fullname != _TARGET:
            return None
        spec = PathFinder.find_spec(fullname, path)
        if spec is None or spec.loader is None:
            return spec
        if isinstance(spec.loader, _TemporalGuardLoader):
            return spec
        spec.loader = _TemporalGuardLoader(spec.loader)
        return spec


def install_operational_memory_temporal_guard() -> None:
    """Install the lazy R46 guard without eagerly importing R37 apply code."""
    if not any(
        getattr(finder, "__continuityos_r46_temporal_guard_finder__", False)
        for finder in sys.meta_path
    ):
        sys.meta_path.insert(0, _TemporalGuardFinder())

    module = sys.modules.get(_TARGET)
    if module is not None:
        _patch(module)
