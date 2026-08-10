"""Fail-closed authorization identity guard for already-applied R37 proposals.

R48 preserves the historical R37/R44 implementation bytes. R37 replay identity
was previously keyed only by proposal id/bytes. A second, different but structurally
valid authorization could therefore receive an ALREADY_APPLIED receipt whose top
level named the newly-presented authorization SHA while the durable apply event
still named the original authorization SHA.

This guard keeps exact replay idempotent only when both proposal and authorization
bytes match the durable apply event. A mismatched replay remains read-only and is
reported as REVISE with both identities made explicit.
"""
from __future__ import annotations

from functools import wraps
from importlib.abc import Loader, MetaPathFinder
from importlib.machinery import PathFinder
import sys
from types import ModuleType
from typing import Any, Mapping

_APPLY_TARGET = "continuityos.operational_memory_apply"
_CHECK_TARGET = "continuityos.current_memory_apply_check"
_TEMPORAL_GUARD_MODULE = "continuityos.operational_memory_temporal_guard"


def _replay_shas(result: Mapping[str, Any]) -> tuple[str | None, str | None]:
    presented = result.get("authorization_file_sha256")
    durable = result.get("durable_apply_event")
    payload = durable.get("payload") if isinstance(durable, Mapping) else None
    historical = payload.get("authorization_file_sha256") if isinstance(payload, Mapping) else None
    return (
        presented if isinstance(presented, str) else None,
        historical if isinstance(historical, str) else None,
    )


def _patch_apply(module: ModuleType) -> None:
    original = module.apply_authorized_memory_delta
    if getattr(original, "__continuityos_r48_replay_guarded__", False):
        return

    @wraps(original)
    def guarded_apply(*args, **kwargs):
        result = original(*args, **kwargs)
        if not isinstance(result, dict) or result.get("terminal") != "CURRENT_MEMORY_APPLY_ALREADY_APPLIED":
            return result
        presented, historical = _replay_shas(result)
        if presented is not None and historical is not None and presented == historical:
            return result
        return module._result(
            "CURRENT_MEMORY_APPLY_REVISE",
            "REPLAY_AUTHORIZATION_IDENTITY_MISMATCH",
            project_id=result.get("project_id"),
            proposal_id=result.get("proposal_id"),
            errors=[
                f"durable_authorization_file_sha256={historical}",
                f"presented_authorization_file_sha256={presented}",
            ],
            proposal_file_sha256=result.get("proposal_file_sha256"),
            historical_apply_status="ALREADY_APPLIED",
            presented_authorization_file_sha256=presented,
            durable_authorization_file_sha256=historical,
            durable_apply_event=result.get("durable_apply_event"),
            current_projection_sha256=result.get("current_projection_sha256"),
        )

    guarded_apply.__continuityos_r48_replay_guarded__ = True
    module.apply_authorized_memory_delta = guarded_apply


def _patch_check(module: ModuleType) -> None:
    original = module.check_authorized_memory_delta
    if getattr(original, "__continuityos_r48_replay_guarded__", False):
        return

    @wraps(original)
    def guarded_check(*args, **kwargs):
        result = original(*args, **kwargs)
        if not isinstance(result, dict) or result.get("terminal") != "CURRENT_MEMORY_APPLY_CHECK_ALREADY_APPLIED":
            return result
        presented, historical = _replay_shas(result)
        if presented is not None and historical is not None and presented == historical:
            return result
        return module._result(
            "CURRENT_MEMORY_APPLY_CHECK_REVISE",
            "REPLAY_AUTHORIZATION_IDENTITY_MISMATCH",
            project_id=result.get("project_id"),
            errors=[
                f"durable_authorization_file_sha256={historical}",
                f"presented_authorization_file_sha256={presented}",
            ],
            proposal_id=result.get("proposal_id"),
            proposal_file_sha256=result.get("proposal_file_sha256"),
            presented_authorization_file_sha256=presented,
            durable_authorization_file_sha256=historical,
            authorization_record_valid=True,
            apply_status="ALREADY_APPLIED",
            apply_ready=False,
            effectful_gate_required=False,
            r37_revalidation_required=False,
            durable_apply_event=result.get("durable_apply_event"),
            current_projection_sha256=result.get("current_projection_sha256"),
        )

    guarded_check.__continuityos_r48_replay_guarded__ = True
    module.check_authorized_memory_delta = guarded_check


class _CheckGuardLoader(Loader):
    def __init__(self, wrapped: Loader):
        self.wrapped = wrapped

    def create_module(self, spec):
        create = getattr(self.wrapped, "create_module", None)
        return create(spec) if create is not None else None

    def exec_module(self, module):
        self.wrapped.exec_module(module)
        _patch_check(module)

    def __getattr__(self, name: str):
        return getattr(self.wrapped, name)


class _CheckGuardFinder(MetaPathFinder):
    __continuityos_r48_replay_guard_finder__ = True

    def find_spec(self, fullname, path=None, target=None):
        if fullname != _CHECK_TARGET:
            return None
        spec = PathFinder.find_spec(fullname, path)
        if spec is None or spec.loader is None:
            return spec
        if isinstance(spec.loader, _CheckGuardLoader):
            return spec
        spec.loader = _CheckGuardLoader(spec.loader)
        return spec


def _compose_with_temporal_apply_guard() -> None:
    temporal = sys.modules.get(_TEMPORAL_GUARD_MODULE)
    if temporal is None:
        raise RuntimeError("R46/R47 temporal guard must be loaded before R48")
    original = temporal._patch
    if getattr(original, "__continuityos_r48_replay_composed__", False):
        return

    @wraps(original)
    def combined_patch(module):
        original(module)
        if module.__name__ == _APPLY_TARGET:
            _patch_apply(module)

    combined_patch.__continuityos_r48_replay_composed__ = True
    temporal._patch = combined_patch


def install_operational_memory_replay_guard() -> None:
    """Install R48 without competing with the existing R46/R47 apply finder."""
    _compose_with_temporal_apply_guard()

    if not any(
        getattr(finder, "__continuityos_r48_replay_guard_finder__", False)
        for finder in sys.meta_path
    ):
        sys.meta_path.insert(0, _CheckGuardFinder())

    apply_module = sys.modules.get(_APPLY_TARGET)
    if apply_module is not None:
        _patch_apply(apply_module)
    check_module = sys.modules.get(_CHECK_TARGET)
    if check_module is not None:
        _patch_check(check_module)
