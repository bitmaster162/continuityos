"""Final immutable snapshot recheck for R52 project-update review packets.

R52 already rechecks the project-specific current-work capsule after R43 planning,
but an unrelated OperationalMemory event can move the global projection/cursor/
chain head without changing that project capsule. Such a packet is safe at R44 but
already stale when emitted. R53 adds one final read-only projection check so PASS
means all R36 base identities still match one coherent final snapshot.
"""
from __future__ import annotations

from functools import wraps
import hashlib
from importlib.abc import Loader, MetaPathFinder
from importlib.machinery import PathFinder
import sys
from types import ModuleType
from typing import Any, Mapping

from .current_work import compile_project_work
from .operational_memory import OperationalMemory

_TARGET = "continuityos.current_project_update_review"


class ProjectUpdateSnapshotDrift(ValueError):
    def __init__(self, expected: Mapping[str, Any], actual: Mapping[str, Any]):
        self.expected = dict(expected)
        self.actual = dict(actual)
        super().__init__(f"project-update snapshot moved expected={self.expected} actual={self.actual}")


def _expected_snapshot(packet: Mapping[str, Any]) -> dict[str, Any]:
    plan = packet.get("claim_sync_plan")
    proposal = plan.get("delta_proposal") if isinstance(plan, Mapping) else None
    base = proposal.get("base") if isinstance(proposal, Mapping) else None
    if not isinstance(base, Mapping):
        raise ValueError("project-update packet lacks nested proposal base")
    return {
        "projection_sha256": base.get("projection_sha256"),
        "event_cursor": base.get("event_cursor"),
        "event_chain_head": base.get("event_chain_head"),
        "current_work_capsule_sha256": base.get("current_work_capsule_sha256"),
    }


def _actual_snapshot(db_path: Any, project_id: str) -> dict[str, Any]:
    with OperationalMemory(str(db_path), read_only=True) as memory:
        verification = memory.verify()
        if verification.get("ok") is not True:
            raise ValueError(
                "operational memory verification failed during final packet snapshot recheck: "
                + "; ".join(verification.get("errors") or [])
            )
        projection = memory.projection()
    work = compile_project_work(projection, project_id)
    if work.get("terminal") == "CURRENT_WORK_REVISE":
        raise ValueError("current-work is REVISE during final packet snapshot recheck")
    return {
        "projection_sha256": projection.get("projection_sha256"),
        "event_cursor": projection.get("event_cursor"),
        "event_chain_head": projection.get("event_chain_head"),
        "current_work_capsule_sha256": work.get("capsule_sha256"),
    }


def _recheck_packet_snapshot(packet: Mapping[str, Any], db_path: Any) -> tuple[dict[str, Any], dict[str, Any]]:
    project_id = str(packet.get("project_id") or "")
    if not project_id:
        raise ValueError("project-update packet project_id missing")
    expected = _expected_snapshot(packet)
    actual = _actual_snapshot(db_path, project_id)
    if actual != expected:
        raise ProjectUpdateSnapshotDrift(expected, actual)
    return expected, actual


def _patch(module: ModuleType) -> None:
    original = module.build_project_update_review_packet
    if getattr(original, "__continuityos_r53_snapshot_rechecked__", False):
        return

    @wraps(original)
    def guarded_review(db_path, claim_sync_request):
        result = original(db_path, claim_sync_request)
        if not isinstance(result, dict) or result.get("terminal") != "CURRENT_PROJECT_UPDATE_REVIEW_PASS":
            return result
        try:
            expected, actual = _recheck_packet_snapshot(result, db_path)
        except ProjectUpdateSnapshotDrift as exc:
            return module._revise(
                "REVIEW_PACKET_SNAPSHOT_STALE",
                [str(exc)],
                project_id=result.get("project_id"),
                claim_sync_plan=result.get("claim_sync_plan"),
            )
        except Exception as exc:
            return module._revise(
                "REVIEW_PACKET_SNAPSHOT_RECHECK_FAILED",
                [f"{type(exc).__name__}: {exc}"],
                project_id=result.get("project_id"),
                claim_sync_plan=result.get("claim_sync_plan"),
            )

        # Recompute packet identity because R53 adds explicit final-snapshot evidence
        # to the packet body. Proposal bytes and authorization skeleton are unchanged.
        result["snapshot_recheck"] = {
            "status": "PASS",
            "one_final_projection": True,
            "expected": expected,
            "actual": actual,
        }
        body = {key: value for key, value in result.items() if key != "packet_id"}
        result["packet_id"] = "purp-" + hashlib.sha256(
            module.apply._canonical_json(body).encode("utf-8")
        ).hexdigest()[:40]
        return result

    guarded_review.__continuityos_r53_snapshot_rechecked__ = True
    module.build_project_update_review_packet = guarded_review


class _SnapshotGuardLoader(Loader):
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


class _SnapshotGuardFinder(MetaPathFinder):
    __continuityos_r53_project_update_snapshot_finder__ = True

    def find_spec(self, fullname, path=None, target=None):
        if fullname != _TARGET:
            return None
        spec = PathFinder.find_spec(fullname, path)
        if spec is None or spec.loader is None:
            return spec
        if isinstance(spec.loader, _SnapshotGuardLoader):
            return spec
        spec.loader = _SnapshotGuardLoader(spec.loader)
        return spec


def install_project_update_snapshot_guard() -> None:
    if not any(
        getattr(finder, "__continuityos_r53_project_update_snapshot_finder__", False)
        for finder in sys.meta_path
    ):
        sys.meta_path.insert(0, _SnapshotGuardFinder())
    module = sys.modules.get(_TARGET)
    if module is not None:
        _patch(module)
