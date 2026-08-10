"""Bind R37/R44/R45 shadow-memory apply to the exact DB target in proposal bytes.

R36 DB-backed proposals already carry ``operational_memory`` metadata. The proposal
file SHA is then bound by the separate R37 authorization, but historical R37/R44
never compared the actual ``db_path`` with that already-authorized target. Two
byte-identical DB clones could therefore accept the same proposal+authorization.

R51 preserves historical R37/R44/R45/R43 implementation bytes and composes a lazy
stdlib-only guard. Effectful R37 rejects a wrong or unbound target before writable
open. R44 and R45 enforce the same binding in read-only review paths. R43 claim-sync
plans copy their already-verified DB metadata into the nested R36 proposal so its
proposal-file SHA binds the target without changing the R37 authorization schema.
"""
from __future__ import annotations

from functools import wraps
from importlib.abc import Loader, MetaPathFinder
from importlib.machinery import PathFinder
from pathlib import Path
import stat
import sys
from types import ModuleType
from typing import Any, Mapping

_APPLY_TARGET = "continuityos.operational_memory_apply"
_CHECK_TARGET = "continuityos.current_memory_apply_check"
_AUTH_REQUEST_TARGET = "continuityos.current_memory_apply_auth_request"
_CLAIM_SYNC_TARGET = "continuityos.current_claim_sync"
_TEMPORAL_GUARD_MODULE = "continuityos.operational_memory_temporal_guard"
_REPLAY_GUARD_MODULE = "continuityos.operational_memory_replay_guard"


class OperationalMemoryTargetBindingError(ValueError):
    def __init__(self, reason: str, detail: str):
        self.reason = reason
        self.detail = detail
        super().__init__(detail)


def _is_reparse(path: Path) -> bool:
    try:
        attrs = getattr(path.lstat(), "st_file_attributes", 0)
    except OSError:
        return False
    return bool(attrs & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))


def _canonical_existing_db(value: Any, *, label: str) -> Path:
    if not isinstance(value, (str, Path)) or not str(value).strip():
        raise OperationalMemoryTargetBindingError(
            "OPERATIONAL_MEMORY_TARGET_BINDING_INVALID",
            f"{label}: missing path",
        )
    path = Path(value).expanduser().absolute()
    if not path.is_file() or path.is_symlink() or _is_reparse(path):
        raise OperationalMemoryTargetBindingError(
            "OPERATIONAL_MEMORY_TARGET_BINDING_INVALID",
            f"{label}: missing or unsafe regular file",
        )
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise OperationalMemoryTargetBindingError(
            "OPERATIONAL_MEMORY_TARGET_BINDING_INVALID",
            f"{label}: cannot resolve: {exc}",
        ) from exc
    # Do not authorize a lexical alias whose physical target differs because of a
    # symlink, junction/reparse ancestor or unresolved ``..`` component.
    if resolved != path:
        raise OperationalMemoryTargetBindingError(
            "OPERATIONAL_MEMORY_TARGET_BINDING_INVALID",
            f"{label}: path traverses symlink/reparse/alias ancestor",
        )
    return resolved


def _validate_bound_target(proposal: Mapping[str, Any], db_path: Any) -> dict[str, Any]:
    metadata = proposal.get("operational_memory")
    if not isinstance(metadata, Mapping):
        raise OperationalMemoryTargetBindingError(
            "OPERATIONAL_MEMORY_TARGET_UNBOUND",
            "proposal.operational_memory is missing",
        )
    if metadata.get("verified") is not True:
        raise OperationalMemoryTargetBindingError(
            "OPERATIONAL_MEMORY_TARGET_BINDING_INVALID",
            "proposal.operational_memory.verified must be true",
        )
    base = proposal.get("base")
    if not isinstance(base, Mapping):
        raise OperationalMemoryTargetBindingError(
            "OPERATIONAL_MEMORY_TARGET_BINDING_INVALID",
            "proposal base is missing",
        )
    expected = {
        "projection_sha256": base.get("projection_sha256"),
        "event_cursor": base.get("event_cursor"),
        "event_chain_head": base.get("event_chain_head"),
    }
    actual_metadata = {key: metadata.get(key) for key in expected}
    if actual_metadata != expected:
        raise OperationalMemoryTargetBindingError(
            "OPERATIONAL_MEMORY_TARGET_BINDING_INVALID",
            f"proposal target/base metadata mismatch expected={expected} actual={actual_metadata}",
        )

    bound = _canonical_existing_db(metadata.get("path"), label="proposal.operational_memory.path")
    actual = _canonical_existing_db(db_path, label="db_path")
    if actual != bound:
        raise OperationalMemoryTargetBindingError(
            "OPERATIONAL_MEMORY_TARGET_MISMATCH",
            f"proposal target={bound} actual target={actual}",
        )
    return {"path": str(bound), **expected}


def _proposal_from_file(apply_module: ModuleType, proposal_path: Any) -> Mapping[str, Any]:
    payload = apply_module._stable_read(Path(proposal_path), "proposal")
    return apply_module._validate_proposal(apply_module._load_object(payload, "proposal"))


def _patch_apply(module: ModuleType) -> None:
    original = module.apply_authorized_memory_delta
    if getattr(original, "__continuityos_r51_target_bound__", False):
        return

    @wraps(original)
    def guarded_apply(db_path, proposal_path, authorization_path):
        # Preserve the established R24/R37 current-session HOLD before any extra
        # artifact or target reads in this effectful path.
        state = module.inspect_current_session()
        if state.get("mode") != module.MODE_LEGACY:
            return original(db_path, proposal_path, authorization_path)
        proposal = None
        try:
            proposal = _proposal_from_file(module, proposal_path)
            target = _validate_bound_target(proposal, db_path)
        except OperationalMemoryTargetBindingError as exc:
            return module._result(
                "CURRENT_MEMORY_APPLY_REVISE",
                exc.reason,
                project_id=proposal.get("project_id") if isinstance(proposal, Mapping) else None,
                proposal_id=proposal.get("proposal_id") if isinstance(proposal, Mapping) else None,
                errors=[exc.detail],
                target_binding_required=True,
            )
        except Exception:
            # Preserve historical artifact-validation receipt semantics for malformed
            # proposals; the original R37 gate will classify the exact error.
            return original(db_path, proposal_path, authorization_path)

        result = original(db_path, proposal_path, authorization_path)
        if isinstance(result, dict):
            result.setdefault("operational_memory_target", target)
        return result

    guarded_apply.__continuityos_r51_target_bound__ = True
    module.apply_authorized_memory_delta = guarded_apply


def _patch_check(module: ModuleType) -> None:
    original = module.check_authorized_memory_delta
    if getattr(original, "__continuityos_r51_target_bound__", False):
        return

    @wraps(original)
    def guarded_check(db_path, proposal_path, authorization_path):
        result = original(db_path, proposal_path, authorization_path)
        if not isinstance(result, dict) or result.get("terminal") not in {
            "CURRENT_MEMORY_APPLY_CHECK_READY",
            "CURRENT_MEMORY_APPLY_CHECK_ALREADY_APPLIED",
        }:
            return result
        try:
            proposal = _proposal_from_file(module.apply, proposal_path)
            target = _validate_bound_target(proposal, db_path)
        except OperationalMemoryTargetBindingError as exc:
            return module._result(
                "CURRENT_MEMORY_APPLY_CHECK_REVISE",
                exc.reason,
                project_id=result.get("project_id"),
                errors=[exc.detail],
                proposal_id=result.get("proposal_id"),
                proposal_file_sha256=result.get("proposal_file_sha256"),
                authorization_file_sha256=result.get("authorization_file_sha256"),
                target_binding_required=True,
                r37_revalidation_required=True,
            )
        result.setdefault("operational_memory_target", target)
        return result

    guarded_check.__continuityos_r51_target_bound__ = True
    module.check_authorized_memory_delta = guarded_check


def _patch_auth_request(module: ModuleType) -> None:
    original = module.build_apply_authorization_request
    if getattr(original, "__continuityos_r51_target_bound__", False):
        return

    @wraps(original)
    def guarded_request(db_path, proposal_path):
        result = original(db_path, proposal_path)
        if not isinstance(result, dict) or result.get("terminal") not in {
            "CURRENT_MEMORY_APPLY_AUTH_REQUEST_PASS",
            "CURRENT_MEMORY_APPLY_AUTH_REQUEST_ALREADY_APPLIED",
        }:
            return result
        try:
            proposal = _proposal_from_file(module.apply, proposal_path)
            target = _validate_bound_target(proposal, db_path)
        except OperationalMemoryTargetBindingError as exc:
            return module._result(
                "CURRENT_MEMORY_APPLY_AUTH_REQUEST_REVISE",
                exc.reason,
                project_id=result.get("project_id"),
                errors=[exc.detail],
                proposal_id=result.get("proposal_id"),
                proposal_file_sha256=result.get("proposal_file_sha256"),
                target_binding_required=True,
            )
        result.setdefault("operational_memory_target", target)
        return result

    guarded_request.__continuityos_r51_target_bound__ = True
    module.build_apply_authorization_request = guarded_request


def _patch_claim_sync(module: ModuleType) -> None:
    original = module.build_claim_sync_plan_from_db
    if getattr(original, "__continuityos_r51_target_bound__", False):
        return

    @wraps(original)
    def guarded_claim_sync(db_path, raw_request):
        result = original(db_path, raw_request)
        if not isinstance(result, dict) or result.get("terminal") != "CURRENT_CLAIM_SYNC_PLAN_PASS":
            return result
        metadata = result.get("operational_memory")
        proposal = result.get("delta_proposal")
        if not isinstance(metadata, Mapping) or not isinstance(proposal, dict):
            return module._revise(
                "OPERATIONAL_MEMORY_TARGET_BINDING_INVALID",
                ["claim-sync plan lacks operational-memory target metadata"],
                project_id=result.get("project_id"),
            )
        # The authorization already binds the exact future proposal-file SHA. By
        # placing the verified target metadata inside that proposal before it is
        # materialized, no R37 authorization schema change is required.
        proposal["operational_memory"] = dict(metadata)
        body = {
            key: value
            for key, value in result.items()
            if key not in {"plan_id", "operational_memory", "target_binding"}
        }
        result["plan_id"] = "csp-" + module._sha(body)[:40]
        result["target_binding"] = "PROPOSAL_FILE_SHA_BINDS_OPERATIONAL_MEMORY_PATH"
        return result

    guarded_claim_sync.__continuityos_r51_target_bound__ = True
    module.build_claim_sync_plan_from_db = guarded_claim_sync


def _patch(module: ModuleType) -> None:
    if module.__name__ == _APPLY_TARGET:
        _patch_apply(module)
    elif module.__name__ == _CHECK_TARGET:
        _patch_check(module)
    elif module.__name__ == _AUTH_REQUEST_TARGET:
        _patch_auth_request(module)
    elif module.__name__ == _CLAIM_SYNC_TARGET:
        _patch_claim_sync(module)


class _TargetBindingLoader(Loader):
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


class _TargetBindingFinder(MetaPathFinder):
    __continuityos_r51_target_binding_finder__ = True

    def find_spec(self, fullname, path=None, target=None):
        # R37 and R44 already have composed R46/R48 loaders; do not compete with
        # them. This finder owns only R45 and R43.
        if fullname not in {_AUTH_REQUEST_TARGET, _CLAIM_SYNC_TARGET}:
            return None
        spec = PathFinder.find_spec(fullname, path)
        if spec is None or spec.loader is None:
            return spec
        if isinstance(spec.loader, _TargetBindingLoader):
            return spec
        spec.loader = _TargetBindingLoader(spec.loader)
        return spec


def _compose_with_apply_guard() -> None:
    temporal = sys.modules.get(_TEMPORAL_GUARD_MODULE)
    if temporal is None:
        raise RuntimeError("R46/R50 temporal guard must be loaded before R51")
    original = temporal._patch
    if getattr(original, "__continuityos_r51_target_composed__", False):
        return

    @wraps(original)
    def combined_patch(module):
        original(module)
        if module.__name__ == _APPLY_TARGET:
            _patch_apply(module)

    combined_patch.__continuityos_r51_target_composed__ = True
    temporal._patch = combined_patch


def _compose_with_check_guard() -> None:
    replay = sys.modules.get(_REPLAY_GUARD_MODULE)
    if replay is None:
        raise RuntimeError("R48 replay guard must be loaded before R51")
    original = replay._patch_check
    if getattr(original, "__continuityos_r51_target_composed__", False):
        return

    @wraps(original)
    def combined_patch(module):
        original(module)
        _patch_check(module)

    combined_patch.__continuityos_r51_target_composed__ = True
    replay._patch_check = combined_patch


def install_operational_memory_target_binding_guard() -> None:
    """Install target binding without competing with R46/R48 import loaders."""
    _compose_with_apply_guard()
    _compose_with_check_guard()

    if not any(
        getattr(finder, "__continuityos_r51_target_binding_finder__", False)
        for finder in sys.meta_path
    ):
        sys.meta_path.insert(0, _TargetBindingFinder())

    for name in (_APPLY_TARGET, _CHECK_TARGET, _AUTH_REQUEST_TARGET, _CLAIM_SYNC_TARGET):
        module = sys.modules.get(name)
        if module is not None:
            _patch(module)
