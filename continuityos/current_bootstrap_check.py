"""Read-only point-in-time preflight for R38 project-memory bootstrap.

R41 validates the exact manifest, authorization record, evidence bytes and target
path while a verified current session remains READ_ONLY. It never applies the
bootstrap. R38 remains the separate effectful gate and must revalidate everything
immediately before publication.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from . import project_memory_bootstrap as boot

CHECK_SCHEMA = "continuityos.operational_memory.project_bootstrap_check/v1"


def _effects() -> dict[str, Any]:
    return {
        "operational_memory_write": False,
        "filesystem_write": False,
        "network_effect": False,
        "subprocess_execution": False,
        "agent_dispatch": False,
        "external_message": False,
        "deployment": False,
        "current_state_apply": False,
        "canonical_mutation": False,
        "trading": False,
        "wallet_access": False,
        "order_execution": False,
        "can_trade": False,
        "capital_permission": "DENY",
        "deploy_permission": "DENY",
    }


def _result(
    terminal: str,
    reason: str,
    *,
    project_id: str | None = None,
    target_db: str | None = None,
    errors: list[str] | None = None,
    **extra: Any,
) -> dict[str, Any]:
    return {
        "schema": CHECK_SCHEMA,
        "terminal": terminal,
        "reason": reason,
        "project_id": project_id,
        "target_db": target_db,
        "errors": list(errors or []),
        "point_in_time": True,
        "authorization_identity_authenticated": False,
        "execution_decision": "HOLD",
        "execution_authorized": False,
        "accepted_truth_modified": False,
        "effects": _effects(),
        **extra,
    }


def check_project_memory_bootstrap(
    target_db: str | Path,
    manifest_path: str | Path,
    authorization_path: str | Path,
) -> dict[str, Any]:
    """Validate R38 bootstrap readiness without creating or mutating any file."""
    try:
        target = boot._normalized_target(str(target_db))
        # R40 strengthens this exact R38 boundary with the lazy canonical-parent
        # guard. Calling the module attribute (rather than copying the logic) keeps
        # this check aligned with the effectful gate.
        boot._safe_parent(target)
        manifest_bytes = boot._stable_read(Path(manifest_path), "manifest")
        auth_bytes = boot._stable_read(Path(authorization_path), "authorization")
        manifest_sha = boot._sha_bytes(manifest_bytes)
        auth_sha = boot._sha_bytes(auth_bytes)
        manifest = boot._validate_manifest(boot._load_object(manifest_bytes, "manifest"))
        verified_evidence, _ = boot._verify_evidence(manifest)
        authorization = boot._validate_authorization(
            boot._load_object(auth_bytes, "authorization"),
            manifest=manifest,
            manifest_sha=manifest_sha,
            target=target,
        )
    except Exception as exc:
        return _result(
            "CURRENT_BOOTSTRAP_CHECK_REVISE",
            "BOOTSTRAP_ARTIFACT_INVALID",
            target_db=str(target_db),
            errors=[f"{type(exc).__name__}: {exc}"],
            bootstrap_status="NOT_APPLIED",
            bootstrap_ready=False,
            authorization_record_valid=False,
            effectful_gate_required=True,
            r38_revalidation_required=True,
        )

    project_id = manifest["project_id"]
    common = {
        "manifest_file_sha256": manifest_sha,
        "authorization_file_sha256": auth_sha,
        "evidence": verified_evidence,
        "authorization_record_valid": True,
        "authorization": {
            "class": authorization["authority_class"],
            "id": authorization["authority_id"],
            "ref": authorization["authority_ref"],
        },
    }

    if target.exists() or target.is_symlink():
        try:
            if target.is_symlink() or boot._is_reparse(target) or not target.is_file():
                raise ValueError("existing target is unsafe")
            with boot.OperationalMemory(str(target), read_only=True) as memory:
                verification = memory.verify()
                if verification.get("ok") is not True:
                    raise ValueError("existing target is not a valid OperationalMemory database")
                prior = boot._bootstrap_event(
                    memory,
                    project_id=project_id,
                    manifest_sha=manifest_sha,
                    auth_sha=auth_sha,
                )
                if prior is None:
                    raise ValueError("target already exists but does not match this bootstrap")
                projection = memory.projection()
            return _result(
                "CURRENT_BOOTSTRAP_CHECK_ALREADY_CREATED",
                "EXACT_BOOTSTRAP_ALREADY_PUBLISHED",
                project_id=project_id,
                target_db=str(target),
                bootstrap_status="ALREADY_CREATED",
                bootstrap_ready=False,
                effectful_gate_required=False,
                r38_revalidation_required=False,
                bootstrap_event=prior,
                projection={
                    "projection_sha256": projection.get("projection_sha256"),
                    "event_cursor": projection.get("event_cursor"),
                    "event_chain_head": projection.get("event_chain_head"),
                },
                **common,
            )
        except Exception as exc:
            return _result(
                "CURRENT_BOOTSTRAP_CHECK_REVISE",
                "TARGET_ALREADY_EXISTS",
                project_id=project_id,
                target_db=str(target),
                errors=[f"{type(exc).__name__}: {exc}"],
                bootstrap_status="NOT_APPLIED",
                bootstrap_ready=False,
                effectful_gate_required=True,
                r38_revalidation_required=True,
                **common,
            )

    return _result(
        "CURRENT_BOOTSTRAP_CHECK_READY",
        "ARTIFACTS_VALIDATED_TARGET_AVAILABLE",
        project_id=project_id,
        target_db=str(target),
        bootstrap_status="NOT_APPLIED",
        bootstrap_ready=True,
        effectful_gate_required=True,
        r38_revalidation_required=True,
        **common,
    )
