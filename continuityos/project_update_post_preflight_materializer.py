"""Materialize exact post-preflight project-update artifacts without applying them.

This is the unbound filesystem handoff after CURRENT_PROJECT_UPDATE_PREFLIGHT_READY.
It binds the exact R52 packet, completed R37 authorization bytes, and the saved
preflight receipt, then writes a fresh no-clobber directory for a later unbound R37
revalidation/apply. It never writes OperationalMemory or grants execution.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import shutil
from typing import Any, Mapping

from . import operational_memory_apply as apply
from .current_effect_boundary import MODE_LEGACY, inspect_current_session
from .current_project_update_preflight import PREFLIGHT_SCHEMA, _validate_packet
from .operational_memory import strict_json_loads
from .project_memory_bootstrap import MAX_ARTIFACT_BYTES, _safe_parent, _stable_read

RECEIPT_SCHEMA = "continuityos.operational_memory.project_update_post_preflight_materialization/v1"
PROPOSAL_NAME = "OPERATIONAL_MEMORY_DELTA_PROPOSAL.json"
AUTHORIZATION_NAME = "OPERATIONAL_MEMORY_APPLY_AUTHORIZATION.json"
PREFLIGHT_NAME = "CURRENT_PROJECT_UPDATE_PREFLIGHT_READY.json"
RECEIPT_NAME = "MATERIALIZATION_RECEIPT.json"
SUMS_NAME = "SHA256SUMS.txt"


def _sha(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _canonical_bytes(value: Any) -> bytes:
    return apply._canonical_json(value).encode("utf-8")


def _effects(*, wrote: bool = False) -> dict[str, Any]:
    return {
        "operational_memory_write": False,
        "filesystem_write": bool(wrote),
        "network_effect": False,
        "subprocess_execution": False,
        "agent_dispatch": False,
        "external_message": False,
        "deployment": False,
        "current_state_apply": False,
        "canonical_mutation": False,
        "accepted_truth_modified": False,
        "trading": False,
        "wallet_access": False,
        "order_execution": False,
        "can_trade": False,
        "capital_permission": "DENY",
        "deploy_permission": "DENY",
    }


def _receipt(terminal: str, reason: str, *, errors=None, wrote: bool = False, **extra: Any) -> dict[str, Any]:
    return {
        "schema": RECEIPT_SCHEMA,
        "terminal": terminal,
        "reason": reason,
        "errors": list(errors or []),
        "materialized": bool(wrote),
        "apply_status": "NOT_APPLIED",
        "execution_decision": "HOLD",
        "execution_authorized": False,
        "effects": _effects(wrote=wrote),
        **extra,
    }


def _load_object(payload: bytes, label: str) -> Mapping[str, Any]:
    try:
        value = strict_json_loads(payload.decode("utf-8-sig"))
    except Exception as exc:
        raise ValueError(f"{label}: invalid JSON: {exc}") from exc
    if not isinstance(value, Mapping):
        raise ValueError(f"{label}: root must be an object")
    return value


def _validate_preflight(
    preflight: Mapping[str, Any],
    *,
    packet: Mapping[str, Any],
    packet_bytes: bytes,
    proposal: Mapping[str, Any],
    proposal_sha: str,
    authorization: Mapping[str, Any],
    authorization_bytes: bytes,
) -> None:
    if preflight.get("schema") != PREFLIGHT_SCHEMA:
        raise ValueError("preflight schema mismatch")
    if preflight.get("terminal") != "CURRENT_PROJECT_UPDATE_PREFLIGHT_READY":
        raise ValueError("preflight is not READY")
    if preflight.get("apply_ready") is not True or preflight.get("apply_status") != "NOT_APPLIED":
        raise ValueError("preflight apply ceiling mismatch")
    if preflight.get("execution_authorized") is not False:
        raise ValueError("preflight unexpectedly grants execution")
    if preflight.get("accepted_truth_modified") is not False:
        raise ValueError("preflight unexpectedly reports accepted truth mutation")
    if preflight.get("packet_id") != packet.get("packet_id"):
        raise ValueError("preflight packet_id mismatch")
    if preflight.get("proposal_id") != proposal.get("proposal_id"):
        raise ValueError("preflight proposal_id mismatch")
    if preflight.get("proposal_file_sha256") != proposal_sha:
        raise ValueError("preflight proposal SHA mismatch")

    authorization_sha = _sha(authorization_bytes)
    if preflight.get("authorization_file_sha256") != authorization_sha:
        raise ValueError("preflight authorization SHA mismatch")

    preflight_auth = preflight.get("authorization")
    if not isinstance(preflight_auth, Mapping):
        raise ValueError("preflight authorization identity missing")
    expected_identity = {
        "class": authorization.get("authority_class"),
        "id": authorization.get("authority_id"),
        "ref": authorization.get("authority_ref"),
    }
    if dict(preflight_auth) != expected_identity:
        raise ValueError("preflight authorization identity mismatch")

    next_gate = preflight.get("next_gate")
    if not isinstance(next_gate, Mapping):
        raise ValueError("preflight next_gate missing")
    if next_gate.get("step") != "MATERIALIZE_EXACT_PROPOSAL_AND_RUN_R37_UNBOUND":
        raise ValueError("preflight next_gate step mismatch")
    if next_gate.get("proposal_file_sha256") != proposal_sha:
        raise ValueError("preflight next_gate proposal SHA mismatch")
    if next_gate.get("authorization_file_sha256") != authorization_sha:
        raise ValueError("preflight next_gate authorization SHA mismatch")
    if next_gate.get("r37_must_revalidate") is not True:
        raise ValueError("preflight does not require R37 revalidation")
    if next_gate.get("current_session_must_not_run_r37") is not True:
        raise ValueError("preflight current-session R37 boundary missing")
    if preflight.get("effectful_gate_required") is not True:
        raise ValueError("preflight effectful gate requirement missing")
    if preflight.get("r37_revalidation_required") is not True:
        raise ValueError("preflight R37 revalidation requirement missing")

    inputs = preflight.get("inputs")
    if not isinstance(inputs, Mapping):
        raise ValueError("saved CLI preflight inputs missing")
    if inputs.get("packet_file_sha256") != _sha(packet_bytes):
        raise ValueError("preflight packet file SHA mismatch")
    if inputs.get("packet_file_size_bytes") != len(packet_bytes):
        raise ValueError("preflight packet file size mismatch")
    if inputs.get("authorization_file_sha256") != authorization_sha:
        raise ValueError("preflight input authorization SHA mismatch")
    if inputs.get("authorization_file_size_bytes") != len(authorization_bytes):
        raise ValueError("preflight input authorization size mismatch")

    current_session = preflight.get("current_session")
    if not isinstance(current_session, Mapping) or current_session.get("binding_verified") is not True:
        raise ValueError("saved preflight lacks verified current-session binding")


def _write_exclusive(path: Path, payload: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(path, flags, 0o600)
    try:
        with os.fdopen(fd, "wb", closefd=True) as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        raise


def materialize_project_update_after_preflight(
    packet_path: str | Path,
    authorization_path: str | Path,
    preflight_path: str | Path,
    output_dir: str | Path,
) -> dict[str, Any]:
    """Write exact READY-bound proposal + authorization for later unbound R37."""
    state = inspect_current_session()
    if state.get("mode") != MODE_LEGACY:
        return _receipt(
            "PROJECT_UPDATE_POST_PREFLIGHT_MATERIALIZATION_HOLD"
            if state.get("binding_verified")
            else "PROJECT_UPDATE_POST_PREFLIGHT_MATERIALIZATION_REVISE",
            "CURRENT_SESSION_FILESYSTEM_EFFECT_FORBIDDEN",
            errors=[str(state.get("reason") or state.get("mode"))],
            current_session=state,
        )

    packet_file = Path(packet_path).expanduser().absolute()
    authorization_file = Path(authorization_path).expanduser().absolute()
    preflight_file = Path(preflight_path).expanduser().absolute()
    out = Path(output_dir).expanduser().absolute()

    try:
        packet_bytes = _stable_read(packet_file, "R52 review packet", max_bytes=MAX_ARTIFACT_BYTES)
        authorization_bytes = _stable_read(
            authorization_file, "completed R37 authorization", max_bytes=MAX_ARTIFACT_BYTES
        )
        preflight_bytes = _stable_read(
            preflight_file, "CURRENT_PROJECT_UPDATE_PREFLIGHT_READY receipt", max_bytes=MAX_ARTIFACT_BYTES
        )

        packet = _load_object(packet_bytes, "R52 review packet")
        preflight = _load_object(preflight_bytes, "preflight receipt")
        packet_value, proposal, proposal_bytes, proposal_sha = _validate_packet(packet)

        authorization = _load_object(authorization_bytes, "completed R37 authorization")
        validated_auth = apply._validate_authorization(
            authorization,
            proposal=proposal,
            proposal_file_sha256=proposal_sha,
        )

        _validate_preflight(
            preflight,
            packet=packet_value,
            packet_bytes=packet_bytes,
            proposal=proposal,
            proposal_sha=proposal_sha,
            authorization=validated_auth,
            authorization_bytes=authorization_bytes,
        )

        if out.exists() or out.is_symlink():
            raise FileExistsError("output directory already exists")
        canonical_parent = _safe_parent(out)
        if canonical_parent != out.parent:
            raise ValueError("output parent is not canonical")
    except Exception as exc:
        return _receipt(
            "PROJECT_UPDATE_POST_PREFLIGHT_MATERIALIZATION_REVISE",
            "MATERIALIZATION_INPUT_INVALID",
            errors=[f"{type(exc).__name__}: {exc}"],
            packet_path=str(packet_file),
            authorization_path=str(authorization_file),
            preflight_path=str(preflight_file),
            output_dir=str(out),
        )

    created = False
    try:
        out.mkdir(mode=0o700)
        created = True

        proposal_sha = _sha(proposal_bytes)
        authorization_sha = _sha(authorization_bytes)
        preflight_sha = _sha(preflight_bytes)
        packet_sha = _sha(packet_bytes)

        _write_exclusive(out / PROPOSAL_NAME, proposal_bytes)
        _write_exclusive(out / AUTHORIZATION_NAME, authorization_bytes)
        _write_exclusive(out / PREFLIGHT_NAME, preflight_bytes)

        receipt = _receipt(
            "PROJECT_UPDATE_POST_PREFLIGHT_MATERIALIZATION_PASS",
            "EXACT_PREFLIGHT_BOUND_R37_ARTIFACTS_WRITTEN",
            wrote=True,
            packet_id=packet_value["packet_id"],
            project_id=packet_value["project_id"],
            proposal_id=proposal["proposal_id"],
            output_dir=str(out),
            packet_file_sha256=packet_sha,
            proposal_file={
                "name": PROPOSAL_NAME,
                "sha256": proposal_sha,
                "size_bytes": len(proposal_bytes),
            },
            authorization_file={
                "name": AUTHORIZATION_NAME,
                "sha256": authorization_sha,
                "size_bytes": len(authorization_bytes),
            },
            preflight_file={
                "name": PREFLIGHT_NAME,
                "sha256": preflight_sha,
                "size_bytes": len(preflight_bytes),
            },
            next_gate="RUN_R37_UNBOUND_WITH_EXACT_MATERIALIZED_PROPOSAL_AND_AUTHORIZATION",
            r37_revalidation_required=True,
            current_session_must_not_run_r37=True,
        )
        receipt_bytes = _canonical_bytes(receipt)
        _write_exclusive(out / RECEIPT_NAME, receipt_bytes)

        sums = (
            f"{proposal_sha}  {PROPOSAL_NAME}\n"
            f"{authorization_sha}  {AUTHORIZATION_NAME}\n"
            f"{preflight_sha}  {PREFLIGHT_NAME}\n"
            f"{_sha(receipt_bytes)}  {RECEIPT_NAME}\n"
        ).encode("ascii")
        _write_exclusive(out / SUMS_NAME, sums)
        return receipt
    except Exception as exc:
        if created:
            shutil.rmtree(out, ignore_errors=True)
        return _receipt(
            "PROJECT_UPDATE_POST_PREFLIGHT_MATERIALIZATION_REVISE",
            "MATERIALIZATION_ROLLED_BACK",
            errors=[f"{type(exc).__name__}: {exc}"],
            packet_path=str(packet_file),
            authorization_path=str(authorization_file),
            preflight_path=str(preflight_file),
            output_dir=str(out),
        )
