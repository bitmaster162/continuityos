"""Anti-Amnesia semantic close v1.2 for verified read-only sessions.

Version 1.1 proves that a return is bound to the current R63 boot receipt,
controller work order, role permission policy, optional Git proof and a
structured proposed delta.  Version 1.2 adds an independently replayed session
input chain:

* canonical ``ANTI_AMNESIA_SESSION_INPUT_MANIFEST_V1``;
* controller-pinned ``SESSION_CONTEXT_CHALLENGE``;
* exact ``SESSION_CONTEXT_ACK``;
* exact successful ``SESSION_CONTEXT_VERDICT`` reconstructed by the controller.

The current operational-context contract has a hard ``READ_ONLY`` ceiling.
Therefore v1.2 deliberately accepts only read-only task returns: no proposed
state delta, no Git mutation and no requested external/live effects.  A future
reversible-write session contract must be introduced explicitly rather than
silently widening this ceiling.

No function applies state, modifies R63, writes the operational database,
changes Git, deploys, trades or grants capital permission.
"""
from __future__ import annotations

import os
from pathlib import Path
import tempfile
from typing import Any, Dict, Iterable, Mapping, Optional, Tuple

from . import anti_amnesia as v1
from . import semantic_close as v11
from . import session_context
from ..session_input import SessionInputError, validate_session_input_manifest

RETURN_ENVELOPE_V12_NAME = "ANTI_AMNESIA_RETURN_V1_2.json"
SCHEMA_RETURN = "ANTI_AMNESIA_RETURN_V1_2"
SCHEMA_CLOSE = "ANTI_AMNESIA_CLOSE_RECEIPT_V1_2"
MODE = v1.MODE
GATE = v1.GATE

_BINDING_KEYS = {
    "session_input_manifest_file_sha256",
    "session_input_manifest_sha256",
    "session_context_binding_id",
    "session_context_challenge_sha256",
    "session_context_ack_sha256",
    "session_context_verdict_sha256",
    "session_context_verdict_status",
}

_VERDICT_KEYS = {
    "schema",
    "binding_id",
    "challenge_sha256",
    "ack_sha256",
    "checks",
    "mismatches",
    "outcome",
    "status",
    "release_blocked",
    "live_state_modified",
    "writes_performed",
    "can_trade",
    "capital_permission",
}

_READ_ONLY_TASK_CLASSES = {"RESEARCH", "AUDIT", "TRANSPORT", "CONTENT", "OTHER"}


class SemanticCloseV12Error(v11.SemanticCloseError):
    """A semantic close v1.2 contract or proof is invalid."""


def _exact_keys(value: Any, expected: Iterable[str], label: str) -> Mapping[str, Any]:
    try:
        return v1._require_exact_keys(value, expected, label)
    except v1.AntiAmnesiaError as exc:
        raise SemanticCloseV12Error(str(exc)) from exc


def _sha(value: Any, label: str) -> str:
    try:
        return v1._require_sha(value, label)
    except v1.AntiAmnesiaError as exc:
        raise SemanticCloseV12Error(str(exc)) from exc


def _load_canonical_json(
    path: Path,
    label: str,
    *,
    expected_sha256: Optional[str] = None,
) -> Tuple[bytes, str, Mapping[str, Any]]:
    payload = v1.stable_read_bytes(Path(path), label=label)
    actual_sha = v1.sha256_bytes(payload)
    if expected_sha256 is not None:
        _sha(expected_sha256, f"{label}.expected_sha256")
        if actual_sha != expected_sha256:
            raise SemanticCloseV12Error(f"{label}:PINNED_SHA256_MISMATCH")
    parsed = v1.strict_json_loads(payload, label)
    if payload != v1.canonical_json_bytes(parsed):
        raise SemanticCloseV12Error(f"{label}:NON_CANONICAL_JSON")
    if not isinstance(parsed, dict):
        raise SemanticCloseV12Error(f"{label}:NOT_OBJECT")
    return payload, actual_sha, parsed


def validate_return_envelope_v12(envelope: Any) -> Mapping[str, Any]:
    root = _exact_keys(
        envelope,
        {
            "schema",
            "gate",
            "mode",
            "semantic_return_v1_1",
            "session_context_binding",
        },
        "return_v1_2",
    )
    if root["schema"] != SCHEMA_RETURN or root["gate"] != GATE or root["mode"] != MODE:
        raise SemanticCloseV12Error("return_v1_2:IDENTITY_MISMATCH")
    v11.validate_return_envelope_v11(root["semantic_return_v1_1"])
    binding = _exact_keys(
        root["session_context_binding"],
        _BINDING_KEYS,
        "return_v1_2.session_context_binding",
    )
    for field in _BINDING_KEYS - {"session_context_verdict_status"}:
        _sha(binding[field], f"return_v1_2.session_context_binding.{field}")
    if binding["session_context_verdict_status"] != "SESSION_CONTEXT_PASS":
        raise SemanticCloseV12Error(
            "return_v1_2.session_context_binding:VERDICT_MUST_BE_PASS"
        )
    _validate_read_only_return(root["semantic_return_v1_1"])
    return root


def _validate_read_only_return(envelope_v11: Mapping[str, Any]) -> None:
    task_class = envelope_v11["work_order_binding"]["task_class"]
    if task_class not in _READ_ONLY_TASK_CLASSES:
        raise SemanticCloseV12Error("return_v1_2:READ_ONLY_TASK_CLASS_REQUIRED")
    if envelope_v11["proposed_delta"] != []:
        raise SemanticCloseV12Error("return_v1_2:READ_ONLY_DELTA_MUST_BE_EMPTY")
    if envelope_v11["git"]["required"] is not False:
        raise SemanticCloseV12Error("return_v1_2:READ_ONLY_GIT_MUTATION_FORBIDDEN")
    effects = envelope_v11["effects"]
    if effects.get("effect_class") != "REVERSIBLE":
        raise SemanticCloseV12Error("return_v1_2:READ_ONLY_EFFECT_CLASS_MUST_BE_REVERSIBLE")
    requested = effects.get("requested")
    if not isinstance(requested, dict):
        raise SemanticCloseV12Error("return_v1_2:READ_ONLY_EFFECT_REQUEST_INVALID")
    for key, value in requested.items():
        if key == "capital_permission":
            if value != "DENY":
                raise SemanticCloseV12Error(
                    "return_v1_2:READ_ONLY_CAPITAL_PERMISSION_MUST_BE_DENY"
                )
        elif value is not False:
            raise SemanticCloseV12Error(
                f"return_v1_2:READ_ONLY_EFFECT_REQUESTED:{key}"
            )


def _validate_verdict(value: Any) -> Mapping[str, Any]:
    row = _exact_keys(value, _VERDICT_KEYS, "session_context_verdict")
    if row["schema"] != session_context.SCHEMA_VERDICT:
        raise SemanticCloseV12Error("session_context_verdict:SCHEMA_MISMATCH")
    for field in ("binding_id", "challenge_sha256", "ack_sha256"):
        _sha(row[field], f"session_context_verdict.{field}")
    if not isinstance(row["checks"], list) or not all(
        isinstance(item, dict) for item in row["checks"]
    ):
        raise SemanticCloseV12Error("session_context_verdict.checks:INVALID")
    if not isinstance(row["mismatches"], list):
        raise SemanticCloseV12Error("session_context_verdict.mismatches:INVALID")
    if (
        row["outcome"] != "PASS"
        or row["status"] != "SESSION_CONTEXT_PASS"
        or row["release_blocked"] is not False
        or row["mismatches"] != []
        or row["live_state_modified"] is not False
        or row["writes_performed"] != []
        or row["can_trade"] is not False
        or row["capital_permission"] != "DENY"
    ):
        raise SemanticCloseV12Error("session_context_verdict:NOT_EXACT_PASS")
    if not row["checks"] or any(
        set(item) != {"check_id", "status", "code"}
        or not isinstance(item["check_id"], str)
        or not item["check_id"]
        or item["status"] != "PASS"
        or item["code"] != "EXACT_MATCH"
        for item in row["checks"]
    ):
        raise SemanticCloseV12Error("session_context_verdict:CHECKS_NOT_EXACT_PASS")
    return row


def _materialize_v11_view(
    files: Mapping[str, bytes],
    envelope_v11: Mapping[str, Any],
    target: Path,
) -> None:
    target.mkdir(parents=True, exist_ok=False)
    for name, payload in files.items():
        if name == RETURN_ENVELOPE_V12_NAME:
            continue
        destination = target.joinpath(*name.split("/"))
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(payload)
    (target / v11.RETURN_ENVELOPE_V11_NAME).write_bytes(
        v1.canonical_json_bytes(envelope_v11)
    )


def _session_context_verification(
    *,
    envelope_v12: Mapping[str, Any],
    nested_receipt: Mapping[str, Any],
    manifest_path: Path,
    expected_manifest_sha256: str,
    challenge_path: Path,
    expected_challenge_sha256: str,
    ack_path: Path,
    verdict_path: Path,
    expected_verdict_sha256: str,
) -> Dict[str, Any]:
    _manifest_payload, manifest_file_sha, manifest_parsed = _load_canonical_json(
        Path(manifest_path),
        "semantic_v1_2.session_input_manifest",
        expected_sha256=expected_manifest_sha256,
    )
    try:
        manifest = validate_session_input_manifest(manifest_parsed)
    except SessionInputError as exc:
        raise SemanticCloseV12Error(str(exc)) from exc

    _challenge_payload, challenge_sha, challenge_parsed = _load_canonical_json(
        Path(challenge_path),
        "semantic_v1_2.session_context_challenge",
        expected_sha256=expected_challenge_sha256,
    )
    if challenge_parsed.get("schema") != session_context.SCHEMA_CHALLENGE:
        raise SemanticCloseV12Error("session_context_challenge:SCHEMA_MISMATCH")
    challenge_manifest = _exact_keys(
        challenge_parsed.get("candidate_session_input_manifest"),
        {"path", "sha256", "manifest_sha256"},
        "session_context_challenge.candidate_session_input_manifest",
    )
    if (
        challenge_manifest["sha256"] != manifest_file_sha
        or challenge_manifest["manifest_sha256"] != manifest["manifest_sha256"]
    ):
        raise SemanticCloseV12Error(
            "session_context_challenge:EXTERNAL_MANIFEST_MISMATCH"
        )

    _ack_payload, ack_sha, _ack_parsed = _load_canonical_json(
        Path(ack_path), "semantic_v1_2.session_context_ack"
    )
    verdict_payload, verdict_sha, verdict_parsed = _load_canonical_json(
        Path(verdict_path),
        "semantic_v1_2.session_context_verdict",
        expected_sha256=expected_verdict_sha256,
    )
    provided_verdict = _validate_verdict(verdict_parsed)
    recomputed = session_context.verify_session_context_ack(
        Path(challenge_path),
        Path(ack_path),
        expected_challenge_sha256=challenge_sha,
    )
    _validate_verdict(recomputed)
    if recomputed["challenge_sha256"] != challenge_sha:
        raise SemanticCloseV12Error("session_context_verdict:CHALLENGE_SHA_MISMATCH")
    if recomputed["ack_sha256"] != ack_sha:
        raise SemanticCloseV12Error("session_context_verdict:ACK_SHA_MISMATCH")
    if recomputed != provided_verdict:
        raise SemanticCloseV12Error("session_context_verdict:REPLAY_MISMATCH")
    if verdict_payload != v1.canonical_json_bytes(recomputed):
        raise SemanticCloseV12Error("session_context_verdict:BYTE_REPLAY_MISMATCH")

    declared = envelope_v12["session_context_binding"]
    observed = {
        "session_input_manifest_file_sha256": manifest_file_sha,
        "session_input_manifest_sha256": manifest["manifest_sha256"],
        "session_context_binding_id": recomputed["binding_id"],
        "session_context_challenge_sha256": challenge_sha,
        "session_context_ack_sha256": ack_sha,
        "session_context_verdict_sha256": verdict_sha,
        "session_context_verdict_status": recomputed["status"],
    }
    mismatches = sorted(key for key in observed if declared.get(key) != observed[key])
    if mismatches:
        raise SemanticCloseV12Error(
            "session_context_binding:DECLARED_MISMATCH:" + ",".join(mismatches)
        )

    nested_envelope = envelope_v12["semantic_return_v1_1"]
    boot = nested_envelope["boot_binding"]
    work = nested_envelope["work_order_binding"]
    session = manifest["session_binding"]
    relation_expected = {
        "authority_generation": "R63",
        "current_pointer_sha256": boot["r63_pointer_sha256"],
        "workspace_context_digest": boot["context_digest"],
        "role": boot["role"],
        "active_case": boot["case_id"],
        "case_binding": boot["case_binding"],
        "work_order_id": work["id"],
    }
    relation_observed = {
        "authority_generation": manifest["authority_generation"],
        "current_pointer_sha256": session["current_pointer_sha256"],
        "workspace_context_digest": session["workspace_context_digest"],
        "role": session["role"],
        "active_case": session["active_case"],
        "case_binding": session["case_binding"],
        "work_order_id": session["work_order_id"],
    }
    relation_mismatches = sorted(
        key for key in relation_expected if relation_expected[key] != relation_observed[key]
    )
    if relation_mismatches:
        raise SemanticCloseV12Error(
            "session_context_binding:RETURN_RELATION_MISMATCH:"
            + ",".join(relation_mismatches)
        )

    nested_binding = nested_receipt["semantic_binding"]
    receipt_relation_expected = {
        "work_order_id": session["work_order_id"],
        "role": session["role"],
        "case_id": session["active_case"],
    }
    receipt_relation_observed = {
        "work_order_id": nested_binding["work_order_id"],
        "role": nested_binding["role"],
        "case_id": nested_binding["case_id"],
    }
    receipt_mismatches = sorted(
        key
        for key in receipt_relation_expected
        if receipt_relation_expected[key] != receipt_relation_observed[key]
    )
    if receipt_mismatches:
        raise SemanticCloseV12Error(
            "session_context_binding:V1_1_RECEIPT_RELATION_MISMATCH:"
            + ",".join(receipt_mismatches)
        )

    if manifest["ceilings"] != {
        "effect_ceiling": "READ_ONLY",
        "accepted_truth_owner": "CONTROL_CENTER",
        "context_is_projection_only": True,
        "content_acceptance": "NOT_PERFORMED",
        "state_apply": "DISABLED",
        "may_dispatch_codex": False,
        "can_trade": False,
        "capital_permission": "DENY",
        "deploy_permission": "DENY",
        "self_application": False,
    }:
        raise SemanticCloseV12Error("session_context_binding:CEILING_MISMATCH")

    return {
        "verified": True,
        **observed,
        "challenge_id": session["challenge_id"],
        "role": session["role"],
        "active_case": session["active_case"],
        "work_order_id": session["work_order_id"],
        "baseline_head": session["git_head"],
        "baseline_tree": session["git_tree"],
        "checkpoint_id": manifest["memory_binding"]["checkpoint_id"],
        "checkpoint_hash": manifest["memory_binding"]["checkpoint_hash"],
        "event_cursor": manifest["memory_binding"]["event_cursor"],
        "projection_sha256": manifest["memory_binding"]["projection_sha256"],
        "effect_ceiling": "READ_ONLY",
    }


def build_semantic_close_v12_receipt(
    return_path: Any,
    dry_run: Any,
    *,
    work_order_path: Path,
    permission_policy_path: Path,
    session_input_manifest_path: Path,
    expected_session_input_manifest_sha256: str,
    session_context_challenge_path: Path,
    expected_session_context_challenge_sha256: str,
    session_context_ack_path: Path,
    session_context_verdict_path: Path,
    expected_session_context_verdict_sha256: str,
    control_root: Optional[Path] = None,
    workspace_root: Optional[Path] = None,
) -> Dict[str, Any]:
    checks: list[dict[str, str]] = []
    errors: list[str] = []
    warnings: list[str] = []
    candidate: Dict[str, Any] = {
        "kind": None,
        "content_sha256": None,
        "size_bytes": None,
        "entry_count": None,
        "envelope_sha256": None,
    }
    nested_receipt: Optional[Mapping[str, Any]] = None
    session_verification: Dict[str, Any] = {
        "verified": False,
        "session_input_manifest_file_sha256": None,
        "session_input_manifest_sha256": None,
        "session_context_binding_id": None,
        "session_context_challenge_sha256": None,
        "session_context_ack_sha256": None,
        "session_context_verdict_sha256": None,
        "session_context_verdict_status": None,
        "challenge_id": None,
        "role": None,
        "active_case": None,
        "work_order_id": None,
        "baseline_head": None,
        "baseline_tree": None,
        "checkpoint_id": None,
        "checkpoint_hash": None,
        "event_cursor": None,
        "projection_sha256": None,
        "effect_ceiling": None,
    }

    files: Dict[str, bytes] = {}
    envelope_v12: Optional[Mapping[str, Any]] = None
    if not isinstance(return_path, (str, os.PathLike)) or not str(return_path):
        v1._record(checks, errors, warnings, "semantic_v1_2.return_path", "FAIL", "INVALID_RETURN_PATH")
    else:
        path = Path(return_path).expanduser()
        try:
            if path.is_dir():
                files, metadata = v1._read_directory_return(path)
            elif path.is_file() and path.suffix.lower() == ".zip":
                files, metadata = v1._read_zip_return(path)
            elif path.is_file():
                raise SemanticCloseV12Error("RETURN_FILE_MUST_BE_ZIP")
            else:
                raise SemanticCloseV12Error("RETURN_PATH_MISSING")
            candidate.update(metadata)
            payload = files.get(RETURN_ENVELOPE_V12_NAME)
            if payload is None:
                raise SemanticCloseV12Error("RETURN_V1_2_ENVELOPE_MISSING")
            parsed = v1.strict_json_loads(payload, RETURN_ENVELOPE_V12_NAME)
            if payload != v1.canonical_json_bytes(parsed):
                raise SemanticCloseV12Error("RETURN_V1_2_ENVELOPE_NON_CANONICAL")
            envelope_v12 = validate_return_envelope_v12(parsed)
            candidate["envelope_sha256"] = v1.sha256_bytes(payload)
            if v11.RETURN_ENVELOPE_V11_NAME in files:
                raise SemanticCloseV12Error("RETURN_V1_2_CONTAINS_COMPETING_V1_1_ENVELOPE")
        except (v1.AntiAmnesiaError, SemanticCloseV12Error) as exc:
            v1._record(checks, errors, warnings, "semantic_v1_2.return_envelope", "FAIL", str(exc))
        else:
            v1._record(checks, errors, warnings, "semantic_v1_2.return_envelope", "PASS", "VERIFIED")

    if envelope_v12 is not None:
        try:
            with tempfile.TemporaryDirectory(prefix="continuityos-semantic-v12-") as tmp:
                normalized = Path(tmp) / "normalized-return"
                _materialize_v11_view(files, envelope_v12["semantic_return_v1_1"], normalized)
                nested_receipt = v11.build_semantic_close_receipt(
                    normalized,
                    dry_run,
                    work_order_path=Path(work_order_path),
                    permission_policy_path=Path(permission_policy_path),
                    control_root=control_root,
                    workspace_root=workspace_root,
                )
        except Exception as exc:
            v1._record(
                checks,
                errors,
                warnings,
                "semantic_v1_2.semantic_v1_1_replay",
                "FAIL",
                f"{type(exc).__name__}:{exc}",
            )
        else:
            if nested_receipt["errors"]:
                for item in nested_receipt["errors"]:
                    errors.append(f"V1_1:{item}")
                v1._record(
                    checks,
                    errors,
                    warnings,
                    "semantic_v1_2.semantic_v1_1_replay",
                    "FAIL",
                    "V1_1_RECEIPT_HOLD",
                )
            else:
                warnings.extend(f"V1_1:{item}" for item in nested_receipt["warnings"])
                v1._record(
                    checks,
                    errors,
                    warnings,
                    "semantic_v1_2.semantic_v1_1_replay",
                    "PASS",
                    "VERIFIED",
                )

    if envelope_v12 is not None and nested_receipt is not None and not nested_receipt["errors"]:
        try:
            session_verification = _session_context_verification(
                envelope_v12=envelope_v12,
                nested_receipt=nested_receipt,
                manifest_path=Path(session_input_manifest_path),
                expected_manifest_sha256=expected_session_input_manifest_sha256,
                challenge_path=Path(session_context_challenge_path),
                expected_challenge_sha256=expected_session_context_challenge_sha256,
                ack_path=Path(session_context_ack_path),
                verdict_path=Path(session_context_verdict_path),
                expected_verdict_sha256=expected_session_context_verdict_sha256,
            )
        except (v1.AntiAmnesiaError, SemanticCloseV12Error, session_context.SessionContextError) as exc:
            v1._record(
                checks,
                errors,
                warnings,
                "semantic_v1_2.session_context",
                "FAIL",
                str(exc),
            )
        else:
            v1._record(
                checks,
                errors,
                warnings,
                "semantic_v1_2.session_context",
                "PASS",
                "EXACT_REPLAY_PASS",
            )

    checks = sorted(checks, key=lambda row: row["check_id"])
    errors = sorted(set(errors))
    warnings = sorted(set(warnings))
    if errors:
        outcome = "WOULD_HOLD"
        status = "SHADOW_HOLD"
    elif nested_receipt is not None and nested_receipt["approval"]["required"]:
        outcome = "PENDING_HUMAN_APPROVAL"
        status = "SHADOW_PENDING_HUMAN_APPROVAL"
    elif warnings:
        outcome = "WOULD_ACCEPT_WITH_WARNINGS"
        status = "SHADOW_ACCEPTABLE_WITH_WARNINGS"
    else:
        outcome = "WOULD_ACCEPT"
        status = "SHADOW_ACCEPTABLE"

    receipt = {
        "schema": SCHEMA_CLOSE,
        "gate": GATE,
        "mode": MODE,
        "command": {"name": "close", "dry_run": dry_run is True},
        "candidate": candidate,
        "semantic_v1_1_receipt": nested_receipt,
        "session_context_verification": session_verification,
        "checks": checks,
        "errors": errors,
        "warnings": warnings,
        "outcome": outcome,
        "status": status,
        "closed": False,
        "enforced": False,
        "live_state_modified": False,
        "r63_authority_replaced": False,
        "writes_performed": [],
        "can_trade": False,
        "capital_permission": "DENY",
        "deploy_permission": "DENY",
        "self_application": False,
    }
    validate_semantic_close_v12_receipt(receipt)
    return receipt


def validate_semantic_close_v12_receipt(value: Any) -> None:
    root = _exact_keys(
        value,
        {
            "schema",
            "gate",
            "mode",
            "command",
            "candidate",
            "semantic_v1_1_receipt",
            "session_context_verification",
            "checks",
            "errors",
            "warnings",
            "outcome",
            "status",
            "closed",
            "enforced",
            "live_state_modified",
            "r63_authority_replaced",
            "writes_performed",
            "can_trade",
            "capital_permission",
            "deploy_permission",
            "self_application",
        },
        "semantic_close_v1_2",
    )
    if root["schema"] != SCHEMA_CLOSE or root["gate"] != GATE or root["mode"] != MODE:
        raise SemanticCloseV12Error("semantic_close_v1_2:IDENTITY_MISMATCH")
    command = _exact_keys(root["command"], {"name", "dry_run"}, "semantic_close_v1_2.command")
    if command["name"] != "close" or not isinstance(command["dry_run"], bool):
        raise SemanticCloseV12Error("semantic_close_v1_2.command:INVALID")
    for field in (
        "closed",
        "enforced",
        "live_state_modified",
        "r63_authority_replaced",
        "can_trade",
        "self_application",
    ):
        if root[field] is not False:
            raise SemanticCloseV12Error(f"semantic_close_v1_2.{field}:EXPECTED_FALSE")
    if (
        root["writes_performed"] != []
        or root["capital_permission"] != "DENY"
        or root["deploy_permission"] != "DENY"
    ):
        raise SemanticCloseV12Error("semantic_close_v1_2:EFFECT_CEILING_MISMATCH")
    candidate = _exact_keys(
        root["candidate"],
        {"kind", "content_sha256", "size_bytes", "entry_count", "envelope_sha256"},
        "semantic_close_v1_2.candidate",
    )
    if candidate["kind"] not in {None, "ZIP", "DIRECTORY"}:
        raise SemanticCloseV12Error("semantic_close_v1_2.candidate:INVALID_KIND")
    for field in ("content_sha256", "envelope_sha256"):
        if candidate[field] is not None:
            _sha(candidate[field], f"semantic_close_v1_2.candidate.{field}")
    for field in ("size_bytes", "entry_count"):
        item = candidate[field]
        if item is not None and (
            not isinstance(item, int) or isinstance(item, bool) or item < 0
        ):
            raise SemanticCloseV12Error(
                f"semantic_close_v1_2.candidate.{field}:INVALID"
            )
    if root["semantic_v1_1_receipt"] is not None:
        v11.validate_semantic_close_receipt(root["semantic_v1_1_receipt"])
    session = _exact_keys(
        root["session_context_verification"],
        {
            "verified",
            "session_input_manifest_file_sha256",
            "session_input_manifest_sha256",
            "session_context_binding_id",
            "session_context_challenge_sha256",
            "session_context_ack_sha256",
            "session_context_verdict_sha256",
            "session_context_verdict_status",
            "challenge_id",
            "role",
            "active_case",
            "work_order_id",
            "baseline_head",
            "baseline_tree",
            "checkpoint_id",
            "checkpoint_hash",
            "event_cursor",
            "projection_sha256",
            "effect_ceiling",
        },
        "semantic_close_v1_2.session_context_verification",
    )
    if not isinstance(session["verified"], bool):
        raise SemanticCloseV12Error("semantic_close_v1_2.session_context_verification.verified:INVALID")
    if session["verified"]:
        for field in (
            "session_input_manifest_file_sha256",
            "session_input_manifest_sha256",
            "session_context_binding_id",
            "session_context_challenge_sha256",
            "session_context_ack_sha256",
            "session_context_verdict_sha256",
            "challenge_id",
            "checkpoint_hash",
            "projection_sha256",
        ):
            _sha(session[field], f"semantic_close_v1_2.session_context_verification.{field}")
        if session["session_context_verdict_status"] != "SESSION_CONTEXT_PASS":
            raise SemanticCloseV12Error("semantic_close_v1_2.session_context_verification:VERDICT_NOT_PASS")
        if session["effect_ceiling"] != "READ_ONLY":
            raise SemanticCloseV12Error("semantic_close_v1_2.session_context_verification:EFFECT_CEILING")
        if not isinstance(session["event_cursor"], int) or isinstance(session["event_cursor"], bool) or session["event_cursor"] < 0:
            raise SemanticCloseV12Error("semantic_close_v1_2.session_context_verification:EVENT_CURSOR")
        for field in ("role", "work_order_id", "baseline_head", "baseline_tree", "checkpoint_id"):
            if not isinstance(session[field], str) or not session[field]:
                raise SemanticCloseV12Error(f"semantic_close_v1_2.session_context_verification.{field}:INVALID")
    if not isinstance(root["checks"], list) or not all(isinstance(row, dict) for row in root["checks"]):
        raise SemanticCloseV12Error("semantic_close_v1_2.checks:INVALID")
    for field in ("errors", "warnings"):
        values = root[field]
        if (
            not isinstance(values, list)
            or not all(isinstance(item, str) and item for item in values)
            or values != sorted(set(values))
        ):
            raise SemanticCloseV12Error(f"semantic_close_v1_2.{field}:INVALID")
    if root["outcome"] not in {
        "WOULD_HOLD",
        "PENDING_HUMAN_APPROVAL",
        "WOULD_ACCEPT_WITH_WARNINGS",
        "WOULD_ACCEPT",
    }:
        raise SemanticCloseV12Error("semantic_close_v1_2.outcome:INVALID")
    expected_status = {
        "WOULD_HOLD": "SHADOW_HOLD",
        "PENDING_HUMAN_APPROVAL": "SHADOW_PENDING_HUMAN_APPROVAL",
        "WOULD_ACCEPT_WITH_WARNINGS": "SHADOW_ACCEPTABLE_WITH_WARNINGS",
        "WOULD_ACCEPT": "SHADOW_ACCEPTABLE",
    }[root["outcome"]]
    if root["status"] != expected_status:
        raise SemanticCloseV12Error("semantic_close_v1_2.status:MISMATCH")
    if bool(root["errors"]) != (root["outcome"] == "WOULD_HOLD"):
        raise SemanticCloseV12Error("semantic_close_v1_2:ERROR_OUTCOME_MISMATCH")
    if not root["errors"] and not session["verified"]:
        raise SemanticCloseV12Error("semantic_close_v1_2:ACCEPT_WITHOUT_SESSION_PROOF")
