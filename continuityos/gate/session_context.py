"""Deliver and verify one exact operational-memory context for one cold-start session.

The canonical input binding is ``ANTI_AMNESIA_SESSION_INPUT_MANIFEST_V1``.  This
module adds only a delivery/acknowledgement envelope around that verified
manifest:

* the base Anti-Amnesia cold-start challenge remains byte-identical;
* the session-input manifest must replay-verify against capsule, context, spec
  and the exact ``OPERATIONAL_CONTEXT_VERIFY_PASS`` receipt;
* the candidate receives capsule, context, manifest, a compact binding envelope,
  a strict ACK schema and minimal instructions;
* the controller retains the source challenge, context spec, context-verification
  receipt and hidden expected ACK;
* verification is exact and never accepts content or applies state.

No function mutates R63, runtime state, the operational-memory database, Git,
services, deployment or trading permissions.
"""
from __future__ import annotations

import json
import os
from importlib.resources import files as resource_files
from pathlib import Path
import re
import shutil
from typing import Any, Dict, Iterable, List, Mapping, Tuple

from .anti_amnesia import (
    GATE,
    MODE,
    AntiAmnesiaError,
    canonical_json_bytes,
    sha256_bytes,
    strict_json_loads,
)
from . import cold_start
from ..operational_context import (
    OperationalContextError,
    SCHEMA_PACK as OPERATIONAL_CONTEXT_SCHEMA,
    validate_context_pack_structure,
    validate_session_capsule,
)
from ..session_input import (
    SCHEMA_MANIFEST as SESSION_INPUT_MANIFEST_SCHEMA,
    SessionInputError,
    validate_session_input_manifest,
    verify_session_input_manifest,
)

SCHEMA_BINDING = "ANTI_AMNESIA_SESSION_CONTEXT_BINDING_V1"
SCHEMA_ACK = "ANTI_AMNESIA_SESSION_CONTEXT_ACK_V1"
SCHEMA_CHALLENGE = "ANTI_AMNESIA_SESSION_CONTEXT_CHALLENGE_V1"
SCHEMA_PREPARE_RECEIPT = "ANTI_AMNESIA_SESSION_CONTEXT_PREPARE_RECEIPT_V1"
SCHEMA_VERDICT = "ANTI_AMNESIA_SESSION_CONTEXT_VERDICT_V1"
AUTHORITY_GENERATION = "R63"
MAX_CONTEXT_BYTES = 4 * 1024 * 1024
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

_BINDING_KEYS = {
    "schema",
    "binding_id",
    "gate",
    "mode",
    "authority_generation",
    "base_challenge",
    "session_input_manifest",
    "ceilings",
}

_ACK_KEYS = {
    "schema",
    "binding_id",
    "challenge_id",
    "authority_generation",
    "role",
    "active_case",
    "work_order_id",
    "baseline_head",
    "baseline_tree",
    "effect_ceiling",
    "session_input_manifest_file_sha256",
    "session_input_manifest_sha256",
    "session_capsule_sha256",
    "operational_context_file_sha256",
    "operational_context_sha256",
    "context_spec_sha256",
    "context_verification_receipt_sha256",
    "checkpoint_id",
    "checkpoint_hash",
    "context_event_cursor",
    "context_projection_sha256",
    "accepted_truth_owner",
    "context_is_projection_only",
    "content_acceptance",
    "state_apply",
    "may_dispatch_codex",
    "can_trade",
    "capital_permission",
    "deploy_permission",
    "self_application",
}

_CHALLENGE_KEYS = {
    "schema",
    "binding_id",
    "gate",
    "mode",
    "authority_generation",
    "base_challenge",
    "binding_manifest",
    "candidate_session_input_manifest",
    "candidate_session_capsule",
    "candidate_operational_context",
    "controller_context_spec",
    "controller_context_verification",
    "candidate_ack_schema",
    "candidate_instructions",
    "controller_expected_ack",
    "live_state_modified",
    "writes_performed",
    "can_trade",
    "capital_permission",
}

_CEILINGS = {
    "accepted_truth_owner": "CONTROL_CENTER",
    "context_is_projection_only": True,
    "content_acceptance": "NOT_PERFORMED",
    "state_apply": "DISABLED",
    "may_dispatch_codex": False,
    "can_trade": False,
    "capital_permission": "DENY",
    "deploy_permission": "DENY",
    "self_application": False,
}

_INSTRUCTIONS = """Read SESSION_CAPSULE.json, OPERATIONAL_CONTEXT.json, SESSION_INPUT_MANIFEST.json and SESSION_CONTEXT_BINDING.json.

Return exactly one file named SESSION_CONTEXT_ACK.json.

The file must contain one JSON object conforming exactly to SESSION_CONTEXT_ACK.schema.json.
Copy only values supported by the supplied candidate files.
Do not add markdown, explanations or extra fields.
Do not request prior context.
Do not create any other file.
Stop after SESSION_CONTEXT_ACK.json.
"""


class SessionContextError(AntiAmnesiaError):
    """The session-context package or acknowledgement is invalid."""


def _exact_keys(value: Any, expected: Iterable[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise SessionContextError(f"{label}:NOT_OBJECT")
    want = set(expected)
    got = set(value)
    if want != got:
        raise SessionContextError(
            f"{label}:KEYS:missing={sorted(want - got)}:extra={sorted(got - want)}"
        )
    return value


def _sha(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
        raise SessionContextError(f"{label}:INVALID_SHA256")
    return value


def _nonempty(value: Any, label: str, *, max_length: int = 4096) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > max_length:
        raise SessionContextError(f"{label}:INVALID_STRING")
    return value


def _descriptor(value: Any, label: str, *, extra: Iterable[str] = ()) -> Mapping[str, Any]:
    keys = {"path", "sha256", *set(extra)}
    row = _exact_keys(value, keys, label)
    _nonempty(row["path"], f"{label}.path", max_length=512)
    _sha(row["sha256"], f"{label}.sha256")
    return row


def _load_json_file(
    path: Path,
    label: str,
    *,
    max_bytes: int = MAX_CONTEXT_BYTES,
    canonical: bool = True,
) -> Tuple[bytes, str, Any]:
    payload = cold_start.stable_read_bytes(path, label=label, max_bytes=max_bytes)
    parsed = strict_json_loads(payload, label)
    if canonical and payload != canonical_json_bytes(parsed):
        raise SessionContextError(f"{label}:NON_CANONICAL_JSON")
    return payload, sha256_bytes(payload), parsed


def _load_base_challenge(
    challenge_path: Path,
    *,
    expected_sha256: str,
) -> Tuple[Dict[str, Any], bytes, str, Path, Dict[str, Any], bytes, str]:
    _sha(expected_sha256, "base_challenge.expected_sha256")
    challenge_payload, challenge_sha, parsed = _load_json_file(
        Path(challenge_path), "session_context.base_challenge"
    )
    if challenge_sha != expected_sha256:
        raise SessionContextError("base_challenge:SHA256_MISMATCH")
    row = _exact_keys(
        parsed,
        {
            "schema",
            "challenge_id",
            "gate",
            "mode",
            "authority_generation",
            "boot_receipt",
            "session_spec",
            "candidate_capsule",
            "controller_expected_ack",
            "candidate_instructions",
            "live_state_modified",
            "can_trade",
            "capital_permission",
        },
        "base_challenge",
    )
    if (
        row["schema"] != cold_start.SCHEMA_CHALLENGE
        or row["gate"] != GATE
        or row["mode"] != MODE
    ):
        raise SessionContextError("base_challenge:UNSUPPORTED_IDENTITY")
    if row["authority_generation"] != AUTHORITY_GENERATION:
        raise SessionContextError("base_challenge:NOT_R63")
    _sha(row["challenge_id"], "base_challenge.challenge_id")
    if (
        row["live_state_modified"] is not False
        or row["can_trade"] is not False
        or row["capital_permission"] != "DENY"
    ):
        raise SessionContextError("base_challenge:EFFECT_CEILING_VIOLATION")

    challenge_root = Path(challenge_path).resolve().parent
    capsule_desc = _descriptor(row["candidate_capsule"], "base_challenge.candidate_capsule")
    capsule_path = cold_start._safe_challenge_relative(
        challenge_root,
        capsule_desc["path"],
        "base_challenge.candidate_capsule.path",
    )
    capsule_payload, capsule_sha, capsule_parsed = _load_json_file(
        capsule_path, "session_context.session_capsule"
    )
    if capsule_sha != capsule_desc["sha256"]:
        raise SessionContextError("base_challenge:CAPSULE_SHA256_MISMATCH")
    try:
        capsule = validate_session_capsule(capsule_parsed)
    except OperationalContextError as exc:
        raise SessionContextError(str(exc)) from exc
    if capsule["challenge_id"] != row["challenge_id"]:
        raise SessionContextError("base_challenge:CAPSULE_CHALLENGE_MISMATCH")
    return (
        dict(row),
        challenge_payload,
        challenge_sha,
        capsule_path,
        capsule,
        capsule_payload,
        capsule_sha,
    )


def _load_operational_context(path: Path) -> Tuple[Dict[str, Any], bytes, str]:
    payload, file_sha, parsed = _load_json_file(
        Path(path), "session_context.operational_context"
    )
    try:
        context = validate_context_pack_structure(parsed)
    except OperationalContextError as exc:
        raise SessionContextError(str(exc)) from exc
    return context, payload, file_sha


def _load_session_input_manifest(
    path: Path,
    *,
    expected_sha256: str,
) -> Tuple[Dict[str, Any], bytes, str]:
    _sha(expected_sha256, "session_input_manifest.expected_sha256")
    payload, file_sha, parsed = _load_json_file(
        Path(path), "session_context.session_input_manifest"
    )
    if file_sha != expected_sha256:
        raise SessionContextError("session_input_manifest:PINNED_SHA256_MISMATCH")
    try:
        manifest = validate_session_input_manifest(parsed)
    except SessionInputError as exc:
        raise SessionContextError(str(exc)) from exc
    return manifest, payload, file_sha


def _require_manifest_replay_pass(
    *,
    capsule_path: Path,
    context_path: Path,
    spec_path: Path,
    context_verification_path: Path,
    manifest_path: Path,
    manifest_file_sha256: str,
) -> Dict[str, Any]:
    try:
        receipt = verify_session_input_manifest(
            capsule_path=Path(capsule_path),
            context_path=Path(context_path),
            spec_path=Path(spec_path),
            context_verification_path=Path(context_verification_path),
            manifest_path=Path(manifest_path),
            expected_manifest_file_sha256=manifest_file_sha256,
        )
    except SessionInputError as exc:
        raise SessionContextError(str(exc)) from exc
    if (
        receipt.get("schema") != "ANTI_AMNESIA_SESSION_INPUT_VERIFY_RECEIPT_V1"
        or receipt.get("status") != "SESSION_INPUT_VERIFY_PASS"
        or receipt.get("ok") is not True
        or receipt.get("exact_bytes") is not True
        or receipt.get("live_state_modified") is not False
        or receipt.get("can_trade") is not False
        or receipt.get("capital_permission") != "DENY"
        or receipt.get("deploy_permission") != "DENY"
        or receipt.get("self_application") is not False
    ):
        raise SessionContextError("session_input_manifest:REPLAY_VERIFY_NOT_PASS")
    return dict(receipt)


def _verify_manifest_matches_base(
    manifest: Mapping[str, Any],
    *,
    base_challenge: Mapping[str, Any],
    capsule: Mapping[str, Any],
    capsule_sha256: str,
    context: Mapping[str, Any],
    context_file_sha256: str,
) -> None:
    session = manifest["session_binding"]
    artifacts = manifest["artifact_binding"]
    memory = manifest["memory_binding"]
    baseline = capsule["git_baseline"]
    expected = {
        "challenge_id": base_challenge["challenge_id"],
        "role": capsule["role"],
        "active_case": capsule["active_case"],
        "work_order_id": capsule["work_order_id"],
        "git_head": baseline["head"],
        "git_tree": baseline["tree"],
        "capsule_sha256": capsule_sha256,
        "context_file_sha256": context_file_sha256,
        "context_sha256": context["context_sha256"],
        "checkpoint_id": context["memory_binding"]["checkpoint"]["checkpoint_id"],
        "checkpoint_hash": context["memory_binding"]["checkpoint"]["checkpoint_hash"],
        "event_cursor": context["memory_binding"]["context_event_cursor"],
        "projection_sha256": context["memory_binding"]["context_projection_sha256"],
    }
    observed = {
        "challenge_id": session["challenge_id"],
        "role": session["role"],
        "active_case": session["active_case"],
        "work_order_id": session["work_order_id"],
        "git_head": session["git_head"],
        "git_tree": session["git_tree"],
        "capsule_sha256": artifacts["session_capsule"]["sha256"],
        "context_file_sha256": artifacts["operational_context"]["file_sha256"],
        "context_sha256": artifacts["operational_context"]["context_sha256"],
        "checkpoint_id": memory["checkpoint_id"],
        "checkpoint_hash": memory["checkpoint_hash"],
        "event_cursor": memory["event_cursor"],
        "projection_sha256": memory["projection_sha256"],
    }
    mismatches = sorted(key for key in expected if observed[key] != expected[key])
    if mismatches:
        raise SessionContextError(
            "session_input_manifest:BASE_RELATION_MISMATCH:" + ",".join(mismatches)
        )
    if manifest["ceilings"] != {
        "effect_ceiling": capsule["effect_ceiling"],
        **_CEILINGS,
    }:
        raise SessionContextError("session_input_manifest:CEILING_VIOLATION")


def _binding_body(
    *,
    base_challenge: Mapping[str, Any],
    base_challenge_sha256: str,
    manifest: Mapping[str, Any],
    manifest_file_sha256: str,
) -> Dict[str, Any]:
    return {
        "schema": SCHEMA_BINDING,
        "gate": GATE,
        "mode": MODE,
        "authority_generation": AUTHORITY_GENERATION,
        "base_challenge": {
            "challenge_id": base_challenge["challenge_id"],
            "sha256": base_challenge_sha256,
        },
        "session_input_manifest": {
            "schema": SESSION_INPUT_MANIFEST_SCHEMA,
            "file_sha256": manifest_file_sha256,
            "manifest_sha256": manifest["manifest_sha256"],
        },
        "ceilings": dict(_CEILINGS),
    }


def validate_session_context_binding(value: Any) -> Dict[str, Any]:
    row = _exact_keys(value, _BINDING_KEYS, "session_context_binding")
    if row["schema"] != SCHEMA_BINDING or row["gate"] != GATE or row["mode"] != MODE:
        raise SessionContextError("session_context_binding:UNSUPPORTED_IDENTITY")
    if row["authority_generation"] != AUTHORITY_GENERATION:
        raise SessionContextError("session_context_binding:NOT_R63")
    binding_id = _sha(row["binding_id"], "session_context_binding.binding_id")
    base = _exact_keys(
        row["base_challenge"],
        {"challenge_id", "sha256"},
        "session_context_binding.base_challenge",
    )
    _sha(base["challenge_id"], "session_context_binding.base_challenge.challenge_id")
    _sha(base["sha256"], "session_context_binding.base_challenge.sha256")
    manifest = _exact_keys(
        row["session_input_manifest"],
        {"schema", "file_sha256", "manifest_sha256"},
        "session_context_binding.session_input_manifest",
    )
    if manifest["schema"] != SESSION_INPUT_MANIFEST_SCHEMA:
        raise SessionContextError("session_context_binding.session_input_manifest:UNSUPPORTED")
    _sha(manifest["file_sha256"], "session_context_binding.session_input_manifest.file_sha256")
    _sha(manifest["manifest_sha256"], "session_context_binding.session_input_manifest.manifest_sha256")
    if row["ceilings"] != _CEILINGS:
        raise SessionContextError("session_context_binding.ceilings:VIOLATION")
    body = dict(row)
    body.pop("binding_id")
    if binding_id != sha256_bytes(canonical_json_bytes(body)):
        raise SessionContextError("session_context_binding.binding_id:MISMATCH")
    return dict(row)


def _expected_ack(
    binding: Mapping[str, Any],
    manifest: Mapping[str, Any],
) -> Dict[str, Any]:
    session = manifest["session_binding"]
    artifacts = manifest["artifact_binding"]
    memory = manifest["memory_binding"]
    ceilings = manifest["ceilings"]
    return {
        "schema": SCHEMA_ACK,
        "binding_id": binding["binding_id"],
        "challenge_id": session["challenge_id"],
        "authority_generation": AUTHORITY_GENERATION,
        "role": session["role"],
        "active_case": session["active_case"],
        "work_order_id": session["work_order_id"],
        "baseline_head": session["git_head"],
        "baseline_tree": session["git_tree"],
        "effect_ceiling": ceilings["effect_ceiling"],
        "session_input_manifest_file_sha256": binding["session_input_manifest"]["file_sha256"],
        "session_input_manifest_sha256": binding["session_input_manifest"]["manifest_sha256"],
        "session_capsule_sha256": artifacts["session_capsule"]["sha256"],
        "operational_context_file_sha256": artifacts["operational_context"]["file_sha256"],
        "operational_context_sha256": artifacts["operational_context"]["context_sha256"],
        "context_spec_sha256": artifacts["context_spec"]["sha256"],
        "context_verification_receipt_sha256": artifacts["context_verification"]["sha256"],
        "checkpoint_id": memory["checkpoint_id"],
        "checkpoint_hash": memory["checkpoint_hash"],
        "context_event_cursor": memory["event_cursor"],
        "context_projection_sha256": memory["projection_sha256"],
        **dict(_CEILINGS),
    }


def validate_session_context_ack(value: Any) -> Dict[str, Any]:
    row = _exact_keys(value, _ACK_KEYS, "session_context_ack")
    if row["schema"] != SCHEMA_ACK:
        raise SessionContextError("session_context_ack.schema:UNSUPPORTED")
    for field in (
        "binding_id",
        "challenge_id",
        "session_input_manifest_file_sha256",
        "session_input_manifest_sha256",
        "session_capsule_sha256",
        "operational_context_file_sha256",
        "operational_context_sha256",
        "context_spec_sha256",
        "context_verification_receipt_sha256",
        "checkpoint_hash",
        "context_projection_sha256",
    ):
        _sha(row[field], f"session_context_ack.{field}")
    for field in ("baseline_head", "baseline_tree"):
        value = row[field]
        if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{40,64}", value):
            raise SessionContextError(f"session_context_ack.{field}:INVALID_GIT_OBJECT")
    if row["authority_generation"] != AUTHORITY_GENERATION:
        raise SessionContextError("session_context_ack.authority_generation:NOT_R63")
    for field in ("role", "work_order_id", "checkpoint_id", "effect_ceiling"):
        _nonempty(row[field], f"session_context_ack.{field}", max_length=192)
    if row["active_case"] is not None:
        _nonempty(row["active_case"], "session_context_ack.active_case", max_length=192)
    if isinstance(row["context_event_cursor"], bool) or not isinstance(
        row["context_event_cursor"], int
    ) or row["context_event_cursor"] < 0:
        raise SessionContextError("session_context_ack.context_event_cursor:INVALID")
    if {key: row[key] for key in _CEILINGS} != _CEILINGS:
        raise SessionContextError("session_context_ack.ceilings:VIOLATION")
    return dict(row)


def _schema_bytes() -> bytes:
    return resource_files("continuityos.gate.schemas").joinpath(
        "anti_amnesia_session_context_ack_v1.schema.json"
    ).read_bytes()


def _write_atomic_directory(target: Path, files: Mapping[str, bytes]) -> None:
    target = Path(target).expanduser().absolute()
    if target.exists():
        raise SessionContextError("output:TARGET_ALREADY_EXISTS")
    target.parent.mkdir(parents=True, exist_ok=True)
    temp_root = target.parent / f".{target.name}.tmp-{os.getpid()}-{os.urandom(8).hex()}"
    if temp_root.exists():
        raise SessionContextError("output:TEMP_ALREADY_EXISTS")
    temp_root.mkdir(mode=0o700)
    try:
        for relative, payload in files.items():
            destination = temp_root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            cold_start._write_new(destination, payload)
        cold_start._fsync_directory(temp_root / "candidate")
        cold_start._fsync_directory(temp_root / "controller")
        cold_start._fsync_directory(temp_root)
        os.replace(temp_root, target)
        cold_start._fsync_directory(target.parent)
    except Exception:
        shutil.rmtree(temp_root, ignore_errors=True)
        raise


def prepare_session_context_binding(
    base_challenge_path: Path,
    context_path: Path,
    session_input_manifest_path: Path,
    context_spec_path: Path,
    context_verification_path: Path,
    output_dir: Path,
    *,
    expected_base_challenge_sha256: str,
    expected_session_input_manifest_sha256: str,
) -> Dict[str, Any]:
    (
        base_challenge,
        base_payload,
        base_sha,
        capsule_path,
        capsule,
        capsule_payload,
        capsule_sha,
    ) = _load_base_challenge(
        Path(base_challenge_path), expected_sha256=expected_base_challenge_sha256
    )
    context, context_payload, context_file_sha = _load_operational_context(Path(context_path))
    manifest, manifest_payload, manifest_file_sha = _load_session_input_manifest(
        Path(session_input_manifest_path),
        expected_sha256=expected_session_input_manifest_sha256,
    )
    replay = _require_manifest_replay_pass(
        capsule_path=capsule_path,
        context_path=Path(context_path),
        spec_path=Path(context_spec_path),
        context_verification_path=Path(context_verification_path),
        manifest_path=Path(session_input_manifest_path),
        manifest_file_sha256=manifest_file_sha,
    )
    _verify_manifest_matches_base(
        manifest,
        base_challenge=base_challenge,
        capsule=capsule,
        capsule_sha256=capsule_sha,
        context=context,
        context_file_sha256=context_file_sha,
    )
    spec_payload = cold_start.stable_read_bytes(
        Path(context_spec_path), label="session_context.context_spec", max_bytes=MAX_CONTEXT_BYTES
    )
    verify_payload = cold_start.stable_read_bytes(
        Path(context_verification_path),
        label="session_context.context_verification",
        max_bytes=MAX_CONTEXT_BYTES,
    )
    if sha256_bytes(spec_payload) != manifest["artifact_binding"]["context_spec"]["sha256"]:
        raise SessionContextError("session_input_manifest:CONTEXT_SPEC_SHA_MISMATCH")
    if sha256_bytes(verify_payload) != manifest["artifact_binding"]["context_verification"]["sha256"]:
        raise SessionContextError("session_input_manifest:CONTEXT_VERIFICATION_SHA_MISMATCH")

    body = _binding_body(
        base_challenge=base_challenge,
        base_challenge_sha256=base_sha,
        manifest=manifest,
        manifest_file_sha256=manifest_file_sha,
    )
    binding_id = sha256_bytes(canonical_json_bytes(body))
    binding = validate_session_context_binding({**body, "binding_id": binding_id})
    binding_payload = canonical_json_bytes(binding)
    expected = validate_session_context_ack(_expected_ack(binding, manifest))
    expected_payload = canonical_json_bytes(expected)
    schema_payload = _schema_bytes()
    instructions_payload = _INSTRUCTIONS.encode("utf-8")

    challenge = {
        "schema": SCHEMA_CHALLENGE,
        "binding_id": binding_id,
        "gate": GATE,
        "mode": MODE,
        "authority_generation": AUTHORITY_GENERATION,
        "base_challenge": {
            "path": "controller/BASE_COLD_START_CHALLENGE.json",
            "sha256": base_sha,
        },
        "binding_manifest": {
            "path": "candidate/SESSION_CONTEXT_BINDING.json",
            "sha256": sha256_bytes(binding_payload),
        },
        "candidate_session_input_manifest": {
            "path": "candidate/SESSION_INPUT_MANIFEST.json",
            "sha256": manifest_file_sha,
            "manifest_sha256": manifest["manifest_sha256"],
        },
        "candidate_session_capsule": {
            "path": "candidate/SESSION_CAPSULE.json",
            "sha256": capsule_sha,
        },
        "candidate_operational_context": {
            "path": "candidate/OPERATIONAL_CONTEXT.json",
            "sha256": context_file_sha,
            "context_sha256": context["context_sha256"],
        },
        "controller_context_spec": {
            "path": "controller/OPERATIONAL_CONTEXT_SPEC.json",
            "sha256": sha256_bytes(spec_payload),
        },
        "controller_context_verification": {
            "path": "controller/OPERATIONAL_CONTEXT_VERIFY_RECEIPT.json",
            "sha256": sha256_bytes(verify_payload),
        },
        "candidate_ack_schema": {
            "path": "candidate/SESSION_CONTEXT_ACK.schema.json",
            "sha256": sha256_bytes(schema_payload),
        },
        "candidate_instructions": {
            "path": "candidate/INSTRUCTIONS.md",
            "sha256": sha256_bytes(instructions_payload),
        },
        "controller_expected_ack": {
            "path": "controller/EXPECTED_SESSION_CONTEXT_ACK.json",
            "sha256": sha256_bytes(expected_payload),
        },
        "live_state_modified": False,
        "writes_performed": [],
        "can_trade": False,
        "capital_permission": "DENY",
    }
    challenge_payload = canonical_json_bytes(challenge)
    paths = [
        "SESSION_CONTEXT_CHALLENGE.json",
        "controller/BASE_COLD_START_CHALLENGE.json",
        "controller/OPERATIONAL_CONTEXT_SPEC.json",
        "controller/OPERATIONAL_CONTEXT_VERIFY_RECEIPT.json",
        "candidate/SESSION_CAPSULE.json",
        "candidate/OPERATIONAL_CONTEXT.json",
        "candidate/SESSION_INPUT_MANIFEST.json",
        "candidate/SESSION_CONTEXT_BINDING.json",
        "candidate/SESSION_CONTEXT_ACK.schema.json",
        "candidate/INSTRUCTIONS.md",
        "controller/EXPECTED_SESSION_CONTEXT_ACK.json",
    ]
    payloads = {
        "SESSION_CONTEXT_CHALLENGE.json": challenge_payload,
        "controller/BASE_COLD_START_CHALLENGE.json": base_payload,
        "controller/OPERATIONAL_CONTEXT_SPEC.json": spec_payload,
        "controller/OPERATIONAL_CONTEXT_VERIFY_RECEIPT.json": verify_payload,
        "candidate/SESSION_CAPSULE.json": capsule_payload,
        "candidate/OPERATIONAL_CONTEXT.json": context_payload,
        "candidate/SESSION_INPUT_MANIFEST.json": manifest_payload,
        "candidate/SESSION_CONTEXT_BINDING.json": binding_payload,
        "candidate/SESSION_CONTEXT_ACK.schema.json": schema_payload,
        "candidate/INSTRUCTIONS.md": instructions_payload,
        "controller/EXPECTED_SESSION_CONTEXT_ACK.json": expected_payload,
    }
    hashes = {path: sha256_bytes(payloads[path]) for path in paths}
    payloads["SHA256SUMS.txt"] = "".join(
        f"{hashes[path]}  {path}\n" for path in paths
    ).encode("utf-8")
    _write_atomic_directory(Path(output_dir), payloads)
    return {
        "schema": SCHEMA_PREPARE_RECEIPT,
        "binding_id": binding_id,
        "output_dir": str(Path(output_dir).expanduser().absolute()),
        "base_challenge_sha256": base_sha,
        "session_input_manifest_file_sha256": manifest_file_sha,
        "session_input_manifest_sha256": manifest["manifest_sha256"],
        "binding_sha256": sha256_bytes(binding_payload),
        "operational_context_file_sha256": context_file_sha,
        "operational_context_sha256": context["context_sha256"],
        "context_spec_sha256": sha256_bytes(spec_payload),
        "context_verification_receipt_sha256": sha256_bytes(verify_payload),
        "session_input_replay_receipt_sha256": sha256_bytes(canonical_json_bytes(replay)),
        "challenge_sha256": sha256_bytes(challenge_payload),
        "expected_ack_sha256": sha256_bytes(expected_payload),
        "checkpoint_id": manifest["memory_binding"]["checkpoint_id"],
        "status": "SESSION_CONTEXT_CHALLENGE_READY",
        "live_state_modified": False,
        "writes_performed": [*paths, "SHA256SUMS.txt"],
        "can_trade": False,
        "capital_permission": "DENY",
    }


def _load_bound_challenge(
    challenge_path: Path,
    *,
    expected_sha256: str,
) -> Tuple[Dict[str, Any], str, Path]:
    _sha(expected_sha256, "session_context_challenge.expected_sha256")
    _payload, actual_sha, parsed = _load_json_file(
        Path(challenge_path), "session_context.challenge"
    )
    if actual_sha != expected_sha256:
        raise SessionContextError("session_context_challenge:SHA256_MISMATCH")
    row = _exact_keys(parsed, _CHALLENGE_KEYS, "session_context_challenge")
    if row["schema"] != SCHEMA_CHALLENGE or row["gate"] != GATE or row["mode"] != MODE:
        raise SessionContextError("session_context_challenge:UNSUPPORTED_IDENTITY")
    if row["authority_generation"] != AUTHORITY_GENERATION:
        raise SessionContextError("session_context_challenge:NOT_R63")
    _sha(row["binding_id"], "session_context_challenge.binding_id")
    if (
        row["live_state_modified"] is not False
        or row["writes_performed"] != []
        or row["can_trade"] is not False
        or row["capital_permission"] != "DENY"
    ):
        raise SessionContextError("session_context_challenge:EFFECT_CEILING_VIOLATION")
    return dict(row), actual_sha, Path(challenge_path).resolve().parent


def _read_descriptor_file(
    root: Path,
    descriptor: Mapping[str, Any],
    label: str,
    *,
    canonical: bool = True,
) -> Tuple[Path, bytes, str, Any]:
    path = cold_start._safe_challenge_relative(root, descriptor["path"], f"{label}.path")
    payload, actual_sha, parsed = _load_json_file(path, label, canonical=canonical)
    if actual_sha != descriptor["sha256"]:
        raise SessionContextError(f"{label}:SHA256_MISMATCH")
    return path, payload, actual_sha, parsed


def _read_raw_descriptor_file(
    root: Path,
    descriptor: Mapping[str, Any],
    label: str,
) -> Tuple[Path, bytes, str]:
    path = cold_start._safe_challenge_relative(root, descriptor["path"], f"{label}.path")
    payload = cold_start.stable_read_bytes(path, label=label, max_bytes=MAX_CONTEXT_BYTES)
    actual_sha = sha256_bytes(payload)
    if actual_sha != descriptor["sha256"]:
        raise SessionContextError(f"{label}:SHA256_MISMATCH")
    return path, payload, actual_sha


def verify_session_context_ack(
    challenge_path: Path,
    ack_path: Path,
    *,
    expected_challenge_sha256: str,
) -> Dict[str, Any]:
    challenge, challenge_sha, root = _load_bound_challenge(
        Path(challenge_path), expected_sha256=expected_challenge_sha256
    )
    base_desc = _descriptor(challenge["base_challenge"], "challenge.base_challenge")
    binding_desc = _descriptor(challenge["binding_manifest"], "challenge.binding_manifest")
    manifest_desc = _descriptor(
        challenge["candidate_session_input_manifest"],
        "challenge.candidate_session_input_manifest",
        extra={"manifest_sha256"},
    )
    capsule_desc = _descriptor(challenge["candidate_session_capsule"], "challenge.candidate_session_capsule")
    context_desc = _descriptor(
        challenge["candidate_operational_context"],
        "challenge.candidate_operational_context",
        extra={"context_sha256"},
    )
    spec_desc = _descriptor(challenge["controller_context_spec"], "challenge.controller_context_spec")
    verify_desc = _descriptor(
        challenge["controller_context_verification"],
        "challenge.controller_context_verification",
    )
    schema_desc = _descriptor(challenge["candidate_ack_schema"], "challenge.candidate_ack_schema")
    instructions_desc = _descriptor(challenge["candidate_instructions"], "challenge.candidate_instructions")
    expected_desc = _descriptor(challenge["controller_expected_ack"], "challenge.controller_expected_ack")
    _sha(manifest_desc["manifest_sha256"], "challenge.candidate_session_input_manifest.manifest_sha256")
    _sha(context_desc["context_sha256"], "challenge.candidate_operational_context.context_sha256")

    base_path, base_payload, base_sha = _read_raw_descriptor_file(root, base_desc, "session_context.base_challenge")
    base_parsed = strict_json_loads(base_payload, "session_context.base_challenge")
    if base_payload != canonical_json_bytes(base_parsed):
        raise SessionContextError("session_context.base_challenge:NON_CANONICAL_JSON")
    base_row = _exact_keys(
        base_parsed,
        {
            "schema", "challenge_id", "gate", "mode", "authority_generation",
            "boot_receipt", "session_spec", "candidate_capsule",
            "controller_expected_ack", "candidate_instructions",
            "live_state_modified", "can_trade", "capital_permission",
        },
        "session_context.base_challenge",
    )
    if (
        base_row["schema"] != cold_start.SCHEMA_CHALLENGE
        or base_row["gate"] != GATE
        or base_row["mode"] != MODE
        or base_row["authority_generation"] != AUTHORITY_GENERATION
    ):
        raise SessionContextError("session_context.base_challenge:UNSUPPORTED_IDENTITY")

    binding_path, _binding_payload, _binding_sha, binding_parsed = _read_descriptor_file(
        root, binding_desc, "session_context.binding_manifest"
    )
    binding = validate_session_context_binding(binding_parsed)
    if binding["binding_id"] != challenge["binding_id"]:
        raise SessionContextError("session_context_challenge:BINDING_ID_MISMATCH")
    if binding["base_challenge"] != {
        "challenge_id": base_row["challenge_id"],
        "sha256": base_sha,
    }:
        raise SessionContextError("session_context_challenge:BASE_CHALLENGE_BINDING_MISMATCH")

    capsule_path, _capsule_payload, capsule_sha, capsule_parsed = _read_descriptor_file(
        root, capsule_desc, "session_context.session_capsule"
    )
    try:
        capsule = validate_session_capsule(capsule_parsed)
    except OperationalContextError as exc:
        raise SessionContextError(str(exc)) from exc
    context_path, _context_payload, context_file_sha, context_parsed = _read_descriptor_file(
        root, context_desc, "session_context.operational_context"
    )
    try:
        context = validate_context_pack_structure(context_parsed)
    except OperationalContextError as exc:
        raise SessionContextError(str(exc)) from exc
    if context["context_sha256"] != context_desc["context_sha256"]:
        raise SessionContextError("session_context_challenge:CONTEXT_SHA256_MISMATCH")
    manifest_path, _manifest_payload, manifest_file_sha, manifest_parsed = _read_descriptor_file(
        root, manifest_desc, "session_context.session_input_manifest"
    )
    try:
        manifest = validate_session_input_manifest(manifest_parsed)
    except SessionInputError as exc:
        raise SessionContextError(str(exc)) from exc
    if manifest["manifest_sha256"] != manifest_desc["manifest_sha256"]:
        raise SessionContextError("session_context_challenge:MANIFEST_SHA256_MISMATCH")
    spec_path, _spec_payload, _spec_sha = _read_raw_descriptor_file(
        root, spec_desc, "session_context.context_spec"
    )
    verify_path, _verify_payload, _verify_sha = _read_raw_descriptor_file(
        root, verify_desc, "session_context.context_verification"
    )
    _require_manifest_replay_pass(
        capsule_path=capsule_path,
        context_path=context_path,
        spec_path=spec_path,
        context_verification_path=verify_path,
        manifest_path=manifest_path,
        manifest_file_sha256=manifest_file_sha,
    )
    _verify_manifest_matches_base(
        manifest,
        base_challenge=base_row,
        capsule=capsule,
        capsule_sha256=capsule_sha,
        context=context,
        context_file_sha256=context_file_sha,
    )
    reconstructed_body = _binding_body(
        base_challenge=base_row,
        base_challenge_sha256=base_sha,
        manifest=manifest,
        manifest_file_sha256=manifest_file_sha,
    )
    reconstructed = validate_session_context_binding(
        {**reconstructed_body, "binding_id": sha256_bytes(canonical_json_bytes(reconstructed_body))}
    )
    if reconstructed != binding:
        raise SessionContextError("session_context_binding:ARTIFACT_RELATION_MISMATCH")

    _schema_path, schema_payload, _schema_sha = _read_raw_descriptor_file(
        root, schema_desc, "session_context.ack_schema"
    )
    if schema_payload != _schema_bytes():
        raise SessionContextError("session_context.ack_schema:PACKAGED_SCHEMA_MISMATCH")
    _instructions_path, instructions_payload, _instructions_sha = _read_raw_descriptor_file(
        root, instructions_desc, "session_context.instructions"
    )
    if instructions_payload != _INSTRUCTIONS.encode("utf-8"):
        raise SessionContextError("session_context.instructions:MISMATCH")
    _expected_path, _expected_payload, _expected_sha, expected_parsed = _read_descriptor_file(
        root, expected_desc, "session_context.expected_ack"
    )
    expected = validate_session_context_ack(expected_parsed)
    if expected != _expected_ack(binding, manifest):
        raise SessionContextError("session_context.expected_ack:DOES_NOT_MATCH_BINDING")

    _ack_payload, ack_sha, ack_parsed = _load_json_file(Path(ack_path), "session_context.ack")
    try:
        ack = validate_session_context_ack(ack_parsed)
    except SessionContextError as exc:
        return {
            "schema": SCHEMA_VERDICT,
            "binding_id": challenge["binding_id"],
            "challenge_sha256": challenge_sha,
            "ack_sha256": ack_sha,
            "checks": [{"check_id": "ack.schema", "status": "FAIL", "code": str(exc)}],
            "mismatches": [{"path": "/", "expected": "schema-valid exact SESSION_CONTEXT_ACK", "observed": str(exc)}],
            "outcome": "FAIL",
            "status": "SESSION_CONTEXT_FAIL",
            "release_blocked": True,
            "live_state_modified": False,
            "writes_performed": [],
            "can_trade": False,
            "capital_permission": "DENY",
        }
    checks: List[Dict[str, str]] = []
    mismatches: List[Dict[str, Any]] = []
    for field in sorted(expected):
        if ack.get(field) == expected.get(field):
            checks.append({"check_id": f"ack.{field}", "status": "PASS", "code": "EXACT_MATCH"})
        else:
            checks.append({"check_id": f"ack.{field}", "status": "FAIL", "code": "MISMATCH"})
            mismatches.append({"path": f"/{field}", "expected": expected.get(field), "observed": ack.get(field)})
    passed = not mismatches
    return {
        "schema": SCHEMA_VERDICT,
        "binding_id": challenge["binding_id"],
        "challenge_sha256": challenge_sha,
        "ack_sha256": ack_sha,
        "checks": checks,
        "mismatches": mismatches,
        "outcome": "PASS" if passed else "FAIL",
        "status": "SESSION_CONTEXT_PASS" if passed else "SESSION_CONTEXT_FAIL",
        "release_blocked": not passed,
        "live_state_modified": False,
        "writes_performed": [],
        "can_trade": False,
        "capital_permission": "DENY",
    }
