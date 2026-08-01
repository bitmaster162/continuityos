"""Bind one verified operational context pack to an Anti-Amnesia session.

The existing cold-start challenge proves that a fresh model recovered the exact
controller-authored session capsule.  Common Operational Context proves that a
bounded memory projection was deterministically derived from a named checkpoint.
This module closes the handoff between those two artifacts without creating a
hash cycle:

* the base cold-start challenge and capsule remain byte-identical;
* the operational context already binds to the exact capsule SHA-256;
* a new session-context binding manifest binds capsule, context and ceilings;
* the fresh model returns one exact SESSION_CONTEXT_ACK;
* verification is byte/hash based and never accepts or applies state.

No function here mutates R63, runtime state, the operational database, Git,
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
    "session",
    "session_capsule",
    "operational_context",
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
    "session_capsule_sha256",
    "operational_context_file_sha256",
    "operational_context_sha256",
    "checkpoint_id",
    "checkpoint_hash",
    "context_event_cursor",
    "context_projection_sha256",
    "selection_spec_sha256",
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
    "candidate_session_capsule",
    "candidate_operational_context",
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

_INSTRUCTIONS = """Read SESSION_CAPSULE.json, OPERATIONAL_CONTEXT.json and SESSION_CONTEXT_BINDING.json.

Return exactly one file named SESSION_CONTEXT_ACK.json.

The file must contain one JSON object conforming exactly to SESSION_CONTEXT_ACK.schema.json.
Copy only values supported by the supplied candidate files.
Do not add markdown, explanations or extra fields.
Do not request prior context.
Do not create any other file.
Stop after SESSION_CONTEXT_ACK.json.
"""


class SessionContextError(AntiAmnesiaError):
    """The session-context binding, package or acknowledgement is invalid."""


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


def _load_json_file(path: Path, label: str, *, max_bytes: int = MAX_CONTEXT_BYTES) -> Tuple[bytes, str, Any]:
    payload = cold_start.stable_read_bytes(path, label=label, max_bytes=max_bytes)
    return payload, sha256_bytes(payload), strict_json_loads(payload, label)


def _load_base_challenge(
    challenge_path: Path,
    *,
    expected_sha256: str,
) -> Tuple[Dict[str, Any], bytes, str, Dict[str, Any], bytes, str]:
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
    return dict(row), challenge_payload, challenge_sha, capsule, capsule_payload, capsule_sha


def _load_operational_context(path: Path) -> Tuple[Dict[str, Any], bytes, str]:
    payload, file_sha, parsed = _load_json_file(
        Path(path), "session_context.operational_context"
    )
    try:
        context = validate_context_pack_structure(parsed)
    except OperationalContextError as exc:
        raise SessionContextError(str(exc)) from exc
    return context, payload, file_sha


def _verify_context_matches_capsule(
    context: Mapping[str, Any],
    capsule: Mapping[str, Any],
    capsule_sha256: str,
) -> None:
    session = context["session_binding"]
    mismatches = []
    checks = {
        "session_capsule_sha256": (session["session_capsule_sha256"], capsule_sha256),
        "challenge_id": (session["challenge_id"], capsule["challenge_id"]),
        "current_pointer_sha256": (
            session["current_pointer_sha256"],
            capsule["current_pointer_sha256"],
        ),
        "workspace_context_digest": (
            session["workspace_context_digest"],
            capsule["workspace_context_digest"],
        ),
        "authority_generation": (
            context["authority_generation"],
            capsule["authority_generation"],
        ),
        "role": (context["role"], capsule["role"]),
        "active_case": (context["active_case"], capsule["active_case"]),
        "work_order_id": (context["work_order_id"], capsule["work_order_id"]),
    }
    for field, (observed, expected) in checks.items():
        if observed != expected:
            mismatches.append(field)
    if mismatches:
        raise SessionContextError(
            f"operational_context:SESSION_BINDING_MISMATCH:{','.join(sorted(mismatches))}"
        )
    if context["ceilings"] != _CEILINGS:
        raise SessionContextError("operational_context:CEILING_VIOLATION")


def _binding_body(
    *,
    base_challenge: Mapping[str, Any],
    base_challenge_sha256: str,
    capsule: Mapping[str, Any],
    capsule_sha256: str,
    context: Mapping[str, Any],
    context_file_sha256: str,
) -> Dict[str, Any]:
    memory = context["memory_binding"]
    checkpoint = memory["checkpoint"]
    return {
        "schema": SCHEMA_BINDING,
        "gate": GATE,
        "mode": MODE,
        "authority_generation": AUTHORITY_GENERATION,
        "base_challenge": {
            "challenge_id": base_challenge["challenge_id"],
            "sha256": base_challenge_sha256,
        },
        "session": {
            "role": capsule["role"],
            "active_case": capsule["active_case"],
            "work_order_id": capsule["work_order_id"],
        },
        "session_capsule": {
            "sha256": capsule_sha256,
        },
        "operational_context": {
            "schema": OPERATIONAL_CONTEXT_SCHEMA,
            "file_sha256": context_file_sha256,
            "context_sha256": context["context_sha256"],
            "checkpoint_id": checkpoint["checkpoint_id"],
            "checkpoint_hash": checkpoint["checkpoint_hash"],
            "event_cursor": memory["context_event_cursor"],
            "event_chain_head": memory["context_event_chain_head"],
            "projection_sha256": memory["context_projection_sha256"],
            "selection_spec_sha256": context["selection"]["spec_sha256"],
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

    session = _exact_keys(
        row["session"],
        {"role", "active_case", "work_order_id"},
        "session_context_binding.session",
    )
    _nonempty(session["role"], "session_context_binding.session.role", max_length=128)
    if session["active_case"] is not None:
        _nonempty(
            session["active_case"],
            "session_context_binding.session.active_case",
            max_length=192,
        )
    _nonempty(
        session["work_order_id"],
        "session_context_binding.session.work_order_id",
        max_length=192,
    )

    capsule = _exact_keys(
        row["session_capsule"],
        {"sha256"},
        "session_context_binding.session_capsule",
    )
    _sha(capsule["sha256"], "session_context_binding.session_capsule.sha256")

    context = _exact_keys(
        row["operational_context"],
        {
            "schema",
            "file_sha256",
            "context_sha256",
            "checkpoint_id",
            "checkpoint_hash",
            "event_cursor",
            "event_chain_head",
            "projection_sha256",
            "selection_spec_sha256",
        },
        "session_context_binding.operational_context",
    )
    if context["schema"] != OPERATIONAL_CONTEXT_SCHEMA:
        raise SessionContextError("session_context_binding.operational_context.schema:UNSUPPORTED")
    for field in (
        "file_sha256",
        "context_sha256",
        "checkpoint_hash",
        "projection_sha256",
        "selection_spec_sha256",
    ):
        _sha(context[field], f"session_context_binding.operational_context.{field}")
    _nonempty(
        context["checkpoint_id"],
        "session_context_binding.operational_context.checkpoint_id",
        max_length=192,
    )
    if isinstance(context["event_cursor"], bool) or not isinstance(context["event_cursor"], int) or context["event_cursor"] < 0:
        raise SessionContextError("session_context_binding.operational_context.event_cursor:INVALID")
    if context["event_chain_head"] is not None:
        _sha(
            context["event_chain_head"],
            "session_context_binding.operational_context.event_chain_head",
        )
    if row["ceilings"] != _CEILINGS:
        raise SessionContextError("session_context_binding.ceilings:VIOLATION")

    body = dict(row)
    body.pop("binding_id")
    expected = sha256_bytes(canonical_json_bytes(body))
    if binding_id != expected:
        raise SessionContextError("session_context_binding.binding_id:MISMATCH")
    return dict(row)


def _expected_ack(binding: Mapping[str, Any]) -> Dict[str, Any]:
    context = binding["operational_context"]
    return {
        "schema": SCHEMA_ACK,
        "binding_id": binding["binding_id"],
        "challenge_id": binding["base_challenge"]["challenge_id"],
        "authority_generation": AUTHORITY_GENERATION,
        "role": binding["session"]["role"],
        "active_case": binding["session"]["active_case"],
        "work_order_id": binding["session"]["work_order_id"],
        "session_capsule_sha256": binding["session_capsule"]["sha256"],
        "operational_context_file_sha256": context["file_sha256"],
        "operational_context_sha256": context["context_sha256"],
        "checkpoint_id": context["checkpoint_id"],
        "checkpoint_hash": context["checkpoint_hash"],
        "context_event_cursor": context["event_cursor"],
        "context_projection_sha256": context["projection_sha256"],
        "selection_spec_sha256": context["selection_spec_sha256"],
        **dict(_CEILINGS),
    }


def validate_session_context_ack(value: Any) -> Dict[str, Any]:
    row = _exact_keys(value, _ACK_KEYS, "session_context_ack")
    if row["schema"] != SCHEMA_ACK:
        raise SessionContextError("session_context_ack.schema:UNSUPPORTED")
    for field in (
        "binding_id",
        "challenge_id",
        "session_capsule_sha256",
        "operational_context_file_sha256",
        "operational_context_sha256",
        "checkpoint_hash",
        "context_projection_sha256",
        "selection_spec_sha256",
    ):
        _sha(row[field], f"session_context_ack.{field}")
    if row["authority_generation"] != AUTHORITY_GENERATION:
        raise SessionContextError("session_context_ack.authority_generation:NOT_R63")
    _nonempty(row["role"], "session_context_ack.role", max_length=128)
    if row["active_case"] is not None:
        _nonempty(row["active_case"], "session_context_ack.active_case", max_length=192)
    _nonempty(row["work_order_id"], "session_context_ack.work_order_id", max_length=192)
    _nonempty(row["checkpoint_id"], "session_context_ack.checkpoint_id", max_length=192)
    if isinstance(row["context_event_cursor"], bool) or not isinstance(
        row["context_event_cursor"], int
    ) or row["context_event_cursor"] < 0:
        raise SessionContextError("session_context_ack.context_event_cursor:INVALID")
    observed_ceilings = {key: row[key] for key in _CEILINGS}
    if observed_ceilings != _CEILINGS:
        raise SessionContextError("session_context_ack.ceilings:VIOLATION")
    return dict(row)


def _schema_bytes() -> bytes:
    return resource_files("continuityos.gate.schemas").joinpath(
        "anti_amnesia_session_context_ack_v1.schema.json"
    ).read_bytes()


def prepare_session_context_binding(
    base_challenge_path: Path,
    context_path: Path,
    output_dir: Path,
    *,
    expected_base_challenge_sha256: str,
) -> Dict[str, Any]:
    (
        base_challenge,
        _base_payload,
        base_sha,
        capsule,
        capsule_payload,
        capsule_sha,
    ) = _load_base_challenge(
        Path(base_challenge_path),
        expected_sha256=expected_base_challenge_sha256,
    )
    context, context_payload, context_file_sha = _load_operational_context(Path(context_path))
    _verify_context_matches_capsule(context, capsule, capsule_sha)

    body = _binding_body(
        base_challenge=base_challenge,
        base_challenge_sha256=base_sha,
        capsule=capsule,
        capsule_sha256=capsule_sha,
        context=context,
        context_file_sha256=context_file_sha,
    )
    binding_id = sha256_bytes(canonical_json_bytes(body))
    binding = validate_session_context_binding({**body, "binding_id": binding_id})
    binding_payload = canonical_json_bytes(binding)
    expected = validate_session_context_ack(_expected_ack(binding))
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
        "candidate_session_capsule": {
            "path": "candidate/SESSION_CAPSULE.json",
            "sha256": capsule_sha,
        },
        "candidate_operational_context": {
            "path": "candidate/OPERATIONAL_CONTEXT.json",
            "sha256": context_file_sha,
            "context_sha256": context["context_sha256"],
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

    try:
        target, temp_root = cold_start._prepare_atomic_output(Path(output_dir))
    except cold_start.ColdStartError as exc:
        raise SessionContextError(str(exc)) from exc
    try:
        (temp_root / "candidate").mkdir()
        (temp_root / "controller").mkdir()
        cold_start._write_new(
            temp_root / "controller" / "BASE_COLD_START_CHALLENGE.json",
            _base_payload,
        )
        cold_start._write_new(
            temp_root / "candidate" / "SESSION_CAPSULE.json", capsule_payload
        )
        cold_start._write_new(
            temp_root / "candidate" / "OPERATIONAL_CONTEXT.json", context_payload
        )
        cold_start._write_new(
            temp_root / "candidate" / "SESSION_CONTEXT_BINDING.json", binding_payload
        )
        cold_start._write_new(
            temp_root / "candidate" / "SESSION_CONTEXT_ACK.schema.json", schema_payload
        )
        cold_start._write_new(
            temp_root / "candidate" / "INSTRUCTIONS.md", instructions_payload
        )
        cold_start._write_new(
            temp_root / "controller" / "EXPECTED_SESSION_CONTEXT_ACK.json",
            expected_payload,
        )
        cold_start._write_new(
            temp_root / "SESSION_CONTEXT_CHALLENGE.json", challenge_payload
        )
        paths = [
            "SESSION_CONTEXT_CHALLENGE.json",
            "controller/BASE_COLD_START_CHALLENGE.json",
            "candidate/SESSION_CAPSULE.json",
            "candidate/OPERATIONAL_CONTEXT.json",
            "candidate/SESSION_CONTEXT_BINDING.json",
            "candidate/SESSION_CONTEXT_ACK.schema.json",
            "candidate/INSTRUCTIONS.md",
            "controller/EXPECTED_SESSION_CONTEXT_ACK.json",
        ]
        hashes = {
            "SESSION_CONTEXT_CHALLENGE.json": sha256_bytes(challenge_payload),
            "controller/BASE_COLD_START_CHALLENGE.json": base_sha,
            "candidate/SESSION_CAPSULE.json": capsule_sha,
            "candidate/OPERATIONAL_CONTEXT.json": context_file_sha,
            "candidate/SESSION_CONTEXT_BINDING.json": sha256_bytes(binding_payload),
            "candidate/SESSION_CONTEXT_ACK.schema.json": sha256_bytes(schema_payload),
            "candidate/INSTRUCTIONS.md": sha256_bytes(instructions_payload),
            "controller/EXPECTED_SESSION_CONTEXT_ACK.json": sha256_bytes(expected_payload),
        }
        sums = "".join(f"{hashes[path]}  {path}\n" for path in paths).encode("utf-8")
        cold_start._write_new(temp_root / "SHA256SUMS.txt", sums)
        cold_start._fsync_directory(temp_root / "candidate")
        cold_start._fsync_directory(temp_root / "controller")
        cold_start._fsync_directory(temp_root)
        os.replace(temp_root, target)
        cold_start._fsync_directory(target.parent)
    except Exception:
        shutil.rmtree(temp_root, ignore_errors=True)
        raise

    writes = [
        "SESSION_CONTEXT_CHALLENGE.json",
        "controller/BASE_COLD_START_CHALLENGE.json",
        "candidate/SESSION_CAPSULE.json",
        "candidate/OPERATIONAL_CONTEXT.json",
        "candidate/SESSION_CONTEXT_BINDING.json",
        "candidate/SESSION_CONTEXT_ACK.schema.json",
        "candidate/INSTRUCTIONS.md",
        "controller/EXPECTED_SESSION_CONTEXT_ACK.json",
        "SHA256SUMS.txt",
    ]
    return {
        "schema": SCHEMA_PREPARE_RECEIPT,
        "binding_id": binding_id,
        "output_dir": str(target.resolve()),
        "base_challenge_sha256": base_sha,
        "binding_sha256": sha256_bytes(binding_payload),
        "operational_context_file_sha256": context_file_sha,
        "operational_context_sha256": context["context_sha256"],
        "challenge_sha256": sha256_bytes(challenge_payload),
        "expected_ack_sha256": sha256_bytes(expected_payload),
        "checkpoint_id": binding["operational_context"]["checkpoint_id"],
        "status": "SESSION_CONTEXT_CHALLENGE_READY",
        "live_state_modified": False,
        "writes_performed": writes,
        "can_trade": False,
        "capital_permission": "DENY",
    }


def _load_bound_challenge(
    challenge_path: Path,
    *,
    expected_sha256: str,
) -> Tuple[Dict[str, Any], str, Path]:
    _sha(expected_sha256, "session_context_challenge.expected_sha256")
    payload, actual_sha, parsed = _load_json_file(
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
) -> Tuple[Path, bytes, str, Any]:
    path = cold_start._safe_challenge_relative(root, descriptor["path"], f"{label}.path")
    payload, actual_sha, parsed = _load_json_file(path, label)
    if actual_sha != descriptor["sha256"]:
        raise SessionContextError(f"{label}:SHA256_MISMATCH")
    return path, payload, actual_sha, parsed



def _read_raw_descriptor_file(
    root: Path,
    descriptor: Mapping[str, Any],
    label: str,
) -> Tuple[Path, bytes, str]:
    path = cold_start._safe_challenge_relative(root, descriptor["path"], f"{label}.path")
    payload = cold_start.stable_read_bytes(
        path,
        label=label,
        max_bytes=MAX_CONTEXT_BYTES,
    )
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
    binding_desc = _descriptor(
        challenge["binding_manifest"], "session_context_challenge.binding_manifest"
    )
    capsule_desc = _descriptor(
        challenge["candidate_session_capsule"],
        "session_context_challenge.candidate_session_capsule",
    )
    context_desc = _descriptor(
        challenge["candidate_operational_context"],
        "session_context_challenge.candidate_operational_context",
        extra={"context_sha256"},
    )
    expected_desc = _descriptor(
        challenge["controller_expected_ack"],
        "session_context_challenge.controller_expected_ack",
    )
    base_desc = _descriptor(
        challenge["base_challenge"],
        "session_context_challenge.base_challenge",
    )
    schema_desc = _descriptor(
        challenge["candidate_ack_schema"],
        "session_context_challenge.candidate_ack_schema",
    )
    instructions_desc = _descriptor(
        challenge["candidate_instructions"],
        "session_context_challenge.candidate_instructions",
    )
    _sha(
        context_desc["context_sha256"],
        "session_context_challenge.candidate_operational_context.context_sha256",
    )

    _base_path, _base_payload, base_file_sha = _read_raw_descriptor_file(
        root, base_desc, "session_context.base_challenge"
    )
    base_parsed = strict_json_loads(_base_payload, "session_context.base_challenge")
    base_row = _exact_keys(
        base_parsed,
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
        "session_context.base_challenge",
    )
    if (
        base_row["schema"] != cold_start.SCHEMA_CHALLENGE
        or base_row["gate"] != GATE
        or base_row["mode"] != MODE
        or base_row["authority_generation"] != AUTHORITY_GENERATION
    ):
        raise SessionContextError("session_context.base_challenge:UNSUPPORTED_IDENTITY")
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

    _binding_path, _binding_payload, _binding_sha, binding_parsed = _read_descriptor_file(
        root, binding_desc, "session_context.binding_manifest"
    )
    binding = validate_session_context_binding(binding_parsed)
    if binding["binding_id"] != challenge["binding_id"]:
        raise SessionContextError("session_context_challenge:BINDING_ID_MISMATCH")
    if binding["base_challenge"]["sha256"] != base_file_sha:
        raise SessionContextError("session_context_challenge:BASE_CHALLENGE_BINDING_MISMATCH")
    if binding["base_challenge"]["challenge_id"] != base_row["challenge_id"]:
        raise SessionContextError("session_context_challenge:BASE_CHALLENGE_ID_MISMATCH")

    _capsule_path, capsule_payload, capsule_sha, capsule_parsed = _read_descriptor_file(
        root, capsule_desc, "session_context.session_capsule"
    )
    try:
        capsule = validate_session_capsule(capsule_parsed)
    except OperationalContextError as exc:
        raise SessionContextError(str(exc)) from exc
    _context_path, context_payload, context_file_sha, context_parsed = _read_descriptor_file(
        root, context_desc, "session_context.operational_context"
    )
    try:
        context = validate_context_pack_structure(context_parsed)
    except OperationalContextError as exc:
        raise SessionContextError(str(exc)) from exc
    _verify_context_matches_capsule(context, capsule, capsule_sha)
    if context["context_sha256"] != context_desc["context_sha256"]:
        raise SessionContextError("session_context_challenge:CONTEXT_SHA256_MISMATCH")

    reconstructed_body = _binding_body(
        base_challenge={"challenge_id": binding["base_challenge"]["challenge_id"]},
        base_challenge_sha256=binding["base_challenge"]["sha256"],
        capsule=capsule,
        capsule_sha256=capsule_sha,
        context=context,
        context_file_sha256=context_file_sha,
    )
    reconstructed = validate_session_context_binding(
        {**reconstructed_body, "binding_id": sha256_bytes(canonical_json_bytes(reconstructed_body))}
    )
    if reconstructed != binding:
        raise SessionContextError("session_context_binding:ARTIFACT_RELATION_MISMATCH")

    _expected_path, _expected_payload, _expected_sha, expected_parsed = _read_descriptor_file(
        root, expected_desc, "session_context.expected_ack"
    )
    expected = validate_session_context_ack(expected_parsed)
    if expected != _expected_ack(binding):
        raise SessionContextError("session_context.expected_ack:DOES_NOT_MATCH_BINDING")

    ack_payload, ack_sha, ack_parsed = _load_json_file(
        Path(ack_path), "session_context.ack"
    )
    try:
        ack = validate_session_context_ack(ack_parsed)
    except SessionContextError as exc:
        return {
            "schema": SCHEMA_VERDICT,
            "binding_id": challenge["binding_id"],
            "challenge_sha256": challenge_sha,
            "ack_sha256": ack_sha,
            "checks": [
                {"check_id": "ack.schema", "status": "FAIL", "code": str(exc)}
            ],
            "mismatches": [
                {
                    "path": "/",
                    "expected": "schema-valid exact SESSION_CONTEXT_ACK",
                    "observed": str(exc),
                }
            ],
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
            checks.append(
                {"check_id": f"ack.{field}", "status": "PASS", "code": "EXACT_MATCH"}
            )
        else:
            checks.append(
                {"check_id": f"ack.{field}", "status": "FAIL", "code": "MISMATCH"}
            )
            mismatches.append(
                {
                    "path": f"/{field}",
                    "expected": expected.get(field),
                    "observed": ack.get(field),
                }
            )
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
