"""Current-authority read-only cold-start for ContinuityOS.

This protocol is deliberately separate from the historical R63 ANTI_AMNESIA
cold-start. It binds a fresh-session capsule to one exact ACTIVE current pointer,
the three stable roots named by that pointer, one resolved operational-state
bundle, and one controller-authored read-only session spec.

It never mutates canonical state, deploys, dispatches agents, trades, grants
capital permission, writes a repository, or activates memory. The only writes
performed by ``prepare`` are a new caller-selected challenge directory.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
from typing import Any, Iterable, Mapping
import uuid

from .gate.anti_amnesia import canonical_json_bytes, sha256_bytes, stable_read_bytes, strict_json_loads
from .gate.state_resolution import canonical_json_text, resolve_state

SCHEMA_SPEC = "CONTINUITYOS_CURRENT_COLD_START_SPEC_V1"
SCHEMA_CAPSULE = "CONTINUITYOS_CURRENT_SESSION_CAPSULE_V1"
SCHEMA_ACK = "CONTINUITYOS_CURRENT_BOOT_ACK_V1"
SCHEMA_CHALLENGE = "CONTINUITYOS_CURRENT_COLD_START_CHALLENGE_V1"
SCHEMA_VERDICT = "CONTINUITYOS_CURRENT_COLD_START_VERDICT_V1"
SCHEMA_PREPARE_RECEIPT = "CONTINUITYOS_CURRENT_COLD_START_PREPARE_RECEIPT_V1"
BUNDLE_SCHEMA = "continuityos.state_resolution.bundle/v1"

MAX_INPUT_BYTES = 4 * 1024 * 1024
MAX_CANDIDATES = 4096
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
GENERATION_RE = re.compile(r"^R[1-9][0-9]*$")
GIT_OBJECT_RE = re.compile(r"^[0-9a-f]{40,64}$")
IDENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,191}$")
OPERATIONALLY_ACCEPTED = {"PASS", "PASS_WITH_CONDITIONS"}

_CORE_EFFECTS = {
    "auto_accept": False,
    "auto_dispatch": False,
    "can_trade": False,
    "capital_permission": "DENY",
    "deploy": "DENY",
    "self_application": False,
}


class CurrentColdStartError(ValueError):
    """Current-authority cold-start input or package is invalid."""


def _effects() -> dict[str, Any]:
    return {
        "force_push": False,
        "merge": False,
        "pull_request_merge": False,
        "auto_merge": False,
        "deployment": False,
        "registry_apply": False,
        "current_state_apply": False,
        "canonical_mutation": False,
        "trading": False,
        "wallet_access": False,
        "order_execution": False,
        "external_message": False,
        "self_application": False,
        "auto_dispatch": False,
        "can_trade": False,
        "capital_permission": "DENY",
        "deploy_permission": "DENY",
    }


def _exact_keys(value: Any, keys: Iterable[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise CurrentColdStartError(f"{label}:NOT_OBJECT")
    expected = set(keys)
    actual = set(value)
    if actual != expected:
        raise CurrentColdStartError(
            f"{label}:KEYS:missing={sorted(expected-actual)}:extra={sorted(actual-expected)}"
        )
    return value


def _mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise CurrentColdStartError(f"{label}:NOT_OBJECT")
    return value


def _nonempty(value: Any, label: str, *, max_length: int = 4096) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > max_length:
        raise CurrentColdStartError(f"{label}:INVALID_STRING")
    return value


def _sha(value: Any, label: str) -> str:
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        raise CurrentColdStartError(f"{label}:INVALID_SHA256")
    return value


def _string_list(value: Any, label: str) -> list[str]:
    if not isinstance(value, list):
        raise CurrentColdStartError(f"{label}:INVALID_LIST")
    out: list[str] = []
    for i, item in enumerate(value):
        out.append(_nonempty(item, f"{label}[{i}]", max_length=2048))
    if len(out) != len(set(out)):
        raise CurrentColdStartError(f"{label}:DUPLICATE_ITEMS")
    return out


def _read_bytes_with_sha(path: Path, label: str) -> tuple[bytes, str]:
    payload = stable_read_bytes(
        Path(path),
        label=label,
        max_bytes=MAX_INPUT_BYTES,
    )
    return payload, sha256_bytes(payload)


def _read_json_with_sha(path: Path, label: str) -> tuple[Any, str]:
    payload, payload_sha = _read_bytes_with_sha(path, label)
    try:
        value = strict_json_loads(payload, label)
    except Exception as exc:
        raise CurrentColdStartError(
            f"{label}:INVALID_JSON:{type(exc).__name__}:{exc}"
        ) from exc
    return value, payload_sha


def _load_bundle(path: Path) -> tuple[list[dict[str, Any]], str]:
    value, payload_sha = _read_json_with_sha(path, "current.state_bundle")
    row = _exact_keys(value, {"schema", "candidates"}, "current.state_bundle")
    if row["schema"] != BUNDLE_SCHEMA:
        raise CurrentColdStartError("current.state_bundle:SCHEMA_UNSUPPORTED")
    candidates = row["candidates"]
    if not isinstance(candidates, list):
        raise CurrentColdStartError("current.state_bundle.candidates:INVALID_LIST")
    if len(candidates) > MAX_CANDIDATES:
        raise CurrentColdStartError("current.state_bundle.candidates:TOO_MANY")
    return candidates, payload_sha


def _validate_pointer(
    value: Any,
    *,
    actual_sha256: str,
    expected_sha256: str,
) -> dict[str, Any]:
    if actual_sha256 != _sha(expected_sha256, "current.pointer.expected_sha256"):
        raise CurrentColdStartError("current.pointer:SHA256_MISMATCH")
    row = _mapping(value, "current.pointer")
    generation = _nonempty(row.get("generation"), "current.pointer.generation", max_length=32)
    if not GENERATION_RE.fullmatch(generation):
        raise CurrentColdStartError("current.pointer.generation:INVALID")
    if row.get("schema") != f"CONTROL_CURRENT_POINTER_{generation}":
        raise CurrentColdStartError("current.pointer.schema:GENERATION_MISMATCH")

    activation = _mapping(row.get("canonical_activation"), "current.pointer.canonical_activation")
    if activation.get("status") != "ACTIVE":
        raise CurrentColdStartError("current.pointer.canonical_activation:NOT_ACTIVE")
    if activation.get("generation") != generation:
        raise CurrentColdStartError("current.pointer.canonical_activation:GENERATION_MISMATCH")
    decision = _nonempty(
        activation.get("decision"),
        "current.pointer.canonical_activation.decision",
        max_length=255,
    )
    manifest_sha = _sha(
        activation.get("accepted_manifest_sha256"),
        "current.pointer.canonical_activation.accepted_manifest_sha256",
    )
    sovereign = _nonempty(
        activation.get("human_sovereign"),
        "current.pointer.canonical_activation.human_sovereign",
        max_length=128,
    )
    provider = _mapping(
        activation.get("stable_root_provider_readback"),
        "current.pointer.canonical_activation.stable_root_provider_readback",
    )
    if provider.get("all_exact") is not True:
        raise CurrentColdStartError("current.pointer.provider_readback:NOT_EXACT")

    manifest = _mapping(row.get("manifest"), "current.pointer.manifest")
    if _sha(manifest.get("sha256"), "current.pointer.manifest.sha256") != manifest_sha:
        raise CurrentColdStartError("current.pointer.manifest:ACTIVATION_SHA_MISMATCH")

    effect = _mapping(row.get("effect_ceiling"), "current.pointer.effect_ceiling")
    for key, expected in _CORE_EFFECTS.items():
        if effect.get(key) != expected:
            raise CurrentColdStartError(f"current.pointer.effect_ceiling.{key}:UNSAFE")
    if effect.get("NO_FURTHER_AGENT_WORK") is not True:
        raise CurrentColdStartError("current.pointer.effect_ceiling.NO_FURTHER_AGENT_WORK:EXPECTED_TRUE")

    root_bindings: dict[str, str] = {}
    for key in ("current_state", "role_index", "role_views"):
        desc = _mapping(row.get(key), f"current.pointer.{key}")
        root_bindings[key] = _sha(desc.get("sha256"), f"current.pointer.{key}.sha256")

    return {
        "generation": generation,
        "schema": row["schema"],
        "pointer_sha256": actual_sha256,
        "accepted_manifest_sha256": manifest_sha,
        "activation_decision": decision,
        "activation_status": "ACTIVE",
        "human_sovereign": sovereign,
        "published_at_utc": _nonempty(
            row.get("published_at_utc"), "current.pointer.published_at_utc", max_length=128
        ),
        "root_bindings": root_bindings,
        "effect_ceiling": dict(effect),
    }


def _validate_stable_roots(
    pointer: Mapping[str, Any],
    current_state_value: Any,
    current_state_sha: str,
    role_index_value: Any,
    role_index_sha: str,
    role_views_value: Any,
    role_views_sha: str,
) -> dict[str, Any]:
    generation = pointer["generation"]
    expected = pointer["root_bindings"]
    observed = {
        "current_state": current_state_sha,
        "role_index": role_index_sha,
        "role_views": role_views_sha,
    }
    for key, sha_value in observed.items():
        if sha_value != expected[key]:
            raise CurrentColdStartError(f"current.{key}:POINTER_SHA_MISMATCH")

    current_state = _mapping(current_state_value, "current.current_state")
    role_index = _mapping(role_index_value, "current.role_index")
    role_views = _mapping(role_views_value, "current.role_views")

    if current_state.get("schema") != f"CONTROL_CURRENT_STATE_{generation}":
        raise CurrentColdStartError("current.current_state.schema:GENERATION_MISMATCH")
    if role_index.get("schema") != f"CONTROL_ROLE_INDEX_{generation}":
        raise CurrentColdStartError("current.role_index.schema:GENERATION_MISMATCH")
    if role_views.get("schema") != f"CONTROL_ROLE_VIEWS_{generation}":
        raise CurrentColdStartError("current.role_views.schema:GENERATION_MISMATCH")
    for label, row in (
        ("current_state", current_state),
        ("role_index", role_index),
        ("role_views", role_views),
    ):
        if row.get("generation") != generation:
            raise CurrentColdStartError(f"current.{label}.generation:MISMATCH")

    pointer_effect = pointer["effect_ceiling"]
    for label, effect in (
        ("current_state", _mapping(current_state.get("global_effect_ceiling"), "current.current_state.global_effect_ceiling")),
        ("role_views", _mapping(role_views.get("global_effect_ceiling"), "current.role_views.global_effect_ceiling")),
    ):
        for key, expected_value in _CORE_EFFECTS.items():
            if effect.get(key) != expected_value or effect.get(key) != pointer_effect.get(key):
                raise CurrentColdStartError(f"current.{label}.global_effect_ceiling.{key}:MISMATCH")
        if effect.get("NO_FURTHER_AGENT_WORK") is not True:
            raise CurrentColdStartError(f"current.{label}.global_effect_ceiling.NO_FURTHER_AGENT_WORK:MISMATCH")

    roles_index = _mapping(role_index.get("role_views"), "current.role_index.role_views")
    roles = _mapping(role_views.get("roles"), "current.role_views.roles")
    return {
        "current_state": current_state,
        "role_index": role_index,
        "role_views": role_views,
        "roles_index": roles_index,
        "roles": roles,
        "sha256": observed,
    }


def _validate_git_baseline(value: Any) -> dict[str, str]:
    row = _exact_keys(value, {"repository", "branch", "head", "tree"}, "current.spec.git_baseline")
    repository = _nonempty(row["repository"], "current.spec.git_baseline.repository")
    branch = _nonempty(row["branch"], "current.spec.git_baseline.branch", max_length=255)
    head = row["head"]
    tree = row["tree"]
    if not isinstance(head, str) or not GIT_OBJECT_RE.fullmatch(head):
        raise CurrentColdStartError("current.spec.git_baseline.head:INVALID")
    if not isinstance(tree, str) or not GIT_OBJECT_RE.fullmatch(tree):
        raise CurrentColdStartError("current.spec.git_baseline.tree:INVALID")
    return {"repository": repository, "branch": branch, "head": head, "tree": tree}


def _validate_spec(
    value: Any,
    *,
    pointer: Mapping[str, Any],
    roles_index: Mapping[str, Any],
    roles: Mapping[str, Any],
    resolution: Mapping[str, Any],
) -> dict[str, Any]:
    keys = {
        "schema",
        "authority_generation",
        "authority_pointer_sha256",
        "required_state_subject",
        "session_id",
        "work_order_id",
        "role",
        "case_id",
        "goal",
        "accepted_decisions",
        "rejected_alternatives",
        "immutable_decisions",
        "git_baseline",
        "next_action",
        "terminal_condition",
        "effect_ceiling",
        "may_dispatch_codex",
        "can_trade",
        "capital_permission",
        "deploy_permission",
    }
    row = _exact_keys(value, keys, "current.spec")
    if row["schema"] != SCHEMA_SPEC:
        raise CurrentColdStartError("current.spec.schema:UNSUPPORTED")
    if row["authority_generation"] != pointer["generation"]:
        raise CurrentColdStartError("current.spec.authority_generation:MISMATCH")
    if row["authority_pointer_sha256"] != pointer["pointer_sha256"]:
        raise CurrentColdStartError("current.spec.authority_pointer_sha256:MISMATCH")

    required_subject = _nonempty(
        row["required_state_subject"], "current.spec.required_state_subject", max_length=255
    )
    if resolution.get("subject") != required_subject:
        raise CurrentColdStartError("current.spec.required_state_subject:MISMATCH")

    session_id = _nonempty(row["session_id"], "current.spec.session_id", max_length=192)
    if not IDENT_RE.fullmatch(session_id):
        raise CurrentColdStartError("current.spec.session_id:INVALID")
    work_order_id = row["work_order_id"]
    if work_order_id is not None:
        work_order_id = _nonempty(work_order_id, "current.spec.work_order_id", max_length=192)
        if not IDENT_RE.fullmatch(work_order_id):
            raise CurrentColdStartError("current.spec.work_order_id:INVALID")

    role = _nonempty(row["role"], "current.spec.role", max_length=128)
    if role not in roles_index or role not in roles:
        raise CurrentColdStartError("current.spec.role:NOT_IN_R64_ROOTS")
    role_desc = _mapping(roles_index[role], f"current.role_index.role_views.{role}")
    if role_desc.get("path") != "ROLE_VIEWS.json":
        raise CurrentColdStartError("current.spec.role:ROLE_VIEW_PATH_MISMATCH")

    case_id = row["case_id"]
    if case_id is not None:
        case_id = _nonempty(case_id, "current.spec.case_id", max_length=192)
        if not IDENT_RE.fullmatch(case_id):
            raise CurrentColdStartError("current.spec.case_id:INVALID")

    if row["effect_ceiling"] != "READ_ONLY":
        raise CurrentColdStartError("current.spec.effect_ceiling:MUST_BE_READ_ONLY")
    if row["may_dispatch_codex"] is not False:
        raise CurrentColdStartError("current.spec.may_dispatch_codex:MUST_BE_FALSE")
    if row["can_trade"] is not False:
        raise CurrentColdStartError("current.spec.can_trade:MUST_BE_FALSE")
    if row["capital_permission"] != "DENY":
        raise CurrentColdStartError("current.spec.capital_permission:MUST_BE_DENY")
    if row["deploy_permission"] != "DENY":
        raise CurrentColdStartError("current.spec.deploy_permission:MUST_BE_DENY")

    return {
        "schema": SCHEMA_SPEC,
        "authority_generation": pointer["generation"],
        "authority_pointer_sha256": pointer["pointer_sha256"],
        "required_state_subject": required_subject,
        "session_id": session_id,
        "work_order_id": work_order_id,
        "role": role,
        "case_id": case_id,
        "goal": _nonempty(row["goal"], "current.spec.goal"),
        "accepted_decisions": _string_list(row["accepted_decisions"], "current.spec.accepted_decisions"),
        "rejected_alternatives": _string_list(row["rejected_alternatives"], "current.spec.rejected_alternatives"),
        "immutable_decisions": _string_list(row["immutable_decisions"], "current.spec.immutable_decisions"),
        "git_baseline": _validate_git_baseline(row["git_baseline"]),
        "next_action": _nonempty(row["next_action"], "current.spec.next_action"),
        "terminal_condition": _nonempty(row["terminal_condition"], "current.spec.terminal_condition"),
        "effect_ceiling": "READ_ONLY",
        "may_dispatch_codex": False,
        "can_trade": False,
        "capital_permission": "DENY",
        "deploy_permission": "DENY",
    }


def _prepare_atomic_output(path: Path) -> tuple[Path, Path]:
    target = Path(path).expanduser().absolute()
    if target.exists():
        raise CurrentColdStartError("current.output:TARGET_ALREADY_EXISTS")
    target.parent.mkdir(parents=True, exist_ok=True)
    temp = target.with_name(f".{target.name}.current-tmp-{os.getpid()}-{uuid.uuid4().hex}")
    temp.mkdir(mode=0o700, exist_ok=False)
    return target, temp


def _write_new(path: Path, payload: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    fd = os.open(path, flags, 0o600)
    try:
        view = memoryview(payload)
        offset = 0
        while offset < len(view):
            written = os.write(fd, view[offset:])
            if written <= 0:
                raise CurrentColdStartError(f"current.output:SHORT_WRITE:{path.name}")
            offset += written
        os.fsync(fd)
    finally:
        os.close(fd)


def _fsync_directory(path: Path) -> None:
    if os.name == "nt":
        return
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _safe_relative(root: Path, raw: Any, label: str) -> Path:
    if not isinstance(raw, str) or not raw or "\\" in raw:
        raise CurrentColdStartError(f"{label}:INVALID_RELATIVE_PATH")
    path = Path(raw)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise CurrentColdStartError(f"{label}:UNSAFE_RELATIVE_PATH")
    resolved_root = root.resolve()
    cursor = resolved_root
    for part in path.parts:
        cursor = cursor / part
        if cursor.exists():
            info = cursor.lstat()
            if stat.S_ISLNK(info.st_mode):
                raise CurrentColdStartError(f"{label}:SYMLINK_REFUSED")
            attrs = getattr(info, "st_file_attributes", 0)
            if attrs & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400):
                raise CurrentColdStartError(f"{label}:REPARSE_REFUSED")
    resolved = (resolved_root / path).resolve()
    try:
        resolved.relative_to(resolved_root)
    except ValueError as exc:
        raise CurrentColdStartError(f"{label}:PATH_ESCAPES_CHALLENGE") from exc
    return resolved


def _expected_ack(capsule: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "schema": SCHEMA_ACK,
        "challenge_id": capsule["challenge_id"],
        "authority_generation": capsule["authority_generation"],
        "authority_pointer_sha256": capsule["authority_pointer_sha256"],
        "accepted_manifest_sha256": capsule["accepted_manifest_sha256"],
        "current_state_sha256": capsule["stable_roots"]["current_state"],
        "role_index_sha256": capsule["stable_roots"]["role_index"],
        "role_views_sha256": capsule["stable_roots"]["role_views"],
        "state_subject": capsule["state_subject"],
        "state_status": capsule["state_status"],
        "state_selected_artifact_id": capsule["state_selected_artifact_id"],
        "state_selected_artifact_sha256": capsule["state_selected_artifact_sha256"],
        "session_id": capsule["session_id"],
        "work_order_id": capsule["work_order_id"],
        "role": capsule["role"],
        "case_id": capsule["case_id"],
        "baseline_head": capsule["git_baseline"]["head"],
        "baseline_tree": capsule["git_baseline"]["tree"],
        "next_action": capsule["next_action"],
        "terminal_condition": capsule["terminal_condition"],
        "effect_ceiling": "READ_ONLY",
        "no_archive_access": True,
        "no_repo_writes": True,
        "may_dispatch_codex": False,
        "can_trade": False,
        "capital_permission": "DENY",
        "deploy_permission": "DENY",
    }


def prepare_current_cold_start(
    *,
    authority_pointer_path: Path,
    expected_authority_pointer_sha256: str,
    current_state_path: Path,
    role_index_path: Path,
    role_views_path: Path,
    state_bundle_path: Path,
    spec_path: Path,
    output_dir: Path,
) -> dict[str, Any]:
    pointer_value, pointer_sha = _read_json_with_sha(authority_pointer_path, "current.pointer")
    pointer = _validate_pointer(
        pointer_value,
        actual_sha256=pointer_sha,
        expected_sha256=expected_authority_pointer_sha256,
    )

    current_state_value, current_state_sha = _read_json_with_sha(
        current_state_path, "current.current_state"
    )
    role_index_value, role_index_sha = _read_json_with_sha(role_index_path, "current.role_index")
    role_views_value, role_views_sha = _read_json_with_sha(role_views_path, "current.role_views")
    roots = _validate_stable_roots(
        pointer,
        current_state_value,
        current_state_sha,
        role_index_value,
        role_index_sha,
        role_views_value,
        role_views_sha,
    )

    candidates, bundle_sha = _load_bundle(state_bundle_path)
    resolution = resolve_state(candidates)
    resolution_sha = hashlib.sha256(
        canonical_json_text(resolution).encode("utf-8")
    ).hexdigest()
    if resolution.get("terminal") != "STATE_RESOLUTION_PASS":
        return {
            "schema": SCHEMA_PREPARE_RECEIPT,
            "terminal": "CURRENT_COLD_START_HOLD",
            "reason": "STATE_RESOLUTION_NOT_PASS",
            "authority_generation": pointer["generation"],
            "authority_pointer_sha256": pointer_sha,
            "state_bundle_sha256": bundle_sha,
            "state_resolution_sha256": resolution_sha,
            "state_resolution": resolution,
            "writes_performed": [],
            "effects": _effects(),
        }
    if resolution.get("current_status") not in OPERATIONALLY_ACCEPTED:
        return {
            "schema": SCHEMA_PREPARE_RECEIPT,
            "terminal": "CURRENT_COLD_START_HOLD",
            "reason": "STATE_NOT_OPERATIONALLY_ACCEPTED",
            "authority_generation": pointer["generation"],
            "authority_pointer_sha256": pointer_sha,
            "state_bundle_sha256": bundle_sha,
            "state_resolution_sha256": resolution_sha,
            "state_resolution": resolution,
            "writes_performed": [],
            "effects": _effects(),
        }

    spec_value, spec_sha = _read_json_with_sha(spec_path, "current.spec")
    spec = _validate_spec(
        spec_value,
        pointer=pointer,
        roles_index=roots["roles_index"],
        roles=roots["roles"],
        resolution=resolution,
    )
    role_view = dict(_mapping(roots["roles"][spec["role"]], f"current.role_views.roles.{spec['role']}"))

    challenge_material = {
        "schema": SCHEMA_CHALLENGE,
        "authority_pointer_sha256": pointer_sha,
        "authority_generation": pointer["generation"],
        "accepted_manifest_sha256": pointer["accepted_manifest_sha256"],
        "current_state_sha256": current_state_sha,
        "role_index_sha256": role_index_sha,
        "role_views_sha256": role_views_sha,
        "state_bundle_sha256": bundle_sha,
        "state_resolution_sha256": resolution_sha,
        "spec_sha256": spec_sha,
        "session_id": spec["session_id"],
        "role": spec["role"],
    }
    challenge_id = sha256_bytes(canonical_json_bytes(challenge_material))
    capsule = {
        "schema": SCHEMA_CAPSULE,
        "challenge_id": challenge_id,
        "authority_generation": pointer["generation"],
        "authority_pointer_sha256": pointer_sha,
        "accepted_manifest_sha256": pointer["accepted_manifest_sha256"],
        "activation_decision": pointer["activation_decision"],
        "activation_status": pointer["activation_status"],
        "human_sovereign": pointer["human_sovereign"],
        "stable_roots": {
            "current_state": current_state_sha,
            "role_index": role_index_sha,
            "role_views": role_views_sha,
        },
        "compiled_current_state_marker": roots["current_state"].get("canonicality_activation"),
        "compiled_marker_interpretation": (
            "Historical compilation marker only; ACTIVE canonical_activation in the exact "
            "pointer controls canonicality while CURRENT_STATE bytes remain immutable."
        ),
        "state_bundle_sha256": bundle_sha,
        "state_resolution_sha256": resolution_sha,
        "state_subject": resolution["subject"],
        "state_status": resolution["current_status"],
        "state_selected_artifact_id": resolution["selected"]["artifact_id"],
        "state_selected_artifact_sha256": resolution["selected"]["artifact_sha256"],
        "state_evidence_debt": bool(resolution.get("evidence_debt", False)),
        "session_id": spec["session_id"],
        "work_order_id": spec["work_order_id"],
        "role": spec["role"],
        "role_view": role_view,
        "case_id": spec["case_id"],
        "goal": spec["goal"],
        "accepted_decisions": list(spec["accepted_decisions"]),
        "rejected_alternatives": list(spec["rejected_alternatives"]),
        "immutable_decisions": list(spec["immutable_decisions"]),
        "git_baseline": dict(spec["git_baseline"]),
        "next_action": spec["next_action"],
        "terminal_condition": spec["terminal_condition"],
        "effect_ceiling": "READ_ONLY",
        "no_external_context": True,
        "no_archive_access": True,
        "no_repo_writes": True,
        "may_dispatch_codex": False,
        "can_trade": False,
        "capital_permission": "DENY",
        "deploy_permission": "DENY",
    }
    expected = _expected_ack(capsule)
    capsule_payload = canonical_json_bytes(capsule)
    expected_payload = canonical_json_bytes(expected)
    challenge = {
        "schema": SCHEMA_CHALLENGE,
        "challenge_id": challenge_id,
        "authority_generation": pointer["generation"],
        "authority_pointer": {
            "source_name": Path(authority_pointer_path).name,
            "sha256": pointer_sha,
            "accepted_manifest_sha256": pointer["accepted_manifest_sha256"],
        },
        "stable_roots": {
            "current_state": {"source_name": Path(current_state_path).name, "sha256": current_state_sha},
            "role_index": {"source_name": Path(role_index_path).name, "sha256": role_index_sha},
            "role_views": {"source_name": Path(role_views_path).name, "sha256": role_views_sha},
        },
        "state_bundle": {"source_name": Path(state_bundle_path).name, "sha256": bundle_sha},
        "state_resolution_sha256": resolution_sha,
        "session_spec": {"source_name": Path(spec_path).name, "sha256": spec_sha},
        "candidate_capsule": {
            "path": "candidate/SESSION_CAPSULE.json",
            "sha256": sha256_bytes(capsule_payload),
        },
        "controller_expected_ack": {
            "path": "controller/EXPECTED_BOOT_ACK.json",
            "sha256": sha256_bytes(expected_payload),
        },
        "candidate_instructions": {
            "output_schema": SCHEMA_ACK,
            "output_filename": "BOOT_ACK.json",
            "no_external_context": True,
            "no_archive_access": True,
            "no_repo_writes": True,
            "read_only": True,
        },
        "live_state_modified": False,
        "auto_dispatch": False,
        "can_trade": False,
        "capital_permission": "DENY",
        "deploy_permission": "DENY",
    }
    challenge_payload = canonical_json_bytes(challenge)

    target, temp = _prepare_atomic_output(output_dir)
    try:
        (temp / "candidate").mkdir()
        (temp / "controller").mkdir()
        _write_new(temp / "candidate" / "SESSION_CAPSULE.json", capsule_payload)
        _write_new(temp / "controller" / "EXPECTED_BOOT_ACK.json", expected_payload)
        _write_new(temp / "CURRENT_COLD_START_CHALLENGE.json", challenge_payload)
        sums = (
            f"{sha256_bytes(challenge_payload)}  CURRENT_COLD_START_CHALLENGE.json\n"
            f"{sha256_bytes(capsule_payload)}  candidate/SESSION_CAPSULE.json\n"
            f"{sha256_bytes(expected_payload)}  controller/EXPECTED_BOOT_ACK.json\n"
        ).encode("utf-8")
        _write_new(temp / "SHA256SUMS.txt", sums)
        _fsync_directory(temp / "candidate")
        _fsync_directory(temp / "controller")
        _fsync_directory(temp)
        os.replace(temp, target)
        _fsync_directory(target.parent)
    except Exception:
        shutil.rmtree(temp, ignore_errors=True)
        raise

    return {
        "schema": SCHEMA_PREPARE_RECEIPT,
        "terminal": "CURRENT_COLD_START_PASS",
        "reason": "ACTIVE_POINTER_AND_STABLE_ROOTS_BOUND",
        "challenge_id": challenge_id,
        "authority_generation": pointer["generation"],
        "authority_pointer_sha256": pointer_sha,
        "accepted_manifest_sha256": pointer["accepted_manifest_sha256"],
        "current_state_sha256": current_state_sha,
        "role_index_sha256": role_index_sha,
        "role_views_sha256": role_views_sha,
        "state_bundle_sha256": bundle_sha,
        "state_resolution_sha256": resolution_sha,
        "spec_sha256": spec_sha,
        "challenge_sha256": sha256_bytes(challenge_payload),
        "capsule_sha256": sha256_bytes(capsule_payload),
        "expected_ack_sha256": sha256_bytes(expected_payload),
        "output_dir": str(target.resolve()),
        "writes_performed": [
            "CURRENT_COLD_START_CHALLENGE.json",
            "candidate/SESSION_CAPSULE.json",
            "controller/EXPECTED_BOOT_ACK.json",
            "SHA256SUMS.txt",
        ],
        "effects": _effects(),
    }


def peek_challenge_schema(path: Path) -> str | None:
    value, _ = _read_json_with_sha(path, "current.challenge.peek")
    if not isinstance(value, dict):
        return None
    schema = value.get("schema")
    return schema if isinstance(schema, str) else None


def verify_current_cold_start_ack(
    challenge_path: Path,
    ack_path: Path,
    *,
    expected_challenge_sha256: str,
) -> dict[str, Any]:
    expected_sha = _sha(expected_challenge_sha256, "current.challenge.expected_sha256")
    challenge_value, challenge_sha = _read_json_with_sha(challenge_path, "current.challenge")
    if challenge_sha != expected_sha:
        raise CurrentColdStartError("current.challenge:SHA256_MISMATCH")
    challenge = _mapping(challenge_value, "current.challenge")
    if challenge.get("schema") != SCHEMA_CHALLENGE:
        raise CurrentColdStartError("current.challenge:UNSUPPORTED_SCHEMA")
    if challenge.get("live_state_modified") is not False:
        raise CurrentColdStartError("current.challenge:LIVE_STATE_EFFECT")
    if challenge.get("auto_dispatch") is not False:
        raise CurrentColdStartError("current.challenge:AUTO_DISPATCH_EFFECT")
    if challenge.get("can_trade") is not False or challenge.get("capital_permission") != "DENY":
        raise CurrentColdStartError("current.challenge:CAPITAL_EFFECT")
    if challenge.get("deploy_permission") != "DENY":
        raise CurrentColdStartError("current.challenge:DEPLOY_EFFECT")

    root = Path(challenge_path).resolve().parent
    capsule_desc = _mapping(challenge.get("candidate_capsule"), "current.challenge.candidate_capsule")
    expected_desc = _mapping(
        challenge.get("controller_expected_ack"), "current.challenge.controller_expected_ack"
    )
    capsule_path = _safe_relative(root, capsule_desc.get("path"), "current.challenge.candidate_capsule.path")
    expected_path = _safe_relative(
        root, expected_desc.get("path"), "current.challenge.controller_expected_ack.path"
    )
    capsule_payload, capsule_sha = _read_bytes_with_sha(capsule_path, "current.capsule")
    expected_payload, expected_ack_sha = _read_bytes_with_sha(expected_path, "current.expected_ack")
    if capsule_sha != _sha(capsule_desc.get("sha256"), "current.challenge.candidate_capsule.sha256"):
        raise CurrentColdStartError("current.challenge:CAPSULE_SHA_MISMATCH")
    if expected_ack_sha != _sha(
        expected_desc.get("sha256"), "current.challenge.controller_expected_ack.sha256"
    ):
        raise CurrentColdStartError("current.challenge:EXPECTED_ACK_SHA_MISMATCH")

    capsule = _mapping(strict_json_loads(capsule_payload, "current.capsule"), "current.capsule")
    if capsule.get("schema") != SCHEMA_CAPSULE:
        raise CurrentColdStartError("current.capsule:UNSUPPORTED_SCHEMA")
    if capsule.get("challenge_id") != challenge.get("challenge_id"):
        raise CurrentColdStartError("current.capsule:CHALLENGE_ID_MISMATCH")
    if capsule.get("authority_generation") != challenge.get("authority_generation"):
        raise CurrentColdStartError("current.capsule:AUTHORITY_GENERATION_MISMATCH")

    expected = _mapping(
        strict_json_loads(expected_payload, "current.expected_ack"), "current.expected_ack"
    )
    if expected.get("schema") != SCHEMA_ACK:
        raise CurrentColdStartError("current.expected_ack:UNSUPPORTED_SCHEMA")
    ack_payload, ack_sha = _read_bytes_with_sha(ack_path, "current.ack")
    try:
        ack = strict_json_loads(ack_payload, "current.ack")
    except Exception as exc:
        return {
            "schema": SCHEMA_VERDICT,
            "challenge_id": challenge.get("challenge_id"),
            "challenge_sha256": challenge_sha,
            "ack_sha256": ack_sha,
            "checks": [{"check_id": "ack.json", "status": "FAIL", "code": str(exc)}],
            "mismatches": [{"path": "/", "expected": "exact schema-valid current BOOT_ACK", "observed": str(exc)}],
            "outcome": "FAIL",
            "status": "CURRENT_COLD_START_FAIL",
            "release_blocked": True,
            "writes_performed": [],
            "effects": _effects(),
        }
    if not isinstance(ack, dict):
        mismatches = [{"path": "/", "expected": expected, "observed": ack}]
        checks = [{"check_id": "ack.object", "status": "FAIL", "code": "NOT_OBJECT"}]
    else:
        checks = []
        mismatches = []
        all_keys = sorted(set(expected) | set(ack))
        for key in all_keys:
            if key in expected and key in ack and expected[key] == ack[key]:
                checks.append({"check_id": f"ack.{key}", "status": "PASS", "code": "EXACT_MATCH"})
            else:
                checks.append({"check_id": f"ack.{key}", "status": "FAIL", "code": "MISMATCH"})
                mismatches.append(
                    {"path": f"/{key}", "expected": expected.get(key), "observed": ack.get(key)}
                )
    passed = not mismatches
    return {
        "schema": SCHEMA_VERDICT,
        "challenge_id": challenge.get("challenge_id"),
        "challenge_sha256": challenge_sha,
        "ack_sha256": ack_sha,
        "authority_generation": challenge.get("authority_generation"),
        "checks": checks,
        "mismatches": mismatches,
        "outcome": "PASS" if passed else "FAIL",
        "status": "CURRENT_COLD_START_PASS" if passed else "CURRENT_COLD_START_FAIL",
        "release_blocked": not passed,
        "writes_performed": [],
        "effects": _effects(),
    }


def json_text(value: Any) -> str:
    return canonical_json_text(value)
