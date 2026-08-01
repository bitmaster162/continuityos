"""Deterministic cold-start challenge and verifier for ANTI_AMNESIA_GATE.

The controller prepares a candidate-facing session capsule from a verified boot
receipt plus a controller-authored session specification.  A fresh agent returns
one structured BOOT_ACK document.  Verification is exact and non-semantic: the
ack either matches the hidden expected fields or it does not.

This module does not invoke an LLM, mutate R63, write runtime state, install
software, or grant effects.  The only writes performed by ``prepare`` are to a
new caller-selected output directory.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import uuid
from typing import Any, Dict, Iterable, List, Mapping, Tuple

from .anti_amnesia import (
    AntiAmnesiaError,
    GATE,
    MODE,
    canonical_json_bytes,
    sha256_bytes,
    stable_read_bytes,
    strict_json_loads,
    validate_boot_receipt,
    validate_case_id,
    validate_role,
)

SCHEMA_SPEC = "ANTI_AMNESIA_COLD_START_SPEC_V1"
SCHEMA_CAPSULE = "ANTI_AMNESIA_SESSION_CAPSULE_V1"
SCHEMA_ACK = "ANTI_AMNESIA_BOOT_ACK_V1"
SCHEMA_CHALLENGE = "ANTI_AMNESIA_COLD_START_CHALLENGE_V1"
SCHEMA_VERDICT = "ANTI_AMNESIA_COLD_START_VERDICT_V1"
AUTHORITY_GENERATION = "R63"
MAX_COLD_START_INPUT_BYTES = 4 * 1024 * 1024
GIT_OBJECT_RE = re.compile(r"^[0-9a-f]{40,64}$")
WORK_ORDER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,191}$")
EFFECT_CEILINGS = {
    "READ_ONLY",
    "REVERSIBLE_LOCAL_IMPLEMENTATION",
    "COMPENSATABLE_HUMAN_APPROVAL",
    "IRREVERSIBLE_HUMAN_APPROVAL",
}


class ColdStartError(AntiAmnesiaError):
    """Cold-start input, package, or ack is invalid."""


def _exact_keys(value: Any, keys: Iterable[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise ColdStartError(f"{label}:NOT_OBJECT")
    expected = set(keys)
    actual = set(value)
    if expected != actual:
        raise ColdStartError(
            f"{label}:KEYS:missing={sorted(expected - actual)}:extra={sorted(actual - expected)}"
        )
    return value


def _nonempty_string(value: Any, label: str, *, max_length: int = 4096) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > max_length:
        raise ColdStartError(f"{label}:INVALID_STRING")
    return value


def _string_list(value: Any, label: str, *, min_items: int = 0) -> List[str]:
    if not isinstance(value, list) or len(value) < min_items:
        raise ColdStartError(f"{label}:INVALID_LIST")
    result: List[str] = []
    for index, item in enumerate(value):
        result.append(_nonempty_string(item, f"{label}[{index}]", max_length=2048))
    if len(result) != len(set(result)):
        raise ColdStartError(f"{label}:DUPLICATE_ITEMS")
    return result


def _sha256_file(path: Path, label: str) -> Tuple[bytes, str]:
    payload = stable_read_bytes(
        path,
        label=label,
        max_bytes=MAX_COLD_START_INPUT_BYTES,
    )
    return payload, sha256_bytes(payload)


def _validate_git_baseline(value: Any) -> Dict[str, str]:
    row = _exact_keys(
        value,
        {"repository", "branch", "head", "tree", "porcelain"},
        "spec.git_baseline",
    )
    repository = _nonempty_string(row["repository"], "spec.git_baseline.repository")
    branch = _nonempty_string(row["branch"], "spec.git_baseline.branch", max_length=255)
    head = row["head"]
    tree = row["tree"]
    if not isinstance(head, str) or not GIT_OBJECT_RE.fullmatch(head):
        raise ColdStartError("spec.git_baseline.head:INVALID_GIT_OBJECT")
    if not isinstance(tree, str) or not GIT_OBJECT_RE.fullmatch(tree):
        raise ColdStartError("spec.git_baseline.tree:INVALID_GIT_OBJECT")
    porcelain = row["porcelain"]
    if porcelain != "":
        raise ColdStartError("spec.git_baseline.porcelain:BASELINE_NOT_CLEAN")
    return {
        "repository": repository,
        "branch": branch,
        "head": head,
        "tree": tree,
        "porcelain": "",
    }


def validate_cold_start_spec(value: Any) -> Dict[str, Any]:
    row = _exact_keys(
        value,
        {
            "schema",
            "authority_generation",
            "work_order_id",
            "role",
            "case_id",
            "goal",
            "accepted_decisions",
            "rejected_alternatives",
            "allowed_changes",
            "forbidden_actions",
            "immutable_decisions",
            "git_baseline",
            "next_action",
            "terminal_condition",
            "effect_ceiling",
            "may_dispatch_codex",
            "can_trade",
            "capital_permission",
        },
        "cold_start_spec",
    )
    if row["schema"] != SCHEMA_SPEC:
        raise ColdStartError("spec.schema:UNSUPPORTED")
    if row["authority_generation"] != AUTHORITY_GENERATION:
        raise ColdStartError("spec.authority_generation:NOT_R63")
    work_order_id = row["work_order_id"]
    if not isinstance(work_order_id, str) or not WORK_ORDER_RE.fullmatch(work_order_id):
        raise ColdStartError("spec.work_order_id:INVALID")
    role = validate_role(row["role"])
    case_id = validate_case_id(row["case_id"])
    goal = _nonempty_string(row["goal"], "spec.goal")
    accepted = _string_list(row["accepted_decisions"], "spec.accepted_decisions")
    rejected = _string_list(row["rejected_alternatives"], "spec.rejected_alternatives")
    allowed = _string_list(row["allowed_changes"], "spec.allowed_changes")
    forbidden = _string_list(row["forbidden_actions"], "spec.forbidden_actions", min_items=1)
    immutable = _string_list(row["immutable_decisions"], "spec.immutable_decisions")
    baseline = _validate_git_baseline(row["git_baseline"])
    next_action = _nonempty_string(row["next_action"], "spec.next_action")
    terminal = _nonempty_string(row["terminal_condition"], "spec.terminal_condition")
    effect_ceiling = row["effect_ceiling"]
    if effect_ceiling not in EFFECT_CEILINGS:
        raise ColdStartError("spec.effect_ceiling:INVALID")
    if row["may_dispatch_codex"] is not False:
        raise ColdStartError("spec.may_dispatch_codex:MUST_BE_FALSE")
    if row["can_trade"] is not False:
        raise ColdStartError("spec.can_trade:MUST_BE_FALSE")
    if row["capital_permission"] != "DENY":
        raise ColdStartError("spec.capital_permission:MUST_BE_DENY")
    return {
        "schema": SCHEMA_SPEC,
        "authority_generation": AUTHORITY_GENERATION,
        "work_order_id": work_order_id,
        "role": role,
        "case_id": case_id,
        "goal": goal,
        "accepted_decisions": accepted,
        "rejected_alternatives": rejected,
        "allowed_changes": allowed,
        "forbidden_actions": forbidden,
        "immutable_decisions": immutable,
        "git_baseline": baseline,
        "next_action": next_action,
        "terminal_condition": terminal,
        "effect_ceiling": effect_ceiling,
        "may_dispatch_codex": False,
        "can_trade": False,
        "capital_permission": "DENY",
    }


def _validate_boot_for_challenge(boot: Any, spec: Mapping[str, Any]) -> Dict[str, Any]:
    validate_boot_receipt(boot)
    if boot.get("outcome") == "WOULD_HOLD" or boot.get("errors"):
        raise ColdStartError("boot_receipt:NOT_ADMISSIBLE")
    role_binding = boot["binding"]["role"]
    case_binding = boot["binding"]["case"]
    if role_binding.get("authority_status") != "EXACT_R63_ROLE":
        raise ColdStartError("boot_receipt:ROLE_NOT_EXACT_R63")
    if role_binding.get("id") != spec["role"] or boot["command"].get("role") != spec["role"]:
        raise ColdStartError("boot_receipt:ROLE_MISMATCH")
    if boot["authority"].get("generation") != AUTHORITY_GENERATION:
        raise ColdStartError("boot_receipt:AUTHORITY_NOT_R63")
    if spec["case_id"] is None:
        if boot["command"].get("case_id") is not None or case_binding.get("status") != "NOT_REQUESTED":
            raise ColdStartError("boot_receipt:CASE_EXPECTED_NOT_REQUESTED")
    else:
        if boot["command"].get("case_id") != spec["case_id"]:
            raise ColdStartError("boot_receipt:CASE_MISMATCH")
        if case_binding.get("status") != "EXACT_STRUCTURED_MATCH" or case_binding.get("authoritative") is not True:
            raise ColdStartError("boot_receipt:CASE_NOT_EXACT_STRUCTURED_MATCH")
    if boot.get("live_state_modified") is not False or boot.get("writes_performed") != []:
        raise ColdStartError("boot_receipt:EFFECT_VIOLATION")
    if boot.get("can_trade") is not False or boot.get("capital_permission") != "DENY":
        raise ColdStartError("boot_receipt:TRADING_CEILING_VIOLATION")
    return dict(boot)


def _expected_ack(capsule: Mapping[str, Any]) -> Dict[str, Any]:
    return {
        "schema": SCHEMA_ACK,
        "challenge_id": capsule["challenge_id"],
        "authority_generation": capsule["authority_generation"],
        "role": capsule["role"],
        "active_case": capsule["active_case"],
        "work_order_id": capsule["work_order_id"],
        "baseline_head": capsule["git_baseline"]["head"],
        "baseline_tree": capsule["git_baseline"]["tree"],
        "allowed_changes": list(capsule["allowed_changes"]),
        "forbidden_actions": list(capsule["forbidden_actions"]),
        "immutable_decisions": list(capsule["immutable_decisions"]),
        "next_action": capsule["next_action"],
        "terminal_condition": capsule["terminal_condition"],
        "effect_ceiling": capsule["effect_ceiling"],
        "may_dispatch_codex": False,
        "can_trade": False,
        "capital_permission": "DENY",
        "boot_status": capsule["boot_status"],
        "boot_warnings": list(capsule["boot_warnings"]),
    }


def validate_boot_ack(value: Any) -> Dict[str, Any]:
    keys = {
        "schema",
        "challenge_id",
        "authority_generation",
        "role",
        "active_case",
        "work_order_id",
        "baseline_head",
        "baseline_tree",
        "allowed_changes",
        "forbidden_actions",
        "immutable_decisions",
        "next_action",
        "terminal_condition",
        "effect_ceiling",
        "may_dispatch_codex",
        "can_trade",
        "capital_permission",
        "boot_status",
        "boot_warnings",
    }
    row = _exact_keys(value, keys, "boot_ack")
    if row["schema"] != SCHEMA_ACK:
        raise ColdStartError("boot_ack.schema:UNSUPPORTED")
    if not isinstance(row["challenge_id"], str) or not re.fullmatch(r"^[0-9a-f]{64}$", row["challenge_id"]):
        raise ColdStartError("boot_ack.challenge_id:INVALID")
    if row["authority_generation"] != AUTHORITY_GENERATION:
        raise ColdStartError("boot_ack.authority_generation:NOT_R63")
    validate_role(row["role"])
    validate_case_id(row["active_case"])
    if not isinstance(row["work_order_id"], str) or not WORK_ORDER_RE.fullmatch(row["work_order_id"]):
        raise ColdStartError("boot_ack.work_order_id:INVALID")
    for field in ("baseline_head", "baseline_tree"):
        if not isinstance(row[field], str) or not GIT_OBJECT_RE.fullmatch(row[field]):
            raise ColdStartError(f"boot_ack.{field}:INVALID_GIT_OBJECT")
    for field in ("allowed_changes", "forbidden_actions", "immutable_decisions", "boot_warnings"):
        _string_list(row[field], f"boot_ack.{field}")
    for field in ("next_action", "terminal_condition"):
        _nonempty_string(row[field], f"boot_ack.{field}")
    if row["effect_ceiling"] not in EFFECT_CEILINGS:
        raise ColdStartError("boot_ack.effect_ceiling:INVALID")
    if row["may_dispatch_codex"] is not False:
        raise ColdStartError("boot_ack.may_dispatch_codex:MUST_BE_FALSE")
    if row["can_trade"] is not False:
        raise ColdStartError("boot_ack.can_trade:MUST_BE_FALSE")
    if row["capital_permission"] != "DENY":
        raise ColdStartError("boot_ack.capital_permission:MUST_BE_DENY")
    if row["boot_status"] not in {"SHADOW_READY", "SHADOW_READY_WITH_WARNINGS"}:
        raise ColdStartError("boot_ack.boot_status:INVALID")
    return dict(row)


def _prepare_atomic_output(path: Path) -> Tuple[Path, Path]:
    target = Path(path).expanduser().absolute()
    if target.exists():
        raise ColdStartError("output:TARGET_ALREADY_EXISTS")
    target.parent.mkdir(parents=True, exist_ok=True)
    temp = target.with_name(f".{target.name}.tmp-{os.getpid()}-{uuid.uuid4().hex}")
    temp.mkdir(mode=0o700, exist_ok=False)
    return target, temp


def _write_new(path: Path, payload: bytes) -> None:
    # Windows CRT file descriptors may otherwise apply text-mode newline
    # translation to raw JSON/schema/instruction bytes.  All challenge
    # descriptors are SHA-256 bound to the pre-write payload, so the output
    # must be opened explicitly in binary mode whenever the platform exposes
    # O_BINARY.
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    fd = os.open(path, flags, 0o600)
    try:
        view = memoryview(payload)
        offset = 0
        while offset < len(view):
            written = os.write(fd, view[offset:])
            if written <= 0:
                raise ColdStartError(f"output:SHORT_WRITE:{path.name}")
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


def prepare_cold_start_challenge(
    boot_receipt_path: Path,
    spec_path: Path,
    output_dir: Path,
) -> Dict[str, Any]:
    boot_payload, boot_sha = _sha256_file(Path(boot_receipt_path), "cold_start.boot_receipt")
    spec_payload, spec_sha = _sha256_file(Path(spec_path), "cold_start.spec")
    boot = strict_json_loads(boot_payload, "cold_start.boot_receipt")
    spec = validate_cold_start_spec(strict_json_loads(spec_payload, "cold_start.spec"))
    boot = _validate_boot_for_challenge(boot, spec)

    challenge_material = {
        "schema": SCHEMA_CHALLENGE,
        "boot_receipt_sha256": boot_sha,
        "spec_sha256": spec_sha,
        "authority_generation": AUTHORITY_GENERATION,
        "role": spec["role"],
        "case_id": spec["case_id"],
        "work_order_id": spec["work_order_id"],
        "workspace_context_digest": boot["workspace"]["context_digest"],
        "pointer_sha256": boot["authority"]["pointer"]["sha256"],
    }
    challenge_id = sha256_bytes(canonical_json_bytes(challenge_material))
    capsule = {
        "schema": SCHEMA_CAPSULE,
        "challenge_id": challenge_id,
        "authority_generation": AUTHORITY_GENERATION,
        "role": spec["role"],
        "active_case": spec["case_id"],
        "case_binding": boot["binding"]["case"]["status"],
        "work_order_id": spec["work_order_id"],
        "role_state": boot["binding"]["role"].get("state"),
        "role_lane": boot["binding"]["role"].get("lane"),
        "workspace_context_digest": boot["workspace"]["context_digest"],
        "current_pointer_sha256": boot["authority"]["pointer"]["sha256"],
        "latest_checkpoint_id": boot["workspace"].get("latest_checkpoint_id"),
        "active_open_loop_ids": list(boot["workspace"].get("active_open_loop_ids") or []),
        "goal": spec["goal"],
        "accepted_decisions": list(spec["accepted_decisions"]),
        "rejected_alternatives": list(spec["rejected_alternatives"]),
        "allowed_changes": list(spec["allowed_changes"]),
        "forbidden_actions": list(spec["forbidden_actions"]),
        "immutable_decisions": list(spec["immutable_decisions"]),
        "git_baseline": dict(spec["git_baseline"]),
        "next_action": spec["next_action"],
        "terminal_condition": spec["terminal_condition"],
        "effect_ceiling": spec["effect_ceiling"],
        "may_dispatch_codex": False,
        "can_trade": False,
        "capital_permission": "DENY",
        "boot_status": boot["status"],
        "boot_outcome": boot["outcome"],
        "boot_warnings": list(boot["warnings"]),
    }
    expected = _expected_ack(capsule)
    capsule_payload = canonical_json_bytes(capsule)
    expected_payload = canonical_json_bytes(expected)
    challenge = {
        "schema": SCHEMA_CHALLENGE,
        "challenge_id": challenge_id,
        "gate": GATE,
        "mode": MODE,
        "authority_generation": AUTHORITY_GENERATION,
        "boot_receipt": {
            "source_name": Path(boot_receipt_path).name,
            "sha256": boot_sha,
        },
        "session_spec": {
            "source_name": Path(spec_path).name,
            "sha256": spec_sha,
        },
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
        },
        "live_state_modified": False,
        "can_trade": False,
        "capital_permission": "DENY",
    }
    challenge_payload = canonical_json_bytes(challenge)

    target, temp_root = _prepare_atomic_output(Path(output_dir))
    try:
        (temp_root / "candidate").mkdir()
        (temp_root / "controller").mkdir()
        _write_new(temp_root / "candidate" / "SESSION_CAPSULE.json", capsule_payload)
        _write_new(temp_root / "controller" / "EXPECTED_BOOT_ACK.json", expected_payload)
        _write_new(temp_root / "COLD_START_CHALLENGE.json", challenge_payload)
        sums = (
            f"{sha256_bytes(challenge_payload)}  COLD_START_CHALLENGE.json\n"
            f"{sha256_bytes(capsule_payload)}  candidate/SESSION_CAPSULE.json\n"
            f"{sha256_bytes(expected_payload)}  controller/EXPECTED_BOOT_ACK.json\n"
        ).encode("utf-8")
        _write_new(temp_root / "SHA256SUMS.txt", sums)
        _fsync_directory(temp_root / "candidate")
        _fsync_directory(temp_root / "controller")
        _fsync_directory(temp_root)
        os.replace(temp_root, target)
        _fsync_directory(target.parent)
    except Exception:
        shutil.rmtree(temp_root, ignore_errors=True)
        raise
    root = target.resolve()
    return {
        "schema": "ANTI_AMNESIA_COLD_START_PREPARE_RECEIPT_V1",
        "challenge_id": challenge_id,
        "output_dir": str(root),
        "challenge_sha256": sha256_bytes(challenge_payload),
        "capsule_sha256": sha256_bytes(capsule_payload),
        "expected_ack_sha256": sha256_bytes(expected_payload),
        "status": "COLD_START_CHALLENGE_READY",
        "live_state_modified": False,
        "writes_performed": [
            "COLD_START_CHALLENGE.json",
            "candidate/SESSION_CAPSULE.json",
            "controller/EXPECTED_BOOT_ACK.json",
            "SHA256SUMS.txt",
        ],
        "can_trade": False,
        "capital_permission": "DENY",
    }


def _safe_challenge_relative(root: Path, raw: Any, label: str) -> Path:
    if not isinstance(raw, str) or not raw or "\\" in raw:
        raise ColdStartError(f"{label}:INVALID_RELATIVE_PATH")
    path = Path(raw)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ColdStartError(f"{label}:UNSAFE_RELATIVE_PATH")
    resolved_root = root.resolve()
    cursor = resolved_root
    for part in path.parts:
        cursor = cursor / part
        if cursor.exists():
            info = cursor.lstat()
            if stat.S_ISLNK(info.st_mode):
                raise ColdStartError(f"{label}:SYMLINK_REFUSED")
            attrs = getattr(info, "st_file_attributes", 0)
            if attrs & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400):
                raise ColdStartError(f"{label}:REPARSE_REFUSED")
    resolved = (resolved_root / path).resolve()
    try:
        resolved.relative_to(resolved_root)
    except ValueError as exc:
        raise ColdStartError(f"{label}:PATH_ESCAPES_CHALLENGE") from exc
    return resolved


def verify_cold_start_ack(
    challenge_path: Path,
    ack_path: Path,
    *,
    expected_challenge_sha256: str,
) -> Dict[str, Any]:
    if not isinstance(expected_challenge_sha256, str) or not re.fullmatch(
        r"^[0-9a-f]{64}$", expected_challenge_sha256
    ):
        raise ColdStartError("challenge:INVALID_EXPECTED_SHA256")
    challenge_payload, challenge_sha = _sha256_file(Path(challenge_path), "cold_start.challenge")
    if challenge_sha != expected_challenge_sha256:
        raise ColdStartError("challenge:SHA256_MISMATCH")
    challenge = strict_json_loads(challenge_payload, "cold_start.challenge")
    row = _exact_keys(
        challenge,
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
        "challenge",
    )
    if row["schema"] != SCHEMA_CHALLENGE or row["gate"] != GATE or row["mode"] != MODE:
        raise ColdStartError("challenge:UNSUPPORTED_IDENTITY")
    if row["authority_generation"] != AUTHORITY_GENERATION:
        raise ColdStartError("challenge:NOT_R63")
    if row["live_state_modified"] is not False or row["can_trade"] is not False or row["capital_permission"] != "DENY":
        raise ColdStartError("challenge:EFFECT_CEILING_VIOLATION")
    challenge_root = Path(challenge_path).resolve().parent
    capsule_desc = _exact_keys(row["candidate_capsule"], {"path", "sha256"}, "challenge.candidate_capsule")
    expected_desc = _exact_keys(row["controller_expected_ack"], {"path", "sha256"}, "challenge.controller_expected_ack")
    capsule_path = _safe_challenge_relative(challenge_root, capsule_desc["path"], "challenge.candidate_capsule.path")
    expected_path = _safe_challenge_relative(challenge_root, expected_desc["path"], "challenge.controller_expected_ack.path")
    capsule_payload, capsule_sha = _sha256_file(capsule_path, "cold_start.capsule")
    expected_payload, expected_sha = _sha256_file(expected_path, "cold_start.expected_ack")
    checks: List[Dict[str, str]] = []
    mismatches: List[Dict[str, Any]] = []
    if capsule_sha != capsule_desc["sha256"]:
        raise ColdStartError("challenge:CAPSULE_SHA_MISMATCH")
    if expected_sha != expected_desc["sha256"]:
        raise ColdStartError("challenge:EXPECTED_ACK_SHA_MISMATCH")
    capsule = strict_json_loads(capsule_payload, "cold_start.capsule")
    if not isinstance(capsule, dict) or capsule.get("schema") != SCHEMA_CAPSULE:
        raise ColdStartError("capsule:UNSUPPORTED")
    if capsule.get("challenge_id") != row["challenge_id"]:
        raise ColdStartError("capsule:CHALLENGE_ID_MISMATCH")
    expected = validate_boot_ack(strict_json_loads(expected_payload, "cold_start.expected_ack"))
    ack_payload, ack_sha = _sha256_file(Path(ack_path), "cold_start.ack")
    try:
        ack = validate_boot_ack(strict_json_loads(ack_payload, "cold_start.ack"))
    except (AntiAmnesiaError, ColdStartError) as exc:
        return {
            "schema": SCHEMA_VERDICT,
            "challenge_id": row["challenge_id"],
            "challenge_sha256": challenge_sha,
            "ack_sha256": ack_sha,
            "checks": [{"check_id": "ack.schema", "status": "FAIL", "code": str(exc)}],
            "mismatches": [{"path": "/", "expected": "schema-valid exact BOOT_ACK", "observed": str(exc)}],
            "outcome": "FAIL",
            "status": "COLD_START_FAIL",
            "release_blocked": True,
            "live_state_modified": False,
            "writes_performed": [],
            "can_trade": False,
            "capital_permission": "DENY",
        }
    all_fields = sorted(expected)
    for field in all_fields:
        if ack.get(field) == expected.get(field):
            checks.append({"check_id": f"ack.{field}", "status": "PASS", "code": "EXACT_MATCH"})
        else:
            checks.append({"check_id": f"ack.{field}", "status": "FAIL", "code": "MISMATCH"})
            mismatches.append({"path": f"/{field}", "expected": expected.get(field), "observed": ack.get(field)})
    passed = not mismatches
    return {
        "schema": SCHEMA_VERDICT,
        "challenge_id": row["challenge_id"],
        "challenge_sha256": challenge_sha,
        "ack_sha256": ack_sha,
        "checks": checks,
        "mismatches": mismatches,
        "outcome": "PASS" if passed else "FAIL",
        "status": "COLD_START_PASS" if passed else "COLD_START_FAIL",
        "release_blocked": not passed,
        "live_state_modified": False,
        "writes_performed": [],
        "can_trade": False,
        "capital_permission": "DENY",
    }
