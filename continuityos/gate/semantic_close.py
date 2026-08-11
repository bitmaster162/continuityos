"""Anti-Amnesia semantic close v1.1 (shadow-only).

This module deliberately does not apply state.  It binds a return candidate to:

* the exact R63 boot receipt and current authority/workspace snapshot;
* a controller-selected work-order body;
* a controller-selected role permission policy;
* an explicit base-state digest;
* an optional, fully verifiable Git bundle and exact diff scope;
* structured JSON-Pointer deltas;
* an effect classification that can require human approval.

The v1 transport/integrity close remains available in :mod:`anti_amnesia`.
"""
from __future__ import annotations

import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import tempfile
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from . import anti_amnesia as v1


RETURN_ENVELOPE_V11_NAME = "ANTI_AMNESIA_RETURN_V1_1.json"
SCHEMA_RETURN = "ANTI_AMNESIA_RETURN_V1_1"
SCHEMA_CLOSE = "ANTI_AMNESIA_CLOSE_RECEIPT_V1_1"
SCHEMA_POLICY = "ANTI_AMNESIA_ROLE_PERMISSION_POLICY_V1"
MODE = v1.MODE
GATE = v1.GATE

COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
JSON_POINTER_RE = re.compile(r"^(?:/(?:[^~/]|~0|~1)*)*$")
DIFF_STATUS_RE = re.compile(r"^(?:A|M|D|T|U|X|B|R[0-9]{1,3}|C[0-9]{1,3})$")

GLOBAL_FORBIDDEN_DELTA_PREFIXES: Tuple[str, ...] = (
    "/authority_generation",
    "/generation",
    "/control_generation",
    "/global_effect_ceiling",
    "/can_trade",
    "/capital_permission",
    "/deploy_permission",
    "/self_application",
    "/current_pointer",
    "/CURRENT_POINTER",
    "/policies/authority",
)

HIGH_EFFECT_FIELDS: Tuple[str, ...] = (
    "live_state_apply",
    "push",
    "deploy",
    "external_message",
    "credential_rotation",
    "service_mutation",
    "scheduler_mutation",
    "trading",
)


class SemanticCloseError(v1.AntiAmnesiaError):
    """A v1.1 semantic close contract or proof is invalid."""


def _exact_keys(value: Any, expected: Iterable[str], label: str) -> Mapping[str, Any]:
    try:
        return v1._require_exact_keys(value, expected, label)
    except v1.AntiAmnesiaError as exc:
        raise SemanticCloseError(str(exc)) from exc


def _require_text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise SemanticCloseError(f"{label}:EMPTY_OR_NOT_STRING")
    return value


def _require_bool(value: Any, label: str) -> bool:
    if not isinstance(value, bool):
        raise SemanticCloseError(f"{label}:NOT_BOOLEAN")
    return value


def _require_commit(value: Any, label: str) -> str:
    if not isinstance(value, str) or not COMMIT_RE.fullmatch(value):
        raise SemanticCloseError(f"{label}:INVALID_GIT_OID")
    return value


def _require_sha(value: Any, label: str) -> str:
    try:
        return v1._require_sha(value, label)
    except v1.AntiAmnesiaError as exc:
        raise SemanticCloseError(str(exc)) from exc


def _safe_posix_path(raw: Any, label: str, *, allow_prefix: bool = False) -> str:
    if not isinstance(raw, str) or not raw:
        raise SemanticCloseError(f"{label}:EMPTY_OR_NOT_STRING")
    if "\\" in raw or raw.startswith("/") or ":" in raw:
        raise SemanticCloseError(f"{label}:UNSAFE_PATH")
    trailing = raw.endswith("/")
    value = raw[:-1] if trailing else raw
    pure = PurePosixPath(value)
    if not pure.parts or any(part in {"", ".", ".."} for part in pure.parts):
        raise SemanticCloseError(f"{label}:UNSAFE_PATH")
    normalized = pure.as_posix()
    if trailing:
        if not allow_prefix:
            raise SemanticCloseError(f"{label}:PREFIX_NOT_ALLOWED")
        normalized += "/"
    return normalized


def _path_permitted(path: str, rules: Sequence[str]) -> bool:
    for rule in rules:
        if rule.endswith("/"):
            prefix = rule[:-1]
            if path == prefix or path.startswith(rule):
                return True
        elif path == rule:
            return True
    return False


def _validate_json_pointer(path: Any, label: str) -> str:
    if not isinstance(path, str) or not path or not JSON_POINTER_RE.fullmatch(path):
        raise SemanticCloseError(f"{label}:INVALID_JSON_POINTER")
    if path == "/":
        raise SemanticCloseError(f"{label}:ROOT_REPLACEMENT_FORBIDDEN")
    return path


def derive_base_state_sha256(boot_receipt: Mapping[str, Any]) -> str:
    """Derive the explicit base-state binding from a validated boot receipt."""
    v1.validate_boot_receipt(boot_receipt)
    role = boot_receipt["binding"]["role"]
    case = boot_receipt["binding"]["case"]
    payload = {
        "authority_generation": boot_receipt["authority"]["generation"],
        "r63_pointer_sha256": boot_receipt["authority"]["pointer"]["sha256"],
        "workspace_context_digest": boot_receipt["workspace"]["context_digest"],
        "role": boot_receipt["command"]["role"],
        "role_record_sha256": role["record_sha256"],
        "case_id": boot_receipt["command"]["case_id"],
        "case_binding": case["status"],
        "case_authoritative": case["authoritative"],
    }
    return v1.sha256_canonical(payload)


def _load_permission_policy(path: Path) -> Tuple[Mapping[str, Any], bytes, str]:
    payload = v1.stable_read_bytes(path, label="semantic.permission_policy")
    parsed = v1.strict_json_loads(payload, "semantic.permission_policy")
    root = _exact_keys(
        parsed,
        {"schema", "authority_generation", "policy_id", "roles"},
        "permission_policy",
    )
    if root["schema"] != SCHEMA_POLICY:
        raise SemanticCloseError("permission_policy:SCHEMA_MISMATCH")
    if root["authority_generation"] != v1.EXPECTED_AUTHORITY_GENERATION:
        raise SemanticCloseError("permission_policy:AUTHORITY_GENERATION_MISMATCH")
    _require_text(root["policy_id"], "permission_policy.policy_id")
    if not isinstance(root["roles"], dict) or not root["roles"]:
        raise SemanticCloseError("permission_policy.roles:EMPTY_OR_NOT_OBJECT")
    for role, record in root["roles"].items():
        v1.validate_role(role)
        row = _exact_keys(
            record,
            {
                "allow_no_case",
                "allowed_delta_prefixes",
                "allowed_git_paths",
                "allowed_effect_classes",
            },
            f"permission_policy.roles.{role}",
        )
        _require_bool(row["allow_no_case"], f"permission_policy.roles.{role}.allow_no_case")
        for field in ("allowed_delta_prefixes", "allowed_git_paths", "allowed_effect_classes"):
            if not isinstance(row[field], list):
                raise SemanticCloseError(f"permission_policy.roles.{role}.{field}:NOT_ARRAY")
        normalized_delta = []
        for index, prefix in enumerate(row["allowed_delta_prefixes"]):
            normalized_delta.append(_validate_json_pointer(prefix, f"permission_policy.roles.{role}.allowed_delta_prefixes[{index}]"))
        if normalized_delta != row["allowed_delta_prefixes"] or len(set(normalized_delta)) != len(normalized_delta):
            raise SemanticCloseError(f"permission_policy.roles.{role}.allowed_delta_prefixes:ORDER_OR_DUPLICATE")
        normalized_git = []
        for index, item in enumerate(row["allowed_git_paths"]):
            normalized_git.append(_safe_posix_path(item, f"permission_policy.roles.{role}.allowed_git_paths[{index}]", allow_prefix=True))
        if normalized_git != row["allowed_git_paths"] or len(set(normalized_git)) != len(normalized_git):
            raise SemanticCloseError(f"permission_policy.roles.{role}.allowed_git_paths:ORDER_OR_DUPLICATE")
        allowed_effects = row["allowed_effect_classes"]
        valid_effects = {"REVERSIBLE", "COMPENSATABLE", "IRREVERSIBLE"}
        if (
            not allowed_effects
            or any(item not in valid_effects for item in allowed_effects)
            or allowed_effects != sorted(set(allowed_effects))
        ):
            raise SemanticCloseError(f"permission_policy.roles.{role}.allowed_effect_classes:INVALID")
    return root, payload, v1.sha256_bytes(payload)


def _validate_permission_for_role(
    policy: Mapping[str, Any],
    role: str,
    case_id: Optional[str],
    case_binding: str,
) -> Mapping[str, Any]:
    record = policy["roles"].get(role)
    if not isinstance(record, dict):
        raise SemanticCloseError("permission_policy:ROLE_NOT_AUTHORIZED")
    if case_id is None:
        if record["allow_no_case"] is not True:
            raise SemanticCloseError("permission_policy:NO_CASE_NOT_AUTHORIZED")
    elif case_binding != "EXACT_STRUCTURED_MATCH":
        raise SemanticCloseError("permission_policy:CASE_NOT_AUTHORITATIVE")
    return record


def _validate_proposed_delta(
    proposed: Any,
    allowed_prefixes: Sequence[str],
) -> List[Dict[str, Any]]:
    if not isinstance(proposed, list):
        raise SemanticCloseError("return.proposed_delta:NOT_ARRAY")
    normalized: List[Dict[str, Any]] = []
    seen = set()
    for index, item in enumerate(proposed):
        if not isinstance(item, dict):
            raise SemanticCloseError(f"return.proposed_delta[{index}]:NOT_OBJECT")
        op = item.get("op")
        if op not in {"add", "replace", "remove"}:
            raise SemanticCloseError(f"return.proposed_delta[{index}]:INVALID_OP")
        expected = {"op", "path"} if op == "remove" else {"op", "path", "value"}
        row = _exact_keys(item, expected, f"return.proposed_delta[{index}]")
        path = _validate_json_pointer(row["path"], f"return.proposed_delta[{index}].path")
        if path in seen:
            raise SemanticCloseError("return.proposed_delta:DUPLICATE_PATH")
        seen.add(path)
        if any(path == prefix or path.startswith(prefix + "/") for prefix in GLOBAL_FORBIDDEN_DELTA_PREFIXES):
            raise SemanticCloseError(f"return.proposed_delta:GLOBAL_FORBIDDEN:{path}")
        if not any(path == prefix or path.startswith(prefix + "/") for prefix in allowed_prefixes):
            raise SemanticCloseError(f"return.proposed_delta:ROLE_SCOPE_VIOLATION:{path}")
        normalized.append(dict(row))
    paths = [row["path"] for row in normalized]
    if paths != sorted(paths):
        raise SemanticCloseError("return.proposed_delta:NON_DETERMINISTIC_ORDER")
    return normalized


def _validate_effects(effects: Any, allowed_classes: Sequence[str]) -> Tuple[Mapping[str, Any], List[str]]:
    root = _exact_keys(effects, {"effect_class", "requested"}, "return.effects")
    effect_class = root["effect_class"]
    if effect_class not in {"REVERSIBLE", "COMPENSATABLE", "IRREVERSIBLE"}:
        raise SemanticCloseError("return.effects:INVALID_EFFECT_CLASS")
    if effect_class not in allowed_classes:
        raise SemanticCloseError("return.effects:ROLE_EFFECT_CLASS_VIOLATION")
    requested = _exact_keys(
        root["requested"],
        {
            "live_state_apply",
            "push",
            "deploy",
            "external_message",
            "credential_rotation",
            "service_mutation",
            "scheduler_mutation",
            "trading",
            "can_trade",
            "capital_permission",
        },
        "return.effects.requested",
    )
    for field in (*HIGH_EFFECT_FIELDS, "can_trade"):
        _require_bool(requested[field], f"return.effects.requested.{field}")
    if requested["capital_permission"] not in {"DENY", "REQUEST"}:
        raise SemanticCloseError("return.effects.requested:INVALID_CAPITAL_PERMISSION")
    reasons: List[str] = []
    if effect_class in {"COMPENSATABLE", "IRREVERSIBLE"}:
        reasons.append(f"EFFECT_CLASS_{effect_class}")
    reasons.extend(field.upper() for field in HIGH_EFFECT_FIELDS if requested[field])
    if requested["can_trade"]:
        reasons.append("CAN_TRADE_REQUESTED")
    if requested["capital_permission"] != "DENY":
        reasons.append("CAPITAL_PERMISSION_REQUESTED")
    return root, sorted(set(reasons))


def _validate_artifacts(files: Mapping[str, bytes], envelope: Mapping[str, Any]) -> None:
    actual_names = sorted(name for name in files if name != RETURN_ENVELOPE_V11_NAME)
    rows = envelope["artifacts"]
    declared = [row["path"] for row in rows]
    if actual_names != declared:
        raise SemanticCloseError("RETURN_ARTIFACT_INVENTORY_MISMATCH")
    for row in rows:
        payload = files[row["path"]]
        if len(payload) != row["size_bytes"] or v1.sha256_bytes(payload) != row["sha256"]:
            raise SemanticCloseError(f"RETURN_ARTIFACT_HASH_MISMATCH:{row['path']}")
    declared_set = set(declared)
    for row in envelope["tests"]:
        evidence = row["evidence"]
        if evidence is not None and evidence not in declared_set:
            raise SemanticCloseError(f"RETURN_TEST_EVIDENCE_MISSING:{evidence}")


def _validate_artifact_rows(value: Any) -> List[Mapping[str, Any]]:
    if not isinstance(value, list) or not value:
        raise SemanticCloseError("return.artifacts:EMPTY_OR_NOT_ARRAY")
    rows: List[Mapping[str, Any]] = []
    names: List[str] = []
    for index, item in enumerate(value):
        row = _exact_keys(item, {"path", "size_bytes", "sha256"}, f"return.artifacts[{index}]")
        path = _safe_posix_path(row["path"], f"return.artifacts[{index}].path")
        if path in {RETURN_ENVELOPE_V11_NAME, v1.RETURN_ENVELOPE_NAME}:
            raise SemanticCloseError("return.artifacts:ENVELOPE_SELF_REFERENCE")
        if not isinstance(row["size_bytes"], int) or isinstance(row["size_bytes"], bool) or row["size_bytes"] < 0:
            raise SemanticCloseError(f"return.artifacts[{index}].size_bytes:INVALID")
        _require_sha(row["sha256"], f"return.artifacts[{index}].sha256")
        names.append(path)
        rows.append(row)
    if names != sorted(names) or len(names) != len(set(names)):
        raise SemanticCloseError("return.artifacts:ORDER_OR_DUPLICATE")
    return rows


def _validate_tests(value: Any) -> List[Mapping[str, Any]]:
    if not isinstance(value, list) or not value:
        raise SemanticCloseError("return.tests:EMPTY_OR_NOT_ARRAY")
    rows: List[Mapping[str, Any]] = []
    names: List[str] = []
    for index, item in enumerate(value):
        row = _exact_keys(
            item,
            {"name", "result", "passed", "failed", "skipped", "evidence"},
            f"return.tests[{index}]",
        )
        name = _require_text(row["name"], f"return.tests[{index}].name")
        if row["result"] not in {"PASS", "FAIL", "SKIP"}:
            raise SemanticCloseError(f"return.tests[{index}].result:INVALID")
        for field in ("passed", "failed", "skipped"):
            if not isinstance(row[field], int) or isinstance(row[field], bool) or row[field] < 0:
                raise SemanticCloseError(f"return.tests[{index}].{field}:INVALID")
        if row["evidence"] is not None:
            _safe_posix_path(row["evidence"], f"return.tests[{index}].evidence")
        result = row["result"]
        if result == "PASS" and (row["passed"] < 1 or row["failed"] != 0):
            raise SemanticCloseError(f"return.tests[{index}]:INCOHERENT_PASS_TALLY")
        if result == "FAIL" and row["failed"] < 1:
            raise SemanticCloseError(f"return.tests[{index}]:INCOHERENT_FAIL_TALLY")
        if result == "SKIP" and (row["passed"] != 0 or row["failed"] != 0 or row["skipped"] < 1):
            raise SemanticCloseError(f"return.tests[{index}]:INCOHERENT_SKIP_TALLY")
        names.append(name)
        rows.append(row)
    if names != sorted(names) or len(names) != len(set(names)):
        raise SemanticCloseError("return.tests:ORDER_OR_DUPLICATE")
    if not any(row["result"] == "PASS" and row["evidence"] for row in rows):
        raise SemanticCloseError("return.tests:NO_EVIDENCED_PASS")
    return rows


def validate_return_envelope_v11(envelope: Any) -> None:
    root = _exact_keys(
        envelope,
        {
            "schema",
            "gate",
            "mode",
            "boot_receipt",
            "boot_binding",
            "work_order_binding",
            "terminal_state",
            "continuity_capsule",
            "proposed_delta",
            "effects",
            "git",
            "artifacts",
            "tests",
        },
        "return",
    )
    if root["schema"] != SCHEMA_RETURN or root["gate"] != GATE or root["mode"] != MODE:
        raise SemanticCloseError("return:IDENTITY_MISMATCH")
    boot_artifact = _exact_keys(root["boot_receipt"], {"path", "sha256"}, "return.boot_receipt")
    _safe_posix_path(boot_artifact["path"], "return.boot_receipt.path")
    _require_sha(boot_artifact["sha256"], "return.boot_receipt.sha256")
    binding = _exact_keys(
        root["boot_binding"],
        {"context_digest", "r63_pointer_sha256", "role", "case_id", "case_binding"},
        "return.boot_binding",
    )
    _require_sha(binding["context_digest"], "return.boot_binding.context_digest")
    _require_sha(binding["r63_pointer_sha256"], "return.boot_binding.r63_pointer_sha256")
    v1.validate_role(binding["role"])
    v1.validate_case_id(binding["case_id"])
    if binding["case_binding"] not in {"NOT_REQUESTED", "EXACT_STRUCTURED_MATCH"}:
        raise SemanticCloseError("return.boot_binding:NON_AUTHORITATIVE_CASE")
    work = _exact_keys(
        root["work_order_binding"],
        {
            "id",
            "body_sha256",
            "task_class",
            "base_state_sha256",
            "permission_policy_sha256",
        },
        "return.work_order_binding",
    )
    _require_text(work["id"], "return.work_order_binding.id")
    for field in ("body_sha256", "base_state_sha256", "permission_policy_sha256"):
        _require_sha(work[field], f"return.work_order_binding.{field}")
    if work["task_class"] not in {"IMPLEMENTATION", "RESEARCH", "AUDIT", "TRANSPORT", "CONTENT", "OTHER"}:
        raise SemanticCloseError("return.work_order_binding:INVALID_TASK_CLASS")
    _require_text(root["terminal_state"], "return.terminal_state")
    capsule = _exact_keys(
        root["continuity_capsule"],
        {"state_digest", "drift_risks", "unresolved", "next_action", "stop_condition"},
        "return.continuity_capsule",
    )
    for field in ("state_digest", "drift_risks", "unresolved"):
        if not isinstance(capsule[field], list) or not all(isinstance(item, str) for item in capsule[field]):
            raise SemanticCloseError(f"return.continuity_capsule.{field}:INVALID")
    if not capsule["state_digest"]:
        raise SemanticCloseError("return.continuity_capsule.state_digest:EMPTY")
    _require_text(capsule["next_action"], "return.continuity_capsule.next_action")
    _require_text(capsule["stop_condition"], "return.continuity_capsule.stop_condition")
    if not isinstance(root["proposed_delta"], list):
        raise SemanticCloseError("return.proposed_delta:NOT_ARRAY")
    if not isinstance(root["effects"], dict):
        raise SemanticCloseError("return.effects:NOT_OBJECT")
    git = _exact_keys(
        root["git"],
        {
            "required",
            "bundle_artifact",
            "branch",
            "baseline_head",
            "baseline_tree",
            "final_head",
            "final_tree",
            "diff_paths",
        },
        "return.git",
    )
    required = _require_bool(git["required"], "return.git.required")
    if required:
        _safe_posix_path(git["bundle_artifact"], "return.git.bundle_artifact")
        _require_text(git["branch"], "return.git.branch")
        for field in ("baseline_head", "baseline_tree", "final_head", "final_tree"):
            _require_commit(git[field], f"return.git.{field}")
        if not isinstance(git["diff_paths"], list):
            raise SemanticCloseError("return.git.diff_paths:NOT_ARRAY")
        previous = None
        for index, row in enumerate(git["diff_paths"]):
            item = _exact_keys(row, {"status", "path", "old_path"}, f"return.git.diff_paths[{index}]")
            if not isinstance(item["status"], str) or not DIFF_STATUS_RE.fullmatch(item["status"]):
                raise SemanticCloseError(f"return.git.diff_paths[{index}].status:INVALID")
            path = _safe_posix_path(item["path"], f"return.git.diff_paths[{index}].path")
            old = item["old_path"]
            if old is not None:
                _safe_posix_path(old, f"return.git.diff_paths[{index}].old_path")
            key = (path, item["status"], old or "")
            if previous is not None and key <= previous:
                raise SemanticCloseError("return.git.diff_paths:ORDER_OR_DUPLICATE")
            previous = key
    else:
        for field in ("bundle_artifact", "branch", "baseline_head", "baseline_tree", "final_head", "final_tree"):
            if git[field] is not None:
                raise SemanticCloseError(f"return.git.{field}:MUST_BE_NULL")
        if git["diff_paths"] != []:
            raise SemanticCloseError("return.git:NON_GIT_IDENTITY_PRESENT")
    _validate_artifact_rows(root["artifacts"])
    _validate_tests(root["tests"])


def _run_git(args: Sequence[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args],
        cwd=str(cwd),
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=60,
    )


def _parse_name_status(text: str) -> List[Dict[str, Optional[str]]]:
    rows: List[Dict[str, Optional[str]]] = []
    for raw in text.splitlines():
        if not raw:
            continue
        parts = raw.split("\t")
        status = parts[0]
        if not DIFF_STATUS_RE.fullmatch(status):
            raise SemanticCloseError(f"git.diff:INVALID_STATUS:{status}")
        if status.startswith(("R", "C")):
            if len(parts) != 3:
                raise SemanticCloseError("git.diff:INVALID_RENAME_ROW")
            old = _safe_posix_path(parts[1], "git.diff.old_path")
            path = _safe_posix_path(parts[2], "git.diff.path")
        else:
            if len(parts) != 2:
                raise SemanticCloseError("git.diff:INVALID_ROW")
            old = None
            path = _safe_posix_path(parts[1], "git.diff.path")
        rows.append({"status": status, "path": path, "old_path": old})
    return sorted(rows, key=lambda row: (row["path"], row["status"], row["old_path"] or ""))


def _verify_git_bundle(
    files: Mapping[str, bytes],
    git_contract: Mapping[str, Any],
    allowed_paths: Sequence[str],
) -> Mapping[str, Any]:
    if git_contract["required"] is not True:
        return {
            "required": False,
            "verified": True,
            "baseline_head": None,
            "final_head": None,
            "final_tree": None,
            "diff_paths": [],
        }
    artifact = git_contract["bundle_artifact"]
    payload = files.get(artifact)
    if payload is None:
        raise SemanticCloseError("git.bundle:ARTIFACT_MISSING")
    with tempfile.TemporaryDirectory(prefix="continuityos-semantic-close-") as tmp:
        tmp_root = Path(tmp)
        bundle = tmp_root / "candidate.bundle"
        bundle.write_bytes(payload)
        clone = tmp_root / "repo"
        result = subprocess.run(
            ["git", "clone", "--bare", "-b", git_contract["branch"], str(bundle), str(clone)],
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=120,
        )
        if result.returncode != 0:
            raise SemanticCloseError("git.bundle:CLONE_FAILED")
        fsck = _run_git(["fsck", "--full", "--strict"], clone)
        if fsck.returncode != 0:
            raise SemanticCloseError("git.bundle:FSCK_FAILED")
        head = _run_git(["rev-parse", "HEAD"], clone)
        if head.returncode != 0 or head.stdout.strip() != git_contract["final_head"]:
            raise SemanticCloseError("git.bundle:FINAL_HEAD_MISMATCH")
        tree = _run_git(["rev-parse", "HEAD^{tree}"], clone)
        if tree.returncode != 0 or tree.stdout.strip() != git_contract["final_tree"]:
            raise SemanticCloseError("git.bundle:FINAL_TREE_MISMATCH")
        baseline_tree = _run_git(["rev-parse", f"{git_contract['baseline_head']}^{{tree}}"], clone)
        if baseline_tree.returncode != 0 or baseline_tree.stdout.strip() != git_contract["baseline_tree"]:
            raise SemanticCloseError("git.bundle:BASELINE_TREE_MISMATCH")
        ancestor = _run_git(["merge-base", "--is-ancestor", git_contract["baseline_head"], git_contract["final_head"]], clone)
        if ancestor.returncode != 0:
            raise SemanticCloseError("git.bundle:BASELINE_NOT_ANCESTOR")
        diff = _run_git(["diff", "--name-status", "-M", git_contract["baseline_head"], git_contract["final_head"]], clone)
        if diff.returncode != 0:
            raise SemanticCloseError("git.bundle:DIFF_FAILED")
        actual = _parse_name_status(diff.stdout)
        if actual != git_contract["diff_paths"]:
            raise SemanticCloseError("git.bundle:DIFF_INVENTORY_MISMATCH")
        for row in actual:
            for path in (row["path"], row["old_path"]):
                if path is not None and not _path_permitted(path, allowed_paths):
                    raise SemanticCloseError(f"git.bundle:ROLE_PATH_VIOLATION:{path}")
        return {
            "required": True,
            "verified": True,
            "baseline_head": git_contract["baseline_head"],
            "final_head": git_contract["final_head"],
            "final_tree": git_contract["final_tree"],
            "diff_paths": actual,
        }


def _validate_boot_artifact_v11(
    files: Mapping[str, bytes],
    envelope: Mapping[str, Any],
    authority_docs: Mapping[str, Any],
    authority: Mapping[str, Any],
    workspace: Mapping[str, Any],
    expected_boot: Mapping[str, Any],
) -> Mapping[str, Any]:
    compatibility_envelope = dict(envelope)
    compatibility_envelope["continuity_capsule"] = {
        "top_open_loops": expected_boot["workspace"]["active_open_loops"],
    }
    try:
        return v1._validate_boot_receipt_artifact(
            files,
            compatibility_envelope,
            authority_docs,
            authority,
            workspace,
            expected_boot,
        )
    except v1.AntiAmnesiaError as exc:
        raise SemanticCloseError(str(exc)) from exc


def build_semantic_close_receipt(
    return_path: Any,
    dry_run: Any,
    *,
    work_order_path: Path,
    permission_policy_path: Path,
    control_root: Optional[Path] = None,
    workspace_root: Optional[Path] = None,
) -> Dict[str, Any]:
    authority, authority_docs, authority_checks, authority_errors, authority_warnings = v1.bind_r63_authority(control_root)
    workspace, _workspace_docs, workspace_checks, workspace_errors, workspace_warnings = v1.bind_workspace(workspace_root)
    checks = [*authority_checks, *workspace_checks]
    errors = [*authority_errors, *workspace_errors]
    warnings = [*authority_warnings, *workspace_warnings]
    candidate: Dict[str, Any] = {
        "kind": None,
        "content_sha256": None,
        "size_bytes": None,
        "entry_count": None,
        "envelope_sha256": None,
    }
    semantic_binding: Dict[str, Any] = {
        "work_order_id": None,
        "work_order_sha256": None,
        "base_state_sha256": None,
        "permission_policy_sha256": None,
        "role": None,
        "case_id": None,
    }
    git_verification: Dict[str, Any] = {
        "required": None,
        "verified": False,
        "baseline_head": None,
        "final_head": None,
        "final_tree": None,
        "diff_paths": [],
    }
    delta_verification: Dict[str, Any] = {
        "count": 0,
        "paths": [],
        "permitted": False,
    }
    approval = {
        "required": False,
        "effect_class": None,
        "reasons": [],
    }

    v1._record(checks, errors, warnings, "semantic.dry_run", "PASS" if dry_run is True else "FAIL", "VERIFIED" if dry_run is True else "CLOSE_REQUIRES_DRY_RUN")

    work_order_payload: Optional[bytes] = None
    work_order_sha: Optional[str] = None
    try:
        work_order_payload = v1.stable_read_bytes(Path(work_order_path), label="semantic.work_order")
        work_order_sha = v1.sha256_bytes(work_order_payload)
    except v1.AntiAmnesiaError as exc:
        v1._record(checks, errors, warnings, "semantic.work_order", "FAIL", str(exc))
    else:
        v1._record(checks, errors, warnings, "semantic.work_order", "PASS", "VERIFIED")

    policy: Optional[Mapping[str, Any]] = None
    policy_sha: Optional[str] = None
    try:
        policy, _policy_payload, policy_sha = _load_permission_policy(Path(permission_policy_path))
    except (v1.AntiAmnesiaError, SemanticCloseError) as exc:
        v1._record(checks, errors, warnings, "semantic.permission_policy", "FAIL", str(exc))
    else:
        v1._record(checks, errors, warnings, "semantic.permission_policy", "PASS", "VERIFIED")

    files: Dict[str, bytes] = {}
    envelope: Optional[Mapping[str, Any]] = None
    if not isinstance(return_path, (str, os.PathLike)) or not str(return_path):
        v1._record(checks, errors, warnings, "semantic.return_path", "FAIL", "INVALID_RETURN_PATH")
    else:
        path = Path(return_path).expanduser()
        try:
            if path.is_dir():
                files, metadata = v1._read_directory_return(path)
            elif path.is_file() and path.suffix.lower() == ".zip":
                files, metadata = v1._read_zip_return(path)
            elif path.is_file():
                raise SemanticCloseError("RETURN_FILE_MUST_BE_ZIP")
            else:
                raise SemanticCloseError("RETURN_PATH_MISSING")
            candidate.update(metadata)
            v1._record(checks, errors, warnings, "semantic.return_path", "PASS", "VERIFIED")
        except (v1.AntiAmnesiaError, SemanticCloseError) as exc:
            v1._record(checks, errors, warnings, "semantic.return_path", "FAIL", str(exc))

    if files:
        try:
            payload = files.get(RETURN_ENVELOPE_V11_NAME)
            if payload is None:
                raise SemanticCloseError("RETURN_V1_1_ENVELOPE_MISSING")
            parsed = v1.strict_json_loads(payload, RETURN_ENVELOPE_V11_NAME)
            validate_return_envelope_v11(parsed)
            envelope = parsed
            candidate["envelope_sha256"] = v1.sha256_bytes(payload)
            _validate_artifacts(files, envelope)
        except (v1.AntiAmnesiaError, SemanticCloseError) as exc:
            v1._record(checks, errors, warnings, "semantic.return_envelope", "FAIL", str(exc))
        else:
            v1._record(checks, errors, warnings, "semantic.return_envelope", "PASS", "VERIFIED")
    else:
        v1._record(checks, errors, warnings, "semantic.return_envelope", "FAIL", "RETURN_V1_1_ENVELOPE_MISSING")

    if envelope is not None:
        boot_binding = envelope["boot_binding"]
        expected_boot = v1.build_boot_receipt(
            boot_binding["role"],
            boot_binding["case_id"],
            control_root=control_root,
            workspace_root=workspace_root,
        )
        try:
            parsed_boot = _validate_boot_artifact_v11(
                files,
                envelope,
                authority_docs,
                authority,
                workspace,
                expected_boot,
            )
        except (v1.AntiAmnesiaError, SemanticCloseError) as exc:
            v1._record(checks, errors, warnings, "semantic.boot_receipt", "FAIL", str(exc))
            parsed_boot = None
        else:
            v1._record(checks, errors, warnings, "semantic.boot_receipt", "PASS", "VERIFIED")

        if parsed_boot is not None:
            base_state_sha = derive_base_state_sha256(parsed_boot)
            semantic_binding.update(
                {
                    "work_order_id": envelope["work_order_binding"]["id"],
                    "work_order_sha256": work_order_sha,
                    "base_state_sha256": base_state_sha,
                    "permission_policy_sha256": policy_sha,
                    "role": boot_binding["role"],
                    "case_id": boot_binding["case_id"],
                }
            )
            work_id_matches_case = (
                boot_binding["case_id"] is None
                or envelope["work_order_binding"]["id"] == boot_binding["case_id"]
            )
            v1._record(
                checks,
                errors,
                warnings,
                "semantic.work_order_case_binding",
                "PASS" if work_id_matches_case else "FAIL",
                "VERIFIED" if work_id_matches_case else "WORK_ORDER_ID_CASE_MISMATCH",
            )
            bindings_ok = (
                work_order_sha is not None
                and work_order_sha == envelope["work_order_binding"]["body_sha256"]
                and base_state_sha == envelope["work_order_binding"]["base_state_sha256"]
                and policy_sha is not None
                and policy_sha == envelope["work_order_binding"]["permission_policy_sha256"]
            )
            v1._record(
                checks,
                errors,
                warnings,
                "semantic.cryptographic_bindings",
                "PASS" if bindings_ok else "FAIL",
                "VERIFIED" if bindings_ok else "SEMANTIC_BINDING_MISMATCH",
            )

            permission_record: Optional[Mapping[str, Any]] = None
            if policy is not None:
                try:
                    permission_record = _validate_permission_for_role(
                        policy,
                        boot_binding["role"],
                        boot_binding["case_id"],
                        boot_binding["case_binding"],
                    )
                except SemanticCloseError as exc:
                    v1._record(checks, errors, warnings, "semantic.role_permission", "FAIL", str(exc))
                else:
                    v1._record(checks, errors, warnings, "semantic.role_permission", "PASS", "VERIFIED")

            if permission_record is not None:
                try:
                    proposed = _validate_proposed_delta(
                        envelope["proposed_delta"],
                        permission_record["allowed_delta_prefixes"],
                    )
                except SemanticCloseError as exc:
                    v1._record(checks, errors, warnings, "semantic.proposed_delta", "FAIL", str(exc))
                else:
                    delta_verification.update(
                        {
                            "count": len(proposed),
                            "paths": [row["path"] for row in proposed],
                            "permitted": True,
                        }
                    )
                    v1._record(checks, errors, warnings, "semantic.proposed_delta", "PASS", "VERIFIED")

                try:
                    effects, approval_reasons = _validate_effects(
                        envelope["effects"],
                        permission_record["allowed_effect_classes"],
                    )
                except SemanticCloseError as exc:
                    v1._record(checks, errors, warnings, "semantic.effects", "FAIL", str(exc))
                else:
                    approval.update(
                        {
                            "required": bool(approval_reasons),
                            "effect_class": effects["effect_class"],
                            "reasons": approval_reasons,
                        }
                    )
                    v1._record(checks, errors, warnings, "semantic.effects", "PASS", "VERIFIED")

                try:
                    git_verification = dict(
                        _verify_git_bundle(
                            files,
                            envelope["git"],
                            permission_record["allowed_git_paths"],
                        )
                    )
                    if envelope["work_order_binding"]["task_class"] == "IMPLEMENTATION" and git_verification["required"] is not True:
                        raise SemanticCloseError("git.bundle:IMPLEMENTATION_REQUIRES_GIT")
                except SemanticCloseError as exc:
                    v1._record(checks, errors, warnings, "semantic.git", "FAIL", str(exc))
                else:
                    v1._record(checks, errors, warnings, "semantic.git", "PASS", "VERIFIED")

        failed_tests = any(row.get("result") == "FAIL" for row in envelope["tests"])
        v1._record(
            checks,
            errors,
            warnings,
            "semantic.technical_tests",
            "FAIL" if failed_tests else "PASS",
            "RETURN_CONTAINS_FAILED_TESTS" if failed_tests else "VERIFIED",
        )

    checks = sorted(checks, key=lambda row: row["check_id"])
    errors = sorted(set(errors))
    warnings = sorted(set(warnings))
    if errors:
        outcome = "WOULD_HOLD"
        status_value = "SHADOW_HOLD"
    elif approval["required"]:
        outcome = "PENDING_HUMAN_APPROVAL"
        status_value = "SHADOW_PENDING_HUMAN_APPROVAL"
    elif warnings:
        outcome = "WOULD_ACCEPT_WITH_WARNINGS"
        status_value = "SHADOW_ACCEPTABLE_WITH_WARNINGS"
    else:
        outcome = "WOULD_ACCEPT"
        status_value = "SHADOW_ACCEPTABLE"

    receipt = {
        "schema": SCHEMA_CLOSE,
        "gate": GATE,
        "mode": MODE,
        "command": {
            "name": "close",
            "dry_run": dry_run is True,
        },
        "authority": authority,
        "workspace": workspace,
        "candidate": candidate,
        "semantic_binding": semantic_binding,
        "git_verification": git_verification,
        "delta_verification": delta_verification,
        "approval": approval,
        "checks": checks,
        "errors": errors,
        "warnings": warnings,
        "outcome": outcome,
        "status": status_value,
        "closed": False,
        "enforced": False,
        "live_state_reads_via_runtime_api": False,
        "live_state_modified": False,
        "r63_authority_replaced": False,
        "writes_performed": [],
        "can_trade": False,
        "capital_permission": "DENY",
    }
    validate_semantic_close_receipt(receipt)
    return receipt


def validate_semantic_close_receipt(receipt: Any) -> None:
    root = _exact_keys(
        receipt,
        {
            "schema",
            "gate",
            "mode",
            "command",
            "authority",
            "workspace",
            "candidate",
            "semantic_binding",
            "git_verification",
            "delta_verification",
            "approval",
            "checks",
            "errors",
            "warnings",
            "outcome",
            "status",
            "closed",
            "enforced",
            "live_state_reads_via_runtime_api",
            "live_state_modified",
            "r63_authority_replaced",
            "writes_performed",
            "can_trade",
            "capital_permission",
        },
        "semantic_close",
    )
    if root["schema"] != SCHEMA_CLOSE or root["gate"] != GATE or root["mode"] != MODE:
        raise SemanticCloseError("semantic_close:IDENTITY_MISMATCH")
    command = _exact_keys(root["command"], {"name", "dry_run"}, "semantic_close.command")
    if command["name"] != "close" or not isinstance(command["dry_run"], bool):
        raise SemanticCloseError("semantic_close.command:INVALID")
    for field in (
        "closed",
        "enforced",
        "live_state_reads_via_runtime_api",
        "live_state_modified",
        "r63_authority_replaced",
        "can_trade",
    ):
        if root[field] is not False:
            raise SemanticCloseError(f"semantic_close.{field}:EXPECTED_FALSE")
    if root["writes_performed"] != [] or root["capital_permission"] != "DENY":
        raise SemanticCloseError("semantic_close:EFFECT_CEILING_MISMATCH")

    candidate = _exact_keys(
        root["candidate"],
        {"kind", "content_sha256", "size_bytes", "entry_count", "envelope_sha256"},
        "semantic_close.candidate",
    )
    if candidate["kind"] not in {None, "ZIP", "DIRECTORY"}:
        raise SemanticCloseError("semantic_close.candidate:INVALID_KIND")
    for field in ("content_sha256", "envelope_sha256"):
        if candidate[field] is not None:
            _require_sha(candidate[field], f"semantic_close.candidate.{field}")
    for field in ("size_bytes", "entry_count"):
        value = candidate[field]
        if value is not None and (not isinstance(value, int) or isinstance(value, bool) or value < 0):
            raise SemanticCloseError(f"semantic_close.candidate:INVALID_{field.upper()}")

    binding = _exact_keys(
        root["semantic_binding"],
        {
            "work_order_id",
            "work_order_sha256",
            "base_state_sha256",
            "permission_policy_sha256",
            "role",
            "case_id",
        },
        "semantic_close.semantic_binding",
    )
    for field in ("work_order_sha256", "base_state_sha256", "permission_policy_sha256"):
        if binding[field] is not None:
            _require_sha(binding[field], f"semantic_close.semantic_binding.{field}")
    if binding["work_order_id"] is not None:
        _require_text(binding["work_order_id"], "semantic_close.semantic_binding.work_order_id")
    if binding["role"] is not None:
        v1.validate_role(binding["role"] )
    if binding["case_id"] is not None:
        v1.validate_case_id(binding["case_id"] )

    git = _exact_keys(
        root["git_verification"],
        {"required", "verified", "baseline_head", "final_head", "final_tree", "diff_paths"},
        "semantic_close.git_verification",
    )
    if git["required"] is not None:
        _require_bool(git["required"], "semantic_close.git_verification.required")
    _require_bool(git["verified"], "semantic_close.git_verification.verified")
    for field in ("baseline_head", "final_head", "final_tree"):
        if git[field] is not None:
            _require_commit(git[field], f"semantic_close.git_verification.{field}")
    if not isinstance(git["diff_paths"], list):
        raise SemanticCloseError("semantic_close.git_verification.diff_paths:NOT_ARRAY")

    delta = _exact_keys(
        root["delta_verification"],
        {"count", "paths", "permitted"},
        "semantic_close.delta_verification",
    )
    if not isinstance(delta["count"], int) or isinstance(delta["count"], bool) or delta["count"] < 0:
        raise SemanticCloseError("semantic_close.delta_verification:INVALID_COUNT")
    if not isinstance(delta["paths"], list):
        raise SemanticCloseError("semantic_close.delta_verification:PATHS_NOT_ARRAY")
    normalized_paths = [
        _validate_json_pointer(path, f"semantic_close.delta_verification.paths[{index}]")
        for index, path in enumerate(delta["paths"])
    ]
    if normalized_paths != sorted(set(normalized_paths)) or delta["count"] != len(normalized_paths):
        raise SemanticCloseError("semantic_close.delta_verification:COUNT_ORDER_OR_DUPLICATE")
    _require_bool(delta["permitted"], "semantic_close.delta_verification.permitted")

    approval = _exact_keys(
        root["approval"],
        {"required", "effect_class", "reasons"},
        "semantic_close.approval",
    )
    _require_bool(approval["required"], "semantic_close.approval.required")
    if approval["effect_class"] is not None and approval["effect_class"] not in {
        "REVERSIBLE", "COMPENSATABLE", "IRREVERSIBLE"
    }:
        raise SemanticCloseError("semantic_close.approval:INVALID_EFFECT_CLASS")
    if (
        not isinstance(approval["reasons"], list)
        or not all(isinstance(item, str) and item for item in approval["reasons"])
        or approval["reasons"] != sorted(set(approval["reasons"]))
    ):
        raise SemanticCloseError("semantic_close.approval:INVALID_REASONS")

    if not isinstance(root["checks"], list) or not all(isinstance(row, dict) for row in root["checks"]):
        raise SemanticCloseError("semantic_close.checks:INVALID")
    for field in ("errors", "warnings"):
        values = root[field]
        if (
            not isinstance(values, list)
            or not all(isinstance(item, str) for item in values)
            or values != sorted(set(values))
        ):
            raise SemanticCloseError(f"semantic_close.{field}:INVALID")

    allowed_pairs = {
        "WOULD_ACCEPT": "SHADOW_ACCEPTABLE",
        "WOULD_ACCEPT_WITH_WARNINGS": "SHADOW_ACCEPTABLE_WITH_WARNINGS",
        "PENDING_HUMAN_APPROVAL": "SHADOW_PENDING_HUMAN_APPROVAL",
        "WOULD_HOLD": "SHADOW_HOLD",
    }
    if allowed_pairs.get(root["outcome"]) != root["status"]:
        raise SemanticCloseError("semantic_close:OUTCOME_STATUS_MISMATCH")
    if root["errors"] and root["outcome"] != "WOULD_HOLD":
        raise SemanticCloseError("semantic_close:ERRORS_WITH_NON_HOLD_OUTCOME")
    if not root["errors"] and root["outcome"] == "WOULD_HOLD":
        raise SemanticCloseError("semantic_close:HOLD_WITHOUT_ERRORS")
    if (
        root["warnings"]
        and root["outcome"] == "WOULD_ACCEPT"
    ):
        raise SemanticCloseError("semantic_close:WARNINGS_WITH_CLEAN_ACCEPT")
    if root["outcome"] != "WOULD_HOLD":
        if command["dry_run"] is not True:
            raise SemanticCloseError("semantic_close:READY_WITHOUT_DRY_RUN")
        checks = {row["check_id"]: row for row in root["checks"]}
        for check_id in (
            "semantic.return_path",
            "semantic.return_envelope",
            "semantic.boot_receipt",
            "semantic.work_order",
            "semantic.permission_policy",
            "semantic.work_order_case_binding",
            "semantic.cryptographic_bindings",
            "semantic.role_permission",
            "semantic.proposed_delta",
            "semantic.effects",
            "semantic.git",
            "semantic.technical_tests",
            "semantic.dry_run",
        ):
            if checks.get(check_id, {}).get("status") != "PASS":
                raise SemanticCloseError(f"semantic_close:READY_WITHOUT_{check_id.upper()}")
        if root["delta_verification"]["permitted"] is not True:
            raise SemanticCloseError("semantic_close:DELTA_NOT_PERMITTED")
        if root["git_verification"]["verified"] is not True:
            raise SemanticCloseError("semantic_close:GIT_NOT_VERIFIED")
    if root["outcome"] == "PENDING_HUMAN_APPROVAL":
        if root["approval"]["required"] is not True or not root["approval"]["reasons"]:
            raise SemanticCloseError("semantic_close:APPROVAL_STATE_MISMATCH")
    elif root["approval"]["required"] is True and root["outcome"] != "WOULD_HOLD":
        raise SemanticCloseError("semantic_close:UNROUTED_APPROVAL_REQUIREMENT")
