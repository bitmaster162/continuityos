"""Fail-closed admission and delta verification for GitHub-bound work.

The gate separates four facts that are often conflated in agent workflows:

* the exact task bytes;
* the exact session capsule;
* the exact Git baseline and candidate branch;
* the exact allowed change/effect envelope.

Both entry points are effect-free.  ``verify_work_admission`` decides whether a
work run may start.  ``verify_work_delta`` decides whether a finished candidate
commit stayed inside the admitted scope.  Neither function creates a branch,
changes the worktree, pushes Git, merges, deploys, applies R63/current state, or
trades.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

REQUEST_SCHEMA = "continuityos.work_admission.request/v1"
RECEIPT_SCHEMA = "continuityos.work_admission.receipt/v1"
VALIDATION_SCHEMA = "continuityos.work_admission.validation_receipt/v1"
DELTA_SCHEMA = "continuityos.work_admission.delta_receipt/v1"

ADMISSION_PASS = "WORK_ADMISSION_PASS"
ADMISSION_HOLD = "WORK_ADMISSION_HOLD"
ADMISSION_REVISE = "WORK_ADMISSION_REVISE"
DELTA_PASS = "WORK_DELTA_PASS"
DELTA_HOLD = "WORK_DELTA_HOLD"
DELTA_REVISE = "WORK_DELTA_REVISE"

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
GIT_OID_RE = re.compile(r"^[0-9a-f]{40}$")
TASK_ID_RE = re.compile(r"^[A-Z0-9][A-Z0-9_.:-]{2,127}$")
BRANCH_RE = re.compile(r"^(?:gpt|agent|codex|spark|claude|fable|work|controller|candidate)/[A-Za-z0-9._/-]+$")
SAFE_ID_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
MAX_JSON_BYTES = 4 * 1024 * 1024
MAX_WORK_ORDER_BYTES = 8 * 1024 * 1024
MAX_REQUIRED_COMMANDS = 100
MAX_ARGV_ITEMS = 64
MAX_ARG_TOKEN_BYTES = 4096
WINDOWS_RESERVED_NAMES = {
    "CON", "PRN", "AUX", "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
}
SHELL_EXECUTABLES = {"sh", "bash", "zsh", "fish", "cmd", "cmd.exe"}
POWERSHELL_EXECUTABLES = {"powershell", "powershell.exe", "pwsh", "pwsh.exe"}
SHELL_META_RE = re.compile(r"&&|\|\||[;|<>]|\$\(|`")

DANGEROUS_EFFECTS = (
    "force_push",
    "merge",
    "pull_request_merge",
    "deployment",
    "registry_apply",
    "current_state_apply",
    "r63_apply",
    "trading",
    "wallet_access",
    "order_execution",
    "external_message",
    "self_application",
)

GLOBAL_BLOCKED_BASENAMES = {
    ".env",
    "credentials.json",
    "client_secret.json",
    "service_account.json",
    "token.json",
    "id_rsa",
    "id_ed25519",
    "chat.html",
    "conversations.json",
}
GLOBAL_BLOCKED_SUFFIXES = (
    ".pem",
    ".key",
    ".p12",
    ".pfx",
    ".sqlite",
    ".sqlite3",
    ".db",
    ".wal",
    ".shm",
)
SHELL_OPERATOR_TOKENS = {"&&", "||", "|", ">", ">>", "<", "<<", ";", "`"}
WORKSPACE_MODES = {"ANY_CLEAN_GIT_ROOT", "DISPOSABLE_CLONE_REQUIRED"}
GIT_OPERATION_MARKERS = (
    "MERGE_HEAD", "CHERRY_PICK_HEAD", "REVERT_HEAD", "BISECT_LOG",
    "rebase-apply", "rebase-merge",
)


def canonical_json_text(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _check(checks: list[dict[str, Any]], check_id: str, status: str, detail: str, **evidence: Any) -> None:
    row: dict[str, Any] = {"id": check_id, "status": status, "detail": detail}
    if evidence:
        row["evidence"] = evidence
    checks.append(row)


def _load_json(path: Path, label: str) -> dict[str, Any]:
    if not path.is_file():
        raise ValueError(f"{label} file is missing")
    if path.stat().st_size > MAX_JSON_BYTES:
        raise ValueError(f"{label} exceeds {MAX_JSON_BYTES} bytes")
    try:
        value = json.loads(path.read_text(encoding="utf-8-sig"))
    except Exception as exc:
        raise ValueError(f"{label} is not valid UTF-8 JSON: {type(exc).__name__}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    return value


def _require_dict(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    return value


def _require_str(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} must be a non-empty string")
    return value


def _require_bool(value: Any, label: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{label} must be boolean")
    return value


def _require_int(value: Any, label: str, *, minimum: int, maximum: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not (minimum <= value <= maximum):
        raise ValueError(f"{label} must be an integer in [{minimum}, {maximum}]")
    return value


def _safe_rel_path(value: Any, label: str) -> str:
    text = _require_str(value, label)
    if "\\" in text or "\x00" in text:
        raise ValueError(f"{label} must use POSIX relative separators")
    p = PurePosixPath(text)
    if p.is_absolute() or text in {".", "./"} or any(part in {"", ".", ".."} for part in p.parts):
        raise ValueError(f"{label} is not a safe relative path")
    if re.match(r"^[A-Za-z]:", text):
        raise ValueError(f"{label} must not be a Windows drive path")
    for part in p.parts:
        if part.endswith((" ", ".")) or any(ch in part for ch in '<>:"|?*'):
            raise ValueError(f"{label} contains a cross-platform-invalid component")
        stem = part.split(".", 1)[0].upper()
        if stem in WINDOWS_RESERVED_NAMES:
            raise ValueError(f"{label} contains a Windows-reserved component")
    return str(p)


def _normalize_host_path(path: Path) -> str:
    return os.path.normcase(str(path.expanduser().resolve())).replace("\\", "/").rstrip("/")


def _under_host_prefix(path: Path, prefix: str) -> bool:
    normalized = _normalize_host_path(path)
    prefix_norm = _normalize_host_path(Path(prefix))
    return normalized == prefix_norm or normalized.startswith(prefix_norm + "/")


def _normalize_host_roots(value: Any, label: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise ValueError(f"{label} must be a list of non-empty strings")
    out: list[str] = []
    for item in value:
        if "\x00" in item:
            raise ValueError(f"{label} contains a NUL byte")
        if not Path(item).expanduser().is_absolute():
            raise ValueError(f"{label} entries must be absolute host paths")
        if item not in out:
            out.append(item)
    return out


def _normalize_paths(value: Any, label: str, *, minimum: int = 0) -> list[str]:
    if not isinstance(value, list) or len(value) < minimum:
        raise ValueError(f"{label} must be a list with at least {minimum} entries")
    out: list[str] = []
    for index, raw in enumerate(value):
        path = _safe_rel_path(raw, f"{label}[{index}]")
        if path not in out:
            out.append(path)
    return out


def _path_is_within(path: str, prefix: str) -> bool:
    return path == prefix or path.startswith(prefix.rstrip("/") + "/")


def _globally_blocked_path(path: str, *, allow_archive_files: bool) -> str | None:
    parts = PurePosixPath(path).parts
    lowered = [part.lower() for part in parts]
    if ".git" in lowered:
        return ".git content is never admissible"
    base = lowered[-1]
    if (
        base in GLOBAL_BLOCKED_BASENAMES
        or base.startswith(("credentials.", "client_secret.", "service_account.", "token."))
        or base.startswith(".env.")
    ):
        return "credential, chat-export, or environment material is protected"
    if any(base.endswith(suffix) for suffix in GLOBAL_BLOCKED_SUFFIXES):
        return "runtime database or key material is protected"
    if not allow_archive_files and base.endswith((".zip", ".7z", ".rar", ".tar", ".tgz", ".gz")):
        return "archive payloads are not admitted by this request"
    joined = "/".join(lowered)
    if any(token in joined for token in ("raw_chat", "chat_export", "drivefs", "wallet_backup", "wallet_seed", "wallet_export", "private_key")):
        return "protected raw evidence or account material"
    return None


def _canonical_github_repo(remote_url: str) -> str:
    value = remote_url.strip()
    patterns = (
        r"^https://github\.com/([^/]+)/([^/]+?)(?:\.git)?/?$",
        r"^git@github\.com:([^/]+)/([^/]+?)(?:\.git)?$",
        r"^ssh://git@github\.com/([^/]+)/([^/]+?)(?:\.git)?/?$",
    )
    for pattern in patterns:
        match = re.match(pattern, value, re.IGNORECASE)
        if match:
            return f"{match.group(1).lower()}/{match.group(2).lower()}"
    raise ValueError("repository.remote_url must be a canonical github.com URL")


def _run(argv: list[str], *, cwd: Path | None = None, check: bool = True) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(
        argv,
        cwd=str(cwd) if cwd else None,
        text=True,
        capture_output=True,
        check=False,
    )
    if check and proc.returncode != 0:
        detail = proc.stderr.strip() or proc.stdout.strip() or f"exit {proc.returncode}"
        raise RuntimeError(f"command failed: {argv!r}: {detail}")
    return proc


def _git(repo: Path, *args: str, check: bool = True) -> str:
    return _run(["git", *args], cwd=repo, check=check).stdout.strip()


def _ls_remote(remote_url: str, branch: str) -> str | None:
    proc = _run(["git", "ls-remote", remote_url, f"refs/heads/{branch}"], check=False)
    if proc.returncode != 0:
        detail = proc.stderr.strip() or proc.stdout.strip() or f"exit {proc.returncode}"
        raise ConnectionError(detail)
    lines = [line for line in proc.stdout.splitlines() if line.strip()]
    if not lines:
        return None
    if len(lines) != 1:
        raise ValueError(f"ls-remote returned {len(lines)} rows for {branch}")
    oid = lines[0].split()[0]
    if not GIT_OID_RE.fullmatch(oid):
        raise ValueError("ls-remote returned an invalid Git object ID")
    return oid


def _normalize_required_commands(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not value:
        raise ValueError("validation.required_commands must be a non-empty list")
    if len(value) > MAX_REQUIRED_COMMANDS:
        raise ValueError(f"validation.required_commands exceeds {MAX_REQUIRED_COMMANDS} rows")
    seen: set[str] = set()
    out: list[dict[str, Any]] = []
    for index, raw in enumerate(value):
        row = _require_dict(raw, f"validation.required_commands[{index}]")
        command_id = _require_str(row.get("id"), f"validation.required_commands[{index}].id")
        if not SAFE_ID_RE.fullmatch(command_id) or command_id in seen:
            raise ValueError(f"invalid or duplicate validation command id: {command_id}")
        seen.add(command_id)
        argv = row.get("argv")
        if (
            not isinstance(argv, list)
            or not argv
            or len(argv) > MAX_ARGV_ITEMS
            or not all(
                isinstance(item, str)
                and item
                and len(item.encode("utf-8")) <= MAX_ARG_TOKEN_BYTES
                and "\x00" not in item
                and "\n" not in item
                and "\r" not in item
                for item in argv
            )
        ):
            raise ValueError(f"validation command {command_id} argv is invalid or exceeds bounds")
        if any(item in SHELL_OPERATOR_TOKENS or SHELL_META_RE.search(item) for item in argv):
            raise ValueError(f"validation command {command_id} contains shell syntax")
        executable = Path(argv[0]).name.lower()
        if executable in SHELL_EXECUTABLES:
            raise ValueError(f"validation command {command_id} may not use a shell executable")
        if executable in POWERSHELL_EXECUTABLES:
            lowered = {item.lower() for item in argv[1:]}
            if "-file" not in lowered or {"-command", "-encodedcommand"} & lowered:
                raise ValueError(
                    f"validation command {command_id} PowerShell requires -File and denies -Command/-EncodedCommand"
                )
        cwd = _safe_rel_path(row.get("cwd", "repo"), f"validation command {command_id} cwd")
        out.append({"id": command_id, "argv": list(argv), "cwd": cwd})
    return out


def normalize_work_admission_request(value: dict[str, Any]) -> dict[str, Any]:
    if value.get("schema") != REQUEST_SCHEMA:
        raise ValueError(f"request.schema must be {REQUEST_SCHEMA}")
    if value.get("authority_generation") != "R63":
        raise ValueError("authority_generation must remain R63")

    task = _require_dict(value.get("task"), "task")
    task_id = _require_str(task.get("task_id"), "task.task_id")
    if not TASK_ID_RE.fullmatch(task_id):
        raise ValueError("task.task_id has invalid syntax")
    task_sha = _require_str(task.get("task_body_sha256"), "task.task_body_sha256").lower()
    if not SHA256_RE.fullmatch(task_sha):
        raise ValueError("task.task_body_sha256 must be 64 lowercase hex")
    terminal_condition = _require_str(task.get("terminal_condition"), "task.terminal_condition")

    repository = _require_dict(value.get("repository"), "repository")
    owner = _require_str(repository.get("owner"), "repository.owner")
    name = _require_str(repository.get("name"), "repository.name")
    remote_url = _require_str(repository.get("remote_url"), "repository.remote_url")
    canonical_repo = _canonical_github_repo(remote_url)
    if canonical_repo != f"{owner.lower()}/{name.lower()}":
        raise ValueError("repository owner/name do not match remote_url")
    visibility = repository.get("visibility")
    if visibility not in {"PRIVATE", "PUBLIC"}:
        raise ValueError("repository.visibility must be PRIVATE or PUBLIC")
    if repository.get("visibility_change") is not False:
        raise ValueError("repository.visibility_change must be false")
    base_branch = _require_str(repository.get("base_branch"), "repository.base_branch")
    base_head = _require_str(repository.get("base_head"), "repository.base_head").lower()
    base_tree = _require_str(repository.get("base_tree"), "repository.base_tree").lower()
    if not GIT_OID_RE.fullmatch(base_head) or not GIT_OID_RE.fullmatch(base_tree):
        raise ValueError("repository base_head/base_tree must be Git object IDs")
    candidate_branch = _require_str(repository.get("candidate_branch"), "repository.candidate_branch")
    default_branch = _require_str(repository.get("default_branch"), "repository.default_branch")
    if candidate_branch in {"main", "master", default_branch, base_branch}:
        raise ValueError("candidate_branch must be distinct from base/default branches")
    if (
        not BRANCH_RE.fullmatch(candidate_branch)
        or "//" in candidate_branch
        or ".." in candidate_branch
        or "@{" in candidate_branch
        or candidate_branch.endswith(("/", ".", ".lock"))
        or "/." in candidate_branch
    ):
        raise ValueError("candidate_branch is outside the admitted candidate namespaces")
    remote_mode = repository.get("remote_readback_mode", "REQUIRED")
    if remote_mode not in {"REQUIRED", "OPTIONAL", "DENY"}:
        raise ValueError("repository.remote_readback_mode is invalid")
    existing_candidate_head = repository.get("existing_candidate_head")
    if existing_candidate_head is not None:
        if not isinstance(existing_candidate_head, str) or not GIT_OID_RE.fullmatch(existing_candidate_head.lower()):
            raise ValueError("repository.existing_candidate_head must be null or a Git object ID")
        existing_candidate_head = existing_candidate_head.lower()

    scope = _require_dict(value.get("scope"), "scope")
    allowed_paths = _normalize_paths(scope.get("allowed_paths"), "scope.allowed_paths", minimum=1)
    forbidden_paths = _normalize_paths(scope.get("forbidden_paths", []), "scope.forbidden_paths")
    allow_archive_files = _require_bool(scope.get("allow_archive_files", False), "scope.allow_archive_files")
    for path in allowed_paths:
        blocker = _globally_blocked_path(path, allow_archive_files=allow_archive_files)
        if blocker:
            raise ValueError(f"scope.allowed_paths contains protected path {path!r}: {blocker}")
        if any(_path_is_within(path, forbidden) for forbidden in forbidden_paths):
            raise ValueError(f"allowed path is contained by forbidden scope at {path!r}")
    max_changed_files = _require_int(scope.get("max_changed_files"), "scope.max_changed_files", minimum=1, maximum=500)
    max_added_bytes = _require_int(scope.get("max_added_bytes"), "scope.max_added_bytes", minimum=0, maximum=100 * 1024 * 1024)
    max_commits = _require_int(scope.get("max_commits"), "scope.max_commits", minimum=1, maximum=50)
    allow_new_files = _require_bool(scope.get("allow_new_files"), "scope.allow_new_files")
    allow_deletions = _require_bool(scope.get("allow_deletions"), "scope.allow_deletions")
    allow_binary_files = _require_bool(scope.get("allow_binary_files", False), "scope.allow_binary_files")

    workspace = _require_dict(value.get("workspace", {}), "workspace")
    workspace_mode = workspace.get("mode", "ANY_CLEAN_GIT_ROOT")
    if workspace_mode not in WORKSPACE_MODES:
        raise ValueError("workspace.mode is invalid")
    allowed_root_prefixes = _normalize_host_roots(workspace.get("allowed_root_prefixes", []), "workspace.allowed_root_prefixes")
    forbidden_root_prefixes = _normalize_host_roots(workspace.get("forbidden_root_prefixes", []), "workspace.forbidden_root_prefixes")
    if workspace_mode == "DISPOSABLE_CLONE_REQUIRED" and not allowed_root_prefixes:
        raise ValueError("DISPOSABLE_CLONE_REQUIRED needs allowed_root_prefixes")

    effects = _require_dict(value.get("effects"), "effects")
    normalized_effects: dict[str, Any] = {}
    for key in ("worktree_write", "test_execution", "local_commit", "candidate_push", "workflow_changes"):
        normalized_effects[key] = _require_bool(effects.get(key, False), f"effects.{key}")
    for key in DANGEROUS_EFFECTS:
        if _require_bool(effects.get(key, False), f"effects.{key}") is not False:
            raise ValueError(f"effects.{key} must be false")
        normalized_effects[key] = False
    if effects.get("capital_permission") != "DENY":
        raise ValueError("effects.capital_permission must be DENY")
    if effects.get("deploy_permission") != "DENY":
        raise ValueError("effects.deploy_permission must be DENY")
    normalized_effects["capital_permission"] = "DENY"
    normalized_effects["deploy_permission"] = "DENY"
    normalized_effects["can_trade"] = _require_bool(effects.get("can_trade", False), "effects.can_trade")
    if normalized_effects["can_trade"]:
        raise ValueError("effects.can_trade must be false")
    if any(_path_is_within(path, ".github/workflows") for path in allowed_paths) and not normalized_effects["workflow_changes"]:
        raise ValueError("workflow paths require effects.workflow_changes=true")

    session = _require_dict(value.get("session"), "session")
    required_role = _require_str(session.get("required_role"), "session.required_role")
    capsule_sha = _require_str(session.get("capsule_sha256"), "session.capsule_sha256").lower()
    if not SHA256_RE.fullmatch(capsule_sha):
        raise ValueError("session.capsule_sha256 must be 64 lowercase hex")

    validation = _require_dict(value.get("validation"), "validation")
    required_commands = _normalize_required_commands(validation.get("required_commands"))
    network_access = validation.get("network_access", "DENY")
    dependency_install = validation.get("dependency_install", "DENY")
    if network_access not in {"DENY", "READ_ONLY"}:
        raise ValueError("validation.network_access must be DENY or READ_ONLY")
    if dependency_install not in {"DENY", "LOCKED_ONLY"}:
        raise ValueError("validation.dependency_install must be DENY or LOCKED_ONLY")
    max_full_suite_runs = _require_int(validation.get("max_full_suite_runs", 1), "validation.max_full_suite_runs", minimum=0, maximum=3)
    max_install_attempts = _require_int(validation.get("max_install_attempts", 0), "validation.max_install_attempts", minimum=0, maximum=2)

    evidence = _require_dict(value.get("evidence", {}), "evidence")
    accepted_parent_terminal = evidence.get("accepted_parent_terminal")
    accepted_parent_receipt_sha256 = evidence.get("accepted_parent_receipt_sha256")
    if accepted_parent_terminal is not None:
        _require_str(accepted_parent_terminal, "evidence.accepted_parent_terminal")
    if accepted_parent_receipt_sha256 is not None:
        if not isinstance(accepted_parent_receipt_sha256, str) or not SHA256_RE.fullmatch(accepted_parent_receipt_sha256.lower()):
            raise ValueError("evidence.accepted_parent_receipt_sha256 is invalid")
        accepted_parent_receipt_sha256 = accepted_parent_receipt_sha256.lower()

    return {
        "schema": REQUEST_SCHEMA,
        "authority_generation": "R63",
        "task": {
            "task_id": task_id,
            "task_body_sha256": task_sha,
            "terminal_condition": terminal_condition,
        },
        "repository": {
            "owner": owner,
            "name": name,
            "remote_url": remote_url,
            "visibility": visibility,
            "visibility_change": False,
            "base_branch": base_branch,
            "base_head": base_head,
            "base_tree": base_tree,
            "candidate_branch": candidate_branch,
            "default_branch": default_branch,
            "remote_readback_mode": remote_mode,
            "existing_candidate_head": existing_candidate_head,
        },
        "scope": {
            "allowed_paths": allowed_paths,
            "forbidden_paths": forbidden_paths,
            "max_changed_files": max_changed_files,
            "max_added_bytes": max_added_bytes,
            "max_commits": max_commits,
            "allow_new_files": allow_new_files,
            "allow_deletions": allow_deletions,
            "allow_binary_files": allow_binary_files,
            "allow_archive_files": allow_archive_files,
        },
        "workspace": {
            "mode": workspace_mode,
            "allowed_root_prefixes": allowed_root_prefixes,
            "forbidden_root_prefixes": forbidden_root_prefixes,
        },
        "effects": normalized_effects,
        "session": {
            "required_role": required_role,
            "capsule_sha256": capsule_sha,
        },
        "validation": {
            "required_commands": required_commands,
            "network_access": network_access,
            "dependency_install": dependency_install,
            "max_full_suite_runs": max_full_suite_runs,
            "max_install_attempts": max_install_attempts,
        },
        "evidence": {
            "accepted_parent_terminal": accepted_parent_terminal,
            "accepted_parent_receipt_sha256": accepted_parent_receipt_sha256,
        },
    }


def _verify_capsule(capsule: dict[str, Any], request: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    task = request["task"]
    repo = request["repository"]
    scope = request["scope"]
    effects = request["effects"]
    if capsule.get("authority_generation") != "R63":
        errors.append("session capsule authority_generation is not R63")
    if capsule.get("role") != request["session"]["required_role"]:
        errors.append("session capsule role does not match request")
    active_task = capsule.get("active_task")
    if not isinstance(active_task, dict):
        errors.append("session capsule active_task is missing")
    else:
        if active_task.get("task_id") != task["task_id"]:
            errors.append("session capsule task_id mismatch")
        if active_task.get("task_body_sha256") != task["task_body_sha256"]:
            errors.append("session capsule task_body_sha256 mismatch")
    capsule_repo = capsule.get("repository")
    if not isinstance(capsule_repo, dict):
        errors.append("session capsule repository binding is missing")
    else:
        expected_repo = {
            "owner": repo["owner"],
            "name": repo["name"],
            "base_branch": repo["base_branch"],
            "base_head": repo["base_head"],
            "base_tree": repo["base_tree"],
            "candidate_branch": repo["candidate_branch"],
        }
        for key, expected in expected_repo.items():
            if capsule_repo.get(key) != expected:
                errors.append(f"session capsule repository.{key} mismatch")
    if capsule.get("terminal_condition") != task["terminal_condition"]:
        errors.append("session capsule terminal_condition mismatch")
    capsule_allowed = capsule.get("allowed_paths")
    if capsule_allowed != scope["allowed_paths"]:
        errors.append("session capsule allowed_paths mismatch")
    if capsule.get("workspace") != request["workspace"]:
        errors.append("session capsule workspace binding mismatch")
    for key in DANGEROUS_EFFECTS:
        if capsule.get(key, False) is not False:
            errors.append(f"session capsule {key} must be false")
    if capsule.get("can_trade") is not False:
        errors.append("session capsule can_trade must be false")
    if capsule.get("capital_permission") != "DENY":
        errors.append("session capsule capital_permission must be DENY")
    if capsule.get("deploy_permission") != "DENY":
        errors.append("session capsule deploy_permission must be DENY")
    if capsule.get("self_application") is not False:
        errors.append("session capsule self_application must be false")
    capsule_effects = capsule.get("effects")
    if isinstance(capsule_effects, dict):
        for key, expected in effects.items():
            if capsule_effects.get(key) != expected:
                errors.append(f"session capsule effects.{key} mismatch")
    else:
        errors.append("session capsule effects binding is missing")
    return errors


def _observed_repository(repo_path: Path, remote_name: str) -> dict[str, Any]:
    if repo_path.expanduser().is_symlink():
        raise ValueError("repo path may not be a symlink")
    resolved = repo_path.expanduser().resolve(strict=True)
    top = Path(_git(resolved, "rev-parse", "--show-toplevel")).resolve(strict=True)
    if top != resolved:
        raise ValueError(f"repo path is not the exact Git top-level: {resolved} != {top}")
    branch = _git(resolved, "branch", "--show-current")
    head = _git(resolved, "rev-parse", "HEAD")
    tree = _git(resolved, "rev-parse", "HEAD^{tree}")
    status = _git(resolved, "status", "--porcelain=v1", "-uall")
    remote_url = _git(resolved, "remote", "get-url", remote_name)
    git_dir_raw = _git(resolved, "rev-parse", "--git-dir")
    git_dir = Path(git_dir_raw)
    if not git_dir.is_absolute():
        git_dir = (resolved / git_dir).resolve()
    active_operations = [name for name in GIT_OPERATION_MARKERS if (git_dir / name).exists()]
    fsck = _run(["git", "fsck", "--full", "--strict"], cwd=resolved, check=False)
    return {
        "path": str(resolved),
        "branch": branch,
        "head": head,
        "tree": tree,
        "worktree_clean": status == "",
        "porcelain": status.splitlines() if status else [],
        "remote_name": remote_name,
        "remote_url": remote_url,
        "git_dir": str(git_dir),
        "active_operations": active_operations,
        "git_fsck": "PASS" if fsck.returncode == 0 else "FAIL",
        "git_fsck_stderr": fsck.stderr.strip(),
    }


def _binding_payload(request_sha: str, work_order_sha: str, capsule_sha: str, request: dict[str, Any], observed: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": "continuityos.work_admission.binding/v1",
        "request_sha256": request_sha,
        "work_order_sha256": work_order_sha,
        "session_capsule_sha256": capsule_sha,
        "task_id": request["task"]["task_id"],
        "authority_generation": "R63",
        "repository": {
            "owner": request["repository"]["owner"],
            "name": request["repository"]["name"],
            "base_branch": request["repository"]["base_branch"],
            "base_head": observed["head"],
            "base_tree": observed["tree"],
            "candidate_branch": request["repository"]["candidate_branch"],
        },
        "scope": request["scope"],
        "workspace": request["workspace"],
        "effects": request["effects"],
        "validation": request["validation"],
        "terminal_condition": request["task"]["terminal_condition"],
    }


def verify_work_admission(
    request_path: Path,
    work_order_path: Path,
    session_capsule_path: Path,
    repo_path: Path,
    *,
    remote_name: str = "origin",
    check_remote: bool = False,
) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    generated = _now()
    try:
        request_raw = _load_json(request_path, "work admission request")
        request = normalize_work_admission_request(request_raw)
        _check(checks, "REQUEST_SCHEMA", "PASS", "Request schema and invariants are valid.")
    except Exception as exc:
        _check(checks, "REQUEST_SCHEMA", "FAIL", f"{type(exc).__name__}: {exc}")
        return _admission_receipt(generated, checks, None, None, None, None, None)

    request_sha = sha256_file(request_path)
    work_order_sha = None
    if work_order_path.is_file() and work_order_path.stat().st_size <= MAX_WORK_ORDER_BYTES:
        work_order_sha = sha256_file(work_order_path)
    capsule_sha = None
    if session_capsule_path.is_file() and session_capsule_path.stat().st_size <= MAX_JSON_BYTES:
        capsule_sha = sha256_file(session_capsule_path)

    if work_order_path.is_file() and work_order_path.stat().st_size > MAX_WORK_ORDER_BYTES:
        _check(checks, "WORK_ORDER_SIZE", "FAIL", f"Work order exceeds {MAX_WORK_ORDER_BYTES} bytes.")
    if session_capsule_path.is_file() and session_capsule_path.stat().st_size > MAX_JSON_BYTES:
        _check(checks, "SESSION_CAPSULE_SIZE", "FAIL", f"Session capsule exceeds {MAX_JSON_BYTES} bytes.")

    if work_order_sha == request["task"]["task_body_sha256"]:
        _check(checks, "WORK_ORDER_SHA", "PASS", "Work-order bytes match task_body_sha256.", sha256=work_order_sha)
    else:
        _check(checks, "WORK_ORDER_SHA", "FAIL", "Work-order SHA mismatch or file missing.", expected=request["task"]["task_body_sha256"], observed=work_order_sha)

    if capsule_sha == request["session"]["capsule_sha256"]:
        _check(checks, "SESSION_CAPSULE_SHA", "PASS", "Session capsule bytes match request.", sha256=capsule_sha)
    else:
        _check(checks, "SESSION_CAPSULE_SHA", "FAIL", "Session capsule SHA mismatch or file missing.", expected=request["session"]["capsule_sha256"], observed=capsule_sha)

    capsule: dict[str, Any] | None = None
    if session_capsule_path.is_file():
        try:
            capsule = _load_json(session_capsule_path, "session capsule")
            errors = _verify_capsule(capsule, request)
            if errors:
                _check(checks, "SESSION_CAPSULE_BINDING", "FAIL", "; ".join(errors))
            else:
                _check(checks, "SESSION_CAPSULE_BINDING", "PASS", "Capsule binds role, task, repository, scope and effect ceiling.")
        except Exception as exc:
            _check(checks, "SESSION_CAPSULE_BINDING", "FAIL", f"{type(exc).__name__}: {exc}")

    observed: dict[str, Any] | None = None
    try:
        observed = _observed_repository(repo_path, remote_name)
        expected_repo = request["repository"]
        errors = []
        if observed["branch"] != expected_repo["base_branch"]:
            errors.append("branch mismatch")
        if observed["head"] != expected_repo["base_head"]:
            errors.append("HEAD mismatch")
        if observed["tree"] != expected_repo["base_tree"]:
            errors.append("tree mismatch")
        if not observed["worktree_clean"]:
            errors.append("worktree is dirty")
        if observed.get("active_operations"):
            errors.append("Git operation in progress: " + ", ".join(observed["active_operations"]))
        if observed.get("git_fsck") != "PASS":
            errors.append("git fsck --full --strict failed")
        workspace = request["workspace"]
        if any(_under_host_prefix(Path(observed["path"]), prefix) for prefix in workspace["forbidden_root_prefixes"]):
            errors.append("repository is under a forbidden workspace root")
        if workspace["mode"] == "DISPOSABLE_CLONE_REQUIRED" and not any(
            _under_host_prefix(Path(observed["path"]), prefix) for prefix in workspace["allowed_root_prefixes"]
        ):
            errors.append("repository is outside every allowed disposable workspace root")
        candidate_proc = _run(
            ["git", "show-ref", "--verify", f"refs/heads/{expected_repo['candidate_branch']}"],
            cwd=Path(observed["path"]), check=False,
        )
        local_candidate = candidate_proc.stdout.split()[0] if candidate_proc.returncode == 0 and candidate_proc.stdout.strip() else None
        observed["local_candidate_head"] = local_candidate
        expected_local_candidate = expected_repo["existing_candidate_head"]
        if local_candidate != expected_local_candidate:
            errors.append("local candidate branch state differs from admission request")
        try:
            observed_remote = _canonical_github_repo(observed["remote_url"])
            expected_remote = _canonical_github_repo(expected_repo["remote_url"])
            if observed_remote != expected_remote:
                errors.append("remote repository mismatch")
        except Exception as exc:
            errors.append(f"remote URL invalid: {exc}")
        if errors:
            _check(checks, "GIT_BASELINE", "FAIL", "; ".join(errors), observed=observed)
        else:
            _check(checks, "GIT_BASELINE", "PASS", "Exact clean Git baseline is verified.", observed=observed)
    except Exception as exc:
        _check(checks, "GIT_BASELINE", "FAIL", f"{type(exc).__name__}: {exc}")

    remote_mode = request["repository"]["remote_readback_mode"]
    if remote_mode == "DENY":
        _check(checks, "REMOTE_READBACK", "PASS", "Remote readback is explicitly denied for this admission.")
    elif not check_remote:
        status = "HOLD" if remote_mode == "REQUIRED" else "WARN"
        _check(checks, "REMOTE_READBACK", status, "Remote readback was not executed.")
    else:
        try:
            remote_base = _ls_remote(request["repository"]["remote_url"], request["repository"]["base_branch"])
            remote_candidate = _ls_remote(request["repository"]["remote_url"], request["repository"]["candidate_branch"])
            errors = []
            if remote_base != request["repository"]["base_head"]:
                errors.append("remote base HEAD mismatch")
            expected_candidate = request["repository"]["existing_candidate_head"]
            if expected_candidate is None and remote_candidate is not None:
                errors.append("candidate branch already exists unexpectedly")
            elif expected_candidate is not None and remote_candidate != expected_candidate:
                errors.append("existing candidate branch HEAD mismatch")
            if errors:
                _check(checks, "REMOTE_READBACK", "FAIL", "; ".join(errors), remote_base=remote_base, remote_candidate=remote_candidate)
            else:
                _check(checks, "REMOTE_READBACK", "PASS", "Remote base and candidate branch state are exact.", remote_base=remote_base, remote_candidate=remote_candidate)
        except ConnectionError as exc:
            status = "HOLD" if remote_mode == "REQUIRED" else "WARN"
            _check(checks, "REMOTE_READBACK", status, f"Remote readback unavailable: {exc}")
        except Exception as exc:
            _check(checks, "REMOTE_READBACK", "FAIL", f"{type(exc).__name__}: {exc}")

    binding = None
    binding_sha = None
    if observed is not None and work_order_sha is not None and capsule_sha is not None:
        binding = _binding_payload(request_sha, work_order_sha, capsule_sha, request, observed)
        binding_sha = sha256_bytes(canonical_json_text(binding).encode("utf-8"))

    return _admission_receipt(generated, checks, request, request_sha, work_order_sha, capsule_sha, observed, binding=binding, binding_sha=binding_sha)


def _admission_receipt(
    generated: str,
    checks: list[dict[str, Any]],
    request: dict[str, Any] | None,
    request_sha: str | None,
    work_order_sha: str | None,
    capsule_sha: str | None,
    observed: dict[str, Any] | None,
    *,
    binding: dict[str, Any] | None = None,
    binding_sha: str | None = None,
) -> dict[str, Any]:
    statuses = {row["status"] for row in checks}
    if "FAIL" in statuses:
        status, outcome = ADMISSION_REVISE, "WOULD_HOLD"
    elif "HOLD" in statuses:
        status, outcome = ADMISSION_HOLD, "WOULD_HOLD"
    else:
        status, outcome = ADMISSION_PASS, "WOULD_ALLOW"
    return {
        "schema": RECEIPT_SCHEMA,
        "generated_at_utc": generated,
        "status": status,
        "outcome": outcome,
        "checks": checks,
        "request": request,
        "request_sha256": request_sha,
        "work_order_sha256": work_order_sha,
        "session_capsule_sha256": capsule_sha,
        "repository_observed": observed,
        "binding": binding,
        "admission_binding_sha256": binding_sha,
        "effect": "VERIFY_ONLY_NO_WRITE",
        "live_state_modified": False,
        "writes_performed": [],
        "can_trade": False,
        "capital_permission": "DENY",
        "deploy_permission": "DENY",
        "self_application": False,
    }


def _validate_admission_binding(receipt: dict[str, Any]) -> tuple[dict[str, Any], str]:
    if receipt.get("schema") != RECEIPT_SCHEMA:
        raise ValueError("admission receipt schema mismatch")
    if receipt.get("status") != ADMISSION_PASS or receipt.get("outcome") != "WOULD_ALLOW":
        raise ValueError("admission receipt did not pass")
    binding = _require_dict(receipt.get("binding"), "admission binding")
    digest = receipt.get("admission_binding_sha256")
    actual = sha256_bytes(canonical_json_text(binding).encode("utf-8"))
    if not isinstance(digest, str) or digest != actual:
        raise ValueError("admission binding SHA mismatch")
    request = normalize_work_admission_request(_require_dict(receipt.get("request"), "admission request"))
    if binding.get("task_id") != request["task"]["task_id"]:
        raise ValueError("admission binding task mismatch")
    if (
        binding.get("scope") != request["scope"]
        or binding.get("workspace") != request["workspace"]
        or binding.get("effects") != request["effects"]
    ):
        raise ValueError("admission binding scope/workspace/effects mismatch")
    return request, digest


def _git_path_exists(repo: Path, revision: str, path: str) -> bool:
    proc = _run(["git", "cat-file", "-e", f"{revision}:{path}"], cwd=repo, check=False)
    return proc.returncode == 0


def _git_blob_size(repo: Path, revision: str, path: str) -> int:
    return int(_git(repo, "cat-file", "-s", f"{revision}:{path}"))


def _parse_name_status(repo: Path, base: str, head: str) -> list[dict[str, str]]:
    raw = _run(["git", "diff", "--name-status", "-z", "--no-renames", base, head], cwd=repo).stdout
    tokens = raw.split("\x00")
    if tokens and tokens[-1] == "":
        tokens.pop()
    if len(tokens) % 2:
        raise ValueError("unexpected git diff --name-status output")
    rows = []
    for index in range(0, len(tokens), 2):
        status, path = tokens[index], tokens[index + 1]
        if status not in {"A", "M", "D", "T", "U"}:
            raise ValueError(f"unsupported Git diff status: {status}")
        path = _safe_rel_path(path, "changed path")
        rows.append({"status": status, "path": path})
    return rows


def _verify_validation_receipt(receipt: dict[str, Any], request: dict[str, Any], binding_sha: str, admission_receipt_sha: str, head: str, tree: str) -> list[str]:
    errors: list[str] = []
    if receipt.get("schema") != VALIDATION_SCHEMA:
        return ["validation receipt schema mismatch"]
    if receipt.get("admission_binding_sha256") != binding_sha:
        errors.append("validation receipt admission binding mismatch")
    if receipt.get("admission_receipt_sha256") != admission_receipt_sha:
        errors.append("validation receipt admission receipt SHA mismatch")
    if receipt.get("base_head") != request["repository"]["base_head"]:
        errors.append("validation receipt base_head mismatch")
    if receipt.get("candidate_head") != head or receipt.get("candidate_tree") != tree:
        errors.append("validation receipt candidate identity mismatch")
    if receipt.get("worktree_clean_after") is not True:
        errors.append("validation receipt does not prove clean worktree")
    commands = receipt.get("commands")
    if not isinstance(commands, list):
        errors.append("validation receipt commands missing")
        commands = []
    by_id: dict[str, dict[str, Any]] = {}
    for row in commands:
        if isinstance(row, dict) and isinstance(row.get("id"), str):
            if row["id"] in by_id:
                errors.append(f"duplicate validation command receipt: {row['id']}")
            by_id[row["id"]] = row
    required_ids = {row["id"] for row in request["validation"]["required_commands"]}
    extra_ids = sorted(set(by_id) - required_ids)
    if extra_ids:
        errors.append("unadmitted validation commands: " + ", ".join(extra_ids))
    for required in request["validation"]["required_commands"]:
        row = by_id.get(required["id"])
        if row is None:
            errors.append(f"missing required validation command: {required['id']}")
            continue
        if row.get("argv") != required["argv"] or row.get("cwd") != required["cwd"]:
            errors.append(f"validation command binding mismatch: {required['id']}")
        if row.get("exit_code") != 0:
            errors.append(f"validation command failed: {required['id']}")
        for label in ("stdout_sha256", "stderr_sha256"):
            value = row.get(label)
            if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
                errors.append(f"validation command {required['id']} has invalid {label}")
    network_used = receipt.get("network_access_used")
    dependency_used = receipt.get("dependency_install_used")
    full_suite_runs = receipt.get("full_suite_runs")
    install_attempts = receipt.get("install_attempts")
    allowed_network = request["validation"]["network_access"]
    if network_used not in {"DENY", "READ_ONLY"} or (allowed_network == "DENY" and network_used != "DENY"):
        errors.append("validation receipt network access exceeds admission")
    allowed_dependency = request["validation"]["dependency_install"]
    if dependency_used not in {"DENY", "LOCKED_ONLY"} or (allowed_dependency == "DENY" and dependency_used != "DENY"):
        errors.append("validation receipt dependency install exceeds admission")
    if not isinstance(full_suite_runs, int) or isinstance(full_suite_runs, bool) or not (0 <= full_suite_runs <= request["validation"]["max_full_suite_runs"]):
        errors.append("validation receipt full_suite_runs exceeds admission")
    if not isinstance(install_attempts, int) or isinstance(install_attempts, bool) or not (0 <= install_attempts <= request["validation"]["max_install_attempts"]):
        errors.append("validation receipt install_attempts exceeds admission")
    effects = receipt.get("effects")
    if not isinstance(effects, dict):
        errors.append("validation receipt effects missing")
    else:
        for key in DANGEROUS_EFFECTS:
            if effects.get(key, False) is not False:
                errors.append(f"validation receipt dangerous effect: {key}")
        if effects.get("can_trade") is not False or effects.get("capital_permission") != "DENY" or effects.get("deploy_permission") != "DENY":
            errors.append("validation receipt effect ceiling widened")
    return errors


def verify_work_delta(
    admission_receipt_path: Path,
    validation_receipt_path: Path,
    repo_path: Path,
    *,
    expected_admission_receipt_sha256: str,
    remote_name: str = "origin",
    check_remote: bool = False,
) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    generated = _now()
    admission_receipt_sha: str | None = None
    try:
        if not isinstance(expected_admission_receipt_sha256, str) or not SHA256_RE.fullmatch(expected_admission_receipt_sha256.lower()):
            raise ValueError("expected admission receipt SHA must be 64 lowercase hex")
        admission_receipt_sha = sha256_file(admission_receipt_path) if admission_receipt_path.is_file() else None
        if admission_receipt_sha != expected_admission_receipt_sha256.lower():
            raise ValueError(
                f"admission receipt SHA mismatch: expected {expected_admission_receipt_sha256.lower()}, observed {admission_receipt_sha}"
            )
        admission = _load_json(admission_receipt_path, "admission receipt")
        request, binding_sha = _validate_admission_binding(admission)
        _check(
            checks,
            "ADMISSION_BINDING",
            "PASS",
            "Admission receipt bytes and binding SHA are valid.",
            admission_binding_sha256=binding_sha,
            admission_receipt_sha256=admission_receipt_sha,
        )
    except Exception as exc:
        _check(checks, "ADMISSION_BINDING", "FAIL", f"{type(exc).__name__}: {exc}")
        return _delta_receipt(generated, checks, None, None, None, None, None)

    observed: dict[str, Any] | None = None
    try:
        observed = _observed_repository(repo_path, remote_name)
        head = observed["head"]
        tree = observed["tree"]
        errors = []
        if observed["branch"] != request["repository"]["candidate_branch"]:
            errors.append("current branch is not the admitted candidate branch")
        if not observed["worktree_clean"]:
            errors.append("candidate worktree is dirty")
        if observed.get("active_operations"):
            errors.append("candidate has an active Git operation")
        if observed.get("git_fsck") != "PASS":
            errors.append("candidate git fsck failed")
        try:
            if _canonical_github_repo(observed["remote_url"]) != _canonical_github_repo(request["repository"]["remote_url"]):
                errors.append("candidate remote repository mismatch")
        except Exception as exc:
            errors.append(f"candidate remote URL invalid: {exc}")
        workspace = request["workspace"]
        candidate_path = Path(observed["path"])
        if any(_under_host_prefix(candidate_path, prefix) for prefix in workspace["forbidden_root_prefixes"]):
            errors.append("candidate repository is under a forbidden workspace root")
        if workspace["mode"] == "DISPOSABLE_CLONE_REQUIRED" and not any(
            _under_host_prefix(candidate_path, prefix) for prefix in workspace["allowed_root_prefixes"]
        ):
            errors.append("candidate repository is outside every allowed disposable workspace root")
        diff_check = _run(
            ["git", "diff", "--check", request["repository"]["base_head"], observed["head"]],
            cwd=Path(observed["path"]), check=False,
        )
        if diff_check.returncode != 0:
            errors.append("git diff --check failed")
        base = request["repository"]["base_head"]
        merge_base = _git(Path(observed["path"]), "merge-base", base, head)
        if merge_base != base:
            errors.append("candidate is not a linear descendant of the admitted base")
        merge_commits = _git(Path(observed["path"]), "rev-list", "--merges", f"{base}..{head}")
        if merge_commits:
            errors.append("candidate contains merge commits")
        commit_count = int(_git(Path(observed["path"]), "rev-list", "--count", f"{base}..{head}"))
        if commit_count < 1:
            errors.append("candidate contains no new commit")
        if commit_count > request["scope"]["max_commits"]:
            errors.append("candidate exceeds max_commits")
        observed["commit_count"] = commit_count
        if errors:
            _check(checks, "CANDIDATE_IDENTITY", "FAIL", "; ".join(errors), observed=observed)
        else:
            _check(checks, "CANDIDATE_IDENTITY", "PASS", "Candidate branch is a clean linear descendant of the admitted base.", observed=observed)
    except Exception as exc:
        _check(checks, "CANDIDATE_IDENTITY", "FAIL", f"{type(exc).__name__}: {exc}")

    changed_rows: list[dict[str, Any]] = []
    if observed is not None:
        try:
            repo = Path(observed["path"])
            base = request["repository"]["base_head"]
            head = observed["head"]
            scope = request["scope"]
            rows = _parse_name_status(repo, base, head)
            errors = []
            total_added_bytes = 0
            binary_paths: list[str] = []
            for row in rows:
                path = row["path"]
                status = row["status"]
                allowed = any(_path_is_within(path, prefix) for prefix in scope["allowed_paths"])
                forbidden = any(_path_is_within(path, prefix) for prefix in scope["forbidden_paths"])
                blocker = _globally_blocked_path(path, allow_archive_files=scope["allow_archive_files"])
                if not allowed:
                    errors.append(f"path outside allowed scope: {path}")
                if forbidden:
                    errors.append(f"path inside forbidden scope: {path}")
                if blocker:
                    errors.append(f"protected path {path}: {blocker}")
                if _path_is_within(path, ".github/workflows") and not request["effects"]["workflow_changes"]:
                    errors.append(f"workflow change not admitted: {path}")
                if status in {"T", "U"}:
                    errors.append(f"Git type/unmerged change not admitted: {path}")
                if status == "A" and not scope["allow_new_files"]:
                    errors.append(f"new file not admitted: {path}")
                if status == "D" and not scope["allow_deletions"]:
                    errors.append(f"deletion not admitted: {path}")
                new_mode = None
                if status != "D" and _git_path_exists(repo, head, path):
                    ls_tree = _git(repo, "ls-tree", head, "--", path)
                    new_mode = ls_tree.split()[0] if ls_tree else None
                    if new_mode in {"120000", "160000"}:
                        errors.append(f"symlink or submodule not admitted: {path}")
                new_size = _git_blob_size(repo, head, path) if status != "D" and _git_path_exists(repo, head, path) else 0
                old_size = _git_blob_size(repo, base, path) if status != "A" and _git_path_exists(repo, base, path) else 0
                added = max(0, new_size - old_size)
                total_added_bytes += added
                binary_probe = _run(["git", "diff", "--numstat", base, head, "--", path], cwd=repo).stdout.strip()
                is_binary = binary_probe.startswith("-\t-")
                if is_binary:
                    binary_paths.append(path)
                    if not scope["allow_binary_files"]:
                        errors.append(f"binary file not admitted: {path}")
                changed_rows.append({
                    "status": status,
                    "path": path,
                    "old_bytes": old_size,
                    "new_bytes": new_size,
                    "positive_byte_delta": added,
                    "binary": is_binary,
                    "git_mode": new_mode,
                })
            if len(rows) > scope["max_changed_files"]:
                errors.append("candidate exceeds max_changed_files")
            if total_added_bytes > scope["max_added_bytes"]:
                errors.append("candidate exceeds max_added_bytes")
            if not rows:
                _check(checks, "DELTA_SCOPE", "HOLD", "Candidate contains no changed files.")
            elif errors:
                _check(checks, "DELTA_SCOPE", "FAIL", "; ".join(errors), changed_files=len(rows), positive_byte_delta=total_added_bytes, binary_paths=binary_paths)
            else:
                _check(checks, "DELTA_SCOPE", "PASS", "All candidate paths and size/commit limits are inside the admitted scope.", changed_files=len(rows), positive_byte_delta=total_added_bytes, binary_paths=binary_paths)
        except Exception as exc:
            _check(checks, "DELTA_SCOPE", "FAIL", f"{type(exc).__name__}: {exc}")

    validation: dict[str, Any] | None = None
    validation_sha: str | None = None
    if observed is not None:
        try:
            validation_sha = sha256_file(validation_receipt_path) if validation_receipt_path.is_file() else None
            validation = _load_json(validation_receipt_path, "validation receipt")
            errors = _verify_validation_receipt(validation, request, binding_sha, admission_receipt_sha or "", observed["head"], observed["tree"])
            if errors:
                _check(checks, "VALIDATION_RECEIPT", "FAIL", "; ".join(errors))
            else:
                _check(checks, "VALIDATION_RECEIPT", "PASS", "Required validation commands and no-effect ceiling are bound to the exact candidate.")
        except Exception as exc:
            _check(checks, "VALIDATION_RECEIPT", "FAIL", f"{type(exc).__name__}: {exc}")

    remote_mode = request["repository"]["remote_readback_mode"]
    if not request["effects"]["candidate_push"]:
        _check(checks, "CANDIDATE_REMOTE", "PASS", "Candidate push is outside this work order; no remote candidate check required.")
    elif remote_mode == "DENY":
        _check(checks, "CANDIDATE_REMOTE", "PASS", "Remote checks are explicitly denied; push must be handled by a later transport order.")
    elif not check_remote:
        status = "HOLD" if remote_mode == "REQUIRED" else "WARN"
        _check(checks, "CANDIDATE_REMOTE", status, "Remote candidate readback was not executed.")
    else:
        try:
            remote_candidate = _ls_remote(request["repository"]["remote_url"], request["repository"]["candidate_branch"])
            expected_existing = request["repository"]["existing_candidate_head"]
            if remote_candidate not in {None, expected_existing, observed["head"] if observed else None}:
                _check(checks, "CANDIDATE_REMOTE", "FAIL", "Remote candidate branch conflicts with this admitted line.", remote_candidate=remote_candidate)
            else:
                _check(checks, "CANDIDATE_REMOTE", "PASS", "Remote candidate branch is absent or exact.", remote_candidate=remote_candidate)
        except ConnectionError as exc:
            status = "HOLD" if remote_mode == "REQUIRED" else "WARN"
            _check(checks, "CANDIDATE_REMOTE", status, f"Remote candidate readback unavailable: {exc}")
        except Exception as exc:
            _check(checks, "CANDIDATE_REMOTE", "FAIL", f"{type(exc).__name__}: {exc}")

    return _delta_receipt(generated, checks, request, binding_sha, observed, changed_rows, validation, validation_sha, admission_receipt_sha)


def _delta_receipt(
    generated: str,
    checks: list[dict[str, Any]],
    request: dict[str, Any] | None,
    binding_sha: str | None,
    observed: dict[str, Any] | None,
    changed_rows: list[dict[str, Any]] | None,
    validation: dict[str, Any] | None,
    validation_sha: str | None = None,
    admission_receipt_sha: str | None = None,
) -> dict[str, Any]:
    statuses = {row["status"] for row in checks}
    if "FAIL" in statuses:
        status, outcome = DELTA_REVISE, "WOULD_HOLD"
    elif "HOLD" in statuses:
        status, outcome = DELTA_HOLD, "WOULD_HOLD"
    else:
        status, outcome = DELTA_PASS, "WOULD_ALLOW_CANDIDATE_TRANSPORT"
    return {
        "schema": DELTA_SCHEMA,
        "generated_at_utc": generated,
        "status": status,
        "outcome": outcome,
        "checks": checks,
        "task_id": request["task"]["task_id"] if request else None,
        "admission_binding_sha256": binding_sha,
        "admission_receipt_sha256": admission_receipt_sha,
        "repository_observed": observed,
        "changed_files": changed_rows or [],
        "validation_receipt_sha256": validation_sha,
        "effect": "VERIFY_ONLY_NO_WRITE",
        "live_state_modified": False,
        "writes_performed": [],
        "can_trade": False,
        "capital_permission": "DENY",
        "deploy_permission": "DENY",
        "self_application": False,
    }


def exit_code_for_work_admission(receipt: dict[str, Any]) -> int:
    return {ADMISSION_PASS: 0, ADMISSION_HOLD: 1, ADMISSION_REVISE: 2}.get(receipt.get("status"), 2)


def exit_code_for_work_delta(receipt: dict[str, Any]) -> int:
    return {DELTA_PASS: 0, DELTA_HOLD: 1, DELTA_REVISE: 2}.get(receipt.get("status"), 2)
