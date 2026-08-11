"""Deterministic raw-evidence execution for admitted GitHub work.

This module closes the gap between a declarative validation receipt and the
actual stdout/stderr bytes produced by the admitted command vectors.

The execution path is deliberately narrow:

* it accepts only a previously PASSed work-admission receipt;
* it executes only the exact argv/cwd vectors embedded in that receipt;
* it never invokes a shell;
* it writes evidence outside the repository;
* it binds raw stdout/stderr bytes, command metadata and Git identity into one
  manifest-backed evidence directory;
* it never pushes, merges, deploys, applies authority/state, trades or uses
  capital.

``execute_work_validation`` performs the admitted commands and writes the
artifact set.  ``verify_work_validation_evidence`` independently re-reads those
artifacts and recomputes every relevant hash before a later delta gate can rely
on them.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import signal
import subprocess
import threading
import time
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any

from .work_admission import (
    DANGEROUS_EFFECTS,
    SHA256_RE,
    VALIDATION_SCHEMA,
    _canonical_github_repo,
    _load_json,
    _observed_repository,
    _require_dict,
    _under_host_prefix,
    _validate_admission_binding,
    _verify_validation_receipt,
    canonical_json_text,
    sha256_bytes,
    sha256_file,
)

EXECUTION_SCHEMA = "continuityos.work_validation.execution_receipt/v1"
MANIFEST_SCHEMA = "continuityos.work_validation.evidence_manifest/v1"
READY_SCHEMA = "continuityos.work_validation.ready/v1"
VERIFICATION_SCHEMA = "continuityos.work_validation.evidence_verification/v1"

EXECUTION_PASS = "WORK_VALIDATION_EXECUTION_PASS"
EXECUTION_REVISE = "WORK_VALIDATION_EXECUTION_REVISE"
EXECUTION_HOLD = "WORK_VALIDATION_EXECUTION_HOLD"
EVIDENCE_PASS = "WORK_VALIDATION_EVIDENCE_PASS"
EVIDENCE_REVISE = "WORK_VALIDATION_EVIDENCE_REVISE"
EVIDENCE_HOLD = "WORK_VALIDATION_EVIDENCE_HOLD"

RECEIPT_NAME = "WORK_VALIDATION_RECEIPT.json"
NO_EFFECT_NAME = "NO_EFFECT_RECEIPT.json"
MANIFEST_NAME = "MANIFEST.json"
READY_NAME = "READY_FOR_VERIFY.json"
RAW_DIR = "raw"

MAX_EVIDENCE_FILES = 512
MAX_EVIDENCE_FILE_BYTES = 128 * 1024 * 1024
MAX_MANIFEST_BYTES = 4 * 1024 * 1024
POLL_INTERVAL_SECONDS = 0.05

NETWORK_EXECUTABLES = {
    "curl", "curl.exe", "wget", "wget.exe", "ssh", "ssh.exe", "scp", "scp.exe",
    "sftp", "sftp.exe", "ftp", "ftp.exe", "gh", "gh.exe",
}
INSTALL_EXECUTABLES = {
    "pip", "pip.exe", "pip3", "pip3.exe", "npm", "npm.cmd", "pnpm", "pnpm.cmd",
    "yarn", "yarn.cmd", "uv", "uv.exe",
}
COMMAND_KINDS = {"FOCUSED", "FULL_SUITE", "BUILD", "STATIC", "SECURITY", "OTHER"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _safe_evidence_rel_path(value: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise ValueError("evidence path must be a non-empty POSIX relative path")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError("evidence path is unsafe")
    if re.match(r"^[A-Za-z]:", value):
        raise ValueError("evidence path must not be a Windows drive path")
    return str(path)


def _path_is_under(path: Path, parent: Path) -> bool:
    try:
        path.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


def _reject_symlink_chain(path: Path) -> None:
    probe = path
    isjunction = getattr(os.path, "isjunction", lambda _: False)
    while True:
        if probe.exists() and (probe.is_symlink() or isjunction(probe)):
            raise ValueError(f"symlinked/junction evidence or workspace path is not allowed: {probe}")
        if probe.parent == probe:
            break
        probe = probe.parent


def _prepare_output_dir(output_dir: Path, repo: Path, request: dict[str, Any]) -> Path:
    output_dir = output_dir.expanduser()
    if not output_dir.is_absolute():
        raise ValueError("output directory must be an absolute host path")
    _reject_symlink_chain(output_dir)
    repo_resolved = repo.expanduser().resolve()
    output_resolved = output_dir.resolve(strict=False)
    if output_resolved == repo_resolved or _path_is_under(output_resolved, repo_resolved):
        raise ValueError("validation evidence must be outside the repository")

    workspace = request["workspace"]
    if any(_under_host_prefix(output_resolved, prefix) for prefix in workspace["forbidden_root_prefixes"]):
        raise ValueError("validation evidence output is under a forbidden workspace root")
    if workspace["mode"] == "DISPOSABLE_CLONE_REQUIRED" and not any(
        _under_host_prefix(output_resolved, prefix) for prefix in workspace["allowed_root_prefixes"]
    ):
        raise ValueError("validation evidence output is outside admitted disposable roots")

    if output_dir.exists():
        if not output_dir.is_dir():
            raise ValueError("output path exists and is not a directory")
        if any(output_dir.iterdir()):
            raise ValueError("output directory must be empty")
    else:
        output_dir.mkdir(parents=True, exist_ok=False)
    (output_dir / RAW_DIR).mkdir()
    return output_dir.resolve()


def _command_cwd(repo: Path, value: str) -> Path:
    if value == "repo":
        cwd = repo.resolve()
    else:
        cwd = (repo / value).resolve()
        if not _path_is_under(cwd, repo.resolve()):
            raise ValueError(f"validation cwd escapes repository: {value}")
    if not cwd.is_dir():
        raise ValueError(f"validation cwd is not a directory: {value}")
    return cwd


def _looks_like_install(argv: list[str]) -> bool:
    executable = Path(argv[0]).name.lower()
    lowered = [item.lower() for item in argv[1:]]
    if executable in {"python", "python.exe", "py", "py.exe"} and len(lowered) >= 2:
        if lowered[0] == "-m" and lowered[1] in {"pip", "uv"}:
            return any(token in lowered[2:] for token in {"install", "sync"})
    if executable in INSTALL_EXECUTABLES:
        return any(token in lowered for token in {"install", "ci", "sync", "add"})
    return False


def _looks_like_network(argv: list[str]) -> bool:
    executable = Path(argv[0]).name.lower()
    lowered = [item.lower() for item in argv[1:]]
    if executable in NETWORK_EXECUTABLES:
        return True
    if executable in {"git", "git.exe"} and lowered:
        return lowered[0] in {"clone", "fetch", "pull", "push", "ls-remote", "remote"}
    if executable in {"python", "python.exe", "py", "py.exe"} and len(lowered) >= 2:
        if lowered[0] == "-m" and lowered[1] == "http.server":
            return True
        if lowered[0] == "-m" and lowered[1] == "pip":
            return any(token in lowered[2:] for token in {"install", "download", "index", "search", "wheel"})
    if executable in {"npm", "npm.cmd", "pnpm", "pnpm.cmd", "yarn", "yarn.cmd"}:
        return any(token in lowered for token in {"install", "ci", "add", "view", "info", "search", "publish"})
    return False


def _kill_process(proc: subprocess.Popen[Any]) -> None:
    if proc.poll() is not None:
        return
    try:
        if os.name == "nt":
            subprocess.run(
                ["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                capture_output=True,
                check=False,
            )
        else:
            os.killpg(proc.pid, signal.SIGTERM)
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                os.killpg(proc.pid, signal.SIGKILL)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass


def _bounded_command(
    argv: list[str],
    *,
    cwd: Path,
    stdout_path: Path,
    stderr_path: Path,
    timeout_seconds: int,
    max_stdout_bytes: int,
    max_stderr_bytes: int,
    max_total_output_bytes: int,
) -> dict[str, Any]:
    """Execute one argv vector while hard-bounding captured output.

    Pipes are drained by two reader threads.  Bytes are written only while both
    the stream-specific and shared total budgets permit it.  The first byte
    beyond either budget sets a limit event and the process group is stopped.
    This avoids the potentially large overshoot inherent in polling file sizes
    after redirecting an unconstrained producer directly to disk.
    """

    started = time.monotonic()
    timed_out = False
    output_limit_exceeded = False
    creationflags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) if os.name == "nt" else 0
    proc = subprocess.Popen(
        argv,
        cwd=str(cwd),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False,
        start_new_session=os.name != "nt",
        creationflags=creationflags,
        bufsize=0,
    )
    if proc.stdout is None or proc.stderr is None:  # pragma: no cover - defensive
        _kill_process(proc)
        raise RuntimeError("validation subprocess pipes were not created")

    limit_event = threading.Event()
    lock = threading.Lock()
    total_written = 0
    reader_errors: list[str] = []
    stream_sizes = {"stdout": 0, "stderr": 0}

    def drain(stream: Any, destination: Path, label: str, stream_cap: int) -> None:
        nonlocal total_written
        try:
            with destination.open("wb") as output:
                while True:
                    # ``BufferedReader.read(n)`` may wait for a large request to
                    # fill while the child is simultaneously blocked on a much
                    # smaller OS pipe.  ``os.read`` returns the bytes currently
                    # available and therefore drains high-volume producers
                    # without a pipe-size deadlock.
                    chunk = os.read(stream.fileno(), 64 * 1024)
                    if not chunk:
                        break
                    with lock:
                        stream_remaining = max(0, stream_cap - stream_sizes[label])
                        total_remaining = max(0, max_total_output_bytes - total_written)
                        writable = min(len(chunk), stream_remaining, total_remaining)
                        if writable:
                            output.write(chunk[:writable])
                            stream_sizes[label] += writable
                            total_written += writable
                        if writable < len(chunk):
                            limit_event.set()
                            break
        except Exception as exc:  # pragma: no cover - rare host I/O failure
            with lock:
                reader_errors.append(f"{label}: {type(exc).__name__}: {exc}")
            limit_event.set()
        finally:
            try:
                stream.close()
            except Exception:
                pass

    stdout_thread = threading.Thread(
        target=drain,
        args=(proc.stdout, stdout_path, "stdout", max_stdout_bytes),
        name="continuity-validation-stdout",
        daemon=True,
    )
    stderr_thread = threading.Thread(
        target=drain,
        args=(proc.stderr, stderr_path, "stderr", max_stderr_bytes),
        name="continuity-validation-stderr",
        daemon=True,
    )
    stdout_thread.start()
    stderr_thread.start()

    while proc.poll() is None:
        elapsed = time.monotonic() - started
        if elapsed > timeout_seconds:
            timed_out = True
            _kill_process(proc)
            break
        if limit_event.is_set():
            output_limit_exceeded = True
            _kill_process(proc)
            break
        time.sleep(POLL_INTERVAL_SECONDS)

    try:
        exit_code = proc.wait(timeout=5)
    except subprocess.TimeoutExpired:  # pragma: no cover - defensive
        _kill_process(proc)
        exit_code = proc.wait(timeout=5)

    stdout_thread.join(timeout=5)
    stderr_thread.join(timeout=5)
    # A short-lived process can exit before the polling loop observes
    # ``limit_event``.  Reader threads may then discover truncation only while
    # they drain the remaining pipe bytes.  Re-read the event after both joins
    # so an exceeded cap can never be reported as PASS.
    if limit_event.is_set():
        output_limit_exceeded = True
    if stdout_thread.is_alive() or stderr_thread.is_alive():  # pragma: no cover - defensive
        output_limit_exceeded = True
        reader_errors.append("reader thread did not terminate")
    if reader_errors:
        output_limit_exceeded = True

    stdout_size = stdout_path.stat().st_size if stdout_path.exists() else 0
    stderr_size = stderr_path.stat().st_size if stderr_path.exists() else 0
    return {
        "exit_code": exit_code,
        "duration_ms": int((time.monotonic() - started) * 1000),
        "timed_out": timed_out,
        "output_limit_exceeded": output_limit_exceeded,
        "truncated": output_limit_exceeded,
        "stdout_size_bytes": stdout_size,
        "stderr_size_bytes": stderr_size,
        "stdout_sha256": sha256_file(stdout_path),
        "stderr_sha256": sha256_file(stderr_path),
        "reader_errors": reader_errors,
    }


def _candidate_identity(repo: Path, remote_name: str) -> dict[str, Any]:
    return _observed_repository(repo, remote_name)


def _candidate_errors(observed: dict[str, Any], request: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    repo = Path(observed["path"])
    workspace = request["workspace"]
    if any(_under_host_prefix(repo, prefix) for prefix in workspace["forbidden_root_prefixes"]):
        errors.append("candidate repository is under a forbidden workspace root")
    if workspace["mode"] == "DISPOSABLE_CLONE_REQUIRED" and not any(
        _under_host_prefix(repo, prefix) for prefix in workspace["allowed_root_prefixes"]
    ):
        errors.append("candidate repository is outside every allowed disposable workspace root")
    if observed["branch"] != request["repository"]["candidate_branch"]:
        errors.append("repository is not on the admitted candidate branch")
    if not observed["worktree_clean"]:
        errors.append("repository worktree is not clean")
    if observed.get("active_operations"):
        errors.append("repository has an active Git operation")
    if observed.get("git_fsck") != "PASS":
        errors.append("git fsck failed")
    try:
        if _canonical_github_repo(observed["remote_url"]) != _canonical_github_repo(request["repository"]["remote_url"]):
            errors.append("repository remote identity mismatch")
    except Exception as exc:
        errors.append(f"repository remote URL invalid: {exc}")
    base = request["repository"]["base_head"]
    head = observed["head"]
    merge_base = subprocess.run(
        ["git", "merge-base", base, head], cwd=repo, text=True, capture_output=True, check=False
    )
    if merge_base.returncode != 0 or merge_base.stdout.strip() != base:
        errors.append("candidate is not a linear descendant of the admitted base")
    merge_commits = subprocess.run(
        ["git", "rev-list", "--merges", f"{base}..{head}"],
        cwd=repo,
        text=True,
        capture_output=True,
        check=False,
    )
    if merge_commits.returncode != 0 or merge_commits.stdout.strip():
        errors.append("candidate contains merge commits")
    return errors


def _effects_receipt() -> dict[str, Any]:
    return {
        **{key: False for key in DANGEROUS_EFFECTS},
        "can_trade": False,
        "capital_permission": "DENY",
        "deploy_permission": "DENY",
    }


def _manifest_rows(output_dir: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path in sorted(output_dir.rglob("*")):
        if not path.is_file() or path.name in {MANIFEST_NAME, READY_NAME}:
            continue
        rel = path.relative_to(output_dir).as_posix()
        rows.append({"path": rel, "bytes": path.stat().st_size, "sha256": sha256_file(path)})
    return rows


def execute_work_validation(
    admission_receipt_path: Path,
    repo_path: Path,
    output_dir: Path,
    *,
    expected_admission_receipt_sha256: str,
    remote_name: str = "origin",
) -> dict[str, Any]:
    generated = _now()
    admission_receipt_path = admission_receipt_path.expanduser()
    repo = repo_path.expanduser().resolve()
    admission_sha = sha256_file(admission_receipt_path) if admission_receipt_path.is_file() else None
    if not isinstance(expected_admission_receipt_sha256, str) or not SHA256_RE.fullmatch(
        expected_admission_receipt_sha256.lower()
    ):
        raise ValueError("expected admission receipt SHA must be 64 lowercase hex")
    if admission_sha != expected_admission_receipt_sha256.lower():
        raise ValueError(
            f"admission receipt SHA mismatch: expected {expected_admission_receipt_sha256.lower()}, observed {admission_sha}"
        )
    admission = _load_json(admission_receipt_path, "admission receipt")
    request, binding_sha = _validate_admission_binding(admission)

    observed_before = _candidate_identity(repo, remote_name)
    identity_errors = _candidate_errors(observed_before, request)
    if identity_errors:
        raise ValueError("; ".join(identity_errors))

    output = _prepare_output_dir(output_dir, repo, request)
    validation = request["validation"]
    max_total_output = validation["max_total_output_bytes"]
    commands: list[dict[str, Any]] = []
    failed = False
    total_output_bytes = 0
    full_suite_runs = 0
    install_attempts = 0
    network_detected = False
    install_detected = False

    for command in validation["required_commands"]:
        command_id = command["id"]
        stdout_rel = f"{RAW_DIR}/{command_id}.stdout.bin"
        stderr_rel = f"{RAW_DIR}/{command_id}.stderr.bin"
        stdout_path = output / stdout_rel
        stderr_path = output / stderr_rel
        argv = list(command["argv"])
        cwd = _command_cwd(repo, command["cwd"])
        kind = command["kind"]
        is_network = _looks_like_network(argv)
        is_install = _looks_like_install(argv)
        network_detected = network_detected or is_network
        install_detected = install_detected or is_install
        if is_install:
            install_attempts += 1
        if is_network:
            result = {
                "exit_code": None,
                "duration_ms": 0,
                "timed_out": False,
                "output_limit_exceeded": False,
                "truncated": False,
                "stdout_size_bytes": 0,
                "stderr_size_bytes": 0,
                "stdout_sha256": hashlib.sha256(b"").hexdigest(),
                "stderr_sha256": hashlib.sha256(b"").hexdigest(),
                "policy_error": (
                    "direct network-capable commands are not executed by the validation runner; "
                    "authenticated transport and remote readback remain separate gates"
                ),
            }
            stdout_path.write_bytes(b"")
            stderr_path.write_bytes(b"")
            failed = True
        elif is_install:
            result = {
                "exit_code": None,
                "duration_ms": 0,
                "timed_out": False,
                "output_limit_exceeded": False,
                "truncated": False,
                "stdout_size_bytes": 0,
                "stderr_size_bytes": 0,
                "stdout_sha256": hashlib.sha256(b"").hexdigest(),
                "stderr_sha256": hashlib.sha256(b"").hexdigest(),
                "policy_error": (
                    "dependency installation is not executed by the validation runner; "
                    "a separate lockfile-bound setup receipt is required"
                ),
            }
            stdout_path.write_bytes(b"")
            stderr_path.write_bytes(b"")
            failed = True
        elif failed and not validation["continue_on_failure"]:
            stdout_path.write_bytes(b"")
            stderr_path.write_bytes(b"")
            result = {
                "exit_code": None,
                "duration_ms": 0,
                "timed_out": False,
                "output_limit_exceeded": False,
                "truncated": False,
                "stdout_size_bytes": 0,
                "stderr_size_bytes": 0,
                "stdout_sha256": hashlib.sha256(b"").hexdigest(),
                "stderr_sha256": hashlib.sha256(b"").hexdigest(),
                "policy_error": "skipped after earlier validation failure",
            }
        else:
            try:
                result = _bounded_command(
                    argv,
                    cwd=cwd,
                    stdout_path=stdout_path,
                    stderr_path=stderr_path,
                    timeout_seconds=command["timeout_seconds"],
                    max_stdout_bytes=command["max_stdout_bytes"],
                    max_stderr_bytes=command["max_stderr_bytes"],
                    max_total_output_bytes=max_total_output - total_output_bytes,
                )
            except Exception as exc:
                if not stdout_path.exists():
                    stdout_path.write_bytes(b"")
                stderr_path.write_bytes((f"{type(exc).__name__}: {exc}\n").encode("utf-8", errors="replace"))
                result = {
                    "exit_code": None,
                    "duration_ms": 0,
                    "timed_out": False,
                    "output_limit_exceeded": False,
                    "truncated": False,
                    "stdout_size_bytes": stdout_path.stat().st_size,
                    "stderr_size_bytes": stderr_path.stat().st_size,
                    "stdout_sha256": sha256_file(stdout_path),
                    "stderr_sha256": sha256_file(stderr_path),
                    "policy_error": f"command launch failed: {type(exc).__name__}: {exc}",
                }
            total_output_bytes += result["stdout_size_bytes"] + result["stderr_size_bytes"]
            if kind == "FULL_SUITE":
                full_suite_runs += 1
            if (
                result["exit_code"] != 0
                or result["timed_out"]
                or result["output_limit_exceeded"]
                or result["truncated"]
            ):
                failed = True
        commands.append(
            {
                "id": command_id,
                "argv": argv,
                "cwd": command["cwd"],
                "kind": kind,
                "timeout_seconds": command["timeout_seconds"],
                "max_stdout_bytes": command["max_stdout_bytes"],
                "max_stderr_bytes": command["max_stderr_bytes"],
                "stdout_path": stdout_rel,
                "stderr_path": stderr_rel,
                **result,
            }
        )

    observed_after = _candidate_identity(repo, remote_name)
    identity_after_errors = _candidate_errors(observed_after, request)
    if (
        observed_after["head"] != observed_before["head"]
        or observed_after["tree"] != observed_before["tree"]
        or observed_after["branch"] != observed_before["branch"]
    ):
        identity_after_errors.append("candidate Git identity changed during validation")
    if identity_after_errors:
        failed = True

    if full_suite_runs > validation["max_full_suite_runs"]:
        failed = True
    if install_attempts > validation["max_install_attempts"]:
        failed = True
    if total_output_bytes > max_total_output:
        failed = True

    status = EXECUTION_REVISE if failed else EXECUTION_PASS
    validation_receipt = {
        "schema": VALIDATION_SCHEMA,
        "execution_schema": EXECUTION_SCHEMA,
        "generated_at_utc": generated,
        "status": status,
        "admission_binding_sha256": binding_sha,
        "admission_receipt_sha256": admission_sha,
        "base_head": request["repository"]["base_head"],
        "candidate_head": observed_after["head"],
        "candidate_tree": observed_after["tree"],
        "candidate_branch": observed_after["branch"],
        "repository_remote": observed_after["remote_url"],
        "worktree_clean_before": observed_before["worktree_clean"],
        "worktree_clean_after": observed_after["worktree_clean"],
        "repository_before": observed_before,
        "repository_after": observed_after,
        "commands": commands,
        "network_access_used": "DENY",
        "dependency_install_used": "DENY",
        "direct_network_command_attempted": network_detected,
        "dependency_install_command_attempted": install_detected,
        "full_suite_runs": full_suite_runs,
        "install_attempts": install_attempts,
        "total_output_bytes": total_output_bytes,
        "raw_evidence_required": validation["raw_evidence_required"],
        "effects": _effects_receipt(),
        "identity_errors": identity_after_errors,
        "effect": "ADMITTED_TEST_EXECUTION_AND_EVIDENCE_WRITE_ONLY",
        "live_state_modified": False,
        "writes_performed": [str(output)],
        "can_trade": False,
        "capital_permission": "DENY",
        "deploy_permission": "DENY",
        "self_application": False,
    }
    _write_json(output / RECEIPT_NAME, validation_receipt)
    _write_json(
        output / NO_EFFECT_NAME,
        {
            "schema": "continuityos.work_validation.no_effect/v1",
            "repository_head_unchanged": observed_before["head"] == observed_after["head"],
            "repository_tree_unchanged": observed_before["tree"] == observed_after["tree"],
            "repository_branch_unchanged": observed_before["branch"] == observed_after["branch"],
            "worktree_clean_before": observed_before["worktree_clean"],
            "worktree_clean_after": observed_after["worktree_clean"],
            "force_push": False,
            "merge": False,
            "pull_request_merge": False,
            "deployment": False,
            "registry_apply": False,
            "current_state_apply": False,
            "r63_apply": False,
            "trading": False,
            "wallet_access": False,
            "order_execution": False,
            "external_message": False,
            "self_application": False,
            "can_trade": False,
            "capital_permission": "DENY",
            "deploy_permission": "DENY",
        },
    )
    manifest = {
        "schema": MANIFEST_SCHEMA,
        "created_at_utc": _now(),
        "files": _manifest_rows(output),
    }
    _write_json(output / MANIFEST_NAME, manifest)
    ready = {
        "schema": READY_SCHEMA,
        "created_at_utc": _now(),
        "status": status,
        "validation_receipt_sha256": sha256_file(output / RECEIPT_NAME),
        "manifest_sha256": sha256_file(output / MANIFEST_NAME),
        "candidate_head": observed_after["head"],
        "candidate_tree": observed_after["tree"],
        "written_last": True,
    }
    _write_json(output / READY_NAME, ready)
    return {
        "schema": EXECUTION_SCHEMA,
        "status": status,
        "output_dir": str(output),
        "validation_receipt": str(output / RECEIPT_NAME),
        "validation_receipt_sha256": ready["validation_receipt_sha256"],
        "manifest_sha256": ready["manifest_sha256"],
        "candidate_head": observed_after["head"],
        "candidate_tree": observed_after["tree"],
        "can_trade": False,
        "capital_permission": "DENY",
        "deploy_permission": "DENY",
        "self_application": False,
    }


def _load_manifest(path: Path) -> dict[str, Any]:
    if not path.is_file() or path.stat().st_size > MAX_MANIFEST_BYTES:
        raise ValueError("validation evidence manifest is missing or oversized")
    value = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict) or value.get("schema") != MANIFEST_SCHEMA:
        raise ValueError("validation evidence manifest schema mismatch")
    return value


def verify_work_validation_evidence(
    evidence_dir: Path,
    admission_receipt_path: Path,
    repo_path: Path,
    *,
    expected_admission_receipt_sha256: str,
    remote_name: str = "origin",
) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    evidence_dir = evidence_dir.expanduser()
    repo = repo_path.expanduser().resolve()

    def add(check_id: str, status: str, detail: str, **evidence: Any) -> None:
        row: dict[str, Any] = {"id": check_id, "status": status, "detail": detail}
        if evidence:
            row["evidence"] = evidence
        checks.append(row)

    admission_sha: str | None = None
    request: dict[str, Any] | None = None
    binding_sha: str | None = None
    try:
        if not evidence_dir.is_dir():
            raise ValueError("validation evidence directory is missing")
        if evidence_dir.is_symlink():
            raise ValueError("validation evidence directory may not be a symlink")
        if _path_is_under(evidence_dir.resolve(), repo):
            raise ValueError("validation evidence directory is inside repository")
        files = [p for p in evidence_dir.rglob("*") if p.is_file()]
        if len(files) > MAX_EVIDENCE_FILES:
            raise ValueError("validation evidence contains too many files")
        symlinks = [str(p) for p in evidence_dir.rglob("*") if p.is_symlink()]
        if symlinks:
            raise ValueError(f"validation evidence contains symlinks: {symlinks[:10]}")
        oversized = [str(p) for p in files if p.stat().st_size > MAX_EVIDENCE_FILE_BYTES]
        if oversized:
            raise ValueError(f"validation evidence contains oversized files: {oversized[:10]}")
        add("EVIDENCE_ROOT", "PASS", "Evidence root is bounded, outside the repository and symlink-free.")
    except Exception as exc:
        add("EVIDENCE_ROOT", "FAIL", f"{type(exc).__name__}: {exc}")

    try:
        admission_sha = sha256_file(admission_receipt_path) if admission_receipt_path.is_file() else None
        if admission_sha != expected_admission_receipt_sha256.lower():
            raise ValueError("admission receipt SHA mismatch")
        admission = _load_json(admission_receipt_path, "admission receipt")
        request, binding_sha = _validate_admission_binding(admission)
        add("ADMISSION_BINDING", "PASS", "Admission receipt bytes and binding are exact.")
    except Exception as exc:
        add("ADMISSION_BINDING", "FAIL", f"{type(exc).__name__}: {exc}")

    receipt: dict[str, Any] | None = None
    manifest_sha: str | None = None
    ready: dict[str, Any] | None = None
    try:
        required = [RECEIPT_NAME, NO_EFFECT_NAME, MANIFEST_NAME, READY_NAME]
        missing = [name for name in required if not (evidence_dir / name).is_file()]
        if missing:
            raise ValueError("missing required evidence files: " + ", ".join(missing))
        manifest = _load_manifest(evidence_dir / MANIFEST_NAME)
        manifest_sha = sha256_file(evidence_dir / MANIFEST_NAME)
        rows = manifest.get("files")
        if not isinstance(rows, list):
            raise ValueError("manifest.files must be a list")
        expected_paths: set[str] = set()
        for index, row in enumerate(rows):
            if not isinstance(row, dict):
                raise ValueError(f"manifest row {index} is not an object")
            rel = _safe_evidence_rel_path(row.get("path"))
            if rel in expected_paths:
                raise ValueError(f"duplicate manifest path: {rel}")
            expected_paths.add(rel)
            path = evidence_dir / rel
            if not path.is_file() or path.is_symlink():
                raise ValueError(f"manifest member missing or symlink: {rel}")
            size = row.get("bytes")
            digest = row.get("sha256")
            if size != path.stat().st_size or not isinstance(digest, str) or digest != sha256_file(path):
                raise ValueError(f"manifest identity mismatch: {rel}")
        actual_paths = {
            p.relative_to(evidence_dir).as_posix()
            for p in evidence_dir.rglob("*")
            if p.is_file() and p.name not in {MANIFEST_NAME, READY_NAME}
        }
        if actual_paths != expected_paths:
            raise ValueError(
                f"manifest coverage mismatch: missing={sorted(actual_paths - expected_paths)}, extra={sorted(expected_paths - actual_paths)}"
            )
        ready = _load_json(evidence_dir / READY_NAME, "validation evidence READY")
        if ready.get("schema") != READY_SCHEMA:
            raise ValueError("validation evidence READY schema mismatch")
        if ready.get("manifest_sha256") != manifest_sha:
            raise ValueError("validation evidence READY manifest SHA mismatch")
        if ready.get("validation_receipt_sha256") != sha256_file(evidence_dir / RECEIPT_NAME):
            raise ValueError("validation evidence READY receipt SHA mismatch")
        if ready.get("written_last") is not True:
            raise ValueError("validation evidence READY does not claim written_last")
        receipt = _load_json(evidence_dir / RECEIPT_NAME, "validation receipt")
        if ready.get("status") != receipt.get("status"):
            raise ValueError("validation evidence READY status conflicts with execution receipt")
        add("MANIFEST_READY", "PASS", "Evidence manifest and READY bind every evidence byte.", manifest_sha256=manifest_sha)
    except Exception as exc:
        add("MANIFEST_READY", "FAIL", f"{type(exc).__name__}: {exc}")

    observed: dict[str, Any] | None = None
    if request is not None:
        try:
            observed = _candidate_identity(repo, remote_name)
            errors = _candidate_errors(observed, request)
            if errors:
                raise ValueError("; ".join(errors))
            add("CANDIDATE_IDENTITY", "PASS", "Candidate Git identity is exact and clean.", observed=observed)
        except Exception as exc:
            add("CANDIDATE_IDENTITY", "FAIL", f"{type(exc).__name__}: {exc}")

    if receipt is not None and request is not None and observed is not None and binding_sha is not None and admission_sha is not None:
        try:
            errors = _verify_validation_receipt(
                receipt,
                request,
                binding_sha,
                admission_sha,
                observed["head"],
                observed["tree"],
            )
            if errors:
                raise ValueError("; ".join(errors))
            commands = receipt.get("commands")
            if not isinstance(commands, list):
                raise ValueError("validation receipt commands missing")
            required_ids = {row["id"] for row in request["validation"]["required_commands"]}
            raw_expected: set[str] = set()
            total = 0
            for row in commands:
                command_id = row.get("id")
                if command_id not in required_ids:
                    raise ValueError(f"unexpected command evidence: {command_id}")
                stdout_rel = _safe_evidence_rel_path(row.get("stdout_path"))
                stderr_rel = _safe_evidence_rel_path(row.get("stderr_path"))
                if stdout_rel != f"{RAW_DIR}/{command_id}.stdout.bin" or stderr_rel != f"{RAW_DIR}/{command_id}.stderr.bin":
                    raise ValueError(f"raw evidence path binding mismatch: {command_id}")
                raw_expected.update({stdout_rel, stderr_rel})
                stdout_path = evidence_dir / stdout_rel
                stderr_path = evidence_dir / stderr_rel
                if not stdout_path.is_file() or not stderr_path.is_file():
                    raise ValueError(f"raw command evidence missing: {command_id}")
                for label, path in (("stdout", stdout_path), ("stderr", stderr_path)):
                    if row.get(f"{label}_size_bytes") != path.stat().st_size:
                        raise ValueError(f"{command_id} {label} size mismatch")
                    if row.get(f"{label}_sha256") != sha256_file(path):
                        raise ValueError(f"{command_id} {label} SHA mismatch")
                    cap_key = f"max_{label}_bytes"
                    if path.stat().st_size > row.get(cap_key, -1):
                        raise ValueError(f"{command_id} {label} exceeds admitted output cap")
                    total += path.stat().st_size
                if not isinstance(row.get("duration_ms"), int) or row["duration_ms"] < 0:
                    raise ValueError(f"validation command duration is invalid: {command_id}")
                if row["duration_ms"] > row.get("timeout_seconds", 0) * 1000 + 5000:
                    raise ValueError(f"validation command duration exceeds admitted timeout: {command_id}")
                if row.get("timed_out") is not False:
                    raise ValueError(f"validation command timed out: {command_id}")
                if row.get("output_limit_exceeded") is not False:
                    raise ValueError(f"validation command exceeded output limit: {command_id}")
                if row.get("truncated") is not False:
                    raise ValueError(f"validation command output was truncated: {command_id}")
                if row.get("exit_code") != 0:
                    raise ValueError(f"validation command did not pass: {command_id}")
            actual_raw = {
                p.relative_to(evidence_dir).as_posix()
                for p in (evidence_dir / RAW_DIR).glob("*")
                if p.is_file()
            }
            if actual_raw != raw_expected:
                raise ValueError("raw evidence file set mismatch")
            if total != receipt.get("total_output_bytes"):
                raise ValueError("validation total_output_bytes mismatch")
            if total > request["validation"]["max_total_output_bytes"]:
                raise ValueError("validation raw output exceeds admitted global cap")
            if receipt.get("raw_evidence_required") is not request["validation"]["raw_evidence_required"]:
                raise ValueError("validation raw_evidence_required binding mismatch")
            before = receipt.get("repository_before")
            after = receipt.get("repository_after")
            if not isinstance(before, dict) or not isinstance(after, dict):
                raise ValueError("validation repository before/after receipts are missing")
            for key in ("branch", "head", "tree"):
                if before.get(key) != after.get(key) or after.get(key) != observed.get(key):
                    raise ValueError(f"validation repository identity changed: {key}")
            if receipt.get("status") != EXECUTION_PASS:
                raise ValueError("validation execution receipt did not pass")
            add("RAW_COMMAND_EVIDENCE", "PASS", "Every admitted command is bound to independently rehashed raw stdout/stderr bytes.", total_output_bytes=total)
        except Exception as exc:
            add("RAW_COMMAND_EVIDENCE", "FAIL", f"{type(exc).__name__}: {exc}")

    try:
        no_effect = _load_json(evidence_dir / NO_EFFECT_NAME, "validation no-effect receipt")
        for key in (
            "force_push", "merge", "pull_request_merge", "deployment", "registry_apply",
            "current_state_apply", "r63_apply", "trading", "wallet_access",
            "order_execution", "external_message", "self_application",
        ):
            if no_effect.get(key) is not False:
                raise ValueError(f"no-effect receipt widened {key}")
        if (
            no_effect.get("can_trade") is not False
            or no_effect.get("capital_permission") != "DENY"
            or no_effect.get("deploy_permission") != "DENY"
        ):
            raise ValueError("no-effect receipt widened effect ceiling")
        for key in (
            "repository_head_unchanged", "repository_tree_unchanged",
            "repository_branch_unchanged", "worktree_clean_before", "worktree_clean_after",
        ):
            if no_effect.get(key) is not True:
                raise ValueError(f"no-effect receipt does not prove {key}")
        add("NO_EFFECT", "PASS", "Validation evidence records no dangerous or live-state effect.")
    except Exception as exc:
        add("NO_EFFECT", "FAIL", f"{type(exc).__name__}: {exc}")

    statuses = {row["status"] for row in checks}
    if "FAIL" in statuses:
        status = EVIDENCE_REVISE
    elif "HOLD" in statuses:
        status = EVIDENCE_HOLD
    else:
        status = EVIDENCE_PASS
    return {
        "schema": VERIFICATION_SCHEMA,
        "generated_at_utc": _now(),
        "status": status,
        "checks": checks,
        "evidence_dir": str(evidence_dir.resolve()) if evidence_dir.exists() else str(evidence_dir),
        "manifest_sha256": manifest_sha,
        "validation_receipt_sha256": sha256_file(evidence_dir / RECEIPT_NAME) if (evidence_dir / RECEIPT_NAME).is_file() else None,
        "candidate_head": observed.get("head") if observed else None,
        "candidate_tree": observed.get("tree") if observed else None,
        "effect": "VERIFY_ONLY_NO_WRITE",
        "live_state_modified": False,
        "writes_performed": [],
        "can_trade": False,
        "capital_permission": "DENY",
        "deploy_permission": "DENY",
        "self_application": False,
    }


def exit_code_for_work_validation_execution(receipt: dict[str, Any]) -> int:
    return {EXECUTION_PASS: 0, EXECUTION_HOLD: 1, EXECUTION_REVISE: 2}.get(receipt.get("status"), 2)


def exit_code_for_work_validation_evidence(receipt: dict[str, Any]) -> int:
    return {EVIDENCE_PASS: 0, EVIDENCE_HOLD: 1, EVIDENCE_REVISE: 2}.get(receipt.get("status"), 2)
