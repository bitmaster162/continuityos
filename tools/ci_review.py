"""Stdlib-only helpers for the local-only review CI workflow.

The helpers deliberately avoid shells and never print credential-like matches.  The
index scanner reads Git blobs by object id, so its manifest and scan describe the
exact index rather than a potentially different working-tree file.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
import platform
import re
import shutil
import site
import subprocess
import sys
import sysconfig
import time
import venv
from pathlib import Path


SECRET_PATTERNS = {
    "private_key": re.compile(
        rb"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"
    ),
    "aws_access_key": re.compile(rb"(?:AKIA|ASIA)[A-Z0-9]{16}"),
    "github_token": re.compile(
        rb"(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{40,255})"
    ),
    "openai_key": re.compile(rb"sk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{32,}"),
    "anthropic_key": re.compile(rb"sk-ant-[A-Za-z0-9_-]{32,}"),
    "slack_token": re.compile(rb"xox[baprs]-[A-Za-z0-9-]{20,}"),
    "google_api_key": re.compile(rb"AIza[0-9A-Za-z_-]{35}"),
    "stripe_live_key": re.compile(rb"[rs]k_live_[0-9A-Za-z]{20,}"),
}

REVIEWED_ACTION_REFS = {
    "actions/checkout": "34e114876b0b11c390a56381ad16ebd13914f8d5",
    "actions/setup-python": "a26af69be951a213d495a4c3e4e4022e16d87065",
    "actions/upload-artifact": "ea165f8d65b6e75b540449e92b4886f43607fa02",
}

REVIEWED_WORKFLOW_SHA256 = (
    "9032fe4ef70aff7c472350e976730b5269bdc3810fdfec7ba9823a3500d72258"
)

REVIEW_PYTHON_VERSION = "3.11.9"

REVIEW_LOCK_PACKAGES = {
    "build",
    "colorama",
    "iniconfig",
    "packaging",
    "pip",
    "pluggy",
    "pygments",
    "pyproject-hooks",
    "pytest",
    "pyyaml",
    "setuptools",
    "wheel",
}

MANDATORY_STEP_IDS = (
    "configure_pycache",
    "lock_policy",
    "create_review_env",
    "install_tooling",
    "pip_check",
    "workflow_policy",
    "pre_index",
    "materialize_source",
    "clean_metadata",
    "nodeids",
    "clean_tests",
    "wheel_build",
    "wheel_tooling",
    "wheel_tests",
    "editable_install",
    "editable_metadata",
    "editable_tests",
    "compileall",
    "governance",
    "portable_probes",
    "linux_symlink",
    "materialized_rebind",
    "post_rebind",
)

WORKFLOW_STEP_IDS = (
    "checkout",
    "setup_python",
    "configure_pycache",
    "pre_index",
    "lock_policy",
    "create_review_env",
    "install_tooling",
    "pip_check",
    "workflow_policy",
    "materialize_source",
    "clean_metadata",
    "nodeids",
    "clean_tests",
    "wheel_build",
    "wheel_tooling",
    "wheel_tests",
    "editable_install",
    "editable_metadata",
    "editable_tests",
    "compileall",
    "governance",
    "portable_probes",
    "linux_symlink",
    "materialized_rebind",
    "post_rebind",
    "final_gate",
    "receipt_manifest",
    "upload_receipts",
    "enforce_conclusions",
)

REVIEW_PYTHON_STEP_RECEIPTS = {
    "install_tooling": "install-review-tooling.json",
    "pip_check": "review-tooling-environment-command.json",
    "workflow_policy": "workflow-policy-command.json",
    "clean_metadata": "clean-source-metadata-command.json",
    "nodeids": "pytest-nodeids-command.json",
    "clean_tests": "clean-source-pytest.json",
    "wheel_build": "wheel-build.json",
    "wheel_tooling": "wheel-test-tooling.json",
    "wheel_tests": "wheel-only-pytest-command.json",
    "editable_install": "editable-install.json",
    "editable_metadata": "editable-metadata-command.json",
    "editable_tests": "editable-pytest.json",
    "compileall": "compileall.json",
    "governance": "governance-corpus.json",
    "portable_probes": "portable-probes-command.json",
    "linux_symlink": "linux-symlink-realpath.json",
}

REVIEW_ENVIRONMENT_RECEIPT_WORKFLOW_PATH = (
    "${{ runner.temp }}/continuityos-review-receipts/"
    "create-review-environment.json"
)

WORKFLOW_CONTEXT_NAMES = frozenset(
    {
        "env",
        "github",
        "inputs",
        "job",
        "jobs",
        "matrix",
        "needs",
        "runner",
        "secrets",
        "steps",
        "strategy",
        "vars",
    }
)

WORKFLOW_PRE_DISPATCH_CONTEXTS = frozenset(
    {"github", "inputs", "matrix", "needs", "strategy", "vars"}
)

WORKFLOW_JOB_ENV_CONTEXTS = WORKFLOW_PRE_DISPATCH_CONTEXTS | {"secrets"}

WORKFLOW_STEP_CONTEXTS = frozenset(
    {
        "env",
        "github",
        "inputs",
        "job",
        "matrix",
        "needs",
        "runner",
        "secrets",
        "steps",
        "strategy",
        "vars",
    }
)

WORKFLOW_STEP_IF_CONTEXTS = WORKFLOW_STEP_CONTEXTS - {"secrets"}

WORKFLOW_GENERAL_EXPRESSION_FUNCTIONS = frozenset(
    {
        "contains",
        "endswith",
        "format",
        "fromjson",
        "join",
        "startswith",
        "tojson",
    }
)

WORKFLOW_STATUS_EXPRESSION_FUNCTIONS = frozenset(
    {"always", "cancelled", "failure", "success"}
)

WORKFLOW_HASH_EXPRESSION_FUNCTIONS = frozenset({"hashfiles"})

WORKFLOW_EXPRESSION_FUNCTIONS = (
    WORKFLOW_GENERAL_EXPRESSION_FUNCTIONS
    | WORKFLOW_STATUS_EXPRESSION_FUNCTIONS
    | WORKFLOW_HASH_EXPRESSION_FUNCTIONS
)

WORKFLOW_EXPRESSION_FUNCTION_ARITY = {
    "always": (0, 0),
    "cancelled": (0, 0),
    "contains": (2, 2),
    "endswith": (2, 2),
    "failure": (0, 0),
    "format": (1, 255),
    "fromjson": (1, 1),
    "hashfiles": (1, 255),
    "join": (1, 2),
    "startswith": (2, 2),
    "success": (0, 0),
    "tojson": (1, 1),
}

WORKFLOW_EXPRESSION_KEYWORDS = frozenset({"false", "null", "true"})
WORKFLOW_EXPRESSION_MAX_LENGTH = 16384
WORKFLOW_EXPRESSION_MAX_TOKENS = 1024


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def _run(command: list[str], *, cwd: Path, env: dict[str, str] | None = None):
    started = time.time()
    completed = subprocess.run(
        command,
        cwd=str(cwd),
        env=env,
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        check=False,
    )
    return completed, round(time.time() - started, 3)


def _emit_text(text: str, stream) -> None:
    value = text if text.endswith("\n") else text + "\n"
    try:
        stream.write(value)
    except UnicodeEncodeError:
        encoding = getattr(stream, "encoding", None) or "utf-8"
        safe_value = value.encode(encoding, errors="backslashreplace").decode(encoding)
        stream.write(safe_value)


def _emit_completed(completed: subprocess.CompletedProcess[str]) -> None:
    if completed.stdout:
        _emit_text(completed.stdout, sys.stdout)
    if completed.stderr:
        _emit_text(completed.stderr, sys.stderr)


def _normalized_path_sha256(path: Path) -> str:
    """Fingerprint a path without placing the path value in a receipt."""
    normalized = os.path.normcase(os.path.normpath(str(path)))
    return _sha256(normalized.encode("utf-8", errors="surrogatepass"))


def _lexical_path_is_within(candidate: str | Path, root: str | Path) -> bool:
    """Check path placement without dereferencing a normal venv interpreter symlink."""
    candidate_path = Path(os.path.abspath(os.fspath(candidate)))
    root_path = Path(os.path.abspath(os.fspath(root)))
    return candidate_path == root_path or root_path in candidate_path.parents


def _safe_execution_context(cwd: Path | None = None) -> dict:
    """Return non-secret context sufficient to explain runner path differences."""
    cwd = (cwd or Path.cwd()).resolve()
    home_value = os.environ.get("HOME")
    home_source = "HOME"
    if home_value is None and os.name == "nt":
        home_value = os.environ.get("USERPROFILE")
        home_source = "USERPROFILE"

    home_path = None
    if not home_value:
        home_class = "unset"
    elif not os.path.isabs(os.path.expandvars(home_value)):
        home_class = "relative"
    else:
        home_class = "absolute"
        try:
            home_path = Path(os.path.expandvars(home_value)).resolve()
        except OSError:
            home_class = "unresolvable"

    if home_path is None:
        cwd_class = "home_unavailable"
    elif cwd == home_path:
        cwd_class = "home"
    else:
        try:
            cwd_class = "inside_home" if cwd.is_relative_to(home_path) else "outside_home"
        except (OSError, ValueError):
            cwd_class = "outside_home"

    policy = {
        "source": "continuityos.gate.policy.default_policy",
        "status": "unavailable",
        "sha256": None,
        "version": None,
    }
    try:
        from continuityos.gate.policy import default_policy, policy_fingerprint

        effective_policy = default_policy()
        policy.update(
            {
                "status": "available",
                "sha256": policy_fingerprint(effective_policy),
                "version": effective_policy.get("version"),
            }
        )
    except Exception as exc:  # pragma: no cover - exercised only in damaged installs
        policy["error_class"] = type(exc).__name__

    return {
        "home": {
            "class": home_class,
            "source": home_source,
            "path_sha256": (
                _normalized_path_sha256(home_path) if home_path is not None else None
            ),
        },
        "cwd": {
            "class": cwd_class,
            "path_sha256": _normalized_path_sha256(cwd),
        },
        "policy": policy,
    }


def command_receipt(args: argparse.Namespace) -> int:
    command = list(args.command)
    if command and command[0] == "--":
        command.pop(0)
    if not command:
        raise SystemExit("run requires a command after --")
    cwd = Path(getattr(args, "cwd", None) or Path.cwd()).resolve()
    completed, duration = _run(command, cwd=cwd)
    _emit_completed(completed)
    _write_json(
        Path(args.output),
        {
            "schema": "continuityos-ci-command-receipt-v2",
            "command": command,
            "cwd": str(cwd),
            "execution_context": _safe_execution_context(cwd),
            "duration_seconds": duration,
            "exit_code": completed.returncode,
            "platform": platform.platform(),
            "python": sys.version,
            "status": "PASS" if completed.returncode == 0 else "FAIL",
            "stderr": completed.stderr,
            "stdout": completed.stdout,
        },
    )
    return completed.returncode


def metadata_receipt(args: argparse.Namespace) -> int:
    output = Path(args.output)
    source_root = Path(args.source_root).resolve()
    try:
        distribution = importlib.metadata.distribution("continuityos")
    except importlib.metadata.PackageNotFoundError:
        distribution = None

    package_path = None
    failure = ""
    if args.mode == "absent":
        if distribution is not None:
            failure = "continuityos distribution metadata is installed"
        else:
            source_text = str(source_root)
            if source_text not in sys.path:
                sys.path.insert(0, source_text)
            try:
                import continuityos
            except Exception as exc:
                failure = (
                    "clean source import failed: "
                    f"{type(exc).__name__}: {exc}"
                )
            else:
                package_path = Path(continuityos.__file__).resolve()
                if source_root not in package_path.parents:
                    failure = "source import did not resolve inside the checkout"
    else:
        if distribution is None:
            failure = "continuityos distribution metadata is absent"
        else:
            try:
                import continuityos
            except Exception as exc:
                failure = (
                    "editable import failed: "
                    f"{type(exc).__name__}: {exc}"
                )
            else:
                package_path = Path(continuityos.__file__).resolve()
                if source_root not in package_path.parents:
                    failure = "editable import did not resolve inside the checkout"

    payload = {
        "schema": "continuityos-ci-metadata-receipt-v1",
        "mode": args.mode,
        "metadata_present": distribution is not None,
        "metadata_version": distribution.version if distribution is not None else None,
        "package_path": str(package_path) if package_path is not None else None,
        "source_root": str(source_root),
        "status": "FAIL" if failure else "PASS",
        "failure": failure,
    }
    _write_json(output, payload)
    print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
    return 1 if failure else 0


def _git(root: Path, *arguments: str, text: bool = False):
    return subprocess.run(
        ["git", *arguments],
        cwd=str(root),
        check=True,
        capture_output=True,
        text=text,
        encoding="utf-8" if text else None,
    ).stdout


def _collect_exact_index(root: Path):
    raw_entries = _git(root, "ls-files", "--stage", "-z")
    entries = []
    findings = []
    allowlisted_fixtures = []
    seen_paths = set()

    for raw_entry in raw_entries.split(b"\0"):
        if not raw_entry:
            continue
        metadata, raw_path = raw_entry.split(b"\t", 1)
        mode, object_id, stage = metadata.decode("ascii").split()
        path = raw_path.decode("utf-8", errors="surrogateescape")
        if stage != "0":
            raise SystemExit(f"unmerged index entry is not reviewable: {path}")
        if mode == "160000":
            raise SystemExit(f"gitlink content is not covered by the exact scan: {path}")
        if path in seen_paths:
            raise SystemExit(f"duplicate index entry: {path}")
        seen_paths.add(path)
        content = _git(root, "cat-file", "blob", object_id)
        entries.append(
            {
                "mode": mode,
                "object_id": object_id,
                "path": path,
                "sha256": _sha256(content),
                "size": len(content),
            }
        )

        name = Path(path).name.lower()
        if name == ".env" or name.startswith(".env."):
            findings.append({"path": path, "pattern": "tracked_dotenv", "offset": 0})
        for pattern_name, pattern in SECRET_PATTERNS.items():
            for match in pattern.finditer(content):
                # AWS publishes this suffix as a non-secret documentation example;
                # retain a precise, auditable exception for the governance corpus.
                if pattern_name == "aws_access_key" and match.group().endswith(b"EXAMPLE"):
                    allowlisted_fixtures.append(
                        {"path": path, "pattern": pattern_name, "offset": match.start()}
                    )
                    continue
                findings.append(
                    {"path": path, "pattern": pattern_name, "offset": match.start()}
                )

    entries.sort(key=lambda item: item["path"])
    findings.sort(key=lambda item: (item["path"], item["offset"], item["pattern"]))
    allowlisted_fixtures.sort(
        key=lambda item: (item["path"], item["offset"], item["pattern"])
    )
    return entries, findings, allowlisted_fixtures


def _exact_index_manifest(root: Path) -> tuple[dict, list[dict], list[dict]]:
    entries, findings, allowlisted_fixtures = _collect_exact_index(root)
    head = _git(root, "rev-parse", "HEAD", text=True).strip()
    head_tree = _git(root, "rev-parse", "HEAD^{tree}", text=True).strip()
    index_tree = _git(root, "write-tree", text=True).strip()
    manifest = {
        "schema": "continuityos-exact-git-index-manifest-v2",
        "head": head,
        "head_tree": head_tree,
        "index_tree": index_tree,
        "entry_count": len(entries),
        "entries": entries,
    }
    return manifest, findings, allowlisted_fixtures


def _write_exact_index_manifest(root: Path, manifest_path: Path):
    manifest, findings, allowlisted_fixtures = _exact_index_manifest(root)
    _write_json(manifest_path, manifest)
    manifest_sha = _sha256_file(manifest_path)
    manifest_path.with_name(manifest_path.name + ".sha256").write_text(
        f"{manifest_sha}  {manifest_path.name}\n", encoding="ascii", newline="\n"
    )
    return manifest, manifest_sha, findings, allowlisted_fixtures


def exact_index(args: argparse.Namespace) -> int:
    root = Path(
        _git(Path.cwd(), "rev-parse", "--show-toplevel", text=True).strip()
    ).resolve()
    manifest_path = Path(args.manifest)
    manifest, manifest_sha, findings, allowlisted_fixtures = (
        _write_exact_index_manifest(root, manifest_path)
    )

    scan = {
        "schema": "continuityos-exact-index-secret-scan-v1",
        "exact_index_manifest_sha256": manifest_sha,
        "patterns": sorted([*SECRET_PATTERNS, "tracked_dotenv"]),
        "scanned_entries": manifest["entry_count"],
        "allowlisted_fixture_count": len(allowlisted_fixtures),
        "allowlisted_fixtures": allowlisted_fixtures,
        "finding_count": len(findings),
        "findings": findings,
        "status": "PASS" if not findings else "FAIL",
    }
    _write_json(Path(args.scan_output), scan)
    print(json.dumps(scan, ensure_ascii=False, sort_keys=True))
    return 1 if findings else 0


def materialize_source(args: argparse.Namespace) -> int:
    root = Path(
        _git(Path.cwd(), "rev-parse", "--show-toplevel", text=True).strip()
    ).resolve()
    manifest_path = Path(args.manifest).resolve()
    destination = Path(args.destination).resolve()
    output = Path(args.output)
    failure_codes = []
    try:
        expected = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        expected = None
        failure_codes.append("invalid_pre_manifest")
    current, _, _ = _exact_index_manifest(root)
    if expected != current:
        failure_codes.append("pre_manifest_not_current_index")
    if destination.exists() and any(destination.iterdir()):
        failure_codes.append("destination_not_empty")

    materialized = []
    if not failure_codes:
        destination.mkdir(parents=True, exist_ok=True)
        for entry in current["entries"]:
            if entry["mode"] not in {"100644", "100755"}:
                failure_codes.append("unsupported_index_mode")
                break
            relative = Path(entry["path"])
            if relative.is_absolute() or ".." in relative.parts:
                failure_codes.append("unsafe_index_path")
                break
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            content = _git(root, "cat-file", "blob", entry["object_id"])
            if _sha256(content) != entry["sha256"]:
                failure_codes.append("blob_sha256_mismatch")
                break
            target.write_bytes(content)
            materialized.append(
                {"path": entry["path"], "sha256": entry["sha256"], "size": len(content)}
            )

    payload = {
        "schema": "continuityos-ci-materialized-source-v1",
        "source_manifest": str(manifest_path),
        "source_manifest_sha256": (
            _sha256_file(manifest_path) if manifest_path.is_file() else None
        ),
        "destination": str(destination),
        "entry_count": len(materialized),
        "expected_entry_count": current["entry_count"],
        "entries_sha256": _sha256(
            json.dumps(materialized, sort_keys=True, separators=(",", ":")).encode(
                "utf-8"
            )
        ),
        "failure_codes": sorted(set(failure_codes)),
        "status": "PASS" if not failure_codes else "FAIL",
    }
    _write_json(output, payload)
    print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
    return 0 if payload["status"] == "PASS" else 1


def verify_materialized_source(args: argparse.Namespace) -> int:
    manifest_path = Path(args.manifest).resolve()
    directory = Path(args.directory).resolve()
    output = Path(args.output)
    failure_codes = []
    mismatches = []
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        manifest = None
        failure_codes.append("missing_or_invalid_pre_manifest")

    expected_paths = set()
    if manifest:
        for entry in manifest.get("entries", []):
            relative = Path(entry["path"])
            expected_paths.add(relative.as_posix())
            if relative.is_absolute() or ".." in relative.parts:
                mismatches.append({"path": entry["path"], "reason": "unsafe_path"})
                continue
            target = directory / relative
            if target.is_symlink():
                mismatches.append({"path": entry["path"], "reason": "symlink"})
            elif not target.is_file():
                mismatches.append({"path": entry["path"], "reason": "missing"})
            else:
                actual_sha = _sha256_file(target)
                if actual_sha != entry["sha256"] or target.stat().st_size != entry["size"]:
                    mismatches.append(
                        {
                            "path": entry["path"],
                            "reason": "content_or_size_mismatch",
                            "expected_sha256": entry["sha256"],
                            "actual_sha256": actual_sha,
                        }
                    )
    if mismatches:
        failure_codes.append("materialized_tracked_content_drift")

    allowed_generated_roots = {"build", "continuityos.egg-info"}
    unexpected = []
    disallowed_generated = []
    if directory.is_dir():
        for path in directory.rglob("*"):
            relative = path.relative_to(directory)
            name = relative.as_posix()
            if name in expected_paths or (path.is_dir() and not path.is_symlink()):
                continue
            unexpected.append(name)
            if (
                path.is_symlink()
                or not relative.parts
                or relative.parts[0] not in allowed_generated_roots
            ):
                disallowed_generated.append(name)
        unexpected.sort()
        disallowed_generated.sort()
    else:
        failure_codes.append("materialized_directory_missing")
    if disallowed_generated:
        failure_codes.append("unexpected_materialized_content")

    payload = {
        "schema": "continuityos-ci-materialized-source-rebind-v1",
        "source_manifest": str(manifest_path),
        "source_manifest_sha256": (
            _sha256_file(manifest_path) if manifest_path.is_file() else None
        ),
        "directory": str(directory),
        "expected_entry_count": manifest.get("entry_count") if manifest else None,
        "verified_entry_count": (
            manifest.get("entry_count", 0) - len(mismatches) if manifest else 0
        ),
        "mismatches": mismatches,
        "unexpected_generated_file_count": len(unexpected),
        "unexpected_generated_files": unexpected,
        "allowed_generated_roots": sorted(allowed_generated_roots),
        "disallowed_generated_files": disallowed_generated,
        "failure_codes": sorted(set(failure_codes)),
        "status": "PASS" if not failure_codes else "FAIL",
    }
    _write_json(output, payload)
    print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
    return 0 if payload["status"] == "PASS" else 1


def _git_state(root: Path) -> dict:
    def run(*arguments: str):
        return subprocess.run(
            ["git", *arguments],
            cwd=str(root),
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
            check=False,
        )

    status = run("status", "--porcelain=v2", "--untracked-files=all")
    unstaged = run("diff", "--quiet", "--no-ext-diff")
    staged = run("diff", "--cached", "--quiet", "--no-ext-diff")
    return {
        "status_exit_code": status.returncode,
        "status_porcelain_v2": status.stdout.splitlines(),
        "status_stderr": status.stderr,
        "unstaged_diff_exit_code": unstaged.returncode,
        "unstaged_diff_stderr": unstaged.stderr,
        "staged_diff_exit_code": staged.returncode,
        "staged_diff_stderr": staged.stderr,
    }


def source_rebind(args: argparse.Namespace) -> int:
    root = Path(
        _git(Path.cwd(), "rev-parse", "--show-toplevel", text=True).strip()
    ).resolve()
    pre_path = Path(args.pre_manifest).resolve()
    post_path = Path(args.post_manifest).resolve()
    output = Path(args.output)
    failure_codes = []
    try:
        pre = json.loads(pre_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        pre = None
        failure_codes.append("missing_or_invalid_pre_manifest")

    post, post_sha, _, _ = _write_exact_index_manifest(root, post_path)
    state = _git_state(root)
    post_worktree_clean = (
        state["status_exit_code"] == 0
        and not state["status_porcelain_v2"]
        and state["unstaged_diff_exit_code"] == 0
        and state["staged_diff_exit_code"] == 0
    )
    if not post_worktree_clean:
        failure_codes.append("post_worktree_or_index_dirty")

    pre_post_equal = pre == post
    entries_equal = bool(pre and pre.get("entries") == post.get("entries"))
    head_unchanged = bool(pre and pre.get("head") == post.get("head"))
    head_tree_unchanged = bool(
        pre and pre.get("head_tree") == post.get("head_tree")
    )
    index_tree_unchanged = bool(
        pre and pre.get("index_tree") == post.get("index_tree")
    )
    entry_count_unchanged = bool(
        pre and pre.get("entry_count") == post.get("entry_count")
    )
    if not pre_post_equal:
        failure_codes.append("pre_post_manifest_mismatch")
    if not entries_equal:
        failure_codes.append("pre_post_entries_mismatch")
    if not head_unchanged:
        failure_codes.append("head_drift")
    if not head_tree_unchanged:
        failure_codes.append("head_tree_drift")
    if not index_tree_unchanged:
        failure_codes.append("index_tree_drift")
    if not entry_count_unchanged:
        failure_codes.append("entry_count_drift")

    payload = {
        "schema": "continuityos-ci-post-source-rebind-v1",
        "repository_root": str(root),
        "pre_manifest": str(pre_path),
        "pre_exact_index_sha256": (
            _sha256_file(pre_path) if pre_path.is_file() else None
        ),
        "post_manifest": str(post_path),
        "post_exact_index_sha256": post_sha,
        "pre_entry_count": pre.get("entry_count") if pre else None,
        "post_entry_count": post["entry_count"],
        "pre_head": pre.get("head") if pre else None,
        "post_head": post["head"],
        "pre_head_tree": pre.get("head_tree") if pre else None,
        "post_head_tree": post["head_tree"],
        "pre_index_tree": pre.get("index_tree") if pre else None,
        "post_index_tree": post["index_tree"],
        "pre_post_equal": pre_post_equal,
        "entries_equal": entries_equal,
        "head_unchanged": head_unchanged,
        "head_tree_unchanged": head_tree_unchanged,
        "index_tree_unchanged": index_tree_unchanged,
        "entry_count_unchanged": entry_count_unchanged,
        "post_worktree_clean": post_worktree_clean,
        "git_state": state,
        "failure_codes": sorted(set(failure_codes)),
        "status": "PASS" if not failure_codes else "FAIL",
    }
    _write_json(output, payload)
    print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
    return 0 if payload["status"] == "PASS" else 1


def _normalize_distribution_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _logical_lock_lines(text: str) -> list[str]:
    logical = []
    pending = ""
    for raw in text.splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.endswith("\\"):
            pending += stripped[:-1].strip() + " "
            continue
        logical.append((pending + stripped).strip())
        pending = ""
    if pending:
        logical.append(pending.strip())
    return logical


def _canonical_file_sha256(path: Path) -> tuple[str | None, str]:
    try:
        root = Path(
            _git(path.parent, "rev-parse", "--show-toplevel", text=True).strip()
        ).resolve()
        relative = path.resolve().relative_to(root).as_posix()
        raw = _git(root, "ls-files", "--stage", "-z", "--", relative)
        records = [item for item in raw.split(b"\0") if item]
        if len(records) == 1:
            metadata, _ = records[0].split(b"\t", 1)
            _, object_id, stage = metadata.decode("ascii").split()
            if stage == "0":
                return _sha256(_git(root, "cat-file", "blob", object_id)), "git_blob"
    except (OSError, ValueError, subprocess.CalledProcessError):
        pass
    if path.is_file():
        return _sha256_file(path), "working_file"
    return None, "missing"


def _review_lock_evidence(lock: Path) -> dict:
    failure_codes = []
    requirements = []
    duplicates = []
    try:
        text = lock.read_text(encoding="utf-8")
    except OSError:
        text = ""
        failure_codes.append("lock_missing")

    source_indexes = [
        line.split(":", 1)[1].strip()
        for line in text.splitlines()
        if line.strip().lower().startswith("# source-index:")
    ]
    generation_commands = [
        line.split(":", 1)[1].strip()
        for line in text.splitlines()
        if line.strip().lower().startswith("# generation-command:")
    ]
    if source_indexes != ["https://pypi.org/simple"]:
        failure_codes.append("source_index_not_exact_pypi")
    if not generation_commands:
        failure_codes.append("generation_command_missing")
    if "binary wheels only" not in text.lower():
        failure_codes.append("binary_only_provenance_missing")

    seen = set()
    pattern = re.compile(
        r"^([A-Za-z0-9][A-Za-z0-9_.-]*)==([^\s;\\]+)\s+(.+)$"
    )
    hash_pattern = re.compile(r"--hash=sha256:([0-9a-f]{64})(?:\s|$)")
    for line in _logical_lock_lines(text):
        if line.startswith(("-", ".", "/")) or "://" in line or "git+" in line:
            failure_codes.append("unsafe_lock_directive")
            continue
        match = pattern.fullmatch(line)
        if not match:
            failure_codes.append("unpinned_or_malformed_requirement")
            continue
        raw_name, version, remainder = match.groups()
        name = _normalize_distribution_name(raw_name)
        if not re.fullmatch(
            r"[0-9]+(?:\.[0-9]+)*(?:(?:a|b|rc)[0-9]+|\.post[0-9]+|\.dev[0-9]+)?",
            version,
            flags=re.IGNORECASE,
        ):
            failure_codes.append(f"non_exact_version:{name}")
        hashes = hash_pattern.findall(remainder)
        residual = hash_pattern.sub("", remainder).strip()
        if not hashes:
            failure_codes.append(f"unhashed_requirement:{name}")
        if residual:
            failure_codes.append(f"unsupported_requirement_option:{name}")
        if name in seen:
            duplicates.append(name)
            failure_codes.append(f"duplicate_requirement:{name}")
        seen.add(name)
        requirements.append(
            {"name": name, "version": version, "hashes": sorted(set(hashes))}
        )

    missing = sorted(REVIEW_LOCK_PACKAGES - seen)
    unexpected = sorted(seen - REVIEW_LOCK_PACKAGES)
    if missing:
        failure_codes.append("missing_locked_packages")
    if unexpected:
        failure_codes.append("unexpected_locked_packages")
    canonical_sha, canonical_source = _canonical_file_sha256(lock)
    return {
        "schema": "continuityos-review-dependency-lock-policy-v1",
        "lock": str(lock.resolve()),
        "canonical_sha256": canonical_sha,
        "canonical_sha256_source": canonical_source,
        "working_file_sha256": _sha256_file(lock) if lock.is_file() else None,
        "source_indexes": source_indexes,
        "generation_command_lines": generation_commands,
        "expected_packages": sorted(REVIEW_LOCK_PACKAGES),
        "packages": requirements,
        "package_count": len(requirements),
        "missing_packages": missing,
        "unexpected_packages": unexpected,
        "duplicates": sorted(set(duplicates)),
        "failure_codes": sorted(set(failure_codes)),
        "status": "PASS" if not failure_codes else "FAIL",
    }


def review_lock_policy(args: argparse.Namespace) -> int:
    payload = _review_lock_evidence(Path(args.lock))
    _write_json(Path(args.output), payload)
    print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
    return 0 if payload["status"] == "PASS" else 1


def _review_environment_layout(
    environment: Path,
    *,
    runner_os: str | None = None,
) -> tuple[Path, Path]:
    windows = (
        runner_os.lower() == "windows" if runner_os is not None else os.name == "nt"
    )
    scripts_directory = environment / ("Scripts" if windows else "bin")
    interpreter = scripts_directory / ("python.exe" if windows else "python")
    return scripts_directory, interpreter


def create_review_environment(args: argparse.Namespace) -> int:
    """Create a one-use venv; an optional PATH export is convenience-only."""
    destination = Path(args.directory).resolve()
    output = Path(args.output)
    path_file_value = args.path_file or ""
    path_file = Path(path_file_value).resolve() if path_file_value else None
    scripts_dir, interpreter = _review_environment_layout(destination)
    environment_preexisted = destination.exists()
    failure_codes = []
    probe = None
    probe_stderr = ""
    path_file_status = "NOT_REQUESTED"
    path_file_error_class = None

    if environment_preexisted:
        failure_codes.append("review_environment_already_exists")
    else:
        try:
            venv.EnvBuilder(
                with_pip=True,
                system_site_packages=False,
                clear=False,
            ).create(destination)
        except Exception as exc:
            failure_codes.append(f"venv_creation_failed:{type(exc).__name__}")

    if not interpreter.is_file():
        failure_codes.append("venv_interpreter_missing")
    else:
        probe_command = [
            str(interpreter),
            "-I",
            "-c",
            (
                "import json,sys;"
                "print(json.dumps({'base_prefix':sys.base_prefix,"
                "'executable':sys.executable,'prefix':sys.prefix,"
                "'version':'.'.join(map(str,sys.version_info[:3]))},"
                "sort_keys=True))"
            ),
        ]
        completed, _ = _run(probe_command, cwd=destination)
        probe_stderr = completed.stderr
        if completed.returncode != 0:
            failure_codes.append("venv_interpreter_probe_failed")
        else:
            try:
                probe = json.loads(completed.stdout.strip())
            except json.JSONDecodeError:
                failure_codes.append("venv_interpreter_probe_invalid")
        if probe and probe.get("prefix") == probe.get("base_prefix"):
            failure_codes.append("venv_not_isolated")
        if probe and probe.get("version") != REVIEW_PYTHON_VERSION:
            failure_codes.append("review_python_version_not_exact")

    if path_file is not None and not failure_codes:
        try:
            path_file.parent.mkdir(parents=True, exist_ok=True)
            with path_file.open("a", encoding="utf-8", newline="\n") as handle:
                handle.write(str(scripts_dir) + "\n")
        except OSError as exc:
            path_file_status = "FAIL"
            path_file_error_class = type(exc).__name__
        else:
            path_file_status = "PASS"

    payload = {
        "schema": "continuityos-review-environment-create-v1",
        "base_interpreter": sys.executable,
        "base_python_version": platform.python_version(),
        "expected_python_version": REVIEW_PYTHON_VERSION,
        "environment": str(destination),
        "environment_preexisted": environment_preexisted,
        "scripts_directory": str(scripts_dir),
        "interpreter": str(interpreter),
        "interpreter_probe": probe,
        "path_file_requested": path_file is not None,
        "path_file_configured": path_file_status == "PASS",
        "path_file_status": path_file_status,
        "path_file_error_class": path_file_error_class,
        "path_has_authority": False,
        "probe_stderr": probe_stderr,
        "failure_codes": sorted(set(failure_codes)),
        "status": "PASS" if not failure_codes else "FAIL",
    }
    _write_json(output, payload)
    print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
    return 0 if payload["status"] == "PASS" else 1


def _normalized_lexical_path(path: str | Path) -> str:
    return os.path.normcase(os.path.normpath(os.path.abspath(os.fspath(path))))


def _lexical_paths_equal(left: str | Path, right: str | Path) -> bool:
    return _normalized_lexical_path(left) == _normalized_lexical_path(right)


def _outer_python_identity() -> dict:
    return {
        "executable": str(Path(os.path.abspath(sys.executable))),
        "prefix": str(Path(os.path.abspath(sys.prefix))),
        "base_prefix": str(Path(os.path.abspath(sys.base_prefix))),
        "version": platform.python_version(),
    }


def _path_order_evidence(environment: Path | None, interpreter: Path | None) -> dict:
    """Fingerprint PATH and classify ordering without recording its path values."""
    raw_path = os.environ.get("PATH", "")
    entries = raw_path.split(os.pathsep)
    environment_scripts = interpreter.parent if interpreter is not None else None
    outer_scripts = Path(os.path.abspath(sys.executable)).parent

    def first_index(candidate: Path | None):
        if candidate is None:
            return None
        for index, entry in enumerate(entries):
            if not entry:
                continue
            try:
                if _lexical_paths_equal(entry, candidate):
                    return index
            except (OSError, ValueError):
                continue
        return None

    environment_index = first_index(environment_scripts)
    outer_index = first_index(outer_scripts)
    generic_python = shutil.which("python", path=raw_path)
    if environment_scripts is not None and _lexical_paths_equal(
        environment_scripts, outer_scripts
    ):
        order_class = "same_interpreter_directory"
    elif environment_index is None and outer_index is None:
        order_class = "both_absent"
    elif environment_index is None:
        order_class = "environment_absent"
    elif outer_index is None:
        order_class = "outer_absent"
    elif environment_index < outer_index:
        order_class = "environment_precedes_outer"
    elif outer_index < environment_index:
        order_class = "outer_precedes_environment"
    else:
        order_class = "same_path_entry"

    if generic_python is None:
        generic_resolution_class = "missing"
    elif interpreter is not None and _lexical_paths_equal(
        generic_python, interpreter
    ):
        generic_resolution_class = "exact_review_interpreter"
    elif _lexical_paths_equal(generic_python, sys.executable):
        generic_resolution_class = "outer_interpreter"
    else:
        generic_resolution_class = "other_interpreter"

    return {
        "path_sha256": _sha256(raw_path.encode("utf-8", errors="surrogatepass")),
        "entry_count": len(entries),
        "empty_entry_count": sum(not entry for entry in entries),
        "environment_scripts_index": environment_index,
        "outer_interpreter_directory_index": outer_index,
        "order_class": order_class,
        "generic_python_resolution_class": generic_resolution_class,
        "generic_python_path_sha256": (
            _normalized_path_sha256(Path(generic_python))
            if generic_python is not None
            else None
        ),
        "environment_is_absolute": bool(
            environment is not None and os.path.isabs(str(environment))
        ),
    }


def _review_python_argument_failure(command: list[str]) -> str:
    """Accept Python arguments, never a caller-supplied replacement executable."""
    if not command:
        return "review_python_arguments_missing"
    index = 0
    while index < len(command) and command[index] in {
        "-B",
        "-E",
        "-I",
        "-S",
        "-s",
        "-u",
    }:
        index += 1
    if index >= len(command):
        return "review_python_payload_missing"
    token = command[index]
    if token in {"-m", "-c"}:
        if index + 1 >= len(command) or not command[index + 1]:
            return "review_python_payload_missing"
        return ""
    if token.lower().endswith(".py"):
        return ""
    return "caller_replacement_interpreter_rejected"


_REVIEW_PYTHON_IDENTITY_PROBE = (
    "import importlib.metadata,json,re,site,sys;"
    "packages=[];"
    "[(packages.append({'name':re.sub(r'[-_.]+','-',n).lower(),"
    "'version':d.version}) if (n:=d.metadata.get('Name')) else None) "
    "for d in importlib.metadata.distributions()];"
    "print(json.dumps({'base_prefix':sys.base_prefix,"
    "'executable':sys.executable,'installed_packages':sorted(packages,"
    "key=lambda item:(item['name'],item['version'])),'prefix':sys.prefix,"
    "'user_site_enabled':site.ENABLE_USER_SITE,"
    "'version':'.'.join(map(str,sys.version_info[:3]))},sort_keys=True))"
)


def _probe_review_python(interpreter: Path, environment: Path):
    command = [str(interpreter), "-I", "-c", _REVIEW_PYTHON_IDENTITY_PROBE]
    try:
        completed, duration = _run(command, cwd=environment)
    except OSError as exc:
        return None, {
            "command": [str(interpreter), "-I", "-c", "<identity probe>"],
            "duration_seconds": 0.0,
            "exit_code": None,
            "stdout": "",
            "stderr": "",
            "error_class": type(exc).__name__,
        }
    evidence = {
        "command": [str(interpreter), "-I", "-c", "<identity probe>"],
        "duration_seconds": duration,
        "exit_code": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
    }
    if completed.returncode != 0:
        return None, evidence
    try:
        identity = json.loads(completed.stdout.strip())
    except (json.JSONDecodeError, TypeError):
        return None, evidence
    installed = identity.get("installed_packages")
    if isinstance(installed, list):
        serialized = json.dumps(
            installed, ensure_ascii=False, separators=(",", ":"), sort_keys=True
        ).encode("utf-8")
        identity["installed_package_count"] = len(installed)
        identity["installed_packages_sha256"] = _sha256(serialized)
    return identity, evidence


def _review_python_identity_failures(
    identity: dict | None,
    *,
    creation_probe: dict,
    environment: Path,
    interpreter: Path,
    phase: str,
) -> list[str]:
    if not isinstance(identity, dict):
        return [f"child_identity_{phase}_unavailable"]
    failures = []
    executable = identity.get("executable")
    prefix = identity.get("prefix")
    base_prefix = identity.get("base_prefix")
    if not executable or not os.path.isabs(str(executable)):
        failures.append(f"child_executable_{phase}_not_absolute")
    elif not _lexical_paths_equal(executable, interpreter):
        failures.append(f"child_executable_{phase}_not_creation_interpreter")
    if not prefix or not os.path.isabs(str(prefix)):
        failures.append(f"child_prefix_{phase}_not_absolute")
    elif not _lexical_paths_equal(prefix, environment):
        failures.append(f"child_prefix_{phase}_not_creation_environment")
    if not base_prefix or not os.path.isabs(str(base_prefix)):
        failures.append(f"child_base_prefix_{phase}_not_absolute")
    else:
        if prefix and _lexical_paths_equal(prefix, base_prefix):
            failures.append(f"child_interpreter_{phase}_not_isolated")
        creation_base_prefix = creation_probe.get("base_prefix")
        if not creation_base_prefix or not _lexical_paths_equal(
            base_prefix, creation_base_prefix
        ):
            failures.append(f"child_base_prefix_{phase}_not_creation_identity")
    if identity.get("version") != REVIEW_PYTHON_VERSION:
        failures.append(f"child_python_version_{phase}_not_exact")
    if identity.get("user_site_enabled") is not False:
        failures.append(f"child_user_site_{phase}_enabled")
    installed = identity.get("installed_packages")
    if not isinstance(installed, list):
        failures.append(f"child_inventory_{phase}_missing")
    return failures


def review_python_command_receipt(args: argparse.Namespace) -> int:
    """Execute Python arguments with the exact interpreter bound by a creation receipt."""
    command_arguments = list(args.command)
    if command_arguments and command_arguments[0] == "--":
        command_arguments.pop(0)
    output = Path(args.output)
    cwd = Path(getattr(args, "cwd", None) or Path.cwd()).resolve()
    receipt_path = Path(args.environment_receipt)
    failure_codes = []
    required_post_lock_value = getattr(args, "require_post_lock", None)
    required_post_lock = (
        Path(required_post_lock_value).resolve()
        if required_post_lock_value
        else None
    )
    required_post_lock_evidence = None
    required_post_versions = None
    post_inventory_exact = None
    if required_post_lock is not None:
        required_post_lock_evidence = _review_lock_evidence(required_post_lock)
        if required_post_lock_evidence.get("status") != "PASS":
            failure_codes.append("required_post_lock_not_exact")
        else:
            required_post_versions = {
                item["name"]: item["version"]
                for item in required_post_lock_evidence["packages"]
            }
    receipt_sha256 = None
    creation = None
    receipt_error = ""
    try:
        receipt_bytes = receipt_path.read_bytes()
        receipt_sha256 = _sha256(receipt_bytes)
    except OSError as exc:
        receipt_bytes = None
        receipt_error = type(exc).__name__
        failure_codes.append("environment_receipt_missing")
    if receipt_bytes is not None:
        try:
            creation = json.loads(receipt_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            receipt_error = "invalid_json"
            failure_codes.append("environment_receipt_invalid_json")
    if creation is not None and not isinstance(creation, dict):
        creation = None
        failure_codes.append("environment_receipt_not_object")

    environment = None
    interpreter = None
    creation_probe = None
    if creation is not None:
        if creation.get("schema") != "continuityos-review-environment-create-v1":
            failure_codes.append("environment_receipt_schema_not_exact")
        if creation.get("status") != "PASS":
            failure_codes.append("environment_receipt_status_not_pass")
        if creation.get("failure_codes") != []:
            failure_codes.append("environment_receipt_failure_codes_present")
        if creation.get("environment_preexisted") is not False:
            failure_codes.append("environment_receipt_not_fresh")
        if creation.get("path_has_authority") is not False:
            failure_codes.append("environment_receipt_path_authority_not_false")
        if creation.get("expected_python_version") != REVIEW_PYTHON_VERSION:
            failure_codes.append("environment_receipt_python_version_not_exact")
        environment_value = creation.get("environment")
        interpreter_value = creation.get("interpreter")
        if not environment_value or not os.path.isabs(str(environment_value)):
            failure_codes.append("environment_path_not_absolute")
        else:
            environment = Path(str(environment_value))
            try:
                environment_exists = environment.is_dir()
            except (OSError, ValueError):
                environment_exists = False
            if not environment_exists:
                failure_codes.append("environment_directory_missing")
        if not interpreter_value or not os.path.isabs(str(interpreter_value)):
            failure_codes.append("interpreter_path_not_absolute")
        else:
            interpreter = Path(str(interpreter_value))
            if environment is not None:
                _, expected_interpreter = _review_environment_layout(environment)
                if not _lexical_paths_equal(interpreter, expected_interpreter):
                    failure_codes.append("interpreter_path_not_canonical")
                if not _lexical_path_is_within(interpreter, environment):
                    failure_codes.append("interpreter_outside_environment")
            try:
                interpreter_exists = interpreter.is_file()
            except (OSError, ValueError):
                interpreter_exists = False
            if not interpreter_exists:
                failure_codes.append("interpreter_missing")
        scripts_value = creation.get("scripts_directory")
        if not scripts_value or not os.path.isabs(str(scripts_value)):
            failure_codes.append("scripts_directory_not_absolute")
        elif environment is not None:
            expected_scripts, _ = _review_environment_layout(environment)
            if not _lexical_paths_equal(scripts_value, expected_scripts):
                failure_codes.append("scripts_directory_not_canonical")
            if interpreter is not None and not _lexical_paths_equal(
                scripts_value, interpreter.parent
            ):
                failure_codes.append("scripts_directory_not_interpreter_parent")
        creation_probe = creation.get("interpreter_probe")
        if not isinstance(creation_probe, dict):
            failure_codes.append("creation_interpreter_probe_missing")
        elif environment is not None and interpreter is not None:
            probe_executable = creation_probe.get("executable")
            probe_prefix = creation_probe.get("prefix")
            probe_base_prefix = creation_probe.get("base_prefix")
            if not probe_executable or not os.path.isabs(str(probe_executable)):
                failure_codes.append("creation_probe_executable_not_absolute")
            elif not _lexical_paths_equal(probe_executable, interpreter):
                failure_codes.append("creation_probe_executable_mismatch")
            if not probe_prefix or not os.path.isabs(str(probe_prefix)):
                failure_codes.append("creation_probe_prefix_not_absolute")
            elif not _lexical_paths_equal(probe_prefix, environment):
                failure_codes.append("creation_probe_prefix_mismatch")
            if not probe_base_prefix or not os.path.isabs(str(probe_base_prefix)):
                failure_codes.append("creation_probe_base_prefix_not_absolute")
            elif probe_prefix and _lexical_paths_equal(
                probe_prefix, probe_base_prefix
            ):
                failure_codes.append("creation_probe_not_isolated")
            if creation_probe.get("version") != REVIEW_PYTHON_VERSION:
                failure_codes.append("creation_probe_version_mismatch")

    argument_failure = _review_python_argument_failure(command_arguments)
    if argument_failure:
        failure_codes.append(argument_failure)
    if not cwd.is_dir():
        failure_codes.append("command_cwd_missing")

    outer_identity_before = _outer_python_identity()
    path_evidence_before = _path_order_evidence(environment, interpreter)
    exact_command = (
        [str(interpreter), *command_arguments] if interpreter is not None else None
    )
    child_before = None
    child_after = None
    pre_probe = None
    post_probe = None
    execution_attempted = False
    completed = None
    duration = 0.0

    if not failure_codes and interpreter is not None and environment is not None:
        child_before, pre_probe = _probe_review_python(interpreter, environment)
        failure_codes.extend(
            _review_python_identity_failures(
                child_before,
                creation_probe=creation_probe,
                environment=environment,
                interpreter=interpreter,
                phase="before",
            )
        )

    if not failure_codes and exact_command is not None:
        child_env = dict(os.environ)
        child_env.pop("PYTHONPATH", None)
        child_env.pop("PYTHONHOME", None)
        child_env["PYTHONNOUSERSITE"] = "1"
        child_env["PYTHONUTF8"] = "1"
        execution_attempted = True
        try:
            completed, duration = _run(exact_command, cwd=cwd, env=child_env)
        except OSError as exc:
            failure_codes.append(f"child_command_launch_failed:{type(exc).__name__}")
        if completed is not None:
            _emit_completed(completed)
            if completed.returncode != 0:
                failure_codes.append("child_command_failed")
        child_after, post_probe = _probe_review_python(interpreter, environment)
        failure_codes.extend(
            _review_python_identity_failures(
                child_after,
                creation_probe=creation_probe,
                environment=environment,
                interpreter=interpreter,
                phase="after",
            )
        )
        if required_post_versions is not None:
            installed = (
                child_after.get("installed_packages")
                if isinstance(child_after, dict)
                else None
            )
            installed_versions, installed_duplicates = _inventory_versions(installed)
            post_inventory_exact = bool(
                installed_versions == required_post_versions
                and not installed_duplicates
                and len(installed or []) == len(required_post_versions)
            )
            if not post_inventory_exact:
                failure_codes.append("post_inventory_not_exact_locked_closure")
    if required_post_lock is not None and post_inventory_exact is None:
        post_inventory_exact = False

    if child_before and child_after:
        for key in ("executable", "prefix", "base_prefix", "version"):
            left = child_before.get(key)
            right = child_after.get(key)
            equal = (
                _lexical_paths_equal(left, right)
                if key != "version" and left and right
                else left == right
            )
            if not equal:
                failure_codes.append(f"child_identity_changed:{key}")

    failure_codes = sorted(set(failure_codes))
    exit_code = completed.returncode if completed is not None else None
    outer_identity_after = _outer_python_identity()
    path_evidence_after = _path_order_evidence(environment, interpreter)
    payload = {
        "schema": "continuityos-review-python-command-receipt-v1",
        "environment_receipt": str(receipt_path.resolve()),
        "environment_receipt_sha256": receipt_sha256,
        "environment_receipt_error": receipt_error,
        "environment": str(environment) if environment is not None else None,
        "exact_interpreter": str(interpreter) if interpreter is not None else None,
        "expected_python_version": REVIEW_PYTHON_VERSION,
        "outer_identity_before": outer_identity_before,
        "outer_identity_after": outer_identity_after,
        "child_identity_before": child_before,
        "child_identity_after": child_after,
        "identity_probe_before": pre_probe,
        "identity_probe_after": post_probe,
        "path_evidence_before": path_evidence_before,
        "path_evidence_after": path_evidence_after,
        "required_post_lock": (
            str(required_post_lock) if required_post_lock is not None else None
        ),
        "required_post_lock_sha256": (
            required_post_lock_evidence.get("canonical_sha256")
            if required_post_lock_evidence is not None
            else None
        ),
        "required_post_versions": required_post_versions,
        "post_inventory_exact": post_inventory_exact,
        "python_environment_policy": {
            "PYTHONHOME": "removed",
            "PYTHONNOUSERSITE": "1",
            "PYTHONPATH": "removed",
            "PYTHONUTF8": "1",
        },
        "command_arguments": command_arguments,
        "exact_command": exact_command,
        "cwd": str(cwd),
        "execution_context": _safe_execution_context(cwd),
        "execution_attempted": execution_attempted,
        "duration_seconds": duration,
        "exit_code": exit_code,
        "platform": platform.platform(),
        "stdout": completed.stdout if completed is not None else "",
        "stderr": completed.stderr if completed is not None else "",
        "failure_codes": failure_codes,
        "status": "PASS" if not failure_codes else "FAIL",
    }
    _write_json(output, payload)
    print(
        json.dumps(
            {
                "environment_receipt_sha256": receipt_sha256,
                "exact_interpreter": payload["exact_interpreter"],
                "exit_code": exit_code,
                "failure_codes": failure_codes,
                "path_order_class": path_evidence_before["order_class"],
                "status": payload["status"],
            },
            sort_keys=True,
        )
    )
    if payload["status"] == "PASS":
        return 0
    if completed is not None and completed.returncode != 0:
        return completed.returncode
    return 1


def verify_review_environment(args: argparse.Namespace) -> int:
    """Fail unless this exact isolated interpreter contains only the locked closure."""
    lock = Path(args.lock).resolve()
    lock_evidence = _review_lock_evidence(lock)
    expected = {
        item["name"]: item["version"] for item in lock_evidence["packages"]
    }
    prefix = Path(sys.prefix).resolve()
    base_prefix = Path(sys.base_prefix).resolve()
    executable = Path(os.path.abspath(sys.executable))
    executable_realpath = executable.resolve()
    installed = []
    by_name: dict[str, list[dict]] = {}
    failure_codes = list(lock_evidence["failure_codes"])

    for distribution in importlib.metadata.distributions():
        raw_name = distribution.metadata.get("Name")
        if not raw_name:
            failure_codes.append("installed_distribution_missing_name")
            continue
        name = _normalize_distribution_name(raw_name)
        location = Path(distribution.locate_file("")).resolve()
        record = {
            "name": name,
            "version": distribution.version,
            "location": str(location),
            "under_prefix": location == prefix or prefix in location.parents,
        }
        installed.append(record)
        by_name.setdefault(name, []).append(record)

    installed_names = set(by_name)
    missing = sorted(set(expected) - installed_names)
    unexpected = sorted(installed_names - set(expected))
    duplicates = sorted(name for name, records in by_name.items() if len(records) != 1)
    version_mismatches = sorted(
        {
            f"{name}:expected_{expected[name]}:observed_{record['version']}"
            for name, records in by_name.items()
            if name in expected
            for record in records
            if record["version"] != expected[name]
        }
    )
    outside_prefix = sorted(
        record["name"] for record in installed if not record["under_prefix"]
    )
    if prefix == base_prefix:
        failure_codes.append("review_interpreter_not_venv")
    executable_under_prefix = _lexical_path_is_within(executable, prefix)
    if not executable_under_prefix:
        failure_codes.append("review_interpreter_outside_venv")
    if site.ENABLE_USER_SITE is not False:
        failure_codes.append("review_user_site_enabled")
    if platform.python_version() != REVIEW_PYTHON_VERSION:
        failure_codes.append("review_python_version_not_exact")
    if missing:
        failure_codes.append("installed_packages_missing")
    if unexpected:
        failure_codes.append("installed_packages_unexpected")
    if duplicates:
        failure_codes.append("installed_packages_duplicate")
    if version_mismatches:
        failure_codes.append("installed_package_version_mismatch")
    if outside_prefix:
        failure_codes.append("installed_package_outside_venv")

    check_command = [
        sys.executable,
        "-I",
        "-m",
        "pip",
        "--disable-pip-version-check",
        "check",
    ]
    checked, duration = _run(check_command, cwd=Path.cwd())
    _emit_completed(checked)
    if checked.returncode != 0:
        failure_codes.append("pip_check_failed")

    payload = {
        "schema": "continuityos-review-environment-inventory-v1",
        "python_executable": str(executable),
        "python_executable_realpath": str(executable_realpath),
        "python_version": platform.python_version(),
        "expected_python_version": REVIEW_PYTHON_VERSION,
        "prefix": str(prefix),
        "base_prefix": str(base_prefix),
        "is_isolated_venv": prefix != base_prefix,
        "interpreter_under_prefix": executable_under_prefix,
        "user_site_enabled": site.ENABLE_USER_SITE,
        "review_lock_sha256": lock_evidence["canonical_sha256"],
        "expected_packages": expected,
        "installed_packages": sorted(installed, key=lambda item: item["name"]),
        "installed_package_count": len(installed),
        "missing_packages": missing,
        "unexpected_packages": unexpected,
        "duplicate_packages": duplicates,
        "version_mismatches": version_mismatches,
        "outside_prefix_packages": outside_prefix,
        "pip_check": {
            "command": check_command,
            "duration_seconds": duration,
            "exit_code": checked.returncode,
            "stdout": checked.stdout,
            "stderr": checked.stderr,
        },
        "failure_codes": sorted(set(failure_codes)),
        "status": "PASS" if not failure_codes else "FAIL",
    }
    _write_json(Path(args.output), payload)
    print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
    return 0 if payload["status"] == "PASS" else 1


def collect_nodeids(args: argparse.Namespace) -> int:
    command = [sys.executable, "-m", "pytest", "--collect-only", "-q"]
    completed, duration = _run(command, cwd=Path.cwd())
    _emit_completed(completed)
    nodeids = sorted(
        line.strip()
        for line in completed.stdout.splitlines()
        if line.startswith("tests/") and "::" in line
    )
    serialized = "".join(f"{nodeid}\n" for nodeid in nodeids).encode("utf-8")
    failure = ""
    if completed.returncode != 0:
        failure = "pytest collection failed"
    elif not nodeids:
        failure = "pytest returned no parseable node IDs"
    payload = {
        "schema": "continuityos-pytest-nodeids-v1",
        "command": command,
        "duration_seconds": duration,
        "exit_code": completed.returncode,
        "node_count": len(nodeids),
        "nodeids_sha256": _sha256(serialized),
        "nodeids": nodeids,
        "status": "FAIL" if failure else "PASS",
        "failure": failure,
        "stderr": completed.stderr,
    }
    _write_json(Path(args.output), payload)
    print(
        json.dumps(
            {key: payload[key] for key in ("status", "node_count", "nodeids_sha256")},
            sort_keys=True,
        )
    )
    return 1 if failure else 0


def wheel_test(args: argparse.Namespace) -> int:
    source_root = Path(args.source_root).resolve()
    wheel_dir = Path(args.wheel_dir).resolve()
    test_wheel_dir = Path(args.test_wheel_dir).resolve()
    review_lock = Path(args.review_lock).resolve()
    wheels = sorted(wheel_dir.glob("*.whl"))
    if len(wheels) != 1:
        raise SystemExit(f"expected exactly one wheel in {wheel_dir}, found {len(wheels)}")
    wheel = wheels[0]
    workspace = Path(args.workspace).resolve()
    if source_root == workspace or source_root in workspace.parents:
        raise SystemExit("wheel workspace must be outside the checkout")
    if workspace.exists() and any(workspace.iterdir()):
        raise SystemExit(f"wheel workspace is not empty: {workspace}")
    workspace.mkdir(parents=True, exist_ok=True)

    suite = workspace / "suite"
    shutil.copytree(source_root / "tests", suite / "tests")
    shutil.copy2(source_root / "gate_hook.py", suite / "gate_hook.py")
    venv_dir = workspace / "venv"
    venv.EnvBuilder(with_pip=True, system_site_packages=False).create(venv_dir)
    python = venv_dir / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    child_env = dict(os.environ)
    child_env.pop("PYTHONPATH", None)
    child_env["PYTHONNOUSERSITE"] = "1"
    child_env["PYTHONUTF8"] = "1"

    commands = []
    tooling_command = [
        str(python),
        "-m",
        "pip",
        "--isolated",
        "install",
        "--disable-pip-version-check",
        "--no-cache-dir",
        "--no-index",
        "--no-deps",
        "--force-reinstall",
        "--find-links",
        str(test_wheel_dir),
        "--require-hashes",
        "--only-binary=:all:",
        "-r",
        str(review_lock),
    ]
    tooled, tooling_duration = _run(tooling_command, cwd=suite, env=child_env)
    commands.append(
        {
            "name": "install_isolated_test_tooling",
            "command": tooling_command,
            "duration_seconds": tooling_duration,
            "exit_code": tooled.returncode,
            "stdout": tooled.stdout,
            "stderr": tooled.stderr,
        }
    )
    _emit_completed(tooled)

    install_command = [
        str(python),
        "-m",
        "pip",
        "install",
        "--no-index",
        "--no-deps",
        "--force-reinstall",
        str(wheel),
    ]
    installed, install_duration = _run(install_command, cwd=suite, env=child_env)
    commands.append(
        {
            "name": "install_wheel",
            "command": install_command,
            "duration_seconds": install_duration,
            "exit_code": installed.returncode,
            "stdout": installed.stdout,
            "stderr": installed.stderr,
        }
    )
    _emit_completed(installed)

    probe_code = f"""
import importlib.metadata, json, pathlib, sys, sysconfig
import continuityos
package_path = pathlib.Path(continuityos.__file__).resolve()
purelib = pathlib.Path(sysconfig.get_paths()["purelib"]).resolve()
source_root = pathlib.Path({str(source_root)!r}).resolve()
resolved_sys_path = []
for entry in sys.path:
    try:
        resolved_sys_path.append(str(pathlib.Path(entry or '.').resolve()))
    except OSError:
        resolved_sys_path.append(entry)
if str(source_root) in resolved_sys_path:
    raise SystemExit(f"source checkout leaked into wheel sys.path: {{source_root}}")
if purelib not in package_path.parents:
    raise SystemExit(f"wheel import is not under site-packages: {{package_path}}")
metadata_version = importlib.metadata.version("continuityos")
if continuityos.__version__ != metadata_version:
    raise SystemExit("wheel package and distribution versions disagree")
print(json.dumps({{"package_path": str(package_path), "purelib": str(purelib),
                  "package_version": continuityos.__version__,
                  "metadata_version": metadata_version,
                  "sys_path": resolved_sys_path}}, sort_keys=True))
"""
    probe_command = [str(python), "-c", probe_code]
    probed, probe_duration = _run(probe_command, cwd=suite, env=child_env)
    commands.append(
        {
            "name": "site_packages_probe",
            "command": [str(python), "-c", "<site-packages assertion>"],
            "duration_seconds": probe_duration,
            "exit_code": probed.returncode,
            "stdout": probed.stdout,
            "stderr": probed.stderr,
        }
    )
    _emit_completed(probed)

    test_command = [
        str(python),
        "-m",
        "pytest",
        "-q",
        "--import-mode=importlib",
        "tests",
        "--ignore=tests/test_ci_review_tool.py",
        "--ignore=tests/test_continuitybench_portable_context.py",
        "--ignore=tests/test_version_consistency.py",
        "--ignore=tests/test_packaging_hygiene.py",
    ]
    tested, test_duration = _run(test_command, cwd=suite, env=child_env)
    commands.append(
        {
            "name": "wheel_only_tests",
            "command": test_command,
            "duration_seconds": test_duration,
            "exit_code": tested.returncode,
            "stdout": tested.stdout,
            "stderr": tested.stderr,
        }
    )
    _emit_completed(tested)

    probe_payload = None
    if probed.returncode == 0 and probed.stdout.strip():
        try:
            probe_payload = json.loads(probed.stdout.strip().splitlines()[-1])
        except json.JSONDecodeError:
            pass
    source_root_excluded = bool(
        probe_payload
        and str(source_root) not in probe_payload.get("sys_path", [])
    )
    passed = (
        all(item["exit_code"] == 0 for item in commands)
        and source_root_excluded
    )
    _write_json(
        Path(args.output),
        {
            "schema": "continuityos-wheel-only-test-receipt-v1",
            "source_root_excluded": source_root_excluded,
            "site_packages_probe": probe_payload,
            "status": "PASS" if passed else "FAIL",
            "wheel": str(wheel),
            "wheel_sha256": _sha256_file(wheel),
            "review_lock": str(review_lock),
            "review_lock_sha256": _canonical_file_sha256(review_lock)[0],
            "workspace": str(workspace),
            "commands": commands,
        },
    )
    return 0 if passed else 1


def _workflow_step_block(text: str, name: str) -> str:
    match = re.search(
        rf"(?ms)^\s*- name: {re.escape(name)}\s*$.*?(?=^\s*- name: |\Z)",
        text,
    )
    return match.group(0) if match else ""


def _parse_workflow_yaml(text: str):
    import yaml
    from yaml.constructor import ConstructorError

    class UniqueSafeLoader(yaml.SafeLoader):
        pass

    def construct_mapping(loader, node, deep=False):
        mapping = {}
        for key_node, value_node in node.value:
            key = loader.construct_object(key_node, deep=deep)
            if key in mapping:
                raise ConstructorError(
                    "while constructing a mapping",
                    node.start_mark,
                    f"duplicate key: {key!r}",
                    key_node.start_mark,
                )
            mapping[key] = loader.construct_object(value_node, deep=deep)
        return mapping

    UniqueSafeLoader.add_constructor(
        yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
        construct_mapping,
    )
    return yaml.load(text, Loader=UniqueSafeLoader)


def _workflow_key_path(path: tuple[object, ...]) -> str:
    rendered = ""
    for item in path:
        if isinstance(item, int):
            rendered += f"[{item}]"
        elif rendered:
            rendered += f".{item}"
        else:
            rendered = str(item)
    return rendered or "<document>"


def _walk_workflow_scalars(value, path=(), active_container_ids=None):
    if active_container_ids is None:
        active_container_ids = set()
    if isinstance(value, str):
        yield path, value
        return
    if not isinstance(value, (dict, list)):
        return

    container_id = id(value)
    if container_id in active_container_ids:
        raise ValueError(f"cyclic YAML value at {_workflow_key_path(path)}")
    active_container_ids.add(container_id)
    try:
        if isinstance(value, dict):
            for index, (key, child) in enumerate(value.items()):
                child_key = str(key)
                if isinstance(key, str) and ("${{" in key or "}}" in key):
                    yield path + (f"<key[{index}]>",), key
                    child_key = f"<expression-key[{index}]>"
                yield from _walk_workflow_scalars(
                    child,
                    path + (child_key,),
                    active_container_ids,
                )
        else:
            for index, child in enumerate(value):
                yield from _walk_workflow_scalars(
                    child,
                    path + (index,),
                    active_container_ids,
                )
    finally:
        active_container_ids.remove(container_id)


def _github_expression_bodies(value: str, *, implicit: bool = False):
    bodies = []
    errors = []
    spans = []
    position = 0
    while position < len(value):
        opening = value.find("${{", position)
        if opening < 0:
            break

        closing = -1
        nested = False
        quote = None
        cursor = opening + 3
        while cursor < len(value) - 1:
            character = value[cursor]
            if quote is not None:
                if character == quote:
                    if quote == "'" and value.startswith("''", cursor):
                        cursor += 2
                        continue
                    quote = None
                elif quote == '"' and character == "\\":
                    cursor += 2
                    continue
                cursor += 1
                continue
            if character in {"'", '"'}:
                quote = character
                cursor += 1
                continue
            if value.startswith("${{", cursor):
                nested = True
                cursor += 3
                continue
            if value.startswith("}}", cursor):
                closing = cursor
                break
            cursor += 1

        if closing < 0:
            errors.append("unclosed_expression")
            break
        body = value[opening + 3 : closing]
        spans.append((opening, closing + 2))
        if nested:
            errors.append("nested_expression")
        elif not body.strip():
            errors.append("empty_expression")
        else:
            bodies.append(body.strip())
        position = closing + 2

    outside = []
    previous = 0
    for opening, closing in spans:
        outside.append(value[previous:opening])
        previous = closing
    outside.append(value[previous:])
    outside_text = "".join(outside)
    if "}}" in outside_text:
        errors.append("unexpected_closing_delimiter")

    if implicit:
        if not spans and value.strip():
            bodies.append(value.strip())
        elif spans:
            if len(spans) != 1 or outside_text.strip():
                errors.append("mixed_if_expression_syntax")
    return bodies, errors


def _tokenize_workflow_expression(body: str):
    tokens = []
    errors = []
    position = 0
    punctuation = {
        ".": "DOT",
        ",": "COMMA",
        "(": "LPAREN",
        ")": "RPAREN",
        "[": "LBRACKET",
        "]": "RBRACKET",
        "*": "STAR",
    }
    while position < len(body):
        character = body[position]
        if character.isspace():
            position += 1
            continue
        if body.startswith(("&&", "||", "==", "!=", "<=", ">="), position):
            tokens.append(("OP", body[position : position + 2]))
            position += 2
            continue
        if character in "!<>":
            tokens.append(("OP", character))
            position += 1
            continue
        if character in punctuation:
            tokens.append((punctuation[character], character))
            position += 1
            continue
        if character == "'":
            cursor = position + 1
            closed = False
            while cursor < len(body):
                if body[cursor] == "'":
                    if body.startswith("''", cursor):
                        cursor += 2
                        continue
                    closed = True
                    cursor += 1
                    break
                cursor += 1
            if not closed:
                errors.append("unclosed_quote")
                position = len(body)
                continue
            tokens.append(("STRING", ""))
            position = cursor
            continue
        if character == '"':
            errors.append("double_quoted_string")
            cursor = position + 1
            while cursor < len(body):
                if body[cursor] == "\\":
                    cursor += 2
                    continue
                if body[cursor] == '"':
                    cursor += 1
                    break
                cursor += 1
            tokens.append(("STRING", ""))
            position = cursor
            continue
        number = re.match(
            r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?",
            body[position:],
        )
        if number:
            tokens.append(("NUMBER", number.group(0)))
            position += len(number.group(0))
            continue
        identifier = re.match(r"[A-Za-z_][A-Za-z0-9_-]*", body[position:])
        if identifier:
            tokens.append(("IDENT", identifier.group(0)))
            position += len(identifier.group(0))
            continue
        errors.append("invalid_token")
        position += 1
    tokens.append(("EOF", ""))
    return tokens, sorted(set(errors))


class _WorkflowExpressionParser:
    def __init__(self, tokens):
        self.tokens = tokens
        self.position = 0
        self.contexts = set()
        self.functions = set()
        self.unknown = set()
        self.errors = []

    def _current(self):
        return self.tokens[self.position]

    def _advance(self):
        token = self._current()
        if token[0] != "EOF":
            self.position += 1
        return token

    def _accept(self, kind, value=None):
        token = self._current()
        if token[0] != kind or (value is not None and token[1] != value):
            return False
        self._advance()
        return True

    def _expect(self, kind, detail):
        if self._accept(kind):
            return True
        self.errors.append(detail)
        return False

    def parse(self):
        self._parse_or()
        if self._current()[0] != "EOF":
            self.errors.append("trailing_token")
        return (
            sorted(self.contexts),
            sorted(self.unknown),
            sorted(self.functions),
            sorted(set(self.errors)),
        )

    def _parse_or(self):
        self._parse_and()
        while self._accept("OP", "||"):
            self._parse_and()

    def _parse_and(self):
        self._parse_equality()
        while self._accept("OP", "&&"):
            self._parse_equality()

    def _parse_equality(self):
        self._parse_relational()
        while self._current() in {("OP", "=="), ("OP", "!=")}:
            self._advance()
            self._parse_relational()

    def _parse_relational(self):
        self._parse_unary()
        while self._current() in {
            ("OP", "<"),
            ("OP", "<="),
            ("OP", ">"),
            ("OP", ">="),
        }:
            self._advance()
            self._parse_unary()

    def _parse_unary(self):
        if self._accept("OP", "!"):
            self._parse_unary()
            return
        self._parse_primary()

    def _parse_primary(self):
        kind, value = self._current()
        allow_suffix = False
        if kind == "IDENT":
            self._advance()
            lowered = value.casefold()
            if self._accept("LPAREN"):
                allow_suffix = True
                self.functions.add(lowered)
                if lowered not in WORKFLOW_EXPRESSION_FUNCTIONS:
                    self.unknown.add(value)
                argument_count = 0
                if not self._accept("RPAREN"):
                    self._parse_or()
                    argument_count = 1
                    while self._accept("COMMA"):
                        self._parse_or()
                        argument_count += 1
                    self._expect("RPAREN", "unclosed_function_call")
                arity = WORKFLOW_EXPRESSION_FUNCTION_ARITY.get(lowered)
                if arity is not None:
                    minimum, maximum = arity
                    if argument_count < minimum or (
                        maximum is not None and argument_count > maximum
                    ):
                        self.errors.append("invalid_function_arity")
            elif lowered in WORKFLOW_EXPRESSION_KEYWORDS:
                pass
            else:
                allow_suffix = True
                if value in WORKFLOW_CONTEXT_NAMES:
                    self.contexts.add(value)
                else:
                    self.unknown.add(value)
        elif kind in {"NUMBER", "STRING"}:
            self._advance()
        elif self._accept("LPAREN"):
            allow_suffix = True
            self._parse_or()
            self._expect("RPAREN", "unclosed_group")
        else:
            self.errors.append("expected_operand")
            self._advance()
            return

        while allow_suffix:
            if self._accept("DOT"):
                if not (self._accept("IDENT") or self._accept("STAR")):
                    self.errors.append("invalid_dereference")
                    return
                continue
            if self._accept("LBRACKET"):
                if not (
                    self._accept("STRING")
                    or self._accept("NUMBER")
                    or self._accept("STAR")
                ):
                    self.errors.append("invalid_index")
                    return
                if not self._expect("RBRACKET", "unclosed_index"):
                    return
                continue
            break


def _workflow_expression_contexts(body: str):
    if len(body) > WORKFLOW_EXPRESSION_MAX_LENGTH:
        return [], [], [], ["expression_length_limit"]
    tokens, token_errors = _tokenize_workflow_expression(body)
    if len(tokens) > WORKFLOW_EXPRESSION_MAX_TOKENS:
        return [], [], [], sorted(set(token_errors + ["expression_token_limit"]))
    parser = _WorkflowExpressionParser(tokens)
    try:
        contexts, unknown, functions, parse_errors = parser.parse()
    except RecursionError:
        return [], [], [], sorted(
            set(token_errors + ["expression_nesting_limit"])
        )
    return contexts, unknown, functions, sorted(set(token_errors + parse_errors))


def _allowed_workflow_contexts(path: tuple[object, ...]):
    if any(isinstance(item, str) and item.startswith("<") for item in path):
        return None
    if path == ("concurrency", "group"):
        return frozenset({"github", "inputs", "vars"})
    if (
        len(path) == 3
        and path[0] == "jobs"
        and path[2] in {"name", "runs-on"}
    ):
        return WORKFLOW_PRE_DISPATCH_CONTEXTS
    if (
        len(path) == 4
        and path[0] == "jobs"
        and path[2] == "env"
    ):
        return WORKFLOW_JOB_ENV_CONTEXTS
    if (
        len(path) >= 5
        and path[0] == "jobs"
        and path[2] == "steps"
        and isinstance(path[3], int)
    ):
        if len(path) == 5 and path[4] in {"run", "working-directory"}:
            return WORKFLOW_STEP_CONTEXTS
        if len(path) == 5 and path[4] == "if":
            return WORKFLOW_STEP_IF_CONTEXTS
        if len(path) == 6 and path[4] in {"env", "with"}:
            return WORKFLOW_STEP_CONTEXTS
    return None


def _allowed_workflow_functions(path: tuple[object, ...]):
    if _allowed_workflow_contexts(path) is None:
        return frozenset()
    allowed = WORKFLOW_GENERAL_EXPRESSION_FUNCTIONS
    if (
        len(path) >= 5
        and path[0] == "jobs"
        and path[2] == "steps"
        and isinstance(path[3], int)
    ):
        allowed |= WORKFLOW_HASH_EXPRESSION_FUNCTIONS
        if len(path) == 5 and path[4] == "if":
            allowed |= WORKFLOW_STATUS_EXPRESSION_FUNCTIONS
    return allowed


def _workflow_if_path(path: tuple[object, ...]) -> bool:
    return (
        len(path) == 5
        and path[0] == "jobs"
        and path[2] == "steps"
        and isinstance(path[3], int)
        and path[4] == "if"
    )


def _workflow_expression_context_evidence(document):
    references = []
    findings = []
    checked_expression_count = 0
    try:
        scalars = list(_walk_workflow_scalars(document))
    except (ValueError, RecursionError) as exc:
        detail = (
            "document_nesting_limit"
            if isinstance(exc, RecursionError)
            else "cyclic_yaml_value"
        )
        findings.append(
            {
                "code": "malformed_expression",
                "detail": detail,
                "path": "<document>",
            }
        )
        scalars = []

    for path, value in scalars:
        key_path = _workflow_key_path(path)
        bodies, delimiter_errors = _github_expression_bodies(
            value,
            implicit=_workflow_if_path(path),
        )
        for detail in delimiter_errors:
            findings.append(
                {
                    "code": "malformed_expression",
                    "detail": detail,
                    "path": key_path,
                }
            )
        for body in bodies:
            checked_expression_count += 1
            allowed = _allowed_workflow_contexts(path)
            allowed_functions = _allowed_workflow_functions(path)
            contexts, unknown_symbols, functions, syntax_errors = (
                _workflow_expression_contexts(body)
            )
            references.append(
                {
                    "allowed_contexts": sorted(allowed or ()),
                    "allowed_functions": sorted(allowed_functions),
                    "contexts": contexts,
                    "functions": functions,
                    "path": key_path,
                }
            )
            if allowed is None:
                findings.append(
                    {
                        "code": "unsupported_expression_key_path",
                        "path": key_path,
                    }
                )
            for detail in syntax_errors:
                findings.append(
                    {
                        "code": "malformed_expression",
                        "detail": detail,
                        "path": key_path,
                    }
                )
            for context in unknown_symbols:
                findings.append(
                    {
                        "code": "unknown_context",
                        "context": context,
                        "path": key_path,
                    }
                )
            for function in sorted(set(functions) - allowed_functions):
                findings.append(
                    {
                        "code": "function_not_available",
                        "function": function,
                        "path": key_path,
                    }
                )
            if allowed is not None:
                for context in sorted(set(contexts) - allowed):
                    findings.append(
                        {
                            "code": "context_not_available",
                            "context": context,
                            "path": key_path,
                        }
                    )

    findings.sort(
        key=lambda item: (
            item["path"],
            item["code"],
            item.get("context", ""),
            item.get("function", ""),
            item.get("detail", ""),
        )
    )
    references.sort(key=lambda item: (item["path"], item["contexts"]))
    failure_codes = []
    for finding in findings:
        parts = [finding["code"], finding["path"]]
        if finding.get("context"):
            parts.append(finding["context"])
        if finding.get("function"):
            parts.append(finding["function"])
        if finding.get("detail"):
            parts.append(finding["detail"])
        failure_codes.append(":".join(parts))
    return {
        "checked_expression_count": checked_expression_count,
        "failure_codes": failure_codes,
        "findings": findings,
        "references": references,
        "status": "PASS" if not findings else "FAIL",
    }


def workflow_policy(args: argparse.Namespace) -> int:
    workflow = Path(args.workflow).resolve()
    text = workflow.read_text(encoding="utf-8")
    normalized_text = text.replace("\r\n", "\n").replace("\r", "\n")
    normalized_workflow_sha256 = _sha256(normalized_text.encode("utf-8"))
    lowered = text.lower()
    forbidden = {
        "secrets expression": "secrets.",
        "deployment trigger": "deployment",
        "release trigger": "release:",
        "schedule trigger": "schedule:",
        "tag trigger": "tags:",
        "privileged PR trigger": "pull_request_target:",
        "GitHub environment": "environment:",
        "non-mandatory step": "continue-on-error:",
    }
    findings = [name for name, token in forbidden.items() if token in lowered]
    if normalized_workflow_sha256 != REVIEWED_WORKFLOW_SHA256:
        findings.append("workflow content not exact reviewed form")
    if re.search(r"(?mi)^\s+[a-z][a-z-]*:\s*write\s*$", text):
        findings.append("write permission")
    required = [
        "pull_request:",
        "review/**",
        "ubuntu-latest",
        "windows-latest",
        "persist-credentials: false",
        "exact-index",
        "wheel-test",
        "compileall",
        "release_hardening_probes.py",
        "verify-materialized",
        "bench.continuitybench",
        "governance-corpus-detail.json",
        "test_ci_linux_symlink_realpath.py",
        "source-rebind",
        "final-gate",
        "validate-lock",
        "create-review-environment",
        "run-review-python",
        "verify-review-environment",
        "python-version: \"3.11.9\"",
        "architecture: \"x64\"",
        "requirements/review-ci-py311.lock",
        "--require-hashes",
        "--only-binary=:all:",
        "--no-isolation",
        "--no-build-isolation",
    ]
    for action, ref in REVIEWED_ACTION_REFS.items():
        required.append(f"{action}@{ref}")
    missing = [token for token in required if token not in text]
    lock_evidence = _review_lock_evidence(Path(args.review_lock))
    for code in lock_evidence["failure_codes"]:
        missing.append(f"review lock: {code}")

    yaml_error = ""
    document = None
    steps = []
    try:
        document = _parse_workflow_yaml(text)
        steps = document["jobs"]["review"]["steps"]
        if not isinstance(steps, list):
            raise TypeError("jobs.review.steps is not a list")
    except Exception as exc:
        yaml_error = f"{type(exc).__name__}: {exc}"
        missing.append("valid unique-key workflow YAML")
        document = None
        steps = []

    if document is None:
        context_validation = {
            "checked_expression_count": 0,
            "failure_codes": ["yaml_document_unavailable"],
            "findings": [
                {
                    "code": "yaml_document_unavailable",
                    "path": "<document>",
                }
            ],
            "references": [],
            "status": "FAIL",
        }
    else:
        context_validation = _workflow_expression_context_evidence(document)
    for failure_code in context_validation["failure_codes"]:
        findings.append(f"workflow context: {failure_code}")

    if document is not None:
        normalized_top_keys = {
            "on" if key is True else str(key) for key in document.keys()
        }
        if normalized_top_keys != {
            "name",
            "on",
            "permissions",
            "concurrency",
            "jobs",
        }:
            findings.append("unexpected workflow top-level keys")
        trigger = document.get("on", document.get(True))
        if trigger != {
            "pull_request": None,
            "push": {
                "branches": [
                    "review/**",
                    "codex/review/**",
                    "codex/sibling-ci-*",
                ]
            },
        }:
            findings.append("workflow triggers not exact review-only set")
        if document.get("permissions") != {"contents": "read"}:
            findings.append("permissions not exact read-only")
        if document.get("concurrency") != {
            "group": "review-gates-${{ github.ref }}",
            "cancel-in-progress": True,
        }:
            findings.append("concurrency policy not exact")
        jobs = document.get("jobs", {})
        if not isinstance(jobs, dict) or set(jobs) != {"review"}:
            findings.append("unexpected workflow jobs")
        else:
            review_job = jobs["review"]
            if set(review_job) != {
                "name",
                "runs-on",
                "timeout-minutes",
                "env",
                "strategy",
                "steps",
            }:
                findings.append("unexpected review job keys")
            if review_job.get("runs-on") != "${{ matrix.os }}":
                findings.append("runner selection not matrix-bound")
            if review_job.get("timeout-minutes") != 35:
                findings.append("job timeout not exact")
            if review_job.get("env") != {
                "CONTINUITYOS_SILENCE_EMBED_WARN": "1",
                "PYTHONNOUSERSITE": "1",
                "PYTHONUTF8": "1",
                "PYTEST_ADDOPTS": "-p no:cacheprovider",
            }:
                findings.append("job environment not exact")
            strategy = review_job.get("strategy", {})
            if strategy != {
                "fail-fast": False,
                "matrix": {
                    "include": [
                        {"os": "ubuntu-latest", "label": "ubuntu"},
                        {"os": "windows-latest", "label": "windows"},
                    ]
                },
            }:
                findings.append("runner matrix not exact")

    step_by_id = {
        step.get("id"): step
        for step in steps
        if isinstance(step, dict) and isinstance(step.get("id"), str)
    }
    duplicate_ids = sorted(
        {
            step.get("id")
            for step in steps
            if isinstance(step, dict)
            and step.get("id")
            and sum(
                1
                for candidate in steps
                if isinstance(candidate, dict)
                and candidate.get("id") == step.get("id")
            )
            > 1
        }
    )
    ordered_step_ids = [
        step.get("id")
        for step in steps
        if isinstance(step, dict) and isinstance(step.get("id"), str)
    ]
    if tuple(ordered_step_ids) != WORKFLOW_STEP_IDS:
        findings.append("unexpected workflow step sequence")
    for step_id in MANDATORY_STEP_IDS:
        if step_id not in step_by_id:
            missing.append(f"mandatory step id: {step_id}")
    if duplicate_ids:
        findings.append("duplicate step ids")

    if step_by_id.get("setup_python", {}).get("with") != {
        "python-version": REVIEW_PYTHON_VERSION,
        "architecture": "x64",
    }:
        findings.append("setup-python inputs not exact")

    configure_pycache_step = step_by_id.get("configure_pycache", {})
    if set(configure_pycache_step) != {"name", "id", "env", "shell", "run"}:
        findings.append("runner-scoped pycache step keys not exact")
    if configure_pycache_step.get("name") != (
        "Configure runner-scoped Python bytecode cache"
    ):
        findings.append("runner-scoped pycache step name not exact")
    if configure_pycache_step.get("env") != {
        "PYTHONPYCACHEPREFIX": "${{ runner.temp }}/continuityos-pycache"
    }:
        findings.append("runner-scoped pycache environment not exact")
    if configure_pycache_step.get("shell") != "python":
        findings.append("runner-scoped pycache shell not exact")

    required_step_tokens = {
        "configure_pycache": (
            'os.environ["GITHUB_ENV"]',
            "PYTHONPYCACHEPREFIX",
            '"a", encoding="utf-8", newline="\\n"',
        ),
        "create_review_env": (
            "create-review-environment",
            "${{ runner.temp }}/continuityos-review-venv",
        ),
        "install_tooling": (
            "--isolated",
            "--no-cache-dir",
            "--no-deps",
            "--force-reinstall",
            "--require-hashes",
            "--only-binary=:all:",
            "--index-url https://pypi.org/simple",
            "--require-post-lock requirements/review-ci-py311.lock",
            "requirements/review-ci-py311.lock",
        ),
        "wheel_tooling": (
            "--isolated",
            "--no-cache-dir",
            "--require-hashes",
            "--only-binary=:all:",
            "--index-url https://pypi.org/simple",
            "requirements/review-ci-py311.lock",
        ),
        "wheel_build": ("--no-isolation",),
        "wheel_tests": (
            "--review-lock requirements/review-ci-py311.lock",
        ),
        "editable_install": ("--no-deps", "--no-build-isolation"),
        "pip_check": (
            "verify-review-environment",
            "--lock requirements/review-ci-py311.lock",
        ),
        "final_gate": (
            '--step "configure_pycache=${{ steps.configure_pycache.outcome }}"',
        ),
    }
    for step_id, tokens in required_step_tokens.items():
        command = str(step_by_id.get(step_id, {}).get("run", ""))
        for token in tokens:
            if token not in command:
                missing.append(f"step token: {step_id}: {token}")

    for step_id, receipt_name in REVIEW_PYTHON_STEP_RECEIPTS.items():
        command = str(step_by_id.get(step_id, {}).get("run", ""))
        binding_tokens = (
            "python -m tools.ci_review run-review-python",
            f'--environment-receipt "{REVIEW_ENVIRONMENT_RECEIPT_WORKFLOW_PATH}"',
            f"/continuityos-review-receipts/{receipt_name}",
            "-- ",
        )
        for token in binding_tokens:
            if token not in command:
                missing.append(f"review interpreter binding: {step_id}: {token}")
        if re.search(
            r"--\s+(?:python(?:\.exe)?|py(?:\.exe)?)(?:\s|$)",
            command,
            flags=re.IGNORECASE,
        ):
            findings.append(f"nested generic interpreter: {step_id}")

    action_refs = {}
    for step in steps:
        if not isinstance(step, dict) or "uses" not in step:
            continue
        specification = str(step["uses"])
        if specification.startswith(("./", "docker://")):
            findings.append(f"unreviewed local/container action: {specification}")
            continue
        if "@" not in specification:
            findings.append(f"action missing ref: {specification}")
            continue
        action, ref = specification.rsplit("@", 1)
        action_refs[action] = ref
        if not re.fullmatch(r"[0-9a-f]{40}", ref):
            findings.append(f"mutable action ref: {specification}")
        elif REVIEWED_ACTION_REFS.get(action) != ref:
            findings.append(f"unreviewed action SHA: {specification}")
    if action_refs != REVIEWED_ACTION_REFS:
        missing.append("exact reviewed action map")

    always_step_ids = (
        "portable_probes",
        "linux_symlink",
        "materialized_rebind",
        "post_rebind",
        "final_gate",
        "receipt_manifest",
        "upload_receipts",
        "enforce_conclusions",
    )
    for step_id in always_step_ids:
        step = step_by_id.get(step_id, {})
        condition = str(step.get("if", ""))
        if "always()" not in condition:
            missing.append(f"always gate id: {step_id}")
    linux_condition = str(step_by_id.get("linux_symlink", {}).get("if", ""))
    if "runner.os == 'Linux'" not in linux_condition:
        missing.append("Linux runner condition: linux_symlink")

    required_order = (
        "materialized_rebind",
        "post_rebind",
        "final_gate",
        "receipt_manifest",
        "upload_receipts",
        "enforce_conclusions",
    )
    positions = {
        step.get("id"): index
        for index, step in enumerate(steps)
        if isinstance(step, dict) and step.get("id")
    }
    if not all(item in positions for item in required_order) or not all(
        positions[left] < positions[right]
        for left, right in zip(required_order, required_order[1:])
        if left in positions and right in positions
    ):
        missing.append("POST/final/manifest/upload/enforce order")

    if any(
        isinstance(step, dict) and step.get("continue-on-error")
        for step in steps
    ):
        findings.append("non-mandatory step")
    payload = {
        "schema": "continuityos-review-workflow-policy-v3",
        "workflow": str(workflow),
        "workflow_sha256": _sha256_file(workflow),
        "normalized_workflow_sha256": normalized_workflow_sha256,
        "reviewed_workflow_sha256": REVIEWED_WORKFLOW_SHA256,
        "yaml_parse_status": "PASS" if not yaml_error else "FAIL",
        "yaml_error": yaml_error,
        "context_validation": context_validation,
        "step_ids": ordered_step_ids,
        "duplicate_step_ids": duplicate_ids,
        "action_refs": action_refs,
        "reviewed_action_refs": REVIEWED_ACTION_REFS,
        "review_lock": lock_evidence,
        "forbidden_findings": findings,
        "missing_required_tokens": missing,
        "status": "PASS" if not findings and not missing else "FAIL",
    }
    _write_json(Path(args.output), payload)
    print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
    return 0 if payload["status"] == "PASS" else 1


def _step_conclusions(values: list[str]) -> tuple[dict[str, str], list[str]]:
    conclusions = {}
    errors = []
    for value in values:
        if "=" not in value:
            errors.append(f"malformed_step_conclusion:{value}")
            continue
        name, conclusion = value.split("=", 1)
        if name in conclusions:
            errors.append(f"duplicate_step_conclusion:{name}")
        conclusions[name] = conclusion
    return conclusions, errors


def _read_json_receipt(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8")), ""
    except OSError:
        return None, "missing"
    except json.JSONDecodeError:
        return None, "invalid_json"


def _inventory_versions(records) -> tuple[dict[str, str], list[str]]:
    versions = {}
    duplicates = []
    if not isinstance(records, list):
        return versions, ["<inventory-not-list>"]
    for record in records:
        if not isinstance(record, dict):
            duplicates.append("<inventory-record-not-object>")
            continue
        name = record.get("name")
        version = record.get("version")
        if not isinstance(name, str) or not isinstance(version, str):
            duplicates.append("<inventory-record-invalid>")
            continue
        normalized = _normalize_distribution_name(name)
        if normalized in versions:
            duplicates.append(normalized)
        versions[normalized] = version
    return versions, sorted(set(duplicates))


def _inventory_locations_within(records, prefix) -> bool:
    if not isinstance(records, list) or not prefix or not os.path.isabs(str(prefix)):
        return False
    for record in records:
        if not isinstance(record, dict) or record.get("under_prefix") is not True:
            return False
        location = record.get("location")
        if not location or not os.path.isabs(str(location)):
            return False
        try:
            if not _lexical_path_is_within(location, prefix):
                return False
        except (OSError, TypeError, ValueError):
            return False
    return True


def _review_python_binding_failures(
    name: str,
    payload: dict | None,
    *,
    creation_sha256: str | None,
    environment: str | None,
    interpreter: str | None,
    creation_probe: dict,
) -> list[str]:
    prefix = f"review_python_binding:{name}"
    if not isinstance(payload, dict):
        return [f"{prefix}:missing"]
    failures = []
    if payload.get("schema") != "continuityos-review-python-command-receipt-v1":
        failures.append(f"{prefix}:schema_not_exact")
    if payload.get("environment_receipt_sha256") != creation_sha256:
        failures.append(f"{prefix}:creation_receipt_sha_mismatch")
    if payload.get("status") != "PASS":
        failures.append(f"{prefix}:status_not_pass")
    if payload.get("failure_codes") != []:
        failures.append(f"{prefix}:failure_codes_present")
    if payload.get("execution_attempted") is not True:
        failures.append(f"{prefix}:execution_not_attempted")
    if payload.get("exit_code") != 0:
        failures.append(f"{prefix}:exit_code_not_zero")
    if payload.get("expected_python_version") != REVIEW_PYTHON_VERSION:
        failures.append(f"{prefix}:expected_version_not_exact")
    if payload.get("python_environment_policy") != {
        "PYTHONHOME": "removed",
        "PYTHONNOUSERSITE": "1",
        "PYTHONPATH": "removed",
        "PYTHONUTF8": "1",
    }:
        failures.append(f"{prefix}:python_environment_policy_not_exact")
    if not environment or not payload.get("environment") or not _lexical_paths_equal(
        payload["environment"], environment
    ):
        failures.append(f"{prefix}:environment_mismatch")
    if not interpreter or not payload.get("exact_interpreter") or not _lexical_paths_equal(
        payload["exact_interpreter"], interpreter
    ):
        failures.append(f"{prefix}:interpreter_mismatch")

    exact_command = payload.get("exact_command")
    arguments = payload.get("command_arguments")
    if not isinstance(exact_command, list) or not exact_command:
        failures.append(f"{prefix}:exact_command_missing")
    else:
        if not interpreter or not _lexical_paths_equal(exact_command[0], interpreter):
            failures.append(f"{prefix}:command_interpreter_mismatch")
        if not isinstance(arguments, list) or exact_command[1:] != arguments:
            failures.append(f"{prefix}:command_arguments_mismatch")
        elif _review_python_argument_failure(arguments):
            failures.append(f"{prefix}:command_arguments_not_python_payload")

    for phase in ("before", "after"):
        outer = payload.get(f"outer_identity_{phase}")
        if not isinstance(outer, dict):
            failures.append(f"{prefix}:outer_identity_{phase}_missing")
        else:
            for key in ("executable", "prefix", "base_prefix"):
                if not outer.get(key) or not os.path.isabs(str(outer[key])):
                    failures.append(f"{prefix}:outer_{key}_{phase}_not_absolute")
            if not isinstance(outer.get("version"), str) or not outer["version"]:
                failures.append(f"{prefix}:outer_version_{phase}_missing")

        path_evidence = payload.get(f"path_evidence_{phase}")
        if not isinstance(path_evidence, dict):
            failures.append(f"{prefix}:path_evidence_{phase}_missing")
        else:
            if not re.fullmatch(r"[0-9a-f]{64}", str(path_evidence.get("path_sha256", ""))):
                failures.append(f"{prefix}:path_sha_{phase}_invalid")
            if not path_evidence.get("order_class"):
                failures.append(f"{prefix}:path_order_{phase}_missing")
            if not path_evidence.get("generic_python_resolution_class"):
                failures.append(f"{prefix}:generic_resolution_{phase}_missing")

        child = payload.get(f"child_identity_{phase}")
        if not isinstance(child, dict):
            failures.append(f"{prefix}:child_identity_{phase}_missing")
            continue
        child_executable = child.get("executable")
        child_prefix = child.get("prefix")
        child_base_prefix = child.get("base_prefix")
        if not interpreter or not child_executable or not _lexical_paths_equal(
            child_executable, interpreter
        ):
            failures.append(f"{prefix}:child_executable_{phase}_mismatch")
        if not environment or not child_prefix or not _lexical_paths_equal(
            child_prefix, environment
        ):
            failures.append(f"{prefix}:child_prefix_{phase}_mismatch")
        creation_base_prefix = creation_probe.get("base_prefix")
        if not creation_base_prefix or not child_base_prefix or not _lexical_paths_equal(
            child_base_prefix, creation_base_prefix
        ):
            failures.append(f"{prefix}:child_base_prefix_{phase}_mismatch")
        if child.get("version") != REVIEW_PYTHON_VERSION:
            failures.append(f"{prefix}:child_version_{phase}_mismatch")
        if child.get("user_site_enabled") is not False:
            failures.append(f"{prefix}:child_user_site_{phase}_enabled")
        installed = child.get("installed_packages")
        if not isinstance(installed, list):
            failures.append(f"{prefix}:child_inventory_{phase}_missing")
        else:
            serialized = json.dumps(
                installed,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
            if child.get("installed_package_count") != len(installed):
                failures.append(f"{prefix}:child_inventory_count_{phase}_mismatch")
            if child.get("installed_packages_sha256") != _sha256(serialized):
                failures.append(f"{prefix}:child_inventory_sha_{phase}_mismatch")
    return failures


def final_gate(args: argparse.Namespace) -> int:
    directory = Path(args.directory).resolve()
    output = Path(args.output)
    runner_os = args.runner_os.lower()
    conclusions, failure_codes = _step_conclusions(list(args.step))
    receipt_statuses = {}
    if args.runner_arch != "X64":
        failure_codes.append(f"unsupported_runner_arch:{args.runner_arch}")

    for step_id in MANDATORY_STEP_IDS:
        expected = (
            "skipped"
            if step_id == "linux_symlink" and runner_os == "windows"
            else "success"
        )
        observed = conclusions.get(step_id)
        if observed != expected:
            failure_codes.append(
                f"step_conclusion:{step_id}:expected_{expected}:observed_{observed}"
            )

    required_status_receipts = {
        "review-lock-policy.json": "status",
        "create-review-environment.json": "status",
        "install-review-tooling.json": "status",
        "review-tooling-environment.json": "status",
        "workflow-policy.json": "status",
        "materialized-source.json": "status",
        "exact-index-secret-scan.json": "status",
        "clean-source-metadata.json": "status",
        "pytest-nodeids.json": "status",
        "clean-source-pytest.json": "status",
        "wheel-build.json": "status",
        "wheel-test-tooling.json": "status",
        "wheel-only-pytest.json": "status",
        "editable-install.json": "status",
        "editable-metadata.json": "status",
        "editable-pytest.json": "status",
        "compileall.json": "status",
        "governance-corpus.json": "status",
        "governance-corpus-detail.json": "status",
        "portable-probes-command.json": "status",
        "materialized-post-bind.json": "status",
        "post-source-bind.json": "status",
    }
    for step_id, receipt_name in REVIEW_PYTHON_STEP_RECEIPTS.items():
        if step_id == "linux_symlink" and runner_os == "windows":
            continue
        required_status_receipts[receipt_name] = "status"
    if runner_os == "linux":
        required_status_receipts["linux-symlink-realpath.json"] = "status"

    receipts = {}
    for name, status_key in required_status_receipts.items():
        payload, error = _read_json_receipt(directory / name)
        receipts[name] = payload
        observed = payload.get(status_key) if payload else error
        receipt_statuses[name] = observed
        if observed != "PASS":
            failure_codes.append(f"receipt_status:{name}:{observed}")

    pre, pre_error = _read_json_receipt(directory / "exact-index-pre.json")
    post, post_error = _read_json_receipt(directory / "exact-index-post.json")
    if pre_error:
        failure_codes.append(f"pre_manifest:{pre_error}")
    if post_error:
        failure_codes.append(f"post_manifest:{post_error}")
    pre_sha = (
        _sha256_file(directory / "exact-index-pre.json") if pre is not None else None
    )
    post_sha = (
        _sha256_file(directory / "exact-index-post.json") if post is not None else None
    )
    pre_post_equal = bool(pre is not None and pre == post and pre_sha == post_sha)
    if not pre_post_equal:
        failure_codes.append("pre_post_exact_index_not_equal")

    source_bind = receipts.get("post-source-bind.json") or {}
    for key in (
        "pre_post_equal",
        "entries_equal",
        "head_unchanged",
        "head_tree_unchanged",
        "index_tree_unchanged",
        "entry_count_unchanged",
        "post_worktree_clean",
    ):
        if source_bind.get(key) is not True:
            failure_codes.append(f"source_bind_false:{key}")

    governance = receipts.get("governance-corpus-detail.json") or {}
    corpus = governance.get("corpus", {})
    adversarial = governance.get("adversarial", {})
    protected_home = governance.get("protected_home", {})
    governance_exact = (
        corpus.get("correct") == corpus.get("total") == 30
        and corpus.get("prevented") == corpus.get("dangerous") == 22
        and corpus.get("false_positives") == 0
        and adversarial.get("caught") == adversarial.get("total") == 8
        and protected_home.get("ok") is True
    )
    if not governance_exact:
        failure_codes.append("governance_counts_not_exact")

    probes, probes_error = _read_json_receipt(directory / "portable-probes.json")
    receipt_statuses["portable-probes.json"] = (
        "PASS" if probes and probes.get("all_passed") else probes_error or "FAIL"
    )
    if not (
        probes
        and probes.get("all_passed") is True
        and probes.get("passed") == probes.get("total") == 10
    ):
        failure_codes.append("portable_probes_not_exact")

    workflow_policy_payload = receipts.get("workflow-policy.json") or {}
    lock_policy_payload = receipts.get("review-lock-policy.json") or {}
    action_map = workflow_policy_payload.get("action_refs", {})
    if action_map != REVIEWED_ACTION_REFS:
        failure_codes.append("action_map_not_exact")
    lock_sha = lock_policy_payload.get("canonical_sha256")
    created_environment = receipts.get("create-review-environment.json") or {}
    review_environment = receipts.get("review-tooling-environment.json") or {}
    creation_receipt_path = directory / "create-review-environment.json"
    creation_receipt_sha256 = (
        _sha256_file(creation_receipt_path)
        if creation_receipt_path.is_file()
        else None
    )
    if created_environment.get("schema") != "continuityos-review-environment-create-v1":
        failure_codes.append("review_environment_creation_schema_not_exact")
    if created_environment.get("failure_codes") != []:
        failure_codes.append("review_environment_creation_failure_codes_present")
    if created_environment.get("expected_python_version") != REVIEW_PYTHON_VERSION:
        failure_codes.append("review_environment_creation_version_not_exact")
    if created_environment.get("path_has_authority") is not False:
        failure_codes.append("review_environment_path_authority_not_false")
    if created_environment.get("environment_preexisted") is not False:
        failure_codes.append("review_environment_not_fresh")
    created_prefix = created_environment.get("environment")
    created_scripts = created_environment.get("scripts_directory")
    created_interpreter = created_environment.get("interpreter")
    creation_probe = created_environment.get("interpreter_probe")
    if not created_prefix or not os.path.isabs(str(created_prefix)):
        failure_codes.append("review_environment_creation_prefix_not_absolute")
    elif not Path(str(created_prefix)).is_dir():
        failure_codes.append("review_environment_creation_prefix_missing")
    expected_created_scripts = None
    expected_created_interpreter = None
    if created_prefix and os.path.isabs(str(created_prefix)):
        expected_created_scripts, expected_created_interpreter = (
            _review_environment_layout(
                Path(str(created_prefix)),
                runner_os=args.runner_os,
            )
        )
    if not created_interpreter or not os.path.isabs(str(created_interpreter)):
        failure_codes.append("review_environment_creation_interpreter_not_absolute")
    else:
        if expected_created_interpreter is None or not _lexical_paths_equal(
            created_interpreter, expected_created_interpreter
        ):
            failure_codes.append(
                "review_environment_creation_interpreter_not_canonical"
            )
        if not created_prefix or not _lexical_path_is_within(
            created_interpreter, created_prefix
        ):
            failure_codes.append("review_environment_creation_interpreter_outside")
        if not Path(str(created_interpreter)).is_file():
            failure_codes.append("review_environment_creation_interpreter_missing")
    if not created_scripts or not os.path.isabs(str(created_scripts)):
        failure_codes.append("review_environment_creation_scripts_not_absolute")
    else:
        if expected_created_scripts is None or not _lexical_paths_equal(
            created_scripts, expected_created_scripts
        ):
            failure_codes.append("review_environment_creation_scripts_not_canonical")
        if not created_interpreter or not _lexical_paths_equal(
            created_scripts, Path(str(created_interpreter)).parent
        ):
            failure_codes.append("review_environment_creation_scripts_mismatch")
    if not isinstance(creation_probe, dict):
        failure_codes.append("review_environment_creation_probe_missing")
        creation_probe = {}
    probe_executable = creation_probe.get("executable")
    probe_prefix = creation_probe.get("prefix")
    probe_base_prefix = creation_probe.get("base_prefix")
    if not probe_executable or not os.path.isabs(str(probe_executable)):
        failure_codes.append("review_environment_creation_probe_executable_invalid")
    elif not created_interpreter or not _lexical_paths_equal(
        probe_executable, created_interpreter
    ):
        failure_codes.append("review_environment_creation_probe_executable_mismatch")
    if not probe_prefix or not os.path.isabs(str(probe_prefix)):
        failure_codes.append("review_environment_creation_probe_prefix_invalid")
    elif not created_prefix or not _lexical_paths_equal(probe_prefix, created_prefix):
        failure_codes.append("review_environment_creation_probe_prefix_mismatch")
    if not probe_base_prefix or not os.path.isabs(str(probe_base_prefix)):
        failure_codes.append("review_environment_creation_probe_base_prefix_invalid")
    elif probe_prefix and _lexical_paths_equal(probe_base_prefix, probe_prefix):
        failure_codes.append("review_environment_creation_probe_not_isolated")
    if creation_probe.get("version") != REVIEW_PYTHON_VERSION:
        failure_codes.append("review_environment_creation_probe_version_not_exact")
    inventoried_prefix = review_environment.get("prefix")
    if not created_prefix or not inventoried_prefix or os.path.normcase(
        os.path.normpath(created_prefix)
    ) != os.path.normcase(os.path.normpath(inventoried_prefix)):
        failure_codes.append("review_environment_prefix_not_bound")
    inventoried_interpreter = review_environment.get("python_executable")
    if not created_interpreter or not inventoried_interpreter or os.path.normcase(
        os.path.normpath(created_interpreter)
    ) != os.path.normcase(os.path.normpath(inventoried_interpreter)):
        failure_codes.append("review_environment_interpreter_not_bound_to_creation")
    if review_environment.get("review_lock_sha256") != lock_sha:
        failure_codes.append("review_environment_lock_not_exact")
    if review_environment.get("is_isolated_venv") is not True:
        failure_codes.append("review_environment_not_isolated")
    if review_environment.get("interpreter_under_prefix") is not True:
        failure_codes.append("review_environment_interpreter_not_bound")
    if review_environment.get("user_site_enabled") is not False:
        failure_codes.append("review_environment_user_site_enabled")
    if review_environment.get("python_version") != REVIEW_PYTHON_VERSION:
        failure_codes.append("review_environment_python_not_exact")
    expected_lock_versions = {
        item.get("name"): item.get("version")
        for item in lock_policy_payload.get("packages", [])
        if isinstance(item, dict)
        and isinstance(item.get("name"), str)
        and isinstance(item.get("version"), str)
    }
    if set(expected_lock_versions) != REVIEW_LOCK_PACKAGES:
        failure_codes.append("review_lock_version_map_not_exact")
    if review_environment.get("expected_packages") != expected_lock_versions:
        failure_codes.append("review_environment_inventory_not_exact")
    installed_records = review_environment.get("installed_packages")
    installed_versions, installed_duplicates = _inventory_versions(installed_records)
    review_environment_closure_exact = bool(
        expected_lock_versions
        and installed_versions == expected_lock_versions
        and not installed_duplicates
        and review_environment.get("installed_package_count")
        == len(REVIEW_LOCK_PACKAGES)
        == len(installed_records or [])
        and review_environment.get("missing_packages") == []
        and review_environment.get("unexpected_packages") == []
        and review_environment.get("duplicate_packages") == []
        and review_environment.get("version_mismatches") == []
        and review_environment.get("outside_prefix_packages") == []
        and _inventory_locations_within(installed_records, created_prefix)
        and isinstance(review_environment.get("pip_check"), dict)
        and review_environment["pip_check"].get("exit_code") == 0
    )
    if not review_environment_closure_exact:
        failure_codes.append("review_environment_installed_closure_not_exact")

    binding_failures = []
    binding_summary = {}
    for step_id, receipt_name in REVIEW_PYTHON_STEP_RECEIPTS.items():
        if step_id == "linux_symlink" and runner_os == "windows":
            continue
        binding_receipt = receipts.get(receipt_name)
        observed_failures = _review_python_binding_failures(
            receipt_name,
            binding_receipt,
            creation_sha256=creation_receipt_sha256,
            environment=created_prefix,
            interpreter=created_interpreter,
            creation_probe=creation_probe,
        )
        binding_failures.extend(observed_failures)
        child_before = (
            binding_receipt.get("child_identity_before", {})
            if isinstance(binding_receipt, dict)
            else {}
        )
        child_after = (
            binding_receipt.get("child_identity_after", {})
            if isinstance(binding_receipt, dict)
            else {}
        )
        binding_summary[receipt_name] = {
            "status": binding_receipt.get("status")
            if isinstance(binding_receipt, dict)
            else None,
            "environment_receipt_sha256": binding_receipt.get(
                "environment_receipt_sha256"
            )
            if isinstance(binding_receipt, dict)
            else None,
            "child_inventory_before_count": child_before.get(
                "installed_package_count"
            ),
            "child_inventory_after_count": child_after.get(
                "installed_package_count"
            ),
            "binding_failure_codes": observed_failures,
        }
    failure_codes.extend(binding_failures)
    review_python_bindings_exact = not binding_failures

    install_binding = receipts.get("install-review-tooling.json") or {}
    install_post_versions, install_post_duplicates = _inventory_versions(
        (install_binding.get("child_identity_after") or {}).get(
            "installed_packages"
        )
    )
    install_post_inventory_exact = bool(
        expected_lock_versions
        and install_post_versions == expected_lock_versions
        and not install_post_duplicates
        and install_binding.get("required_post_lock_sha256") == lock_sha
        and install_binding.get("required_post_versions")
        == expected_lock_versions
        and install_binding.get("post_inventory_exact") is True
    )
    if not install_post_inventory_exact:
        failure_codes.append("install_post_inventory_not_exact")

    verify_binding = receipts.get("review-tooling-environment-command.json") or {}
    verify_binding_inventory_exact = True
    for phase in ("before", "after"):
        observed, duplicates = _inventory_versions(
            (verify_binding.get(f"child_identity_{phase}") or {}).get(
                "installed_packages"
            )
        )
        if observed != expected_lock_versions or duplicates:
            verify_binding_inventory_exact = False
    if not verify_binding_inventory_exact:
        failure_codes.append("verify_command_inventory_not_exact")
    lock_entry_sha = None
    if pre:
        lock_entry = next(
            (
                item
                for item in pre.get("entries", [])
                if item.get("path") == "requirements/review-ci-py311.lock"
            ),
            None,
        )
        lock_entry_sha = lock_entry.get("sha256") if lock_entry else None
    if not lock_sha or lock_sha != lock_entry_sha:
        failure_codes.append("review_lock_not_bound_to_exact_index")

    try:
        root = Path(
            _git(Path.cwd(), "rev-parse", "--show-toplevel", text=True).strip()
        ).resolve()
        checkout_head = _git(root, "rev-parse", "HEAD", text=True).strip()
        checkout_tree = _git(root, "rev-parse", "HEAD^{tree}", text=True).strip()
    except subprocess.CalledProcessError:
        checkout_head = None
        checkout_tree = None
        failure_codes.append("checkout_identity_unavailable")
    if args.github_sha != checkout_head:
        failure_codes.append("github_sha_not_checkout_head")
    if not args.github_ref:
        failure_codes.append("github_ref_missing")
    if pre and (
        pre.get("head") != checkout_head or pre.get("head_tree") != checkout_tree
    ):
        failure_codes.append("pre_manifest_not_checkout_identity")

    failure_codes = sorted(set(failure_codes))
    payload = {
        "schema": "continuityos-release-review-final-gate-v1",
        "GITHUB_SHA": args.github_sha,
        "GITHUB_REF": args.github_ref,
        "runner_os": args.runner_os,
        "runner_arch": args.runner_arch,
        "checkout_head": checkout_head,
        "checkout_tree": checkout_tree,
        "pre_exact_index_sha256": pre_sha,
        "post_exact_index_sha256": post_sha,
        "pre_entry_count": pre.get("entry_count") if pre else None,
        "post_entry_count": post.get("entry_count") if post else None,
        "pre_post_equal": pre_post_equal,
        "post_worktree_clean": source_bind.get("post_worktree_clean") is True,
        "action_exact_sha_map": action_map,
        "review_lock_sha256": lock_sha,
        "review_lock_exact_index_sha256": lock_entry_sha,
        "review_environment_creation_receipt_sha256": creation_receipt_sha256,
        "review_environment_python_version": review_environment.get("python_version"),
        "review_environment_isolated": review_environment.get("is_isolated_venv"),
        "review_environment_fresh": (
            created_environment.get("environment_preexisted") is False
        ),
        "review_environment_prefix_bound": (
            "review_environment_prefix_not_bound" not in failure_codes
        ),
        "review_environment_interpreter_bound": (
            "review_environment_interpreter_not_bound_to_creation"
            not in failure_codes
        ),
        "review_environment_package_count": review_environment.get(
            "installed_package_count"
        ),
        "review_environment_closure_exact": review_environment_closure_exact,
        "install_post_inventory_exact": install_post_inventory_exact,
        "verify_command_inventory_exact": verify_binding_inventory_exact,
        "review_python_bindings_exact": review_python_bindings_exact,
        "review_python_binding_receipts": binding_summary,
        "mandatory_step_conclusions": conclusions,
        "required_receipt_statuses": receipt_statuses,
        "governance_exact": governance_exact,
        "portable_probes_exact": "portable_probes_not_exact" not in failure_codes,
        "failure_codes": failure_codes,
        "final_gate": "PASS" if not failure_codes else "FAIL",
        "status": "PASS" if not failure_codes else "FAIL",
    }
    _write_json(output, payload)
    print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
    return 0 if payload["final_gate"] == "PASS" else 1


def enforce_conclusions(args: argparse.Namespace) -> int:
    conclusions, errors = _step_conclusions(list(args.step))
    for name in ("final_gate", "receipt_manifest", "upload_receipts"):
        if conclusions.get(name) != "success":
            errors.append(f"step_conclusion:{name}:{conclusions.get(name)}")
    payload = {
        "conclusions": conclusions,
        "failure_codes": sorted(set(errors)),
        "status": "PASS" if not errors else "FAIL",
    }
    print(json.dumps(payload, sort_keys=True))
    return 0 if payload["status"] == "PASS" else 1


def receipt_manifest(args: argparse.Namespace) -> int:
    directory = Path(args.directory).resolve()
    output = Path(args.output).resolve()
    directory.mkdir(parents=True, exist_ok=True)
    records = []
    for path in sorted(item for item in directory.rglob("*") if item.is_file()):
        if path == output:
            continue
        records.append((_sha256_file(path), path.relative_to(directory).as_posix()))
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        "".join(f"{digest}  {name}\n" for digest, name in records),
        encoding="ascii",
        newline="\n",
    )
    print(f"{len(records)} receipt files; manifest_sha256={_sha256_file(output)}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="subcommand", required=True)

    run = commands.add_parser("run")
    run.add_argument("--output", required=True)
    run.add_argument("--cwd")
    run.add_argument("command", nargs=argparse.REMAINDER)
    run.set_defaults(func=command_receipt)

    review_run = commands.add_parser("run-review-python")
    review_run.add_argument("--environment-receipt", required=True)
    review_run.add_argument("--output", required=True)
    review_run.add_argument("--cwd")
    review_run.add_argument("--require-post-lock")
    review_run.add_argument("command", nargs=argparse.REMAINDER)
    review_run.set_defaults(func=review_python_command_receipt)

    metadata = commands.add_parser("metadata")
    metadata.add_argument("--mode", choices=("absent", "editable"), required=True)
    metadata.add_argument("--source-root", default=".")
    metadata.add_argument("--output", required=True)
    metadata.set_defaults(func=metadata_receipt)

    index = commands.add_parser("exact-index")
    index.add_argument("--manifest", required=True)
    index.add_argument("--scan-output", required=True)
    index.set_defaults(func=exact_index)

    materialize = commands.add_parser("materialize-source")
    materialize.add_argument("--manifest", required=True)
    materialize.add_argument("--destination", required=True)
    materialize.add_argument("--output", required=True)
    materialize.set_defaults(func=materialize_source)

    materialized_rebind = commands.add_parser("verify-materialized")
    materialized_rebind.add_argument("--manifest", required=True)
    materialized_rebind.add_argument("--directory", required=True)
    materialized_rebind.add_argument("--output", required=True)
    materialized_rebind.set_defaults(func=verify_materialized_source)

    rebind = commands.add_parser("source-rebind")
    rebind.add_argument("--pre-manifest", required=True)
    rebind.add_argument("--post-manifest", required=True)
    rebind.add_argument("--output", required=True)
    rebind.set_defaults(func=source_rebind)

    nodes = commands.add_parser("collect-nodeids")
    nodes.add_argument("--output", required=True)
    nodes.set_defaults(func=collect_nodeids)

    wheel = commands.add_parser("wheel-test")
    wheel.add_argument("--wheel-dir", required=True)
    wheel.add_argument("--test-wheel-dir", required=True)
    wheel.add_argument("--review-lock", required=True)
    wheel.add_argument("--workspace", required=True)
    wheel.add_argument("--source-root", default=".")
    wheel.add_argument("--output", required=True)
    wheel.set_defaults(func=wheel_test)

    policy = commands.add_parser("validate-workflow")
    policy.add_argument("--workflow", required=True)
    policy.add_argument("--review-lock", required=True)
    policy.add_argument("--output", required=True)
    policy.set_defaults(func=workflow_policy)

    lock = commands.add_parser("validate-lock")
    lock.add_argument("--lock", required=True)
    lock.add_argument("--output", required=True)
    lock.set_defaults(func=review_lock_policy)

    review_env = commands.add_parser("create-review-environment")
    review_env.add_argument("--directory", required=True)
    review_env.add_argument("--path-file")
    review_env.add_argument("--output", required=True)
    review_env.set_defaults(func=create_review_environment)

    inventory = commands.add_parser("verify-review-environment")
    inventory.add_argument("--lock", required=True)
    inventory.add_argument("--output", required=True)
    inventory.set_defaults(func=verify_review_environment)

    gate = commands.add_parser("final-gate")
    gate.add_argument("--directory", required=True)
    gate.add_argument("--runner-os", choices=("Linux", "Windows"), required=True)
    gate.add_argument("--runner-arch", required=True)
    gate.add_argument("--github-sha", required=True)
    gate.add_argument("--github-ref", required=True)
    gate.add_argument("--step", action="append", default=[])
    gate.add_argument("--output", required=True)
    gate.set_defaults(func=final_gate)

    enforce = commands.add_parser("enforce-conclusions")
    enforce.add_argument("--step", action="append", default=[])
    enforce.set_defaults(func=enforce_conclusions)

    manifest = commands.add_parser("receipt-manifest")
    manifest.add_argument("--directory", required=True)
    manifest.add_argument("--output", required=True)
    manifest.set_defaults(func=receipt_manifest)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
