"""Evidence-bound completion lifecycle gate.

A narrative completion claim is never stronger than the highest contiguous
state with physical evidence.  The evaluator distinguishes local design,
materialization, Git, tests, bundle, packaging, delivery, provider readback,
CI and semantic acceptance.

The gate is verify-only.  It has no push, merge, deployment, registry/current
state/R63 apply, wallet, order or trading path.
"""
from __future__ import annotations

from pathlib import Path, PurePosixPath
from typing import Any
import json
import re
import subprocess
import zipfile

from .evidence_common import (
    add_check,
    canonical_json_text,
    git,
    load_json,
    now_utc,
    require_bool,
    require_dict,
    require_list,
    require_oid,
    require_repo,
    require_sha,
    require_str,
    sha256_file,
    sidecar_sha,
    validate_effects,
    verify_manifest,
    verify_zip,
)

REQUEST_SCHEMA = "continuityos.completion_claim.request/v1"
TEST_SCHEMA = "continuityos.completion_claim.test_receipt/v1"
FRESH_CLONE_SCHEMA = "continuityos.completion_claim.fresh_clone_receipt/v1"
PACKAGE_READY_SCHEMA = "continuityos.completion_claim.package_ready/v1"
RELEASE_SCHEMA = "continuityos.completion_claim.release_receipt/v1"
EXPOSURE_SCHEMA = "continuityos.completion_claim.exposure_receipt/v1"
DRIVE_SCHEMA = "continuityos.completion_claim.drive_readback_receipt/v1"
GITHUB_SCHEMA = "continuityos.completion_claim.github_readback_receipt/v1"
CI_SCHEMA = "continuityos.completion_claim.ci_receipt/v1"
ACCEPTANCE_SCHEMA = "continuityos.completion_claim.acceptance_receipt/v1"
EVALUATION_SCHEMA = "continuityos.completion_claim.evaluation/v1"

PASS = "COMPLETION_CLAIM_PASS"
HOLD = "COMPLETION_CLAIM_HOLD"
REVISE = "COMPLETION_CLAIM_REVISE"

WORK_STATES = (
    "DESIGNED",
    "MATERIALIZED",
    "COMMITTED",
    "TESTED_FOCUSED",
    "TESTED_FULL",
)
ARTIFACT_STATES = (
    "NONE",
    "BUNDLE_VERIFIED",
    "FRESH_CLONE_VERIFIED",
    "PACKAGED",
    "READY_LAST_VERIFIED",
)
GIT_STATES = (
    "UNPUBLISHED",
    "GITHUB_REMOTE_VERIFIED",
    "CI_VERIFIED",
)
WORK_INDEX = {state: index for index, state in enumerate(WORK_STATES)}
ARTIFACT_INDEX = {state: index for index, state in enumerate(ARTIFACT_STATES)}
GIT_INDEX = {state: index for index, state in enumerate(GIT_STATES)}
CLAIM_KEYS = {
    "work_state",
    "artifact_state",
    "git_state",
    "user_download_exposed",
    "drive_readback_verified",
    "accepted",
}
CLAIM_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{2,127}$")
BRANCH_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$")

EVIDENCE_KEYS = {
    "design",
    "repository",
    "focused_test_receipt",
    "full_test_receipt",
    "bundle",
    "fresh_clone_receipt",
    "package",
    "user_exposure_receipt",
    "drive_readback_receipt",
    "github_readback_receipt",
    "ci_receipt",
    "acceptance_receipt",
}


def _bound_file(value: Any, label: str) -> tuple[Path, str]:
    row = require_dict(value, label)
    path = Path(require_str(row.get("path"), f"{label}.path")).expanduser()
    expected = require_sha(row.get("sha256"), f"{label}.sha256")
    actual = sha256_file(path)
    if actual != expected:
        raise ValueError(f"{label} SHA mismatch")
    return path, actual


def _request_binding(request: dict[str, Any]) -> dict[str, Any]:
    if request.get("schema") != REQUEST_SCHEMA:
        raise ValueError("completion request schema mismatch")
    if request.get("authority_generation") != "R63":
        raise ValueError("authority_generation must remain R63")
    claim_id = require_str(request.get("claim_id"), "claim_id")
    if not CLAIM_ID_RE.fullmatch(claim_id):
        raise ValueError("claim_id is invalid")
    claim = require_dict(request.get("claim"), "claim")
    if set(claim) != CLAIM_KEYS:
        raise ValueError("claim fields mismatch")
    work_state = require_str(claim.get("work_state"), "claim.work_state")
    artifact_state = require_str(claim.get("artifact_state"), "claim.artifact_state")
    git_state = require_str(claim.get("git_state"), "claim.git_state")
    if work_state not in WORK_INDEX:
        raise ValueError("claim.work_state is invalid")
    if artifact_state not in ARTIFACT_INDEX:
        raise ValueError("claim.artifact_state is invalid")
    if git_state not in GIT_INDEX:
        raise ValueError("claim.git_state is invalid")
    normalized_claim = {
        "work_state": work_state,
        "artifact_state": artifact_state,
        "git_state": git_state,
        "user_download_exposed": require_bool(
            claim.get("user_download_exposed"), "claim.user_download_exposed"
        ),
        "drive_readback_verified": require_bool(
            claim.get("drive_readback_verified"), "claim.drive_readback_verified"
        ),
        "accepted": require_bool(claim.get("accepted"), "claim.accepted"),
    }
    subject = require_dict(request.get("subject"), "subject")
    branch = require_str(subject.get("branch"), "subject.branch")
    if not BRANCH_RE.fullmatch(branch) or branch.endswith("/") or "//" in branch or ".." in branch:
        raise ValueError("subject.branch is invalid")
    evidence = require_dict(request.get("evidence"), "evidence")
    if set(evidence) != EVIDENCE_KEYS:
        raise ValueError("evidence fields mismatch")
    validate_effects(request.get("effects"), "effects")
    return {
        "claim_id": claim_id,
        "claim": normalized_claim,
        "repository": require_repo(subject.get("repository"), "subject.repository"),
        "branch": branch,
        "base_head": require_oid(subject.get("base_head"), "subject.base_head"),
        "candidate_head": require_oid(subject.get("candidate_head"), "subject.candidate_head"),
        "candidate_tree": require_oid(subject.get("candidate_tree"), "subject.candidate_tree"),
        "evidence": evidence,
    }


def _verify_design(value: Any) -> dict[str, Any]:
    path, digest = _bound_file(value, "design")
    if path.stat().st_size == 0:
        raise ValueError("design file is empty")
    return {"path": str(path), "sha256": digest, "bytes": path.stat().st_size}


def _verify_repository(value: Any, binding: dict[str, Any]) -> dict[str, Any]:
    row = require_dict(value, "repository evidence")
    repo = Path(require_str(row.get("path"), "repository.path")).expanduser()
    if not (repo / ".git").exists():
        raise ValueError("repository path is not a Git worktree")
    observed = {
        "branch": git(repo, "branch", "--show-current"),
        "head": git(repo, "rev-parse", "HEAD"),
        "tree": git(repo, "rev-parse", "HEAD^{tree}"),
        "status": git(repo, "status", "--porcelain=v1"),
    }
    if observed["branch"] != binding["branch"]:
        raise ValueError("repository branch mismatch")
    if observed["head"] != binding["candidate_head"]:
        raise ValueError("repository HEAD mismatch")
    if observed["tree"] != binding["candidate_tree"]:
        raise ValueError("repository tree mismatch")
    if observed["status"]:
        raise ValueError("repository worktree is dirty")
    ancestry = subprocess.run(
        ["git", "-C", str(repo), "merge-base", "--is-ancestor", binding["base_head"], binding["candidate_head"]],
        capture_output=True,
        check=False,
    )
    if ancestry.returncode != 0:
        raise ValueError("base_head is not an ancestor of candidate_head")
    git(repo, "fsck", "--full", "--strict")
    git(repo, "diff", "--check")
    return {"path": str(repo), **observed, "git_fsck": "PASS", "git_diff_check": "PASS"}


def _verify_test(value: Any, binding: dict[str, Any], kind: str) -> dict[str, Any]:
    path, digest = _bound_file(value, f"{kind.lower()} test receipt")
    receipt = load_json(path, f"{kind.lower()} test receipt")
    if receipt.get("schema") != TEST_SCHEMA or receipt.get("authority_generation") != "R63":
        raise ValueError("test receipt schema/authority mismatch")
    if receipt.get("kind") != kind:
        raise ValueError(f"test receipt kind must be {kind}")
    candidate = require_dict(receipt.get("candidate"), "test candidate")
    for key, expected in {
        "branch": binding["branch"],
        "head": binding["candidate_head"],
        "tree": binding["candidate_tree"],
    }.items():
        if candidate.get(key) != expected:
            raise ValueError(f"test candidate {key} mismatch")
    if receipt.get("terminal") != "TESTS_PASS":
        raise ValueError("test receipt terminal is not TESTS_PASS")
    commands = require_list(receipt.get("commands"), "commands", 256)
    if not commands:
        raise ValueError("test receipt has no commands")
    for index, command in enumerate(commands):
        command = require_dict(command, f"commands[{index}]")
        argv = require_list(command.get("argv"), f"commands[{index}].argv", 128)
        if not argv or not all(isinstance(item, str) and item for item in argv):
            raise ValueError(f"commands[{index}].argv is invalid")
        if command.get("exit_code") != 0:
            raise ValueError(f"commands[{index}] did not pass")
    files = require_list(receipt.get("evidence_files"), "evidence_files", 1024)
    for index, item in enumerate(files):
        _bound_file(item, f"evidence_files[{index}]")
    validate_effects(receipt.get("effects"), "test effects")
    return {"path": str(path), "sha256": digest, "commands": len(commands), "evidence_files": len(files)}


def _verify_bundle(value: Any, binding: dict[str, Any], repo_result: dict[str, Any]) -> dict[str, Any]:
    row = require_dict(value, "bundle evidence")
    path = Path(require_str(row.get("path"), "bundle.path")).expanduser()
    expected_sha = require_sha(row.get("sha256"), "bundle.sha256")
    if sha256_file(path) != expected_sha:
        raise ValueError("bundle SHA mismatch")
    expected_ref = require_str(row.get("ref"), "bundle.ref")
    if expected_ref != f"refs/heads/{binding['branch']}":
        raise ValueError("bundle ref mismatch")
    repo = Path(repo_result["path"])
    verify = subprocess.run(
        ["git", "-C", str(repo), "bundle", "verify", str(path)],
        text=True,
        capture_output=True,
        check=False,
    )
    if verify.returncode != 0:
        raise ValueError(f"git bundle verify failed: {verify.stderr.strip()}")
    refs = subprocess.run(
        ["git", "ls-remote", str(path)],
        text=True,
        capture_output=True,
        check=False,
    )
    if refs.returncode != 0:
        raise ValueError(f"git ls-remote bundle failed: {refs.stderr.strip()}")
    ref_map = {}
    for line in refs.stdout.splitlines():
        parts = line.split()
        if len(parts) == 2:
            ref_map[parts[1]] = parts[0]
    if ref_map.get(expected_ref) != binding["candidate_head"]:
        raise ValueError("bundle does not expose exact candidate HEAD")
    return {"path": str(path), "sha256": expected_sha, "ref": expected_ref, "head": binding["candidate_head"]}


def _verify_fresh_clone(value: Any, binding: dict[str, Any], bundle_sha: str, full_test_sha: str) -> dict[str, Any]:
    path, digest = _bound_file(value, "fresh clone receipt")
    receipt = load_json(path, "fresh clone receipt")
    if receipt.get("schema") != FRESH_CLONE_SCHEMA or receipt.get("authority_generation") != "R63":
        raise ValueError("fresh clone schema/authority mismatch")
    if receipt.get("bundle_sha256") != bundle_sha:
        raise ValueError("fresh clone bundle SHA mismatch")
    if receipt.get("full_test_receipt_sha256") != full_test_sha:
        raise ValueError("fresh clone full-test SHA mismatch")
    candidate = require_dict(receipt.get("candidate"), "fresh clone candidate")
    for key, expected in {
        "branch": binding["branch"],
        "head": binding["candidate_head"],
        "tree": binding["candidate_tree"],
    }.items():
        if candidate.get(key) != expected:
            raise ValueError(f"fresh clone candidate {key} mismatch")
    if receipt.get("worktree_clean") is not True or receipt.get("git_fsck") != "PASS":
        raise ValueError("fresh clone Git verification did not pass")
    if receipt.get("terminal") != "FRESH_CLONE_PASS":
        raise ValueError("fresh clone terminal mismatch")
    validate_effects(receipt.get("effects"), "fresh clone effects")
    return {"path": str(path), "sha256": digest, "terminal": receipt.get("terminal")}


def _find_unique(names: list[str], basename: str) -> str:
    matches = [name for name in names if PurePosixPath(name).name == basename]
    if len(matches) != 1:
        raise ValueError(f"package must contain exactly one {basename}")
    return matches[0]


def _verify_package_archive(value: Any, binding: dict[str, Any], full_test_sha: str, bundle_sha: str) -> dict[str, Any]:
    row = require_dict(value, "package evidence")
    package = Path(require_str(row.get("zip"), "package.zip")).expanduser()
    sidecar = Path(require_str(row.get("sidecar"), "package.sidecar")).expanduser()
    names = verify_zip(package)
    digest = sha256_file(package)
    if sidecar_sha(sidecar) != digest:
        raise ValueError("package sidecar SHA mismatch")
    with zipfile.ZipFile(package, "r") as archive:
        release_name = _find_unique(names, "RELEASE_RECEIPT.json")
        manifest_name = _find_unique(names, "MANIFEST.json")
        release = json.loads(archive.read(release_name).decode("utf-8"))
        if release.get("schema") != RELEASE_SCHEMA or release.get("authority_generation") != "R63":
            raise ValueError("release receipt schema/authority mismatch")
        candidate = require_dict(release.get("candidate"), "release candidate")
        for key, expected in {
            "branch": binding["branch"],
            "head": binding["candidate_head"],
            "tree": binding["candidate_tree"],
        }.items():
            if candidate.get(key) != expected:
                raise ValueError(f"release candidate {key} mismatch")
        if release.get("full_test_receipt_sha256") != full_test_sha:
            raise ValueError("release full-test SHA mismatch")
        if release.get("bundle_sha256") != bundle_sha:
            raise ValueError("release bundle SHA mismatch")
        if release.get("terminal") != "RELEASE_READY":
            raise ValueError("release terminal is not RELEASE_READY")
        validate_effects(release.get("effects"), "release effects")
        manifest_entries = verify_manifest(archive, manifest_name)
    return {
        "zip": str(package),
        "sidecar": str(sidecar),
        "sha256": digest,
        "bytes": package.stat().st_size,
        "manifest_entries": manifest_entries,
        "zip_crc": "PASS",
    }


def _verify_ready(value: Any, binding: dict[str, Any], package_result: dict[str, Any]) -> dict[str, Any]:
    row = require_dict(value, "package evidence")
    ready_path = Path(require_str(row.get("ready"), "package.ready")).expanduser()
    ready = load_json(ready_path, "package READY")
    if ready.get("schema") != PACKAGE_READY_SCHEMA:
        raise ValueError("package READY schema mismatch")
    package = Path(package_result["zip"])
    sidecar = Path(package_result["sidecar"])
    if ready.get("artifact_zip") != package.name or ready.get("artifact_sha256") != package_result["sha256"]:
        raise ValueError("package READY identity mismatch")
    if ready.get("terminal") != "PACKAGE_READY" or ready.get("written_last") is not True:
        raise ValueError("package READY terminal/written_last mismatch")
    if ready.get("candidate_head") != binding["candidate_head"] or ready.get("candidate_tree") != binding["candidate_tree"]:
        raise ValueError("package READY candidate mismatch")
    if ready_path.stat().st_mtime_ns < max(package.stat().st_mtime_ns, sidecar.stat().st_mtime_ns):
        raise ValueError("package READY was not physically written last")
    return {"path": str(ready_path), "sha256": sha256_file(ready_path), "written_last": True}


def _verify_exposure(value: Any, package_sha: str) -> dict[str, Any]:
    path, digest = _bound_file(value, "user exposure receipt")
    receipt = load_json(path, "user exposure receipt")
    if receipt.get("schema") != EXPOSURE_SCHEMA:
        raise ValueError("user exposure receipt schema mismatch")
    if receipt.get("artifact_sha256") != package_sha:
        raise ValueError("user exposure artifact SHA mismatch")
    if receipt.get("status") != "USER_DOWNLOAD_EXPOSED" or receipt.get("external_readback") is not True:
        raise ValueError("user exposure readback is not proven")
    if receipt.get("channel") not in {"CHAT_DOWNLOAD", "GOOGLE_DRIVE", "GITHUB_RELEASE"}:
        raise ValueError("user exposure channel is invalid")
    validate_effects(receipt.get("effects"), "user exposure effects")
    return {"path": str(path), "sha256": digest, "channel": receipt.get("channel")}


def _verify_drive(value: Any, package_sha: str) -> dict[str, Any]:
    path, digest = _bound_file(value, "Drive readback receipt")
    receipt = load_json(path, "Drive readback receipt")
    if receipt.get("schema") != DRIVE_SCHEMA or receipt.get("provider") != "GOOGLE_DRIVE":
        raise ValueError("Drive receipt schema/provider mismatch")
    if receipt.get("readback") is not True or receipt.get("artifact_sha256") != package_sha:
        raise ValueError("Drive artifact readback mismatch")
    if require_sha(receipt.get("provider_readback_sha256"), "provider_readback_sha256") != package_sha:
        raise ValueError("Drive provider bytes differ from artifact")
    require_str(receipt.get("provider_object_id"), "provider_object_id")
    validate_effects(receipt.get("effects"), "Drive effects")
    return {"path": str(path), "sha256": digest, "provider_object_id": receipt.get("provider_object_id")}


def _verify_github(value: Any, binding: dict[str, Any]) -> dict[str, Any]:
    path, digest = _bound_file(value, "GitHub readback receipt")
    receipt = load_json(path, "GitHub readback receipt")
    if receipt.get("schema") != GITHUB_SCHEMA or receipt.get("provider") != "GITHUB":
        raise ValueError("GitHub readback schema/provider mismatch")
    if receipt.get("readback") is not True:
        raise ValueError("GitHub readback is not proven")
    for key, expected in {
        "repository": binding["repository"],
        "branch": binding["branch"],
        "remote_head": binding["candidate_head"],
        "remote_tree": binding["candidate_tree"],
    }.items():
        if receipt.get(key) != expected:
            raise ValueError(f"GitHub readback {key} mismatch")
    if receipt.get("force_push") is not False or receipt.get("merge") is not False:
        raise ValueError("GitHub readback reports force push or merge")
    validate_effects(receipt.get("effects"), "GitHub effects")
    return {"path": str(path), "sha256": digest, "remote_head": receipt.get("remote_head")}


def _verify_ci(value: Any, binding: dict[str, Any], github_sha: str) -> dict[str, Any]:
    path, digest = _bound_file(value, "CI receipt")
    receipt = load_json(path, "CI receipt")
    if receipt.get("schema") != CI_SCHEMA or receipt.get("provider") != "GITHUB_ACTIONS":
        raise ValueError("CI receipt schema/provider mismatch")
    if receipt.get("github_readback_receipt_sha256") != github_sha:
        raise ValueError("CI receipt GitHub-readback SHA mismatch")
    if receipt.get("repository") != binding["repository"] or receipt.get("branch") != binding["branch"]:
        raise ValueError("CI subject mismatch")
    if receipt.get("head_sha") != binding["candidate_head"]:
        raise ValueError("CI head SHA mismatch")
    runs = require_list(receipt.get("required_runs"), "required_runs", 128)
    if not runs:
        raise ValueError("CI required_runs is empty")
    for index, row in enumerate(runs):
        run = require_dict(row, f"required_runs[{index}]")
        require_str(run.get("name"), f"required_runs[{index}].name")
        if run.get("head_sha") != binding["candidate_head"]:
            raise ValueError(f"required_runs[{index}] wrong head")
        if run.get("status") != "completed" or run.get("conclusion") != "success":
            raise ValueError(f"required_runs[{index}] is not successful")
    validate_effects(receipt.get("effects"), "CI effects")
    return {"path": str(path), "sha256": digest, "required_runs": len(runs)}


def _verify_acceptance(value: Any, binding: dict[str, Any], ci_sha: str) -> dict[str, Any]:
    path, digest = _bound_file(value, "acceptance receipt")
    receipt = load_json(path, "acceptance receipt")
    if receipt.get("schema") != ACCEPTANCE_SCHEMA:
        raise ValueError("acceptance receipt schema mismatch")
    if receipt.get("ci_receipt_sha256") != ci_sha:
        raise ValueError("acceptance CI SHA mismatch")
    if receipt.get("repository") != binding["repository"] or receipt.get("branch") != binding["branch"]:
        raise ValueError("acceptance subject mismatch")
    if receipt.get("head") != binding["candidate_head"] or receipt.get("tree") != binding["candidate_tree"]:
        raise ValueError("acceptance candidate mismatch")
    if receipt.get("decision") not in {"ACCEPT", "PASS_WITH_CONDITIONS"}:
        raise ValueError("acceptance decision is not positive")
    if receipt.get("reviewer_role") != "GPT_CONTROLLER":
        raise ValueError("acceptance reviewer must be GPT_CONTROLLER")
    if receipt.get("apply_status") != "NOT_APPLIED":
        raise ValueError("acceptance apply_status must remain NOT_APPLIED")
    validate_effects(receipt.get("effects"), "acceptance effects")
    return {"path": str(path), "sha256": digest, "decision": receipt.get("decision")}


def evaluate_completion_claim(request_path: Path) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    reasons: list[str] = []
    holds: list[str] = []
    unsupported_claims: list[str] = []
    evidence_state: dict[str, Any] = {}
    binding: dict[str, Any] = {}

    proven_work_index = -1
    proven_artifact_index = 0
    proven_git_index = 0
    user_exposed = False
    drive_verified = False
    accepted = False

    def record_missing(label: str) -> None:
        holds.append(f"missing evidence required for {label}")
        add_check(checks, label, "MISSING", "Required evidence is absent.")

    def run_stage(label: str, verifier) -> bool:
        try:
            result = verifier()
            evidence_state[label] = result
            add_check(checks, label, "PASS", f"{label} evidence verified.")
            return True
        except FileNotFoundError:
            return False
        except Exception as exc:
            reasons.append(f"{label}: {type(exc).__name__}: {exc}")
            add_check(checks, label, "FAIL", f"{label} evidence is contradictory.")
            return False

    try:
        request_path = Path(request_path)
        request = load_json(request_path, "completion request")
        binding = _request_binding(request)
        add_check(
            checks,
            "REQUEST",
            "PASS",
            "Completion request and independent claim dimensions are valid.",
            sha256=sha256_file(request_path),
        )
        evidence = binding["evidence"]
        claim = binding["claim"]

        # Work axis: strictly ordered, but independent from delivery/Git axes.
        if evidence.get("design") is not None and run_stage(
            "DESIGNED", lambda: _verify_design(evidence["design"])
        ):
            proven_work_index = WORK_INDEX["DESIGNED"]
            if evidence.get("repository") is not None and run_stage(
                "MATERIALIZED", lambda: _verify_repository(evidence["repository"], binding)
            ):
                proven_work_index = WORK_INDEX["COMMITTED"]
                evidence_state["COMMITTED"] = dict(evidence_state["MATERIALIZED"])
                add_check(checks, "COMMITTED", "PASS", "Exact clean candidate commit is present.")
                if evidence.get("focused_test_receipt") is not None and run_stage(
                    "TESTED_FOCUSED",
                    lambda: _verify_test(
                        evidence["focused_test_receipt"], binding, "FOCUSED"
                    ),
                ):
                    proven_work_index = WORK_INDEX["TESTED_FOCUSED"]
                    if evidence.get("full_test_receipt") is not None and run_stage(
                        "TESTED_FULL",
                        lambda: _verify_test(
                            evidence["full_test_receipt"], binding, "FULL"
                        ),
                    ):
                        proven_work_index = WORK_INDEX["TESTED_FULL"]

        # Artifact axis.  It may advance without any Drive/GitHub delivery claim.
        if evidence.get("bundle") is not None:
            if "MATERIALIZED" not in evidence_state:
                if ARTIFACT_INDEX[claim["artifact_state"]] >= ARTIFACT_INDEX["BUNDLE_VERIFIED"]:
                    record_missing("MATERIALIZED prerequisite for BUNDLE_VERIFIED")
            elif run_stage(
                "BUNDLE_VERIFIED",
                lambda: _verify_bundle(
                    evidence["bundle"], binding, evidence_state["MATERIALIZED"]
                ),
            ):
                proven_artifact_index = ARTIFACT_INDEX["BUNDLE_VERIFIED"]
                if evidence.get("fresh_clone_receipt") is not None:
                    if "TESTED_FULL" not in evidence_state:
                        if ARTIFACT_INDEX[claim["artifact_state"]] >= ARTIFACT_INDEX["FRESH_CLONE_VERIFIED"]:
                            record_missing("TESTED_FULL prerequisite for FRESH_CLONE_VERIFIED")
                    elif run_stage(
                        "FRESH_CLONE_VERIFIED",
                        lambda: _verify_fresh_clone(
                            evidence["fresh_clone_receipt"],
                            binding,
                            evidence_state["BUNDLE_VERIFIED"]["sha256"],
                            evidence_state["TESTED_FULL"]["sha256"],
                        ),
                    ):
                        proven_artifact_index = ARTIFACT_INDEX["FRESH_CLONE_VERIFIED"]
                        if evidence.get("package") is not None and run_stage(
                            "PACKAGED",
                            lambda: _verify_package_archive(
                                evidence["package"],
                                binding,
                                evidence_state["TESTED_FULL"]["sha256"],
                                evidence_state["BUNDLE_VERIFIED"]["sha256"],
                            ),
                        ):
                            proven_artifact_index = ARTIFACT_INDEX["PACKAGED"]
                            if run_stage(
                                "READY_LAST_VERIFIED",
                                lambda: _verify_ready(
                                    evidence["package"], binding, evidence_state["PACKAGED"]
                                ),
                            ):
                                proven_artifact_index = ARTIFACT_INDEX["READY_LAST_VERIFIED"]

        # Delivery flags are independent of provider/Git lifecycle.
        if evidence.get("user_exposure_receipt") is not None:
            if "PACKAGED" not in evidence_state:
                if claim["user_download_exposed"]:
                    record_missing("PACKAGED prerequisite for USER_DOWNLOAD_EXPOSED")
            elif run_stage(
                "USER_DOWNLOAD_EXPOSED",
                lambda: _verify_exposure(
                    evidence["user_exposure_receipt"], evidence_state["PACKAGED"]["sha256"]
                ),
            ):
                user_exposed = True
        if evidence.get("drive_readback_receipt") is not None:
            if "PACKAGED" not in evidence_state:
                if claim["drive_readback_verified"]:
                    record_missing("PACKAGED prerequisite for DRIVE_READBACK_VERIFIED")
            elif run_stage(
                "DRIVE_READBACK_VERIFIED",
                lambda: _verify_drive(
                    evidence["drive_readback_receipt"], evidence_state["PACKAGED"]["sha256"]
                ),
            ):
                drive_verified = True

        # Git/provider axis does not require Drive or user-download delivery.
        if evidence.get("github_readback_receipt") is not None and run_stage(
            "GITHUB_REMOTE_VERIFIED",
            lambda: _verify_github(evidence["github_readback_receipt"], binding),
        ):
            proven_git_index = GIT_INDEX["GITHUB_REMOTE_VERIFIED"]
            if evidence.get("ci_receipt") is not None and run_stage(
                "CI_VERIFIED",
                lambda: _verify_ci(
                    evidence["ci_receipt"],
                    binding,
                    evidence_state["GITHUB_REMOTE_VERIFIED"]["sha256"],
                ),
            ):
                proven_git_index = GIT_INDEX["CI_VERIFIED"]

        if evidence.get("acceptance_receipt") is not None:
            if "CI_VERIFIED" not in evidence_state:
                if claim["accepted"]:
                    record_missing("CI_VERIFIED prerequisite for ACCEPTED")
            elif run_stage(
                "ACCEPTED",
                lambda: _verify_acceptance(
                    evidence["acceptance_receipt"],
                    binding,
                    evidence_state["CI_VERIFIED"]["sha256"],
                ),
            ):
                accepted = True

        # Compare independent claims with independently proven dimensions.
        if WORK_INDEX[claim["work_state"]] > proven_work_index:
            unsupported_claims.append(
                f"work_state={claim['work_state']} exceeds proven work state"
            )
        if ARTIFACT_INDEX[claim["artifact_state"]] > proven_artifact_index:
            unsupported_claims.append(
                f"artifact_state={claim['artifact_state']} exceeds proven artifact state"
            )
        if GIT_INDEX[claim["git_state"]] > proven_git_index:
            unsupported_claims.append(
                f"git_state={claim['git_state']} exceeds proven Git state"
            )
        if claim["user_download_exposed"] and not user_exposed:
            unsupported_claims.append("user_download_exposed=true is not proven")
        if claim["drive_readback_verified"] and not drive_verified:
            unsupported_claims.append("drive_readback_verified=true is not proven")
        if claim["accepted"] and not accepted:
            unsupported_claims.append("accepted=true is not proven")
        holds.extend(item for item in unsupported_claims if item not in holds)

    except Exception as exc:
        reasons.append(f"{type(exc).__name__}: {exc}")
        add_check(checks, "INTERNAL_VALIDATION", "FAIL", "Completion validation failed.")

    proven_work_state = WORK_STATES[proven_work_index] if proven_work_index >= 0 else None
    proven_artifact_state = ARTIFACT_STATES[proven_artifact_index]
    proven_git_state = GIT_STATES[proven_git_index]

    if reasons:
        status, outcome = REVISE, "WOULD_HOLD"
    elif holds:
        status, outcome = HOLD, "WOULD_HOLD"
    else:
        status, outcome = PASS, "CLAIM_PROVEN"

    state_vector = {
        "work": {
            state: {
                "status": "PROVEN" if index <= proven_work_index else "NOT_PROVEN",
                "evidence": evidence_state.get(state),
            }
            for index, state in enumerate(WORK_STATES)
        },
        "artifact": {
            state: {
                "status": "PROVEN" if index <= proven_artifact_index else "NOT_PROVEN",
                "evidence": evidence_state.get(state),
            }
            for index, state in enumerate(ARTIFACT_STATES)
        },
        "git": {
            state: {
                "status": "PROVEN" if index <= proven_git_index else "NOT_PROVEN",
                "evidence": evidence_state.get(state),
            }
            for index, state in enumerate(GIT_STATES)
        },
        "delivery": {
            "USER_DOWNLOAD_EXPOSED": {
                "status": "PROVEN" if user_exposed else "NOT_PROVEN",
                "evidence": evidence_state.get("USER_DOWNLOAD_EXPOSED"),
            },
            "DRIVE_READBACK_VERIFIED": {
                "status": "PROVEN" if drive_verified else "NOT_PROVEN",
                "evidence": evidence_state.get("DRIVE_READBACK_VERIFIED"),
            },
        },
        "acceptance": {
            "ACCEPTED": {
                "status": "PROVEN" if accepted else "NOT_PROVEN",
                "evidence": evidence_state.get("ACCEPTED"),
            }
        },
    }
    return {
        "schema": EVALUATION_SCHEMA,
        "generated_at_utc": now_utc(),
        "status": status,
        "outcome": outcome,
        "binding": {key: value for key, value in binding.items() if key != "evidence"},
        "claim": binding.get("claim"),
        "proven_state": {
            "work_state": proven_work_state,
            "artifact_state": proven_artifact_state,
            "git_state": proven_git_state,
            "user_download_exposed": user_exposed,
            "drive_readback_verified": drive_verified,
            "accepted": accepted,
        },
        "evidence_state_vector": state_vector,
        "unsupported_claims": unsupported_claims,
        "checks": checks,
        "reasons": reasons,
        "holds": holds,
        "effect": "VERIFY_ONLY_NO_WRITE",
        "live_state_modified": False,
        "writes_performed": [],
        "can_trade": False,
        "capital_permission": "DENY",
        "deploy_permission": "DENY",
        "self_application": False,
    }


def exit_code_for_completion_claim(receipt: dict[str, Any]) -> int:
    if receipt.get("status") == PASS:
        return 0
    if receipt.get("status") == HOLD:
        return 3
    return 2
