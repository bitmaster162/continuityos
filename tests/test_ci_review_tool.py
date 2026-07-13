from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from types import SimpleNamespace

import pytest

from continuityos.gate.policy import default_policy, policy_fingerprint
from tools import ci_review


ROOT = Path(__file__).resolve().parents[1]


class _AsciiOnlyStream:
    encoding = "ascii"

    def __init__(self):
        self.values = []

    def write(self, value):
        value.encode(self.encoding)
        self.values.append(value)


def test_clean_metadata_receipt_imports_checkout_without_site_packages(tmp_path):
    clean_root = tmp_path / "clean-checkout"
    shutil.copytree(ROOT / "tools", clean_root / "tools")
    shutil.copytree(
        ROOT / "continuityos",
        clean_root / "continuityos",
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
    )
    receipt = tmp_path / "clean-source-metadata.json"
    env = os.environ.copy()
    env.pop("PYTHONPATH", None)
    env["PYTHONNOUSERSITE"] = "1"
    completed = subprocess.run(
        [
            sys.executable,
            "-S",
            "-m",
            "tools.ci_review",
            "metadata",
            "--mode",
            "absent",
            "--source-root",
            str(clean_root),
            "--output",
            str(receipt),
        ],
        cwd=clean_root,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    payload = json.loads(receipt.read_text(encoding="utf-8"))
    assert payload["status"] == "PASS"
    assert payload["metadata_present"] is False
    assert Path(payload["package_path"]).resolve().is_relative_to(clean_root)


def test_completed_command_output_is_safe_for_narrow_windows_console(monkeypatch):
    stdout = _AsciiOnlyStream()
    stderr = _AsciiOnlyStream()
    monkeypatch.setattr(sys, "stdout", stdout)
    monkeypatch.setattr(sys, "stderr", stderr)
    completed = subprocess.CompletedProcess(
        ["example"],
        0,
        stdout="corpus \N{EM DASH} pass",
        stderr="diagnostic \N{EM DASH} retained",
    )

    ci_review._emit_completed(completed)

    assert stdout.values == ["corpus \\u2014 pass\n"]
    assert stderr.values == ["diagnostic \\u2014 retained\n"]


def test_command_receipt_records_safe_runner_context(tmp_path, monkeypatch):
    home = tmp_path / "home-with-sensitive-label"
    workspace = tmp_path / "workspace"
    home.mkdir()
    workspace.mkdir()
    receipt = tmp_path / "command.json"
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.chdir(workspace)

    args = type(
        "Args",
        (),
        {
            "command": [sys.executable, "-c", "print('ok')"],
            "output": str(receipt),
        },
    )()
    assert ci_review.command_receipt(args) == 0

    payload = json.loads(receipt.read_text(encoding="utf-8"))
    context = payload["execution_context"]
    assert payload["schema"] == "continuityos-ci-command-receipt-v2"
    assert context["home"]["class"] == "absolute"
    assert context["home"]["source"] == "HOME"
    assert context["home"]["path_sha256"]
    assert context["cwd"]["class"] == "outside_home"
    assert context["cwd"]["path_sha256"]
    assert context["policy"] == {
        "sha256": policy_fingerprint(default_policy()),
        "source": "continuityos.gate.policy.default_policy",
        "status": "available",
        "version": default_policy()["version"],
    }
    assert str(home) not in json.dumps(context)
    assert "sensitive-label" not in json.dumps(context)


def test_execution_context_classifies_checkout_inside_home(tmp_path, monkeypatch):
    home = tmp_path / "home"
    checkout = home / "work" / "continuityos"
    checkout.mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.chdir(checkout)

    context = ci_review._safe_execution_context()

    assert context["home"]["class"] == "absolute"
    assert context["cwd"]["class"] == "inside_home"
    assert str(home) not in json.dumps(context)


def _validate_workflow_text(tmp_path, text, *, review_lock_text=None):
    workflow = tmp_path / "ci.yml"
    review_lock = tmp_path / "review-ci-py311.lock"
    output = tmp_path / "policy.json"
    workflow.write_text(text, encoding="utf-8")
    if review_lock_text is None:
        review_lock_text = (ROOT / "requirements" / "review-ci-py311.lock").read_text(
            encoding="utf-8"
        )
    review_lock.write_text(review_lock_text, encoding="utf-8", newline="\n")
    args = type(
        "Args",
        (),
        {
            "workflow": str(workflow),
            "review_lock": str(review_lock),
            "output": str(output),
        },
    )()
    return ci_review.workflow_policy(args), json.loads(output.read_text(encoding="utf-8"))


def _validate_lock_text(tmp_path, text):
    review_lock = tmp_path / "review-ci-py311.lock"
    output = tmp_path / "lock-policy.json"
    review_lock.write_text(text, encoding="utf-8", newline="\n")
    args = SimpleNamespace(lock=str(review_lock), output=str(output))
    exit_code = ci_review.review_lock_policy(args)
    return exit_code, json.loads(output.read_text(encoding="utf-8"))


def _git(repo, *arguments):
    env = os.environ.copy()
    env.update(
        {
            "GIT_AUTHOR_DATE": "2000-01-01T00:00:00+00:00",
            "GIT_AUTHOR_EMAIL": "ci-review@example.invalid",
            "GIT_AUTHOR_NAME": "CI Review Test",
            "GIT_COMMITTER_DATE": "2000-01-01T00:00:00+00:00",
            "GIT_COMMITTER_EMAIL": "ci-review@example.invalid",
            "GIT_COMMITTER_NAME": "CI Review Test",
        }
    )
    completed = subprocess.run(
        ["git", *arguments],
        cwd=repo,
        env=env,
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    return completed.stdout.strip()


def _init_git_repo(tmp_path, *, include_review_lock=False):
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "--initial-branch=main")
    _git(repo, "config", "core.autocrlf", "false")
    _git(repo, "config", "core.filemode", "false")
    (repo / "tracked.txt").write_text("original\n", encoding="utf-8", newline="\n")
    if include_review_lock:
        lock = repo / "requirements" / "review-ci-py311.lock"
        lock.parent.mkdir()
        lock.write_bytes((ROOT / "requirements" / lock.name).read_bytes())
    _git(repo, "add", "--all")
    _git(repo, "commit", "--message", "deterministic fixture")
    return repo


def _capture_pre_manifest(repo, tmp_path):
    receipt_dir = tmp_path / "receipts"
    receipt_dir.mkdir(exist_ok=True)
    pre = receipt_dir / "exact-index-pre.json"
    ci_review._write_exact_index_manifest(repo, pre)
    return pre


def _run_source_rebind(repo, pre, tmp_path, monkeypatch):
    post = pre.with_name("exact-index-post.json")
    output = tmp_path / "post-source-bind.json"
    monkeypatch.chdir(repo)
    exit_code = ci_review.source_rebind(
        SimpleNamespace(
            pre_manifest=str(pre),
            post_manifest=str(post),
            output=str(output),
        )
    )
    return exit_code, json.loads(output.read_text(encoding="utf-8"))


def _write_json(path, payload):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def _final_gate_args(directory, output, repo, runner_os, steps):
    return SimpleNamespace(
        directory=str(directory),
        output=str(output),
        runner_os=runner_os,
        runner_arch="X64",
        github_sha=_git(repo, "rev-parse", "HEAD"),
        github_ref="refs/heads/review/deterministic-fixture",
        step=steps,
    )


def _complete_final_gate_fixture(tmp_path, runner_os):
    repo = _init_git_repo(tmp_path, include_review_lock=True)
    receipts = tmp_path / "final-gate-receipts"
    receipts.mkdir()
    pre = receipts / "exact-index-pre.json"
    manifest, _, _, _ = ci_review._write_exact_index_manifest(repo, pre)
    post = receipts / "exact-index-post.json"
    post.write_bytes(pre.read_bytes())

    lock_entry = next(
        entry
        for entry in manifest["entries"]
        if entry["path"] == "requirements/review-ci-py311.lock"
    )
    status_receipts = (
        "install-review-tooling.json",
        "materialized-source.json",
        "exact-index-secret-scan.json",
        "clean-source-metadata.json",
        "pytest-nodeids.json",
        "clean-source-pytest.json",
        "wheel-build.json",
        "wheel-test-tooling.json",
        "wheel-only-pytest.json",
        "editable-install.json",
        "editable-metadata.json",
        "editable-pytest.json",
        "compileall.json",
        "governance-corpus.json",
        "portable-probes-command.json",
        "materialized-post-bind.json",
    )
    for name in status_receipts:
        _write_json(receipts / name, {"status": "PASS"})
    _write_json(
        receipts / "review-lock-policy.json",
        {"status": "PASS", "canonical_sha256": lock_entry["sha256"]},
    )
    review_environment = tmp_path / "review-venv"
    review_interpreter = review_environment / "Scripts" / "python.exe"
    _write_json(
        receipts / "create-review-environment.json",
        {
            "status": "PASS",
            "environment_preexisted": False,
            "environment": str(review_environment),
            "interpreter": str(review_interpreter),
        },
    )
    _write_json(
        receipts / "review-tooling-environment.json",
        {
            "status": "PASS",
            "prefix": str(review_environment),
            "python_executable": str(review_interpreter),
            "review_lock_sha256": lock_entry["sha256"],
            "is_isolated_venv": True,
            "interpreter_under_prefix": True,
            "user_site_enabled": False,
            "python_version": ci_review.REVIEW_PYTHON_VERSION,
            "expected_packages": {
                name: "fixture" for name in ci_review.REVIEW_LOCK_PACKAGES
            },
            "installed_package_count": len(ci_review.REVIEW_LOCK_PACKAGES),
        },
    )
    _write_json(
        receipts / "workflow-policy.json",
        {"status": "PASS", "action_refs": ci_review.REVIEWED_ACTION_REFS},
    )
    _write_json(
        receipts / "post-source-bind.json",
        {
            "status": "PASS",
            "pre_post_equal": True,
            "entries_equal": True,
            "head_unchanged": True,
            "head_tree_unchanged": True,
            "index_tree_unchanged": True,
            "entry_count_unchanged": True,
            "post_worktree_clean": True,
        },
    )
    _write_json(
        receipts / "governance-corpus-detail.json",
        {
            "status": "PASS",
            "corpus": {
                "correct": 30,
                "total": 30,
                "prevented": 22,
                "dangerous": 22,
                "false_positives": 0,
            },
            "adversarial": {"caught": 8, "total": 8},
            "protected_home": {"ok": True},
        },
    )
    _write_json(
        receipts / "portable-probes.json",
        {"all_passed": True, "passed": 10, "total": 10},
    )
    if runner_os == "Linux":
        _write_json(receipts / "linux-symlink-realpath.json", {"status": "PASS"})

    steps = []
    for step_id in ci_review.MANDATORY_STEP_IDS:
        conclusion = (
            "skipped"
            if step_id == "linux_symlink" and runner_os == "Windows"
            else "success"
        )
        steps.append(f"{step_id}={conclusion}")
    return repo, receipts, steps


def test_workflow_policy_requires_always_on_post_corpus_gates(tmp_path):
    text = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    text = text.replace(
        "        id: portable_probes\n        if: always()\n",
        "        id: portable_probes\n",
    )
    exit_code, payload = _validate_workflow_text(tmp_path, text)
    assert exit_code == 1
    assert "always gate id: portable_probes" in payload["missing_required_tokens"]


def test_workflow_policy_requires_always_and_linux_on_symlink_gate(tmp_path):
    text = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    text = text.replace(
        "        if: always() && runner.os == 'Linux'\n",
        "        if: runner.os == 'Linux'\n",
    )
    exit_code, payload = _validate_workflow_text(tmp_path, text)
    assert exit_code == 1
    assert "always gate id: linux_symlink" in payload["missing_required_tokens"]


def test_workflow_policy_rejects_continue_on_error_for_mandatory_gates(tmp_path):
    text = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    text = text.replace(
        "      - name: Run governance regression corpus\n",
        "      - name: Run governance regression corpus\n        continue-on-error: true\n",
    )
    exit_code, payload = _validate_workflow_text(tmp_path, text)
    assert exit_code == 1
    assert "non-mandatory step" in payload["forbidden_findings"]


def test_source_rebind_rejects_unstaged_tracked_drift(tmp_path, monkeypatch):
    repo = _init_git_repo(tmp_path)
    pre = _capture_pre_manifest(repo, tmp_path)
    (repo / "tracked.txt").write_text(
        "unstaged mutation\n", encoding="utf-8", newline="\n"
    )

    exit_code, payload = _run_source_rebind(repo, pre, tmp_path, monkeypatch)

    assert exit_code == 1
    assert payload["status"] == "FAIL"
    assert payload["post_worktree_clean"] is False
    assert "post_worktree_or_index_dirty" in payload["failure_codes"]
    assert payload["pre_post_equal"] is True


def test_source_rebind_rejects_staged_index_drift(tmp_path, monkeypatch):
    repo = _init_git_repo(tmp_path)
    pre = _capture_pre_manifest(repo, tmp_path)
    (repo / "tracked.txt").write_text(
        "staged mutation\n", encoding="utf-8", newline="\n"
    )
    _git(repo, "add", "tracked.txt")

    exit_code, payload = _run_source_rebind(repo, pre, tmp_path, monkeypatch)

    assert exit_code == 1
    assert payload["status"] == "FAIL"
    assert payload["post_worktree_clean"] is False
    assert payload["index_tree_unchanged"] is False
    assert payload["entries_equal"] is False
    assert "post_worktree_or_index_dirty" in payload["failure_codes"]
    assert "index_tree_drift" in payload["failure_codes"]


def test_source_rebind_rejects_head_and_tree_drift(tmp_path, monkeypatch):
    repo = _init_git_repo(tmp_path)
    pre = _capture_pre_manifest(repo, tmp_path)
    (repo / "tracked.txt").write_text(
        "committed mutation\n", encoding="utf-8", newline="\n"
    )
    _git(repo, "add", "tracked.txt")
    _git(repo, "commit", "--message", "drift after PRE")

    exit_code, payload = _run_source_rebind(repo, pre, tmp_path, monkeypatch)

    assert exit_code == 1
    assert payload["status"] == "FAIL"
    assert payload["post_worktree_clean"] is True
    assert payload["head_unchanged"] is False
    assert payload["head_tree_unchanged"] is False
    assert "head_drift" in payload["failure_codes"]
    assert "head_tree_drift" in payload["failure_codes"]


def test_source_rebind_accepts_unchanged_exact_tree(tmp_path, monkeypatch):
    repo = _init_git_repo(tmp_path)
    pre = _capture_pre_manifest(repo, tmp_path)

    exit_code, payload = _run_source_rebind(repo, pre, tmp_path, monkeypatch)

    assert exit_code == 0
    assert payload["schema"] == "continuityos-ci-post-source-rebind-v1"
    assert payload["status"] == "PASS"
    assert payload["failure_codes"] == []
    assert payload["pre_exact_index_sha256"] == payload["post_exact_index_sha256"]
    for field in (
        "pre_post_equal",
        "entries_equal",
        "head_unchanged",
        "head_tree_unchanged",
        "index_tree_unchanged",
        "entry_count_unchanged",
        "post_worktree_clean",
    ):
        assert payload[field] is True


def test_final_gate_rejects_missing_post_manifest(tmp_path, monkeypatch):
    repo = _init_git_repo(tmp_path)
    receipts = tmp_path / "receipts"
    receipts.mkdir()
    output = tmp_path / "final-gate.json"
    monkeypatch.chdir(repo)

    exit_code = ci_review.final_gate(
        _final_gate_args(receipts, output, repo, "Windows", [])
    )
    payload = json.loads(output.read_text(encoding="utf-8"))

    assert exit_code == 1
    assert payload["final_gate"] == "FAIL"
    assert "post_manifest:missing" in payload["failure_codes"]


def test_final_gate_rejects_pre_post_manifest_mismatch(tmp_path, monkeypatch):
    repo = _init_git_repo(tmp_path)
    receipts = tmp_path / "receipts"
    receipts.mkdir()
    _write_json(receipts / "exact-index-pre.json", {"entry_count": 1, "entries": []})
    _write_json(receipts / "exact-index-post.json", {"entry_count": 2, "entries": []})
    output = tmp_path / "final-gate.json"
    monkeypatch.chdir(repo)

    exit_code = ci_review.final_gate(
        _final_gate_args(receipts, output, repo, "Linux", [])
    )
    payload = json.loads(output.read_text(encoding="utf-8"))

    assert exit_code == 1
    assert payload["final_gate"] == "FAIL"
    assert payload["pre_post_equal"] is False
    assert "pre_post_exact_index_not_equal" in payload["failure_codes"]


def test_workflow_policy_accepts_reviewed_immutable_actions_and_lock(tmp_path):
    text = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")

    exit_code, payload = _validate_workflow_text(tmp_path, text)

    assert exit_code == 0
    assert payload["status"] == "PASS"
    assert payload["action_refs"] == ci_review.REVIEWED_ACTION_REFS
    assert payload["review_lock"]["status"] == "PASS"


def test_workflow_policy_rejects_mutable_action_ref(tmp_path):
    text = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    reviewed = ci_review.REVIEWED_ACTION_REFS["actions/checkout"]
    text = text.replace(f"actions/checkout@{reviewed}", "actions/checkout@v4", 1)

    exit_code, payload = _validate_workflow_text(tmp_path, text)

    assert exit_code == 1
    assert "mutable action ref: actions/checkout@v4" in payload["forbidden_findings"]
    assert "exact reviewed action map" in payload["missing_required_tokens"]


def test_workflow_policy_rejects_unapproved_immutable_action_ref(tmp_path):
    text = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    reviewed = ci_review.REVIEWED_ACTION_REFS["actions/setup-python"]
    unapproved = "0" * 40
    text = text.replace(
        f"actions/setup-python@{reviewed}",
        f"actions/setup-python@{unapproved}",
        1,
    )

    exit_code, payload = _validate_workflow_text(tmp_path, text)

    assert exit_code == 1
    assert (
        f"unreviewed action SHA: actions/setup-python@{unapproved}"
        in payload["forbidden_findings"]
    )
    assert "exact reviewed action map" in payload["missing_required_tokens"]


def test_review_lock_policy_rejects_unhashed_dependency(tmp_path):
    text = (ROOT / "requirements" / "review-ci-py311.lock").read_text(
        encoding="utf-8"
    )
    locked = (
        "build==1.5.0 \\\n"
        "    --hash=sha256:13f3eecb844759ab66efec90ca17639bbf14dc06cb2fdf37a9010322d9c50a6f"
    )
    assert locked in text
    text = text.replace(locked, "build==1.5.0 no-hash", 1)

    exit_code, payload = _validate_lock_text(tmp_path, text)

    assert exit_code == 1
    assert payload["status"] == "FAIL"
    assert "unhashed_requirement:build" in payload["failure_codes"]


def test_review_lock_policy_rejects_unpinned_dependency(tmp_path):
    text = (ROOT / "requirements" / "review-ci-py311.lock").read_text(
        encoding="utf-8"
    )
    pinned_line = "build==1.5.0 \\\n"
    assert pinned_line in text
    text = text.replace(pinned_line, "build>=1.5.0 \\\n", 1)

    exit_code, payload = _validate_lock_text(tmp_path, text)

    assert exit_code == 1
    assert payload["status"] == "FAIL"
    assert "unpinned_or_malformed_requirement" in payload["failure_codes"]


def test_workflow_policy_rejects_removed_always_run_receipt_step(tmp_path):
    text = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    block = ci_review._workflow_step_block(text, "Write SHA-256 receipt manifest")
    assert block
    text = text.replace(block, "", 1)

    exit_code, payload = _validate_workflow_text(tmp_path, text)

    assert exit_code == 1
    assert "always gate id: receipt_manifest" in payload["missing_required_tokens"]
    assert (
        "POST/final/manifest/upload/enforce order"
        in payload["missing_required_tokens"]
    )


@pytest.mark.parametrize("runner_os", ["Linux", "Windows"])
def test_final_gate_accepts_exact_unchanged_source_and_counts(
    tmp_path, monkeypatch, runner_os
):
    repo, receipts, steps = _complete_final_gate_fixture(tmp_path, runner_os)
    output = tmp_path / f"final-gate-{runner_os.lower()}.json"
    monkeypatch.chdir(repo)

    exit_code = ci_review.final_gate(
        _final_gate_args(receipts, output, repo, runner_os, steps)
    )
    payload = json.loads(output.read_text(encoding="utf-8"))

    assert exit_code == 0
    assert payload["schema"] == "continuityos-release-review-final-gate-v1"
    assert payload["runner_os"] == runner_os
    assert payload["runner_arch"] == "X64"
    assert payload["status"] == payload["final_gate"] == "PASS"
    assert payload["failure_codes"] == []
    assert payload["pre_post_equal"] is True
    assert payload["post_worktree_clean"] is True
    assert payload["pre_entry_count"] == payload["post_entry_count"] == 2
    assert payload["governance_exact"] is True
    assert payload["portable_probes_exact"] is True


def test_final_gate_rejects_inventory_from_different_environment(
    tmp_path, monkeypatch
):
    repo, receipts, steps = _complete_final_gate_fixture(tmp_path, "Windows")
    inventory_path = receipts / "review-tooling-environment.json"
    inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
    inventory["prefix"] = str(tmp_path / "different-preexisting-venv")
    _write_json(inventory_path, inventory)
    output = tmp_path / "final-gate-wrong-environment.json"
    monkeypatch.chdir(repo)

    exit_code = ci_review.final_gate(
        _final_gate_args(receipts, output, repo, "Windows", steps)
    )
    payload = json.loads(output.read_text(encoding="utf-8"))

    assert exit_code == 1
    assert payload["final_gate"] == "FAIL"
    assert "review_environment_prefix_not_bound" in payload["failure_codes"]


def test_materialized_rebind_rejects_unexpected_injected_source(
    tmp_path, monkeypatch
):
    repo = _init_git_repo(tmp_path)
    pre = _capture_pre_manifest(repo, tmp_path)
    destination = tmp_path / "materialized"
    materialize_receipt = tmp_path / "materialized.json"
    monkeypatch.chdir(repo)
    assert ci_review.materialize_source(
        SimpleNamespace(
            manifest=str(pre),
            destination=str(destination),
            output=str(materialize_receipt),
        )
    ) == 0
    injected = destination / "tests" / "conftest.py"
    injected.parent.mkdir()
    injected.write_text("raise RuntimeError('injected')\n", encoding="utf-8")
    output = tmp_path / "materialized-post-bind.json"

    exit_code = ci_review.verify_materialized_source(
        SimpleNamespace(
            manifest=str(pre),
            directory=str(destination),
            output=str(output),
        )
    )
    payload = json.loads(output.read_text(encoding="utf-8"))

    assert exit_code == 1
    assert payload["status"] == "FAIL"
    assert "tests/conftest.py" in payload["disallowed_generated_files"]
    assert "unexpected_materialized_content" in payload["failure_codes"]


def test_review_lock_policy_rejects_wildcard_version(tmp_path):
    text = (ROOT / "requirements" / "review-ci-py311.lock").read_text(
        encoding="utf-8"
    )
    pinned_line = "build==1.5.0 \\\n"
    assert pinned_line in text
    text = text.replace(pinned_line, "build==1.* \\\n", 1)

    exit_code, payload = _validate_lock_text(tmp_path, text)

    assert exit_code == 1
    assert "non_exact_version:build" in payload["failure_codes"]


def test_workflow_policy_requires_exact_read_only_permissions(tmp_path):
    text = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    text = text.replace(
        "permissions:\n  contents: read\n",
        "permissions: write-all\n",
        1,
    )

    exit_code, payload = _validate_workflow_text(tmp_path, text)

    assert exit_code == 1
    assert "permissions not exact read-only" in payload["forbidden_findings"]


def test_workflow_policy_rejects_extra_step_even_with_reviewed_actions(tmp_path):
    text = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    marker = "      - name: Run portable release-hardening probes\n"
    assert marker in text
    text = text.replace(
        marker,
        "      - name: Injected unreviewed command\n"
        "        id: injected_command\n"
        "        run: echo injected\n\n"
        + marker,
        1,
    )

    exit_code, payload = _validate_workflow_text(tmp_path, text)

    assert exit_code == 1
    assert "unexpected workflow step sequence" in payload["forbidden_findings"]
    assert "workflow content not exact reviewed form" in payload["forbidden_findings"]


def test_workflow_policy_requires_fresh_forced_hash_install(tmp_path):
    text = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    exact = "          --no-cache-dir --no-deps --force-reinstall\n"
    assert exact in text
    text = text.replace(exact, "          --no-cache-dir --no-deps\n", 1)

    exit_code, payload = _validate_workflow_text(tmp_path, text)

    assert exit_code == 1
    assert (
        "step token: install_tooling: --force-reinstall"
        in payload["missing_required_tokens"]
    )


def test_create_review_environment_exports_isolated_interpreter(tmp_path):
    environment = tmp_path / "review-venv"
    github_path = tmp_path / "github-path"
    output = tmp_path / "create-review-environment.json"

    exit_code = ci_review.create_review_environment(
        SimpleNamespace(
            directory=str(environment),
            path_file=str(github_path),
            output=str(output),
        )
    )
    payload = json.loads(output.read_text(encoding="utf-8"))

    assert exit_code == 0
    assert payload["status"] == "PASS"
    assert payload["interpreter_probe"]["prefix"] != payload["interpreter_probe"][
        "base_prefix"
    ]
    assert payload["interpreter_probe"]["version"] == ci_review.REVIEW_PYTHON_VERSION
    assert github_path.read_text(encoding="utf-8").strip() == payload[
        "scripts_directory"
    ]


@pytest.mark.skipif(os.name == "nt", reason="native venv interpreter symlink control")
def test_lexical_venv_interpreter_binding_accepts_external_realpath(tmp_path):
    prefix = tmp_path / "review-venv"
    interpreter = prefix / "bin" / "python"
    base_interpreter = tmp_path / "base-python" / "python"
    interpreter.parent.mkdir(parents=True)
    base_interpreter.parent.mkdir(parents=True)
    base_interpreter.write_text("fixture\n", encoding="utf-8")
    interpreter.symlink_to(base_interpreter)

    assert interpreter.resolve() == base_interpreter.resolve()
    assert prefix.resolve() not in interpreter.resolve().parents
    assert ci_review._lexical_path_is_within(interpreter, prefix)


@pytest.mark.parametrize(
    ("mutation", "failure_code"),
    [
        ("none", None),
        ("missing", "installed_packages_missing"),
        ("version", "installed_package_version_mismatch"),
        ("unexpected", "installed_packages_unexpected"),
    ],
)
def test_review_environment_inventory_fails_closed(
    tmp_path, monkeypatch, mutation, failure_code
):
    prefix = tmp_path / "review-venv"
    site_packages = prefix / "Lib" / "site-packages"
    site_packages.mkdir(parents=True)
    expected = {name: "1.0" for name in ci_review.REVIEW_LOCK_PACKAGES}

    class FakeDistribution:
        def __init__(self, name, version):
            self.metadata = {"Name": name}
            self.version = version

        def locate_file(self, _path):
            return site_packages

    installed = [
        FakeDistribution(name, version) for name, version in expected.items()
    ]
    if mutation == "missing":
        installed.pop()
    elif mutation == "version":
        installed[0].version = "9.9"
    elif mutation == "unexpected":
        installed.append(FakeDistribution("unexpected-tool", "1.0"))

    monkeypatch.setattr(ci_review.importlib.metadata, "distributions", lambda: installed)
    monkeypatch.setattr(ci_review.sys, "prefix", str(prefix))
    monkeypatch.setattr(ci_review.sys, "base_prefix", str(tmp_path / "base-python"))
    monkeypatch.setattr(ci_review.sys, "executable", str(prefix / "Scripts" / "python.exe"))
    monkeypatch.setattr(ci_review.site, "ENABLE_USER_SITE", False)
    monkeypatch.setattr(
        ci_review.platform, "python_version", lambda: ci_review.REVIEW_PYTHON_VERSION
    )
    monkeypatch.setattr(
        ci_review,
        "_review_lock_evidence",
        lambda _lock: {
            "failure_codes": [],
            "canonical_sha256": "a" * 64,
            "packages": [
                {"name": name, "version": version}
                for name, version in expected.items()
            ],
        },
    )
    monkeypatch.setattr(
        ci_review,
        "_run",
        lambda *_args, **_kwargs: (
            subprocess.CompletedProcess(
                ["python", "-m", "pip", "check"],
                0,
                stdout="No broken requirements found.\n",
                stderr="",
            ),
            0.01,
        ),
    )
    output = tmp_path / f"inventory-{mutation}.json"

    exit_code = ci_review.verify_review_environment(
        SimpleNamespace(lock=str(tmp_path / "lock"), output=str(output))
    )
    payload = json.loads(output.read_text(encoding="utf-8"))

    if failure_code is None:
        assert exit_code == 0
        assert payload["status"] == "PASS"
        assert payload["failure_codes"] == []
    else:
        assert exit_code == 1
        assert payload["status"] == "FAIL"
        assert failure_code in payload["failure_codes"]
