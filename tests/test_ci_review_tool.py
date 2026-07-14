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


@pytest.fixture(scope="module")
def bound_review_environment(tmp_path_factory):
    base = tmp_path_factory.mktemp("bound-review-python")
    environment = base / "review environment with spaces"
    ci_review.venv.EnvBuilder(
        with_pip=True,
        system_site_packages=False,
        clear=False,
    ).create(environment)
    scripts_directory = environment / ("Scripts" if os.name == "nt" else "bin")
    interpreter = scripts_directory / ("python.exe" if os.name == "nt" else "python")
    completed = subprocess.run(
        [
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
        ],
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    probe = json.loads(completed.stdout)
    return SimpleNamespace(
        environment=environment,
        interpreter=interpreter,
        probe=probe,
        scripts_directory=scripts_directory,
        version=probe["version"],
    )


def _valid_creation_receipt(bound_review_environment):
    bound = bound_review_environment
    return {
        "schema": "continuityos-review-environment-create-v1",
        "status": "PASS",
        "failure_codes": [],
        "expected_python_version": bound.version,
        "environment_preexisted": False,
        "environment": str(bound.environment),
        "scripts_directory": str(bound.scripts_directory),
        "interpreter": str(bound.interpreter),
        "interpreter_probe": dict(bound.probe),
        "path_has_authority": False,
    }


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


def _locked_review_versions():
    evidence = ci_review._review_lock_evidence(
        ROOT / "requirements" / "review-ci-py311.lock"
    )
    assert evidence["status"] == "PASS"
    return {item["name"]: item["version"] for item in evidence["packages"]}


def _command_inventory(versions):
    return [
        {"name": name, "version": version}
        for name, version in sorted(versions.items())
    ]


def _command_identity(environment, interpreter, base_prefix, versions):
    installed = _command_inventory(versions)
    serialized = json.dumps(
        installed,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return {
        "base_prefix": str(base_prefix),
        "executable": str(interpreter),
        "installed_packages": installed,
        "installed_package_count": len(installed),
        "installed_packages_sha256": ci_review._sha256(serialized),
        "prefix": str(environment),
        "user_site_enabled": False,
        "version": ci_review.REVIEW_PYTHON_VERSION,
    }


def _binding_receipt(
    *,
    creation_sha256,
    environment,
    interpreter,
    base_prefix,
    versions,
    arguments=None,
):
    arguments = list(arguments or ["-m", "fixture"])
    identity = _command_identity(
        environment,
        interpreter,
        base_prefix,
        versions,
    )
    outer = {
        "base_prefix": str(base_prefix),
        "executable": str(base_prefix / "python.exe"),
        "prefix": str(base_prefix),
        "version": "fixture-outer",
    }
    path_evidence = {
        "generic_python_resolution_class": "outer_interpreter",
        "order_class": "outer_precedes_environment",
        "path_sha256": "a" * 64,
    }
    return {
        "schema": "continuityos-review-python-command-receipt-v1",
        "environment_receipt_sha256": creation_sha256,
        "environment": str(environment),
        "exact_interpreter": str(interpreter),
        "expected_python_version": ci_review.REVIEW_PYTHON_VERSION,
        "python_environment_policy": {
            "PYTHONHOME": "removed",
            "PYTHONNOUSERSITE": "1",
            "PYTHONPATH": "removed",
            "PYTHONUTF8": "1",
        },
        "outer_identity_before": dict(outer),
        "outer_identity_after": dict(outer),
        "child_identity_before": dict(identity),
        "child_identity_after": dict(identity),
        "path_evidence_before": dict(path_evidence),
        "path_evidence_after": dict(path_evidence),
        "command_arguments": arguments,
        "exact_command": [str(interpreter), *arguments],
        "execution_attempted": True,
        "exit_code": 0,
        "failure_codes": [],
        "status": "PASS",
    }


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
    locked_versions = _locked_review_versions()
    _write_json(
        receipts / "review-lock-policy.json",
        {
            "status": "PASS",
            "canonical_sha256": lock_entry["sha256"],
            "packages": [
                {"name": name, "version": version}
                for name, version in sorted(locked_versions.items())
            ],
        },
    )
    review_environment = tmp_path / "review-venv"
    scripts_directory = review_environment / (
        "bin" if runner_os == "Linux" else "Scripts"
    )
    review_interpreter = scripts_directory / (
        "python" if runner_os == "Linux" else "python.exe"
    )
    scripts_directory.mkdir(parents=True)
    review_interpreter.write_bytes(b"fixture interpreter\n")
    base_prefix = tmp_path / "base-python"
    _write_json(
        receipts / "create-review-environment.json",
        {
            "schema": "continuityos-review-environment-create-v1",
            "status": "PASS",
            "failure_codes": [],
            "expected_python_version": ci_review.REVIEW_PYTHON_VERSION,
            "environment_preexisted": False,
            "environment": str(review_environment),
            "scripts_directory": str(scripts_directory),
            "interpreter": str(review_interpreter),
            "interpreter_probe": {
                "base_prefix": str(base_prefix),
                "executable": str(review_interpreter),
                "prefix": str(review_environment),
                "version": ci_review.REVIEW_PYTHON_VERSION,
            },
            "path_has_authority": False,
        },
    )
    creation_sha256 = ci_review._sha256_file(
        receipts / "create-review-environment.json"
    )
    installed_records = [
        {
            "location": str(review_environment / "site-packages"),
            "name": name,
            "under_prefix": True,
            "version": version,
        }
        for name, version in sorted(locked_versions.items())
    ]
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
            "expected_packages": locked_versions,
            "installed_packages": installed_records,
            "installed_package_count": len(ci_review.REVIEW_LOCK_PACKAGES),
            "missing_packages": [],
            "unexpected_packages": [],
            "duplicate_packages": [],
            "version_mismatches": [],
            "outside_prefix_packages": [],
            "pip_check": {"exit_code": 0},
        },
    )
    for step_id, receipt_name in ci_review.REVIEW_PYTHON_STEP_RECEIPTS.items():
        if step_id == "linux_symlink" and runner_os == "Windows":
            continue
        binding = _binding_receipt(
            creation_sha256=creation_sha256,
            environment=review_environment,
            interpreter=review_interpreter,
            base_prefix=base_prefix,
            versions=locked_versions,
        )
        if step_id == "install_tooling":
            binding.update(
                {
                    "required_post_lock_sha256": lock_entry["sha256"],
                    "required_post_versions": locked_versions,
                    "post_inventory_exact": True,
                }
            )
        _write_json(
            receipts / receipt_name,
            binding,
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


def test_workflow_context_accepts_github_ref_in_job_env():
    evidence = ci_review._workflow_expression_context_evidence(
        {"jobs": {"review": {"env": {"REFERENCE": "${{ github.ref }}"}}}}
    )

    assert evidence["status"] == "PASS"
    assert evidence["failure_codes"] == []
    assert evidence["references"] == [
        {
            "allowed_contexts": [
                "github",
                "inputs",
                "matrix",
                "needs",
                "secrets",
                "strategy",
                "vars",
            ],
            "allowed_functions": [
                "contains",
                "endswith",
                "format",
                "fromjson",
                "join",
                "startswith",
                "tojson",
            ],
            "contexts": ["github"],
            "functions": [],
            "path": "jobs.review.env.REFERENCE",
        }
    ]


def test_workflow_context_accepts_matrix_label_in_job_name():
    evidence = ci_review._workflow_expression_context_evidence(
        {"jobs": {"review": {"name": "${{ matrix.label }} / Python 3.11"}}}
    )

    assert evidence["status"] == "PASS"
    assert evidence["checked_expression_count"] == 1
    assert evidence["references"][0]["contexts"] == ["matrix"]


@pytest.mark.parametrize(
    "step",
    [
        {"run": "echo ${{ runner.temp }}"},
        {"env": {"CACHE": "${{ runner.temp }}/cache"}},
        {"with": {"path": "${{ runner.temp }}/receipts"}},
        {"working-directory": "${{ runner.temp }}/source"},
    ],
)
def test_workflow_context_allows_runner_temp_in_step_runtime_fields(step):
    evidence = ci_review._workflow_expression_context_evidence(
        {"jobs": {"review": {"steps": [step]}}}
    )

    assert evidence["status"] == "PASS"
    assert evidence["checked_expression_count"] == 1
    assert evidence["references"][0]["contexts"] == ["runner"]


@pytest.mark.parametrize(
    ("expression", "context"),
    [
        ("${{ runner.temp }}", "runner"),
        ("${{ env.VALUE }}", "env"),
        ("${{ job.status }}", "job"),
        ("${{ jobs.audit.result }}", "jobs"),
        ("${{ steps.setup_python.outcome }}", "steps"),
    ],
)
def test_workflow_context_rejects_runtime_context_at_job_env(
    expression, context
):
    evidence = ci_review._workflow_expression_context_evidence(
        {"jobs": {"review": {"env": {"INVALID": expression}}}}
    )

    assert evidence["status"] == "FAIL"
    assert evidence["findings"] == [
        {
            "code": "context_not_available",
            "context": context,
            "path": "jobs.review.env.INVALID",
        }
    ]


def test_workflow_context_rejects_runner_at_job_name():
    evidence = ci_review._workflow_expression_context_evidence(
        {"jobs": {"review": {"name": "${{ runner.os }}"}}}
    )

    assert evidence["status"] == "FAIL"
    assert evidence["findings"] == [
        {
            "code": "context_not_available",
            "context": "runner",
            "path": "jobs.review.name",
        }
    ]


@pytest.mark.parametrize(
    ("expression", "detail"),
    [
        ("${{ github.ref", "unclosed_expression"),
        ("${{ }}", "empty_expression"),
        ("${{ github['ref' }}", "unclosed_index"),
    ],
)
def test_workflow_context_rejects_malformed_expression(expression, detail):
    evidence = ci_review._workflow_expression_context_evidence(
        {"jobs": {"review": {"env": {"INVALID": expression}}}}
    )

    assert evidence["status"] == "FAIL"
    assert any(
        finding["code"] == "malformed_expression"
        and finding.get("detail") == detail
        for finding in evidence["findings"]
    )


def test_workflow_context_rejects_unknown_context():
    evidence = ci_review._workflow_expression_context_evidence(
        {"jobs": {"review": {"env": {"INVALID": "${{ mystery.value }}"}}}}
    )

    assert evidence["status"] == "FAIL"
    assert evidence["findings"] == [
        {
            "code": "unknown_context",
            "context": "mystery",
            "path": "jobs.review.env.INVALID",
        }
    ]


@pytest.mark.parametrize(
    "expression",
    [
        "${{ github.ref && }}",
        "${{ github..ref }}",
        '${{ "hello" }}',
        "${{ .mystery.value }}",
        "${{ тайна.value }}",
        "${{ [] }}",
        "${{ () }}",
        "${{ !!! }}",
        "${{ $ }}",
        "${{ 1 + 2 }}",
        "${{ github/**/.ref }}",
        "${{ github.ref; }}",
        "${{ github.ref, }}",
        '${{ github["ref"] }}',
    ],
)
def test_workflow_context_rejects_malformed_expression_grammar(expression):
    evidence = ci_review._workflow_expression_context_evidence(
        {"jobs": {"review": {"env": {"INVALID": expression}}}}
    )

    assert evidence["status"] == "FAIL"
    assert any(
        finding["code"] == "malformed_expression"
        for finding in evidence["findings"]
    )


@pytest.mark.parametrize("function", ["always", "hashFiles"])
def test_workflow_context_rejects_unavailable_function_at_job_env(function):
    evidence = ci_review._workflow_expression_context_evidence(
        {
            "jobs": {
                "review": {
                    "env": {"INVALID": f"${{{{ {function}('value') }}}}"}
                }
            }
        }
    )

    assert evidence["status"] == "FAIL"
    assert any(
        finding["code"] == "function_not_available"
        and finding.get("function") == function.casefold()
        for finding in evidence["findings"]
    )


@pytest.mark.parametrize(
    "expression",
    [
        "always('value')",
        "success(github.ref)",
        "contains(github.ref)",
        "fromJSON('value', 'extra')",
        "format()",
        "hashFiles()",
        "join('a', 'b', 'c')",
        "toJSON()",
    ],
)
def test_workflow_context_rejects_invalid_function_arity(expression):
    evidence = ci_review._workflow_expression_context_evidence(
        {"jobs": {"review": {"steps": [{"if": expression}]}}}
    )

    assert evidence["status"] == "FAIL"
    assert any(
        finding["code"] == "malformed_expression"
        and finding.get("detail") == "invalid_function_arity"
        for finding in evidence["findings"]
    )


@pytest.mark.parametrize("function", ["format", "hashFiles"])
def test_workflow_context_rejects_excessive_variadic_function_arity(function):
    arguments = ", ".join("'value'" for _ in range(256))
    evidence = ci_review._workflow_expression_context_evidence(
        {
            "jobs": {
                "review": {
                    "steps": [{"if": f"{function}({arguments})"}]
                }
            }
        }
    )

    assert evidence["status"] == "FAIL"
    assert any(
        finding["code"] == "malformed_expression"
        and finding.get("detail") == "invalid_function_arity"
        for finding in evidence["findings"]
    )


@pytest.mark.parametrize(
    ("expression", "detail"),
    [
        ("!" * 2000 + "github.ref", "expression_token_limit"),
        ("(" * 1200 + "github.ref" + ")" * 1200, "expression_token_limit"),
    ],
)
def test_workflow_context_fails_closed_at_expression_resource_limit(
    expression, detail
):
    evidence = ci_review._workflow_expression_context_evidence(
        {"jobs": {"review": {"env": {"INVALID": f"${{{{ {expression} }}}}"}}}}
    )

    assert evidence["status"] == "FAIL"
    assert any(
        finding["code"] == "malformed_expression"
        and finding.get("detail") == detail
        for finding in evidence["findings"]
    )


def test_workflow_context_fails_closed_at_document_nesting_limit():
    document = "${{ github.ref }}"
    for _ in range(1200):
        document = [document]

    evidence = ci_review._workflow_expression_context_evidence(document)

    assert evidence["status"] == "FAIL"
    assert evidence["findings"] == [
        {
            "code": "malformed_expression",
            "detail": "document_nesting_limit",
            "path": "<document>",
        }
    ]


def test_workflow_context_rejects_unmatched_closing_delimiter():
    document = {"jobs": {"review": {"env": {}}}}
    document["jobs"]["review"]["env"]["INVALID"] = "github.ref }}"
    evidence = ci_review._workflow_expression_context_evidence(
        document
    )

    assert evidence["status"] == "FAIL"
    assert evidence["findings"] == [
        {
            "code": "malformed_expression",
            "detail": "unexpected_closing_delimiter",
            "path": "jobs.review.env.INVALID",
        }
    ]


def test_workflow_context_accepts_quoted_closing_delimiter_and_bracket_access():
    evidence = ci_review._workflow_expression_context_evidence(
        {
            "jobs": {
                "review": {
                    "env": {
                        "REFERENCE": "${{ format('}}', github['ref']) }}"
                    }
                }
            }
        }
    )

    assert evidence["status"] == "PASS"
    assert evidence["checked_expression_count"] == 1
    assert evidence["references"][0]["contexts"] == ["github"]
    assert evidence["references"][0]["functions"] == ["format"]


def test_workflow_context_rejects_mixed_wrapped_and_implicit_if_expression():
    evidence = ci_review._workflow_expression_context_evidence(
        {
            "jobs": {
                "review": {
                    "steps": [
                        {
                            "if": "${{ github.ref }} && secrets.TOKEN != null",
                            "run": "echo never",
                        }
                    ]
                }
            }
        }
    )

    assert evidence["status"] == "FAIL"
    assert any(
        finding["code"] == "malformed_expression"
        and finding.get("detail") == "mixed_if_expression_syntax"
        for finding in evidence["findings"]
    )


def test_workflow_context_rejects_expression_in_mapping_key():
    evidence = ci_review._workflow_expression_context_evidence(
        {"jobs": {"review": {"env": {"${{ runner.temp }}": "value"}}}}
    )

    assert evidence["status"] == "FAIL"
    assert any(
        finding["code"] == "unsupported_expression_key_path"
        for finding in evidence["findings"]
    )


def test_workflow_context_rejects_unsupported_expression_key_path():
    evidence = ci_review._workflow_expression_context_evidence(
        {"jobs": {"review": {"timeout-minutes": "${{ github.run_id }}"}}}
    )

    assert evidence["status"] == "FAIL"
    assert evidence["findings"] == [
        {
            "code": "unsupported_expression_key_path",
            "path": "jobs.review.timeout-minutes",
        }
    ]


def test_workflow_context_policy_integration_rejects_runner_at_job_env(tmp_path):
    text = (ROOT / ".github" / "workflows" / "ci.yml").read_text(
        encoding="utf-8"
    )
    text = text.replace(
        '      PYTHONNOUSERSITE: "1"\n',
        "      PYTHONNOUSERSITE: ${{ runner.temp }}\n",
        1,
    )

    exit_code, payload = _validate_workflow_text(tmp_path, text)

    assert exit_code == 1
    assert payload["context_validation"]["status"] == "FAIL"
    assert {
        "code": "context_not_available",
        "context": "runner",
        "path": "jobs.review.env.PYTHONNOUSERSITE",
    } in payload["context_validation"]["findings"]


def test_workflow_context_configure_pycache_step_appends_github_env(
    tmp_path, monkeypatch
):
    text = (ROOT / ".github" / "workflows" / "ci.yml").read_text(
        encoding="utf-8"
    )
    document = ci_review._parse_workflow_yaml(text)
    step = next(
        candidate
        for candidate in document["jobs"]["review"]["steps"]
        if candidate.get("id") == "configure_pycache"
    )
    github_env = tmp_path / "GITHUB_ENV"
    github_env.write_text("EXISTING=value\n", encoding="utf-8", newline="\n")
    pycache = tmp_path / "runner-temp" / "continuityos-pycache"
    monkeypatch.setenv("GITHUB_ENV", str(github_env))
    monkeypatch.setenv("PYTHONPYCACHEPREFIX", str(pycache))

    exec(compile(step["run"], "<configure_pycache>", "exec"), {})

    assert github_env.read_text(encoding="utf-8").splitlines() == [
        "EXISTING=value",
        f"PYTHONPYCACHEPREFIX={pycache}",
    ]


def test_workflow_policy_accepts_reviewed_immutable_actions_and_lock(tmp_path):
    text = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")

    exit_code, payload = _validate_workflow_text(tmp_path, text)

    assert exit_code == 0
    assert payload["status"] == "PASS"
    assert payload["action_refs"] == ci_review.REVIEWED_ACTION_REFS
    assert payload["review_lock"]["status"] == "PASS"
    assert payload["context_validation"]["status"] == "PASS"
    assert payload["context_validation"]["failure_codes"] == []
    assert payload["context_validation"]["checked_expression_count"] > 0


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
    assert payload["review_environment_closure_exact"] is True
    assert payload["install_post_inventory_exact"] is True
    assert payload["verify_command_inventory_exact"] is True
    assert payload["review_python_bindings_exact"] is True


def test_final_gate_rejects_missing_configure_pycache_outcome(
    tmp_path, monkeypatch
):
    repo, receipts, steps = _complete_final_gate_fixture(tmp_path, "Windows")
    steps = [
        conclusion
        for conclusion in steps
        if not conclusion.startswith("configure_pycache=")
    ]
    output = tmp_path / "final-gate-missing-configure-pycache.json"
    monkeypatch.chdir(repo)

    exit_code = ci_review.final_gate(
        _final_gate_args(receipts, output, repo, "Windows", steps)
    )
    payload = json.loads(output.read_text(encoding="utf-8"))

    assert exit_code == 1
    assert (
        "step_conclusion:configure_pycache:expected_success:observed_None"
        in payload["failure_codes"]
    )


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


def test_final_gate_recomputes_inventory_location_containment(
    tmp_path, monkeypatch
):
    repo, receipts, steps = _complete_final_gate_fixture(tmp_path, "Windows")
    inventory_path = receipts / "review-tooling-environment.json"
    inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
    inventory["installed_packages"][0]["location"] = str(
        tmp_path / "outside-review-environment"
    )
    inventory["installed_packages"][0]["under_prefix"] = True
    _write_json(inventory_path, inventory)
    output = tmp_path / "final-gate-forged-location.json"
    monkeypatch.chdir(repo)

    exit_code = ci_review.final_gate(
        _final_gate_args(receipts, output, repo, "Windows", steps)
    )
    payload = json.loads(output.read_text(encoding="utf-8"))

    assert exit_code == 1
    assert payload["review_environment_closure_exact"] is False
    assert "review_environment_installed_closure_not_exact" in payload[
        "failure_codes"
    ]


def test_final_gate_revalidates_creation_receipt_after_sha_rebinding(
    tmp_path, monkeypatch
):
    repo, receipts, steps = _complete_final_gate_fixture(tmp_path, "Windows")
    creation_path = receipts / "create-review-environment.json"
    creation = json.loads(creation_path.read_text(encoding="utf-8"))
    creation["expected_python_version"] = "0.0.0"
    _write_json(creation_path, creation)
    tampered_sha256 = ci_review._sha256_file(creation_path)
    for step_id, receipt_name in ci_review.REVIEW_PYTHON_STEP_RECEIPTS.items():
        if step_id == "linux_symlink":
            continue
        binding_path = receipts / receipt_name
        binding = json.loads(binding_path.read_text(encoding="utf-8"))
        binding["environment_receipt_sha256"] = tampered_sha256
        _write_json(binding_path, binding)
    output = tmp_path / "final-gate-tampered-creation-version.json"
    monkeypatch.chdir(repo)

    exit_code = ci_review.final_gate(
        _final_gate_args(receipts, output, repo, "Windows", steps)
    )
    payload = json.loads(output.read_text(encoding="utf-8"))

    assert exit_code == 1
    assert payload["review_python_bindings_exact"] is True
    assert "review_environment_creation_version_not_exact" in payload[
        "failure_codes"
    ]


def test_final_gate_rejects_consistent_alternate_interpreter_rebinding(
    tmp_path, monkeypatch
):
    repo, receipts, steps = _complete_final_gate_fixture(tmp_path, "Windows")
    creation_path = receipts / "create-review-environment.json"
    creation = json.loads(creation_path.read_text(encoding="utf-8"))
    alternate = Path(creation["scripts_directory"]) / "alternate-python.exe"
    alternate.write_bytes(b"alternate launcher negative control\n")
    creation["interpreter"] = str(alternate)
    creation["interpreter_probe"]["executable"] = str(alternate)
    _write_json(creation_path, creation)
    tampered_sha256 = ci_review._sha256_file(creation_path)
    inventory_path = receipts / "review-tooling-environment.json"
    inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
    inventory["python_executable"] = str(alternate)
    _write_json(inventory_path, inventory)
    for step_id, receipt_name in ci_review.REVIEW_PYTHON_STEP_RECEIPTS.items():
        if step_id == "linux_symlink":
            continue
        binding_path = receipts / receipt_name
        binding = json.loads(binding_path.read_text(encoding="utf-8"))
        binding["environment_receipt_sha256"] = tampered_sha256
        binding["exact_interpreter"] = str(alternate)
        binding["exact_command"][0] = str(alternate)
        binding["child_identity_before"]["executable"] = str(alternate)
        binding["child_identity_after"]["executable"] = str(alternate)
        _write_json(binding_path, binding)
    output = tmp_path / "final-gate-alternate-interpreter.json"
    monkeypatch.chdir(repo)

    exit_code = ci_review.final_gate(
        _final_gate_args(receipts, output, repo, "Windows", steps)
    )
    payload = json.loads(output.read_text(encoding="utf-8"))

    assert exit_code == 1
    assert payload["review_python_bindings_exact"] is True
    assert (
        "review_environment_creation_interpreter_not_canonical"
        in payload["failure_codes"]
    )


@pytest.mark.parametrize(
    ("mutation", "failure_fragment"),
    [
        ("missing", "receipt_status:clean-source-pytest.json:missing"),
        (
            "schema",
            "review_python_binding:compileall.json:schema_not_exact",
        ),
        (
            "creation_sha",
            "review_python_binding:compileall.json:creation_receipt_sha_mismatch",
        ),
        (
            "child_identity",
            "review_python_binding:compileall.json:child_prefix_after_mismatch",
        ),
    ],
)
def test_final_gate_rejects_invalid_review_python_command_receipt(
    tmp_path, monkeypatch, mutation, failure_fragment
):
    repo, receipts, steps = _complete_final_gate_fixture(tmp_path, "Windows")
    target = receipts / "compileall.json"
    if mutation == "missing":
        target = receipts / "clean-source-pytest.json"
        target.unlink()
    else:
        payload = json.loads(target.read_text(encoding="utf-8"))
        if mutation == "schema":
            payload["schema"] = "wrong-schema"
        elif mutation == "creation_sha":
            payload["environment_receipt_sha256"] = "0" * 64
        elif mutation == "child_identity":
            payload["child_identity_after"]["prefix"] = str(
                tmp_path / "different-environment"
            )
        _write_json(target, payload)
    output = tmp_path / f"final-gate-{mutation}.json"
    monkeypatch.chdir(repo)

    exit_code = ci_review.final_gate(
        _final_gate_args(receipts, output, repo, "Windows", steps)
    )
    payload = json.loads(output.read_text(encoding="utf-8"))

    assert exit_code == 1
    assert payload["status"] == payload["final_gate"] == "FAIL"
    assert failure_fragment in payload["failure_codes"]
    assert payload["review_python_bindings_exact"] is False


def test_final_gate_rejects_seed_only_inventory_after_successful_install(
    tmp_path, monkeypatch
):
    repo, receipts, steps = _complete_final_gate_fixture(tmp_path, "Windows")
    install_path = receipts / "install-review-tooling.json"
    install = json.loads(install_path.read_text(encoding="utf-8"))
    seed_only = [
        {"name": "pip", "version": "24.0"},
        {"name": "setuptools", "version": "65.5.0"},
    ]
    serialized = json.dumps(
        seed_only,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    install["child_identity_after"]["installed_packages"] = seed_only
    install["child_identity_after"]["installed_package_count"] = len(seed_only)
    install["child_identity_after"]["installed_packages_sha256"] = (
        ci_review._sha256(serialized)
    )
    assert install["status"] == "PASS"
    assert install["exit_code"] == 0
    _write_json(install_path, install)
    output = tmp_path / "final-gate-seed-only.json"
    monkeypatch.chdir(repo)

    exit_code = ci_review.final_gate(
        _final_gate_args(receipts, output, repo, "Windows", steps)
    )
    payload = json.loads(output.read_text(encoding="utf-8"))

    assert exit_code == 1
    assert payload["status"] == payload["final_gate"] == "FAIL"
    assert payload["install_post_inventory_exact"] is False
    assert "install_post_inventory_not_exact" in payload["failure_codes"]


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


def test_workflow_policy_requires_receipt_binding_for_every_locked_consumer(
    tmp_path,
):
    text = (ROOT / ".github" / "workflows" / "ci.yml").read_text(
        encoding="utf-8"
    )
    exact = "          python -m tools.ci_review run-review-python\n"
    assert text.count(exact) == len(ci_review.REVIEW_PYTHON_STEP_RECEIPTS)
    text = text.replace(
        exact,
        "          python -m tools.ci_review run\n",
        1,
    )

    exit_code, payload = _validate_workflow_text(tmp_path, text)

    assert exit_code == 1
    assert (
        "review interpreter binding: install_tooling: "
        "python -m tools.ci_review run-review-python"
        in payload["missing_required_tokens"]
    )


def test_workflow_policy_rejects_nested_generic_interpreter(tmp_path):
    text = (ROOT / ".github" / "workflows" / "ci.yml").read_text(
        encoding="utf-8"
    )
    exact = "          -- -m pytest -q\n"
    assert exact in text
    text = text.replace(exact, "          -- python -m pytest -q\n", 1)

    exit_code, payload = _validate_workflow_text(tmp_path, text)

    assert exit_code == 1
    assert "nested generic interpreter: clean_tests" in payload[
        "forbidden_findings"
    ]


def test_create_review_environment_exports_isolated_interpreter(
    tmp_path, monkeypatch
):
    host_version = ".".join(map(str, sys.version_info[:3]))
    monkeypatch.setattr(ci_review, "REVIEW_PYTHON_VERSION", host_version)
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
    assert payload["expected_python_version"] == host_version
    assert payload["interpreter_probe"]["version"] == host_version
    assert github_path.read_text(encoding="utf-8").strip() == payload[
        "scripts_directory"
    ]


def test_create_review_environment_rejects_host_version_mismatch(
    tmp_path, monkeypatch
):
    host_version = ".".join(map(str, sys.version_info[:3]))
    mismatched_version = "0.0.0" if host_version != "0.0.0" else "999.999.999"
    monkeypatch.setattr(
        ci_review, "REVIEW_PYTHON_VERSION", mismatched_version
    )
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

    assert exit_code == 1
    assert payload["status"] == "FAIL"
    assert payload["expected_python_version"] == mismatched_version
    assert payload["interpreter_probe"]["version"] == host_version
    assert payload["failure_codes"] == ["review_python_version_not_exact"]
    assert not github_path.exists()


def test_create_review_environment_passes_without_path_export(
    tmp_path, monkeypatch
):
    host_version = ".".join(map(str, sys.version_info[:3]))
    monkeypatch.setattr(ci_review, "REVIEW_PYTHON_VERSION", host_version)
    output = tmp_path / "create-review-environment.json"

    exit_code = ci_review.create_review_environment(
        SimpleNamespace(
            directory=str(tmp_path / "review environment without path export"),
            path_file=None,
            output=str(output),
        )
    )
    payload = json.loads(output.read_text(encoding="utf-8"))

    assert exit_code == 0
    assert payload["status"] == "PASS"
    assert payload["failure_codes"] == []
    assert payload["path_file_requested"] is False
    assert payload["path_file_status"] == "NOT_REQUESTED"
    assert payload["path_has_authority"] is False


def test_create_review_environment_path_export_failure_is_non_authoritative(
    tmp_path, monkeypatch
):
    host_version = ".".join(map(str, sys.version_info[:3]))
    monkeypatch.setattr(ci_review, "REVIEW_PYTHON_VERSION", host_version)
    path_file = tmp_path / "unwritable-github-path"
    original_open = Path.open

    def controlled_open(path, *args, **kwargs):
        if path == path_file:
            raise PermissionError("negative control")
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", controlled_open)
    output = tmp_path / "create-review-environment.json"

    exit_code = ci_review.create_review_environment(
        SimpleNamespace(
            directory=str(tmp_path / "review-venv"),
            path_file=str(path_file),
            output=str(output),
        )
    )
    payload = json.loads(output.read_text(encoding="utf-8"))

    assert exit_code == 0
    assert payload["status"] == "PASS"
    assert payload["failure_codes"] == []
    assert payload["path_file_requested"] is True
    assert payload["path_file_configured"] is False
    assert payload["path_file_status"] == "FAIL"
    assert payload["path_file_error_class"] == "PermissionError"
    assert payload["path_has_authority"] is False


def test_review_python_uses_receipt_bound_child_with_poisoned_path_and_spaces(
    tmp_path, monkeypatch, bound_review_environment
):
    bound = bound_review_environment
    monkeypatch.setattr(ci_review, "REVIEW_PYTHON_VERSION", bound.version)
    receipt = tmp_path / "create-review-environment.json"
    _write_json(receipt, _valid_creation_receipt(bound))
    outer_directory = Path(sys.executable).resolve().parent
    poisoned_path = os.pathsep.join(
        [str(outer_directory), str(bound.scripts_directory), os.environ.get("PATH", "")]
    )
    monkeypatch.setenv("PATH", poisoned_path)
    monkeypatch.setenv("PYTHONHOME", str(tmp_path / "hostile-python-home"))
    generic_python = shutil.which("python")
    assert generic_python is not None
    assert ci_review._lexical_paths_equal(generic_python, sys.executable)
    output = tmp_path / "bound-command.json"
    code = (
        "import json,sys;"
        "print(json.dumps({'executable':sys.executable,'prefix':sys.prefix},"
        "sort_keys=True))"
    )

    exit_code = ci_review.review_python_command_receipt(
        SimpleNamespace(
            environment_receipt=str(receipt),
            output=str(output),
            cwd=str(tmp_path),
            command=["--", "-c", code],
        )
    )
    payload = json.loads(output.read_text(encoding="utf-8"))
    observed = json.loads(payload["stdout"])

    assert exit_code == 0
    assert payload["status"] == "PASS"
    assert payload["failure_codes"] == []
    assert payload["exact_command"][0] == str(bound.interpreter)
    assert ci_review._lexical_paths_equal(observed["executable"], bound.interpreter)
    assert ci_review._lexical_paths_equal(observed["prefix"], bound.environment)
    assert payload["path_evidence_before"][
        "generic_python_resolution_class"
    ] == "outer_interpreter"
    assert payload["path_evidence_before"][
        "order_class"
    ] == "outer_precedes_environment"
    path_evidence_text = json.dumps(payload["path_evidence_before"])
    assert str(outer_directory) not in path_evidence_text
    assert str(bound.scripts_directory) not in path_evidence_text
    assert " " in str(bound.interpreter)


def test_review_python_preserves_failed_command_and_post_identity(
    tmp_path, monkeypatch, bound_review_environment
):
    bound = bound_review_environment
    monkeypatch.setattr(ci_review, "REVIEW_PYTHON_VERSION", bound.version)
    receipt = tmp_path / "create-review-environment.json"
    _write_json(receipt, _valid_creation_receipt(bound))
    output = tmp_path / "failed-command.json"
    code = (
        "import sys;print('retained stdout');"
        "print('retained stderr',file=sys.stderr);raise SystemExit(7)"
    )

    exit_code = ci_review.review_python_command_receipt(
        SimpleNamespace(
            environment_receipt=str(receipt),
            output=str(output),
            cwd=str(tmp_path),
            command=["--", "-c", code],
        )
    )
    payload = json.loads(output.read_text(encoding="utf-8"))

    assert exit_code == 7
    assert payload["status"] == "FAIL"
    assert payload["execution_attempted"] is True
    assert payload["exit_code"] == 7
    assert "retained stdout" in payload["stdout"]
    assert "retained stderr" in payload["stderr"]
    assert payload["child_identity_before"]
    assert payload["child_identity_after"]
    assert payload["identity_probe_after"]["exit_code"] == 0
    assert payload["failure_codes"] == ["child_command_failed"]


def test_review_python_rejects_seed_only_post_install_inventory(
    tmp_path, monkeypatch, bound_review_environment
):
    bound = bound_review_environment
    monkeypatch.setattr(ci_review, "REVIEW_PYTHON_VERSION", bound.version)
    receipt = tmp_path / "create-review-environment.json"
    _write_json(receipt, _valid_creation_receipt(bound))
    output = tmp_path / "seed-only-install-command.json"

    exit_code = ci_review.review_python_command_receipt(
        SimpleNamespace(
            environment_receipt=str(receipt),
            output=str(output),
            cwd=str(ROOT),
            require_post_lock=str(
                ROOT / "requirements" / "review-ci-py311.lock"
            ),
            command=["--", "-c", "print('successful no-op install')"],
        )
    )
    payload = json.loads(output.read_text(encoding="utf-8"))

    assert exit_code == 1
    assert payload["execution_attempted"] is True
    assert payload["exit_code"] == 0
    assert payload["post_inventory_exact"] is False
    assert payload["required_post_lock_sha256"]
    assert "post_inventory_not_exact_locked_closure" in payload[
        "failure_codes"
    ]
    assert payload["status"] == "FAIL"


@pytest.mark.parametrize(
    ("mutation", "failure_code"),
    [
        ("status", "environment_receipt_status_not_pass"),
        ("failure_codes", "environment_receipt_failure_codes_present"),
        ("schema", "environment_receipt_schema_not_exact"),
        ("missing_interpreter", "interpreter_missing"),
        ("alternate_interpreter", "interpreter_path_not_canonical"),
        ("outside_interpreter", "interpreter_outside_environment"),
        ("expected_version", "environment_receipt_python_version_not_exact"),
        ("probe_version", "creation_probe_version_mismatch"),
        ("tampered_environment", "creation_probe_prefix_mismatch"),
        ("relative_environment", "environment_path_not_absolute"),
        ("relative_interpreter", "interpreter_path_not_absolute"),
        ("path_authority", "environment_receipt_path_authority_not_false"),
        ("probe_executable", "creation_probe_executable_mismatch"),
        ("probe_base_prefix", "child_base_prefix_before_not_creation_identity"),
    ],
)
def test_review_python_rejects_tampered_creation_receipt(
    tmp_path,
    monkeypatch,
    bound_review_environment,
    mutation,
    failure_code,
):
    bound = bound_review_environment
    monkeypatch.setattr(ci_review, "REVIEW_PYTHON_VERSION", bound.version)
    payload = _valid_creation_receipt(bound)
    if mutation == "status":
        payload["status"] = "FAIL"
    elif mutation == "failure_codes":
        payload["failure_codes"] = ["forged-pass-negative-control"]
    elif mutation == "schema":
        payload["schema"] = "wrong-schema"
    elif mutation == "missing_interpreter":
        missing = bound.scripts_directory / "missing-review-python.exe"
        payload["interpreter"] = str(missing)
        payload["interpreter_probe"]["executable"] = str(missing)
    elif mutation == "alternate_interpreter":
        alternate = bound.scripts_directory / (
            "alternate-python.exe" if os.name == "nt" else "alternate-python"
        )
        alternate.write_bytes(b"alternate launcher negative control\n")
        payload["interpreter"] = str(alternate)
        payload["interpreter_probe"]["executable"] = str(alternate)
    elif mutation == "outside_interpreter":
        payload["interpreter"] = str(Path(sys.executable).resolve())
        payload["scripts_directory"] = str(Path(sys.executable).resolve().parent)
    elif mutation == "expected_version":
        payload["expected_python_version"] = "0.0.0"
    elif mutation == "probe_version":
        payload["interpreter_probe"]["version"] = "0.0.0"
    elif mutation == "tampered_environment":
        payload["environment"] = str(bound.environment.parent)
    elif mutation == "relative_environment":
        payload["environment"] = "relative-review-environment"
    elif mutation == "relative_interpreter":
        payload["interpreter"] = "Scripts/python.exe"
    elif mutation == "path_authority":
        payload["path_has_authority"] = True
    elif mutation == "probe_executable":
        payload["interpreter_probe"]["executable"] = str(
            Path(sys.executable).resolve()
        )
    elif mutation == "probe_base_prefix":
        payload["interpreter_probe"]["base_prefix"] = str(
            bound.environment.parent / "different-base-python"
        )
    receipt = tmp_path / f"creation-{mutation}.json"
    _write_json(receipt, payload)
    output = tmp_path / f"command-{mutation}.json"

    exit_code = ci_review.review_python_command_receipt(
        SimpleNamespace(
            environment_receipt=str(receipt),
            output=str(output),
            cwd=str(tmp_path),
            command=["--", "-c", "print('must not execute')"],
        )
    )
    observed = json.loads(output.read_text(encoding="utf-8"))

    assert exit_code == 1
    assert observed["status"] == "FAIL"
    assert failure_code in observed["failure_codes"]
    assert observed["execution_attempted"] is False


def test_review_python_rejects_invalid_creation_receipt_json(tmp_path):
    receipt = tmp_path / "invalid-create-review-environment.json"
    receipt.write_text("{invalid", encoding="utf-8")
    output = tmp_path / "invalid-command.json"

    exit_code = ci_review.review_python_command_receipt(
        SimpleNamespace(
            environment_receipt=str(receipt),
            output=str(output),
            cwd=str(tmp_path),
            command=["--", "-c", "print('must not execute')"],
        )
    )
    payload = json.loads(output.read_text(encoding="utf-8"))

    assert exit_code == 1
    assert payload["status"] == "FAIL"
    assert "environment_receipt_invalid_json" in payload["failure_codes"]
    assert payload["execution_attempted"] is False


def test_review_python_rejects_caller_replacement_interpreter(
    tmp_path, monkeypatch, bound_review_environment
):
    bound = bound_review_environment
    monkeypatch.setattr(ci_review, "REVIEW_PYTHON_VERSION", bound.version)
    receipt = tmp_path / "create-review-environment.json"
    _write_json(receipt, _valid_creation_receipt(bound))
    output = tmp_path / "replacement-command.json"

    exit_code = ci_review.review_python_command_receipt(
        SimpleNamespace(
            environment_receipt=str(receipt),
            output=str(output),
            cwd=str(tmp_path),
            command=["--", sys.executable, "-c", "print('must not execute')"],
        )
    )
    payload = json.loads(output.read_text(encoding="utf-8"))

    assert exit_code == 1
    assert payload["status"] == "FAIL"
    assert payload["execution_attempted"] is False
    assert payload["failure_codes"] == [
        "caller_replacement_interpreter_rejected"
    ]


def test_review_python_rejects_child_identity_drift(
    tmp_path, monkeypatch, bound_review_environment
):
    bound = bound_review_environment
    monkeypatch.setattr(ci_review, "REVIEW_PYTHON_VERSION", bound.version)
    receipt = tmp_path / "create-review-environment.json"
    _write_json(receipt, _valid_creation_receipt(bound))
    output = tmp_path / "identity-drift-command.json"
    original_probe = ci_review._probe_review_python

    def mismatched_probe(interpreter, environment):
        identity, evidence = original_probe(interpreter, environment)
        identity["prefix"] = str(bound.environment.parent)
        return identity, evidence

    monkeypatch.setattr(ci_review, "_probe_review_python", mismatched_probe)

    exit_code = ci_review.review_python_command_receipt(
        SimpleNamespace(
            environment_receipt=str(receipt),
            output=str(output),
            cwd=str(tmp_path),
            command=["--", "-c", "print('must not execute')"],
        )
    )
    payload = json.loads(output.read_text(encoding="utf-8"))

    assert exit_code == 1
    assert payload["status"] == "FAIL"
    assert payload["execution_attempted"] is False
    assert "child_prefix_before_not_creation_environment" in payload[
        "failure_codes"
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
        assert payload["installed_package_count"] == len(
            ci_review.REVIEW_LOCK_PACKAGES
        ) == 12
        assert {
            item["name"] for item in payload["installed_packages"]
        } == ci_review.REVIEW_LOCK_PACKAGES
    else:
        assert exit_code == 1
        assert payload["status"] == "FAIL"
        assert failure_code in payload["failure_codes"]
