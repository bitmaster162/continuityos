from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

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


def _validate_workflow_text(tmp_path, text):
    workflow = tmp_path / "ci.yml"
    output = tmp_path / "policy.json"
    workflow.write_text(text, encoding="utf-8")
    args = type(
        "Args",
        (),
        {"workflow": str(workflow), "output": str(output)},
    )()
    return ci_review.workflow_policy(args), json.loads(output.read_text(encoding="utf-8"))


def test_workflow_policy_requires_always_on_post_corpus_gates(tmp_path):
    text = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    text = text.replace(
        "      - name: Run portable release-hardening probes\n        if: always()\n",
        "      - name: Run portable release-hardening probes\n",
    )
    exit_code, payload = _validate_workflow_text(tmp_path, text)
    assert exit_code == 1
    assert "always gate: Run portable release-hardening probes" in payload[
        "missing_required_tokens"
    ]


def test_workflow_policy_requires_always_and_linux_on_symlink_gate(tmp_path):
    text = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    text = text.replace(
        "        if: always() && runner.os == 'Linux'\n",
        "        if: runner.os == 'Linux'\n",
    )
    exit_code, payload = _validate_workflow_text(tmp_path, text)
    assert exit_code == 1
    assert "always gate: Run mandatory Linux symlink and realpath regression" in payload[
        "missing_required_tokens"
    ]


def test_workflow_policy_rejects_continue_on_error_for_mandatory_gates(tmp_path):
    text = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    text = text.replace(
        "      - name: Run governance regression corpus\n",
        "      - name: Run governance regression corpus\n        continue-on-error: true\n",
    )
    exit_code, payload = _validate_workflow_text(tmp_path, text)
    assert exit_code == 1
    assert "non-mandatory step" in payload["forbidden_findings"]
