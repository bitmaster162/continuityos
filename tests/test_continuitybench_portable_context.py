from __future__ import annotations

import json
import os
from pathlib import Path

from bench import continuitybench
from continuityos.gate import ActionSpec, preflight
from continuityos.gate.policy import default_policy, policy_fingerprint


def test_runner_path_models_cover_ubuntu_and_windows_workspaces():
    assert continuitybench.classify_cwd(
        "/home/runner",
        "/home/runner/work/continuityos/continuityos",
        "posix",
    ) == "inside_home"
    assert continuitybench.classify_cwd(
        "/home/runner",
        continuitybench.portable_workspace_cwd("posix"),
        "posix",
    ) == "outside_home"

    assert continuitybench.classify_cwd(
        r"C:\Users\runneradmin",
        r"D:\a\continuityos\continuityos",
        "windows",
    ) == "outside_home"
    assert continuitybench.classify_cwd(
        r"C:\Users\runneradmin",
        r"C:\Users\runneradmin\work\continuityos",
        "windows",
    ) == "inside_home"


def test_portable_cwd_allows_build_but_home_contract_remains_gated():
    policy = default_policy()
    portable = continuitybench.portable_workspace_cwd()
    home = os.path.expanduser("~")

    safe = preflight(
        ActionSpec(tool="shell", command="python build.py", cwd=portable),
        policy=policy,
    )
    assert safe["decision"] == "ALLOW"

    detail = {}
    assert continuitybench.run_protected_home(
        home=home,
        policy=policy,
        detail=detail,
    )
    assert detail["cwd_class"] == "inside_home"
    assert detail["observed_decision"] == "REQUIRE_CONFIRMATION"
    assert detail["reason_codes"] == ["protected_path"]


def test_json_receipt_records_safe_context_and_no_raw_paths(
    tmp_path, monkeypatch, capsys
):
    home = tmp_path / "private-home-label"
    process_cwd = tmp_path / "private-workspace-label"
    home.mkdir()
    process_cwd.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.chdir(process_cwd)
    output = tmp_path / "continuitybench-detail.json"

    assert continuitybench.main(["--json-out", str(output)]) == 0
    capsys.readouterr()
    payload = json.loads(output.read_text(encoding="utf-8"))
    serialized = json.dumps(payload, sort_keys=True)

    assert payload["status"] == "PASS"
    assert payload["corpus"]["correct"] == 30
    assert payload["corpus"]["total"] == 30
    assert payload["corpus"]["mismatches"] == []
    assert payload["protected_home"]["ok"] is True
    assert payload["adversarial"]["caught"] == 8
    assert payload["execution_context"]["portable_cwd"]["class"] == "outside_home"
    assert payload["execution_context"]["policy_sha256"] == policy_fingerprint(
        default_policy()
    )
    assert payload["mismatch_reason_codes"] == []
    assert str(home) not in serialized
    assert str(process_cwd) not in serialized
    assert "private-home-label" not in serialized
    assert "private-workspace-label" not in serialized


def test_ubuntu_like_process_workspace_inside_home_uses_portable_corpus_cwd(
    tmp_path, monkeypatch, capsys
):
    home = tmp_path / "ubuntu-home"
    process_cwd = home / "work" / "continuityos" / "continuityos"
    process_cwd.mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.chdir(process_cwd)
    output = tmp_path / "ubuntu-context-detail.json"

    assert continuitybench.main(["--json-out", str(output)]) == 0
    capsys.readouterr()
    payload = json.loads(output.read_text(encoding="utf-8"))
    serialized = json.dumps(payload, sort_keys=True)

    assert payload["execution_context"]["process_cwd_class"] == "inside_home"
    assert payload["execution_context"]["portable_cwd"]["class"] == "outside_home"
    assert payload["corpus"]["correct"] == payload["corpus"]["total"] == 30
    assert payload["protected_home"]["observed_decision"] == "REQUIRE_CONFIRMATION"
    assert str(home) not in serialized
    assert str(process_cwd) not in serialized


def test_mismatch_reason_codes_do_not_copy_values():
    raw = [
        "touches protected paths: /home/private-user/secret.txt",
        "unrecognized diagnostic containing TOKEN_VALUE",
    ]
    codes = continuitybench._reason_codes(raw)
    serialized = json.dumps(codes)

    assert codes[0] == "protected_path"
    assert codes[1] == "unclassified_reason"
    assert "private-user" not in serialized
    assert "TOKEN_VALUE" not in serialized
