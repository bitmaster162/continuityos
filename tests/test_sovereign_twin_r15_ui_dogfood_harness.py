from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "windows" / "SovereignTwin-Dogfood-R15-UI.ps1"
TARGET = "670d83f13f23dd9a3294015c9cffa774adc043ef"
PRIOR = "41fbbbddfdd36865ad9d661f11fc19d5babf5459"


def _require_source_script() -> Path:
    if not SCRIPT.is_file():
        pytest.skip("R15 UI Windows harness is source-only and is not shipped in the wheel")
    return SCRIPT


def _text() -> str:
    return _require_source_script().read_text(encoding="utf-8")


def test_r15_harness_locks_exact_lineage_and_shadow_boundaries():
    text = _text()
    assert TARGET in text
    assert PRIOR in text
    assert "LOCAL_SHADOW" in text
    assert 'execution_authority -eq "NONE"' in text
    assert "can_trade = $false" in text
    assert "capital_permission = 'DENY'" in text
    assert "memory-nomic-768-" in text


def test_r15_harness_keeps_wheel_build_output_out_of_return_value():
    text = _text()
    assert "$buildOutput = & $Py -m pip wheel" in text
    assert "$buildOutput | ForEach-Object { Write-Host ([string]$_) }" in text
    assert "return [string]$wheelPath" in text
    assert "target wheel scalar path validation failed" in text
    assert "rollback wheel scalar path validation failed" in text


def test_r15_harness_checks_human_ui_and_real_deep_lite_contract():
    text = _text()
    for marker in (
        "R15_HUMAN_UI_CONTRACT=PASS",
        'id=\"answer\"',
        'id=\"evidence\"',
        "Raw response",
        "textContent",
        "innerHTML",
        "/ask/deep-lite",
        "bounded_two_pass_reasoning_off",
        "draft token budget mismatch",
        "final token budget mismatch",
        "final answer cites mem:$id outside retrieved evidence",
        "Assert-LmsEmpty 'POST_API_DOGFOOD'",
        "R15_UI_DOGFOOD=PASS",
    ):
        assert marker in text


def test_r15_harness_is_ascii_only():
    raw = _require_source_script().read_bytes()
    raw.decode("ascii")


def test_r15_harness_parses_in_windows_powershell():
    if os.name != "nt":
        pytest.skip("Windows PowerShell parser gate")

    source_script = _require_source_script()
    powershell = shutil.which("powershell.exe") or shutil.which("powershell")
    if not powershell:
        pytest.skip("Windows PowerShell unavailable")

    escaped = str(source_script).replace("'", "''")
    command = (
        "$tokens=$null;$errors=$null;"
        f"[System.Management.Automation.Language.Parser]::ParseFile('{escaped}',[ref]$tokens,[ref]$errors)|Out-Null;"
        "if($errors.Count -gt 0){$errors|ForEach-Object{Write-Error $_.Message};exit 1}"
    )
    result = subprocess.run(
        [powershell, "-NoProfile", "-NonInteractive", "-Command", command],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
