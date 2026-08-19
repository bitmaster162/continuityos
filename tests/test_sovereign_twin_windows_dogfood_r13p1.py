from pathlib import Path
import platform
import subprocess

import pytest


SCRIPT = Path("scripts/windows/SovereignTwin-Dogfood-R13P1.ps1")


def _require_source_script() -> Path:
    if not SCRIPT.is_file():
        pytest.skip("R13P1 Windows harness is source-only and is not shipped in the wheel")
    return SCRIPT


def _text() -> str:
    return _require_source_script().read_text(encoding="utf-8")


def test_r13p1_harness_is_exact_sha_bound_and_authority_none():
    text = _text()
    assert "b781108be9c8c7be3d1c7169642b9ef0d657289c" in text
    assert "edacb54409ebcf355f7a57b3e34190c79dd6c7cd" in text
    assert 'execution_authority -eq "NONE"' in text
    assert "can_execute" in text
    assert "capital_permission = 'DENY'" in text


def test_r13p1_harness_checks_raw_empty_lms_json_without_false_array_wrapper():
    text = _text()
    assert "(& lms ps --json 2>&1 | Out-String).Trim()" in text
    assert "$compact -eq '[]'" in text
    assert "@(lms ps --json | ConvertFrom-Json)" not in text


def test_r13p1_harness_captures_pip_wheel_stdout_before_returning_path():
    text = _text()
    assert "$buildOutput = & $Py -m pip wheel" in text
    assert "$buildExitCode = $LASTEXITCODE" in text
    assert "$buildOutput | ForEach-Object { Write-Host ([string]$_) }" in text
    assert "$wheels = @(Get-ChildItem $wheelDir -Filter 'continuityos-*.whl')" in text
    assert "return [string]$wheelPath" in text
    assert "Require (Test-Path -LiteralPath $targetWheel) 'target wheel scalar path validation failed'" in text
    assert "Require (Test-Path -LiteralPath $rollbackWheel) 'rollback wheel scalar path validation failed'" in text


def test_r13p1_harness_preserves_nomic_pointer_and_has_rollback_path():
    text = _text()
    assert "memory-nomic-768-*.db" in text
    assert "manifest DB pointer changed" in text
    assert "rollbackWheel" in text
    assert "$targetInstallAttempted = $true" in text
    assert "if ($targetInstallAttempted -and $rollbackWheel" in text
    assert "ROLLBACK=PASS" in text


def test_r13p1_harness_recovers_stopped_twin_before_preflight():
    text = _text()
    assert "function Ensure-TwinRunning" in text
    assert "Twin not healthy; attempting launcher recovery" in text
    assert "$pre = Ensure-TwinRunning $activeDb" in text


def test_r13p1_harness_enforces_ascii_only_unicode_emission():
    text = _text()
    text.encode("ascii")
    assert "-notmatch '[^\\x00-\\x7F]'" in text
    assert "FromBase64String" in text
    assert "Unicode round-trip failed" in text
    assert "Unicode was not escaped in CLI JSON" in text


def test_r13p1_harness_avoids_ambiguous_variable_colon_interpolation():
    text = _text()
    assert "$Stage:" not in text
    assert "$exitCode:" not in text
    assert "${Stage}:" in text
    assert "${exitCode}" in text


def test_r13p1_harness_validates_two_pass_reasoning_off_contract():
    text = _text()
    assert "bounded_two_pass_reasoning_off" in text
    assert "pass_count -eq 2" in text
    assert "draft_max_output_tokens -eq 400" in text
    assert "final_max_output_tokens -eq 700" in text
    assert "reasoning_output_tokens -eq 0" in text
    assert "outside retrieved evidence" in text


@pytest.mark.skipif(platform.system() != "Windows", reason="PowerShell parser gate is Windows-specific")
def test_r13p1_harness_parses_in_windows_powershell():
    source_script = _require_source_script()
    script = str(source_script.resolve()).replace("'", "''")
    command = (
        "$errors=$null; "
        f"[void][System.Management.Automation.Language.Parser]::ParseFile('{script}', [ref]$null, [ref]$errors); "
        "if ($errors.Count -gt 0) { $errors | ForEach-Object { Write-Error $_.Message }; exit 1 }"
    )
    result = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", command],
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
