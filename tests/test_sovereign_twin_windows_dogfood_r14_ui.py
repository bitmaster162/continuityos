from pathlib import Path
import platform
import subprocess

import pytest


SCRIPT = Path("scripts/windows/SovereignTwin-Dogfood-R14-UI.ps1")


def _require_source_script() -> Path:
    if not SCRIPT.is_file():
        pytest.skip("R14 UI Windows harness is source-only and is not shipped in the wheel")
    return SCRIPT


def _text() -> str:
    return _require_source_script().read_text(encoding="utf-8")


def test_r14_ui_harness_is_exact_sha_bound_and_authority_none():
    text = _text()
    assert "41fbbbddfdd36865ad9d661f11fc19d5babf5459" in text
    assert "b781108be9c8c7be3d1c7169642b9ef0d657289c" in text
    assert 'execution_authority -eq "NONE"' in text
    assert "can_execute" in text
    assert "capital_permission = 'DENY'" in text


def test_r14_ui_harness_checks_raw_empty_lms_json():
    text = _text()
    assert "(& lms ps --json 2>&1 | Out-String).Trim()" in text
    assert "$compact -eq '[]'" in text
    assert "@(lms ps --json | ConvertFrom-Json)" not in text


def test_r14_ui_harness_captures_wheel_stdout_and_returns_scalar_path():
    text = _text()
    assert "$buildOutput = & $Py -m pip wheel" in text
    assert "$buildExitCode = $LASTEXITCODE" in text
    assert "$buildOutput | ForEach-Object { Write-Host ([string]$_) }" in text
    assert "$wheels = @(Get-ChildItem $wheelDir -Filter 'continuityos-*.whl')" in text
    assert "return [string]$wheelPath" in text
    assert "target wheel scalar path validation failed" in text
    assert "rollback wheel scalar path validation failed" in text


def test_r14_ui_harness_preserves_nomic_pointer_and_has_rollback():
    text = _text()
    assert "memory-nomic-768-*.db" in text
    assert "manifest DB pointer changed" in text
    assert "$targetInstallAttempted = $true" in text
    assert "if ($targetInstallAttempted -and $rollbackWheel" in text
    assert "ROLLBACK=PASS" in text
    assert "function Ensure-TwinRunning" in text


def test_r14_ui_harness_checks_real_ui_and_dedicated_http_endpoint():
    text = _text()
    assert "Invoke-WebRequest \"$UiUrl/\"" in text
    assert "$html.Contains('DEEP-LITE')" in text
    assert "$html.Contains('/ask/deep-lite')" in text
    assert "$html.Contains(\"ask('fast')\")" in text
    assert "$html.Contains(\"ask('deep')\")" in text
    assert '"$UiUrl/ask/deep-lite"' in text
    assert "-Method Post" in text
    assert "$body = @{ query = $query } | ConvertTo-Json -Compress" in text
    assert "mode = 'deep-lite'" not in text


def test_r14_ui_harness_validates_two_pass_citations_cleanup_and_authority():
    text = _text()
    assert "bounded_two_pass_reasoning_off" in text
    assert "pass_count -eq 2" in text
    assert "draft_max_output_tokens -eq 400" in text
    assert "final_max_output_tokens -eq 700" in text
    assert "reasoning_output_tokens -eq 0" in text
    assert "outside retrieved evidence" in text
    assert "Assert-LmsEmpty 'PRE_API_DOGFOOD'" in text
    assert "Assert-LmsEmpty 'POST_API_DOGFOOD'" in text
    assert "R14_UI_DOGFOOD=PASS" in text
    assert "ENDPOINT=/ask/deep-lite" in text


def test_r14_ui_harness_is_ascii_only_and_avoids_colon_interpolation_hazards():
    text = _text()
    text.encode("ascii")
    assert "$Stage:" not in text
    assert "$exitCode:" not in text
    assert "${Stage}:" in text


@pytest.mark.skipif(platform.system() != "Windows", reason="PowerShell parser gate is Windows-specific")
def test_r14_ui_harness_parses_in_windows_powershell():
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
