from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "windows" / "SovereignTwin-Dogfood-R11.ps1"


def _script_or_skip() -> Path:
    if not SCRIPT.exists():
        pytest.skip("repo-only Windows dogfood script is not packaged in wheel")
    return SCRIPT


def test_dogfood_r11_contract_is_fail_closed_and_opt_in_for_fast_smoke():
    script = _script_or_skip()
    text = script.read_text(encoding="utf-8")

    assert "[Parameter(Mandatory=$true)][string]$SourceSha" in text
    assert "$SourceSha -notmatch '^[0-9a-fA-F]{40}$'" in text
    assert "SovereignTwin-Install-Runtime.ps1" in text
    assert "-NoAutostart -NoStart" in text
    assert "runtime source manifest did not bind exact SourceSha" in text

    dry_pos = text.index('Step "Dry-run re-embedding plan"')
    commit_pos = text.index('Step "Commit re-embedding into fresh target only"')
    compat_pos = text.index('Step "Manifest-bound compatibility gate on target"')
    activate_pos = text.index('Step "Atomic activation with rollback-on-failure"')
    final_pos = text.index('Step "Final active runtime verification"')
    assert dry_pos < commit_pos < compat_pos < activate_pos < final_pos

    assert '"COMPATIBLE_MANIFEST_BOUND"' in text
    assert 'selected_embedding_dimension -eq 768' in text
    assert 'execution_authority = "NONE"' in text
    assert 'can_execute = $false' in text
    assert "[switch]$SmokeFast" in text
    assert "if ($SmokeFast)" in text
    assert "ask --mode fast" in text


def test_dogfood_r11_powershell_syntax_on_windows():
    script = _script_or_skip()
    ps = shutil.which("powershell.exe") or shutil.which("powershell")
    if ps is None:
        pytest.skip("PowerShell unavailable on this runner")

    escaped_script = str(script).replace("'", "''")
    command = (
        "$ErrorActionPreference='Stop'; "
        f"$text=Get-Content -LiteralPath '{escaped_script}' -Raw; "
        "[scriptblock]::Create($text) | Out-Null"
    )
    proc = subprocess.run(
        [ps, "-NoProfile", "-NonInteractive", "-Command", command],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=30,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr or proc.stdout
