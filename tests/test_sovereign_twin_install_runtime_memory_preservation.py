from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "windows" / "SovereignTwin-Install-Runtime.ps1"


def _script_or_skip() -> Path:
    if not SCRIPT.exists():
        pytest.skip("repo-only Windows installer script is not packaged in wheel")
    return SCRIPT


def test_runtime_installer_preserves_existing_active_memory_contract():
    script = _script_or_skip()
    text = script.read_text(encoding="utf-8")

    assert '[string]$MemoryDb = ""' in text
    assert '$PSBoundParameters.ContainsKey("MemoryDb")' in text
    assert 'existing runtime manifest has no memory_db' in text
    assert 'existing active memory DB is missing:' in text
    assert 'installer refuses to change active memory DB; use SovereignTwin-Activate-Memory.ps1' in text
    assert 'existing runtime manifest violates no-execution authority' in text
    assert '$PreserveExistingMemory = $true' in text
    assert 'Step "Preserve existing active memory container"' in text
    assert 'Existing memory DB left untouched:' in text
    assert 'schema = "sovereign-twin.windows-runtime-source/v3"' in text
    assert '$prop.Name -like "memory_*" -and $prop.Name -ne "memory_db"' in text
    assert 'installer refuses to change the active embedding model' in text
    assert 'with expected memory DB $MemoryDb' in text

    preserve_pos = text.index('if ($PreserveExistingMemory)')
    preserve_step_pos = text.index('Step "Preserve existing active memory container"')
    init_step_pos = text.index('Step "Initialize local memory container"')
    init_call_pos = text.index('& $Twin --db $MemoryDb init')
    manifest_pos = text.index('$manifestObj = [ordered]@{')
    assert preserve_pos < preserve_step_pos < init_step_pos < init_call_pos < manifest_pos

    preserve_block = text[preserve_pos:manifest_pos]
    assert '} else {' in preserve_block
    assert preserve_block.count('& $Twin --db $MemoryDb init') == 1


def test_runtime_installer_powershell_syntax_on_windows():
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
