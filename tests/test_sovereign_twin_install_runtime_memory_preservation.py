from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
WINDOWS = ROOT / "scripts" / "windows"
INSTALLER = WINDOWS / "SovereignTwin-Install-Runtime.ps1"
DOCTOR = WINDOWS / "SovereignTwin-FirstRun-Doctor.ps1"
RUNTIME_STATUS = WINDOWS / "SovereignTwin-Runtime-Status.ps1"
OPEN_UI = WINDOWS / "SovereignTwin-Open.ps1"
REEMBED = WINDOWS / "SovereignTwin-Reembed-Memory.ps1"


def _script_or_skip(path: Path) -> Path:
    if not path.exists():
        pytest.skip(f"repo-only Windows script is not packaged in wheel: {path.name}")
    return path


def test_runtime_installer_preserves_existing_active_memory_contract():
    text = _script_or_skip(INSTALLER).read_text(encoding="utf-8")

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


def test_runtime_installer_stops_only_validated_twin_before_in_place_upgrade():
    text = _script_or_skip(INSTALLER).read_text(encoding="utf-8")

    assert 'function Stop-KnownTwinListener' in text
    assert 'Get-NetTCPConnection -LocalPort 8765 -State Listen' in text
    assert "if ($cmd -notmatch 'sovereign-twin' -or $cmd -notmatch 'serve')" in text
    assert 'refusing to stop unknown listener on 127.0.0.1:8765' in text
    assert 'Twin listener did not stop on port 8765' in text
    assert 'Step "Stop validated Twin listener before in-place runtime upgrade"' in text
    assert '$StoppedTwinForUpgrade = [bool](Stop-KnownTwinListener)' in text
    assert 'pip install failed; Twin remains stopped fail-closed' in text

    stop_pos = text.index('Step "Stop validated Twin listener before in-place runtime upgrade"')
    install_pos = text.index('Step "Install exact source into venv"')
    manifest_pos = text.index('$manifestObj = [ordered]@{')
    launcher_pos = text.index('Step "Write local UI launcher"')
    start_pos = text.index('Step "Start local Twin UI now"')
    assert stop_pos < install_pos < manifest_pos < launcher_pos < start_pos


def test_first_run_doctor_uses_manifest_bound_memory_and_embedding_model():
    text = _script_or_skip(DOCTOR).read_text(encoding="utf-8")

    assert 'runtime manifest memory_db missing' in text
    assert '$MemoryDb = [System.IO.Path]::GetFullPath([string]$manifestObj.memory_db)' in text
    assert 'runtime manifest memory_db does not exist:' in text
    assert '$EmbeddingModel = [string]$manifestObj.embedding_model' in text
    assert 'Twin UI health memory_db does not match runtime manifest' in text
    assert '& $Twin --db $MemoryDb --embedding-model $EmbeddingModel doctor' in text
    assert '& $Twin --db $MemoryDb --embedding-model $EmbeddingModel memory-doctor' in text
    assert '& $Twin --db $MemoryDb --embedding-model $EmbeddingModel ask' in text
    assert 'schema = "sovereign-twin.first-run-receipt/v2"' in text
    assert 'memory_db = $MemoryDb' in text
    assert 'embedding_model = $EmbeddingModel' in text


def test_runtime_status_reports_manifest_bound_memory_path():
    text = _script_or_skip(RUNTIME_STATUS).read_text(encoding="utf-8")

    assert '$ManifestObj = Get-Content $Manifest -Raw | ConvertFrom-Json' in text
    assert '$MemoryDb = [System.IO.Path]::GetFullPath([string]$ManifestObj.memory_db)' in text
    assert 'MemoryDbPath = $MemoryDb' in text
    assert 'MemoryDb = (Test-Path -LiteralPath $MemoryDb)' in text


def test_ui_opener_requires_manifest_bound_runtime_identity():
    text = _script_or_skip(OPEN_UI).read_text(encoding="utf-8")

    assert '$Manifest = Join-Path $Root "runtime-source.json"' in text
    assert 'runtime manifest authority mismatch' in text
    assert 'runtime manifest unexpectedly grants execution' in text
    assert 'runtime manifest memory_db missing' in text
    assert '$ExpectedMemoryDb = [System.IO.Path]::GetFullPath([string]$runtime.memory_db)' in text
    assert 'runtime manifest memory_db does not exist:' in text
    assert 'function Test-ExpectedHealth' in text
    assert '[string]$Health.execution_authority -ne "NONE"' in text
    assert '[bool]$Health.can_execute' in text
    assert '[System.StringComparer]::OrdinalIgnoreCase.Equals($active, $ExpectedMemoryDb)' in text
    assert 'refusing to open UI: live health does not match runtime manifest' in text
    assert 'started Twin health does not match runtime manifest' in text
    assert 'Sovereign Twin UI did not become healthy with expected runtime identity' in text


def test_reembed_defaults_to_manifest_bound_active_memory():
    text = _script_or_skip(REEMBED).read_text(encoding="utf-8")

    assert '[string]$SourceDb = ""' in text
    assert '$Manifest = Join-Path $Root "runtime-source.json"' in text
    assert 'runtime manifest violates no-execution authority' in text
    assert '$SourceDb = [System.IO.Path]::GetFullPath([string]$runtime.memory_db)' in text
    assert 'Source memory bound to active runtime manifest:' in text
    assert 'Explicit source override differs from active runtime memory:' in text
    assert 'SourceDb must be provided when runtime manifest is missing' in text
    assert '$PSBoundParameters.ContainsKey("EmbeddingModel")' in text
    assert '$EmbeddingModel = $runtimeEmbedding' in text
    assert '[System.StringComparer]::OrdinalIgnoreCase.Equals($SourceDb, $TargetDb)' in text


@pytest.mark.parametrize("script", [INSTALLER, DOCTOR, RUNTIME_STATUS, OPEN_UI, REEMBED])
def test_r16_windows_scripts_parse_on_windows(script: Path):
    script = _script_or_skip(script)
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
