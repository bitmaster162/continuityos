param(
    [Parameter(Mandatory=$true)][string]$SourceSha,
    [string]$SourceDb = "$HOME\.continuityos\memory.db",
    [string]$TargetDb = "",
    [string]$EmbeddingModel = "text-embedding-nomic-embed-text-v1.5",
    [switch]$SmokeFast
)

$ErrorActionPreference = "Stop"
$Repo = "bitmaster162/continuityos"
$Root = Join-Path $env:LOCALAPPDATA "SovereignTwin"
$Twin = Join-Path $Root "runtime-venv\Scripts\sovereign-twin.exe"
$RuntimeManifestPath = Join-Path $Root "runtime-source.json"
$Receipts = Join-Path $Root "receipts"
$LlmUrl = "http://127.0.0.1:1234"
$UiUrl = "http://127.0.0.1:8765"
$UiTask = "SovereignTwin-UI"

function Step([string]$Text) { Write-Host "`n=== $Text ===" -ForegroundColor Cyan }
function Require([bool]$Condition, [string]$Message) { if (-not $Condition) { throw $Message } }
function Download-Reviewed([string]$Path, [string]$OutFile) {
    $uri = "https://raw.githubusercontent.com/$Repo/$SourceSha/$Path"
    Invoke-WebRequest -Uri $uri -OutFile $OutFile -UseBasicParsing
    Require (Test-Path -LiteralPath $OutFile) "download failed: $Path"
}
function Resolve-ExactPath([string]$PathValue) {
    return [System.IO.Path]::GetFullPath((Resolve-Path -LiteralPath $PathValue).Path)
}
function Stop-KnownTwinListener {
    $listener = Get-NetTCPConnection -LocalPort 8765 -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $listener) { return $false }
    $pidValue = [int]$listener.OwningProcess
    $proc = Get-CimInstance Win32_Process -Filter "ProcessId = $pidValue" -ErrorAction Stop
    $cmd = [string]$proc.CommandLine
    if ($cmd -notmatch 'sovereign-twin' -or $cmd -notmatch 'serve') {
        throw "refusing to stop unknown listener on 127.0.0.1:8765 (PID=$pidValue)"
    }
    Stop-Process -Id $pidValue -Force -ErrorAction Stop
    for ($i = 0; $i -lt 20; $i++) {
        Start-Sleep -Milliseconds 250
        $still = Get-NetTCPConnection -LocalPort 8765 -State Listen -ErrorAction SilentlyContinue
        if (-not $still) { return $true }
    }
    throw "Twin listener did not stop on port 8765"
}
function Restore-SourceTwin([string]$ExpectedDb) {
    Start-ScheduledTask -TaskName $UiTask
    for ($i = 0; $i -lt 45; $i++) {
        Start-Sleep -Seconds 1
        try {
            $h = Invoke-RestMethod -Uri "$UiUrl/health" -TimeoutSec 2
            if ($h.ok -and $h.memory_db) {
                $active = [System.IO.Path]::GetFullPath([string]$h.memory_db)
                if ($active -eq $ExpectedDb) { return }
            }
        } catch {}
    }
    throw "previous Twin did not recover on source DB: $ExpectedDb"
}

if ($SourceSha -notmatch '^[0-9a-fA-F]{40}$') { throw "-SourceSha must be an exact 40-character Git commit SHA" }
$SourceSha = $SourceSha.ToLowerInvariant()
Require (Test-Path -LiteralPath $SourceDb) "source memory DB missing: $SourceDb"
Require (Test-Path -LiteralPath $RuntimeManifestPath) "runtime source manifest missing: $RuntimeManifestPath"
Require ((Get-ScheduledTask -TaskName "SovereignTwin-LLMStudio" -ErrorAction SilentlyContinue) -ne $null) "SovereignTwin-LLMStudio task missing"
Require ((Get-ScheduledTask -TaskName $UiTask -ErrorAction SilentlyContinue) -ne $null) "$UiTask task missing"

if (-not $TargetDb) {
    $stamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $TargetDb = "$HOME\.continuityos\memory-nomic-768-$stamp.db"
}
$SourceDb = Resolve-ExactPath $SourceDb
$TargetDb = [System.IO.Path]::GetFullPath($TargetDb)
Require ($SourceDb -ne $TargetDb) "source and target DB must be different paths"
Require (-not (Test-Path -LiteralPath $TargetDb)) "target DB already exists: $TargetDb"

New-Item -ItemType Directory -Path $Receipts -Force | Out-Null
$sessionStamp = Get-Date -Format "yyyyMMdd-HHmmss"
$Transcript = Join-Path $Receipts ("dogfood-r11-$sessionStamp.log")
$Work = $null
$TwinStoppedForUpgrade = $false
$ActivationSucceeded = $false
Start-Transcript -Path $Transcript -Force | Out-Null

try {
    Step "Bind migration source to current runtime manifest"
    $preRuntime = Get-Content -LiteralPath $RuntimeManifestPath -Raw | ConvertFrom-Json
    Require ([string]$preRuntime.execution_authority -eq "NONE") "current runtime manifest authority is not NONE"
    Require (-not [bool]$preRuntime.can_execute) "current runtime manifest unexpectedly grants execution"
    Require (-not [string]::IsNullOrWhiteSpace([string]$preRuntime.memory_db)) "current runtime manifest has no memory_db"
    $currentManifestDb = Resolve-ExactPath ([string]$preRuntime.memory_db)
    Require ($currentManifestDb -eq $SourceDb) "SourceDb does not match current runtime memory_db: $currentManifestDb"
    Write-Host "current source DB binding: PASS ($SourceDb)"

    Step "Preflight local services and model catalog"
    $daemonRaw = & lms daemon status --json 2>$null
    if ($LASTEXITCODE -ne 0) { throw "lms daemon status failed" }
    $daemon = ($daemonRaw | Out-String) | ConvertFrom-Json
    Require ([string]$daemon.status -eq "running") "llmster daemon is not running"
    Require ([bool]$daemon.isDaemon) "LM Studio service is not standalone llmster daemon"

    $catalog = Invoke-RestMethod -Uri "$LlmUrl/api/v1/models" -TimeoutSec 10
    $keys = @($catalog.models | ForEach-Object { $_.key })
    foreach ($required in @("qwen3.5-4b", "qwen3.6-35b-a3b", $EmbeddingModel)) {
        Require ($keys -contains $required) "required model missing from llmster catalog: $required"
    }
    Write-Host "llmster/model catalog: PASS"

    Step "Download exact reviewed Windows tools"
    $Work = Join-Path $env:TEMP ("sovereign-twin-r11-" + [guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Path $Work -Force | Out-Null
    $Installer = Join-Path $Work "SovereignTwin-Install-Runtime.ps1"
    $Reembed = Join-Path $Work "SovereignTwin-Reembed-Memory.ps1"
    $Activate = Join-Path $Work "SovereignTwin-Activate-Memory.ps1"
    Download-Reviewed "scripts/windows/SovereignTwin-Install-Runtime.ps1" $Installer
    Download-Reviewed "scripts/windows/SovereignTwin-Reembed-Memory.ps1" $Reembed
    Download-Reviewed "scripts/windows/SovereignTwin-Activate-Memory.ps1" $Activate

    Step "Stop validated Twin listener before in-place Windows runtime upgrade"
    $TwinStoppedForUpgrade = [bool](Stop-KnownTwinListener)
    if ($TwinStoppedForUpgrade) { Write-Host "validated Twin listener stopped: PASS" }
    else { Write-Host "no active Twin listener: PASS" }

    Step "Upgrade runtime to exact reviewed source without auto-start"
    & $Installer -SourceSha $SourceSha -EmbeddingModel $EmbeddingModel -NoAutostart -NoStart
    if ($LASTEXITCODE -ne 0) { throw "runtime installer failed" }
    Require (Test-Path -LiteralPath $Twin) "Twin executable missing after runtime upgrade"

    $runtimeManifest = Get-Content -LiteralPath $RuntimeManifestPath -Raw | ConvertFrom-Json
    Require ([string]$runtimeManifest.source_sha -eq $SourceSha) "runtime source manifest did not bind exact SourceSha"
    Require ([string]$runtimeManifest.execution_authority -eq "NONE") "runtime manifest authority is not NONE"
    Require (-not [bool]$runtimeManifest.can_execute) "runtime manifest unexpectedly grants execution"
    Require ((Resolve-ExactPath ([string]$runtimeManifest.memory_db)) -eq $SourceDb) "upgraded runtime manifest changed source DB unexpectedly"
    Write-Host "runtime exact-source binding: PASS"

    Step "Read-only compatibility report on legacy source"
    $legacyCompatRaw = & $Twin --db $SourceDb --embedding-model $EmbeddingModel memory-compat
    $legacyCompatExit = $LASTEXITCODE
    $legacyCompat = ($legacyCompatRaw | Out-String) | ConvertFrom-Json
    Write-Host ($legacyCompat | ConvertTo-Json -Depth 8)
    Require ($legacyCompatExit -ne 0 -or -not [bool]$legacyCompat.ok) "legacy DB unexpectedly reported compatible; refusing unneeded migration"

    Step "Dry-run re-embedding plan"
    & $Reembed -SourceDb $SourceDb -TargetDb $TargetDb -EmbeddingModel $EmbeddingModel
    if ($LASTEXITCODE -ne 0) { throw "re-embedding dry-run failed" }
    Require (-not (Test-Path -LiteralPath $TargetDb)) "dry-run unexpectedly created target DB"

    Step "Commit re-embedding into fresh target only"
    & $Reembed -SourceDb $SourceDb -TargetDb $TargetDb -EmbeddingModel $EmbeddingModel -Commit
    if ($LASTEXITCODE -ne 0) { throw "re-embedding commit failed" }
    Require (Test-Path -LiteralPath $TargetDb) "migration did not create target DB"

    Step "Manifest-bound compatibility gate on target"
    $targetCompatRaw = & $Twin --db $TargetDb --embedding-model $EmbeddingModel memory-compat
    if ($LASTEXITCODE -ne 0) { throw "target memory-compat command failed: $targetCompatRaw" }
    $targetCompat = ($targetCompatRaw | Out-String) | ConvertFrom-Json
    Write-Host ($targetCompat | ConvertTo-Json -Depth 8)
    Require ([bool]$targetCompat.ok) "target compatibility not OK"
    Require ([string]$targetCompat.verdict -eq "COMPATIBLE_MANIFEST_BOUND") "target not manifest-bound compatible: $($targetCompat.verdict)"
    Require ([int]$targetCompat.selected_embedding_dimension -eq 768) "unexpected selected embedding dimension: $($targetCompat.selected_embedding_dimension)"

    Step "Activation dry-run"
    & $Activate -TargetDb $TargetDb -EmbeddingModel $EmbeddingModel
    if ($LASTEXITCODE -ne 0) { throw "activation dry-run failed" }

    Step "Atomic activation with rollback-on-failure"
    & $Activate -TargetDb $TargetDb -EmbeddingModel $EmbeddingModel -Commit
    if ($LASTEXITCODE -ne 0) { throw "activation failed" }
    $ActivationSucceeded = $true

    Step "Final active runtime verification"
    $health = Invoke-RestMethod -Uri "$UiUrl/health" -TimeoutSec 8
    Require ([bool]$health.ok) "Twin health is not OK after activation"
    $activeDb = [System.IO.Path]::GetFullPath([string]$health.memory_db)
    Require ($activeDb -eq $TargetDb) "Twin health reports wrong active DB: $activeDb"
    Require ([string]$health.execution_authority -eq "NONE") "health authority is not NONE"
    Require (-not [bool]$health.can_execute) "health unexpectedly grants execution"

    $doctorRaw = & $Twin --db $TargetDb --embedding-model $EmbeddingModel doctor
    if ($LASTEXITCODE -ne 0) { throw "doctor failed after activation" }
    $doctor = ($doctorRaw | Out-String) | ConvertFrom-Json
    Require ([bool]$doctor.ok) "doctor not OK after activation"
    Require ([System.IO.Path]::GetFullPath([string]$doctor.memory_db) -eq $TargetDb) "doctor reports wrong memory DB"

    $finalCompatRaw = & $Twin --db $TargetDb --embedding-model $EmbeddingModel memory-compat
    if ($LASTEXITCODE -ne 0) { throw "final memory-compat failed" }
    $finalCompat = ($finalCompatRaw | Out-String) | ConvertFrom-Json
    Require ([string]$finalCompat.verdict -eq "COMPATIBLE_MANIFEST_BOUND") "final compatibility verdict changed"

    if ($SmokeFast) {
        Step "Optional FAST product smoke"
        $smokeRaw = & $Twin --db $TargetDb --embedding-model $EmbeddingModel ask --mode fast "Return one concise memory-grounded observation and cite its mem:<id>. Do not execute anything."
        if ($LASTEXITCODE -ne 0) { throw "FAST smoke failed" }
        Write-Host ($smokeRaw | Out-String)
    }

    Step "Dogfood receipt"
    $receipt = [ordered]@{
        schema = "sovereign-twin.dogfood-r11/v1"
        ok = $true
        source_sha = $SourceSha
        source_db = $SourceDb
        active_db = $TargetDb
        embedding_model = $EmbeddingModel
        embedding_dimension = 768
        compatibility_verdict = [string]$finalCompat.verdict
        health = $health
        smoke_fast = [bool]$SmokeFast
        transcript = $Transcript
        completed_at_utc = [DateTime]::UtcNow.ToString("o")
        execution_authority = "NONE"
        can_execute = $false
    }
    $receiptPath = Join-Path $Receipts ("dogfood-r11-$sessionStamp.json")
    $receipt | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $receiptPath -Encoding UTF8
    $receipt.receipt = $receiptPath
    $receipt | ConvertTo-Json -Depth 10
} catch {
    $dogfoodError = $_.Exception.Message
    if ($TwinStoppedForUpgrade -and -not $ActivationSucceeded) {
        try {
            Restore-SourceTwin $SourceDb
            Write-Host "Previous Twin source DB restored after pre-activation failure: PASS" -ForegroundColor Yellow
        } catch {
            throw "dogfood failed ($dogfoodError) AND previous Twin recovery failed: $($_.Exception.Message)"
        }
    }
    throw $dogfoodError
} finally {
    if ($Work -and (Test-Path -LiteralPath $Work)) {
        Remove-Item -LiteralPath $Work -Recurse -Force -ErrorAction SilentlyContinue
    }
    Stop-Transcript | Out-Null
}
