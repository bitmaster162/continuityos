param(
    [Parameter(Mandatory=$true)][string]$TargetDb,
    [string]$EmbeddingModel = "text-embedding-nomic-embed-text-v1.5",
    [switch]$Commit
)

$ErrorActionPreference = "Stop"
$Root = Join-Path $env:LOCALAPPDATA "SovereignTwin"
$Twin = Join-Path $Root "runtime-venv\Scripts\sovereign-twin.exe"
$Launcher = Join-Path $Root "start-sovereign-twin.ps1"
$RuntimeManifest = Join-Path $Root "runtime-source.json"
$TaskName = "SovereignTwin-UI"
$UiUrl = "http://127.0.0.1:8765"
$AdmissionQueue = Join-Path $HOME ".continuityos\twin-admissions.jsonl"
$Receipts = Join-Path $Root "receipts"

function Resolve-ExactPath([string]$PathValue) {
    return [System.IO.Path]::GetFullPath((Resolve-Path -LiteralPath $PathValue).Path)
}

function Stop-KnownTwinListener {
    $listener = Get-NetTCPConnection -LocalPort 8765 -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $listener) { return }
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
        if (-not $still) { return }
    }
    throw "Twin listener did not stop on port 8765"
}

if (-not (Test-Path -LiteralPath $Twin)) { throw "sovereign-twin runtime missing: $Twin" }
if (-not (Test-Path -LiteralPath $Launcher)) { throw "Twin launcher missing: $Launcher" }
if (-not (Test-Path -LiteralPath $RuntimeManifest)) { throw "runtime source manifest missing: $RuntimeManifest" }
if (-not (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue)) {
    throw "$TaskName scheduled task missing"
}
if (-not (Test-Path -LiteralPath $TargetDb)) { throw "target memory DB missing: $TargetDb" }

$TargetDb = Resolve-ExactPath $TargetDb
$targetItem = Get-Item -LiteralPath $TargetDb
$targetManifestPath = Join-Path $targetItem.DirectoryName ($targetItem.BaseName + ".manifest.json")
if (-not (Test-Path -LiteralPath $targetManifestPath)) {
    throw "target-specific memory manifest missing: $targetManifestPath"
}
$targetManifest = Get-Content -LiteralPath $targetManifestPath -Raw | ConvertFrom-Json
$manifestDb = Resolve-ExactPath ([string]$targetManifest.db)
if ($manifestDb -ne $TargetDb) { throw "target manifest DB binding mismatch" }
if ([string]$targetManifest.embedding_model -ne $EmbeddingModel) {
    throw "target manifest embedding model mismatch"
}
if ([int]$targetManifest.embedding_dimension -le 0) { throw "target manifest embedding dimension invalid" }
if ([string]$targetManifest.execution_authority -ne "NONE" -or [bool]$targetManifest.can_execute) {
    throw "target manifest violates no-execution authority"
}

$compatRaw = & $Twin --db $TargetDb --embedding-model $EmbeddingModel memory-compat
if ($LASTEXITCODE -ne 0) { throw "target memory-compat command failed: $compatRaw" }
$compat = ($compatRaw | Out-String) | ConvertFrom-Json
if (-not [bool]$compat.ok -or [string]$compat.verdict -ne "COMPATIBLE_MANIFEST_BOUND") {
    throw "target memory is not manifest-bound compatible: $($compat.verdict)"
}

$runtime = Get-Content -LiteralPath $RuntimeManifest -Raw | ConvertFrom-Json
$currentDbRaw = [string]$runtime.memory_db
if (-not $currentDbRaw) { throw "runtime manifest has no memory_db" }
$currentDb = Resolve-ExactPath $currentDbRaw
if ([string]$runtime.execution_authority -ne "NONE" -or [bool]$runtime.can_execute) {
    throw "runtime manifest violates no-execution authority"
}

$plan = [ordered]@{
    schema = "sovereign-twin.memory-activation-plan/v1"
    commit = [bool]$Commit
    current_db = $currentDb
    target_db = $TargetDb
    target_manifest = $targetManifestPath
    target_embedding_model = [string]$targetManifest.embedding_model
    target_embedding_dimension = [int]$targetManifest.embedding_dimension
    compatibility_verdict = [string]$compat.verdict
    execution_authority = "NONE"
    can_execute = $false
}

if (-not $Commit) {
    $plan | ConvertTo-Json -Depth 8
    exit 0
}
if ($currentDb -eq $TargetDb) { throw "target DB is already active" }

New-Item -ItemType Directory -Path $Receipts -Force | Out-Null
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$launcherBackup = Join-Path $Root ("start-sovereign-twin.pre-memory-activation-$stamp.ps1")
$manifestBackup = Join-Path $Root ("runtime-source.pre-memory-activation-$stamp.json")
Copy-Item -LiteralPath $Launcher -Destination $launcherBackup -ErrorAction Stop
Copy-Item -LiteralPath $RuntimeManifest -Destination $manifestBackup -ErrorAction Stop

$escapedTwin = $Twin.Replace("'", "''")
$escapedDb = $TargetDb.Replace("'", "''")
$escapedQueue = $AdmissionQueue.Replace("'", "''")
$escapedEmbedding = $EmbeddingModel.Replace("'", "''")
$newLauncher = @"
`$ErrorActionPreference = "SilentlyContinue"
Start-Sleep -Seconds 8
try {
    `$h = Invoke-RestMethod -Uri "$UiUrl/health" -TimeoutSec 2
    if (`$h.ok -and [System.IO.Path]::GetFullPath([string]`$h.memory_db) -eq [System.IO.Path]::GetFullPath('$escapedDb')) { exit 0 }
} catch {}
& '$escapedTwin' --db '$escapedDb' --admission-queue '$escapedQueue' --embedding-model '$escapedEmbedding' serve --host 127.0.0.1 --port 8765
"@

$runtime.memory_db = $TargetDb
$runtime | Add-Member -NotePropertyName memory_activated_at_utc -NotePropertyValue ([DateTime]::UtcNow.ToString("o")) -Force
$runtime | Add-Member -NotePropertyName memory_manifest -NotePropertyValue $targetManifestPath -Force
$runtime | Add-Member -NotePropertyName memory_embedding_dimension -NotePropertyValue ([int]$targetManifest.embedding_dimension) -Force

$tmpLauncher = "$Launcher.tmp-$stamp"
$tmpManifest = "$RuntimeManifest.tmp-$stamp"
$newLauncher | Set-Content -LiteralPath $tmpLauncher -Encoding UTF8
$runtime | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $tmpManifest -Encoding UTF8

try {
    Stop-KnownTwinListener
    Move-Item -LiteralPath $tmpLauncher -Destination $Launcher -Force
    Move-Item -LiteralPath $tmpManifest -Destination $RuntimeManifest -Force
    Start-ScheduledTask -TaskName $TaskName

    $healthy = $false
    $health = $null
    for ($i = 0; $i -lt 45; $i++) {
        Start-Sleep -Seconds 1
        try {
            $health = Invoke-RestMethod -Uri "$UiUrl/health" -TimeoutSec 2
            if ($health.ok -and (Resolve-ExactPath ([string]$health.memory_db)) -eq $TargetDb) {
                $healthy = $true
                break
            }
        } catch {}
    }
    if (-not $healthy) { throw "activated Twin did not report target memory DB on /health" }

    $postCompatRaw = & $Twin --db $TargetDb --embedding-model $EmbeddingModel memory-compat
    if ($LASTEXITCODE -ne 0) { throw "post-activation memory-compat failed: $postCompatRaw" }
    $postCompat = ($postCompatRaw | Out-String) | ConvertFrom-Json
    if (-not [bool]$postCompat.ok -or [string]$postCompat.verdict -ne "COMPATIBLE_MANIFEST_BOUND") {
        throw "post-activation memory compatibility failed: $($postCompat.verdict)"
    }

    $receipt = [ordered]@{
        schema = "sovereign-twin.memory-activation-receipt/v1"
        ok = $true
        activated_at_utc = [DateTime]::UtcNow.ToString("o")
        previous_db = $currentDb
        active_db = $TargetDb
        active_memory_manifest = $targetManifestPath
        embedding_model = $EmbeddingModel
        embedding_dimension = [int]$targetManifest.embedding_dimension
        compatibility_verdict = [string]$postCompat.verdict
        launcher_backup = $launcherBackup
        runtime_manifest_backup = $manifestBackup
        execution_authority = "NONE"
        can_execute = $false
    }
    $receiptPath = Join-Path $Receipts ("memory-activation-$stamp.json")
    $receipt | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $receiptPath -Encoding UTF8
    $receipt.receipt = $receiptPath
    $receipt | ConvertTo-Json -Depth 8
} catch {
    $activationError = $_.Exception.Message
    try { Stop-KnownTwinListener } catch {}
    Copy-Item -LiteralPath $launcherBackup -Destination $Launcher -Force
    Copy-Item -LiteralPath $manifestBackup -Destination $RuntimeManifest -Force
    Start-ScheduledTask -TaskName $TaskName

    $rollbackOk = $false
    for ($i = 0; $i -lt 45; $i++) {
        Start-Sleep -Seconds 1
        try {
            $h = Invoke-RestMethod -Uri "$UiUrl/health" -TimeoutSec 2
            if ($h.ok -and (Resolve-ExactPath ([string]$h.memory_db)) -eq $currentDb) {
                $rollbackOk = $true
                break
            }
        } catch {}
    }
    if (-not $rollbackOk) {
        throw "memory activation failed ($activationError) AND rollback health verification failed"
    }
    throw "memory activation failed and was rolled back: $activationError"
}
