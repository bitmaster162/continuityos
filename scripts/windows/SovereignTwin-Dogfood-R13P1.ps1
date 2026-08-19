param(
    [string]$TargetSha = "b781108be9c8c7be3d1c7169642b9ef0d657289c",
    [string]$EmbeddingModel = "text-embedding-nomic-embed-text-v1.5"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$Repo = "bitmaster162/continuityos"
$Root = Join-Path $env:LOCALAPPDATA "SovereignTwin"
$Py = Join-Path $Root "runtime-venv\Scripts\python.exe"
$ManifestPath = Join-Path $Root "runtime-source.json"
$Launcher = Join-Path $Root "start-sovereign-twin.ps1"
$Receipts = Join-Path $Root "receipts"
$UiUrl = "http://127.0.0.1:8765"
$ExpectedR13P = "edacb54409ebcf355f7a57b3e34190c79dd6c7cd"

function Step([string]$Text) { Write-Host "`n=== $Text ===" -ForegroundColor Cyan }
function Require([bool]$Condition, [string]$Message) { if (-not $Condition) { throw $Message } }
function FullPath([string]$PathValue) { return [IO.Path]::GetFullPath($PathValue) }
function Health { return Invoke-RestMethod "$UiUrl/health" -TimeoutSec 5 }
function Assert-Health($Value, [string]$Stage, [string]$ExpectedDb) {
    Require ([bool]$Value.ok) "health not OK at $Stage"
    Require ([string]$Value.mode -eq "LOCAL_SHADOW") "mode changed at $Stage: $($Value.mode)"
    Require ([string]$Value.execution_authority -eq "NONE") "authority changed at $Stage"
    Require (-not [bool]$Value.can_execute) "can_execute changed at $Stage"
    Require ((FullPath ([string]$Value.memory_db)) -eq (FullPath $ExpectedDb)) "memory DB changed at $Stage"
}
function Assert-LmsEmpty([string]$Stage) {
    $raw = (& lms ps --json 2>&1 | Out-String).Trim()
    Require ($LASTEXITCODE -eq 0) "lms ps failed at $Stage: $raw"
    $compact = $raw -replace '\s',''
    Require ($compact -eq '[]') "LM Studio residency not empty at $Stage: $raw"
    Write-Host "LMS_$Stage=EMPTY"
}
function Stop-ValidatedTwin([string]$ExpectedDb) {
    $listeners = @(Get-NetTCPConnection -LocalPort 8765 -State Listen -ErrorAction Stop)
    $pids = @($listeners | Select-Object -ExpandProperty OwningProcess -Unique)
    Require ($pids.Count -eq 1) "expected exactly one :8765 listener; found $($pids.Count)"
    $pidValue = [int]$pids[0]
    $proc = Get-CimInstance Win32_Process -Filter "ProcessId=$pidValue"
    Require ($null -ne $proc) "cannot resolve :8765 owner"
    $cmd = [string]$proc.CommandLine
    Require ($cmd -like '*SovereignTwin*') "unexpected :8765 process"
    Require ($cmd -like '*sovereign-twin*') "unexpected :8765 process"
    Require ($cmd -like '*serve*') "unexpected :8765 process"
    Require ($cmd.Contains($ExpectedDb)) "listener is not bound to expected active DB"
    Stop-Process -Id $pidValue -Force
    Start-Sleep -Seconds 2
    Require (-not (Get-NetTCPConnection -LocalPort 8765 -State Listen -ErrorAction SilentlyContinue)) "Twin listener did not stop"
}
function Start-And-VerifyTwin([string]$ExpectedDb) {
    Start-Process powershell.exe -WindowStyle Hidden -ArgumentList "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$Launcher`"" | Out-Null
    for ($i = 0; $i -lt 30; $i++) {
        Start-Sleep -Seconds 1
        try {
            $candidate = Health
            Assert-Health $candidate "START" $ExpectedDb
            return $candidate
        } catch {}
    }
    throw "Twin did not return healthy on expected DB"
}
function Build-Wheel([string]$Sha, [string]$Work, [string]$Label) {
    Require ($Sha -match '^[0-9a-f]{40}$') "$Label SHA is not exact"
    $zip = Join-Path $Work "$Label.zip"
    $unpack = Join-Path $Work $Label
    $wheelDir = Join-Path $Work "$Label-wheel"
    New-Item -ItemType Directory -Path $unpack,$wheelDir -Force | Out-Null
    Invoke-WebRequest -Uri "https://github.com/$Repo/archive/$Sha.zip" -OutFile $zip -UseBasicParsing
    Expand-Archive -Path $zip -DestinationPath $unpack -Force
    $src = Get-ChildItem $unpack -Directory | Where-Object { $_.Name -like 'continuityos-*' } | Select-Object -First 1
    Require ($null -ne $src) "$Label source not found"
    & $Py -m pip wheel --disable-pip-version-check --no-deps --wheel-dir $wheelDir $src.FullName
    Require ($LASTEXITCODE -eq 0) "$Label wheel build failed"
    $wheel = Get-ChildItem $wheelDir -Filter 'continuityos-*.whl' | Select-Object -First 1
    Require ($null -ne $wheel) "$Label wheel missing"
    return $wheel.FullName
}
function Install-Wheel([string]$Wheel) {
    & $Py -m pip install --disable-pip-version-check --no-deps --upgrade --force-reinstall $Wheel
    Require ($LASTEXITCODE -eq 0) "pip install failed: $Wheel"
}
function Write-ManifestSource([string]$Sha, [string]$ExpectedDb) {
    $m = Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json
    Require ((FullPath ([string]$m.memory_db)) -eq (FullPath $ExpectedDb)) "manifest DB pointer changed"
    $m.source_sha = $Sha
    $m.installed_at_utc = [DateTime]::UtcNow.ToString('o')
    $tmp = "$ManifestPath.tmp.$([guid]::NewGuid().ToString('N'))"
    $m | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $tmp -Encoding UTF8
    Move-Item -LiteralPath $tmp -Destination $ManifestPath -Force
}

Require (Test-Path -LiteralPath $Py) "runtime Python missing: $Py"
Require (Test-Path -LiteralPath $ManifestPath) "runtime manifest missing: $ManifestPath"
Require (Test-Path -LiteralPath $Launcher) "Twin launcher missing: $Launcher"
Require ($TargetSha -match '^[0-9a-f]{40}$') "TargetSha must be exact 40-char lowercase SHA"
New-Item -ItemType Directory -Path $Receipts -Force | Out-Null

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$transcript = Join-Path $Receipts "dogfood-r13p1-$stamp.log"
$work = Join-Path $env:TEMP ("sovereign-twin-r13p1-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $work -Force | Out-Null
Start-Transcript -Path $transcript -Force | Out-Null

$oldSha = $null
$activeDb = $null
$targetWheel = $null
$rollbackWheel = $null
$stopped = $false
$targetInstallAttempted = $false

try {
    Step 'Preflight live runtime and authority'
    $pre = Health
    Require ([bool]$pre.ok) 'Twin health is not OK'
    $activeDb = [string]$pre.memory_db
    Require ($activeDb -like '*memory-nomic-768-*.db') "active DB is not Nomic-768: $activeDb"
    Assert-Health $pre 'PRE' $activeDb

    $manifest = Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json
    Require ((FullPath ([string]$manifest.memory_db)) -eq (FullPath $activeDb)) 'manifest DB differs from live DB'
    $oldSha = [string]$manifest.source_sha
    Require (($oldSha -eq $ExpectedR13P) -or ($oldSha -eq $TargetSha)) "unexpected installed source SHA: $oldSha"
    Write-Host "ACTIVE_DB=$activeDb"
    Write-Host "OLD_SOURCE_SHA=$oldSha"
    Assert-LmsEmpty 'PRE'

    if ($oldSha -ne $TargetSha) {
        Step 'Prebuild target and rollback wheels before stopping Twin'
        $targetWheel = Build-Wheel $TargetSha $work 'target'
        $rollbackWheel = Build-Wheel $oldSha $work 'rollback'

        Step 'Stop validated Twin and install exact green candidate'
        Stop-ValidatedTwin $activeDb
        $stopped = $true
        $targetInstallAttempted = $true
        Install-Wheel $targetWheel
        Write-ManifestSource $TargetSha $activeDb
        [void](Start-And-VerifyTwin $activeDb)
        $stopped = $false
    } else {
        Write-Host 'TARGET_ALREADY_INSTALLED=true'
    }

    Step 'Verify Windows-safe JSON emitter without model call'
    $unicodeRaw = (& $Py -c "from continuityos.sovereign_twin_deep_lite import _emit; _emit({'text':'архитектура — память'})" | Out-String).Trim()
    Require ($LASTEXITCODE -eq 0) 'Unicode emitter smoke failed'
    Require ($unicodeRaw -notmatch '[^\x00-\x7F]') 'emitter output is not ASCII-only'
    $unicodeParsed = $unicodeRaw | ConvertFrom-Json
    Require ([string]$unicodeParsed.text -eq 'архитектура — память') 'Unicode round-trip failed'
    Require ($unicodeRaw -match '\\u[0-9a-fA-F]{4}') 'Unicode was not escaped in CLI JSON'
    Write-Host 'WINDOWS_UNICODE_EMITTER=PASS'

    Assert-LmsEmpty 'PRE_DOGFOOD'

    Step 'Run real R13P1 DEEP-LITE dogfood'
    $query = 'Using only retrieved ContinuityOS memory, identify one important architectural principle of the system. State the memory-backed fact, then a brief inference about why it matters. Cite only supporting mem:<id> references. Do not execute anything.'
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $raw = (& $Py -m continuityos.sovereign_twin_deep_lite $query --db $activeDb --embedding-model $EmbeddingModel --model 'qwen3.5-4b' | Out-String).Trim()
    $exitCode = $LASTEXITCODE
    $sw.Stop()
    Require ($exitCode -eq 0) "DEEP-LITE exited $exitCode: $raw"
    $result = $raw | ConvertFrom-Json

    Require ([string]$result.mode -eq 'deep-lite') 'mode != deep-lite'
    Require ([string]$result.model -eq 'qwen3.5-4b') 'model mismatch'
    Require (-not [bool]$result.reasoning_present) 'reasoning_present is true'
    Require ([string]$result.stats.strategy -eq 'bounded_two_pass_reasoning_off') 'strategy mismatch'
    Require ([int]$result.stats.pass_count -eq 2) 'pass_count != 2'
    Require ([int]$result.stats.draft_max_output_tokens -eq 400) 'draft token budget mismatch'
    Require ([int]$result.stats.final_max_output_tokens -eq 700) 'final token budget mismatch'
    if ($result.stats.PSObject.Properties.Name -contains 'reasoning_output_tokens') {
        Require ([int]$result.stats.reasoning_output_tokens -eq 0) 'reasoning_output_tokens != 0'
    }
    Require ([string]$result.execution_authority -eq 'NONE') 'execution authority changed'
    Require (-not [bool]$result.can_execute) 'can_execute changed'

    $allowed = @{}
    foreach ($e in @($result.evidence)) { $allowed[[string][int]$e.id] = $true }
    $matches = [regex]::Matches([string]$result.text, '\bmem:(\d+)\b')
    Require ($matches.Count -gt 0) 'final answer has no mem:<id> citation'
    foreach ($match in $matches) {
        $id = [string][int]$match.Groups[1].Value
        Require ($allowed.ContainsKey($id)) "final answer cites mem:$id outside retrieved evidence"
    }

    Start-Sleep -Seconds 3
    Assert-LmsEmpty 'POST_DOGFOOD'
    $finalHealth = Health
    Assert-Health $finalHealth 'FINAL' $activeDb

    $receipt = [ordered]@{
        schema = 'sovereign-twin.dogfood-r13p1/v1'
        ok = $true
        source_sha = $TargetSha
        active_db = $activeDb
        embedding_model = $EmbeddingModel
        external_wall_seconds = [math]::Round($sw.Elapsed.TotalSeconds, 2)
        result = $result
        final_health = $finalHealth
        execution_authority = 'NONE'
        can_execute = $false
        can_trade = $false
        capital_permission = 'DENY'
        transcript = $transcript
        completed_at_utc = [DateTime]::UtcNow.ToString('o')
    }
    $receiptPath = Join-Path $Receipts "dogfood-r13p1-$stamp.json"
    $receipt | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $receiptPath -Encoding UTF8

    Step 'PASS'
    Write-Host 'R13P1_DOGFOOD=PASS' -ForegroundColor Green
    Write-Host "SOURCE_SHA=$TargetSha"
    Write-Host "MODE=$($result.mode)"
    Write-Host "PASS_COUNT=$($result.stats.pass_count)"
    Write-Host "REASONING_PRESENT=$($result.reasoning_present)"
    if ($result.stats.PSObject.Properties.Name -contains 'reasoning_output_tokens') { Write-Host "REASONING_OUTPUT_TOKENS=$($result.stats.reasoning_output_tokens)" }
    Write-Host "EXECUTION_AUTHORITY=$($result.execution_authority)"
    Write-Host "CAN_EXECUTE=$($result.can_execute)"
    Write-Host "RECEIPT=$receiptPath"
    Write-Host 'FINAL_TEXT:'
    Write-Host ([string]$result.text)
}
catch {
    $primary = $_.Exception.Message
    Write-Host "`nR13P1_DOGFOOD=FAIL" -ForegroundColor Red
    Write-Host "ERROR=$primary"

    if ($targetInstallAttempted -and $rollbackWheel -and $oldSha -and $activeDb) {
        try {
            if (Get-NetTCPConnection -LocalPort 8765 -State Listen -ErrorAction SilentlyContinue) {
                Stop-ValidatedTwin $activeDb
            }
            Install-Wheel $rollbackWheel
            Write-ManifestSource $oldSha $activeDb
            [void](Start-And-VerifyTwin $activeDb)
            Write-Host "ROLLBACK=PASS source_sha=$oldSha" -ForegroundColor Yellow
        } catch {
            Write-Host "ROLLBACK=FAIL $($_.Exception.Message)" -ForegroundColor Red
        }
    } elseif ($stopped -and $activeDb) {
        try {
            [void](Start-And-VerifyTwin $activeDb)
            Write-Host 'TWIN_RESTART=PASS' -ForegroundColor Yellow
        } catch {
            Write-Host "TWIN_RESTART=FAIL $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    exit 2
}
finally {
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
    try { Stop-Transcript | Out-Null } catch {}
}
