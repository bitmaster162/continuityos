param(
    [string]$TargetSha = "41fbbbddfdd36865ad9d661f11fc19d5babf5459"
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
$ExpectedPrior = "b781108be9c8c7be3d1c7169642b9ef0d657289c"

function Step([string]$Text) {
    Write-Host "`n=== $Text ===" -ForegroundColor Cyan
}

function Require([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}

function FullPath([string]$PathValue) {
    return [IO.Path]::GetFullPath($PathValue)
}

function Health {
    return Invoke-RestMethod "$UiUrl/health" -TimeoutSec 5
}

function Assert-Health($Value, [string]$Stage, [string]$ExpectedDb) {
    Require ([bool]$Value.ok) "health not OK at $Stage"
    Require ([string]$Value.mode -eq "LOCAL_SHADOW") "mode changed at ${Stage}: $($Value.mode)"
    Require ([string]$Value.execution_authority -eq "NONE") "authority changed at $Stage"
    Require (-not [bool]$Value.can_execute) "can_execute changed at $Stage"
    Require ((FullPath ([string]$Value.memory_db)) -eq (FullPath $ExpectedDb)) "memory DB changed at $Stage"
}

function Assert-LmsEmpty([string]$Stage) {
    $raw = (& lms ps --json 2>&1 | Out-String).Trim()
    Require ($LASTEXITCODE -eq 0) "lms ps failed at ${Stage}: $raw"
    $compact = $raw -replace '\s',''
    Require ($compact -eq '[]') "LM Studio residency not empty at ${Stage}: $raw"
    Write-Host "LMS_$Stage=EMPTY"
}

function Start-And-VerifyTwin([string]$ExpectedDb) {
    Start-Process powershell.exe `
        -WindowStyle Hidden `
        -ArgumentList "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$Launcher`"" |
        Out-Null

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

function Ensure-TwinRunning([string]$ExpectedDb) {
    try {
        $candidate = Health
        Assert-Health $candidate "ENSURE" $ExpectedDb
        return $candidate
    } catch {
        Write-Host "Twin not healthy; attempting launcher recovery" -ForegroundColor Yellow
        return Start-And-VerifyTwin $ExpectedDb
    }
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

function Build-Wheel([string]$Sha, [string]$Work, [string]$Label) {
    Require ($Sha -match '^[0-9a-f]{40}$') "$Label SHA is not exact"

    $zip = Join-Path $Work "$Label.zip"
    $unpack = Join-Path $Work $Label
    $wheelDir = Join-Path $Work "$Label-wheel"
    New-Item -ItemType Directory -Path $unpack,$wheelDir -Force | Out-Null

    Invoke-WebRequest `
        -Uri "https://github.com/$Repo/archive/$Sha.zip" `
        -OutFile $zip `
        -UseBasicParsing
    Expand-Archive -Path $zip -DestinationPath $unpack -Force

    $src = Get-ChildItem $unpack -Directory |
        Where-Object { $_.Name -like 'continuityos-*' } |
        Select-Object -First 1
    Require ($null -ne $src) "$Label source not found"

    $buildOutput = & $Py -m pip wheel `
        --disable-pip-version-check `
        --no-deps `
        --wheel-dir $wheelDir `
        $src.FullName 2>&1
    $buildExitCode = $LASTEXITCODE
    $buildOutput | ForEach-Object { Write-Host ([string]$_) }
    Require ($buildExitCode -eq 0) "$Label wheel build failed"

    $wheels = @(Get-ChildItem $wheelDir -Filter 'continuityos-*.whl')
    Require ($wheels.Count -eq 1) "$Label wheel count is $($wheels.Count), expected 1"
    $wheelPath = [string]$wheels[0].FullName
    Require (Test-Path -LiteralPath $wheelPath) "$Label wheel missing: $wheelPath"
    return [string]$wheelPath
}

function Install-Wheel([string]$Wheel) {
    Require (Test-Path -LiteralPath $Wheel) "wheel path does not exist: $Wheel"
    $installOutput = & $Py -m pip install `
        --disable-pip-version-check `
        --no-deps `
        --upgrade `
        --force-reinstall `
        $Wheel 2>&1
    $installExitCode = $LASTEXITCODE
    $installOutput | ForEach-Object { Write-Host ([string]$_) }
    Require ($installExitCode -eq 0) "pip install failed: $Wheel"
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
$transcript = Join-Path $Receipts "dogfood-r14-ui-$stamp.log"
$work = Join-Path $env:TEMP ("sovereign-twin-r14-ui-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $work -Force | Out-Null
Start-Transcript -Path $transcript -Force | Out-Null

$oldSha = $null
$activeDb = $null
$targetWheel = $null
$rollbackWheel = $null
$targetInstallAttempted = $false
$failed = $false

try {
    Step 'Preflight live R13P1 runtime and authority'

    $manifest = Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json
    $activeDb = [string]$manifest.memory_db
    Require ($activeDb -like '*memory-nomic-768-*.db') "manifest DB is not Nomic-768: $activeDb"

    $pre = Ensure-TwinRunning $activeDb
    Assert-Health $pre 'PRE' $activeDb
    Require ((FullPath ([string]$manifest.memory_db)) -eq (FullPath ([string]$pre.memory_db))) 'manifest DB differs from live DB'

    $oldSha = [string]$manifest.source_sha
    Require (($oldSha -eq $ExpectedPrior) -or ($oldSha -eq $TargetSha)) "unexpected installed source SHA: $oldSha"

    Write-Host "ACTIVE_DB=$activeDb"
    Write-Host "OLD_SOURCE_SHA=$oldSha"
    Assert-LmsEmpty 'PRE'

    if ($oldSha -ne $TargetSha) {
        Step 'Prebuild exact R14 target and rollback wheels'
        $targetWheel = Build-Wheel $TargetSha $work 'target'
        $rollbackWheel = Build-Wheel $oldSha $work 'rollback'
        Write-Host "TARGET_WHEEL=$targetWheel"
        Write-Host "ROLLBACK_WHEEL=$rollbackWheel"

        Require (Test-Path -LiteralPath $targetWheel) 'target wheel scalar path validation failed'
        Require (Test-Path -LiteralPath $rollbackWheel) 'rollback wheel scalar path validation failed'

        Step 'Stop validated Twin and install exact green R14 candidate'
        Stop-ValidatedTwin $activeDb
        $targetInstallAttempted = $true
        Install-Wheel $targetWheel
        Write-ManifestSource $TargetSha $activeDb
        [void](Start-And-VerifyTwin $activeDb)
    } else {
        Write-Host 'TARGET_ALREADY_INSTALLED=true'
    }

    Step 'Verify R14 source receipt and local UI contract'
    $postManifest = Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json
    Require ([string]$postManifest.source_sha -eq $TargetSha) 'manifest source SHA is not R14 target'
    Require ((FullPath ([string]$postManifest.memory_db)) -eq (FullPath $activeDb)) 'post-install manifest DB pointer changed'

    $ui = Invoke-WebRequest "$UiUrl/" -UseBasicParsing -TimeoutSec 10
    Require ([int]$ui.StatusCode -eq 200) 'Twin UI did not return HTTP 200'
    $html = [string]$ui.Content
    Require ($html.Contains('DEEP-LITE')) 'UI missing DEEP-LITE button label'
    Require ($html.Contains('/ask/deep-lite')) 'UI missing dedicated /ask/deep-lite endpoint'
    Require ($html.Contains("ask('fast')")) 'UI lost FAST control'
    Require ($html.Contains("ask('deep')")) 'UI lost DEEP control'
    Write-Host 'R14_UI_CONTRACT=PASS'

    Assert-LmsEmpty 'PRE_API_DOGFOOD'

    Step 'Run real R14 DEEP-LITE through loopback HTTP API'
    $query = 'Using only retrieved ContinuityOS memory, identify one important architectural principle of the system. State the memory-backed fact, then a brief inference about why it matters. Cite only supporting mem:<id> references. Do not execute anything.'
    $body = @{ query = $query } | ConvertTo-Json -Compress

    $sw = [Diagnostics.Stopwatch]::StartNew()
    $result = Invoke-RestMethod `
        "$UiUrl/ask/deep-lite" `
        -Method Post `
        -ContentType 'application/json; charset=utf-8' `
        -Body $body `
        -TimeoutSec 180
    $sw.Stop()

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
    foreach ($e in @($result.evidence)) {
        $allowed[[string][int]$e.id] = $true
    }

    $matches = [regex]::Matches([string]$result.text, '\bmem:(\d+)\b')
    Require ($matches.Count -gt 0) 'final answer has no mem:<id> citation'
    foreach ($match in $matches) {
        $id = [string][int]$match.Groups[1].Value
        Require ($allowed.ContainsKey($id)) "final answer cites mem:$id outside retrieved evidence"
    }

    Start-Sleep -Seconds 3
    Assert-LmsEmpty 'POST_API_DOGFOOD'

    $finalHealth = Health
    Assert-Health $finalHealth 'FINAL' $activeDb

    $receipt = [ordered]@{
        schema = 'sovereign-twin.dogfood-r14-ui/v1'
        ok = $true
        source_sha = $TargetSha
        prior_source_sha = $oldSha
        endpoint = '/ask/deep-lite'
        active_db = $activeDb
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

    $receiptPath = Join-Path $Receipts "dogfood-r14-ui-$stamp.json"
    $receipt | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $receiptPath -Encoding UTF8

    Step 'PASS'
    Write-Host 'R14_UI_DOGFOOD=PASS' -ForegroundColor Green
    Write-Host "SOURCE_SHA=$TargetSha"
    Write-Host 'ENDPOINT=/ask/deep-lite'
    Write-Host "MODE=$($result.mode)"
    Write-Host "PASS_COUNT=$($result.stats.pass_count)"
    Write-Host "REASONING_PRESENT=$($result.reasoning_present)"
    if ($result.stats.PSObject.Properties.Name -contains 'reasoning_output_tokens') {
        Write-Host "REASONING_OUTPUT_TOKENS=$($result.stats.reasoning_output_tokens)"
    }
    Write-Host "EXECUTION_AUTHORITY=$($result.execution_authority)"
    Write-Host "CAN_EXECUTE=$($result.can_execute)"
    Write-Host "RECEIPT=$receiptPath"
    Write-Host 'FINAL_TEXT:'
    Write-Host ([string]$result.text)
}
catch {
    $failed = $true
    $primary = $_.Exception.Message
    Write-Host "`nR14_UI_DOGFOOD=FAIL" -ForegroundColor Red
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
    } elseif ($activeDb -and -not (Get-NetTCPConnection -LocalPort 8765 -State Listen -ErrorAction SilentlyContinue)) {
        try {
            [void](Start-And-VerifyTwin $activeDb)
            Write-Host 'TWIN_RESTART=PASS' -ForegroundColor Yellow
        } catch {
            Write-Host "TWIN_RESTART=FAIL $($_.Exception.Message)" -ForegroundColor Red
        }
    }

    try {
        $lmsNow = (& lms ps --json 2>&1 | Out-String).Trim()
        Write-Host "LMS_PS_NOW=$lmsNow"
    } catch {}

    try {
        $healthNow = Health
        Write-Host ("FINAL_HEALTH=" + ($healthNow | ConvertTo-Json -Compress -Depth 5))
    } catch {
        Write-Host 'FINAL_HEALTH=UNAVAILABLE'
    }
}
finally {
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
    try { Stop-Transcript | Out-Null } catch {}
}

if ($failed) { exit 2 }
exit 0
