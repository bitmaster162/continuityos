$ErrorActionPreference = "Stop"
$Root = Join-Path $env:LOCALAPPDATA "SovereignTwin"
$Manifest = Join-Path $Root "runtime-source.json"
$Ui = "http://127.0.0.1:8765"
$TaskName = "SovereignTwin-UI"

function Require([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}

Require (Test-Path -LiteralPath $Manifest) "runtime-source.json is missing; install Sovereign Twin runtime first"
$runtime = Get-Content -LiteralPath $Manifest -Raw | ConvertFrom-Json
Require ([string]$runtime.execution_authority -eq "NONE") "runtime manifest authority mismatch"
Require (-not [bool]$runtime.can_execute) "runtime manifest unexpectedly grants execution"
Require (-not [string]::IsNullOrWhiteSpace([string]$runtime.memory_db)) "runtime manifest memory_db missing"
$ExpectedMemoryDb = [System.IO.Path]::GetFullPath([string]$runtime.memory_db)
Require (Test-Path -LiteralPath $ExpectedMemoryDb) "runtime manifest memory_db does not exist: $ExpectedMemoryDb"

function Test-ExpectedHealth([object]$Health) {
    if ($null -eq $Health -or -not [bool]$Health.ok) { return $false }
    if ([string]$Health.execution_authority -ne "NONE" -or [bool]$Health.can_execute) { return $false }
    if ([string]::IsNullOrWhiteSpace([string]$Health.memory_db)) { return $false }
    try {
        $active = [System.IO.Path]::GetFullPath([string]$Health.memory_db)
    } catch {
        return $false
    }
    return [System.StringComparer]::OrdinalIgnoreCase.Equals($active, $ExpectedMemoryDb)
}

$reachable = $false
$health = $null
try {
    $health = Invoke-RestMethod -Uri "$Ui/health" -TimeoutSec 3
    $reachable = $true
} catch {}

if ($reachable) {
    if (-not (Test-ExpectedHealth $health)) {
        throw "refusing to open UI: live health does not match runtime manifest"
    }
} else {
    $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if (-not $task) { throw "$TaskName is not installed" }
    Start-ScheduledTask -TaskName $TaskName
    $ok = $false
    for ($i = 0; $i -lt 30; $i++) {
        Start-Sleep -Seconds 1
        $candidate = $null
        try {
            $candidate = Invoke-RestMethod -Uri "$Ui/health" -TimeoutSec 2
        } catch {
            continue
        }
        if (-not (Test-ExpectedHealth $candidate)) {
            throw "started Twin health does not match runtime manifest"
        }
        $health = $candidate
        $ok = $true
        break
    }
    if (-not $ok) { throw "Sovereign Twin UI did not become healthy with expected runtime identity" }
}

Start-Process $Ui
Write-Host "Opened $Ui with memory DB $ExpectedMemoryDb"
