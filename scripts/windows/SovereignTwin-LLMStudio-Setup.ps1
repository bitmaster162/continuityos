param(
    [switch]$StatusOnly,
    [switch]$NoAutostart,
    [switch]$RemoveAutostart
)

$ErrorActionPreference = "Stop"
$TaskName = "SovereignTwin-LLMStudio"
$Root = Join-Path $env:LOCALAPPDATA "SovereignTwin"
$Launcher = Join-Path $Root "start-llmster.ps1"
$ApiHost = "127.0.0.1"
$ApiPort = 1234

function Write-Step([string]$Text) {
    Write-Host "`n=== $Text ===" -ForegroundColor Cyan
}

function Get-LmsPath {
    $cmd = Get-Command lms -ErrorAction SilentlyContinue
    if ($null -eq $cmd) { return $null }
    return $cmd.Source
}

function Get-LlmsterStatus([string]$LmsPath) {
    if (-not $LmsPath) { return $null }
    try {
        $raw = (& $LmsPath daemon status --json 2>$null | Out-String).Trim()
        if (-not $raw) { return $null }
        return $raw | ConvertFrom-Json
    } catch {
        return $null
    }
}

function Test-Port1234Listener {
    try {
        return $null -ne (Get-NetTCPConnection -LocalPort $ApiPort -State Listen -ErrorAction Stop | Select-Object -First 1)
    } catch {
        return $false
    }
}

function Assert-NoDesktopHeadlessAmbiguity {
    param([string]$LmsPath)

    $gui = Get-Process | Where-Object { $_.ProcessName -match "^LM Studio$|^LM Studio" }
    if ($gui) {
        Write-Warning "LM Studio Desktop is still running."
        Write-Warning "Fully quit LM Studio from the tray before switching to standalone llmster."
        Write-Warning "This script will not terminate the GUI automatically."
        exit 2
    }

    if (Test-Port1234Listener) {
        $daemon = Get-LlmsterStatus $LmsPath
        $isLlmster = $daemon -and $daemon.status -eq "running" -and $daemon.isDaemon -eq $true
        if (-not $isLlmster) {
            Write-Error "Port 1234 is already listening but standalone llmster is not confirmed. Disable LM Studio Desktop 'Enable Local LLM Service (headless)', quit Desktop from the tray, then run again."
            exit 2
        }
    }
}

function Show-Status {
    Write-Step "LMS / llmster status"
    $lms = Get-LmsPath
    if (-not $lms) {
        Write-Host "lms: NOT FOUND"
        return
    }
    Write-Host "lms: $lms"
    try { & $lms daemon status --json } catch { Write-Warning $_ }
    try { & $lms server status --json --quiet } catch { Write-Warning $_ }
    try { & $lms ps --json } catch { Write-Warning $_ }

    Write-Step "Local API"
    try {
        $models = Invoke-RestMethod -Uri "http://${ApiHost}:${ApiPort}/api/v1/models" -TimeoutSec 8
        $ids = @($models.models | ForEach-Object { $_.key })
        Write-Host "Server OK on ${ApiHost}:${ApiPort}"
        Write-Host "Visible models:"
        $ids | ForEach-Object { Write-Host " - $_" }
        Write-Host "FAST qwen3.5-4b visible: $($ids -contains 'qwen3.5-4b')"
        Write-Host "DEEP qwen3.6-35b-a3b visible: $($ids -contains 'qwen3.6-35b-a3b')"
    } catch {
        Write-Warning "Local API not reachable: $($_.Exception.Message)"
    }

    Write-Step "Autostart task"
    $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($task) { Write-Host "$TaskName : $($task.State)" }
    else { Write-Host "$TaskName : NOT INSTALLED" }
}

if ($RemoveAutostart) {
    Write-Step "Remove autostart"
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    Remove-Item $Launcher -Force -ErrorAction SilentlyContinue
    Write-Host "Removed $TaskName"
    exit 0
}

if ($StatusOnly) {
    Show-Status
    exit 0
}

Write-Step "Preflight"
$lmsBefore = Get-LmsPath
Assert-NoDesktopHeadlessAmbiguity -LmsPath $lmsBefore

Write-Step "Install / update llmster from official LM Studio installer"
try {
    irm https://lmstudio.ai/install.ps1 | iex
} catch {
    Write-Error "Official llmster installer failed: $($_.Exception.Message)"
    exit 2
}

$lms = Get-LmsPath
if (-not $lms) {
    Write-Error "lms was not found after install. Open a new PowerShell and run this script again."
    exit 2
}
Write-Host "Using: $lms"

Assert-NoDesktopHeadlessAmbiguity -LmsPath $lms

Write-Step "Start llmster daemon"
$daemonRaw = (& $lms daemon up --json 2>&1 | Out-String).Trim()
Write-Host $daemonRaw
try {
    $daemon = $daemonRaw | ConvertFrom-Json
} catch {
    Write-Error "Could not parse llmster daemon status JSON."
    exit 2
}
if ($daemon.status -ne "running" -or $daemon.isDaemon -ne $true) {
    Write-Error "Standalone llmster did not report status=running and isDaemon=true."
    exit 2
}

Write-Step "Start localhost API server"
try {
    & $lms server start --port $ApiPort --bind $ApiHost
} catch {
    Write-Warning $_
}

Start-Sleep -Seconds 2

Write-Step "Verify models / JIT visibility"
try {
    $models = Invoke-RestMethod -Uri "http://${ApiHost}:${ApiPort}/api/v1/models" -TimeoutSec 10
    $ids = @($models.models | ForEach-Object { $_.key })
    if (-not ($ids -contains "qwen3.5-4b")) { Write-Warning "qwen3.5-4b is not visible to the daemon." }
    if (-not ($ids -contains "qwen3.6-35b-a3b")) { Write-Warning "qwen3.6-35b-a3b is not visible to the daemon." }
    Write-Host "Visible models:"
    $ids | ForEach-Object { Write-Host " - $_" }
} catch {
    Write-Error "Server verification failed: $($_.Exception.Message)"
    exit 2
}

if (-not $NoAutostart) {
    Write-Step "Create Windows logon autostart"
    New-Item -ItemType Directory -Path $Root -Force | Out-Null

    $escapedLms = $lms.Replace("'", "''")
    $launcherBody = @"
`$ErrorActionPreference = "SilentlyContinue"
& '$escapedLms' daemon up | Out-Null
Start-Sleep -Seconds 2
& '$escapedLms' server start --port $ApiPort --bind $ApiHost | Out-Null
"@
    Set-Content -Path $Launcher -Value $launcherBody -Encoding UTF8

    $psExe = (Get-Command powershell.exe).Source
    $arguments = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$Launcher`""
    $action = New-ScheduledTaskAction -Execute $psExe -Argument $arguments
    $trigger = New-ScheduledTaskTrigger -AtLogOn
    $principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Limited

    Register-ScheduledTask `
        -TaskName $TaskName `
        -Action $action `
        -Trigger $trigger `
        -Principal $principal `
        -Description "Start standalone LM Studio llmster + loopback API server for Sovereign Twin" `
        -Force | Out-Null

    Write-Host "Autostart installed: $TaskName"
}

Write-Step "Final status"
Show-Status
Write-Host "`nDONE."
Write-Host "Keep JIT loading, Auto Unload Unused JIT Models, and Only Keep Last JIT Loaded Model enabled."
Write-Host "Keep LM Studio Desktop headless service disabled while using this standalone llmster task."
Write-Host "Keep the server bound to 127.0.0.1 unless you intentionally configure authentication/network access."
