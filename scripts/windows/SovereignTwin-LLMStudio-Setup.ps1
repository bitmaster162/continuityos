param(
    [switch]$StatusOnly,
    [switch]$NoAutostart,
    [switch]$RemoveAutostart
)

$ErrorActionPreference = "Stop"
$TaskName = "SovereignTwin-LLMStudio"
$Root = Join-Path $env:LOCALAPPDATA "SovereignTwin"
$Launcher = Join-Path $Root "start-llmster.ps1"

function Write-Step([string]$Text) {
    Write-Host "`n=== $Text ===" -ForegroundColor Cyan
}

function Get-LmsPath {
    $cmd = Get-Command lms -ErrorAction SilentlyContinue
    if ($null -eq $cmd) { return $null }
    return $cmd.Source
}

function Show-Status {
    Write-Step "LMS / LLmster status"
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
        $models = Invoke-RestMethod -Uri "http://127.0.0.1:1234/api/v1/models" -TimeoutSec 8
        $ids = @($models.models | ForEach-Object { $_.key })
        Write-Host "Server OK on 127.0.0.1:1234"
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
$gui = Get-Process | Where-Object { $_.ProcessName -match "^LM Studio$|^LM Studio" }
if ($gui) {
    Write-Warning "LM Studio GUI is still running."
    Write-Warning "Fully exit LM Studio from the tray, then run this script again."
    Write-Warning "This script will not kill the GUI automatically."
    exit 2
}

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

Write-Step "Start llmster daemon"
& $lms daemon up

Write-Step "Start localhost API server"
try {
    & $lms server start --port 1234 --bind 127.0.0.1
} catch {
    Write-Warning $_
}

Start-Sleep -Seconds 2

Write-Step "Verify models / JIT visibility"
try {
    $models = Invoke-RestMethod -Uri "http://127.0.0.1:1234/api/v1/models" -TimeoutSec 10
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
& '$escapedLms' server start --port 1234 --bind 127.0.0.1 | Out-Null
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
        -Description "Start LM Studio llmster + local API server for Sovereign Twin" `
        -Force | Out-Null

    Write-Host "Autostart installed: $TaskName"
}

Write-Step "Final status"
Show-Status
Write-Host "`nDONE."
Write-Host "Keep JIT loading, Auto Unload Unused JIT Models, and Only Keep Last JIT Loaded Model enabled."
Write-Host "Keep the server bound to 127.0.0.1 unless you intentionally configure authentication/network access."
