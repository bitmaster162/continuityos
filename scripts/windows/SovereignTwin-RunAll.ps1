param(
    [switch]$NoAutostart
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$Setup = Join-Path $Root "SovereignTwin-LLMStudio-Setup.ps1"
$Status = Join-Path $Root "SovereignTwin-Status.ps1"
$Stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$Log = Join-Path $Root "SovereignTwin-run-$Stamp.log"

function Write-Logged([string]$Text) {
    $Text | Tee-Object -FilePath $Log -Append
}

function Run-ChildScript([string]$Path, [string[]]$Arguments = @()) {
    if (-not (Test-Path $Path)) {
        Write-Logged "ERROR: missing script: $Path"
        return 2
    }
    $ps = (Get-Command powershell.exe).Source
    $argList = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $Path) + $Arguments
    $output = & $ps @argList 2>&1
    $code = $LASTEXITCODE
    $output | ForEach-Object { Write-Logged ([string]$_) }
    return $code
}

"Sovereign Twin Windows bootstrap" | Set-Content -Path $Log -Encoding UTF8
Write-Logged "started_at=$(Get-Date -Format o)"
Write-Logged "computer=$env:COMPUTERNAME user=$env:USERNAME"
Write-Logged "root=$Root"

Write-Logged ""
Write-Logged "=== SETUP ==="
$setupArgs = @()
if ($NoAutostart) { $setupArgs += "-NoAutostart" }
$setupCode = Run-ChildScript -Path $Setup -Arguments $setupArgs
Write-Logged "setup_exit_code=$setupCode"
if ($setupCode -ne 0) {
    Write-Logged "RESULT=FAIL_SETUP"
    Write-Host "`nSetup failed. Log: $Log" -ForegroundColor Red
    exit $setupCode
}

Write-Logged ""
Write-Logged "=== STATUS ==="
$statusCode = Run-ChildScript -Path $Status
Write-Logged "status_exit_code=$statusCode"

Write-Logged ""
Write-Logged "=== SCHEDULED TASK ==="
try {
    $task = Get-ScheduledTask -TaskName "SovereignTwin-LLMStudio" -ErrorAction Stop
    Write-Logged "task_name=$($task.TaskName) state=$($task.State)"
} catch {
    if ($NoAutostart) {
        Write-Logged "task=NOT_INSTALLED_EXPECTED"
    } else {
        Write-Logged "task=NOT_FOUND"
    }
}

Write-Logged ""
Write-Logged "finished_at=$(Get-Date -Format o)"
if ($statusCode -eq 0) {
    Write-Logged "RESULT=PASS"
    Write-Host "`nSovereign Twin llmster bootstrap PASS" -ForegroundColor Green
} else {
    Write-Logged "RESULT=STATUS_WARN"
    Write-Host "`nSetup completed but status returned a warning/failure." -ForegroundColor Yellow
}
Write-Host "Log: $Log"
exit $statusCode
