param(
    [switch]$SmokeFast
)

$ErrorActionPreference = "Stop"
$Root = Join-Path $env:LOCALAPPDATA "SovereignTwin"
$Manifest = Join-Path $Root "runtime-source.json"
$Twin = Join-Path $Root "runtime-venv\Scripts\sovereign-twin.exe"
$Ui = "http://127.0.0.1:8765"
$Llm = "http://127.0.0.1:1234"
$ReceiptDir = Join-Path $Root "receipts"
New-Item -ItemType Directory -Path $ReceiptDir -Force | Out-Null
$Stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$Receipt = Join-Path $ReceiptDir "first-run-$Stamp.json"

function Require([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}

Require (Test-Path $Manifest) "runtime-source.json is missing; install Sovereign Twin runtime first"
Require (Test-Path $Twin) "sovereign-twin executable is missing"

$manifestObj = Get-Content $Manifest -Raw | ConvertFrom-Json
Require ($manifestObj.execution_authority -eq "NONE") "runtime manifest authority mismatch"
Require ($manifestObj.can_execute -eq $false) "runtime manifest unexpectedly grants execution"

$llmTask = Get-ScheduledTask -TaskName "SovereignTwin-LLMStudio" -ErrorAction SilentlyContinue
$uiTask = Get-ScheduledTask -TaskName "SovereignTwin-UI" -ErrorAction SilentlyContinue
Require ($null -ne $llmTask) "SovereignTwin-LLMStudio task missing"
Require ($null -ne $uiTask) "SovereignTwin-UI task missing"

$models = Invoke-RestMethod -Uri "$Llm/api/v1/models" -TimeoutSec 10
$keys = @($models.models | ForEach-Object { $_.key })
foreach ($required in @("qwen3.5-4b", "qwen3.6-35b-a3b", "text-embedding-nomic-embed-text-v1.5")) {
    Require ($keys -contains $required) "required local model missing: $required"
}

$health = Invoke-RestMethod -Uri "$Ui/health" -TimeoutSec 10
Require ($health.ok -eq $true) "Twin UI health is not OK"
Require ($health.execution_authority -eq "NONE") "Twin UI authority mismatch"
Require ($health.can_execute -eq $false) "Twin UI unexpectedly grants execution"

$doctorRaw = & $Twin doctor
Require ($LASTEXITCODE -eq 0) "sovereign-twin doctor failed"
$doctor = $doctorRaw | ConvertFrom-Json
$memoryRaw = & $Twin memory-doctor
$memoryExit = $LASTEXITCODE
$memoryDoctor = $null
try { $memoryDoctor = $memoryRaw | ConvertFrom-Json } catch { $memoryDoctor = @{ ok = $false; raw = ($memoryRaw | Out-String) } }

$smoke = $null
if ($SmokeFast) {
    $smokeRaw = & $Twin ask "Reply with exactly LOCAL_TWIN_OK and nothing else." --mode fast
    $smokeExit = $LASTEXITCODE
    $smoke = @{ exit_code = $smokeExit; raw = ($smokeRaw | Out-String).Trim() }
}

$os = Get-CimInstance Win32_OperatingSystem
$ram = [ordered]@{
    total_gb = [math]::Round($os.TotalVisibleMemorySize / 1MB, 2)
    free_gb  = [math]::Round($os.FreePhysicalMemory / 1MB, 2)
    used_gb  = [math]::Round(($os.TotalVisibleMemorySize - $os.FreePhysicalMemory) / 1MB, 2)
}

$receiptObj = [ordered]@{
    schema = "sovereign-twin.first-run-receipt/v1"
    created_at = (Get-Date).ToString("o")
    source_sha = $manifestObj.source_sha
    llmster_task = $llmTask.State.ToString()
    ui_task = $uiTask.State.ToString()
    model_keys = $keys
    ui_health = $health
    doctor = $doctor
    memory_doctor = $memoryDoctor
    memory_doctor_exit = $memoryExit
    smoke_fast = $smoke
    ram = $ram
    execution_authority = "NONE"
    can_execute = $false
}
$receiptObj | ConvertTo-Json -Depth 12 | Set-Content -Path $Receipt -Encoding UTF8
$receiptObj | ConvertTo-Json -Depth 12
Write-Host "`nReceipt: $Receipt"
