$ErrorActionPreference = "Continue"
Write-Host "=== Sovereign Twin / LM Studio status ===" -ForegroundColor Cyan
lms daemon status --json
lms server status --json --quiet
lms ps --json
try {
  Invoke-RestMethod http://127.0.0.1:1234/api/v1/models | ConvertTo-Json -Depth 8
} catch {
  Write-Warning $_
}
Write-Host "`n=== RAM ===" -ForegroundColor Cyan
$os = Get-CimInstance Win32_OperatingSystem
[pscustomobject]@{
    RAM_Total_GB = [math]::Round($os.TotalVisibleMemorySize / 1MB, 2)
    RAM_Free_GB  = [math]::Round($os.FreePhysicalMemory / 1MB, 2)
    RAM_Used_GB  = [math]::Round(($os.TotalVisibleMemorySize - $os.FreePhysicalMemory) / 1MB, 2)
}
Write-Host "`n=== NVIDIA ===" -ForegroundColor Cyan
nvidia-smi
