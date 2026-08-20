$ErrorActionPreference = "Continue"
$Root = Join-Path $env:LOCALAPPDATA "SovereignTwin"
$Manifest = Join-Path $Root "runtime-source.json"
$DefaultMemoryDb = Join-Path $HOME ".continuityos\memory.db"
$Twin = Join-Path $Root "runtime-venv\Scripts\sovereign-twin.exe"
$MemoryDb = $DefaultMemoryDb
$ManifestObj = $null

Write-Host "=== Sovereign Twin runtime ===" -ForegroundColor Cyan
if (Test-Path $Manifest) {
    try {
        $ManifestObj = Get-Content $Manifest -Raw | ConvertFrom-Json
        Get-Content $Manifest
        if (-not [string]::IsNullOrWhiteSpace([string]$ManifestObj.memory_db)) {
            $MemoryDb = [System.IO.Path]::GetFullPath([string]$ManifestObj.memory_db)
        }
    } catch {
        Write-Warning "runtime-source.json could not be parsed: $_"
    }
} else {
    Write-Warning "runtime-source.json missing"
}

Write-Host "`n=== Scheduled Tasks ===" -ForegroundColor Cyan
Get-ScheduledTask -TaskName "SovereignTwin-LLMStudio" -ErrorAction SilentlyContinue | Select-Object TaskName,State
Get-ScheduledTask -TaskName "SovereignTwin-UI" -ErrorAction SilentlyContinue | Select-Object TaskName,State

Write-Host "`n=== LM Studio / llmster ===" -ForegroundColor Cyan
try { lms daemon status --json } catch { Write-Warning $_ }
try { lms server status --json --quiet } catch { Write-Warning $_ }
try { Invoke-RestMethod "http://127.0.0.1:1234/api/v1/models" -TimeoutSec 5 | ConvertTo-Json -Depth 8 } catch { Write-Warning $_ }

Write-Host "`n=== Twin UI/API ===" -ForegroundColor Cyan
try { Invoke-RestMethod "http://127.0.0.1:8765/health" -TimeoutSec 5 | ConvertTo-Json -Depth 5 } catch { Write-Warning $_ }
try { Invoke-RestMethod "http://127.0.0.1:8765/doctor" -TimeoutSec 20 | ConvertTo-Json -Depth 10 } catch { Write-Warning $_ }

Write-Host "`n=== Local state ===" -ForegroundColor Cyan
[pscustomobject]@{
    TwinExecutable = (Test-Path $Twin)
    MemoryDbPath = $MemoryDb
    MemoryDb = (Test-Path -LiteralPath $MemoryDb)
    RuntimeManifest = (Test-Path $Manifest)
    UI = "http://127.0.0.1:8765"
    LLM = "http://127.0.0.1:1234"
    ExecutionAuthority = "NONE"
    CanExecute = $false
}