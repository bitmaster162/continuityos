$ErrorActionPreference = "Stop"
$Ui = "http://127.0.0.1:8765"
$TaskName = "SovereignTwin-UI"

try {
    $health = Invoke-RestMethod -Uri "$Ui/health" -TimeoutSec 3
    if (-not $health.ok) { throw "health returned not-ok" }
} catch {
    $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if (-not $task) { throw "$TaskName is not installed" }
    Start-ScheduledTask -TaskName $TaskName
    $ok = $false
    for ($i = 0; $i -lt 30; $i++) {
        Start-Sleep -Seconds 1
        try {
            $health = Invoke-RestMethod -Uri "$Ui/health" -TimeoutSec 2
            if ($health.ok) { $ok = $true; break }
        } catch {}
    }
    if (-not $ok) { throw "Sovereign Twin UI did not become healthy" }
}

Start-Process $Ui
Write-Host "Opened $Ui"
