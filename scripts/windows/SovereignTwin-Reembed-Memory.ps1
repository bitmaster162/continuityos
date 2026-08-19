param(
    [string]$SourceDb = "$HOME\.continuityos\memory.db",
    [string]$TargetDb = "$HOME\.continuityos\memory-nomic-768.db",
    [string]$EmbeddingModel = "text-embedding-nomic-embed-text-v1.5",
    [switch]$Commit
)

$ErrorActionPreference = "Stop"
$Python = Join-Path $env:LOCALAPPDATA "SovereignTwin\runtime-venv\Scripts\python.exe"
if (-not (Test-Path $Python)) {
    throw "Sovereign Twin runtime Python not found: $Python"
}
if (-not (Test-Path $SourceDb)) {
    throw "Source memory DB not found: $SourceDb"
}
if (([System.IO.Path]::GetFullPath($SourceDb)) -eq ([System.IO.Path]::GetFullPath($TargetDb))) {
    throw "Source and target DB must be different paths"
}

$args = @(
    "-m", "continuityos.sovereign_twin_reembed",
    "--source", $SourceDb,
    "--target", $TargetDb,
    "--embedding-model", $EmbeddingModel
)
if ($Commit) { $args += "--commit" }

& $Python @args
$code = $LASTEXITCODE
if ($code -ne 0) {
    throw "Sovereign Twin memory re-embedding failed with exit code $code"
}

if (-not $Commit) {
    Write-Host "`nDRY RUN ONLY. Re-run with -Commit to create the new DB." -ForegroundColor Yellow
} else {
    Write-Host "`nMigration completed. Canonical memory pointer was NOT switched." -ForegroundColor Green
    Write-Host "Source remains unchanged: $SourceDb"
    Write-Host "Candidate target: $TargetDb"
}
