param(
    [string]$SourceDb = "",
    [string]$TargetDb = "$HOME\.continuityos\memory-nomic-768.db",
    [string]$EmbeddingModel = "text-embedding-nomic-embed-text-v1.5",
    [switch]$Commit
)

$ErrorActionPreference = "Stop"
$Root = Join-Path $env:LOCALAPPDATA "SovereignTwin"
$Python = Join-Path $Root "runtime-venv\Scripts\python.exe"
$Manifest = Join-Path $Root "runtime-source.json"

if (-not (Test-Path -LiteralPath $Python)) {
    throw "Sovereign Twin runtime Python not found: $Python"
}

$runtime = $null
if (Test-Path -LiteralPath $Manifest) {
    $runtime = Get-Content -LiteralPath $Manifest -Raw | ConvertFrom-Json
    if ([string]$runtime.execution_authority -ne "NONE" -or [bool]$runtime.can_execute) {
        throw "runtime manifest violates no-execution authority"
    }

    if ([string]::IsNullOrWhiteSpace($SourceDb)) {
        if ([string]::IsNullOrWhiteSpace([string]$runtime.memory_db)) {
            throw "runtime manifest memory_db missing"
        }
        $SourceDb = [System.IO.Path]::GetFullPath([string]$runtime.memory_db)
        Write-Host "Source memory bound to active runtime manifest: $SourceDb"
    } else {
        $SourceDb = [System.IO.Path]::GetFullPath($SourceDb)
        $activeDb = $null
        if (-not [string]::IsNullOrWhiteSpace([string]$runtime.memory_db)) {
            $activeDb = [System.IO.Path]::GetFullPath([string]$runtime.memory_db)
        }
        if ($activeDb -and -not [System.StringComparer]::OrdinalIgnoreCase.Equals($SourceDb, $activeDb)) {
            Write-Host "Explicit source override differs from active runtime memory: $SourceDb" -ForegroundColor Yellow
        }
    }

    if (-not $PSBoundParameters.ContainsKey("EmbeddingModel")) {
        $runtimeEmbedding = [string]$runtime.embedding_model
        if (-not [string]::IsNullOrWhiteSpace($runtimeEmbedding)) {
            $EmbeddingModel = $runtimeEmbedding
        }
    }
} else {
    if ([string]::IsNullOrWhiteSpace($SourceDb)) {
        throw "SourceDb must be provided when runtime manifest is missing"
    }
    $SourceDb = [System.IO.Path]::GetFullPath($SourceDb)
}

if (-not (Test-Path -LiteralPath $SourceDb)) {
    throw "Source memory DB not found: $SourceDb"
}
$TargetDb = [System.IO.Path]::GetFullPath($TargetDb)
if ([System.StringComparer]::OrdinalIgnoreCase.Equals($SourceDb, $TargetDb)) {
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
