param(
    [Parameter(Mandatory=$true)][string]$SourceSha,
    [string]$EmbeddingModel = "text-embedding-nomic-embed-text-v1.5",
    [string]$MemoryDb = "",
    [switch]$NoAutostart,
    [switch]$NoStart
)

$ErrorActionPreference = "Stop"
$Repo = "bitmaster162/continuityos"
$Root = Join-Path $env:LOCALAPPDATA "SovereignTwin"
$Venv = Join-Path $Root "runtime-venv"
$Python = Join-Path $Venv "Scripts\python.exe"
$Twin = Join-Path $Venv "Scripts\sovereign-twin.exe"
$Launcher = Join-Path $Root "start-sovereign-twin.ps1"
$Manifest = Join-Path $Root "runtime-source.json"
$TaskName = "SovereignTwin-UI"
$DefaultMemoryDb = Join-Path $HOME ".continuityos\memory.db"
$AdmissionQueue = Join-Path $HOME ".continuityos\twin-admissions.jsonl"
$UiUrl = "http://127.0.0.1:8765"
$LlmUrl = "http://127.0.0.1:1234"
$FastModel = "qwen3.5-4b"
$DeepModel = "qwen3.6-35b-a3b"
$ExistingRuntime = $null
$PreserveExistingMemory = $false

function Step([string]$Text) { Write-Host "`n=== $Text ===" -ForegroundColor Cyan }

if ($SourceSha -notmatch '^[0-9a-fA-F]{40}$') {
    throw "-SourceSha must be an exact 40-character Git commit SHA"
}
$SourceSha = $SourceSha.ToLowerInvariant()

Step "Resolve active memory target"
if (Test-Path -LiteralPath $Manifest) {
    $ExistingRuntime = Get-Content -LiteralPath $Manifest -Raw | ConvertFrom-Json
    if ([string]$ExistingRuntime.execution_authority -ne "NONE" -or [bool]$ExistingRuntime.can_execute) {
        throw "existing runtime manifest violates no-execution authority"
    }

    $existingMemoryRaw = [string]$ExistingRuntime.memory_db
    if ([string]::IsNullOrWhiteSpace($existingMemoryRaw)) {
        throw "existing runtime manifest has no memory_db"
    }
    $existingMemory = [System.IO.Path]::GetFullPath($existingMemoryRaw)
    if (-not (Test-Path -LiteralPath $existingMemory)) {
        throw "existing active memory DB is missing: $existingMemory"
    }

    if ($PSBoundParameters.ContainsKey("MemoryDb")) {
        $requestedMemory = [System.IO.Path]::GetFullPath($MemoryDb)
        if (-not [System.StringComparer]::OrdinalIgnoreCase.Equals($requestedMemory, $existingMemory)) {
            throw "installer refuses to change active memory DB; use SovereignTwin-Activate-Memory.ps1"
        }
    }
    $MemoryDb = $existingMemory
    $PreserveExistingMemory = $true

    $existingEmbedding = [string]$ExistingRuntime.embedding_model
    if (-not [string]::IsNullOrWhiteSpace($existingEmbedding)) {
        if ($PSBoundParameters.ContainsKey("EmbeddingModel") -and $EmbeddingModel -ne $existingEmbedding) {
            throw "installer refuses to change the active embedding model; re-embed and activate memory explicitly"
        }
        $EmbeddingModel = $existingEmbedding
    }

    $existingQueue = [string]$ExistingRuntime.admission_queue
    if (-not [string]::IsNullOrWhiteSpace($existingQueue)) {
        $AdmissionQueue = $existingQueue
    }
    Write-Host "Active memory DB preserved: $MemoryDb"
} else {
    if ([string]::IsNullOrWhiteSpace($MemoryDb)) {
        $MemoryDb = $DefaultMemoryDb
    } else {
        $MemoryDb = [System.IO.Path]::GetFullPath($MemoryDb)
    }
    Write-Host "Initial memory DB: $MemoryDb"
}

Step "Preflight"
$llmTask = Get-ScheduledTask -TaskName "SovereignTwin-LLMStudio" -ErrorAction SilentlyContinue
if (-not $llmTask) {
    throw "SovereignTwin-LLMStudio task not found. Finish the llmster bootstrap first."
}
try {
    $catalog = Invoke-RestMethod -Uri "$LlmUrl/api/v1/models" -TimeoutSec 8
    $keys = @($catalog.models | ForEach-Object { $_.key })
    foreach ($required in @($FastModel, $DeepModel, $EmbeddingModel)) {
        if (-not ($keys -contains $required)) {
            throw "required local model is not visible to llmster: $required"
        }
    }
    Write-Host "FAST model: PASS ($FastModel)"
    Write-Host "DEEP model: PASS ($DeepModel)"
    Write-Host "Embedding model: PASS ($EmbeddingModel)"
} catch {
    throw "LM Studio/llmster preflight failed on 127.0.0.1:1234: $($_.Exception.Message)"
}

$py = Get-Command py.exe -ErrorAction SilentlyContinue
if ($py) {
    $BootstrapPython = $py.Source
    $PyArgs = @("-3.11")
} else {
    $p = Get-Command python.exe -ErrorAction SilentlyContinue
    if (-not $p) { throw "Python 3.10+ is required" }
    $BootstrapPython = $p.Source
    $PyArgs = @()
}

$version = & $BootstrapPython @PyArgs -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')"
$parts = $version.Trim().Split('.')
if ([int]$parts[0] -lt 3 -or ([int]$parts[0] -eq 3 -and [int]$parts[1] -lt 10)) {
    throw "Python 3.10+ required; found $version"
}
Write-Host "Python bootstrap: $BootstrapPython $($PyArgs -join ' ') ($version)"

Step "Download exact reviewed source"
New-Item -ItemType Directory -Path $Root -Force | Out-Null
$Work = Join-Path $env:TEMP ("sovereign-twin-install-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $Work -Force | Out-Null
try {
    $Zip = Join-Path $Work "source.zip"
    $ArchiveUrl = "https://github.com/$Repo/archive/$SourceSha.zip"
    Invoke-WebRequest -Uri $ArchiveUrl -OutFile $Zip -UseBasicParsing
    Expand-Archive -Path $Zip -DestinationPath $Work -Force
    $Source = Get-ChildItem $Work -Directory | Where-Object { $_.Name -like 'continuityos-*' } | Select-Object -First 1
    if (-not $Source) { throw "Downloaded archive did not contain continuityos source directory" }

    Step "Create isolated runtime venv"
    if (-not (Test-Path $Python)) {
        & $BootstrapPython @PyArgs -m venv $Venv
    }
    if (-not (Test-Path $Python)) { throw "venv Python was not created" }

    Step "Install exact source into venv"
    & $Python -m pip install --disable-pip-version-check --no-deps --upgrade $Source.FullName
    if ($LASTEXITCODE -ne 0) { throw "pip install failed" }
    if (-not (Test-Path $Twin)) { throw "sovereign-twin entry point not installed" }

    if ($PreserveExistingMemory) {
        Step "Preserve existing active memory container"
        if (-not (Test-Path -LiteralPath $MemoryDb)) {
            throw "existing active memory DB disappeared during install: $MemoryDb"
        }
        Write-Host "Existing memory DB left untouched: $MemoryDb"
    } else {
        Step "Initialize local memory container"
        & $Twin --db $MemoryDb init
        if ($LASTEXITCODE -ne 0) { throw "sovereign-twin init failed" }
    }

    $manifestObj = [ordered]@{
        schema = "sovereign-twin.windows-runtime-source/v3"
        repository = $Repo
        source_sha = $SourceSha
        installed_at_utc = [DateTime]::UtcNow.ToString("o")
        python = $Python
        twin_executable = $Twin
        memory_db = $MemoryDb
        admission_queue = $AdmissionQueue
        llm_server = $LlmUrl
        ui = $UiUrl
        fast_model = $FastModel
        deep_model = $DeepModel
        embedding_model = $EmbeddingModel
        execution_authority = "NONE"
        can_execute = $false
    }
    if ($ExistingRuntime) {
        foreach ($prop in $ExistingRuntime.PSObject.Properties) {
            if ($prop.Name -like "memory_*" -and $prop.Name -ne "memory_db") {
                $manifestObj[$prop.Name] = $prop.Value
            }
        }
    }
    $manifestObj | ConvertTo-Json -Depth 8 | Set-Content -Path $Manifest -Encoding UTF8
} finally {
    Remove-Item $Work -Recurse -Force -ErrorAction SilentlyContinue
}

Step "Write local UI launcher"
$escapedTwin = $Twin.Replace("'", "''")
$escapedDb = $MemoryDb.Replace("'", "''")
$escapedQueue = $AdmissionQueue.Replace("'", "''")
$escapedEmbedding = $EmbeddingModel.Replace("'", "''")
$launcherBody = @"
`$ErrorActionPreference = "SilentlyContinue"
Start-Sleep -Seconds 8
try {
    `$h = Invoke-RestMethod -Uri "$UiUrl/health" -TimeoutSec 2
    if (`$h.ok -and [System.IO.Path]::GetFullPath([string]`$h.memory_db) -eq [System.IO.Path]::GetFullPath('$escapedDb')) { exit 0 }
} catch {}
& '$escapedTwin' --db '$escapedDb' --admission-queue '$escapedQueue' --embedding-model '$escapedEmbedding' serve --host 127.0.0.1 --port 8765
"@
Set-Content -Path $Launcher -Value $launcherBody -Encoding UTF8

if (-not $NoAutostart) {
    Step "Register per-user UI autostart"
    $psExe = (Get-Command powershell.exe).Source
    $args = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$Launcher`""
    $action = New-ScheduledTaskAction -Execute $psExe -Argument $args
    $trigger = New-ScheduledTaskTrigger -AtLogOn
    $principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Limited
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal `
        -Description "Start local Sovereign Twin UI/API on 127.0.0.1:8765" -Force | Out-Null
    Write-Host "Autostart installed: $TaskName"
}

if (-not $NoStart) {
    Step "Start local Twin UI now"
    $launchArgs = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$Launcher`""
    Start-Process powershell.exe -WindowStyle Hidden -ArgumentList $launchArgs | Out-Null

    $ok = $false
    for ($i = 0; $i -lt 30; $i++) {
        Start-Sleep -Seconds 1
        try {
            $h = Invoke-RestMethod -Uri "$UiUrl/health" -TimeoutSec 2
            if ($h.ok -and [System.IO.Path]::GetFullPath([string]$h.memory_db) -eq [System.IO.Path]::GetFullPath($MemoryDb)) {
                $ok = $true
                break
            }
        } catch {}
    }
    if (-not $ok) { throw "Sovereign Twin UI did not become healthy on $UiUrl with expected memory DB $MemoryDb" }
    Write-Host "Twin health: PASS"
}

Step "Receipt"
Get-Content $Manifest
Write-Host "`nDONE. Open $UiUrl"