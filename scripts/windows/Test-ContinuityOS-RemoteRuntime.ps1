[CmdletBinding()]
param(
    [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path,
    [string]$RemoteRoot = "",
    [string]$ProbeRelativePath = "README.md",
    [string]$TunnelClient = "tunnel-client",
    [string]$Python = "python",
    [string]$ExpectedHead = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Require-Command {
    param([Parameter(Mandatory = $true)][string]$Name)
    $resolved = Get-Command $Name -ErrorAction Stop
    if (-not $resolved.Source) {
        throw "Cannot resolve executable path for $Name"
    }
    return $resolved.Source
}

$repo = (Resolve-Path -LiteralPath $RepoRoot).Path
if ([string]::IsNullOrWhiteSpace($RemoteRoot)) {
    $RemoteRoot = $repo
}
$root = (Resolve-Path -LiteralPath $RemoteRoot).Path
$probe = Join-Path $root $ProbeRelativePath
if (-not (Test-Path -LiteralPath $probe -PathType Leaf)) {
    throw "ProbeRelativePath must identify an existing file inside RemoteRoot."
}

$pythonExe = Require-Command -Name $Python
$tunnelExe = Require-Command -Name $TunnelClient
$launcher = Join-Path $repo "scripts\windows\ContinuityOS-RemoteTunnel.ps1"
if (-not (Test-Path -LiteralPath $launcher -PathType Leaf)) {
    throw "ContinuityOS Remote Tunnel launcher is missing."
}

Push-Location $repo
try {
    $head = (git rev-parse HEAD).Trim()
    $dirty = @(git status --porcelain)
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to read Git baseline."
    }
    if ($dirty.Count -ne 0) {
        throw "Runtime qualification requires a clean Git worktree."
    }
    if (-not [string]::IsNullOrWhiteSpace($ExpectedHead) -and $head -ne $ExpectedHead) {
        throw "Git HEAD does not match ExpectedHead."
    }

    $planArgs = @(
        "-Mode", "Plan",
        "-RemoteRoot", $root,
        "-TunnelClient", $tunnelExe,
        "-Python", $pythonExe
    )
    $plan = (& $launcher @planArgs | Out-String) | ConvertFrom-Json

    if ($plan.schema -ne "continuityos.remote_tunnel_plan/v1") {
        throw "Unexpected launcher plan schema."
    }
    if ($plan.mcp_transport -ne "stdio" -or
        $plan.mcp_tool_profile -ne "chatgpt-pro-readonly" -or
        $plan.public_mcp_listener -ne $false -or
        $plan.health_listener_scope -ne "loopback" -or
        $plan.direct_shell -ne $false) {
        throw "Launcher plan violates the R3 safety contract."
    }

    $tunnelVersion = (& $tunnelExe --version 2>&1 | Select-Object -First 1).ToString().Trim()
    $quickstart = (& $tunnelExe help quickstart 2>&1 | Out-String)
    if ($LASTEXITCODE -ne 0 -or $quickstart -notmatch "sample_mcp_stdio_local") {
        throw "tunnel-client quickstart does not advertise the local stdio sample."
    }
    $sample = (& $tunnelExe profiles samples show sample_mcp_stdio_local 2>&1 | Out-String)
    if ($LASTEXITCODE -ne 0 -or $sample -notmatch "mcp.command|mcp-command") {
        throw "tunnel-client local stdio sample contract is unavailable."
    }

    $requests = @(
        @{jsonrpc="2.0"; id=1; method="initialize"; params=@{}},
        @{jsonrpc="2.0"; id=2; method="tools/list"; params=@{}},
        @{jsonrpc="2.0"; id=3; method="tools/call"; params=@{name="capability_status"; arguments=@{}}},
        @{jsonrpc="2.0"; id=4; method="tools/call"; params=@{name="fs_read"; arguments=@{path=$ProbeRelativePath; max_bytes=2048}}},
        @{jsonrpc="2.0"; id=5; method="tools/call"; params=@{name="remember"; arguments=@{text="must not write"}}}
    )
    $payload = (($requests | ForEach-Object { $_ | ConvertTo-Json -Compress -Depth 8 }) -join [Environment]::NewLine) + [Environment]::NewLine
    $mcpArgs = @(
        "-m", "continuityos.remote_mcp_server",
        "--db", ":memory:",
        "--enable-remote",
        "--tool-profile", "chatgpt-pro-readonly",
        "--remote-root", $root
    )
    $raw = $payload | & $pythonExe @mcpArgs
    if ($LASTEXITCODE -ne 0) {
        throw "Remote MCP stdio qualification failed."
    }
    $responses = @($raw | ForEach-Object { $_ | ConvertFrom-Json })
    $toolsResponse = $responses | Where-Object { $_.id -eq 2 } | Select-Object -First 1
    $statusResponse = $responses | Where-Object { $_.id -eq 3 } | Select-Object -First 1
    $readResponse = $responses | Where-Object { $_.id -eq 4 } | Select-Object -First 1
    $denyResponse = $responses | Where-Object { $_.id -eq 5 } | Select-Object -First 1

    $tools = @($toolsResponse.result.tools | ForEach-Object { $_.name })
    $expectedTools = @("capability_status", "system_info", "fs_list", "fs_read")
    if (($tools -join ",") -ne ($expectedTools -join ",")) {
        throw "Unexpected ChatGPT Pro tool surface."
    }
    $status = $statusResponse.result.content[0].text | ConvertFrom-Json
    if ($status.mode -ne "read_only_host_surface" -or $status.mutating_execution.available -ne $false) {
        throw "Capability status does not report a read-only host surface."
    }
    if ($readResponse.result.isError -eq $true) {
        throw "Benign fs_read probe failed."
    }
    $hiddenWriteDenied = (
        $denyResponse.result.isError -eq $true -and
        $denyResponse.result.content[0].text -match "tool hidden by remote tool profile"
    )
    if (-not $hiddenWriteDenied) {
        throw "Hidden write tool was not rejected."
    }

    [pscustomobject]@{
        schema = "continuityos.remote_runtime_qualification/v1"
        status = "LOCAL_READONLY_RUNTIME_GREEN"
        git_head = $head
        git_clean = $true
        tunnel_client_version = $tunnelVersion
        tunnel_client_stdio_sample = $true
        mcp_transport = $plan.mcp_transport
        mcp_tool_profile = $plan.mcp_tool_profile
        advertised_tools = $tools
        benign_read = "pass"
        hidden_write_denied = $true
        public_mcp_listener = $plan.public_mcp_listener
        health_listener = $plan.health_listener
        health_listener_scope = $plan.health_listener_scope
        direct_shell = $plan.direct_shell
        control_plane_key_present = -not [string]::IsNullOrWhiteSpace($env:CONTROL_PLANE_API_KEY)
        tunnel_id_present = -not [string]::IsNullOrWhiteSpace($env:CONTROL_PLANE_TUNNEL_ID)
        live_tunnel_qualified = $false
    } | ConvertTo-Json -Depth 6
}
finally {
    Pop-Location
}
