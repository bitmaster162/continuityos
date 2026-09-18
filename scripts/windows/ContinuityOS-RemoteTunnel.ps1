[CmdletBinding()]
param(
    [ValidateSet("Plan", "Init", "Doctor", "Run")]
    [string]$Mode = "Plan",

    [string]$TunnelId = $env:CONTROL_PLANE_TUNNEL_ID,
    [string]$Profile = "continuityos-remote",
    [string]$RemoteRoot = (Get-Location).Path,
    [string]$TunnelClient = "tunnel-client",
    [string]$Python = "python"
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

function Require-ControlPlaneKey {
    if ([string]::IsNullOrWhiteSpace($env:CONTROL_PLANE_API_KEY)) {
        throw "CONTROL_PLANE_API_KEY must be supplied through the process environment."
    }
}

function Validate-TunnelId {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) {
        throw "TunnelId is required for Init."
    }
    if ($Value -notmatch '^tunnel_[0-9a-f]{32}$') {
        throw "TunnelId has an invalid format."
    }
}

if (
    [string]::IsNullOrWhiteSpace($Profile) -or
    $Profile.Length -gt 64 -or
    $Profile -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]*$'
) {
    throw "Profile has an invalid format."
}

$pythonExe = Require-Command -Name $Python
$root = (Resolve-Path -LiteralPath $RemoteRoot).Path
if (-not (Test-Path -LiteralPath $root -PathType Container)) {
    throw "RemoteRoot must be an existing directory."
}

# The child MCP is deliberately fixed. No arbitrary shell text is accepted.
# The Pro profile is enforced again inside remote_mcp_server for both tools/list
# and tools/call; the tunnel is transport only.
$quotedPython = '"' + $pythonExe.Replace('"', '""') + '"'
$quotedRoot = '"' + $root.Replace('"', '""') + '"'
$mcpCommand = (
    $quotedPython +
    " -m continuityos.remote_mcp_server" +
    " --enable-remote" +
    " --tool-profile chatgpt-pro-readonly" +
    " --remote-root " + $quotedRoot
)

$plan = [ordered]@{
    schema = "continuityos.remote_tunnel_plan/v1"
    mode = $Mode
    profile = $Profile
    tunnel_id_present = -not [string]::IsNullOrWhiteSpace($TunnelId)
    control_plane_key_present = -not [string]::IsNullOrWhiteSpace($env:CONTROL_PLANE_API_KEY)
    remote_root = $root
    python = $pythonExe
    mcp_transport = "stdio"
    mcp_tool_profile = "chatgpt-pro-readonly"
    public_mcp_listener = $false
    health_listener = "127.0.0.1:8080"
    health_listener_scope = "loopback"
    direct_shell = $false
}

if ($Mode -eq "Plan") {
    $plan | ConvertTo-Json -Depth 4
    exit 0
}

$tunnelExe = Require-Command -Name $TunnelClient
Require-ControlPlaneKey

switch ($Mode) {
    "Init" {
        Validate-TunnelId -Value $TunnelId
        & $tunnelExe init `
            --sample sample_mcp_stdio_local `
            --profile $Profile `
            --tunnel-id $TunnelId `
            --health-listen-addr 127.0.0.1:8080 `
            --mcp-command $mcpCommand
        if ($LASTEXITCODE -ne 0) {
            throw "tunnel-client init failed with exit code $LASTEXITCODE"
        }
    }
    "Doctor" {
        & $tunnelExe doctor --profile $Profile --explain
        if ($LASTEXITCODE -ne 0) {
            throw "tunnel-client doctor failed with exit code $LASTEXITCODE"
        }
    }
    "Run" {
        & $tunnelExe run --profile $Profile
        if ($LASTEXITCODE -ne 0) {
            throw "tunnel-client run failed with exit code $LASTEXITCODE"
        }
    }
}
