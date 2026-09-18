# ContinuityOS Remote Commander R1

## Purpose

R1 extends the existing ContinuityOS MCP server with a fail-closed, bounded,
read-only host inspection surface. It deliberately does **not** add a second
shell implementation.

The existing ContinuityOS execution path remains authoritative for mutating
commands:

`preflight_exec -> GateBroker -> execute_preflight`

This preserves policy evaluation, durable request identity, witness validation,
and execution receipts instead of creating an ungoverned subprocess bypass.

## R1 tools

- `capability_status` — reports the effective boundary and allowed roots.
- `system_info` — OS/runtime identity only; no environment-variable dump.
- `fs_list` — bounded directory listing inside configured roots.
- `fs_read` — bounded UTF-8 text reads inside configured roots.
- Existing `preflight_exec` / `execute_preflight` — the only mutation-capable
  command path exposed by this extension.

## Fail-closed defaults

Remote host inspection is disabled unless explicitly enabled.

PowerShell example:

```powershell
$env:CONTINUITYOS_REMOTE_ENABLED = "1"
$env:CONTINUITYOS_REMOTE_ROOTS = "C:\Repos;C:\Work"
python -m continuityos.remote_mcp_server --db "$HOME\.continuityos\memory.db"
```

Equivalent CLI configuration:

```powershell
python -m continuityos.remote_mcp_server `
  --enable-remote `
  --remote-root C:\Repos `
  --remote-root C:\Work `
  --db "$HOME\.continuityos\memory.db"
```

If no root is configured, the process working directory is the only root. A
path must resolve inside one configured root. Symlink/path traversal that
resolves outside the roots is denied.

## Secret boundary

R1 refuses known credential/key locations and file patterns, including common
SSH/GPG/cloud credential directories, `.env*`, private-key formats, and
credential/secret files. Reads are UTF-8 text only and capped at 256 KiB.
Directory listings are capped at 500 entries and omit sensitive entries.

This is defense in depth, not a claim that file-name filtering can classify all
secrets. Remote roots should therefore be narrow and purpose-specific.

## Transport boundary

R1 is a **stdio MCP extension**. It prepares the governed host-side capability
but does not expose a public network listener and does not open an inbound port.

The next transport layer should use an outbound authenticated tunnel/agent to a
remote MCP endpoint suitable for ChatGPT. Authentication material must not be
stored in the repository. The remote endpoint must preserve the same tool
boundary and must not introduce a direct shell route around GateBroker.

## Baseline evidence

- Repository: `bitmaster162/continuityos`
- Baseline branch: `master`
- Baseline commit: `502df1efe0741f9681b7a2cb7988240113bda266`
- Implementation branch: `agent/r23-remote-commander-mcp-r1`

No change in this R1 is intended to modify `master` directly.
