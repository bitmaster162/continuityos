# `cos connect` — connect ContinuityOS to an AI client

`cos connect` is the product onboarding surface for wiring the same local ContinuityOS memory into MCP-capable clients.

The command is intentionally conservative:

- previews the exact config before a write (`--dry-run`);
- preserves unrelated client configuration;
- creates an exact backup before replacing an existing JSON config;
- records the post-write hash for fail-closed rollback;
- refuses rollback if the client config changed afterward;
- verifies the ContinuityOS MCP server with an `initialize` request after a write;
- automatically restores the pre-connect config if MCP verification fails;
- remains blocked inside a verified R64 READ_ONLY current session by the same `cos` containment gate as other product entrypoints.

## Status

```bash
cos connect --status
cos connect claude --status
cos connect cursor --status
```

Machine-readable output:

```bash
cos connect --status --json
```

## Preview

Claude Desktop:

```bash
cos connect claude --dry-run
```

Cursor (project-local `.cursor/mcp.json`):

```bash
cos connect cursor --dry-run
```

Use another memory database explicitly:

```bash
cos --db /path/to/memory.db connect claude --dry-run
# equivalent:
cos connect claude --db /path/to/memory.db --dry-run
```

Override the client config path when needed:

```bash
cos connect claude --config /path/to/claude_desktop_config.json --dry-run
```

## Apply

Interactive terminals ask before changing the client config:

```bash
cos connect claude
cos connect cursor
```

Non-interactive scripts must opt in explicitly:

```bash
cos connect claude --yes
```

After a successful write, ContinuityOS starts its MCP server locally and sends a JSON-RPC `initialize` request. A successful connection ends with:

```text
COS_CONNECT_PASS: CONFIG_WRITTEN_AND_MCP_VERIFIED
```

If verification fails, the connector restores the exact pre-connect config automatically and returns `COS_CONNECT_VERIFY_HOLD`.

## Rollback

```bash
cos connect claude --rollback
cos connect cursor --rollback
```

Rollback is hash-bound to the config written by the connector. If the file changed after connection, rollback stops with `CONFIG_DRIFTED_SINCE_CONNECT` instead of overwriting the user's newer edits.

## Client behavior

### Claude Desktop

Managed JSON configuration:

- Windows: `%APPDATA%\Claude\claude_desktop_config.json`
- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Linux fallback: `~/.config/Claude/claude_desktop_config.json`

Environment override: `CONTINUITYOS_CLAUDE_CONFIG`.

### Cursor

Managed project-local JSON configuration:

```text
.cursor/mcp.json
```

Environment override: `CONTINUITYOS_CURSOR_CONFIG`.

### Hermes

`cos connect hermes` currently emits the exact `hermes mcp add ...` command instead of rewriting YAML configuration. This keeps the core stdlib-only and avoids destructive YAML round-trips.

### Generic MCP

`cos connect generic-mcp` prints a ready-to-copy MCP server configuration snippet.

## MCP server binding

Managed JSON clients receive an entry equivalent to:

```json
{
  "command": "/absolute/path/to/python",
  "args": [
    "-m",
    "continuityos.mcp_server",
    "--db",
    "/absolute/path/to/memory.db"
  ]
}
```

The exact Python executable and memory database path are canonicalized before being written.
