# MCP Integration Guide

## What is MCP?

Model Context Protocol (MCP) is an open protocol for connecting AI assistants to external tools and context providers. ContinuityOS ships an MCP stdio server. The authoritative tool inventory is the server's live `tools/list` response; do not pin documentation to a fixed tool count.

## Recommended v0.10 connection flow

Use the product connector first:

```bash
cos connect --status
cos connect claude --dry-run
cos connect claude --yes

# Cursor uses the same managed flow:
cos connect cursor --dry-run
cos connect cursor --yes
```

The managed flow:

- resolves the exact ContinuityOS memory DB;
- previews the client config before writing;
- preserves unrelated config keys;
- records rollback state and backs up an existing config;
- detects config drift between preview and write;
- verifies MCP `initialize` after the write;
- automatically rolls back if verification fails.

Use `cos connect <client> --rollback` to revert the last managed Claude/Cursor change when the config has not drifted since the write.

## Hermes Agent

Hermes is guidance-only in v0.10; ContinuityOS does not silently edit its config format.

```bash
cos connect hermes
```

The command prints the exact `hermes mcp add ...` command for the resolved ContinuityOS server and DB.

Manual fallback:

```bash
hermes mcp add continuityos \
  --command "python" \
  --args "/path/to/mcp_bridge.py"
```

Or add to `config.yaml`:

```yaml
mcp_servers:
  continuityos:
    command: python
    args:
      - /path/to/mcp_bridge.py
    enabled: true
```

After adding, restart Hermes or run `/reset`.

## Claude Desktop

Recommended:

```bash
cos connect claude --dry-run
cos connect claude --yes
```

Manual fallback uses the `mcpServers` object in `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "continuityos": {
      "command": "python",
      "args": ["/path/to/mcp_bridge.py"]
    }
  }
}
```

## Cursor

Recommended:

```bash
cos connect cursor --dry-run
cos connect cursor --yes
```

Manual fallback for `.cursor/mcp.json` also uses `mcpServers`:

```json
{
  "mcpServers": {
    "continuityos": {
      "command": "python",
      "args": ["/path/to/mcp_bridge.py"]
    }
  }
}
```

## Generic MCP client

```bash
cos connect generic-mcp
```

ContinuityOS prints a version-correct `mcpServers` snippet instead of guessing a client-specific config path.

## Available tools

Ask the running server:

```text
initialize
-> tools/list
```

The `tools/list` response is the source of truth for the installed version. Core capabilities include durable memory/recall plus continuity operations such as checkpoint, handoff, doctor, frontier management and governance-related checks; exact names may evolve between releases.

## Cross-platform bridge fallback

`mcp_bridge.py` auto-detects the environment and launches the MCP server:

```bash
python mcp_bridge.py
```

The bridge passes `--db` to point at the selected memory database.

## Verification

Managed `cos connect` performs MCP initialization verification automatically after a config write.

For a manual setup, you can probe the bridge directly:

```bash
echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' | \
  python mcp_bridge.py
```

A successful response contains a JSON-RPC result object for request id `1`.
