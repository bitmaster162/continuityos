# MCP Integration Guide

## What is MCP?

Model Context Protocol (MCP) is Anthropic's open standard for connecting AI assistants to external tools. ContinuityOS implements an MCP server that exposes 12 tools.

## Connecting to Hermes Agent

### Option A: CLI (recommended)
```bash
hermes mcp add continuityos \
  --command "python" \
  --args "/path/to/mcp_bridge.py"
```

### Option B: Config file
Add to `config.yaml`:
```yaml
mcp_servers:
  continuityos:
    command: python
    args:
      - /path/to/mcp_bridge.py
    enabled: true
```

After adding, restart Hermes or run `/reset`. Tools appear as `mcp_continuityos_*`.

## Connecting to Claude Desktop

Add to `claude_desktop_config.json`:
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

## Connecting to Cursor

Add to `.cursor/mcp.json`:
```json
{
  "servers": {
    "continuityos": {
      "command": "python",
      "args": ["/path/to/mcp_bridge.py"]
    }
  }
}
```

## Available Tools (12)

| Tool | Description |
|------|-------------|
| `remember` | Store a fact in memory |
| `recall` | Hybrid semantic + keyword search |
| `context` | Ready-to-inject context block |
| `forget` | Delete memory by ID |
| `list_namespaces` | List all memory folders |
| `checkpoint` | Close session with delta + next |
| `handoff` | Serialize state for agent transfer |
| `doctor` | Health check (8 invariants) |
| `set_frontier` | Change active focus area |
| `predict` | Digital twin: predict owner stance |
| `alignment` | Check action against canon |
| `preflight_action` | Gate: safety decision before action |

## Cross-Platform Bridge

`mcp_bridge.py` auto-detects the venv Python and launches the MCP server:

```bash
python mcp_bridge.py    # Works on Windows, Linux, macOS
```

The bridge passes `--db` to point at your memory database.

## Verification

```bash
# Test MCP server responds
echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' | \
  python mcp_bridge.py
# → {"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2024-11-05",...}}
```
