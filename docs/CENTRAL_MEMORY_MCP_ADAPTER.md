# R6.1 MCP Adapter — status-only

Only one read-only tool: agent_view_status. It reads the two bounded JSON files from a local R6.1 agent_view folder and returns DENY status, count and SHA-256. No write, memory, gate or execution tools. No canonical SQLite access, client wiring, merge or deployment. Legacy MCP is unchanged. Run tests: python -m pytest -q tests/test_central_memory_mcp_adapter.py.
