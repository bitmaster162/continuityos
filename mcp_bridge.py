#!/usr/bin/env python3
"""ContinuityOS MCP Bridge — cross-platform launcher.

Replaces mcp_bridge.bat. Works on Windows, Linux, macOS.
Auto-detects venv python, launches MCP server with correct DB path.
"""
import os
import sys

# Resolve paths relative to this file's location
HERE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(HERE, "hermes_memory.db")

# On Windows: .venv/Scripts/python.exe; on Linux/macOS: .venv/bin/python
if sys.platform == "win32":
    VENV_PYTHON = os.path.join(HERE, ".venv", "Scripts", "python.exe")
else:
    VENV_PYTHON = os.path.join(HERE, ".venv", "bin", "python")

# If venv python doesn't exist, use current interpreter
if not os.path.exists(VENV_PYTHON):
    VENV_PYTHON = sys.executable

if __name__ == "__main__":
    # Re-exec with venv python if we're not already in it
    if os.path.normpath(sys.executable) != os.path.normpath(VENV_PYTHON):
        os.execv(VENV_PYTHON, [
            VENV_PYTHON, "-m", "continuityos.mcp_server",
            "--db", DB_PATH
        ])
    else:
        # Already in venv, run directly
        from continuityos.mcp_server import main
        sys.argv = ["mcp_server", "--db", DB_PATH]
        main()
