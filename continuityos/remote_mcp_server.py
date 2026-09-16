"""Governed Remote Commander extension for the ContinuityOS MCP server.

R1 intentionally adds only bounded read-only host inspection. Mutating command
execution is not reimplemented here: callers must use the inherited
``preflight_exec`` -> ``execute_preflight`` GateBroker path.

The remote surface is fail-closed. Enable it explicitly with
``CONTINUITYOS_REMOTE_ENABLED=1`` or ``--enable-remote`` and scope filesystem
access with ``CONTINUITYOS_REMOTE_ROOTS`` or one or more ``--remote-root``
arguments.
"""
from __future__ import annotations

import argparse
import fnmatch
import json
import os
import platform
from pathlib import Path
import socket
import sys
from typing import Iterable

from . import __version__
from .mcp_server import PROTOCOL, TOOLS as BASE_TOOLS, Server as BaseServer

MAX_READ_BYTES = 256 * 1024
MAX_LIST_ENTRIES = 500

_SENSITIVE_DIRS = {
    ".ssh",
    ".gnupg",
    ".aws",
    ".azure",
    ".kube",
}
_SENSITIVE_FILE_PATTERNS = (
    ".env",
    ".env.*",
    "*.pem",
    "*.key",
    "*.p12",
    "*.pfx",
    "id_rsa",
    "id_rsa.*",
    "id_ed25519",
    "id_ed25519.*",
    "credentials",
    "credentials.*",
    "secrets",
    "secrets.*",
)

REMOTE_TOOLS = [
    {
        "name": "capability_status",
        "description": (
            "Report the ContinuityOS Remote Commander capability boundary: "
            "enabled state, allowed roots, read limits, and governed execution path."
        ),
        "inputSchema": {"type": "object", "additionalProperties": False, "properties": {}},
    },
    {
        "name": "system_info",
        "description": (
            "Read-only host identity and runtime information. Does not return environment "
            "variables, credentials, or process contents."
        ),
        "inputSchema": {"type": "object", "additionalProperties": False, "properties": {}},
    },
    {
        "name": "fs_list",
        "description": (
            "List one directory inside an explicitly allowed remote root. Sensitive files "
            "and credential directories are omitted. Read-only."
        ),
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "path": {"type": "string", "default": "."},
                "limit": {"type": "integer", "minimum": 1, "maximum": MAX_LIST_ENTRIES, "default": 200},
            },
        },
    },
    {
        "name": "fs_read",
        "description": (
            "Read a bounded UTF-8 text file inside an explicitly allowed remote root. "
            "Known credential/key paths are denied. Read-only."
        ),
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "path": {"type": "string", "minLength": 1, "maxLength": 32768},
                "max_bytes": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": MAX_READ_BYTES,
                    "default": 65536,
                },
            },
            "required": ["path"],
        },
    },
]

TOOLS = [*BASE_TOOLS, *REMOTE_TOOLS]


def _env_enabled(value: str | None) -> bool:
    return (value or "").strip().lower() in {"1", "true", "yes", "on"}


def _canonical_roots(values: Iterable[str | os.PathLike[str]] | None) -> list[Path]:
    raw = list(values or [])
    if not raw:
        configured = os.environ.get("CONTINUITYOS_REMOTE_ROOTS", "")
        raw = [item for item in configured.split(os.pathsep) if item]
    if not raw:
        raw = [os.getcwd()]

    roots: list[Path] = []
    for value in raw:
        root = Path(value).expanduser().resolve(strict=True)
        if not root.is_dir():
            raise ValueError(f"remote root is not a directory: {root}")
        if root not in roots:
            roots.append(root)
    return roots


class RemoteSurface:
    """Fail-closed read-only host surface with root containment and secret denial."""

    def __init__(self, *, enabled: bool | None = None, roots: Iterable[str | os.PathLike[str]] | None = None):
        self.enabled = _env_enabled(os.environ.get("CONTINUITYOS_REMOTE_ENABLED")) if enabled is None else bool(enabled)
        self.roots = _canonical_roots(roots)

    def _require_enabled(self) -> None:
        if not self.enabled:
            raise PermissionError(
                "remote commander disabled; set CONTINUITYOS_REMOTE_ENABLED=1 or pass --enable-remote"
            )

    @staticmethod
    def _sensitive_reason(path: Path) -> str | None:
        lowered_parts = [part.lower() for part in path.parts]
        for part in lowered_parts:
            if part in _SENSITIVE_DIRS:
                return f"sensitive directory denied: {part}"
        name = path.name.lower()
        for pattern in _SENSITIVE_FILE_PATTERNS:
            if fnmatch.fnmatch(name, pattern):
                return f"sensitive file denied: {pattern}"
        return None

    def _resolve(self, value: str | os.PathLike[str]) -> Path:
        self._require_enabled()
        candidate = Path(value).expanduser()
        if not candidate.is_absolute():
            candidate = self.roots[0] / candidate
        resolved = candidate.resolve(strict=True)
        if not any(resolved == root or resolved.is_relative_to(root) for root in self.roots):
            raise PermissionError("path is outside configured remote roots")
        reason = self._sensitive_reason(resolved)
        if reason:
            raise PermissionError(reason)
        return resolved

    def status(self) -> dict:
        return {
            "enabled": self.enabled,
            "mode": "read_only_host_surface_plus_governed_exec",
            "roots": [str(root) for root in self.roots],
            "max_read_bytes": MAX_READ_BYTES,
            "max_list_entries": MAX_LIST_ENTRIES,
            "mutating_execution": {
                "direct_shell": False,
                "path": ["preflight_exec", "execute_preflight"],
                "governor": "ContinuityOS GateBroker",
            },
            "secret_policy": "deny known credential/key files and sensitive credential directories",
        }

    def system_info(self) -> dict:
        self._require_enabled()
        return {
            "hostname": socket.gethostname(),
            "platform": platform.system(),
            "platform_release": platform.release(),
            "machine": platform.machine(),
            "python": platform.python_version(),
            "cwd": os.getcwd(),
        }

    def list_dir(self, path: str = ".", *, limit: int = 200) -> dict:
        directory = self._resolve(path)
        if not directory.is_dir():
            raise NotADirectoryError(str(directory))
        if not isinstance(limit, int) or isinstance(limit, bool) or not (1 <= limit <= MAX_LIST_ENTRIES):
            raise ValueError(f"limit must be an integer in 1..{MAX_LIST_ENTRIES}")

        entries = []
        omitted_sensitive = 0
        for child in sorted(directory.iterdir(), key=lambda item: item.name.lower()):
            if self._sensitive_reason(child):
                omitted_sensitive += 1
                continue
            if len(entries) >= limit:
                break
            stat = child.lstat()
            if child.is_symlink():
                kind = "symlink"
            elif child.is_dir():
                kind = "directory"
            elif child.is_file():
                kind = "file"
            else:
                kind = "other"
            entries.append({"name": child.name, "type": kind, "size": stat.st_size})
        return {
            "path": str(directory),
            "entries": entries,
            "returned": len(entries),
            "limit": limit,
            "omitted_sensitive": omitted_sensitive,
        }

    def read_text(self, path: str, *, max_bytes: int = 65536) -> dict:
        target = self._resolve(path)
        if not target.is_file():
            raise FileNotFoundError(f"not a regular file: {target}")
        if not isinstance(max_bytes, int) or isinstance(max_bytes, bool) or not (1 <= max_bytes <= MAX_READ_BYTES):
            raise ValueError(f"max_bytes must be an integer in 1..{MAX_READ_BYTES}")

        with target.open("rb") as handle:
            data = handle.read(max_bytes + 1)
        truncated = len(data) > max_bytes
        data = data[:max_bytes]
        if b"\x00" in data:
            raise ValueError("binary file refused")
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("non-UTF-8 file refused") from exc
        return {
            "path": str(target),
            "text": text,
            "bytes": len(data),
            "truncated": truncated,
        }


class RemoteServer(BaseServer):
    def __init__(self, db=None, policy_path: str = "", db_source: str = "", *, remote_enabled: bool | None = None, remote_roots=None):
        super().__init__(db, policy_path, db_source)
        self.remote = RemoteSurface(enabled=remote_enabled, roots=remote_roots)

    def call(self, name, args):
        if name == "capability_status":
            self.turns += 1
            return json.dumps(self.remote.status(), ensure_ascii=False, indent=2)
        if name == "system_info":
            self.turns += 1
            return json.dumps(self.remote.system_info(), ensure_ascii=False, indent=2)
        if name == "fs_list":
            self.turns += 1
            return json.dumps(
                self.remote.list_dir(args.get("path", "."), limit=args.get("limit", 200)),
                ensure_ascii=False,
                indent=2,
            )
        if name == "fs_read":
            self.turns += 1
            return json.dumps(
                self.remote.read_text(args["path"], max_bytes=args.get("max_bytes", 65536)),
                ensure_ascii=False,
                indent=2,
            )
        return super().call(name, args)


def _send(obj) -> None:
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", default=None)
    parser.add_argument("--policy", default="", help="Path to one JSON policy, or YAML when PyYAML is installed")
    parser.add_argument("--enable-remote", action="store_true", default=None)
    parser.add_argument(
        "--remote-root",
        action="append",
        default=None,
        help="Allowed read-only filesystem root; repeat for multiple roots.",
    )
    args = parser.parse_args()
    server = RemoteServer(
        args.db,
        args.policy,
        remote_enabled=args.enable_remote,
        remote_roots=args.remote_root,
    )

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            request = json.loads(line)
        except Exception:
            continue
        message_id = request.get("id")
        method = request.get("method")
        if method == "initialize":
            _send(
                {
                    "jsonrpc": "2.0",
                    "id": message_id,
                    "result": {
                        "protocolVersion": PROTOCOL,
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": "continuityos-remote", "version": __version__},
                    },
                }
            )
        elif method == "notifications/initialized":
            continue
        elif method == "tools/list":
            _send({"jsonrpc": "2.0", "id": message_id, "result": {"tools": TOOLS}})
        elif method == "tools/call":
            params = request.get("params", {}) or {}
            try:
                output = server.call(params.get("name"), params.get("arguments", {}) or {})
                _send(
                    {
                        "jsonrpc": "2.0",
                        "id": message_id,
                        "result": {"content": [{"type": "text", "text": str(output)}]},
                    }
                )
            except Exception as exc:
                _send(
                    {
                        "jsonrpc": "2.0",
                        "id": message_id,
                        "result": {
                            "isError": True,
                            "content": [{"type": "text", "text": f"error: {exc}"}],
                        },
                    }
                )
        elif method == "ping":
            _send({"jsonrpc": "2.0", "id": message_id, "result": {}})
        elif message_id is not None:
            _send(
                {
                    "jsonrpc": "2.0",
                    "id": message_id,
                    "error": {"code": -32601, "message": f"method not found: {method}"},
                }
            )


if __name__ == "__main__":
    main()
