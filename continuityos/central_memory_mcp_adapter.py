"""Offline, read-only R6.1 agent_view status adapter. No core/database access."""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

from . import __version__
PROTOCOL = "2024-11-05"  # Pinned protocol; no import of legacy MCP modules.

POLICY_SCHEMA = "central-memory.r2.agent-safepolicy-r61/v1"
RECEIPT_SCHEMA = "central-memory.r2.r61.offline-review-receipt/v1"
STATUS_SCHEMA = "continuityos.central_memory_agent_view_status/v1"
MAX_FILE_BYTES = 131_072
TOOLS = (
    {
        "name": "agent_view_status",
        "description": "Offline R6.1 integrity and DENY-status readback only; grants no memory or effect access.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
)
_ALLOWED = frozenset(tool["name"] for tool in TOOLS)


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("DUPLICATE_JSON_FIELD")
        result[key] = value
    return result


def _load_json(path: Path) -> tuple[dict[str, Any], str]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("AGENT_VIEW_FILE_MISSING_OR_LINKED")
    if path.stat().st_size > MAX_FILE_BYTES:
        raise ValueError("AGENT_VIEW_FILE_TOO_LARGE")
    raw = path.read_bytes()
    if len(raw) > MAX_FILE_BYTES:
        raise ValueError("AGENT_VIEW_FILE_TOO_LARGE")
    try:
        data = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("AGENT_VIEW_INVALID_JSON") from exc
    if not isinstance(data, dict):
        raise ValueError("AGENT_VIEW_INVALID_OBJECT")
    return data, hashlib.sha256(raw).hexdigest()


class CentralMemoryMCPAdapter:
    """Status-only MCP surface. NEVER delegates into the legacy MCP server."""

    def __init__(self, agent_view: str):
        self._root = Path(agent_view).expanduser()

    def call(self, name: str, arguments: Any) -> str:
        if name not in _ALLOWED:
            raise PermissionError("TOOL_NOT_EXPOSED_BY_CENTRAL_MEMORY_ADAPTER")
        if arguments != {}:
            raise ValueError("STATUS_TAKES_NO_ARGUMENTS")
        if self._root.name != "agent_view" or self._root.is_symlink() or not self._root.is_dir():
            raise ValueError("AGENT_VIEW_DIRECTORY_INVALID")

        policy, digest = _load_json(self._root / "AGENT_POLICY_R61.json")
        receipt, _ = _load_json(self._root / "R61_LOCAL_REVIEW_RECEIPT.json")
        if policy.get("schema") != POLICY_SCHEMA or receipt.get("schema") != RECEIPT_SCHEMA:
            raise ValueError("AGENT_VIEW_SCHEMA_MISMATCH")
        if digest != receipt.get("projection_sha256"):
            raise ValueError("AGENT_VIEW_SHA256_MISMATCH")
        if (policy.get("agent_access") != "DENY"
                or policy.get("effect_authority") != "NONE"
                or policy.get("release_status") != "OFFLINE_DRAFT_NOT_DEPLOYED"
                or policy.get("clients_connected") is not False
                or receipt.get("client_connected") is not False
                or receipt.get("owner_sqlite_changed") is not False):
            raise PermissionError("R61_ADMISSION_GUARD_FAILED")
        sources = receipt.get("sources")
        bindings = policy.get("source_binding")
        if not isinstance(sources, dict) or not isinstance(bindings, dict):
            raise ValueError("AGENT_VIEW_PROVENANCE_INVALID")
        if set(sources) != {"rozi", "shaytan", "sharmanka"} or set(bindings) != set(sources):
            raise ValueError("AGENT_VIEW_PROVENANCE_INVALID")
        for source in sources:
            if not isinstance(sources[source], dict) or not isinstance(bindings[source], dict):
                raise ValueError("AGENT_VIEW_PROVENANCE_INVALID")
            if sources[source].get("sha256") != bindings[source].get("sha256"):
                raise ValueError("AGENT_VIEW_PROVENANCE_MISMATCH")
        policies = policy.get("policies")
        if not isinstance(policies, list) or len(policies) != 10:
            raise ValueError("AGENT_VIEW_POLICY_COUNT_INVALID")
        result = {
            "schema": STATUS_SCHEMA,
            "agent_access": "DENY",
            "effect_authority": "NONE",
            "release_status": "OFFLINE_DRAFT_NOT_DEPLOYED",
            "canonical_truth_promoted": False,
            "clients_connected": False,
            "policy_count": len(policies),
            "projection_sha256": digest,
        }
        return json.dumps(result, sort_keys=True, separators=(",", ":"))


def _send(response: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(response, ensure_ascii=False) + "\n")
    sys.stdout.flush()


def main() -> None:
    parser = argparse.ArgumentParser(description="R6.1 DENY-status adapter: no core DB or effects")
    parser.add_argument("--agent-view", required=True, help="Local R6.1 agent_view directory only")
    args = parser.parse_args()
    adapter = CentralMemoryMCPAdapter(args.agent_view)
    for raw in sys.stdin:
        if len(raw) > MAX_FILE_BYTES:
            continue
        try:
            req = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if not isinstance(req, dict):
            continue
        mid, method = req.get("id"), req.get("method")
        if method == "initialize":
            _send({"jsonrpc": "2.0", "id": mid, "result": {
                "protocolVersion": PROTOCOL, "capabilities": {"tools": {}},
                "serverInfo": {"name": "continuityos-r61-status-only", "version": __version__}}})
        elif method == "notifications/initialized":
            continue
        elif method == "tools/list":
            _send({"jsonrpc": "2.0", "id": mid, "result": {"tools": TOOLS}})
        elif method == "tools/call":
            p = req.get("params", {})
            if not isinstance(p, dict):
                p = {}
            try:
                result = adapter.call(p.get("name"), p.get("arguments", {}))
                _send({"jsonrpc": "2.0", "id": mid, "result": {
                    "content": [{"type": "text", "text": result}]}})
            except Exception as exc:
                _send({"jsonrpc": "2.0", "id": mid, "result": {
                    "isError": True, "content": [{"type": "text",
                    "text": f"{type(exc).__name__}: {exc}"}]}})
        elif method == "ping":
            _send({"jsonrpc": "2.0", "id": mid, "result": {}})
        elif mid is not None:
            _send({"jsonrpc": "2.0", "id": mid, "error": {
                "code": -32601, "message": "method not found"}})


if __name__ == "__main__":
    main()
