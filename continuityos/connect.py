"""Safe product onboarding for MCP-capable AI clients.

`cos connect` is an ordinary product surface. It is routed through
`current_entrypoints.cos_main`, so verified current sessions still receive the
same fail-closed R64 containment as every other `cos` command.

The connector edits only the selected client configuration, preserves unrelated
keys, writes an exact backup before replacing an existing file, records enough
local state for fail-closed rollback, and verifies the ContinuityOS MCP server
after a successful write.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from typing import Any, Mapping, Sequence

from .db import resolve_memory_db

SCHEMA = "continuityos.product_connect/v1"
STATE_SCHEMA = "continuityos.product_connect_state/v1"
SERVER_NAME = "continuityos"
SUPPORTED_CLIENTS = ("claude", "cursor", "hermes", "generic-mcp")


def _utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: Path) -> str:
    return _sha256_bytes(path.read_bytes())


def _json_bytes(value: Mapping[str, Any]) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _canonical_path(path: str | Path) -> str:
    return os.path.normcase(os.path.realpath(os.path.abspath(os.path.expanduser(str(path)))))


def _state_path(home: Path | None = None) -> Path:
    base = home if home is not None else Path.home()
    return base / ".continuityos" / "connect_state.json"


def _load_state(home: Path | None = None) -> dict[str, Any]:
    path = _state_path(home)
    if not path.exists():
        return {"schema": STATE_SCHEMA, "clients": {}}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise ValueError(f"connect state is not valid JSON: {path}: {exc}") from exc
    if not isinstance(value, dict) or not isinstance(value.get("clients", {}), dict):
        raise ValueError(f"connect state has invalid shape: {path}")
    value.setdefault("schema", STATE_SCHEMA)
    value.setdefault("clients", {})
    return value


def _atomic_write_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=str(path.parent))
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    finally:
        try:
            tmp.unlink()
        except FileNotFoundError:
            pass


def _save_state(state: Mapping[str, Any], home: Path | None = None) -> None:
    _atomic_write_bytes(_state_path(home), _json_bytes(dict(state)))


def _client_config_path(
    client: str,
    *,
    config_override: str | None = None,
    environ: Mapping[str, str] | None = None,
    home: Path | None = None,
    cwd: Path | None = None,
    platform: str | None = None,
) -> Path | None:
    if config_override:
        return Path(_canonical_path(config_override))
    env = os.environ if environ is None else environ
    base_home = home if home is not None else Path.home()
    here = cwd if cwd is not None else Path.cwd()
    plat = sys.platform if platform is None else platform

    if client == "claude":
        override = env.get("CONTINUITYOS_CLAUDE_CONFIG")
        if override:
            return Path(_canonical_path(override))
        if plat == "win32" or env.get("APPDATA"):
            appdata = env.get("APPDATA")
            if appdata:
                return Path(_canonical_path(Path(appdata) / "Claude" / "claude_desktop_config.json"))
        if plat == "darwin":
            return Path(_canonical_path(base_home / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json"))
        return Path(_canonical_path(base_home / ".config" / "Claude" / "claude_desktop_config.json"))

    if client == "cursor":
        override = env.get("CONTINUITYOS_CURSOR_CONFIG")
        if override:
            return Path(_canonical_path(override))
        return Path(_canonical_path(here / ".cursor" / "mcp.json"))

    return None


def _server_spec(db_path: str, python_executable: str | None = None) -> dict[str, Any]:
    return {
        "command": _canonical_path(python_executable or sys.executable),
        "args": ["-m", "continuityos.mcp_server", "--db", _canonical_path(db_path)],
    }


def _config_key(client: str) -> str:
    if client == "claude":
        return "mcpServers"
    if client == "cursor":
        return "servers"
    raise ValueError(f"client does not use managed JSON config: {client}")


def _load_json_config(path: Path) -> tuple[dict[str, Any], bool]:
    if not path.exists():
        return {}, False
    if not path.is_file():
        raise ValueError(f"config path is not a file: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise ValueError(f"client config is not valid JSON: {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"client config root must be a JSON object: {path}")
    return value, True


def _patched_config(client: str, original: Mapping[str, Any], server: Mapping[str, Any]) -> dict[str, Any]:
    result = copy.deepcopy(dict(original))
    key = _config_key(client)
    section = result.get(key)
    if section is None:
        section = {}
    if not isinstance(section, dict):
        raise ValueError(f"{key} must be a JSON object")
    section = copy.deepcopy(section)
    section[SERVER_NAME] = copy.deepcopy(dict(server))
    result[key] = section
    return result


def _status_managed(client: str, config_path: Path, server: Mapping[str, Any]) -> dict[str, Any]:
    try:
        config, exists = _load_json_config(config_path)
    except Exception as exc:
        return {
            "client": client,
            "managed": True,
            "config_path": str(config_path),
            "config_exists": config_path.exists(),
            "configured": False,
            "connected": False,
            "drift": True,
            "error": f"{type(exc).__name__}: {exc}",
        }
    key = _config_key(client)
    section = config.get(key)
    entry = section.get(SERVER_NAME) if isinstance(section, dict) else None
    configured = isinstance(entry, dict)
    connected = configured and entry == dict(server)
    return {
        "client": client,
        "managed": True,
        "config_path": str(config_path),
        "config_exists": exists,
        "configured": configured,
        "connected": connected,
        "drift": configured and not connected,
        "server": entry if configured else None,
    }


def _manual_receipt(client: str, server: Mapping[str, Any]) -> dict[str, Any]:
    if client == "hermes":
        args = " ".join(json.dumps(x) for x in server["args"])
        command = f'hermes mcp add {SERVER_NAME} --command {json.dumps(server["command"])} --args {json.dumps(args)}'
        return {
            "client": client,
            "managed": False,
            "connected": False,
            "reason": "MANUAL_COMMAND_REQUIRED",
            "manual_command": command,
            "server": dict(server),
        }
    return {
        "client": client,
        "managed": False,
        "connected": False,
        "reason": "MANUAL_CONFIG_REQUIRED",
        "config_snippet": {"mcpServers": {SERVER_NAME: dict(server)}},
    }


def _verify_mcp(db_path: str, *, timeout: float = 5.0) -> dict[str, Any]:
    command = [
        sys.executable,
        "-m",
        "continuityos.mcp_server",
        "--db",
        _canonical_path(db_path),
    ]
    request = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
    try:
        completed = subprocess.run(
            command,
            input=request + "\n",
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
        )
    except Exception as exc:
        return {
            "verified": False,
            "reason": "MCP_SUBPROCESS_FAILED",
            "error": f"{type(exc).__name__}: {exc}",
            "command": command,
        }

    response = None
    for line in completed.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            candidate = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(candidate, dict) and candidate.get("id") == 1:
            response = candidate
            break
    ok = (
        completed.returncode == 0
        and isinstance(response, dict)
        and isinstance(response.get("result"), dict)
    )
    return {
        "verified": ok,
        "reason": "MCP_INITIALIZE_PASS" if ok else "MCP_INITIALIZE_FAILED",
        "returncode": completed.returncode,
        "response": response,
        "stderr": completed.stderr[-2000:],
        "command": command,
    }


def _preview(
    client: str,
    *,
    db_path: str,
    config_path: Path | None,
    server: Mapping[str, Any],
) -> dict[str, Any]:
    if client not in {"claude", "cursor"}:
        return _manual_receipt(client, server)
    assert config_path is not None
    original, existed = _load_json_config(config_path)
    patched = _patched_config(client, original, server)
    old_bytes = config_path.read_bytes() if existed else b""
    new_bytes = _json_bytes(patched)
    return {
        "client": client,
        "managed": True,
        "config_path": str(config_path),
        "config_exists": existed,
        "would_change": (not existed) or old_bytes != new_bytes,
        "before_sha256": _sha256_bytes(old_bytes) if existed else None,
        "after_sha256": _sha256_bytes(new_bytes),
        "memory_db": db_path,
        "server": dict(server),
        "patched_config": patched,
    }


def _record_write_state(
    *,
    client: str,
    config_path: Path,
    previous_exists: bool,
    backup_path: Path | None,
    before_sha256: str | None,
    after_sha256: str,
    home: Path | None = None,
) -> None:
    state = _load_state(home)
    state["clients"][client] = {
        "config_path": str(config_path),
        "previous_exists": previous_exists,
        "backup_path": str(backup_path) if backup_path else None,
        "before_sha256": before_sha256,
        "after_sha256": after_sha256,
        "recorded_at": datetime.now(timezone.utc).isoformat(),
    }
    _save_state(state, home)


def _rollback(client: str, *, home: Path | None = None) -> dict[str, Any]:
    state = _load_state(home)
    record = state.get("clients", {}).get(client)
    if not isinstance(record, dict):
        return {
            "terminal": "COS_CONNECT_ROLLBACK_HOLD",
            "reason": "NO_ROLLBACK_RECORD",
            "client": client,
        }
    config_path = Path(record["config_path"])
    expected_after = record.get("after_sha256")
    if not config_path.exists():
        return {
            "terminal": "COS_CONNECT_ROLLBACK_HOLD",
            "reason": "CONFIG_MISSING_SINCE_CONNECT",
            "client": client,
            "config_path": str(config_path),
        }
    actual = _sha256_file(config_path)
    if actual != expected_after:
        return {
            "terminal": "COS_CONNECT_ROLLBACK_HOLD",
            "reason": "CONFIG_DRIFTED_SINCE_CONNECT",
            "client": client,
            "config_path": str(config_path),
            "expected_sha256": expected_after,
            "actual_sha256": actual,
        }

    if record.get("previous_exists"):
        backup_raw = record.get("backup_path")
        backup = Path(backup_raw) if backup_raw else None
        if backup is None or not backup.exists():
            return {
                "terminal": "COS_CONNECT_ROLLBACK_HOLD",
                "reason": "BACKUP_MISSING",
                "client": client,
                "backup_path": backup_raw,
            }
        _atomic_write_bytes(config_path, backup.read_bytes())
        action = "RESTORED_BACKUP"
    else:
        config_path.unlink()
        action = "REMOVED_CREATED_CONFIG"

    state["clients"].pop(client, None)
    _save_state(state, home)
    return {
        "terminal": "COS_CONNECT_ROLLBACK_PASS",
        "reason": action,
        "client": client,
        "config_path": str(config_path),
    }


def _emit(value: Mapping[str, Any], *, as_json: bool) -> None:
    if as_json:
        print(json.dumps(dict(value), ensure_ascii=False, sort_keys=True, separators=(",", ":")))
        return
    terminal = value.get("terminal")
    if terminal:
        print(f"{terminal}: {value.get('reason', '')}")
    if value.get("client"):
        print(f"client: {value['client']}")
    if value.get("memory_db"):
        print(f"memory: {value['memory_db']}")
    if value.get("config_path"):
        print(f"config: {value['config_path']}")
    if value.get("backup_path"):
        print(f"backup: {value['backup_path']}")
    if value.get("manual_command"):
        print(f"run: {value['manual_command']}")
    if value.get("config_snippet"):
        print(json.dumps(value["config_snippet"], ensure_ascii=False, indent=2))
    if "connected" in value:
        print(f"connected: {str(bool(value['connected'])).lower()}")
    if "verified" in value:
        print(f"mcp verified: {str(bool(value['verified'])).lower()}")


def _confirm(client: str, config_path: Path) -> bool:
    if not sys.stdin.isatty():
        return False
    try:
        answer = input(f"Write ContinuityOS MCP config for {client} to {config_path}? [y/N] ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        return False
    return answer in {"y", "yes"}


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="cos connect",
        description="Connect ContinuityOS memory to an MCP-capable AI client.",
    )
    parser.add_argument("client", nargs="?", choices=SUPPORTED_CLIENTS)
    parser.add_argument("--db", default=None, help="memory DB (default: CONTINUITYOS_DB or ~/.continuityos/memory.db)")
    parser.add_argument("--config", default=None, help="override selected client config path")
    parser.add_argument("--status", action="store_true", help="show connection status")
    parser.add_argument("--dry-run", action="store_true", help="preview exact config, write nothing")
    parser.add_argument("--yes", action="store_true", help="apply without interactive confirmation")
    parser.add_argument("--rollback", action="store_true", help="restore the exact pre-connect config")
    parser.add_argument("--json", dest="as_json", action="store_true", help="machine-readable output")
    args = parser.parse_args(list(argv) if argv is not None else None)

    try:
        db_path = resolve_memory_db(args.db)["path"]
    except Exception as exc:
        receipt = {
            "schema": SCHEMA,
            "terminal": "COS_CONNECT_HOLD",
            "reason": "MEMORY_DB_RESOLUTION_FAILED",
            "error": f"{type(exc).__name__}: {exc}",
        }
        _emit(receipt, as_json=args.as_json)
        return 2

    server = _server_spec(db_path)

    if args.rollback:
        if not args.client or args.client not in {"claude", "cursor"}:
            receipt = {
                "schema": SCHEMA,
                "terminal": "COS_CONNECT_ROLLBACK_HOLD",
                "reason": "ROLLBACK_REQUIRES_MANAGED_CLIENT",
            }
            _emit(receipt, as_json=args.as_json)
            return 2
        receipt = {"schema": SCHEMA, **_rollback(args.client)}
        _emit(receipt, as_json=args.as_json)
        return 0 if receipt["terminal"].endswith("_PASS") else 2

    if args.status or args.client is None:
        clients = [args.client] if args.client else list(SUPPORTED_CLIENTS)
        statuses = []
        for client in clients:
            path = _client_config_path(client, config_override=args.config if len(clients) == 1 else None)
            if client in {"claude", "cursor"}:
                assert path is not None
                statuses.append(_status_managed(client, path, server))
            else:
                statuses.append(_manual_receipt(client, server))
        receipt = {
            "schema": SCHEMA,
            "terminal": "COS_CONNECT_STATUS_PASS",
            "reason": "STATUS_ONLY",
            "memory_db": db_path,
            "clients": statuses,
        }
        if args.as_json:
            _emit(receipt, as_json=True)
        else:
            print(f"memory: {db_path}")
            for status in statuses:
                print(
                    f"{status['client']}: "
                    + ("CONNECTED" if status.get("connected") else status.get("reason", "NOT_CONNECTED"))
                )
                if status.get("config_path"):
                    print(f"  config: {status['config_path']}")
                if status.get("manual_command"):
                    print(f"  run: {status['manual_command']}")
        return 0

    client = args.client
    path = _client_config_path(client, config_override=args.config)
    try:
        preview = _preview(client, db_path=db_path, config_path=path, server=server)
    except Exception as exc:
        receipt = {
            "schema": SCHEMA,
            "terminal": "COS_CONNECT_HOLD",
            "reason": "CONFIG_PREVIEW_FAILED",
            "client": client,
            "memory_db": db_path,
            "error": f"{type(exc).__name__}: {exc}",
        }
        _emit(receipt, as_json=args.as_json)
        return 2

    if not preview.get("managed"):
        receipt = {
            "schema": SCHEMA,
            "terminal": "COS_CONNECT_GUIDANCE_PASS",
            "reason": preview.get("reason"),
            "memory_db": db_path,
            **preview,
        }
        _emit(receipt, as_json=args.as_json)
        return 0

    if args.dry_run:
        receipt = {
            "schema": SCHEMA,
            "terminal": "COS_CONNECT_DRY_RUN_PASS",
            "reason": "PREVIEW_ONLY",
            **preview,
        }
        _emit(receipt, as_json=args.as_json)
        if not args.as_json:
            print(json.dumps(preview["patched_config"], ensure_ascii=False, indent=2))
        return 0

    if not preview["would_change"]:
        verify = _verify_mcp(db_path)
        receipt = {
            "schema": SCHEMA,
            "terminal": "COS_CONNECT_PASS" if verify["verified"] else "COS_CONNECT_VERIFY_HOLD",
            "reason": "ALREADY_CONFIGURED" if verify["verified"] else verify["reason"],
            **preview,
            "verified": verify["verified"],
            "verification": verify,
        }
        _emit(receipt, as_json=args.as_json)
        return 0 if verify["verified"] else 3

    assert path is not None
    if not args.yes and not _confirm(client, path):
        receipt = {
            "schema": SCHEMA,
            "terminal": "COS_CONNECT_CONFIRMATION_REQUIRED",
            "reason": "WRITE_NOT_CONFIRMED",
            **preview,
        }
        _emit(receipt, as_json=args.as_json)
        return 2

    existed = bool(preview["config_exists"])
    backup_path = None
    before_bytes = path.read_bytes() if existed else None
    if existed:
        backup_path = path.with_name(path.name + f".continuityos-backup-{_utc_stamp()}")
        _atomic_write_bytes(backup_path, before_bytes or b"")

    new_bytes = _json_bytes(preview["patched_config"])
    _atomic_write_bytes(path, new_bytes)
    after_sha = _sha256_file(path)
    if after_sha != preview["after_sha256"]:
        receipt = {
            "schema": SCHEMA,
            "terminal": "COS_CONNECT_HOLD",
            "reason": "POST_WRITE_HASH_MISMATCH",
            **preview,
            "actual_sha256": after_sha,
            "backup_path": str(backup_path) if backup_path else None,
        }
        _emit(receipt, as_json=args.as_json)
        return 3

    _record_write_state(
        client=client,
        config_path=path,
        previous_exists=existed,
        backup_path=backup_path,
        before_sha256=preview["before_sha256"],
        after_sha256=after_sha,
    )

    verify = _verify_mcp(db_path)
    if not verify["verified"]:
        rollback = _rollback(client)
        receipt = {
            "schema": SCHEMA,
            "terminal": "COS_CONNECT_VERIFY_HOLD",
            "reason": verify["reason"],
            **preview,
            "backup_path": str(backup_path) if backup_path else None,
            "verified": False,
            "verification": verify,
            "automatic_rollback": rollback,
        }
        _emit(receipt, as_json=args.as_json)
        return 3

    receipt = {
        "schema": SCHEMA,
        "terminal": "COS_CONNECT_PASS",
        "reason": "CONFIG_WRITTEN_AND_MCP_VERIFIED",
        **preview,
        "backup_path": str(backup_path) if backup_path else None,
        "verified": True,
        "verification": verify,
    }
    _emit(receipt, as_json=args.as_json)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
