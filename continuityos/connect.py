"""Safe product onboarding for MCP-capable AI clients."""
from __future__ import annotations

import argparse
import copy
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from typing import Any, Mapping, Sequence

from .db import resolve_memory_db

SCHEMA = "continuityos.product_connect/v1"
STATE_SCHEMA = "continuityos.product_connect_state/v1"
SERVER_NAME = "continuityos"
MANAGED = {"claude", "cursor"}
SUPPORTED_CLIENTS = ("claude", "cursor", "hermes", "generic-mcp")


def _canon(path: str | Path) -> str:
    return os.path.normcase(os.path.realpath(os.path.abspath(os.path.expanduser(str(path)))))


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _file_sha(path: Path) -> str:
    return _sha(path.read_bytes())


def _json_bytes(value: Mapping[str, Any]) -> bytes:
    return (json.dumps(dict(value), ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _atomic_write(path: Path, data: bytes) -> None:
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


def _state_path() -> Path:
    return Path.home() / ".continuityos" / "connect_state.json"


def _load_state() -> dict[str, Any]:
    path = _state_path()
    if not path.exists():
        return {"schema": STATE_SCHEMA, "clients": {}}
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or not isinstance(value.get("clients"), dict):
        raise ValueError(f"invalid connect state: {path}")
    return value


def _save_state(state: Mapping[str, Any]) -> None:
    _atomic_write(_state_path(), _json_bytes(state))


def _config_path(client: str, override: str | None = None) -> Path | None:
    if override:
        return Path(_canon(override))
    if client == "claude":
        env_override = os.environ.get("CONTINUITYOS_CLAUDE_CONFIG")
        if env_override:
            return Path(_canon(env_override))
        appdata = os.environ.get("APPDATA")
        if sys.platform == "win32" and appdata:
            return Path(_canon(Path(appdata) / "Claude" / "claude_desktop_config.json"))
        if sys.platform == "darwin":
            return Path(_canon(Path.home() / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json"))
        return Path(_canon(Path.home() / ".config" / "Claude" / "claude_desktop_config.json"))
    if client == "cursor":
        env_override = os.environ.get("CONTINUITYOS_CURSOR_CONFIG")
        if env_override:
            return Path(_canon(env_override))
        return Path(_canon(Path.cwd() / ".cursor" / "mcp.json"))
    return None


def _server(db_path: str) -> dict[str, Any]:
    return {
        "command": _canon(sys.executable),
        "args": ["-m", "continuityos.mcp_server", "--db", _canon(db_path)],
    }


def _read_config(path: Path) -> tuple[dict[str, Any], bool, bytes]:
    if not path.exists():
        return {}, False, b""
    if not path.is_file():
        raise ValueError(f"config path is not a file: {path}")
    raw = path.read_bytes()
    value = json.loads(raw.decode("utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"config root must be an object: {path}")
    return value, True, raw


def _patch_config(original: Mapping[str, Any], server: Mapping[str, Any]) -> dict[str, Any]:
    result = copy.deepcopy(dict(original))
    section = result.get("mcpServers", {})
    if not isinstance(section, dict):
        raise ValueError("mcpServers must be a JSON object")
    section = copy.deepcopy(section)
    section[SERVER_NAME] = copy.deepcopy(dict(server))
    result["mcpServers"] = section
    return result


def _manual(client: str, server: Mapping[str, Any]) -> dict[str, Any]:
    if client == "hermes":
        args = " ".join(json.dumps(x) for x in server["args"])
        return {
            "client": client,
            "managed": False,
            "connected": False,
            "reason": "MANUAL_COMMAND_REQUIRED",
            "manual_command": (
                f'hermes mcp add {SERVER_NAME} '
                f'--command {json.dumps(server["command"])} --args {json.dumps(args)}'
            ),
            "server": dict(server),
        }
    return {
        "client": client,
        "managed": False,
        "connected": False,
        "reason": "MANUAL_CONFIG_REQUIRED",
        "config_snippet": {"mcpServers": {SERVER_NAME: dict(server)}},
    }


def _status(client: str, config_path: Path, server: Mapping[str, Any]) -> dict[str, Any]:
    try:
        config, exists, _ = _read_config(config_path)
    except Exception as exc:
        return {
            "client": client,
            "managed": True,
            "config_path": str(config_path),
            "configured": False,
            "connected": False,
            "drift": True,
            "error": f"{type(exc).__name__}: {exc}",
        }
    section = config.get("mcpServers")
    entry = section.get(SERVER_NAME) if isinstance(section, dict) else None
    configured = isinstance(entry, dict)
    return {
        "client": client,
        "managed": True,
        "config_path": str(config_path),
        "config_exists": exists,
        "configured": configured,
        "connected": configured and entry == dict(server),
        "drift": configured and entry != dict(server),
        "server": entry if configured else None,
    }


def _verify_mcp(db_path: str, timeout: float = 5.0) -> dict[str, Any]:
    command = [sys.executable, "-m", "continuityos.mcp_server", "--db", _canon(db_path)]
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
        try:
            candidate = json.loads(line)
        except Exception:
            continue
        if isinstance(candidate, dict) and candidate.get("id") == 1:
            response = candidate
            break
    verified = (
        completed.returncode == 0
        and isinstance(response, dict)
        and isinstance(response.get("result"), dict)
    )
    return {
        "verified": verified,
        "reason": "MCP_INITIALIZE_PASS" if verified else "MCP_INITIALIZE_FAILED",
        "returncode": completed.returncode,
        "response": response,
        "stderr": completed.stderr[-2000:],
        "command": command,
    }


def _preview(client: str, db_path: str, config_path: Path | None, server: Mapping[str, Any]) -> dict[str, Any]:
    if client not in MANAGED:
        return _manual(client, server)
    assert config_path is not None
    original, existed, raw = _read_config(config_path)
    patched = _patch_config(original, server)
    new_raw = _json_bytes(patched)
    return {
        "client": client,
        "managed": True,
        "config_path": str(config_path),
        "config_exists": existed,
        "before_sha256": _sha(raw) if existed else None,
        "after_sha256": _sha(new_raw),
        "would_change": (not existed) or raw != new_raw,
        "memory_db": db_path,
        "server": dict(server),
        "patched_config": patched,
    }


def _record_state(
    client: str,
    config_path: Path,
    existed: bool,
    backup_path: Path | None,
    before_sha: str | None,
    after_sha: str,
) -> None:
    state = _load_state()
    state["clients"][client] = {
        "config_path": str(config_path),
        "previous_exists": existed,
        "backup_path": str(backup_path) if backup_path else None,
        "before_sha256": before_sha,
        "after_sha256": after_sha,
        "recorded_at": datetime.now(timezone.utc).isoformat(),
    }
    _save_state(state)


def _rollback(client: str) -> dict[str, Any]:
    state = _load_state()
    record = state.get("clients", {}).get(client)
    if not isinstance(record, dict):
        return {"terminal": "COS_CONNECT_ROLLBACK_HOLD", "reason": "NO_ROLLBACK_RECORD", "client": client}
    path = Path(record["config_path"])
    if not path.exists():
        return {"terminal": "COS_CONNECT_ROLLBACK_HOLD", "reason": "CONFIG_MISSING_SINCE_CONNECT", "client": client}
    actual = _file_sha(path)
    if actual != record.get("after_sha256"):
        return {
            "terminal": "COS_CONNECT_ROLLBACK_HOLD",
            "reason": "CONFIG_DRIFTED_SINCE_CONNECT",
            "client": client,
            "config_path": str(path),
            "actual_sha256": actual,
            "expected_sha256": record.get("after_sha256"),
        }
    if record.get("previous_exists"):
        backup = Path(record.get("backup_path") or "")
        if not backup.is_file():
            return {"terminal": "COS_CONNECT_ROLLBACK_HOLD", "reason": "BACKUP_MISSING", "client": client}
        _atomic_write(path, backup.read_bytes())
        reason = "RESTORED_BACKUP"
    else:
        path.unlink()
        reason = "REMOVED_CREATED_CONFIG"
    state["clients"].pop(client, None)
    _save_state(state)
    return {"terminal": "COS_CONNECT_ROLLBACK_PASS", "reason": reason, "client": client, "config_path": str(path)}


def _emit(receipt: Mapping[str, Any], as_json: bool) -> None:
    if as_json:
        print(json.dumps(dict(receipt), ensure_ascii=False, sort_keys=True, separators=(",", ":")))
        return
    if receipt.get("terminal"):
        print(f"{receipt['terminal']}: {receipt.get('reason', '')}")
    for key, label in (("client", "client"), ("memory_db", "memory"), ("config_path", "config"), ("backup_path", "backup")):
        if receipt.get(key):
            print(f"{label}: {receipt[key]}")
    if receipt.get("manual_command"):
        print(f"run: {receipt['manual_command']}")
    if receipt.get("config_snippet"):
        print(json.dumps(receipt["config_snippet"], ensure_ascii=False, indent=2))
    if "verified" in receipt:
        print(f"mcp verified: {str(bool(receipt['verified'])).lower()}")


def _confirm(client: str, path: Path) -> bool:
    if not sys.stdin.isatty():
        return False
    try:
        answer = input(f"Write ContinuityOS MCP config for {client} to {path}? [y/N] ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        return False
    return answer in {"y", "yes"}


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="cos connect", description="Connect ContinuityOS to an MCP client.")
    parser.add_argument("client", nargs="?", choices=SUPPORTED_CLIENTS)
    parser.add_argument("--db", default=None)
    parser.add_argument("--config", default=None)
    parser.add_argument("--status", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--yes", action="store_true")
    parser.add_argument("--rollback", action="store_true")
    parser.add_argument("--json", dest="as_json", action="store_true")
    args = parser.parse_args(list(argv) if argv is not None else None)

    try:
        db_path = resolve_memory_db(args.db)["path"]
    except Exception as exc:
        receipt = {"schema": SCHEMA, "terminal": "COS_CONNECT_HOLD", "reason": "MEMORY_DB_RESOLUTION_FAILED", "error": f"{type(exc).__name__}: {exc}"}
        _emit(receipt, args.as_json)
        return 2

    memory_exists = db_path == ":memory:" or Path(db_path).is_file()
    server = _server(db_path)

    if args.rollback:
        if args.client not in MANAGED:
            receipt = {"schema": SCHEMA, "terminal": "COS_CONNECT_ROLLBACK_HOLD", "reason": "ROLLBACK_REQUIRES_MANAGED_CLIENT"}
            _emit(receipt, args.as_json)
            return 2
        receipt = {"schema": SCHEMA, **_rollback(args.client)}
        _emit(receipt, args.as_json)
        return 0 if receipt["terminal"].endswith("_PASS") else 2

    if args.status or args.client is None:
        clients = [args.client] if args.client else list(SUPPORTED_CLIENTS)
        statuses = []
        for client in clients:
            path = _config_path(client, args.config if len(clients) == 1 else None)
            statuses.append(_status(client, path, server) if client in MANAGED else _manual(client, server))
        receipt = {
            "schema": SCHEMA,
            "terminal": "COS_CONNECT_STATUS_PASS",
            "reason": "STATUS_ONLY",
            "memory_db": db_path,
            "memory_exists": memory_exists,
            "clients": statuses,
        }
        if args.as_json:
            _emit(receipt, True)
        else:
            print(f"memory: {db_path} ({'FOUND' if memory_exists else 'MISSING'})")
            for status in statuses:
                state = "CONNECTED" if status.get("connected") else status.get("reason", "NOT_CONNECTED")
                print(f"{status['client']}: {state}")
                if status.get("config_path"):
                    print(f"  config: {status['config_path']}")
                if status.get("manual_command"):
                    print(f"  run: {status['manual_command']}")
        return 0

    client = args.client
    path = _config_path(client, args.config)
    try:
        preview = _preview(client, db_path, path, server)
    except Exception as exc:
        receipt = {
            "schema": SCHEMA,
            "terminal": "COS_CONNECT_HOLD",
            "reason": "CONFIG_PREVIEW_FAILED",
            "client": client,
            "memory_db": db_path,
            "error": f"{type(exc).__name__}: {exc}",
        }
        _emit(receipt, args.as_json)
        return 2

    if not preview.get("managed"):
        receipt = {"schema": SCHEMA, "terminal": "COS_CONNECT_GUIDANCE_PASS", "memory_db": db_path, **preview}
        _emit(receipt, args.as_json)
        return 0

    if args.dry_run:
        receipt = {"schema": SCHEMA, "terminal": "COS_CONNECT_DRY_RUN_PASS", "reason": "PREVIEW_ONLY", "memory_exists": memory_exists, **preview}
        _emit(receipt, args.as_json)
        if not args.as_json:
            print(json.dumps(preview["patched_config"], ensure_ascii=False, indent=2))
        return 0

    if not memory_exists:
        receipt = {"schema": SCHEMA, "terminal": "COS_CONNECT_HOLD", "reason": "MEMORY_DB_NOT_FOUND", "client": client, "memory_db": db_path, "config_path": str(path)}
        _emit(receipt, args.as_json)
        return 2

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
        _emit(receipt, args.as_json)
        return 0 if verify["verified"] else 3

    assert path is not None
    if not args.yes and not _confirm(client, path):
        receipt = {"schema": SCHEMA, "terminal": "COS_CONNECT_CONFIRMATION_REQUIRED", "reason": "WRITE_NOT_CONFIRMED", **preview}
        _emit(receipt, args.as_json)
        return 2

    existed = bool(preview["config_exists"])
    current_exists = path.exists()
    if current_exists != existed:
        receipt = {"schema": SCHEMA, "terminal": "COS_CONNECT_HOLD", "reason": "CONFIG_DRIFTED_AFTER_PREVIEW", **preview}
        _emit(receipt, args.as_json)
        return 3
    before_raw = path.read_bytes() if existed else b""
    if existed and _sha(before_raw) != preview["before_sha256"]:
        receipt = {"schema": SCHEMA, "terminal": "COS_CONNECT_HOLD", "reason": "CONFIG_DRIFTED_AFTER_PREVIEW", **preview, "actual_before_sha256": _sha(before_raw)}
        _emit(receipt, args.as_json)
        return 3

    backup = None
    if existed:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        backup = path.with_name(path.name + f".continuityos-backup-{stamp}")
        _atomic_write(backup, before_raw)

    new_raw = _json_bytes(preview["patched_config"])
    _atomic_write(path, new_raw)
    after_sha = _file_sha(path)
    if after_sha != preview["after_sha256"]:
        receipt = {"schema": SCHEMA, "terminal": "COS_CONNECT_HOLD", "reason": "POST_WRITE_HASH_MISMATCH", **preview, "actual_sha256": after_sha, "backup_path": str(backup) if backup else None}
        _emit(receipt, args.as_json)
        return 3

    try:
        _record_state(client, path, existed, backup, preview["before_sha256"], after_sha)
    except Exception as exc:
        if existed and backup and backup.is_file():
            _atomic_write(path, backup.read_bytes())
            rollback_reason = "RESTORED_BACKUP_AFTER_STATE_RECORD_FAILURE"
        elif not existed and path.exists() and _file_sha(path) == after_sha:
            path.unlink()
            rollback_reason = "REMOVED_CREATED_CONFIG_AFTER_STATE_RECORD_FAILURE"
        else:
            rollback_reason = "STATE_RECORD_FAILED_MANUAL_REVIEW_REQUIRED"
        receipt = {
            "schema": SCHEMA,
            "terminal": "COS_CONNECT_HOLD",
            "reason": "ROLLBACK_STATE_RECORD_FAILED",
            **preview,
            "error": f"{type(exc).__name__}: {exc}",
            "rollback_reason": rollback_reason,
            "backup_path": str(backup) if backup else None,
        }
        _emit(receipt, args.as_json)
        return 3

    verify = _verify_mcp(db_path)
    if not verify["verified"]:
        rollback = _rollback(client)
        receipt = {
            "schema": SCHEMA,
            "terminal": "COS_CONNECT_VERIFY_HOLD",
            "reason": verify["reason"],
            **preview,
            "backup_path": str(backup) if backup else None,
            "verified": False,
            "verification": verify,
            "automatic_rollback": rollback,
        }
        _emit(receipt, args.as_json)
        return 3

    receipt = {
        "schema": SCHEMA,
        "terminal": "COS_CONNECT_PASS",
        "reason": "CONFIG_WRITTEN_AND_MCP_VERIFIED",
        **preview,
        "backup_path": str(backup) if backup else None,
        "verified": True,
        "verification": verify,
    }
    _emit(receipt, args.as_json)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
