"""Fail-closed Windows product entry for the read-only Control Center."""
from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import sys
import time
import webbrowser
from pathlib import Path
from typing import Callable
from urllib.error import URLError
from urllib.request import Request, urlopen

from .control_center import (
    DEFAULT_HOST,
    DEFAULT_LM_STUDIO_URL,
    DEFAULT_PORT,
    DEFAULT_TWIN_URL,
    ControlCenterConfig,
    _validate_local_config,
)

SUPPRESS_BROWSER_ENV = "SOVEREIGN_TWIN_CONTROL_CENTER_SUPPRESS_BROWSER"


def _json_get(url: str, *, timeout: float = 0.5) -> dict:
    request = Request(url, headers={"Accept": "application/json"}, method="GET")
    with urlopen(request, timeout=timeout) as response:
        payload = json.loads(response.read().decode("utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("Control Center health did not return a JSON object")
    return payload


def _health_is_exact_read_only(payload: dict) -> bool:
    return (
        payload.get("ok") is True
        and payload.get("read_only") is True
        and payload.get("execution_authority") == "NONE"
        and payload.get("can_execute") is False
    )


def _port_is_occupied(host: str, port: int, *, timeout: float = 0.2) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _stop_child(proc: subprocess.Popen[bytes]) -> None:
    if proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=2.0)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=2.0)


def _emit_failure(message: str) -> int:
    print(
        json.dumps(
            {
                "ok": False,
                "error": message,
                "read_only": True,
                "execution_authority": "NONE",
                "can_execute": False,
            },
            sort_keys=True,
        )
    )
    return 2


def open_control_center(
    *,
    host: str,
    port: int,
    config: ControlCenterConfig,
    health_getter: Callable[..., dict] = _json_get,
    popen_factory: Callable[..., subprocess.Popen[bytes]] = subprocess.Popen,
    browser_open: Callable[..., bool] = webbrowser.open,
    port_checker: Callable[..., bool] = _port_is_occupied,
    sleep: Callable[[float], None] = time.sleep,
    monotonic: Callable[[], float] = time.monotonic,
) -> int:
    _validate_local_config(host, config)
    if port <= 0 or port > 65535:
        return _emit_failure("Control Center port is invalid")
    if port_checker(host, port):
        return _emit_failure("Control Center port is already occupied; refusing ambiguous service")

    command = [
        sys.executable,
        "-B",
        "-I",
        "-m",
        "continuityos.control_center",
        "serve",
        "--host",
        host,
        "--port",
        str(port),
        "--runtime-root",
        str(config.runtime_root),
        "--twin-url",
        config.twin_url,
        "--lm-studio-url",
        config.lm_studio_url,
    ]
    creationflags = 0
    if os.name == "nt":
        creationflags = int(getattr(subprocess, "CREATE_NO_WINDOW", 0)) | int(
            getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        )

    proc = popen_factory(
        command,
        cwd=str(Path(sys.executable).resolve().parent),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        close_fds=True,
        creationflags=creationflags,
    )
    health_url = f"http://{host}:{port}/health"
    deadline = monotonic() + 10.0
    health: dict | None = None

    while monotonic() < deadline:
        if proc.poll() is not None:
            return _emit_failure(
                f"Control Center exited before healthy startup rc={proc.returncode}"
            )
        try:
            candidate = health_getter(health_url, timeout=0.5)
        except (OSError, URLError, ValueError, json.JSONDecodeError):
            sleep(0.1)
            continue
        if not _health_is_exact_read_only(candidate):
            _stop_child(proc)
            return _emit_failure("Control Center health violated read-only authority contract")
        health = candidate
        break

    if health is None:
        _stop_child(proc)
        return _emit_failure("Control Center did not become healthy before timeout")

    ui_url = f"http://{host}:{port}/"
    if os.environ.get(SUPPRESS_BROWSER_ENV) != "1":
        if browser_open(ui_url, new=2) is not True:
            _stop_child(proc)
            return _emit_failure("Control Center browser open failed")

    print(
        json.dumps(
            {
                "ok": True,
                "read_only": True,
                "execution_authority": "NONE",
                "can_execute": False,
                "pid": proc.pid,
                "url": ui_url,
                "health_url": health_url,
            },
            sort_keys=True,
        )
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="sovereign-twin-control-center-entry")
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--runtime-root", required=True)
    parser.add_argument("--twin-url", default=DEFAULT_TWIN_URL)
    parser.add_argument("--lm-studio-url", default=DEFAULT_LM_STUDIO_URL)
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    config = ControlCenterConfig(
        runtime_root=Path(args.runtime_root).expanduser(),
        twin_url=args.twin_url,
        lm_studio_url=args.lm_studio_url,
    )
    try:
        return open_control_center(
            host=args.host,
            port=args.port,
            config=config,
        )
    except (OSError, ValueError) as exc:
        return _emit_failure(f"{type(exc).__name__}: {exc}")


if __name__ == "__main__":
    raise SystemExit(main())
