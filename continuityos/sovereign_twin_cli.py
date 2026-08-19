"""CLI for the local-only Sovereign Twin runtime."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from .sovereign_twin_runtime import LmStudioClient, LocalModelEndpointError, SovereignTwinRuntime


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="sovereign-twin")
    p.add_argument("--db", default=str(Path.home() / ".continuityos" / "memory.db"))
    p.add_argument("--base-url", default="http://127.0.0.1:1234")
    p.add_argument("--allow-remote-model-server", action="store_true")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("doctor")
    ask = sub.add_parser("ask")
    ask.add_argument("query")
    ask.add_argument("--mode", choices=["fast", "deep"], default="fast")
    return p


def _emit(value: dict, code: int = 0) -> int:
    print(json.dumps(value, ensure_ascii=False, sort_keys=True))
    return code


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    client = LmStudioClient(args.base_url, allow_remote=args.allow_remote_model_server)
    runtime = None
    try:
        runtime = SovereignTwinRuntime(args.db, client=client)
        if args.cmd == "doctor":
            result = runtime.doctor()
            return _emit(result, 0 if result["ok"] else 2)
        if args.cmd == "ask":
            return _emit(runtime.ask(args.query, mode=args.mode).to_dict())
        return _emit({"ok": False, "error": "unsupported command", "execution_authority": "NONE"}, 2)
    except (LocalModelEndpointError, OSError, ValueError) as exc:
        return _emit(
            {
                "ok": False,
                "error": str(exc),
                "error_class": type(exc).__name__,
                "execution_authority": "NONE",
                "can_execute": False,
            },
            2,
        )
    finally:
        if runtime is not None:
            runtime.close()


if __name__ == "__main__":
    raise SystemExit(main())
