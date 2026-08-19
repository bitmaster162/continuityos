"""CLI for the local-only Sovereign Twin runtime."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from .memory import Memory
from .sovereign_twin_admission import AdmissionQueueError, ShadowMemoryAdmissionQueue
from .sovereign_twin_runtime import LmStudioClient, LocalModelEndpointError, SovereignTwinRuntime


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="sovereign-twin")
    p.add_argument("--db", default=str(Path.home() / ".continuityos" / "memory.db"))
    p.add_argument("--base-url", default="http://127.0.0.1:1234")
    p.add_argument("--allow-remote-model-server", action="store_true")
    p.add_argument(
        "--admission-queue",
        default=str(Path.home() / ".continuityos" / "twin-admissions.jsonl"),
    )
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("init")
    sub.add_parser("doctor")

    ask = sub.add_parser("ask")
    ask.add_argument("query")
    ask.add_argument("--mode", choices=["fast", "deep"], default="fast")

    serve = sub.add_parser("serve")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8765)

    propose = sub.add_parser("admission-propose")
    propose.add_argument("text")
    propose.add_argument("--namespace", default="notes")
    propose.add_argument("--tag", action="append", default=[])
    propose.add_argument("--evidence-ref", action="append", default=[])

    sub.add_parser("admission-list")
    return p


def _emit(value: dict, code: int = 0) -> int:
    print(json.dumps(value, ensure_ascii=False, sort_keys=True))
    return code


def _initialize_memory_db(path: str) -> dict:
    db = Path(path).expanduser()
    db.parent.mkdir(parents=True, exist_ok=True)
    existed = db.exists()
    memory = Memory(str(db))
    try:
        namespaces = memory.namespaces()
    finally:
        close = getattr(memory.store, "close", None)
        if callable(close):
            close()
        else:
            memory.store.con.close()
    return {
        "ok": True,
        "db": str(db),
        "created": not existed,
        "namespace_count": len(namespaces),
        "mode": "LOCAL_SHADOW",
        "execution_authority": "NONE",
        "can_execute": False,
    }


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)

    if args.cmd == "init":
        try:
            return _emit(_initialize_memory_db(args.db))
        except (OSError, ValueError) as exc:
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

    if args.cmd == "serve":
        if args.allow_remote_model_server:
            return _emit(
                {
                    "ok": False,
                    "error": "serve refuses --allow-remote-model-server in local shadow mode",
                    "execution_authority": "NONE",
                },
                2,
            )
        from .sovereign_twin_api import serve

        serve(
            memory_db=args.db,
            base_url=args.base_url,
            host=args.host,
            port=args.port,
            admission_path=args.admission_queue,
        )
        return 0

    if args.cmd in {"admission-propose", "admission-list"}:
        queue = ShadowMemoryAdmissionQueue(args.admission_queue)
        try:
            if args.cmd == "admission-propose":
                event = queue.propose(
                    args.text,
                    namespace=args.namespace,
                    tags=args.tag,
                    evidence_refs=args.evidence_ref,
                    source="CLI_USER",
                )
                return _emit({"ok": True, "event": event, "verify": queue.verify()})
            return _emit(
                {
                    "ok": True,
                    "pending": queue.pending(),
                    "verify": queue.verify(),
                    "execution_authority": "NONE",
                }
            )
        except AdmissionQueueError as exc:
            return _emit({"ok": False, "error": str(exc), "execution_authority": "NONE"}, 2)

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
