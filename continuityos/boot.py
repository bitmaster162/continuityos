"""Offline product boot from one read-only local memory snapshot.

No optional embedder is constructed. A PyPI update check is available only through
the explicit --check-updates option, after successful context capture.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Sequence

from .continuity import Continuity, assess_continuity_health
from .current_effect_boundary import assert_current_effect_allowed
from .db import resolve_memory_db
from .embed import HashingEmbedder
from .memory import Memory


def _doctor_lines(report: dict[str, Any]) -> list[str]:
    lines = [f"{'OK' if report['healthy'] else 'DRIFT'} {report['passed']}/{report['total']}"]
    for check in report["checks"]:
        if not check["ok"]:
            lines.append(f"  ! {check['check']} — {check['detail']}")
    return lines


def _update_lines() -> list[str]:
    assert_current_effect_allowed("boot.check_updates")
    from . import updater

    info = updater.check(force=True)
    latest = info.get("latest")
    if not latest:
        return ["[update check] unavailable"]
    if info.get("update_available"):
        return [f"[update] {info['current']} -> {latest} available  (run: cos update --yes)"]
    return [f"[update check] {info['current']} is current (PyPI {latest})"]


def _hold(as_json: bool, reason: str, **details: Any) -> int:
    value = {"schema": "continuityos.product_boot/v1", "terminal": "COS_BOOT_HOLD",
             "reason": reason, "authority_granted": False, **details}
    if as_json:
        print(json.dumps(value, ensure_ascii=False, indent=2))
    else:
        print("COS_BOOT_HOLD: " + reason)
        if "memory" in details:
            print("memory: " + details["memory"])
        if reason == "MEMORY_DB_NOT_FOUND":
            print("run: cos setup")
        if "handoff" in details:
            print(Continuity.render_handoff(details["handoff"]))
    return 2


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="cos boot",
        description="Resume ContinuityOS from local durable state. Offline by default.",
    )
    parser.add_argument("--db", default=None)
    parser.add_argument("--project", default=None)
    parser.add_argument("--subject", default=None)
    parser.add_argument("--json", dest="as_json", action="store_true")
    parser.add_argument("--max-items", type=int, default=None)
    parser.add_argument("--max-bytes", type=int, default=None,
                        help="canonical context payload UTF-8 budget")
    parser.add_argument("--check-updates", action="store_true",
                        help="explicitly allow a PyPI update check (may write the updater cache)")
    args = parser.parse_args(list(argv) if argv is not None else None)
    for name in ("project", "subject"):
        value = getattr(args, name)
        if value is not None and not value.strip():
            parser.error(f"--{name} must be non-empty")
    for name in ("max_items", "max_bytes"):
        value = getattr(args, name)
        if value is not None and value < 0:
            parser.error("--" + name.replace("_", "-") + " must be non-negative")
    try:
        assert_current_effect_allowed("boot.read_context")
    except Exception:
        return _hold(args.as_json, "CURRENT_EFFECT_HOLD")
    try:
        db_path = resolve_memory_db(args.db)["path"]
    except Exception:
        return _hold(args.as_json, "MEMORY_DB_RESOLUTION_FAILED")
    if db_path == ":memory:" or not Path(db_path).is_file():
        return _hold(args.as_json, "MEMORY_DB_NOT_FOUND", memory=db_path)

    memory = None
    try:
        # mode=ro prevents a missing/replaced path from being recreated or migrated.
        memory = Memory(db_path, embedder=HashingEmbedder(), read_only=True)
        continuity = Continuity(memory=memory, project=args.project, subject=args.subject)
        with memory.store.read_snapshot():
            snapshot = continuity.handoff_snapshot(max_items=args.max_items, max_bytes=args.max_bytes)
            if not snapshot["complete"]:
                return _hold(args.as_json, "HANDOFF_BUDGET_EXCEEDED", handoff=snapshot)
            payload = snapshot["payload"]
            frontiers = {
                row["meta"].get("kind") or (row["tags"][0] if row["tags"] else "parked"): row["text"]
                for row in payload["frontiers"]
            }
            doctor = assess_continuity_health(
                memory_count=len(continuity._dump(None)),
                canon_count=len(payload["canon"]),
                frontiers=frontiers, loops=payload["open_loops"],
                last_checkpoint=payload["last_checkpoint"], now=snapshot["observed_at"],
                scope=snapshot["scope"],
            )
    except Exception as exc:
        return _hold(args.as_json, "MEMORY_SNAPSHOT_READ_FAILED", error_type=type(exc).__name__)
    finally:
        if memory is not None:
            memory.store.con.close()

    updates = []
    if args.check_updates:
        try:
            updates = _update_lines()
        except Exception as exc:
            updates = [f"[update check] unavailable ({type(exc).__name__})"]
    if args.as_json:
        print(json.dumps({
            "schema": "continuityos.product_boot/v1", "terminal": "COS_BOOT_PASS",
            "reason": "LOCAL_SNAPSHOT_READ", "handoff": snapshot, "doctor": doctor,
            "update_check_requested": args.check_updates, "update_check": updates,
            "authority_granted": False,
        }, ensure_ascii=False, indent=2))
    else:
        print(Continuity.render_handoff(snapshot))
        print("\n--- doctor ---")
        for line in _doctor_lines(doctor):
            print(line)
        if updates:
            print()
            for line in updates:
                print(line)
        print('\nOptional advisory review: cos advocate "<claim>"')
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
