"""Offline-first product boot for ContinuityOS.

Default boot is deliberately local-only: no updater import, no PyPI request, no
FastEmbed/model initialization. Network access is opt-in via --check-updates.
"""
from __future__ import annotations

import argparse
from pathlib import Path
from typing import Sequence

from .continuity import Continuity
from .db import resolve_memory_db
from .memory import Memory


def _doctor_lines(continuity: Continuity) -> list[str]:
    report = continuity.doctor()
    lines = [f"{'OK' if report['healthy'] else 'DRIFT'} {report['passed']}/{report['total']}"]
    for check in report["checks"]:
        if not check["ok"]:
            lines.append(f"  ! {check['check']} — {check['detail']}")
    return lines


def _update_lines() -> list[str]:
    # Import only on the explicit network-enabled path.
    from . import updater

    info = updater.check(force=True)
    latest = info.get("latest")
    if not latest:
        return ["[update check] unavailable"]
    if info.get("update_available"):
        return [f"[update] {info['current']} -> {latest} available  (run: cos update --yes)"]
    return [f"[update check] {info['current']} is current (PyPI {latest})"]


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="cos boot",
        description="Resume ContinuityOS from local durable state. Offline by default.",
    )
    parser.add_argument("--db", default=None)
    parser.add_argument(
        "--check-updates",
        action="store_true",
        help="explicitly allow a PyPI update check (may write the updater cache)",
    )
    args = parser.parse_args(list(argv) if argv is not None else None)

    try:
        db_path = resolve_memory_db(args.db)["path"]
    except Exception as exc:
        print("COS_BOOT_HOLD: MEMORY_DB_RESOLUTION_FAILED")
        print(f"error: {type(exc).__name__}: {exc}")
        return 2

    if db_path != ":memory:" and not Path(db_path).is_file():
        print("COS_BOOT_HOLD: MEMORY_DB_NOT_FOUND")
        print(f"memory: {db_path}")
        print("run: cos setup")
        return 2

    # HashingEmbedder is Memory's stdlib/local default. Do not instantiate optional
    # FastEmbed/SentenceTransformer/Model2Vec providers during boot: constructors may
    # resolve or download model assets and therefore violate the offline-by-default contract.
    memory = Memory(db_path)
    continuity = Continuity(memory=memory)

    print(continuity.handoff())
    print("\n--- doctor ---")
    for line in _doctor_lines(continuity):
        print(line)

    if args.check_updates:
        print()
        for line in _update_lines():
            print(line)

    print(
        '\n[advocate armed] consequential moves get challenged before they land '
        '(anti-sycophancy / bliss-attractor guard) - cos advocate "<claim>"'
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
