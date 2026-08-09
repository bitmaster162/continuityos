"""CLI for separately-authorized atomic shadow OperationalMemory delta apply."""
from __future__ import annotations

import argparse
import json
import sys

from .operational_memory_apply import apply_authorized_memory_delta


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="continuity-memory-apply",
        description=(
            "Apply one exact R36 proposal atomically to shadow OperationalMemory. "
            "Any declared current session is refused; exact authorization is required."
        ),
    )
    parser.add_argument("--operational-db", required=True)
    parser.add_argument("--proposal", required=True)
    parser.add_argument("--authorization", required=True)
    try:
        args = parser.parse_args(sys.argv[1:] if argv is None else argv)
    except SystemExit as exc:
        return int(exc.code or 0)

    result = apply_authorized_memory_delta(
        args.operational_db,
        args.proposal,
        args.authorization,
    )
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
    terminal = result.get("terminal")
    if terminal in {"CURRENT_MEMORY_APPLY_PASS", "CURRENT_MEMORY_APPLY_ALREADY_APPLIED"}:
        return 0
    if terminal == "CURRENT_MEMORY_APPLY_HOLD":
        return 3
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
