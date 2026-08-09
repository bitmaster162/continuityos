"""CLI for authorized fresh shadow project-memory bootstrap."""
from __future__ import annotations

import argparse
import json
import sys

from .project_memory_bootstrap import bootstrap_project_memory


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="continuity-memory-bootstrap",
        description=(
            "Create one new shadow OperationalMemory project from a verified declarative "
            "manifest. Existing databases are never overwritten."
        ),
    )
    parser.add_argument("--db", required=True, help="new target SQLite path; parent must already exist")
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--authorization", required=True)
    try:
        args = parser.parse_args(sys.argv[1:] if argv is None else argv)
    except SystemExit as exc:
        return int(exc.code or 0)

    result = bootstrap_project_memory(args.db, args.manifest, args.authorization)
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
    terminal = result.get("terminal")
    if terminal in {"PROJECT_MEMORY_BOOTSTRAP_PASS", "PROJECT_MEMORY_BOOTSTRAP_ALREADY_CREATED"}:
        return 0
    if terminal == "PROJECT_MEMORY_BOOTSTRAP_HOLD":
        return 3
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
