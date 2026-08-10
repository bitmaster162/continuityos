"""CLI for non-authorizing R52 review artifact materialization."""
from __future__ import annotations

import argparse
import json
import sys

from .project_update_review_materializer import (
    RECEIPT_SCHEMA,
    materialize_project_update_review,
)


def _emit(value):
    print(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="continuity-project-update-materialize",
        description=(
            "Materialize exact R52 proposal bytes and an intentionally invalid R37 "
            "authorization skeleton into one fresh review directory. Does not authorize or apply."
        ),
    )
    parser.add_argument("--packet", required=True, help="R52 CURRENT_PROJECT_UPDATE_REVIEW_PASS JSON file")
    parser.add_argument("--output-dir", required=True, help="new review directory; must not already exist")
    try:
        args = parser.parse_args(sys.argv[1:] if argv is None else argv)
    except SystemExit as exc:
        return int(exc.code or 0)

    result = materialize_project_update_review(args.packet, args.output_dir)
    _emit(result)
    if result.get("schema") == RECEIPT_SCHEMA and result.get("terminal") == "PROJECT_UPDATE_MATERIALIZATION_PASS":
        return 0
    if result.get("terminal") == "PROJECT_UPDATE_MATERIALIZATION_HOLD":
        return 3
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
