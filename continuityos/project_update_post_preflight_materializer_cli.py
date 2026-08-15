"""CLI for exact post-preflight project-update materialization."""
from __future__ import annotations

import argparse
import json
import sys

from .project_update_post_preflight_materializer import (
    RECEIPT_SCHEMA,
    materialize_project_update_after_preflight,
)


def _emit(value):
    print(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="continuity-project-update-materialize-ready",
        description=(
            "After CURRENT_PROJECT_UPDATE_PREFLIGHT_READY, bind the exact R52 packet, "
            "completed authorization bytes, and saved preflight receipt into one fresh "
            "directory for later unbound R37 revalidation. Does not apply."
        ),
    )
    parser.add_argument("--packet", required=True, help="exact R52 review packet JSON file")
    parser.add_argument("--authorization", required=True, help="exact completed R37 authorization JSON file")
    parser.add_argument("--preflight", required=True, help="saved CURRENT_PROJECT_UPDATE_PREFLIGHT_READY JSON output")
    parser.add_argument("--output-dir", required=True, help="new review directory; must not already exist")
    try:
        args = parser.parse_args(sys.argv[1:] if argv is None else argv)
    except SystemExit as exc:
        return int(exc.code or 0)

    result = materialize_project_update_after_preflight(
        args.packet,
        args.authorization,
        args.preflight,
        args.output_dir,
    )
    _emit(result)
    if result.get("schema") == RECEIPT_SCHEMA and result.get("terminal") == "PROJECT_UPDATE_POST_PREFLIGHT_MATERIALIZATION_PASS":
        return 0
    if result.get("terminal") == "PROJECT_UPDATE_POST_PREFLIGHT_MATERIALIZATION_HOLD":
        return 3
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
