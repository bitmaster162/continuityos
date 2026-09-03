"""CLI for the fail-closed read-only canonical payload consumer."""
from __future__ import annotations

import argparse
import json
from typing import Sequence

from .canonical_payload_consumer import (
    CanonicalPayloadConsumer,
    ConsumerHold,
    disabled_receipt,
    hold_receipt,
    load_config,
)


def _emit(value: object) -> None:
    print(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="continuity-canon")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("health")
    sub.add_parser("snapshot")
    decision = sub.add_parser("decision")
    decision.add_argument("decision_id")
    project = sub.add_parser("project")
    project.add_argument("project_id")
    sub.add_parser("context")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(list(argv) if argv is not None else None)
    try:
        config = load_config()
        if config is None:
            _emit(disabled_receipt())
            return 0
        consumer = CanonicalPayloadConsumer(config)
        if args.command == "health":
            result = consumer.health()
        elif args.command == "snapshot":
            result = consumer.snapshot()
        elif args.command == "decision":
            result = consumer.decision(args.decision_id)
        elif args.command == "project":
            result = consumer.project(args.project_id)
        else:
            result = consumer.context()
        _emit(result)
        return 0
    except ConsumerHold as exc:
        _emit(hold_receipt(exc))
        return 3


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
