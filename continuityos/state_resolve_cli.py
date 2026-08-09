"""Read-only CLI for ContinuityOS state/evidence reconciliation.

This command exposes the fail-closed state-resolution guard without importing the
legacy execution plane. It reads one bounded JSON bundle, resolves current truth,
prints canonical JSON, and performs no writes or external effects.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from .gate.state_resolution import canonical_json_text, resolve_state

BUNDLE_SCHEMA = "continuityos.state_resolution.bundle/v1"
MAX_INPUT_BYTES = 4 * 1024 * 1024
MAX_CANDIDATES = 4096


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _effects() -> dict[str, Any]:
    return {
        "force_push": False,
        "merge": False,
        "pull_request_merge": False,
        "auto_merge": False,
        "deployment": False,
        "registry_apply": False,
        "current_state_apply": False,
        "r63_apply": False,
        "trading": False,
        "wallet_access": False,
        "order_execution": False,
        "external_message": False,
        "self_application": False,
        "can_trade": False,
        "capital_permission": "DENY",
        "deploy_permission": "DENY",
    }


def _error_result(exc: Exception) -> dict[str, Any]:
    return {
        "schema": "continuityos.state_resolution.result/v1",
        "terminal": "STATE_RESOLUTION_REVISE",
        "reason": "INPUT_INVALID",
        "error_type": type(exc).__name__,
        "error": str(exc),
        "selected": None,
        "stale": [],
        "effects": _effects(),
    }


def load_bundle(path: Path) -> list[dict[str, Any]]:
    path = Path(path)
    if path.is_symlink():
        raise ValueError("input path may not be a symlink")
    if not path.is_file():
        raise FileNotFoundError("input file is missing")
    if path.stat().st_size > MAX_INPUT_BYTES:
        raise ValueError(f"input exceeds {MAX_INPUT_BYTES} bytes")

    try:
        value = json.loads(
            path.read_text(encoding="utf-8-sig"),
            object_pairs_hook=_reject_duplicate_keys,
        )
    except FileNotFoundError:
        raise
    except Exception as exc:
        raise ValueError(
            f"input is not strict UTF-8 JSON: {type(exc).__name__}: {exc}"
        ) from exc

    if not isinstance(value, dict):
        raise ValueError("input root must be an object")
    if value.get("schema") != BUNDLE_SCHEMA:
        raise ValueError("state-resolution bundle schema mismatch")
    if set(value) != {"schema", "candidates"}:
        raise ValueError("state-resolution bundle fields mismatch")

    candidates = value.get("candidates")
    if not isinstance(candidates, list):
        raise ValueError("candidates must be a list")
    if len(candidates) > MAX_CANDIDATES:
        raise ValueError(f"candidates exceeds {MAX_CANDIDATES} entries")
    return candidates


def exit_code_for_result(result: dict[str, Any]) -> int:
    terminal = result.get("terminal")
    if terminal == "STATE_RESOLUTION_PASS":
        return 0
    if terminal == "STATE_RESOLUTION_HOLD":
        return 3
    return 2


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="continuity-state",
        description="Resolve competing ContinuityOS state/evidence without applying anything.",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)
    evaluate = sub.add_parser("evaluate", help="resolve one bounded evidence bundle")
    evaluate.add_argument("--input", required=True, help="state-resolution bundle JSON")
    args = parser.parse_args(argv)

    try:
        candidates = load_bundle(Path(args.input).expanduser())
        result = resolve_state(candidates)
    except Exception as exc:
        result = _error_result(exc)

    print(canonical_json_text(result), end="")
    return exit_code_for_result(result)


if __name__ == "__main__":
    raise SystemExit(main())
