"""CLI for ContinuityOS state/evidence reconciliation and state-bound cold-start.

``evaluate`` is pure/read-only. ``prepare-cold-start`` first resolves one bounded
state bundle and refuses to create a cold-start challenge unless the resolved
operational state is accepted. Only then does it delegate to the existing
ANTI_AMNESIA cold-start preparer. It never deploys, applies current state, trades,
changes capital permissions, or activates memory.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from .gate.cold_start import prepare_cold_start_challenge
from .gate.state_resolution import canonical_json_text, resolve_state

BUNDLE_SCHEMA = "continuityos.state_resolution.bundle/v1"
STATE_BOUND_COLD_START_SCHEMA = "continuityos.state_bound_cold_start.receipt/v1"
MAX_INPUT_BYTES = 4 * 1024 * 1024
MAX_CANDIDATES = 4096
OPERATIONALLY_ACCEPTED = {"PASS", "PASS_WITH_CONDITIONS"}


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


def _state_bound_error(exc: Exception) -> dict[str, Any]:
    return {
        "schema": STATE_BOUND_COLD_START_SCHEMA,
        "terminal": "STATE_BOUND_COLD_START_REVISE",
        "reason": "INPUT_OR_COLD_START_INVALID",
        "error_type": type(exc).__name__,
        "error": str(exc),
        "state_resolution": None,
        "cold_start": None,
        "writes_performed": [],
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


def _sha256_path(path: Path) -> str:
    payload = Path(path).read_bytes()
    return hashlib.sha256(payload).hexdigest()


def exit_code_for_result(result: dict[str, Any]) -> int:
    terminal = result.get("terminal")
    if terminal in {"STATE_RESOLUTION_PASS", "STATE_BOUND_COLD_START_PASS"}:
        return 0
    if terminal in {"STATE_RESOLUTION_HOLD", "STATE_BOUND_COLD_START_HOLD"}:
        return 3
    return 2


def prepare_state_bound_cold_start(
    state_bundle: Path,
    boot_receipt: Path,
    spec: Path,
    output: Path,
) -> dict[str, Any]:
    """Prepare a cold-start challenge only after accepted state resolution.

    The state bundle is immutable input evidence for this invocation. A successful
    resolver terminal is not enough by itself: the selected current status must be
    exactly PASS or PASS_WITH_CONDITIONS. OPEN/PARTIAL/HOLD/REJECT/REVISE all block
    cold-start creation and therefore perform no writes.
    """
    state_bundle = Path(state_bundle)
    candidates = load_bundle(state_bundle)
    resolution = resolve_state(candidates)
    resolution_sha = hashlib.sha256(
        canonical_json_text(resolution).encode("utf-8")
    ).hexdigest()

    if resolution.get("terminal") != "STATE_RESOLUTION_PASS":
        return {
            "schema": STATE_BOUND_COLD_START_SCHEMA,
            "terminal": "STATE_BOUND_COLD_START_HOLD",
            "reason": "STATE_RESOLUTION_NOT_PASS",
            "state_bundle_sha256": _sha256_path(state_bundle),
            "state_resolution_sha256": resolution_sha,
            "state_resolution": resolution,
            "cold_start": None,
            "writes_performed": [],
            "effects": _effects(),
        }

    current_status = resolution.get("current_status")
    if current_status not in OPERATIONALLY_ACCEPTED:
        return {
            "schema": STATE_BOUND_COLD_START_SCHEMA,
            "terminal": "STATE_BOUND_COLD_START_HOLD",
            "reason": "STATE_NOT_OPERATIONALLY_ACCEPTED",
            "state_bundle_sha256": _sha256_path(state_bundle),
            "state_resolution_sha256": resolution_sha,
            "state_resolution": resolution,
            "cold_start": None,
            "writes_performed": [],
            "effects": _effects(),
        }

    cold_start = prepare_cold_start_challenge(
        Path(boot_receipt), Path(spec), Path(output)
    )
    return {
        "schema": STATE_BOUND_COLD_START_SCHEMA,
        "terminal": "STATE_BOUND_COLD_START_PASS",
        "reason": "OPERATIONAL_STATE_ACCEPTED",
        "state_bundle_sha256": _sha256_path(state_bundle),
        "state_resolution_sha256": resolution_sha,
        "selected_artifact_id": resolution["selected"]["artifact_id"],
        "selected_artifact_sha256": resolution["selected"]["artifact_sha256"],
        "current_status": current_status,
        "operational_state": resolution.get("operational_state"),
        "production_qualified": resolution.get("production_qualified", False),
        "evidence_debt": resolution.get("evidence_debt", False),
        "state_resolution": resolution,
        "cold_start": cold_start,
        "writes_performed": list(cold_start.get("writes_performed") or []),
        "effects": _effects(),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="continuity-state",
        description="Resolve state evidence and gate cold-start without applying live state.",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    evaluate = sub.add_parser("evaluate", help="resolve one bounded evidence bundle")
    evaluate.add_argument("--input", required=True, help="state-resolution bundle JSON")

    prepare = sub.add_parser(
        "prepare-cold-start",
        help="prepare cold-start only when resolved state is operationally accepted",
    )
    prepare.add_argument("--input", required=True, help="state-resolution bundle JSON")
    prepare.add_argument("--boot-receipt", required=True)
    prepare.add_argument("--spec", required=True)
    prepare.add_argument("--output", required=True)

    args = parser.parse_args(argv)

    if args.cmd == "evaluate":
        try:
            candidates = load_bundle(Path(args.input).expanduser())
            result = resolve_state(candidates)
        except Exception as exc:
            result = _error_result(exc)
    else:
        try:
            result = prepare_state_bound_cold_start(
                Path(args.input).expanduser(),
                Path(args.boot_receipt).expanduser(),
                Path(args.spec).expanduser(),
                Path(args.output).expanduser(),
            )
        except Exception as exc:
            result = _state_bound_error(exc)

    print(canonical_json_text(result), end="")
    return exit_code_for_result(result)


if __name__ == "__main__":
    raise SystemExit(main())
