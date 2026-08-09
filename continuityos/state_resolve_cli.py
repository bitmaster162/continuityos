"""CLI for ContinuityOS state/evidence reconciliation and state-bound cold-start.

``evaluate`` is pure/read-only. ``prepare-cold-start`` first resolves one bounded
state bundle and refuses to create a cold-start challenge unless the resolved
operational state is accepted. Conditional acceptance is clamped to READ_ONLY.
Only then does it delegate to the existing ANTI_AMNESIA cold-start preparer.
It never deploys, applies current state, trades, changes capital permissions, or
activates memory.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
from typing import Any
import uuid

from .gate.cold_start import prepare_cold_start_challenge
from .gate.state_resolution import canonical_json_text, resolve_state

BUNDLE_SCHEMA = "continuityos.state_resolution.bundle/v1"
STATE_BOUND_COLD_START_SCHEMA = "continuityos.state_bound_cold_start.receipt/v1"
MAX_INPUT_BYTES = 4 * 1024 * 1024
MAX_CANDIDATES = 4096
OPERATIONALLY_ACCEPTED = {"PASS", "PASS_WITH_CONDITIONS"}
KNOWN_EFFECT_CEILINGS = {
    "READ_ONLY",
    "REVERSIBLE_LOCAL_IMPLEMENTATION",
    "COMPENSATABLE_HUMAN_APPROVAL",
    "IRREVERSIBLE_HUMAN_APPROVAL",
}


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


def _read_json_with_sha(path: Path, label: str) -> tuple[Any, str]:
    """Read, stability-check, hash and parse one exact JSON payload."""
    path = Path(path)
    if path.is_symlink():
        raise ValueError(f"{label} path may not be a symlink")
    if not path.is_file():
        raise FileNotFoundError(f"{label} file is missing")
    before = path.stat()
    if before.st_size > MAX_INPUT_BYTES:
        raise ValueError(f"{label} exceeds {MAX_INPUT_BYTES} bytes")

    payload = path.read_bytes()
    after = path.stat()
    if len(payload) > MAX_INPUT_BYTES:
        raise ValueError(f"{label} exceeds {MAX_INPUT_BYTES} bytes")
    if (
        before.st_size != after.st_size
        or before.st_mtime_ns != after.st_mtime_ns
        or before.st_ctime_ns != after.st_ctime_ns
    ):
        raise ValueError(f"{label} changed during read")

    try:
        text = payload.decode("utf-8-sig")
        value = json.loads(text, object_pairs_hook=_reject_duplicate_keys)
    except Exception as exc:
        raise ValueError(
            f"{label} is not strict UTF-8 JSON: {type(exc).__name__}: {exc}"
        ) from exc
    return value, hashlib.sha256(payload).hexdigest()


def _load_bundle_with_sha(path: Path) -> tuple[list[dict[str, Any]], str]:
    value, payload_sha = _read_json_with_sha(path, "input")
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
    return candidates, payload_sha


def _load_spec_effect_ceiling_with_sha(path: Path) -> tuple[str, str]:
    value, payload_sha = _read_json_with_sha(path, "cold_start.spec")
    if not isinstance(value, dict):
        raise ValueError("cold_start.spec root must be an object")
    effect_ceiling = value.get("effect_ceiling")
    if effect_ceiling not in KNOWN_EFFECT_CEILINGS:
        raise ValueError("cold_start.spec effect_ceiling is missing or unsupported")
    return effect_ceiling, payload_sha


def load_bundle(path: Path) -> list[dict[str, Any]]:
    candidates, _ = _load_bundle_with_sha(path)
    return candidates


def exit_code_for_result(result: dict[str, Any]) -> int:
    terminal = result.get("terminal")
    if terminal in {"STATE_RESOLUTION_PASS", "STATE_BOUND_COLD_START_PASS"}:
        return 0
    if terminal in {"STATE_RESOLUTION_HOLD", "STATE_BOUND_COLD_START_HOLD"}:
        return 3
    return 2


def _verified_prepare(
    boot_receipt: Path,
    spec: Path,
    output: Path,
    *,
    expected_spec_sha256: str,
) -> dict[str, Any]:
    """Prepare off-path, prove the challenge bound the expected spec, then publish."""
    target = Path(output).expanduser().absolute()
    if target.exists():
        raise FileExistsError("output target already exists")
    target.parent.mkdir(parents=True, exist_ok=True)
    temp_target = target.with_name(
        f".{target.name}.state-bound-{os.getpid()}-{uuid.uuid4().hex}"
    )
    if temp_target.exists():
        raise FileExistsError("temporary output target already exists")

    try:
        cold_start = prepare_cold_start_challenge(
            Path(boot_receipt), Path(spec), temp_target
        )
        challenge, _ = _read_json_with_sha(
            temp_target / "COLD_START_CHALLENGE.json",
            "cold_start.generated_challenge",
        )
        if not isinstance(challenge, dict):
            raise ValueError("generated cold-start challenge must be an object")
        session_spec = challenge.get("session_spec")
        if not isinstance(session_spec, dict):
            raise ValueError("generated cold-start challenge has no session_spec binding")
        if session_spec.get("sha256") != expected_spec_sha256:
            raise ValueError("cold-start spec changed before challenge binding")

        os.replace(temp_target, target)
        cold_start = dict(cold_start)
        cold_start["output_dir"] = str(target.resolve())
        return cold_start
    except Exception:
        shutil.rmtree(temp_target, ignore_errors=True)
        raise


def prepare_state_bound_cold_start(
    state_bundle: Path,
    boot_receipt: Path,
    spec: Path,
    output: Path,
) -> dict[str, Any]:
    """Prepare a cold-start challenge only after accepted state resolution.

    A successful resolver terminal is not enough by itself: the selected current
    status must be exactly PASS or PASS_WITH_CONDITIONS. Conditional acceptance
    is constrained to a READ_ONLY cold-start spec. OPEN/PARTIAL/HOLD/REJECT/REVISE
    all block cold-start creation and therefore perform no final-output writes.
    """
    candidates, bundle_sha = _load_bundle_with_sha(Path(state_bundle))
    resolution = resolve_state(candidates)
    resolution_sha = hashlib.sha256(
        canonical_json_text(resolution).encode("utf-8")
    ).hexdigest()

    if resolution.get("terminal") != "STATE_RESOLUTION_PASS":
        return {
            "schema": STATE_BOUND_COLD_START_SCHEMA,
            "terminal": "STATE_BOUND_COLD_START_HOLD",
            "reason": "STATE_RESOLUTION_NOT_PASS",
            "state_bundle_sha256": bundle_sha,
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
            "state_bundle_sha256": bundle_sha,
            "state_resolution_sha256": resolution_sha,
            "state_resolution": resolution,
            "cold_start": None,
            "writes_performed": [],
            "effects": _effects(),
        }

    effect_ceiling, spec_sha = _load_spec_effect_ceiling_with_sha(Path(spec))
    if current_status == "PASS_WITH_CONDITIONS" and effect_ceiling != "READ_ONLY":
        return {
            "schema": STATE_BOUND_COLD_START_SCHEMA,
            "terminal": "STATE_BOUND_COLD_START_HOLD",
            "reason": "CONDITIONAL_STATE_REQUIRES_READ_ONLY",
            "state_bundle_sha256": bundle_sha,
            "state_resolution_sha256": resolution_sha,
            "spec_sha256": spec_sha,
            "requested_effect_ceiling": effect_ceiling,
            "allowed_effect_ceiling": "READ_ONLY",
            "state_resolution": resolution,
            "cold_start": None,
            "writes_performed": [],
            "effects": _effects(),
        }

    cold_start = _verified_prepare(
        Path(boot_receipt),
        Path(spec),
        Path(output),
        expected_spec_sha256=spec_sha,
    )
    return {
        "schema": STATE_BOUND_COLD_START_SCHEMA,
        "terminal": "STATE_BOUND_COLD_START_PASS",
        "reason": "OPERATIONAL_STATE_ACCEPTED",
        "state_bundle_sha256": bundle_sha,
        "state_resolution_sha256": resolution_sha,
        "spec_sha256": spec_sha,
        "requested_effect_ceiling": effect_ceiling,
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
