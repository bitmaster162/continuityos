from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from .errors import SctError
from .r13 import (
    authorize_case001_r13,
    ensure_r13_protocol_amended,
    qualify_r13_pre_case_gate,
    r13_enrollment_gate_status,
    r13_protocol_manifest,
    record_r13_qualification_pass,
    run_r13_balanced_context_sentinel,
    run_r13_determinism_preflight,
    run_r13_stable_void,
    seal_baseline_spec,
    seal_model_selection,
    validate_model_selection_manifest,
)
from .runner.logits import SubprocessLogitRunner
from .store.sqlite import SQLiteEvidenceStore


def _json_file(path: str) -> dict:
    value = json.loads(Path(path).expanduser().read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise SctError(f"JSON object required: {path}")
    return value


def _sha_file(path: str) -> str:
    return hashlib.sha256(Path(path).expanduser().read_bytes()).hexdigest()


def _emit(value, code=0):
    print(json.dumps(value, sort_keys=True, ensure_ascii=False))
    return code


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="sct-r13")
    p.add_argument("--db", default=str(Path.home() / ".sct" / "evidence.db"))
    sub = p.add_subparsers(dest="cmd", required=True)

    amend = sub.add_parser("amend")
    amend.add_argument("--r2-diagnostic-sha256", required=True)

    model = sub.add_parser("seal-model")
    model.add_argument("--manifest", required=True)
    model.add_argument("--protocol-manifest-sha256", required=True)

    baseline = sub.add_parser("seal-baseline")
    baseline.add_argument("--manifest", required=True)
    baseline.add_argument("--protocol-manifest-sha256", required=True)

    for name in ("preflight", "context-sentinel", "stable-void"):
        c = sub.add_parser(name)
        c.add_argument("--model-manifest", required=True)
        c.add_argument("--protocol-manifest-sha256", required=True)
        c.add_argument("--runner", nargs=argparse.REMAINDER, required=True)

    qualify = sub.add_parser("qualify")
    qualify.add_argument("--preflight-receipt", required=True)
    qualify.add_argument("--sentinel-receipt", required=True)
    qualify.add_argument("--stable-void-receipt", required=True)
    qualify.add_argument("--operator-attestation", required=True)
    qualify.add_argument("--operator-attestation-verified", action="store_true")

    sub.add_parser("status")

    auth = sub.add_parser("authorize-case001")
    auth.add_argument("--approval", required=True)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    store = SQLiteEvidenceStore(Path(args.db).expanduser())
    try:
        if args.cmd == "amend":
            manifest = r13_protocol_manifest(r2_diagnostic_sha256=args.r2_diagnostic_sha256)
            recorded = ensure_r13_protocol_amended(store, manifest)
            return _emit({"ok": True, "manifest": manifest, "recorded": recorded})
        if args.cmd == "seal-model":
            manifest = _json_file(args.manifest)
            validated = validate_model_selection_manifest(manifest)
            recorded = seal_model_selection(store, validated, protocol_manifest_sha256=args.protocol_manifest_sha256)
            return _emit({"ok": True, "manifest": validated, "recorded": recorded})
        if args.cmd == "seal-baseline":
            spec = _json_file(args.manifest)
            recorded = seal_baseline_spec(store, spec, protocol_manifest_sha256=args.protocol_manifest_sha256)
            return _emit({"ok": True, "recorded": recorded})
        if args.cmd in {"preflight", "context-sentinel", "stable-void"}:
            if not args.runner:
                raise SctError("--runner requires executable and optional arguments")
            manifest = _json_file(args.model_manifest)
            runner = SubprocessLogitRunner(args.runner)
            if args.cmd == "preflight":
                out = run_r13_determinism_preflight(
                    logit_runner=runner,
                    model_manifest=manifest,
                    protocol_manifest_sha256=args.protocol_manifest_sha256,
                )
                return _emit(out, 0 if out["deterministic"] else 2)
            if args.cmd == "context-sentinel":
                out = run_r13_balanced_context_sentinel(
                    logit_runner=runner,
                    model_manifest=manifest,
                    protocol_manifest_sha256=args.protocol_manifest_sha256,
                )
                return _emit(out, 0 if out["satisfies_context_responsiveness_gate"] else 2)
            out = run_r13_stable_void(
                logit_runner=runner,
                model_manifest=manifest,
                protocol_manifest_sha256=args.protocol_manifest_sha256,
            )
            return _emit(out, 0 if out["stable_void_pass"] else 2)
        if args.cmd == "qualify":
            preflight = _json_file(args.preflight_receipt)
            sentinel = _json_file(args.sentinel_receipt)
            stable = _json_file(args.stable_void_receipt)
            result = qualify_r13_pre_case_gate(
                preflight,
                sentinel,
                stable,
                operator_attestation_sha256=_sha_file(args.operator_attestation),
                operator_attestation_verified=args.operator_attestation_verified,
            )
            recorded = record_r13_qualification_pass(store, result) if result["scientific_pre_case_gate_pass"] else None
            return _emit(
                {"qualification": result, "recorded": recorded, "r13": r13_enrollment_gate_status(store)},
                0 if result["scientific_pre_case_gate_pass"] else 2,
            )
        if args.cmd == "status":
            return _emit(r13_enrollment_gate_status(store))
        if args.cmd == "authorize-case001":
            recorded = authorize_case001_r13(store, approval_token=args.approval)
            return _emit({"ok": True, "recorded": recorded, "r13": r13_enrollment_gate_status(store)})
        raise SctError("unsupported R13 command")
    except (SctError, ValueError) as exc:
        return _emit({"ok": False, "error": str(exc), "execution_authority": "NONE"}, 2)
    except Exception as exc:
        return _emit({"ok": False, "error": str(exc), "error_class": type(exc).__name__, "execution_authority": "NONE"}, 2)
    finally:
        store.close()


if __name__ == "__main__":
    raise SystemExit(main())
