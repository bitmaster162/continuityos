from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from .bench.arena import ProspectiveArena
from .bench.envelope import BASELINES, build_standard_inputs
from .canon import sha256_obj
from .errors import SctError
from .r13 import (
    R13CasePredictionRunner,
    authorize_case001_r13,
    ensure_r13_protocol_amended,
    freeze_case_mapping,
    qualify_r13_pre_case_gate,
    r13_enrollment_gate_status,
    r13_protocol_manifest,
    record_r13_qualification_pass,
    require_r13_enrollment_authorized,
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


def _read_text(path: str | None, *, default: str = "") -> str:
    if not path:
        return default
    return Path(path).expanduser().read_text(encoding="utf-8")


def _sha_file(path: str) -> str:
    return hashlib.sha256(Path(path).expanduser().read_bytes()).hexdigest()


def _emit(value, code=0):
    print(json.dumps(value, sort_keys=True, ensure_ascii=False))
    return code


def _validated_sealed_model(store, path: str) -> dict:
    manifest = validate_model_selection_manifest(_json_file(path))
    model_events = list(store.query(kind="R13_MODEL_SELECTION_SEALED"))
    if not model_events or model_events[-1].payload.get("model_selection_manifest_sha256") != manifest["manifest_sha256"]:
        raise SctError("sealed R13 model manifest does not match --model-manifest")
    return manifest


def _require_protocol(store, protocol_sha: str) -> None:
    events = list(store.query(kind="R13_PRECASE_PROTOCOL_AMENDED"))
    if not events or events[-1].payload.get("manifest_sha256") != protocol_sha:
        raise SctError("sealed R13 protocol does not match --protocol-manifest-sha256")


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

    op = sub.add_parser("open-case")
    op.add_argument("--id", required=True)
    op.add_argument("--situation", required=True)
    op.add_argument("--option", action="append", required=True)
    op.add_argument("--model-manifest", required=True)
    op.add_argument("--protocol-manifest-sha256", required=True)
    op.add_argument("--static-profile-file", required=True)
    op.add_argument("--permitted-history-file")
    op.add_argument("--sct-state-file", required=True)
    op.add_argument("--token-budget", type=int, default=4096)
    op.add_argument("--temperature", type=float, default=0.0)
    op.add_argument("--reasoning", default="fixed")
    op.add_argument("--project-id", default="")
    op.add_argument("--domain-id", required=True)
    op.add_argument("--time-epoch", required=True)
    op.add_argument("--decision-family", required=True)
    op.add_argument("--assistant-influence", choices=["NONE", "ADVICE_GIVEN", "INCLINATION_DISCLOSED", "UNKNOWN"], required=True)

    predict = sub.add_parser("predict-case")
    predict.add_argument("case_id")
    predict.add_argument("--model-manifest", required=True)
    predict.add_argument("--protocol-manifest-sha256", required=True)
    predict.add_argument("--runner", nargs=argparse.REMAINDER, required=True)
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
        if args.cmd == "open-case":
            gate = require_r13_enrollment_authorized(store)
            manifest = _validated_sealed_model(store, args.model_manifest)
            _require_protocol(store, args.protocol_manifest_sha256)
            model_id = manifest["model_repo_or_provider_id"]
            model_version = manifest["model_revision"]
            arena = ProspectiveArena(store)
            inputs = build_standard_inputs(
                scenario=args.situation,
                options=args.option,
                provider=model_id,
                model=model_id,
                model_version=model_version,
                static_profile=_read_text(args.static_profile_file),
                permitted_history=_read_text(args.permitted_history_file),
                sct_state=_read_text(args.sct_state_file),
                token_budget=args.token_budget,
                temperature=args.temperature,
                reasoning=args.reasoning,
                frozen_at=__import__("time").time(),
            )
            case = arena.open_case(
                case_id=args.id,
                situation=args.situation,
                options=args.option,
                inputs=inputs,
                cluster={
                    "project_id": args.project_id,
                    "domain_id": args.domain_id,
                    "time_epoch": args.time_epoch,
                    "decision_family": args.decision_family,
                },
                assistant_influence=args.assistant_influence,
            )
            mapping = freeze_case_mapping(
                store,
                case_id=args.id,
                semantic_options=case["options"],
                alias_manifest=manifest,
                protocol_manifest_sha256=args.protocol_manifest_sha256,
                model_selection_manifest_sha256=manifest["manifest_sha256"],
            )
            requests = arena.requests(args.id)
            return _emit({
                "ok": True,
                "case": case,
                "r13_gate": gate,
                "mapping": mapping,
                "request_hashes": {arm: sha256_obj(requests[arm]) for arm in BASELINES},
                "execution_authority": "NONE",
            })
        if args.cmd == "predict-case":
            if not args.runner:
                raise SctError("--runner requires executable and optional arguments")
            gate = require_r13_enrollment_authorized(store)
            manifest = _validated_sealed_model(store, args.model_manifest)
            _require_protocol(store, args.protocol_manifest_sha256)
            arena = ProspectiveArena(store)
            case = arena._case_event(args.case_id)
            if case is None:
                raise SctError("case not open")
            frozen_model = manifest["model_repo_or_provider_id"]
            frozen_version = manifest["model_revision"]
            for request in arena.requests(args.case_id).values():
                if request.get("model") != frozen_model or request.get("model_version") != frozen_version:
                    raise SctError("CASE_MODEL_IDENTITY_MISMATCH_WITH_SEALED_R13_SUBSTRATE")
            mapping = freeze_case_mapping(
                store,
                case_id=args.case_id,
                semantic_options=case.payload["options"],
                alias_manifest=manifest,
                protocol_manifest_sha256=args.protocol_manifest_sha256,
                model_selection_manifest_sha256=manifest["manifest_sha256"],
            )
            runner = R13CasePredictionRunner(
                logit_runner=SubprocessLogitRunner(args.runner),
                case_id=args.case_id,
                mapping=mapping["semantic_to_alias"],
                textual_order=mapping["textual_order"],
                model_manifest=manifest,
            )
            requests = arena.requests(args.case_id)
            predictions = {}
            for arm in BASELINES:
                try:
                    response = runner.predict(requests[arm], arm=arm)
                except Exception as exc:
                    arena.void_case(args.case_id, f"R13_LOGIT_RUNNER_FAILURE:{type(exc).__name__}")
                    raise SctError(f"R13 logit runner failure: {type(exc).__name__}") from exc
                predictions[arm] = arena.submit_prediction(args.case_id, arm, response)
            return _emit({
                "ok": True,
                "r13_gate": gate,
                "mapping": mapping,
                "predictions": {arm: pred.to_dict() for arm, pred in predictions.items()},
                "execution_authority": "NONE",
            })
        raise SctError("unsupported R13 command")
    except (SctError, ValueError) as exc:
        return _emit({"ok": False, "error": str(exc), "execution_authority": "NONE"}, 2)
    except Exception as exc:
        return _emit({"ok": False, "error": str(exc), "error_class": type(exc).__name__, "execution_authority": "NONE"}, 2)
    finally:
        store.close()


if __name__ == "__main__":
    raise SystemExit(main())
