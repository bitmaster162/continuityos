from __future__ import annotations

import argparse
import json
from pathlib import Path

from .bench.arena import ProspectiveArena
from .bench.envelope import BASELINES, build_standard_inputs
from .baseline_r13 import build_arm_b_profile_rag
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
)
from .r13_attempt import (
    finish_r13_component_attempt,
    r13_attempt_status,
    record_r13_component_abort,
    record_verified_r13_operator_attestation,
    require_recorded_r13_component_receipts,
    start_r13_component_attempt,
)
from .r13_attestation import validate_r13_operator_attestation
from .r13_manifest_guard import validate_baseline_for_seal, validate_model_manifest_for_seal
from .r13_live_provenance import build_arm_b_live_provenance_receipt, canonical_evidence_blob
from .runner.logits import CapturingLogitRunner, ManifestBoundLogitRunner, SubprocessLogitRunner
from .store.sqlite import SQLiteEvidenceStore


def _json_file(path: str) -> dict:
    value = json.loads(Path(path).expanduser().read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise SctError(f"JSON object required: {path}")
    return value


def _json_array_file(path: str) -> list[dict]:
    value = json.loads(Path(path).expanduser().read_text(encoding="utf-8"))
    if not isinstance(value, list) or not all(isinstance(row, dict) for row in value):
        raise SctError(f"JSON array of objects required: {path}")
    return value


def _read_text(path: str | None, *, default: str = "") -> str:
    if not path:
        return default
    return Path(path).expanduser().read_text(encoding="utf-8")


def _emit(value, code=0):
    print(json.dumps(value, sort_keys=True, ensure_ascii=False))
    return code


def _require_protocol(store, protocol_sha: str) -> None:
    events = list(store.query(kind="R13_PRECASE_PROTOCOL_AMENDED"))
    if not events or events[-1].payload.get("manifest_sha256") != protocol_sha:
        raise SctError("sealed R13 protocol does not match --protocol-manifest-sha256")


def _sealed_model(store, path: str) -> dict:
    manifest = validate_model_manifest_for_seal(_json_file(path))
    events = list(store.query(kind="R13_MODEL_SELECTION_SEALED"))
    if not events or events[-1].payload.get("model_selection_manifest_sha256") != manifest["manifest_sha256"]:
        raise SctError("sealed R13 model manifest does not match --model-manifest")
    return manifest


def _capturing_runner(command, manifest) -> CapturingLogitRunner:
    if not command:
        raise SctError("--runner requires executable and optional arguments")
    base = SubprocessLogitRunner(command)
    bound = ManifestBoundLogitRunner.from_model_manifest(base, manifest)
    return CapturingLogitRunner(bound)


def _trace_receipt(receipt: dict, capture: CapturingLogitRunner) -> dict:
    return {
        **receipt,
        "raw_logit_trace": tuple(capture.records),
        "raw_logit_trace_sha256": sha256_obj(capture.records),
    }


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
        c.add_argument("--source-sha", required=True)
        c.add_argument("--source-tree-sha", required=True)
        c.add_argument("--runner", nargs=argparse.REMAINDER, required=True)

    qualify = sub.add_parser("qualify")
    qualify.add_argument("--model-manifest", required=True)
    qualify.add_argument("--preflight-receipt", required=True)
    qualify.add_argument("--sentinel-receipt", required=True)
    qualify.add_argument("--stable-void-receipt", required=True)
    qualify.add_argument("--operator-attestation", required=True)
    qualify.add_argument("--source-sha", required=True)
    qualify.add_argument("--source-tree-sha", required=True)

    sub.add_parser("status")

    auth = sub.add_parser("authorize-case001")
    auth.add_argument("--approval", required=True)

    op = sub.add_parser("open-case")
    op.add_argument("--id", required=True)
    op.add_argument("--situation", required=True)
    op.add_argument("--option", action="append", required=True)
    op.add_argument("--model-manifest", required=True)
    op.add_argument("--protocol-manifest-sha256", required=True)
    op.add_argument("--arm-b-evidence-file", required=True)
    op.add_argument("--arm-b-source-cutoff", type=float, required=True)
    op.add_argument("--arm-b-expected-pool-sha256", required=True)
    op.add_argument("--sct-state-file", required=True)
    op.add_argument("--token-budget", type=int, default=4096)
    op.add_argument("--temperature", type=float, default=0.0)
    op.add_argument("--reasoning", default="fixed")
    op.add_argument("--project-id", default="")
    op.add_argument("--domain-id", required=True)
    op.add_argument("--time-epoch", required=True)
    op.add_argument("--decision-family", required=True)
    op.add_argument(
        "--assistant-influence",
        choices=["NONE", "ADVICE_GIVEN", "INCLINATION_DISCLOSED", "UNKNOWN"],
        required=True,
    )

    predict = sub.add_parser("predict-case")
    predict.add_argument("case_id")
    predict.add_argument("--model-manifest", required=True)
    predict.add_argument("--protocol-manifest-sha256", required=True)
    predict.add_argument("--runner", nargs=argparse.REMAINDER, required=True)
    return p


def _run_component(args, store, manifest):
    component = args.cmd
    model_sha = manifest["manifest_sha256"]
    start_r13_component_attempt(
        store,
        component=component,
        protocol_manifest_sha256=args.protocol_manifest_sha256,
        model_selection_manifest_sha256=model_sha,
        source_code_sha=args.source_sha,
        source_tree_sha=args.source_tree_sha,
    )
    runner = _capturing_runner(args.runner, manifest)
    try:
        if component == "preflight":
            out = run_r13_determinism_preflight(
                logit_runner=runner,
                model_manifest=manifest,
                protocol_manifest_sha256=args.protocol_manifest_sha256,
            )
            pass_field = "deterministic"
        elif component == "context-sentinel":
            out = run_r13_balanced_context_sentinel(
                logit_runner=runner,
                model_manifest=manifest,
                protocol_manifest_sha256=args.protocol_manifest_sha256,
            )
            pass_field = "satisfies_context_responsiveness_gate"
        else:
            out = run_r13_stable_void(
                logit_runner=runner,
                model_manifest=manifest,
                protocol_manifest_sha256=args.protocol_manifest_sha256,
            )
            pass_field = "stable_void_pass"
        out = _trace_receipt(out, runner)
        finish_r13_component_attempt(store, component=component, receipt=out)
        return _emit(
            out,
            0 if out.get(pass_field) is True else 2,
        )
    except Exception as exc:
        try:
            record_r13_component_abort(
                store,
                component=component,
                protocol_manifest_sha256=args.protocol_manifest_sha256,
                model_selection_manifest_sha256=model_sha,
                failure_class=type(exc).__name__,
            )
        except Exception:
            # ATTEMPT_STARTED already makes the binding terminal even if the abort receipt cannot be appended.
            pass
        raise


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    store = SQLiteEvidenceStore(Path(args.db).expanduser())
    try:
        if args.cmd == "amend":
            manifest = r13_protocol_manifest(r2_diagnostic_sha256=args.r2_diagnostic_sha256)
            recorded = ensure_r13_protocol_amended(store, manifest)
            return _emit({"ok": True, "manifest": manifest, "recorded": recorded})

        if args.cmd == "seal-model":
            _require_protocol(store, args.protocol_manifest_sha256)
            manifest = validate_model_manifest_for_seal(_json_file(args.manifest))
            recorded = seal_model_selection(
                store, manifest, protocol_manifest_sha256=args.protocol_manifest_sha256
            )
            return _emit({"ok": True, "manifest": manifest, "recorded": recorded})

        if args.cmd == "seal-baseline":
            _require_protocol(store, args.protocol_manifest_sha256)
            spec = validate_baseline_for_seal(_json_file(args.manifest))
            recorded = seal_baseline_spec(
                store, spec, protocol_manifest_sha256=args.protocol_manifest_sha256
            )
            return _emit({"ok": True, "manifest": spec, "recorded": recorded})

        if args.cmd in {"preflight", "context-sentinel", "stable-void"}:
            _require_protocol(store, args.protocol_manifest_sha256)
            manifest = _sealed_model(store, args.model_manifest)
            return _run_component(args, store, manifest)

        if args.cmd == "qualify":
            manifest = _sealed_model(store, args.model_manifest)
            preflight = _json_file(args.preflight_receipt)
            sentinel = _json_file(args.sentinel_receipt)
            stable = _json_file(args.stable_void_receipt)
            attestation = _json_file(args.operator_attestation)
            component_bindings = require_recorded_r13_component_receipts(
                store,
                preflight=preflight,
                sentinel=sentinel,
                stable_void=stable,
                expected_source_sha=args.source_sha,
                expected_source_tree_sha=args.source_tree_sha,
            )
            if component_bindings["model_selection_manifest_sha256"] != manifest["manifest_sha256"]:
                raise SctError("R13 recorded component receipts do not match sealed model manifest")
            verify = store.verify()
            validated_attestation = validate_r13_operator_attestation(
                attestation,
                model_manifest=manifest,
                preflight=preflight,
                sentinel=sentinel,
                stable_void=stable,
                expected_source_sha=args.source_sha,
                expected_source_tree_sha=args.source_tree_sha,
                store_verify_ok=verify.ok,
            )
            attestation_event = record_verified_r13_operator_attestation(store, validated_attestation)
            result = qualify_r13_pre_case_gate(
                preflight,
                sentinel,
                stable,
                operator_attestation_sha256=validated_attestation["attestation_sha256"],
                operator_attestation_verified=True,
            )
            recorded = (
                record_r13_qualification_pass(store, result)
                if result["scientific_pre_case_gate_pass"]
                else None
            )
            return _emit(
                {
                    "qualification": result,
                    "component_bindings": component_bindings,
                    "validated_operator_attestation": validated_attestation,
                    "operator_attestation_event": attestation_event,
                    "recorded": recorded,
                    "r13": r13_enrollment_gate_status(store),
                    "attempt": r13_attempt_status(store),
                },
                0 if result["scientific_pre_case_gate_pass"] else 2,
            )

        if args.cmd == "status":
            return _emit({"r13": r13_enrollment_gate_status(store), "attempt": r13_attempt_status(store)})

        if args.cmd == "authorize-case001":
            recorded = authorize_case001_r13(store, approval_token=args.approval)
            return _emit(
                {"ok": True, "recorded": recorded, "r13": r13_enrollment_gate_status(store)}
            )

        if args.cmd == "open-case":
            gate = require_r13_enrollment_authorized(store)
            _require_protocol(store, args.protocol_manifest_sha256)
            manifest = _sealed_model(store, args.model_manifest)
            model_id = manifest["model_repo_or_provider_id"]
            model_version = manifest["model_revision"]
            evidence_rows = _json_array_file(args.arm_b_evidence_file)
            sct_state = _read_text(args.sct_state_file)
            target_context_bytes = len(sct_state.encode("utf-8"))
            builder_output = build_arm_b_profile_rag(
                scenario=args.situation,
                options=args.option,
                evidence_rows=evidence_rows,
                source_cutoff=args.arm_b_source_cutoff,
                target_context_bytes=target_context_bytes,
                expected_admitted_pool_sha256=args.arm_b_expected_pool_sha256,
            )
            frozen_at = __import__("time").time()
            inputs = build_standard_inputs(
                scenario=args.situation,
                options=args.option,
                provider=model_id,
                model=model_id,
                model_version=model_version,
                static_profile=builder_output["static_profile"],
                permitted_history=builder_output["permitted_history"],
                sct_state=sct_state,
                token_budget=args.token_budget,
                temperature=args.temperature,
                reasoning=args.reasoning,
                frozen_at=frozen_at,
            )
            baseline_events = list(store.query(kind="R13_BASELINE_SPEC_SEALED"))
            if not baseline_events:
                raise SctError("R13 Arm B baseline must be sealed before LIVE provenance")
            evidence_blob_sha256 = store.put_blob(canonical_evidence_blob(evidence_rows))
            arm_b_provenance = build_arm_b_live_provenance_receipt(
                case_id=args.id,
                scenario=args.situation,
                options=args.option,
                evidence_rows=evidence_rows,
                evidence_blob_sha256=evidence_blob_sha256,
                source_cutoff=args.arm_b_source_cutoff,
                target_context_bytes=target_context_bytes,
                expected_admitted_pool_sha256=args.arm_b_expected_pool_sha256,
                builder_output=builder_output,
                profile_rag_snapshot_sha256=inputs["profile_rag"].snapshot_sha256,
                baseline_manifest_sha256=baseline_events[-1].payload["baseline_manifest_sha256"],
            )
            store.append("R13_ARM_B_LIVE_PROVENANCE_VERIFIED", arm_b_provenance)
            arena = ProspectiveArena(store)
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
                frozen_at=frozen_at,
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
            return _emit(
                {
                    "ok": True,
                    "case": case,
                    "r13_gate": gate,
                    "mapping": mapping,
                    "arm_b_provenance": arm_b_provenance,
                    "request_hashes": {arm: sha256_obj(requests[arm]) for arm in BASELINES},
                    "execution_authority": "NONE",
                }
            )

        if args.cmd == "predict-case":
            gate = require_r13_enrollment_authorized(store)
            _require_protocol(store, args.protocol_manifest_sha256)
            manifest = _sealed_model(store, args.model_manifest)
            arena = ProspectiveArena(store)
            case = arena._case_event(args.case_id)
            if case is None:
                raise SctError("case not open")
            frozen_model = manifest["model_repo_or_provider_id"]
            frozen_version = manifest["model_revision"]
            requests = arena.requests(args.case_id)
            for request in requests.values():
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
            capture = _capturing_runner(args.runner, manifest)
            runner = R13CasePredictionRunner(
                logit_runner=capture,
                case_id=args.case_id,
                mapping=mapping["semantic_to_alias"],
                textual_order=mapping["textual_order"],
                model_manifest=manifest,
            )
            predictions = {}
            for arm in BASELINES:
                before = len(capture.records)
                try:
                    response = runner.predict(requests[arm], arm=arm)
                except Exception as exc:
                    arena.void_case(args.case_id, f"R13_LOGIT_RUNNER_FAILURE:{type(exc).__name__}")
                    raise SctError(f"R13 logit runner failure: {type(exc).__name__}") from exc
                if len(capture.records) != before + 1:
                    arena.void_case(args.case_id, "R13_RAW_LOGIT_TRACE_CARDINALITY_FAILURE")
                    raise SctError("R13 raw-logit trace cardinality mismatch")
                trace = capture.records[-1]
                measurement = {
                    "case_id": args.case_id,
                    "arm": arm,
                    "protocol_manifest_sha256": args.protocol_manifest_sha256,
                    "model_selection_manifest_sha256": manifest["manifest_sha256"],
                    "mapping_sha256": mapping["mapping_sha256"],
                    "semantic_to_alias": mapping["semantic_to_alias"],
                    "raw_logit_trace": trace,
                    "option_probabilities": response["option_probabilities"],
                    "probability_vector_sha256": sha256_obj(response["option_probabilities"]),
                    "execution_authority": "NONE",
                    "can_execute": False,
                }
                store.append("R13_FORECAST_MEASUREMENT_COMMITTED", measurement)
                predictions[arm] = arena.submit_prediction(args.case_id, arm, response)
            return _emit(
                {
                    "ok": True,
                    "r13_gate": gate,
                    "mapping": mapping,
                    "predictions": {arm: pred.to_dict() for arm, pred in predictions.items()},
                    "raw_logit_trace_sha256": sha256_obj(capture.records),
                    "execution_authority": "NONE",
                }
            )

        raise SctError("unsupported R13 command")
    except (SctError, ValueError) as exc:
        return _emit({"ok": False, "error": str(exc), "execution_authority": "NONE"}, 2)
    except Exception as exc:
        return _emit(
            {
                "ok": False,
                "error": str(exc),
                "error_class": type(exc).__name__,
                "execution_authority": "NONE",
            },
            2,
        )
    finally:
        store.close()


if __name__ == "__main__":
    raise SystemExit(main())
