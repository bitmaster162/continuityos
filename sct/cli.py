from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

from .bench.arena import ProspectiveArena
from .bench.envelope import build_standard_inputs
from .dryrun import run_void_distribution_dryrun, run_real_model_void_dryrun, run_real_model_pool_void_dryrun
from .epoch import amendment_v2_manifest, ensure_epoch_amended, r12_precase_manifest, ensure_r12_precase_amended
from .errors import SctError
from .qualification import (
    authorize_case001_enrollment,
    qualify_r12_pre_case_gate,
    record_r12_qualification_pass,
    require_r12_enrollment_authorized,
    r12_enrollment_gate_status,
    run_context_responsiveness_sentinel,
    run_r12_stable_single_model_void_dryrun,
)
from .report import epoch_score_report
from .runner.provider import SubprocessJsonRunner
from .store.sqlite import SQLiteEvidenceStore

PARENT_COMMIT = "60f7558c13cb15a6ebac858747629ad1147852f6"
PARENT_TREE = "50e10dffed773144c4c5b16788ffad10f839bf6e"
R12_PARENT_COMMIT = "13256bae2395a514287ccb1685b24b249f087373"
R12_PARENT_TREE = "1393fe4efe2873b27194d628a1325c9b474899dd"


def _store(path: str) -> SQLiteEvidenceStore:
    return SQLiteEvidenceStore(Path(path).expanduser())


def _read_text(path: str | None, *, default: str = "") -> str:
    if not path:
        return default
    return Path(path).expanduser().read_text(encoding="utf-8")


def _read_json(path: str) -> dict:
    value = json.loads(Path(path).expanduser().read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise SctError(f"JSON object required: {path}")
    return value


def _sha256_file(path: str) -> str:
    return hashlib.sha256(Path(path).expanduser().read_bytes()).hexdigest()


def _command_sha(command: list[str]) -> str:
    return hashlib.sha256("\0".join(command).encode("utf-8")).hexdigest()


def _is_sha256(value: str) -> bool:
    return len(value) == 64 and all(ch in "0123456789abcdefABCDEF" for ch in value)


def _json(data, *, exit_code: int = 0) -> int:
    print(json.dumps(data, ensure_ascii=False, sort_keys=True))
    return exit_code


def _ensure_amendment(store):
    manifest = amendment_v2_manifest(parent_commit=PARENT_COMMIT, parent_tree=PARENT_TREE)
    return ensure_epoch_amended(store, manifest)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="sct")
    p.add_argument("--db", default=str(Path.home() / ".sct" / "evidence.db"))
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("init")
    sub.add_parser("doctor")
    sub.add_parser("verify")
    sub.add_parser("dry-run")

    real = sub.add_parser("real-model-dry-run")
    real.add_argument("--cases", type=int, default=12)
    real.add_argument("--provider", required=True)
    real.add_argument("--model", required=True)
    real.add_argument("--model-version", required=True)
    real.add_argument("--runner", nargs=argparse.REMAINDER, required=True)

    pool = sub.add_parser("real-model-pool-dry-run")
    pool.add_argument("--cases", type=int, default=20)
    pool.add_argument("--min-complete", type=int, default=10)
    pool.add_argument("--provider", required=True)
    pool.add_argument("--model", action="append", required=True)
    pool.add_argument("--runner", nargs=argparse.REMAINDER, required=True)

    r12 = sub.add_parser("r12")
    r12s = r12.add_subparsers(dest="r12_cmd", required=True)

    amend = r12s.add_parser("amend")
    amend.add_argument("--r11-receipt-sha256", required=True)

    sentinel = r12s.add_parser("context-sentinel")
    sentinel.add_argument("--provider", required=True)
    sentinel.add_argument("--model", required=True)
    sentinel.add_argument("--model-version", required=True)
    sentinel.add_argument("--option", action="append")
    sentinel.add_argument("--token-budget", type=int, default=512)
    sentinel.add_argument("--temperature", type=float, default=0.0)
    sentinel.add_argument("--reasoning", default="fixed")
    sentinel.add_argument("--runner", nargs=argparse.REMAINDER, required=True)

    stable = r12s.add_parser("stable-void")
    stable.add_argument("--cases", type=int, default=12)
    stable.add_argument("--provider", required=True)
    stable.add_argument("--model", required=True)
    stable.add_argument("--model-version", required=True)
    stable.add_argument("--runner", nargs=argparse.REMAINDER, required=True)

    qualify = r12s.add_parser("qualify")
    qualify.add_argument("--void-receipt", required=True)
    qualify.add_argument("--context-receipt", required=True)
    qualify.add_argument("--operator-attestation", required=True)
    qualify.add_argument("--operator-attestation-verified", action="store_true")

    r12s.add_parser("status")

    auth = r12s.add_parser("authorize-case001")
    auth.add_argument("--approval", required=True)

    case = sub.add_parser("case")
    cs = case.add_subparsers(dest="case_cmd", required=True)

    op = cs.add_parser("open")
    op.add_argument("--id", required=True)
    op.add_argument("--situation", required=True)
    op.add_argument("--option", action="append", required=True)
    op.add_argument("--provider", required=True)
    op.add_argument("--model", required=True)
    op.add_argument("--model-version", required=True)
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

    pred = cs.add_parser("predict")
    pred.add_argument("case_id")
    pred.add_argument("--runner", nargs=argparse.REMAINDER, required=True)

    rev = cs.add_parser("reveal")
    rev.add_argument("case_id")
    rev.add_argument("--choice", required=True)

    sc = sub.add_parser("score")
    sc.add_argument("--inferential", action="store_true")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    store = _store(args.db)
    arena = ProspectiveArena(store)
    try:
        if args.cmd == "init":
            amendment = _ensure_amendment(store)
            return _json({"ok": True, "db": str(store.path), "head": store.head().__dict__, "epoch_amendment": amendment})
        if args.cmd == "doctor":
            amendment = _ensure_amendment(store)
            return _json({
                "ok": True,
                "capabilities": sorted(store.capabilities()),
                "verify": store.verify().__dict__,
                "epoch_amendment": amendment,
                "r12": r12_enrollment_gate_status(store),
            })
        if args.cmd == "verify":
            result = store.verify().__dict__
            return _json(result, exit_code=0 if result["ok"] else 2)
        if args.cmd == "dry-run":
            return _json(run_void_distribution_dryrun())
        if args.cmd == "real-model-dry-run":
            if not args.runner:
                raise SctError("--runner requires an executable and optional arguments")
            runner = SubprocessJsonRunner(args.runner)
            return _json(run_real_model_void_dryrun(
                runner=runner, cases=args.cases, provider=args.provider, model=args.model,
                model_version=args.model_version, runner_command_sha256=_command_sha(args.runner),
            ))
        if args.cmd == "real-model-pool-dry-run":
            if not args.runner:
                raise SctError("--runner requires an executable and optional arguments")
            runner = SubprocessJsonRunner(args.runner)
            result = run_real_model_pool_void_dryrun(
                runner=runner,
                cases=args.cases,
                min_complete=args.min_complete,
                provider=args.provider,
                models=args.model,
                runner_command_sha256=_command_sha(args.runner),
            )
            return _json(result, exit_code=0 if result["satisfies_real_model_gate"] else 2)
        if args.cmd == "r12" and args.r12_cmd == "amend":
            if not _is_sha256(args.r11_receipt_sha256):
                raise SctError("--r11-receipt-sha256 must be 64 hex characters")
            manifest = r12_precase_manifest(
                parent_commit=R12_PARENT_COMMIT,
                parent_tree=R12_PARENT_TREE,
                r11_receipt_sha256=args.r11_receipt_sha256.lower(),
            )
            recorded = ensure_r12_precase_amended(store, manifest)
            return _json({"ok": True, "manifest": manifest, "recorded": recorded})
        if args.cmd == "r12" and args.r12_cmd == "context-sentinel":
            if not args.runner:
                raise SctError("--runner requires an executable and optional arguments")
            runner = SubprocessJsonRunner(args.runner)
            result = run_context_responsiveness_sentinel(
                runner=runner,
                provider=args.provider,
                model=args.model,
                model_version=args.model_version,
                options=args.option or ("A", "B", "C"),
                token_budget=args.token_budget,
                temperature=args.temperature,
                reasoning=args.reasoning,
            )
            return _json(result, exit_code=0 if result["satisfies_context_responsiveness_gate"] else 2)
        if args.cmd == "r12" and args.r12_cmd == "stable-void":
            if not args.runner:
                raise SctError("--runner requires an executable and optional arguments")
            runner = SubprocessJsonRunner(args.runner)
            result = run_r12_stable_single_model_void_dryrun(
                runner=runner,
                cases=args.cases,
                provider=args.provider,
                model=args.model,
                model_version=args.model_version,
                runner_command_sha256=_command_sha(args.runner),
            )
            return _json(result, exit_code=0 if result["phase1_transport_component_pass"] else 2)
        if args.cmd == "r12" and args.r12_cmd == "qualify":
            void_receipt = _read_json(args.void_receipt)
            context_receipt = _read_json(args.context_receipt)
            attestation_sha = _sha256_file(args.operator_attestation)
            result = qualify_r12_pre_case_gate(
                void_receipt,
                context_receipt,
                operator_attestation_sha256=attestation_sha,
                operator_attestation_verified=args.operator_attestation_verified,
            )
            recorded = record_r12_qualification_pass(store, result) if result["scientific_pre_case_gate_pass"] else None
            return _json(
                {"qualification": result, "recorded": recorded, "r12": r12_enrollment_gate_status(store)},
                exit_code=0 if result["scientific_pre_case_gate_pass"] else 2,
            )
        if args.cmd == "r12" and args.r12_cmd == "status":
            return _json(r12_enrollment_gate_status(store))
        if args.cmd == "r12" and args.r12_cmd == "authorize-case001":
            recorded = authorize_case001_enrollment(store, approval_token=args.approval)
            return _json({"ok": True, "recorded": recorded, "r12": r12_enrollment_gate_status(store)})
        if args.cmd == "case" and args.case_cmd == "open":
            _ensure_amendment(store)
            r12_gate = require_r12_enrollment_authorized(store)
            inputs = build_standard_inputs(
                scenario=args.situation,
                options=args.option,
                provider=args.provider,
                model=args.model,
                model_version=args.model_version,
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
            requests = arena.requests(args.id)
            return _json({
                "ok": True,
                "case": case,
                "r12_gate": r12_gate,
                "request_hashes": {
                    a: __import__("sct.canon", fromlist=["sha256_obj"]).sha256_obj(r)
                    for a, r in requests.items()
                },
            })
        if args.cmd == "case" and args.case_cmd == "predict":
            if not args.runner:
                raise SctError("--runner requires an executable and optional arguments")
            runner = SubprocessJsonRunner(args.runner)
            preds = arena.predict_with_runner(args.case_id, runner)
            return _json({"ok": True, "predictions": {a: p.to_dict() for a, p in preds.items()}})
        if args.cmd == "case" and args.case_cmd == "reveal":
            reveal = arena.reveal(args.case_id, args.choice)
            scores = arena.score(args.case_id)
            return _json({"ok": True, "reveal": reveal, "scores": scores})
        if args.cmd == "score":
            report = epoch_score_report(store, inferential=args.inferential)
            if args.inferential and not report["gate"]["allowed"]:
                return _json(report, exit_code=2)
            return _json(report)
        raise SctError("unsupported command")
    except SctError as exc:
        return _json({"ok": False, "error": str(exc), "execution_authority": "NONE"}, exit_code=2)
    finally:
        store.close()


if __name__ == "__main__":
    raise SystemExit(main())
