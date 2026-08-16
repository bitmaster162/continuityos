
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from .bench.arena import ProspectiveArena
from .bench.envelope import build_standard_inputs
from .dryrun import run_void_distribution_dryrun
from .epoch import amendment_v2_manifest, ensure_epoch_amended
from .errors import SctError
from .report import epoch_score_report
from .runner.provider import SubprocessJsonRunner
from .store.sqlite import SQLiteEvidenceStore

PARENT_COMMIT = "60f7558c13cb15a6ebac858747629ad1147852f6"
PARENT_TREE = "50e10dffed773144c4c5b16788ffad10f839bf6e"


def _store(path: str) -> SQLiteEvidenceStore:
    return SQLiteEvidenceStore(Path(path).expanduser())


def _read_text(path: str | None, *, default: str = "") -> str:
    if not path:
        return default
    return Path(path).expanduser().read_text(encoding="utf-8")


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
            return _json({"ok": True, "capabilities": sorted(store.capabilities()), "verify": store.verify().__dict__, "epoch_amendment": amendment})
        if args.cmd == "verify":
            result = store.verify().__dict__
            return _json(result, exit_code=0 if result["ok"] else 2)
        if args.cmd == "dry-run":
            return _json(run_void_distribution_dryrun())
        if args.cmd == "case" and args.case_cmd == "open":
            _ensure_amendment(store)
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
                assistant_influence="NONE",
            )
            requests = arena.requests(args.id)
            return _json({"ok": True, "case": case, "request_hashes": {a: __import__("sct.canon", fromlist=["sha256_obj"]).sha256_obj(r) for a, r in requests.items()}})
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
