
from __future__ import annotations

from pathlib import Path
import tempfile

from .bench.arena import ProspectiveArena
from .bench.envelope import build_standard_inputs
from .runner.provider import FixtureRunner
from .store.sqlite import SQLiteEvidenceStore


def run_void_distribution_dryrun(*, cases: int = 12) -> dict:
    if not 10 <= cases <= 20:
        raise ValueError("dry-run must contain 10–20 cases")
    distributions = []
    with tempfile.TemporaryDirectory(prefix="sct-dryrun-") as tmp:
        store = SQLiteEvidenceStore(Path(tmp) / "dryrun.db")
        arena = ProspectiveArena(store)
        for i in range(cases):
            cid = f"VOID-{i+1:03d}"
            options = ["A", "B", "C"]
            b_ctx = f"profile-{i:02d}-" + ("x" * 40)
            c_ctx = f"twin-{i:02d}-" + ("y" * 41)
            inputs = build_standard_inputs(
                scenario=f"Synthetic choice {i}",
                options=options,
                provider="fixture",
                model="fixture-model",
                model_version="v1",
                static_profile=b_ctx,
                sct_state=c_ctx,
                permitted_history="",
                token_budget=512,
                temperature=0.0,
                reasoning="fixed",
                frozen_at=1000.0 + i,
            )
            arena.open_case(
                case_id=cid,
                situation=f"Synthetic choice {i}",
                options=options,
                inputs=inputs,
                cluster={
                    "project_id": f"dryrun-{i%3}",
                    "domain_id": "synthetic",
                    "time_epoch": "VOID",
                    "decision_family": "distribution_dryrun",
                },
                frozen_at=1000.0 + i,
            )
            wobble = (i % 5) * 0.01
            runner = FixtureRunner(
                {
                    "generic": {
                        "option_probabilities": {"A": 0.45, "B": 0.35, "C": 0.20},
                        "reasons": ["fixture"], "change_conditions": [], "would_escalate": False,
                    },
                    "profile_rag": {
                        "option_probabilities": {"A": 0.50, "B": 0.30 - wobble, "C": 0.20 + wobble},
                        "reasons": ["fixture"], "change_conditions": [], "would_escalate": False,
                    },
                    "sct": {
                        "option_probabilities": {"A": 0.50, "B": 0.20 + wobble, "C": 0.30 - wobble},
                        "reasons": ["fixture"], "change_conditions": [], "would_escalate": False,
                    },
                }
            )
            preds = arena.predict_with_runner(cid, runner)
            actual = ("A", "B", "C")[i % 3]
            arena.reveal(cid, actual, decided_at=2000.0 + i)
            scores = arena.score(cid)
            arena.void_case(cid, "SYNTHETIC_DISTRIBUTION_DRY_RUN_ONLY")
            distributions.append(
                {
                    "case_id": cid,
                    "actual": actual,
                    "probabilities": {a: dict(p.option_probabilities) for a, p in preds.items()},
                    "scores": scores,
                }
            )
        void_count = sum(1 for e in store.query(kind="CASE_VOIDED"))
        valid_score_report = {"valid_cases_after_void_exclusion": 0}
        verified = store.verify()
        store.close()
    return {
        "cases": cases,
        "void_cases": void_count,
        "valid_cases": 0,
        "all_probability_vectors_non_degenerate": all(
            len(set(round(v, 6) for v in arm_probs.values())) > 1
            for row in distributions
            for arm_probs in row["probabilities"].values()
        ),
        "store_verify_ok": verified.ok,
        "examples": distributions[:3],
        **valid_score_report,
    }
