from __future__ import annotations

from pathlib import Path
from typing import Any
import hashlib
import math
import tempfile

from .bench.arena import ProspectiveArena
from .bench.envelope import build_standard_inputs
from .runner.provider import FixtureRunner
from .store.sqlite import SQLiteEvidenceStore


def _nondegenerate(probabilities: dict[str, float]) -> bool:
    vals = [float(v) for v in probabilities.values()]
    return max(vals) - min(vals) > 1e-6


def _entropy(probabilities: dict[str, float]) -> float:
    return -sum(float(p) * math.log(float(p)) for p in probabilities.values() if float(p) > 0)


def _run_distribution_dryrun(*, runner, cases: int, provider: str, model: str, model_version: str, reason: str) -> dict[str, Any]:
    if not 10 <= cases <= 20:
        raise ValueError("dry-run must contain 10–20 cases")
    distributions = []
    with tempfile.TemporaryDirectory(prefix="sct-dryrun-") as tmp:
        store = SQLiteEvidenceStore(Path(tmp) / "dryrun.db")
        try:
            arena = ProspectiveArena(store)
            for i in range(cases):
                cid = f"VOID-{i+1:03d}"
                options = ["A", "B", "C"]
                # B/C contexts are intentionally close in byte length to exercise the real parity gate.
                b_ctx = f"profile-{i:02d}-" + ("x" * 80)
                c_ctx = f"twin-{i:02d}-" + ("y" * 81)
                inputs = build_standard_inputs(
                    scenario=f"Synthetic unresolved choice {i}: choose exactly one of A, B, C.",
                    options=options,
                    provider=provider,
                    model=model,
                    model_version=model_version,
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
                    situation=f"Synthetic unresolved choice {i}: choose exactly one of A, B, C.",
                    options=options,
                    inputs=inputs,
                    cluster={
                        "project_id": f"dryrun-{i%3}",
                        "domain_id": "synthetic",
                        "time_epoch": "VOID",
                        "decision_family": "distribution_dryrun",
                    },
                    assistant_influence="NONE",
                    frozen_at=1000.0 + i,
                )
                preds = arena.predict_with_runner(cid, runner)
                actual = ("A", "B", "C")[i % 3]
                arena.reveal(cid, actual, decided_at=2000.0 + i)
                scores = arena.score(cid)
                arena.void_case(cid, reason)
                distributions.append(
                    {
                        "case_id": cid,
                        "actual": actual,
                        "probabilities": {a: dict(p.option_probabilities) for a, p in preds.items()},
                        "scores": scores,
                    }
                )
            void_count = sum(1 for e in store.query(kind="CASE_VOIDED"))
            verified = store.verify()
        finally:
            # Required on Windows: TemporaryDirectory cannot remove an open SQLite file
            # after a fail-closed provider exception.
            store.close()

    vectors = [arm_probs for row in distributions for arm_probs in row["probabilities"].values()]
    uniform_count = sum(1 for p in vectors if not _nondegenerate(p))
    entropies = [_entropy(p) for p in vectors]
    unique_vectors = len({tuple(sorted((k, round(float(v), 6)) for k, v in p.items())) for p in vectors})
    return {
        "cases": cases,
        "prediction_vectors": len(vectors),
        "void_cases": void_count,
        "valid_cases": 0,
        "valid_cases_after_void_exclusion": 0,
        "schema_transport_pass": void_count == cases and bool(verified.ok) and len(vectors) == cases * 3,
        "degenerate_uniform_vector_count": uniform_count,
        "all_probability_vectors_non_degenerate": uniform_count == 0,
        "unique_probability_vectors": unique_vectors,
        "mean_entropy_nats": (sum(entropies) / len(entropies)) if entropies else None,
        "store_verify_ok": verified.ok,
        "examples": distributions[:3],
        "execution_authority": "NONE",
    }


def run_void_distribution_dryrun(*, cases: int = 12) -> dict:
    """Fixture-only engineering dry run. It never satisfies the real-model gate."""
    # Deterministic, non-degenerate vectors; arm C differs in residual mass.
    # One fixture runner is reused because FixtureRunner keys its response by local arm metadata.
    class WobbleFixture:
        def __init__(self):
            self.calls = 0
        def predict(self, request, *, arm: str):
            i = self.calls // 3
            self.calls += 1
            wobble = (i % 5) * 0.01
            by_arm = {
                "generic": {"A": 0.45, "B": 0.35, "C": 0.20},
                "profile_rag": {"A": 0.50, "B": 0.30 - wobble, "C": 0.20 + wobble},
                "sct": {"A": 0.50, "B": 0.20 + wobble, "C": 0.30 - wobble},
            }
            return {
                "option_probabilities": by_arm[arm],
                "reasons": ["fixture"],
                "change_conditions": [],
                "would_escalate": False,
            }
    result = _run_distribution_dryrun(
        runner=WobbleFixture(),
        cases=cases,
        provider="fixture",
        model="fixture-model",
        model_version="v1",
        reason="SYNTHETIC_FIXTURE_DISTRIBUTION_DRY_RUN_ONLY",
    )
    result.update({
        "runner_kind": "FIXTURE_ONLY",
        "satisfies_real_model_gate": False,
        "operator_attestation_required": False,
    })
    return result


def run_real_model_void_dryrun(*, runner, cases: int = 12, provider: str, model: str, model_version: str, runner_command_sha256: str | None = None) -> dict:
    """Run the 10–20 VOID distribution gate through a real provider adapter.

    SCT can verify transport/schema/integrity, but cannot prove that an arbitrary
    subprocess truly called the named external model. The final receipt therefore
    requires an operator/provider attestation before Case #001.
    """
    result = _run_distribution_dryrun(
        runner=runner,
        cases=cases,
        provider=provider,
        model=model,
        model_version=model_version,
        reason="REAL_MODEL_DISTRIBUTION_DRY_RUN_VOID",
    )
    result.update({
        "runner_kind": "SUBPROCESS_JSON_PROVIDER",
        "provider": provider,
        "model": model,
        "model_version": model_version,
        "runner_command_sha256": runner_command_sha256,
        "satisfies_real_model_gate": bool(result["schema_transport_pass"]),
        "operator_attestation_required": True,
        "note": "SCT verifies the frozen request/response path but cannot cryptographically prove the subprocess invoked the declared model.",
    })
    return result
