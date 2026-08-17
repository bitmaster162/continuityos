from __future__ import annotations

from sct.dryrun import run_real_model_pool_void_dryrun


class _HalfAvailableRunner:
    def predict(self, request, *, arm: str):
        model = request["model"]
        if model == "free/model-b" and arm == "generic":
            raise RuntimeError("synthetic upstream 429")
        return {
            "option_probabilities": {"A": 0.50, "B": 0.30, "C": 0.20},
            "reasons": ["pool fixture"],
            "change_conditions": [],
            "would_escalate": False,
        }


class _UnavailableRunner:
    def predict(self, request, *, arm: str):
        raise RuntimeError("synthetic provider unavailable")


def test_pool_gate_preregisters_all_cases_and_passes_with_ten_complete_without_replacements():
    result = run_real_model_pool_void_dryrun(
        runner=_HalfAvailableRunner(),
        provider="fixture-provider",
        models=["free/model-a", "free/model-b"],
        cases=20,
        min_complete=10,
        runner_command_sha256="runner-sha",
    )

    assert result["cases"] == 20
    assert result["completed_cases"] == 10
    assert result["failed_cases"] == 10
    assert result["prediction_vectors"] == 30
    assert result["all_prediction_commit_count"] == 30
    assert result["void_cases"] == 20
    assert result["valid_cases"] == 0
    assert result["replacement_cases"] == 0
    assert result["automatic_retry"] is False
    assert result["same_exact_model_within_each_abc_case"] is True
    assert result["schema_transport_pass"] is True
    assert result["satisfies_real_model_gate"] is True
    assert result["store_verify_ok"] is True
    assert result["degenerate_uniform_vector_count"] == 0
    assert len(result["planned_cases"]) == 20
    assert [x["model"] for x in result["planned_cases"][:4]] == [
        "free/model-a",
        "free/model-b",
        "free/model-a",
        "free/model-b",
    ]
    assert {f["model"] for f in result["failures"]} == {"free/model-b"}


def test_pool_gate_fails_closed_when_fewer_than_ten_cases_complete():
    result = run_real_model_pool_void_dryrun(
        runner=_UnavailableRunner(),
        provider="fixture-provider",
        models=["free/model-a", "free/model-b"],
        cases=20,
        min_complete=10,
    )

    assert result["completed_cases"] == 0
    assert result["failed_cases"] == 20
    assert result["prediction_vectors"] == 0
    assert result["void_cases"] == 20
    assert result["valid_cases"] == 0
    assert result["replacement_cases"] == 0
    assert result["schema_transport_pass"] is False
    assert result["satisfies_real_model_gate"] is False
    assert result["store_verify_ok"] is True
