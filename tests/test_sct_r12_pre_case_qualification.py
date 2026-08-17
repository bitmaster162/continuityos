import json

import pytest

from sct.bench.predict import validate_probability_response
from sct.bench.score import score_distribution
from sct.epoch import r12_precase_manifest, ensure_r12_precase_amended
from sct.qualification import (
    qualify_r12_pre_case_gate,
    run_context_responsiveness_sentinel,
    run_r12_stable_single_model_void_dryrun,
)
from sct.report import epoch_score_report
from sct.stats.cluster import paired_cluster_randomization
from sct.store.sqlite import SQLiteEvidenceStore


class ContextResponsiveRunner:
    def predict(self, request, *, arm: str):
        payload = json.loads(request["messages"][1]["content"])
        options = tuple(payload["options"])
        context = payload["personal_context"]
        target = next(opt for opt in options if f"SYNTHETIC_TARGET={opt}" in context)
        rest = [opt for opt in options if opt != target]
        residual = 0.35 / len(rest)
        probs = {opt: residual for opt in rest}
        probs[target] = 0.65
        return {
            "option_probabilities": probs,
            "reasons": ["synthetic sentinel"],
            "change_conditions": [],
            "would_escalate": False,
        }


class ConstantRunner:
    def predict(self, request, *, arm: str):
        payload = json.loads(request["messages"][1]["content"])
        options = tuple(payload["options"])
        probs = {opt: 1.0 / len(options) for opt in options}
        return {
            "option_probabilities": probs,
            "reasons": ["constant"],
            "change_conditions": [],
            "would_escalate": False,
        }


class StableVoidRunner:
    def predict(self, request, *, arm: str):
        payload = json.loads(request["messages"][1]["content"])
        a, b, c = payload["options"]
        return {
            "option_probabilities": {a: 0.50, b: 0.30, c: 0.20},
            "reasons": ["stable void"],
            "change_conditions": [],
            "would_escalate": False,
        }


def test_top1_tie_has_no_lexicographic_winner():
    probs, predicted, confidence = validate_probability_response(
        ["B", "A"], {"option_probabilities": {"B": 0.5, "A": 0.5}}
    )
    assert probs == {"B": 0.5, "A": 0.5}
    assert predicted is None
    assert confidence == pytest.approx(0.5)

    out = score_distribution(["B", "A"], {"B": 0.5, "A": 0.5}, "A")
    assert out["predicted_choice"] is None
    assert out["top1_tied"] is True
    assert set(out["top1_tied_options"]) == {"A", "B"}
    assert out["correct"] is False


def test_sign_flip_is_not_mislabeled_as_design_randomization():
    rows = [{"cluster_key": "a", "delta": 1.0}, {"cluster_key": "b", "delta": 1.0}]
    out = paired_cluster_randomization(rows)
    assert out["method"] == "exact_cluster_sign_flip"
    assert out["design_based_randomization"] is False
    assert out["interpretation"] == "SIGN_FLIP_SENSITIVITY_UNDER_SYMMETRY_NOT_RANDOM_ASSIGNMENT_INFERENCE"


def test_context_responsiveness_sentinel_requires_context_effect_not_probability_gap():
    out = run_context_responsiveness_sentinel(
        runner=ContextResponsiveRunner(),
        provider="test-provider",
        model="test-model",
        model_version="v1",
    )
    assert out["satisfies_context_responsiveness_gate"] is True
    assert out["minimum_probability_gap_required"] is False
    assert out["automatic_retry"] is False
    assert [x["predicted_choice"] for x in out["results"]] == ["A", "C"]


def test_constant_context_insensitive_runner_fails_sentinel():
    out = run_context_responsiveness_sentinel(
        runner=ConstantRunner(),
        provider="test-provider",
        model="test-model",
        model_version="v1",
    )
    assert out["satisfies_context_responsiveness_gate"] is False
    assert out["minimum_probability_gap_required"] is False


def test_r12_stable_single_model_void_component_and_final_qualification():
    context = run_context_responsiveness_sentinel(
        runner=ContextResponsiveRunner(),
        provider="test-provider",
        model="test-model",
        model_version="v1",
    )
    void = run_r12_stable_single_model_void_dryrun(
        runner=StableVoidRunner(),
        cases=10,
        provider="test-provider",
        model="test-model",
        model_version="v1",
        runner_command_sha256="1" * 64,
    )
    assert void["phase1_transport_component_pass"] is True
    assert void["satisfies_real_model_gate"] is False
    assert void["automatic_retry"] is False
    assert void["replacement_cases"] == 0

    final = qualify_r12_pre_case_gate(
        void,
        context,
        operator_attestation_sha256="a" * 64,
        operator_attestation_verified=True,
    )
    assert final["scientific_pre_case_gate_pass"] is True
    assert final["case_001_authorized"] is False
    assert final["execution_authority"] == "NONE"


def test_r12_qualification_fails_without_genuine_attestation_hash():
    context = run_context_responsiveness_sentinel(
        runner=ContextResponsiveRunner(),
        provider="test-provider",
        model="test-model",
        model_version="v1",
    )
    void = run_r12_stable_single_model_void_dryrun(
        runner=StableVoidRunner(),
        cases=10,
        provider="test-provider",
        model="test-model",
        model_version="v1",
    )
    final = qualify_r12_pre_case_gate(void, context, operator_attestation_sha256=None)
    assert final["scientific_pre_case_gate_pass"] is False
    assert "R12_GENUINE_OPERATOR_ATTESTATION_REQUIRED" in final["blockers"]


def test_r12_amendment_is_hash_bound_and_must_precede_live_case(tmp_path):
    store = SQLiteEvidenceStore(tmp_path / "db.sqlite")
    manifest = r12_precase_manifest(
        parent_commit="13256bae2395a514287ccb1685b24b249f087373",
        parent_tree="1393fe4efe2873b27194d628a1325c9b474899dd",
        r11_receipt_sha256="1c5937da898e89e92d9c9a1f905cb29b8e0aec133fb4fb3dffcfe74a94f1fd0c",
    )
    out = ensure_r12_precase_amended(store, manifest)
    assert out["valid_live_n"] == 0
    assert out["execution_authority"] == "NONE"
    again = ensure_r12_precase_amended(store, manifest)
    assert again == out


def test_report_declares_single_confirmatory_primary(tmp_path):
    store = SQLiteEvidenceStore(tmp_path / "db.sqlite")
    out = epoch_score_report(store, inferential=True)
    assert out["analysis_protocol"]["confirmatory_primary"] == "brier_skill_delta_c_minus_b"
    assert out["analysis_protocol"]["descriptive_secondary"] == [
        "accuracy_delta_c_minus_b",
        "log_loss_delta_c_minus_b",
    ]
    assert out["inferential_refused"] is True
