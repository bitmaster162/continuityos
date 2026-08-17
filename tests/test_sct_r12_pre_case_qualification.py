import json

import pytest

from sct.bench.predict import PREDICTION_SCHEMA, validate_probability_response
from sct.bench.score import SCORER_VERSION, score_distribution
from sct.cli import main as cli_main
from sct.epoch import r12_precase_manifest, ensure_r12_precase_amended
from sct.errors import EvidenceError
from sct.qualification import (
    authorize_case001_enrollment,
    qualify_r12_pre_case_gate,
    record_r12_qualification_pass,
    require_r12_enrollment_authorized,
    r12_enrollment_gate_status,
    run_context_responsiveness_sentinel,
    run_r12_stable_single_model_void_dryrun,
)
from sct.report import epoch_score_report
from sct.stats.cluster import paired_cluster_randomization
from sct.store.sqlite import SQLiteEvidenceStore

R11_SHA = "1c5937da898e89e92d9c9a1f905cb29b8e0aec133fb4fb3dffcfe74a94f1fd0c"
R12_PARENT_COMMIT = "13256bae2395a514287ccb1685b24b249f087373"
R12_PARENT_TREE = "1393fe4efe2873b27194d628a1325c9b474899dd"


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


def _context_receipt():
    return run_context_responsiveness_sentinel(
        runner=ContextResponsiveRunner(),
        provider="test-provider",
        model="test-model",
        model_version="v1",
    )


def _void_receipt():
    return run_r12_stable_single_model_void_dryrun(
        runner=StableVoidRunner(),
        cases=10,
        provider="test-provider",
        model="test-model",
        model_version="v1",
        runner_command_sha256="1" * 64,
    )


def _qualification():
    return qualify_r12_pre_case_gate(
        _void_receipt(),
        _context_receipt(),
        operator_attestation_sha256="a" * 64,
        operator_attestation_verified=True,
    )


def _amend(store):
    manifest = r12_precase_manifest(
        parent_commit=R12_PARENT_COMMIT,
        parent_tree=R12_PARENT_TREE,
        r11_receipt_sha256=R11_SHA,
    )
    return manifest, ensure_r12_precase_amended(store, manifest)


def test_top1_tie_has_no_lexicographic_winner():
    assert PREDICTION_SCHEMA == "sct.prediction/v3"
    assert SCORER_VERSION == "sct.score/v2"
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
    out = _context_receipt()
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
    context = _context_receipt()
    void = _void_receipt()
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
    assert final["provider"] == "test-provider"
    assert final["model"] == "test-model"
    assert final["model_version"] == "v1"
    assert final["case_001_authorized"] is False
    assert final["execution_authority"] == "NONE"


def test_r12_qualification_fails_without_genuine_attestation_hash():
    final = qualify_r12_pre_case_gate(
        _void_receipt(),
        _context_receipt(),
        operator_attestation_sha256=None,
    )
    assert final["scientific_pre_case_gate_pass"] is False
    assert "R12_GENUINE_OPERATOR_ATTESTATION_REQUIRED" in final["blockers"]


def test_r12_amendment_is_hash_bound_and_must_precede_live_case(tmp_path):
    store = SQLiteEvidenceStore(tmp_path / "db.sqlite")
    manifest, out = _amend(store)
    assert manifest["manifest_sha256"] == "c0d5e8b28f2fcb4ce3d5c3094a9a976249a6272894d6ff4a33b88cd0c4794eeb"
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


def test_scientific_pass_does_not_authorize_live_enrollment(tmp_path):
    store = SQLiteEvidenceStore(tmp_path / "db.sqlite")
    _amend(store)
    recorded = record_r12_qualification_pass(store, _qualification())
    assert recorded["case_001_authorized"] is False
    assert recorded["execution_authority"] == "NONE"

    status = r12_enrollment_gate_status(store)
    assert status["scientific_pass_recorded"] is True
    assert status["owner_enrollment_authorization_recorded"] is False
    assert status["live_enrollment_allowed"] is False
    with pytest.raises(EvidenceError, match="R12_PRECASE_ADMISSION_BLOCKED"):
        require_r12_enrollment_authorized(store)


def test_owner_gate_requires_exact_qualification_bound_token(tmp_path):
    store = SQLiteEvidenceStore(tmp_path / "db.sqlite")
    _amend(store)
    recorded = record_r12_qualification_pass(store, _qualification())
    qsha = recorded["qualification_sha256"]

    with pytest.raises(EvidenceError, match="exact owner Case #001 approval token required"):
        authorize_case001_enrollment(store, approval_token="go")

    auth = authorize_case001_enrollment(
        store,
        approval_token=f"APPROVE_SCT_CASE001:{qsha}",
    )
    assert auth["case_001_authorized"] is True
    assert auth["execution_authority"] == "NONE"
    assert auth["can_execute"] is False
    status = require_r12_enrollment_authorized(store)
    assert status["live_enrollment_allowed"] is True
    assert status["execution_authority"] == "NONE"


def test_cli_case_open_fails_closed_before_r12_scientific_and_owner_gates(tmp_path):
    db = tmp_path / "db.sqlite"
    rc = cli_main([
        "--db", str(db),
        "case", "open",
        "--id", "CASE-001",
        "--situation", "A or B?",
        "--option", "A",
        "--option", "B",
        "--provider", "p",
        "--model", "m",
        "--model-version", "v",
        "--static-profile-file", str(tmp_path / "missing-profile.txt"),
        "--sct-state-file", str(tmp_path / "missing-sct.txt"),
        "--domain-id", "d",
        "--time-epoch", "t",
        "--decision-family", "f",
        "--assistant-influence", "NONE",
    ])
    assert rc == 2
    store = SQLiteEvidenceStore(db)
    assert not list(store.query(kind="CASE_FROZEN"))
    status = r12_enrollment_gate_status(store)
    assert status["live_enrollment_allowed"] is False
    store.close()
