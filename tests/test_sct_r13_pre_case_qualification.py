import json

import pytest

from sct.canon import sha256_obj
from sct.errors import EvidenceError
from sct.r13 import (
    R13_ADAPTER_ID,
    R13_ALIAS_INVENTORY,
    R13_BASELINE_SCHEMA,
    R13_CONFIRMATORY_PRIMARY,
    R13_DESCRIPTIVE_SECONDARY,
    R13_MODEL_SELECTION_SCHEMA,
    R13_PROTOCOL_SCHEMA,
    R13_SIGN_FLIP_INTERPRETATION,
    R13CasePredictionRunner,
    authorize_case001_r13,
    constrained_probabilities,
    derive_case_mapping,
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
from sct.r13_attempt import (
    finish_r13_component_attempt,
    record_verified_r13_operator_attestation,
    start_r13_component_attempt,
)
from sct.store.sqlite import SQLiteEvidenceStore

R2_SHA = "beebc38d4dd32317a3b83c6dba9fbc02054ca4cfbe3a73c1c29ea3c82783d6fc"
SOURCE_SHA = "5" * 40
SOURCE_TREE = "6" * 40


def _model_manifest():
    return {
        "schema": R13_MODEL_SELECTION_SCHEMA,
        "selection_must_not_use_r13_outputs": True,
        "exact_epoch001_live_substrate": True,
        "model_repo_or_provider_id": "local/test-instruct",
        "model_revision": "rev-001",
        "weight_hashes": {"weights": "a" * 64},
        "tokenizer_hashes": {"tokenizer": "b" * 64},
        "runtime_backend": "test-backend",
        "runtime_version": "1.0",
        "precision_or_quantization": "fp32",
        "device_class": "cpu",
        "context_window": "8192",
        "deterministic_flags": "deterministic=true",
        "selection_rationale_non_r13": "selected before R13 based on local runtime compatibility",
        "alias_tokens": [
            {"alias": alias, "token_id": i + 100}
            for i, alias in enumerate(R13_ALIAS_INVENTORY[:15])
        ],
        "max_option_cardinality_required": 15,
        "execution_authority": "NONE",
    }


def _baseline_spec():
    return {
        "schema": R13_BASELINE_SCHEMA,
        "profile_construction_policy": "Frozen static profile from admitted evidence only.",
        "profile_builder_sha256": "1" * 64,
        "retrieval_policy": "Frozen chronological retrieval policy.",
        "retrieval_policy_sha256": "2" * 64,
        "source_cutoff_policy": "Same frozen source cutoff as Arm C.",
        "source_cutoff_sha256": "3" * 64,
        "admissible_evidence_pool": "Same admitted raw evidence pool as Arm C, without SCT-only claims.",
        "context_selection_policy": "Deterministic fixed retrieval and truncation policy.",
        "context_selection_policy_sha256": "4" * 64,
        "disallow_sct_structured_claims": True,
        "payload_parity_ratio": 1.15,
        "execution_authority": "NONE",
    }


class ResponsiveWithLabelPrior:
    def __init__(self):
        self.calls = 0

    def allowed_token_logits(self, request, *, aliases):
        self.calls += 1
        payload_text = request["messages"][-1]["content"].split("\nSelected option: ", 1)[0]
        payload = json.loads(payload_text)
        labeled = {row["semantic_option"]: row["label"] for row in payload["labeled_options"]}
        context = payload["personal_context"]
        target = next((semantic for semantic in labeled if semantic in context), None)
        out = {alias: 0.0 for alias in aliases}
        if "C" in out:
            out["C"] += 2.0
        if target is not None:
            out[labeled[target]] += 4.0
        return out


class FixedCLabelPrior:
    def allowed_token_logits(self, request, *, aliases):
        return {alias: (4.0 if alias == "C" else 0.0) for alias in aliases}


class NondeterministicRunner:
    def __init__(self):
        self.n = 0

    def allowed_token_logits(self, request, *, aliases):
        self.n += 1
        return {alias: float(self.n if alias == aliases[0] else 0.0) for alias in aliases}


class UniformValidRunner:
    def allowed_token_logits(self, request, *, aliases):
        return {alias: 0.0 for alias in aliases}


def _receipts(model, protocol_sha):
    runner = ResponsiveWithLabelPrior()
    preflight = run_r13_determinism_preflight(logit_runner=runner, model_manifest=model, protocol_manifest_sha256=protocol_sha)
    sentinel = run_r13_balanced_context_sentinel(logit_runner=runner, model_manifest=model, protocol_manifest_sha256=protocol_sha)
    stable = run_r13_stable_void(logit_runner=UniformValidRunner(), model_manifest=model, protocol_manifest_sha256=protocol_sha)
    return preflight, sentinel, stable


def _with_trace(receipt, count):
    rows = []
    for ordinal in range(1, count + 1):
        rows.append({
            "ordinal": ordinal,
            "request_sha256": sha256_obj({"ordinal": ordinal, "schema": receipt["schema"]}),
            "request_envelope_sha256": sha256_obj({"envelope": receipt["schema"], "ordinal": ordinal}),
            "allowed_aliases": ["A", "B"],
            "allowed_alias_token_ids": {"A": 100, "B": 101},
            "raw_allowed_token_logits": {"A": 0.0, "B": 0.0},
            "execution_authority": "NONE",
        })
    return {**receipt, "raw_logit_trace": rows, "raw_logit_trace_sha256": sha256_obj(rows)}


def _recorded_receipts(store, model, protocol):
    protocol_sha = protocol["manifest_sha256"]
    model_sha = validate_model_selection_manifest(model)["manifest_sha256"]
    raw = _receipts(model, protocol_sha)
    components = (
        ("preflight", _with_trace(raw[0], 2)),
        ("context-sentinel", _with_trace(raw[1], 18)),
        ("stable-void", _with_trace(raw[2], 30)),
    )
    out = []
    for component, receipt in components:
        start_r13_component_attempt(
            store,
            component=component,
            protocol_manifest_sha256=protocol_sha,
            model_selection_manifest_sha256=model_sha,
            source_code_sha=SOURCE_SHA,
            source_tree_sha=SOURCE_TREE,
        )
        finish_r13_component_attempt(store, component=component, receipt=receipt)
        out.append(receipt)
    return tuple(out)


def _record_attestation_event(store, model, protocol, receipts, attestation_sha):
    model_sha = validate_model_selection_manifest(model)["manifest_sha256"]
    payload = {
        "attestation_sha256": attestation_sha,
        "protocol_manifest_sha256": protocol["manifest_sha256"],
        "model_selection_manifest_sha256": model_sha,
        "source_code_sha": SOURCE_SHA,
        "source_tree_sha": SOURCE_TREE,
        "preflight_receipt_sha256": sha256_obj(receipts[0]),
        "sentinel_receipt_sha256": sha256_obj(receipts[1]),
        "stable_void_receipt_sha256": sha256_obj(receipts[2]),
        "valid_live_n": 0,
        "can_execute": False,
        "execution_authority": "NONE",
    }
    return record_verified_r13_operator_attestation(store, payload)


def test_protocol_is_post_r2_threshold_free_and_single_primary():
    manifest = r13_protocol_manifest(r2_diagnostic_sha256=R2_SHA)
    assert manifest["schema"] == R13_PROTOCOL_SCHEMA
    assert manifest["adapter"]["id"] == R13_ADAPTER_ID
    assert manifest["adapter"]["uniform_mix"] == 0.0
    assert manifest["adapter"]["rationale_before_choice"] is False
    assert manifest["adapter"]["fallback_distribution"] is None
    assert manifest["sentinel"]["planned_calls"] == 18
    assert manifest["sentinel"]["minimum_gap"] is None
    assert manifest["sentinel"]["entropy_threshold"] is None
    assert manifest["sentinel"]["confidence_threshold"] is None
    assert manifest["analysis_protocol"]["confirmatory_primary"] == R13_CONFIRMATORY_PRIMARY
    assert tuple(manifest["analysis_protocol"]["descriptive_secondary"]) == R13_DESCRIPTIVE_SECONDARY
    assert manifest["analysis_protocol"]["sign_flip_interpretation"] == R13_SIGN_FLIP_INTERPRETATION
    assert manifest["max_planned_real_model_calls_successful_run"] == 50


def test_model_manifest_has_exogenous_selection_and_15_aliases():
    validated = validate_model_selection_manifest(_model_manifest())
    assert len(validated["alias_tokens"]) == 15
    assert validated["selection_must_not_use_r13_outputs"] is True
    assert validated["exact_epoch001_live_substrate"] is True
    assert len(validated["manifest_sha256"]) == 64


def test_constrained_softmax_maps_aliases_back_to_semantics():
    probs = constrained_probabilities(
        semantic_options=("left", "right"),
        semantic_to_alias={"left": "B", "right": "A"},
        alias_logits={"A": 2.0, "B": 1.0},
    )
    assert probs["right"] > probs["left"]
    assert sum(probs.values()) == pytest.approx(1.0)


def test_balanced_sentinel_passes_semantic_response_despite_fixed_c_label_prior():
    model = _model_manifest()
    protocol = r13_protocol_manifest(r2_diagnostic_sha256=R2_SHA)
    out = run_r13_balanced_context_sentinel(
        logit_runner=ResponsiveWithLabelPrior(), model_manifest=model, protocol_manifest_sha256=protocol["manifest_sha256"]
    )
    assert out["attempted_calls"] == 18
    assert len(out["relations"]) == 18
    assert out["satisfies_context_responsiveness_gate"] is True
    assert out["minimum_probability_gap_required"] is False
    assert out["entropy_threshold_required"] is False


def test_fixed_label_prior_fails_balanced_sentinel():
    model = _model_manifest()
    protocol = r13_protocol_manifest(r2_diagnostic_sha256=R2_SHA)
    out = run_r13_balanced_context_sentinel(
        logit_runner=FixedCLabelPrior(), model_manifest=model, protocol_manifest_sha256=protocol["manifest_sha256"]
    )
    assert out["satisfies_context_responsiveness_gate"] is False
    assert any(not row["strict_directional_relation_pass"] for row in out["relations"])


def test_determinism_preflight_is_exact_and_fails_changed_logits():
    model = _model_manifest()
    protocol = r13_protocol_manifest(r2_diagnostic_sha256=R2_SHA)
    ok = run_r13_determinism_preflight(
        logit_runner=UniformValidRunner(), model_manifest=model, protocol_manifest_sha256=protocol["manifest_sha256"]
    )
    assert ok["deterministic"] is True
    assert ok["attempted_calls"] == 2
    bad = run_r13_determinism_preflight(
        logit_runner=NondeterministicRunner(), model_manifest=model, protocol_manifest_sha256=protocol["manifest_sha256"]
    )
    assert bad["deterministic"] is False


def test_stable_void_is_exactly_10_cases_30_calls_and_never_live():
    model = _model_manifest()
    protocol = r13_protocol_manifest(r2_diagnostic_sha256=R2_SHA)
    out = run_r13_stable_void(
        logit_runner=UniformValidRunner(), model_manifest=model, protocol_manifest_sha256=protocol["manifest_sha256"]
    )
    assert out["stable_void_pass"] is True
    assert out["planned_cases"] == 10
    assert out["attempted_calls"] == 30
    assert out["valid_live_cases_added"] == 0
    assert out["automatic_retry"] is False


def test_case_mapping_is_deterministic_and_changes_alias_identity(tmp_path):
    model = _model_manifest()
    protocol = r13_protocol_manifest(r2_diagnostic_sha256=R2_SHA)
    m1 = derive_case_mapping(case_id="CASE-X", semantic_options=("one", "two", "three"), alias_manifest=model, epoch_manifest_sha256=protocol["manifest_sha256"])
    m2 = derive_case_mapping(case_id="CASE-X", semantic_options=("one", "two", "three"), alias_manifest=model, epoch_manifest_sha256=protocol["manifest_sha256"])
    assert m1 == m2
    assert set(m1.semantic_to_alias) == {"one", "two", "three"}
    assert len(set(m1.semantic_to_alias.values())) == 3

    store = SQLiteEvidenceStore(tmp_path / "db.sqlite")
    frozen = freeze_case_mapping(
        store,
        case_id="CASE-X",
        semantic_options=("one", "two", "three"),
        alias_manifest=model,
        protocol_manifest_sha256=protocol["manifest_sha256"],
        model_selection_manifest_sha256=validate_model_selection_manifest(model)["manifest_sha256"],
    )
    again = freeze_case_mapping(
        store,
        case_id="CASE-X",
        semantic_options=("one", "two", "three"),
        alias_manifest=model,
        protocol_manifest_sha256=protocol["manifest_sha256"],
        model_selection_manifest_sha256=validate_model_selection_manifest(model)["manifest_sha256"],
    )
    assert again == json.loads(json.dumps(frozen))
    store.close()


def test_scientific_pass_requires_protocol_model_and_strong_b_baseline_before_recording(tmp_path):
    store = SQLiteEvidenceStore(tmp_path / "db.sqlite")
    protocol = r13_protocol_manifest(r2_diagnostic_sha256=R2_SHA)
    ensure_r13_protocol_amended(store, protocol)
    model = _model_manifest()
    seal_model_selection(store, model, protocol_manifest_sha256=protocol["manifest_sha256"])
    preflight, sentinel, stable = _receipts(model, protocol["manifest_sha256"])
    q = qualify_r13_pre_case_gate(
        preflight, sentinel, stable,
        operator_attestation_sha256="c" * 64,
        operator_attestation_verified=True,
    )
    assert q["scientific_pre_case_gate_pass"] is True
    with pytest.raises(EvidenceError, match="Arm B baseline"):
        record_r13_qualification_pass(store, q)

    baseline = seal_baseline_spec(store, _baseline_spec(), protocol_manifest_sha256=protocol["manifest_sha256"])
    receipts = _recorded_receipts(store, model, protocol)
    attestation_sha = "c" * 64
    _record_attestation_event(store, model, protocol, receipts, attestation_sha)
    q = qualify_r13_pre_case_gate(
        receipts[0], receipts[1], receipts[2],
        operator_attestation_sha256=attestation_sha,
        operator_attestation_verified=True,
    )
    recorded = record_r13_qualification_pass(store, q)
    assert recorded["case_001_authorized"] is False
    assert recorded["execution_authority"] == "NONE"
    assert recorded["baseline_manifest_sha256"] == baseline["baseline_manifest_sha256"]
    status = r13_enrollment_gate_status(store)
    assert status["scientific_pass_recorded"] is True
    assert status["live_enrollment_allowed"] is False
    store.close()


def test_owner_authorization_is_separate_and_exact_hash_bound(tmp_path):
    store = SQLiteEvidenceStore(tmp_path / "db.sqlite")
    protocol = r13_protocol_manifest(r2_diagnostic_sha256=R2_SHA)
    ensure_r13_protocol_amended(store, protocol)
    model = _model_manifest()
    seal_model_selection(store, model, protocol_manifest_sha256=protocol["manifest_sha256"])
    seal_baseline_spec(store, _baseline_spec(), protocol_manifest_sha256=protocol["manifest_sha256"])
    receipts = _recorded_receipts(store, model, protocol)
    attestation_sha = "d" * 64
    _record_attestation_event(store, model, protocol, receipts, attestation_sha)
    q = qualify_r13_pre_case_gate(
        receipts[0], receipts[1], receipts[2],
        operator_attestation_sha256=attestation_sha,
        operator_attestation_verified=True,
    )
    recorded = record_r13_qualification_pass(store, q)
    qsha = recorded["qualification_sha256"]

    with pytest.raises(EvidenceError, match="exact R13 owner"):
        authorize_case001_r13(store, approval_token="go")
    auth = authorize_case001_r13(store, approval_token=f"APPROVE_SCT_CASE001_R13:{qsha}")
    assert auth["case_001_authorized"] is True
    assert auth["can_execute"] is False
    assert require_r13_enrollment_authorized(store)["live_enrollment_allowed"] is True
    store.close()


def test_r13_case_prediction_runner_freezes_choice_before_rationale():
    model = _model_manifest()
    mapping = {"Alpha": "A", "Beta": "B"}
    request = {
        "provider": "local/test-instruct",
        "model": "local/test-instruct",
        "model_version": "rev-001",
        "messages": [
            {"role": "system", "content": "legacy envelope"},
            {"role": "user", "content": json.dumps({"scenario": "Pick", "options": ["Alpha", "Beta"], "personal_context": "Principal prefers Beta"})},
        ],
    }
    runner = R13CasePredictionRunner(
        logit_runner=ResponsiveWithLabelPrior(),
        case_id="CASE-001",
        mapping=mapping,
        textual_order=("Alpha", "Beta"),
        model_manifest=model,
    )
    out = runner.predict(request, arm="sct")
    assert out["option_probabilities"]["Beta"] > out["option_probabilities"]["Alpha"]
    assert out["reasons"] == ["R13_DIRECT_CONSTRAINED_LABEL_LOGITS_FORECAST_COMMITTED_BEFORE_RATIONALE"]
    assert out["would_escalate"] is False
