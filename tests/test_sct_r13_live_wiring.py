import json

import pytest

from sct.bench.arena import ProspectiveArena
from sct.bench.envelope import build_standard_inputs
from sct.canon import sha256_obj
from sct.errors import BenchError, EvidenceError
from sct.r13 import (
    R13_ALIAS_INVENTORY,
    R13_BASELINE_SCHEMA,
    R13_MODEL_SELECTION_SCHEMA,
    authorize_case001_r13,
    ensure_r13_protocol_amended,
    qualify_r13_pre_case_gate,
    r13_protocol_manifest,
    record_r13_qualification_pass,
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
        "selection_rationale_non_r13": "selected before R13 from local compatibility only",
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
        "profile_construction_policy": "Frozen admitted-evidence profile.",
        "profile_builder_sha256": "1" * 64,
        "retrieval_policy": "Frozen chronological retrieval.",
        "retrieval_policy_sha256": "2" * 64,
        "source_cutoff_policy": "Same cutoff as Arm C.",
        "source_cutoff_sha256": "3" * 64,
        "admissible_evidence_pool": "Same admitted raw pool as Arm C, without SCT-only claims.",
        "context_selection_policy": "Deterministic frozen selection.",
        "context_selection_policy_sha256": "4" * 64,
        "disallow_sct_structured_claims": True,
        "payload_parity_ratio": 1.15,
        "execution_authority": "NONE",
    }


class ResponsiveRunner:
    def allowed_token_logits(self, request, *, aliases):
        payload = json.loads(request["messages"][-1]["content"].split("\nSelected option: ", 1)[0])
        mapping = {row["semantic_option"]: row["label"] for row in payload["labeled_options"]}
        target = next((semantic for semantic in mapping if semantic in payload["personal_context"]), None)
        logits = {alias: (2.0 if alias == "C" else 0.0) for alias in aliases}
        if target is not None:
            logits[mapping[target]] += 4.0
        return logits


class UniformRunner:
    def allowed_token_logits(self, request, *, aliases):
        return {alias: 0.0 for alias in aliases}


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


def _fully_authorized_store(tmp_path):
    store = SQLiteEvidenceStore(tmp_path / "authorized.sqlite")
    protocol = r13_protocol_manifest(r2_diagnostic_sha256=R2_SHA)
    ensure_r13_protocol_amended(store, protocol)
    model = _model_manifest()
    sealed_model = seal_model_selection(store, model, protocol_manifest_sha256=protocol["manifest_sha256"])
    seal_baseline_spec(store, _baseline_spec(), protocol_manifest_sha256=protocol["manifest_sha256"])

    preflight = _with_trace(run_r13_determinism_preflight(
        logit_runner=ResponsiveRunner(), model_manifest=model, protocol_manifest_sha256=protocol["manifest_sha256"]
    ), 2)
    sentinel = _with_trace(run_r13_balanced_context_sentinel(
        logit_runner=ResponsiveRunner(), model_manifest=model, protocol_manifest_sha256=protocol["manifest_sha256"]
    ), 18)
    stable = _with_trace(run_r13_stable_void(
        logit_runner=UniformRunner(), model_manifest=model, protocol_manifest_sha256=protocol["manifest_sha256"]
    ), 30)
    model_sha = sealed_model["model_selection_manifest_sha256"]
    for component, receipt in (
        ("preflight", preflight),
        ("context-sentinel", sentinel),
        ("stable-void", stable),
    ):
        start_r13_component_attempt(
            store,
            component=component,
            protocol_manifest_sha256=protocol["manifest_sha256"],
            model_selection_manifest_sha256=model_sha,
            source_code_sha=SOURCE_SHA,
            source_tree_sha=SOURCE_TREE,
        )
        finish_r13_component_attempt(store, component=component, receipt=receipt)

    attestation_sha = "e" * 64
    record_verified_r13_operator_attestation(store, {
        "attestation_sha256": attestation_sha,
        "protocol_manifest_sha256": protocol["manifest_sha256"],
        "model_selection_manifest_sha256": validate_model_selection_manifest(model)["manifest_sha256"],
        "source_code_sha": SOURCE_SHA,
        "source_tree_sha": SOURCE_TREE,
        "preflight_receipt_sha256": sha256_obj(preflight),
        "sentinel_receipt_sha256": sha256_obj(sentinel),
        "stable_void_receipt_sha256": sha256_obj(stable),
        "valid_live_n": 0,
        "can_execute": False,
        "execution_authority": "NONE",
    })
    qualification = qualify_r13_pre_case_gate(
        preflight,
        sentinel,
        stable,
        operator_attestation_sha256=attestation_sha,
        operator_attestation_verified=True,
    )
    recorded = record_r13_qualification_pass(store, qualification)
    authorize_case001_r13(
        store,
        approval_token=f"APPROVE_SCT_CASE001_R13:{recorded['qualification_sha256']}",
    )
    return store, protocol, model


def test_sqlite_physically_blocks_case_frozen_after_r13_amend_until_bound_authorization(tmp_path):
    store = SQLiteEvidenceStore(tmp_path / "blocked.sqlite")
    protocol = r13_protocol_manifest(r2_diagnostic_sha256=R2_SHA)
    ensure_r13_protocol_amended(store, protocol)
    with pytest.raises(EvidenceError, match="R13_PRECASE_ADMISSION_BLOCKED"):
        store.append("CASE_FROZEN", {"case_id": "BYPASS-ATTEMPT"})
    assert not list(store.query(kind="CASE_FROZEN"))
    store.close()

    store, _, _ = _fully_authorized_store(tmp_path)
    rec = store.append("CASE_FROZEN", {"case_id": "AUTHORIZED-DIRECT"})
    assert rec.payload["case_id"] == "AUTHORIZED-DIRECT"
    store.close()


def test_legacy_json_prediction_path_is_rejected_once_r13_protocol_is_active(tmp_path):
    store, _, model = _fully_authorized_store(tmp_path)
    arena = ProspectiveArena(store)
    inputs = build_standard_inputs(
        scenario="Synthetic live-path wiring check",
        options=("Alpha", "Beta", "Gamma"),
        provider=model["model_repo_or_provider_id"],
        model=model["model_repo_or_provider_id"],
        model_version=model["model_revision"],
        static_profile="P" * 100,
        permitted_history="",
        sct_state="S" * 100,
        token_budget=512,
        temperature=0.0,
        reasoning="fixed",
        frozen_at=9000.0,
    )
    arena.open_case(
        case_id="CASE-R13-GUARD",
        situation="Synthetic live-path wiring check",
        options=("Alpha", "Beta", "Gamma"),
        inputs=inputs,
        cluster={"project_id": "p", "domain_id": "d", "time_epoch": "t", "decision_family": "f"},
        assistant_influence="NONE",
        frozen_at=9000.0,
    )

    class LegacyRunner:
        def predict(self, request, *, arm):
            return {
                "option_probabilities": {"Alpha": 0.34, "Beta": 0.33, "Gamma": 0.33},
                "reasons": ["legacy"],
                "change_conditions": [],
                "would_escalate": False,
            }

    with pytest.raises(BenchError, match="R13_DIRECT_LOGIT_RUNNER_REQUIRED"):
        arena.predict_with_runner("CASE-R13-GUARD", LegacyRunner())
    assert not list(store.query(kind="PREDICTION_COMMITTED"))
    store.close()
