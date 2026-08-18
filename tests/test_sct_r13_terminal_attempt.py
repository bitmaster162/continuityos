import json

import pytest

from sct.canon import sha256_obj
from sct.baseline_r13 import baseline_policy_hashes
from sct.errors import EvidenceError
from sct.r13 import (
    R13_ALIAS_INVENTORY,
    R13_BASELINE_SCHEMA,
    R13_MODEL_SELECTION_SCHEMA,
    ensure_r13_protocol_amended,
    r13_protocol_manifest,
    run_r13_balanced_context_sentinel,
    run_r13_determinism_preflight,
    seal_baseline_spec,
    seal_model_selection,
)
from sct.r13_attempt import (
    finish_r13_component_attempt,
    r13_attempt_status,
    start_r13_component_attempt,
    validate_r13_component_receipt,
)
from sct.store.sqlite import SQLiteEvidenceStore

R2_SHA = "beebc38d4dd32317a3b83c6dba9fbc02054ca4cfbe3a73c1c29ea3c82783d6fc"
SOURCE_SHA = "7" * 40
SOURCE_TREE = "8" * 40


def _model():
    return {
        "schema": R13_MODEL_SELECTION_SCHEMA,
        "selection_must_not_use_r13_outputs": True,
        "exact_epoch001_live_substrate": True,
        "model_repo_or_provider_id": "local/terminal-test",
        "model_revision": "rev-terminal",
        "weight_hashes": {"weights": "a" * 64},
        "tokenizer_hashes": {"tokenizer": "b" * 64},
        "runtime_backend": "test",
        "runtime_version": "1",
        "precision_or_quantization": "fp32",
        "device_class": "cpu",
        "context_window": "8192",
        "deterministic_flags": "deterministic=true",
        "selection_rationale_non_r13": "selected from compatibility evidence before R13 outputs",
        "alias_tokens": [
            {"alias": alias, "token_id": i + 200}
            for i, alias in enumerate(R13_ALIAS_INVENTORY[:15])
        ],
        "max_option_cardinality_required": 15,
        "execution_authority": "NONE",
    }


def _baseline():
    return {
        "schema": R13_BASELINE_SCHEMA,
        "profile_construction_policy": "Frozen profile builder.",
        "retrieval_policy": "Frozen retrieval.",
        "source_cutoff_policy": "Frozen cutoff.",
        "admissible_evidence_pool": "Frozen admitted pool.",
        "context_selection_policy": "Frozen deterministic selection.",
        **baseline_policy_hashes(),
        "disallow_sct_structured_claims": True,
        "payload_parity_ratio": 1.15,
        "execution_authority": "NONE",
    }


class UniformRunner:
    def allowed_token_logits(self, request, *, aliases):
        return {alias: 0.0 for alias in aliases}


class FixedCLabelPrior:
    def allowed_token_logits(self, request, *, aliases):
        return {alias: (4.0 if alias == "C" else 0.0) for alias in aliases}


def _setup(tmp_path):
    store = SQLiteEvidenceStore(tmp_path / "terminal.sqlite")
    protocol = r13_protocol_manifest(r2_diagnostic_sha256=R2_SHA)
    ensure_r13_protocol_amended(store, protocol)
    model = _model()
    sealed = seal_model_selection(store, model, protocol_manifest_sha256=protocol["manifest_sha256"])
    seal_baseline_spec(store, _baseline(), protocol_manifest_sha256=protocol["manifest_sha256"])
    return store, protocol, model, sealed["model_selection_manifest_sha256"]


def _trace(receipt, count):
    rows = [
        {
            "ordinal": ordinal,
            "request_sha256": sha256_obj({"ordinal": ordinal, "schema": receipt["schema"]}),
            "request_envelope_sha256": sha256_obj({"envelope": ordinal}),
            "allowed_aliases": ["A", "B"],
            "allowed_alias_token_ids": {"A": 200, "B": 201},
            "raw_allowed_token_logits": {"A": 0.0, "B": 0.0},
            "execution_authority": "NONE",
        }
        for ordinal in range(1, count + 1)
    ]
    return {**receipt, "raw_logit_trace": rows, "raw_logit_trace_sha256": sha256_obj(rows)}


def _record_preflight_pass(store, protocol, model, model_sha):
    start_r13_component_attempt(
        store,
        component="preflight",
        protocol_manifest_sha256=protocol["manifest_sha256"],
        model_selection_manifest_sha256=model_sha,
        source_code_sha=SOURCE_SHA,
        source_tree_sha=SOURCE_TREE,
    )
    receipt = _trace(run_r13_determinism_preflight(
        logit_runner=UniformRunner(),
        model_manifest=model,
        protocol_manifest_sha256=protocol["manifest_sha256"],
    ), 2)
    finish_r13_component_attempt(store, component="preflight", receipt=receipt)
    return receipt


def test_attempt_start_is_point_of_no_return_even_without_receipt(tmp_path):
    store, protocol, _, model_sha = _setup(tmp_path)
    start_r13_component_attempt(
        store,
        component="preflight",
        protocol_manifest_sha256=protocol["manifest_sha256"],
        model_selection_manifest_sha256=model_sha,
        source_code_sha=SOURCE_SHA,
        source_tree_sha=SOURCE_TREE,
    )
    with pytest.raises(EvidenceError, match="rerun is forbidden"):
        start_r13_component_attempt(
            store,
            component="preflight",
            protocol_manifest_sha256=protocol["manifest_sha256"],
            model_selection_manifest_sha256=model_sha,
            source_code_sha=SOURCE_SHA,
            source_tree_sha=SOURCE_TREE,
        )
    status = r13_attempt_status(store)
    assert status["started_components"] == ["preflight"]
    assert status["rerun_allowed_for_same_binding"] is False
    store.close()


def test_failed_sentinel_is_terminal_and_blocks_stable_void(tmp_path):
    store, protocol, model, model_sha = _setup(tmp_path)
    _record_preflight_pass(store, protocol, model, model_sha)
    start_r13_component_attempt(
        store,
        component="context-sentinel",
        protocol_manifest_sha256=protocol["manifest_sha256"],
        model_selection_manifest_sha256=model_sha,
        source_code_sha=SOURCE_SHA,
        source_tree_sha=SOURCE_TREE,
    )
    failed = _trace(run_r13_balanced_context_sentinel(
        logit_runner=FixedCLabelPrior(),
        model_manifest=model,
        protocol_manifest_sha256=protocol["manifest_sha256"],
    ), 18)
    assert failed["satisfies_context_responsiveness_gate"] is False
    lifecycle = finish_r13_component_attempt(store, component="context-sentinel", receipt=failed)
    assert lifecycle["component_pass"] is False
    assert list(store.query(kind="R13_QUALIFICATION_FAILED"))

    with pytest.raises(EvidenceError, match="TERMINAL_ATTEMPT_FAILED"):
        start_r13_component_attempt(
            store,
            component="stable-void",
            protocol_manifest_sha256=protocol["manifest_sha256"],
            model_selection_manifest_sha256=model_sha,
            source_code_sha=SOURCE_SHA,
            source_tree_sha=SOURCE_TREE,
        )
    with pytest.raises(EvidenceError, match="TERMINAL_ATTEMPT_FAILED"):
        start_r13_component_attempt(
            store,
            component="context-sentinel",
            protocol_manifest_sha256=protocol["manifest_sha256"],
            model_selection_manifest_sha256=model_sha,
            source_code_sha=SOURCE_SHA,
            source_tree_sha=SOURCE_TREE,
        )
    store.close()


def test_pass_receipt_without_raw_logit_trace_is_rejected(tmp_path):
    store, protocol, model, model_sha = _setup(tmp_path)
    receipt = run_r13_determinism_preflight(
        logit_runner=UniformRunner(),
        model_manifest=model,
        protocol_manifest_sha256=protocol["manifest_sha256"],
    )
    with pytest.raises(EvidenceError, match="raw_logit_trace"):
        validate_r13_component_receipt("preflight", receipt)
    store.close()


def test_store_rejects_forged_r13_pass_without_recorded_components(tmp_path):
    store, protocol, _, model_sha = _setup(tmp_path)
    with pytest.raises(EvidenceError, match="R13_QUALIFICATION_EVIDENCE_BLOCKED"):
        store.append("R13_QUALIFICATION_PASSED", {
            "qualification_sha256": "9" * 64,
            "protocol_manifest_sha256": protocol["manifest_sha256"],
            "model_selection_manifest_sha256": model_sha,
            "baseline_manifest_sha256": list(store.query(kind="R13_BASELINE_SPEC_SEALED"))[-1].payload["baseline_manifest_sha256"],
            "preflight_receipt_sha256": "1" * 64,
            "sentinel_receipt_sha256": "2" * 64,
            "stable_void_receipt_sha256": "3" * 64,
            "operator_attestation_sha256": "4" * 64,
            "case_001_authorized": False,
            "valid_live_n": 0,
            "can_execute": False,
            "execution_authority": "NONE",
        })
    assert not list(store.query(kind="R13_QUALIFICATION_PASSED"))
    store.close()
