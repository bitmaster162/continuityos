import copy

import pytest

from sct.baseline_r13 import baseline_policy_hashes
from sct.canon import sha256_obj
from sct.errors import EvidenceError
from sct.r13 import (
    R13_ALIAS_INVENTORY,
    R13_BASELINE_SCHEMA,
    R13_MODEL_SELECTION_SCHEMA,
    r13_protocol_manifest,
    run_r13_balanced_context_sentinel,
    run_r13_determinism_preflight,
    run_r13_stable_void,
    validate_model_selection_manifest,
)
from sct.r13_attestation import R13_OPERATOR_ATTESTATION_SCHEMA, validate_r13_operator_attestation
from sct.r13_manifest_guard import validate_baseline_for_seal, validate_model_manifest_for_seal
from sct.runner.logits import CapturingLogitRunner, ManifestBoundLogitRunner

R2_SHA = "beebc38d4dd32317a3b83c6dba9fbc02054ca4cfbe3a73c1c29ea3c82783d6fc"


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
        "selection_rationale_non_r13": "local compatibility selected before R13",
        "alias_tokens": [{"alias": a, "token_id": 100 + i} for i, a in enumerate(R13_ALIAS_INVENTORY[:15])],
        "max_option_cardinality_required": 15,
        "execution_authority": "NONE",
    }


def _baseline_spec():
    return {
        "schema": R13_BASELINE_SCHEMA,
        "profile_construction_policy": "Frozen deterministic human-authored profile excerpts from the admitted pool",
        "retrieval_policy": "Frozen deterministic Unicode lexical-overlap retrieval from the admitted pool",
        "source_cutoff_policy": "Same frozen cutoff as C; no future evidence",
        "admissible_evidence_pool": "Same raw admitted pool as C without SCT-only or assistant-authored claims",
        "context_selection_policy": "Frozen 40/60 byte allocation with deterministic spill and parity ceiling",
        "disallow_sct_structured_claims": True,
        "payload_parity_ratio": 1.15,
        "execution_authority": "NONE",
        **baseline_policy_hashes(),
    }


class EchoInner:
    def __init__(self):
        self.seen = []

    def allowed_token_logits(self, request, *, aliases, alias_token_ids=None):
        self.seen.append((tuple(aliases), dict(alias_token_ids or {})))
        return {alias: float(i) for i, alias in enumerate(aliases)}


class ResponsiveRunner:
    def allowed_token_logits(self, request, *, aliases):
        import json
        payload = json.loads(request["messages"][-1]["content"].split("\nSelected option: ", 1)[0])
        mapping = {row["semantic_option"]: row["label"] for row in payload["labeled_options"]}
        target = next((semantic for semantic in mapping if semantic in payload["personal_context"]), None)
        out = {alias: 0.0 for alias in aliases}
        if target is not None:
            out[mapping[target]] += 4.0
        return out


class UniformRunner:
    def allowed_token_logits(self, request, *, aliases):
        return {alias: 0.0 for alias in aliases}


def test_model_and_baseline_templates_fail_closed_on_placeholders():
    model = _model_manifest()
    model["runtime_backend"] = "__FILL_BEFORE_R13__"
    with pytest.raises(EvidenceError, match="placeholder"):
        validate_model_manifest_for_seal(model)

    baseline = _baseline_spec()
    baseline["retrieval_policy_sha256"] = "__SHA256__"
    with pytest.raises(EvidenceError, match="placeholder"):
        validate_baseline_for_seal(baseline)


def test_model_seal_guard_requires_real_weight_and_tokenizer_sha256_values():
    model = _model_manifest()
    model["weight_hashes"] = {"weights": "not-a-sha"}
    with pytest.raises(EvidenceError, match="weight_hashes"):
        validate_model_manifest_for_seal(model)
    assert validate_model_manifest_for_seal(_model_manifest())["manifest_sha256"]


def test_baseline_seal_guard_requires_implementation_hashes():
    baseline = _baseline_spec()
    del baseline["profile_builder_sha256"]
    with pytest.raises(EvidenceError, match="profile_builder_sha256"):
        validate_baseline_for_seal(baseline)
    assert validate_baseline_for_seal(_baseline_spec())["manifest_sha256"]


def test_manifest_bound_runner_forwards_exact_sealed_alias_token_ids_and_capture_hashes():
    inner = EchoInner()
    manifest = _model_manifest()
    bound = ManifestBoundLogitRunner.from_model_manifest(inner, manifest)
    capture = CapturingLogitRunner(bound)
    out = capture.allowed_token_logits({"envelope_sha256": "e" * 64}, aliases=("A", "C"))
    assert out == {"A": 0.0, "C": 1.0}
    assert inner.seen == [(("A", "C"), {"A": 100, "C": 102})]
    assert capture.records[0]["allowed_aliases"] == ("A", "C")
    assert capture.records[0]["raw_allowed_token_logits"] == {"A": 0.0, "C": 1.0}
    assert len(capture.records[0]["request_sha256"]) == 64


def test_operator_attestation_is_content_verified_not_boolean_only():
    model = validate_model_selection_manifest(_model_manifest())
    protocol = r13_protocol_manifest(r2_diagnostic_sha256=R2_SHA)
    preflight = run_r13_determinism_preflight(
        logit_runner=ResponsiveRunner(), model_manifest=model, protocol_manifest_sha256=protocol["manifest_sha256"]
    )
    sentinel = run_r13_balanced_context_sentinel(
        logit_runner=ResponsiveRunner(), model_manifest=model, protocol_manifest_sha256=protocol["manifest_sha256"]
    )
    stable = run_r13_stable_void(
        logit_runner=UniformRunner(), model_manifest=model, protocol_manifest_sha256=protocol["manifest_sha256"]
    )
    source_sha = "5" * 40
    source_tree = "6" * 40
    attestation = {
        "schema": R13_OPERATOR_ATTESTATION_SCHEMA,
        "source_code_sha": source_sha,
        "source_tree_sha": source_tree,
        "protocol_manifest_sha256": protocol["manifest_sha256"],
        "model_selection_manifest_sha256": model["manifest_sha256"],
        "model_repo_or_provider_id": model["model_repo_or_provider_id"],
        "model_revision": model["model_revision"],
        "weight_hashes": model["weight_hashes"],
        "tokenizer_hashes": model["tokenizer_hashes"],
        "runtime_backend": model["runtime_backend"],
        "runtime_version": model["runtime_version"],
        "precision_or_quantization": model["precision_or_quantization"],
        "device_class": model["device_class"],
        "deterministic_flags": model["deterministic_flags"],
        "preflight_receipt_sha256": sha256_obj(preflight),
        "sentinel_receipt_sha256": sha256_obj(sentinel),
        "stable_void_receipt_sha256": sha256_obj(stable),
        "planned_real_model_calls": 50,
        "observed_preflight_calls": 2,
        "observed_sentinel_calls": 18,
        "observed_stable_void_calls": 30,
        "valid_live_n": 0,
        "store_verify_ok": True,
        "automatic_retry": False,
        "replacement_cases": 0,
        "replacement_models": 0,
        "execution_authority": "NONE",
        "can_execute": False,
    }
    attestation["attestation_sha256"] = sha256_obj({k: v for k, v in attestation.items() if k != "attestation_sha256"})
    validated = validate_r13_operator_attestation(
        attestation,
        model_manifest=model,
        preflight=preflight,
        sentinel=sentinel,
        stable_void=stable,
        expected_source_sha=source_sha,
        expected_source_tree_sha=source_tree,
        store_verify_ok=True,
    )
    assert validated["attestation_sha256"] == attestation["attestation_sha256"]
    tampered = copy.deepcopy(attestation)
    tampered["model_revision"] = "other"
    tampered["attestation_sha256"] = sha256_obj({k: v for k, v in tampered.items() if k != "attestation_sha256"})
    with pytest.raises(EvidenceError, match="model_revision"):
        validate_r13_operator_attestation(
            tampered,
            model_manifest=model,
            preflight=preflight,
            sentinel=sentinel,
            stable_void=stable,
            expected_source_sha=source_sha,
            expected_source_tree_sha=source_tree,
            store_verify_ok=True,
        )
