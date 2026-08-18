import json
from importlib import resources

import pytest

from sct.baseline_r13 import baseline_policy_hashes
from sct.errors import EvidenceError
from sct.r13 import r13_protocol_manifest
from sct.r13_manifest_guard import validate_baseline_for_seal, validate_model_manifest_for_seal

R2_SHA = "beebc38d4dd32317a3b83c6dba9fbc02054ca4cfbe3a73c1c29ea3c82783d6fc"
FROZEN_MODEL_SHA = "80341c77f9fbb427613ee5dcd75cbbefb2ba86ac81ee41b8fc431ddcfbfe344b"
FROZEN_BASELINE_SHA = "c332f8e69459cc551ee3ed40e45b10bab14aa5aa6bab427f42ecbaf31831c069"


def _load(name):
    return json.loads(resources.files("sct.protocols").joinpath(name).read_text(encoding="utf-8"))


def test_static_r13_protocol_asset_matches_runtime_scientific_contract():
    static = _load("r13_protocol_spec.json")
    runtime = r13_protocol_manifest(r2_diagnostic_sha256=R2_SHA)
    assert static["schema"] == runtime["schema"]
    assert static["parent"] == runtime["parent"]
    assert static["adapter"]["id"] == runtime["adapter"]["id"]
    assert static["adapter"]["temperature"] == 1.0
    assert static["adapter"]["uniform_mix"] == 0.0
    assert static["adapter"]["rationale_before_choice"] is False
    assert static["sentinel"]["planned_calls"] == runtime["sentinel"]["planned_calls"] == 18
    assert static["sentinel"]["minimum_gap"] is None
    assert static["sentinel"]["entropy_threshold"] is None
    assert static["stable_void"]["planned_calls"] == runtime["stable_void"]["planned_calls"] == 30
    assert static["max_planned_real_model_calls_successful_run"] == runtime["max_planned_real_model_calls_successful_run"] == 50
    assert static["analysis_protocol"]["confirmatory_primary"] == runtime["analysis_protocol"]["confirmatory_primary"]
    assert static["analysis_protocol"]["sign_flip_interpretation"] == runtime["analysis_protocol"]["sign_flip_interpretation"]
    assert static["execution_authority"] == "NONE"


def test_shipped_templates_are_deliberately_unsealable_until_filled():
    with pytest.raises(EvidenceError):
        validate_model_manifest_for_seal(_load("r13_model_selection_template.json"))
    with pytest.raises(EvidenceError):
        validate_baseline_for_seal(_load("r13_arm_b_baseline_template.json"))


def test_frozen_qwen_model_manifest_is_self_hashing_and_sealable():
    manifest = _load("r13_model_selection_qwen25_1_5b_frozen.json")
    validated = validate_model_manifest_for_seal(manifest)
    assert validated["manifest_sha256"] == FROZEN_MODEL_SHA
    assert validated["model_revision"] == "5fee7c4ed634dc66c6e318c8ac2897b8b9154536"
    assert validated["weight_hashes"]["model.safetensors"] == "dd924a11b4c220f385b51ffa522daea7c9f3d850e31b162bb5661df483c6d3ee"
    assert [(x["alias"], x["token_id"]) for x in validated["alias_tokens"]] == [
        (chr(65 + i), 32 + i) for i in range(15)
    ]
    prep = validated["provenance_prep"]
    assert prep["scientific_model_calls"] == 0
    assert prep["model_inference_executed"] is False


def test_frozen_arm_b_manifest_is_bound_to_exact_builder_policy():
    manifest = _load("r13_arm_b_baseline_frozen.json")
    validated = validate_baseline_for_seal(manifest)
    assert validated["manifest_sha256"] == FROZEN_BASELINE_SHA
    for field, digest in baseline_policy_hashes().items():
        assert validated[field] == digest
    assert validated["disallow_sct_structured_claims"] is True
    assert validated["payload_parity_ratio"] == 1.15
