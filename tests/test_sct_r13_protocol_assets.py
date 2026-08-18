import json
from pathlib import Path

import pytest

from sct.errors import EvidenceError
from sct.r13 import r13_protocol_manifest
from sct.r13_manifest_guard import validate_baseline_for_seal, validate_model_manifest_for_seal

R2_SHA = "beebc38d4dd32317a3b83c6dba9fbc02054ca4cfbe3a73c1c29ea3c82783d6fc"
PROTOCOL_DIR = Path(__file__).resolve().parents[1] / "sct" / "protocols"


def _load(name):
    return json.loads((PROTOCOL_DIR / name).read_text(encoding="utf-8"))


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
