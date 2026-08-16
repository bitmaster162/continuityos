import json
from dataclasses import dataclass

import pytest

from continuityos.live_release import (
    BASELINES,
    LiveReleaseError,
    build_feature_release,
    build_opportunity,
    build_release_receipt,
    prepare_released_live_case,
    validate_feature_release,
)


PARENT = "a" * 64


def _features():
    return {
        "DS-001": {
            "state": "PROVENANCE_ADMITTED_PROVISIONAL",
            "gate_met": True,
            "accepted_decisions": 3,
            "independent_clusters": 3,
            "predictive_strength": 0.82,
        },
        "DS-002": {
            "state": "PROVENANCE_ADMITTED_PROVISIONAL",
            "gate_met": True,
            "accepted_decisions": 2,
            "independent_clusters": 2,
            "predictive_strength": 0.72,
        },
        "DS-003": {
            "state": "WEAK_ONLY",
            "gate_met": True,
            "accepted_decisions": 1,
            "independent_clusters": 1,
            "predictive_strength": 0.35,
        },
    }


def _release(ts=10.0):
    return build_feature_release(
        parent_evidence_sha256=PARENT,
        features=_features(),
        generated_at=ts,
    )


def _opportunity():
    return build_opportunity(
        opportunity_id="OPP-001",
        case_id="live-001",
        observed_at=11.0,
        decision_surface="technical_project_governance",
        situation="Validate a bounded slice or expand immediately?",
        domains=["technical_project_governance", "validation"],
    )


@dataclass
class Frozen:
    snapshot_sha256: str


def _inputs():
    return {name: Frozen((str(i + 1) * 64)[:64]) for i, name in enumerate(BASELINES)}


def test_release_accepts_preregistered_core_thresholds():
    release = _release()
    validate_feature_release(release)
    assert release["core_provenance_gate_met"] is True
    assert release["execution_authority"] == "NONE"
    assert release["can_execute"] is False
    assert len(release["release_sha256"]) == 64


def test_release_rejects_missing_core_feature():
    features = _features()
    del features["DS-002"]
    with pytest.raises(LiveReleaseError, match="missing required core feature"):
        build_feature_release(
            parent_evidence_sha256=PARENT,
            features=features,
            generated_at=10.0,
        )


def test_release_rejects_insufficient_decision_count():
    features = _features()
    features["DS-001"]["accepted_decisions"] = 2
    with pytest.raises(LiveReleaseError, match="insufficient direct-source decisions"):
        build_feature_release(
            parent_evidence_sha256=PARENT,
            features=features,
            generated_at=10.0,
        )


def test_release_rejects_insufficient_cluster_count():
    features = _features()
    features["DS-002"]["independent_clusters"] = 1
    with pytest.raises(LiveReleaseError, match="insufficient independent clusters"):
        build_feature_release(
            parent_evidence_sha256=PARENT,
            features=features,
            generated_at=10.0,
        )


def test_release_rejects_authority_bearing_feature():
    features = _features()
    features["DS-001"]["execution_authority"] = "ALLOW"
    with pytest.raises(LiveReleaseError, match="cannot grant execution authority"):
        build_feature_release(
            parent_evidence_sha256=PARENT,
            features=features,
            generated_at=10.0,
        )


def test_release_hash_is_deterministic_and_privacy_minimized():
    first = _release()
    second = _release()
    assert first["release_sha256"] == second["release_sha256"]
    text = json.dumps(first)
    assert "excerpt" not in text
    assert "message_id" not in text
    assert "path" not in text


def test_opportunity_accepts_clean_unresolved_case():
    opp = _opportunity()
    assert opp["unresolved"] is True
    assert opp["execution_authority"] == "NONE"
    assert len(opp["opportunity_sha256"]) == 64


@pytest.mark.parametrize(
    "field,error",
    [
        ("human_inclination_disclosed", "inclination leakage"),
        ("prior_assistant_recommendation", "recommendation contamination"),
        ("actual_choice_known", "already known"),
        ("retrospective", "not prospective LIVE"),
        ("high_stakes_excluded", "high-stakes"),
    ],
)
def test_opportunity_fails_closed_on_contamination(field, error):
    kwargs = dict(
        opportunity_id="OPP-001",
        case_id="live-001",
        observed_at=11.0,
        decision_surface="technical_project_governance",
        situation="Validate a bounded slice or expand immediately?",
        domains=["validation"],
    )
    kwargs[field] = True
    with pytest.raises(LiveReleaseError, match=error):
        build_opportunity(**kwargs)


def test_opportunity_rejects_resolved_case():
    with pytest.raises(LiveReleaseError, match="must be unresolved"):
        build_opportunity(
            opportunity_id="OPP-001",
            case_id="live-001",
            observed_at=11.0,
            decision_surface="technical_project_governance",
            situation="A or B?",
            domains=["validation"],
            unresolved=False,
        )


def test_release_receipt_binds_exact_abc_snapshots():
    receipt = build_release_receipt(
        case_id="live-001",
        decision_surface="technical_project_governance",
        situation="Validate a bounded slice or expand immediately?",
        choice_contract_sha256="b" * 64,
        frozen_inputs=_inputs(),
        feature_release=_release(),
        opportunity=_opportunity(),
        bound_at=12.0,
    )
    assert set(receipt["input_snapshot_sha256"]) == set(BASELINES)
    assert receipt["execution_authority"] == "NONE"
    assert len(receipt["receipt_sha256"]) == 64


def test_release_receipt_rejects_missing_baseline():
    inputs = _inputs()
    inputs.pop("generic")
    with pytest.raises(LiveReleaseError, match="exactly"):
        build_release_receipt(
            case_id="live-001",
            decision_surface="technical_project_governance",
            situation="Validate a bounded slice or expand immediately?",
            choice_contract_sha256="b" * 64,
            frozen_inputs=inputs,
            feature_release=_release(),
            opportunity=_opportunity(),
            bound_at=12.0,
        )


def test_release_receipt_rejects_case_surface_or_situation_mismatch():
    common = dict(
        choice_contract_sha256="b" * 64,
        frozen_inputs=_inputs(),
        feature_release=_release(),
        opportunity=_opportunity(),
        bound_at=12.0,
    )
    with pytest.raises(LiveReleaseError, match="case_id"):
        build_release_receipt(
            case_id="other",
            decision_surface="technical_project_governance",
            situation="Validate a bounded slice or expand immediately?",
            **common,
        )
    with pytest.raises(LiveReleaseError, match="decision_surface"):
        build_release_receipt(
            case_id="live-001",
            decision_surface="other",
            situation="Validate a bounded slice or expand immediately?",
            **common,
        )
    with pytest.raises(LiveReleaseError, match="situation"):
        build_release_receipt(
            case_id="live-001",
            decision_surface="technical_project_governance",
            situation="Different situation",
            **common,
        )


def test_prepare_released_case_wraps_existing_live01_preparer(tmp_path):
    inputs = _inputs()
    contract = type("Contract", (), {"contract_sha256": "b" * 64})()

    def fake_preparer(
        arena,
        *,
        root,
        case_id,
        decision_surface,
        situation,
        choice_contract,
        frozen_inputs,
        eligibility,
        opened_at,
    ):
        case_dir = root / case_id
        case_dir.mkdir(parents=True)
        return {
            "base_manifest": {"manifest_sha256": "c" * 64},
            "choice_contract": {"contract_sha256": choice_contract.contract_sha256},
            "choice_contract_receipt": {"receipt_sha256": "d" * 64},
        }

    result = prepare_released_live_case(
        arena=object(),
        root=tmp_path,
        case_id="live-001",
        decision_surface="technical_project_governance",
        situation="Validate a bounded slice or expand immediately?",
        choice_contract=contract,
        frozen_inputs=inputs,
        feature_release=_release(),
        opportunity=_opportunity(),
        opened_at=12.0,
        case_preparer=fake_preparer,
    )
    path = tmp_path / "live-001" / "live_release_receipt.json"
    assert path.exists()
    on_disk = json.loads(path.read_text())
    assert on_disk == result["live_release_receipt"]
    assert on_disk["can_execute"] is False
    assert on_disk["execution_authority"] == "NONE"


def test_tampered_release_is_rejected():
    release = _release()
    release["features"][0]["accepted_decisions"] = 999
    with pytest.raises(LiveReleaseError, match="hash mismatch"):
        validate_feature_release(release)
