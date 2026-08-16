import json

import pytest

from continuityos.decision_twin import DecisionTwinError
from continuityos.live_twinbench import (
    BASELINES,
    CaseEligibility,
    analysis_export,
    build_standard_inputs,
    evidence_stage,
    prepare_live_case,
    render_request,
)
from continuityos.twinbench import TwinBenchArena


def _inputs(ts=10.0):
    return build_standard_inputs(
        provider="test-provider",
        model="same-model",
        model_version="2026-08-16",
        static_profile="approved static profile",
        permitted_history="frozen permitted history",
        sct_state="sovereign SCT state",
        token_budget=2048,
        temperature=0.0,
        reasoning="fixed",
        frozen_at=ts,
    )


def test_standard_inputs_hold_model_constant_and_contexts_differ():
    inputs = _inputs()
    assert tuple(inputs) == BASELINES
    assert {x.model for x in inputs.values()} == {"same-model"}
    assert {x.model_version for x in inputs.values()} == {"2026-08-16"}
    assert len({x.snapshot_sha256 for x in inputs.values()}) == 3
    assert inputs["generic"].context_sections == ()
    assert "approved_static_profile" in dict(inputs["profile_rag"].context_sections)
    assert "sovereign_person_state" in dict(inputs["sct"].context_sections)
    assert all(x.can_execute is False for x in inputs.values())
    assert all(x.execution_authority == "NONE" for x in inputs.values())


def test_request_is_bound_to_snapshot_and_generic_has_no_personal_context():
    inputs = _inputs()
    req = render_request(
        situation="Archive or ship?",
        options=["ARCHIVE", "SHIP"],
        frozen_input=inputs["generic"],
    )
    assert req["snapshot_sha256"] == inputs["generic"].snapshot_sha256
    assert req["can_execute"] is False
    user = json.loads(req["messages"][1]["content"])
    assert user["scenario"] == "Archive or ship?"
    assert user["frozen_personal_context"] == []
    assert user["constraints"]["do_not_requery_for_a_better_answer"] is True


def test_ineligible_case_is_rejected():
    with pytest.raises(DecisionTwinError, match="externally_forced"):
        CaseEligibility(externally_forced=True).validate()
    with pytest.raises(DecisionTwinError, match="prospective"):
        CaseEligibility(prospective=False).validate()


def test_prepare_live_case_writes_reproducible_bundle_and_registers_r2(tmp_path):
    arena = TwinBenchArena(tmp_path / "arena.jsonl")
    manifest = prepare_live_case(
        arena,
        root=tmp_path / "cases",
        case_id="live-001",
        decision_surface="executive_inbox_triage",
        situation="Reply now or defer until tomorrow?",
        options=["REPLY_NOW", "DEFER"],
        frozen_inputs=_inputs(ts=10.0),
        opened_at=11.0,
    )
    case_dir = tmp_path / "cases" / "live-001"
    assert len(manifest["manifest_sha256"]) == 64
    assert set(manifest["input_snapshots"]) == set(BASELINES)
    assert (case_dir / "case_manifest.json").exists()
    assert all((case_dir / "inputs" / f"{name}.json").exists() for name in BASELINES)
    assert all((case_dir / "requests" / f"{name}.json").exists() for name in BASELINES)
    checked = arena.verify()
    assert checked["ok"] is True
    assert checked["arena_cases"] == 1


def test_prepare_requires_exact_abc_contestants(tmp_path):
    arena = TwinBenchArena(tmp_path / "arena.jsonl")
    inputs = _inputs()
    inputs.pop("generic")
    with pytest.raises(DecisionTwinError, match="exactly"):
        prepare_live_case(
            arena,
            root=tmp_path / "cases",
            case_id="bad",
            decision_surface="inbox",
            situation="A or B?",
            options=["A", "B"],
            frozen_inputs=inputs,
            opened_at=11.0,
        )


def test_case_opening_cannot_predate_frozen_inputs(tmp_path):
    arena = TwinBenchArena(tmp_path / "arena.jsonl")
    with pytest.raises(DecisionTwinError, match="cannot predate"):
        prepare_live_case(
            arena,
            root=tmp_path / "cases",
            case_id="bad-time",
            decision_surface="inbox",
            situation="A or B?",
            options=["A", "B"],
            frozen_inputs=_inputs(ts=10.0),
            opened_at=9.0,
        )


def test_live_bundle_can_complete_real_r2_flow(tmp_path):
    arena = TwinBenchArena(tmp_path / "arena.jsonl")
    prepare_live_case(
        arena,
        root=tmp_path / "cases",
        case_id="live-001",
        decision_surface="executive_inbox_triage",
        situation="Reply now or defer?",
        options=["REPLY_NOW", "DEFER"],
        frozen_inputs=_inputs(ts=10.0),
        opened_at=11.0,
    )
    arena.submit_prediction("live-001", "generic", predicted_choice="REPLY_NOW", confidence=0.6, created_at=12.0)
    arena.submit_prediction("live-001", "profile_rag", predicted_choice="DEFER", confidence=0.7, created_at=12.1)
    arena.submit_prediction("live-001", "sct", predicted_choice="DEFER", confidence=0.8, created_at=12.2)
    arena.reveal_human("live-001", actual_choice="DEFER", decided_at=20.0)
    card = arena.finalize_case("live-001", evaluated_at=21.0)
    assert card["complete"] is True
    export = analysis_export(arena)
    assert export["primary_comparison"] == "sct_vs_profile_rag"
    assert export["evidence_stage"]["stage"] == "DEBUG_ONLY"
    assert export["status"] == "DESCRIPTIVE_ONLY"


def test_evidence_stage_does_not_turn_sample_count_into_proof():
    assert evidence_stage(5)["stage"] == "DEBUG_ONLY"
    assert evidence_stage(20)["stage"] == "PILOT_NO_CLAIM"
    assert evidence_stage(30)["stage"] == "DIRECTIONAL_ONLY"
    hundred = evidence_stage(100)
    assert hundred["stage"] == "DEFENSIBLE_DIRECTIONAL_CANDIDATE"
    assert hundred["inferential_claim_allowed"] is True
    assert "not statistical proof" in hundred["note"]
