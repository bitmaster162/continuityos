import json

import pytest

from continuityos.decision_twin import DecisionTwinError
from continuityos.live_choice_contract import (
    build_choice_contract,
    normalize_human_choice,
    prepare_contracted_live_case,
)
from continuityos.live_twinbench import build_standard_inputs
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


def test_combinable_contract_registers_parallel_outcome():
    contract = build_choice_contract(
        ["FIX_PREVIEW", "CONTINUE_SCT"],
        mode="COMBINABLE",
        allow_none=True,
    )
    assert contract.compiled_options == (
        "FIX_PREVIEW",
        "CONTINUE_SCT",
        "FIX_PREVIEW+CONTINUE_SCT",
        "NEITHER",
    )
    assert normalize_human_choice(contract, ["CONTINUE_SCT", "FIX_PREVIEW"]) == (
        "FIX_PREVIEW+CONTINUE_SCT"
    )
    assert len(contract.contract_sha256) == 64
    assert contract.can_execute is False
    assert contract.execution_authority == "NONE"


def test_priority_contract_makes_parallelism_explicit():
    contract = build_choice_contract(
        ["FIX_PREVIEW", "CONTINUE_SCT"],
        mode="PRIORITY",
        allow_split=True,
    )
    assert contract.compiled_options == (
        "FIX_PREVIEW_FIRST",
        "CONTINUE_SCT_FIRST",
        "SPLIT",
    )
    assert normalize_human_choice(contract, "SPLIT") == "SPLIT"


def test_unregistered_human_combination_is_rejected():
    contract = build_choice_contract(["A", "B"], mode="EXCLUSIVE")
    with pytest.raises(DecisionTwinError, match="outside the pre-registered"):
        normalize_human_choice(contract, "A+B")


def test_reserved_labels_and_combination_explosion_are_rejected():
    with pytest.raises(DecisionTwinError, match="reserved"):
        build_choice_contract(["A+B", "C"], mode="EXCLUSIVE")
    with pytest.raises(DecisionTwinError, match="at most four"):
        build_choice_contract(["A", "B", "C", "D", "E"], mode="COMBINABLE")


def test_contracted_bundle_embeds_choice_semantics_in_every_request(tmp_path):
    arena = TwinBenchArena(tmp_path / "arena.jsonl")
    contract = build_choice_contract(
        ["FIX_PREVIEW", "CONTINUE_SCT"], mode="COMBINABLE", allow_none=True
    )
    result = prepare_contracted_live_case(
        arena,
        root=tmp_path / "cases",
        case_id="live-002",
        decision_surface="parallel_work",
        situation="What work will the principal do in this bounded window?",
        choice_contract=contract,
        frozen_inputs=_inputs(ts=10.0),
        opened_at=11.0,
    )
    case_dir = tmp_path / "cases" / "live-002"
    assert (case_dir / "choice_contract.json").exists()
    assert (case_dir / "choice_contract_receipt.json").exists()
    assert result["choice_contract"]["mode"] == "COMBINABLE"
    assert arena.verify()["ok"] is True

    for name in ("generic", "profile_rag", "sct"):
        request = json.loads((case_dir / "requests" / f"{name}.json").read_text())
        payload = json.loads(request["messages"][1]["content"])
        assert payload["choice_contract"]["compiled_options"] == list(contract.compiled_options)
        assert payload["constraints"]["do_not_invent_unregistered_combination"] is True
        assert "choice_contract.compiled_options" in request["response_contract"]["predicted_choice"]


def test_parallel_choice_completes_existing_r2_scoring_without_void(tmp_path):
    arena = TwinBenchArena(tmp_path / "arena.jsonl")
    contract = build_choice_contract(
        ["FIX_PREVIEW", "CONTINUE_SCT"], mode="COMBINABLE", allow_none=True
    )
    prepare_contracted_live_case(
        arena,
        root=tmp_path / "cases",
        case_id="live-002",
        decision_surface="parallel_work",
        situation="What work will the principal do in this bounded window?",
        choice_contract=contract,
        frozen_inputs=_inputs(ts=10.0),
        opened_at=11.0,
    )
    both = normalize_human_choice(contract, ["FIX_PREVIEW", "CONTINUE_SCT"])
    arena.submit_prediction("live-002", "generic", predicted_choice="FIX_PREVIEW", confidence=0.6, created_at=12.0)
    arena.submit_prediction("live-002", "profile_rag", predicted_choice=both, confidence=0.7, created_at=12.1)
    arena.submit_prediction("live-002", "sct", predicted_choice=both, confidence=0.8, created_at=12.2)
    arena.reveal_human("live-002", actual_choice=both, decided_at=20.0)
    card = arena.finalize_case("live-002", evaluated_at=21.0)
    by = {row["contestant_id"]: row for row in card["scores"]}
    assert card["complete"] is True
    assert by["generic"]["correct"] is False
    assert by["profile_rag"]["correct"] is True
    assert by["sct"]["correct"] is True
