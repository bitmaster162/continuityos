import hashlib
import json

import pytest

from continuityos.decision_twin import DecisionTwinError
from continuityos.twinbench import TwinBenchArena


def _sha(text):
    return hashlib.sha256(text.encode()).hexdigest()


def _open_case(arena, case_id="c1", opened_at=10.0):
    return arena.open_case(
        case_id=case_id,
        situation="Ship or hold?",
        options=["SHIP", "HOLD"],
        input_snapshots={
            "generic": _sha("g-" + case_id),
            "profile_rag": _sha("p-" + case_id),
            "sct": _sha("s-" + case_id),
        },
        opened_at=opened_at,
    )


def _submit_all(arena, case_id="c1", t=11.0):
    arena.submit_prediction(case_id, "generic", predicted_choice="SHIP", confidence=0.6, created_at=t)
    arena.submit_prediction(case_id, "profile_rag", predicted_choice="HOLD", confidence=0.7, created_at=t + 0.1)
    arena.submit_prediction(case_id, "sct", predicted_choice="HOLD", confidence=0.9, created_at=t + 0.2)


def test_case_is_shadow_only_and_context_bound(tmp_path):
    arena = TwinBenchArena(tmp_path / "arena.jsonl")
    case = _open_case(arena)
    assert case["can_execute"] is False
    assert case["execution_authority"] == "NONE"
    assert len(case["case_spec_id"]) == 64
    assert arena.verify()["ok"] is True


def test_reveal_blocked_until_all_contestants_commit(tmp_path):
    arena = TwinBenchArena(tmp_path / "arena.jsonl")
    _open_case(arena)
    arena.submit_prediction("c1", "generic", predicted_choice="SHIP", confidence=0.5, created_at=11)
    with pytest.raises(DecisionTwinError, match="missing"):
        arena.reveal_human("c1", actual_choice="HOLD", decided_at=20)


def test_predictions_are_blind_then_one_human_reveal(tmp_path):
    arena = TwinBenchArena(tmp_path / "arena.jsonl")
    _open_case(arena)
    _submit_all(arena)
    reveal = arena.reveal_human("c1", actual_choice="HOLD", reasons=["need more evidence"], decided_at=20)
    assert len(reveal["reveal_id"]) == 64
    with pytest.raises(DecisionTwinError, match="already revealed"):
        arena.reveal_human("c1", actual_choice="SHIP", decided_at=21)
    with pytest.raises(DecisionTwinError, match="closed after"):
        arena.submit_prediction("c1", "sct", predicted_choice="HOLD", confidence=0.8, created_at=21)


def test_finalize_scores_all_contestants(tmp_path):
    arena = TwinBenchArena(tmp_path / "arena.jsonl")
    _open_case(arena)
    _submit_all(arena)
    arena.reveal_human("c1", actual_choice="HOLD", decided_at=20)
    card = arena.finalize_case("c1", evaluated_at=21)
    by = {row["contestant_id"]: row for row in card["scores"]}
    assert card["complete"] is True
    assert by["generic"]["correct"] is False
    assert by["profile_rag"]["correct"] is True
    assert by["sct"]["correct"] is True
    assert by["sct"]["brier"] < by["profile_rag"]["brier"]


def test_duplicate_contestant_is_rejected(tmp_path):
    arena = TwinBenchArena(tmp_path / "arena.jsonl")
    _open_case(arena)
    arena.submit_prediction("c1", "generic", predicted_choice="SHIP", confidence=0.5, created_at=11)
    with pytest.raises(DecisionTwinError, match="already committed"):
        arena.submit_prediction("c1", "generic", predicted_choice="HOLD", confidence=0.5, created_at=12)


def test_invalid_or_missing_context_digest_rejected(tmp_path):
    arena = TwinBenchArena(tmp_path / "arena.jsonl")
    with pytest.raises(DecisionTwinError, match="SHA-256"):
        arena.open_case(
            case_id="x", situation="x", options=["A", "B"],
            input_snapshots={"a": "bad", "b": _sha("b")}, opened_at=1,
        )
    with pytest.raises(DecisionTwinError, match="at least two"):
        arena.open_case(
            case_id="x", situation="x", options=["A", "B"],
            input_snapshots={"a": _sha("a")}, opened_at=1,
        )


def test_prediction_cannot_predate_case(tmp_path):
    arena = TwinBenchArena(tmp_path / "arena.jsonl")
    _open_case(arena, opened_at=10)
    with pytest.raises(DecisionTwinError, match="predate"):
        arena.submit_prediction("c1", "generic", predicted_choice="SHIP", confidence=0.5, created_at=9)


def test_tamper_is_detected_and_future_append_fails(tmp_path):
    path = tmp_path / "arena.jsonl"
    arena = TwinBenchArena(path)
    _open_case(arena)
    rows = [json.loads(line) for line in path.read_text().splitlines()]
    rows[0]["payload"]["situation"] = "tampered"
    path.write_text("\n".join(json.dumps(row, sort_keys=True) for row in rows) + "\n")
    assert arena.verify()["ok"] is False
    with pytest.raises(DecisionTwinError):
        arena.submit_prediction("c1", "generic", predicted_choice="SHIP", confidence=0.5, created_at=11)


def test_pairwise_uses_only_common_cases(tmp_path):
    arena = TwinBenchArena(tmp_path / "arena.jsonl")
    for i, actual in enumerate(["HOLD", "SHIP"], 1):
        case_id = f"c{i}"
        _open_case(arena, case_id, opened_at=10 * i)
        _submit_all(arena, case_id, t=10 * i + 1)
        arena.reveal_human(case_id, actual_choice=actual, decided_at=10 * i + 5)
        arena.finalize_case(case_id, evaluated_at=10 * i + 6)
    pair = arena.pairwise("sct", "generic")
    assert pair["common_cases"] == 2
    assert pair["accuracy_delta_a_minus_b"] == 0.0


def test_leaderboard_has_minimum_sample_gate(tmp_path):
    arena = TwinBenchArena(tmp_path / "arena.jsonl")
    _open_case(arena)
    _submit_all(arena)
    arena.reveal_human("c1", actual_choice="HOLD", decided_at=20)
    arena.finalize_case("c1", evaluated_at=21)
    board = arena.leaderboard(min_cases=2)
    assert board["winner"] is None
    assert all(not row["eligible"] for row in board["contestants"])
