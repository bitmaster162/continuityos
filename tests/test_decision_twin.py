import json

import pytest

from continuityos.decision_twin import (
    DecisionTwinError,
    ShadowDecisionLedger,
    build_human_decision,
    build_prediction,
    evaluate,
)


def _prediction(**kw):
    data = dict(
        case_id="case-001",
        situation="Ship candidate A or hold for more evidence?",
        options=["SHIP", "HOLD"],
        predicted_choice="HOLD",
        confidence=0.8,
        reasons=["evidence is incomplete"],
        evidence_refs=["receipt:abc123"],
        change_conditions=["independent verification passes"],
        created_at=100.0,
    )
    data.update(kw)
    return build_prediction(**data)


def test_shadow_prediction_has_no_execution_authority():
    pred = _prediction()
    assert pred.mode == "SHADOW"
    assert pred.execution_authority == "NONE"
    assert pred.can_execute is False
    assert len(pred.prediction_id) == 64


def test_commit_before_answer_and_score_correct_prediction(tmp_path):
    ledger = ShadowDecisionLedger(tmp_path / "twin.jsonl")
    pred = _prediction()
    ledger.commit_prediction(pred)
    decision = build_human_decision(pred, actual_choice="HOLD", decided_at=110.0)
    ledger.record_human_decision(decision)
    result = evaluate(pred, decision, evaluated_at=120.0)
    ledger.record_evaluation(result)

    assert result.correct is True
    assert result.absolute_calibration_error == pytest.approx(0.2)
    assert result.squared_calibration_error == pytest.approx(0.04)
    assert ledger.verify()["ok"] is True
    assert ledger.summary()["accuracy"] == 1.0


def test_wrong_prediction_is_measurable_not_rewritten(tmp_path):
    ledger = ShadowDecisionLedger(tmp_path / "twin.jsonl")
    pred = _prediction(confidence=0.75)
    ledger.commit_prediction(pred)
    decision = build_human_decision(pred, actual_choice="SHIP", decided_at=101.0)
    ledger.record_human_decision(decision)
    result = evaluate(pred, decision, evaluated_at=102.0)
    ledger.record_evaluation(result)

    assert result.correct is False
    assert result.absolute_calibration_error == pytest.approx(0.75)
    assert result.squared_calibration_error == pytest.approx(0.5625)
    rows = [json.loads(line) for line in (tmp_path / "twin.jsonl").read_text(encoding="utf-8").splitlines()]
    assert rows[0]["payload"]["predicted_choice"] == "HOLD"
    assert rows[1]["payload"]["actual_choice"] == "SHIP"


def test_human_decision_cannot_precede_prediction():
    pred = _prediction(created_at=200.0)
    with pytest.raises(DecisionTwinError, match="at or after prediction"):
        build_human_decision(pred, actual_choice="HOLD", decided_at=199.0)


def test_uncommitted_prediction_cannot_receive_human_decision(tmp_path):
    ledger = ShadowDecisionLedger(tmp_path / "twin.jsonl")
    pred = _prediction()
    decision = build_human_decision(pred, actual_choice="HOLD", decided_at=101.0)
    with pytest.raises(DecisionTwinError, match="committed before"):
        ledger.record_human_decision(decision)


def test_duplicate_prediction_and_decision_are_rejected(tmp_path):
    ledger = ShadowDecisionLedger(tmp_path / "twin.jsonl")
    pred = _prediction()
    ledger.commit_prediction(pred)
    with pytest.raises(DecisionTwinError, match="already committed"):
        ledger.commit_prediction(pred)
    decision = build_human_decision(pred, actual_choice="HOLD", decided_at=101.0)
    ledger.record_human_decision(decision)
    with pytest.raises(DecisionTwinError, match="already recorded"):
        ledger.record_human_decision(decision)


def test_ledger_tamper_is_detected(tmp_path):
    path = tmp_path / "twin.jsonl"
    ledger = ShadowDecisionLedger(path)
    pred = _prediction()
    ledger.commit_prediction(pred)
    assert ledger.verify()["ok"] is True

    row = json.loads(path.read_text(encoding="utf-8"))
    row["payload"]["predicted_choice"] = "SHIP"
    path.write_text(json.dumps(row, sort_keys=True) + "\n", encoding="utf-8")
    checked = ledger.verify()
    assert checked["ok"] is False
    assert "hash mismatch" in checked["error"]


def test_prediction_requires_real_choice_set():
    with pytest.raises(DecisionTwinError, match="at least two"):
        _prediction(options=["HOLD"])
    with pytest.raises(DecisionTwinError, match="one of options"):
        _prediction(predicted_choice="MAYBE")
    with pytest.raises(DecisionTwinError, match="confidence"):
        _prediction(confidence=1.1)


def test_refuses_append_after_tamper(tmp_path):
    path = tmp_path / "twin.jsonl"
    ledger = ShadowDecisionLedger(path)
    pred = _prediction()
    ledger.commit_prediction(pred)
    row = json.loads(path.read_text(encoding="utf-8"))
    row["payload"]["confidence"] = 0.1
    path.write_text(json.dumps(row, sort_keys=True) + "\n", encoding="utf-8")
    with pytest.raises(DecisionTwinError, match="invalid ledger"):
        ledger.append("ANY", {"x": 1})


def test_duplicate_evaluation_is_rejected(tmp_path):
    ledger = ShadowDecisionLedger(tmp_path / "twin.jsonl")
    pred = _prediction()
    ledger.commit_prediction(pred)
    decision = build_human_decision(pred, actual_choice="HOLD", decided_at=101.0)
    ledger.record_human_decision(decision)
    result = evaluate(pred, decision, evaluated_at=102.0)
    ledger.record_evaluation(result)
    with pytest.raises(DecisionTwinError, match="already recorded"):
        ledger.record_evaluation(result)
