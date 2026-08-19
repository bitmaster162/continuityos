import copy

import pytest

from sct.canon import sha256_obj
from sct.errors import BenchError
from sct.trusted_replay import prepare_trusted_replay_shadow_case

SAFETY = {
    "mode": "SHADOW",
    "execution_authority": "NONE",
    "can_trade": False,
    "capital_permission": "DENY",
    "orders_allowed": False,
    "signals_allowed": False,
}

NO_EFFECTS = {
    "current_truth_apply": False,
    "continuity_write": False,
    "return_write": False,
    "archive_write": False,
    "runtime_activation": False,
    "model_call": False,
    "exchange_call": False,
    "signal": False,
    "order": False,
    "capital_effect": False,
}

FREEZE_EPOCH = 1_787_151_600.0


def _case(case_id="trusted-replay-001"):
    body = {
        "schema": "tradingos.shadow_trade_case.v1",
        "case_id": case_id,
        "frozen_at": "2026-08-19T15:00:00Z",
        "symbol": "BTCUSDT",
        "venue": "Binance",
        "timeframe": "1h",
        "scenario": "Trusted replay fixture.",
        "options": ("LONG", "SHORT", "WAIT"),
        "market_evidence": {
            "snapshot": {
                "source_id": "snapshot:trusted",
                "sha256": "a" * 64,
                "schema": "market.snapshot/v1",
            },
            "vision": {
                "source_id": "vision:trusted",
                "sha256": "b" * 64,
                "schema": "vision.market/v1",
            },
        },
        "human_decision_status": "UNREVEALED",
        "safety": dict(SAFETY),
    }
    body["case_sha256"] = sha256_obj(body)
    return body


def _qualification(case):
    body = {
        "schema": "tradingos.shadow_temporal_replay_qualification.v1",
        "generated_at": "2026-08-20T02:10:00+07:00",
        "case_id": case["case_id"],
        "case_sha256": case["case_sha256"],
        "frozen_at": case["frozen_at"],
        "evidence_bundle_sha256": "c" * 64,
        "anchor_sha256": "d" * 64,
        "temporal_status": "QUALIFIED_PRE_FREEZE_AND_FRESH_AT_FREEZE",
        "trust_status": "MATCHED_EXPECTED_EXTERNAL_ROOT_AND_CASE_BINDING",
        "qualification_status": "QUALIFIED_FOR_OFFLINE_REPLAY_ONLY",
        "source_authenticity_created_here": False,
        "external_expected_reference_required": True,
        "apply_allowed": False,
        "execution_authority": "NONE",
        "safety": dict(SAFETY),
        "effects": dict(NO_EFFECTS),
    }
    body["qualification_sha256"] = sha256_obj(body)
    return body


def _replay_input():
    case = _case()
    qualification = _qualification(case)
    body = {
        "schema": "tradingos.trusted_replay_input.v1",
        "trade_case": case,
        "case_id": case["case_id"],
        "case_sha256": case["case_sha256"],
        "qualification": qualification,
        "qualification_sha256": qualification["qualification_sha256"],
        "replay_mode": "OFFLINE_TRUSTED_REPLAY_ONLY",
        "external_expected_reference_consumed": True,
        "source_authenticity_created_here": False,
        "execution_authority": "NONE",
        "can_execute": False,
        "safety": dict(SAFETY),
        "effects": dict(NO_EFFECTS),
    }
    body["replay_input_sha256"] = sha256_obj(body)
    return body


def _prepare(replay_input=None, expected=None):
    value = _replay_input() if replay_input is None else replay_input
    expected_sha = value["qualification_sha256"] if expected is None else expected
    return prepare_trusted_replay_shadow_case(
        value,
        expected_qualification_sha256=expected_sha,
        static_profile="profile context xxxxxxxxxxxxxxxxxxxxxxxxxx",
        sct_state="sct context xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        provider="fixture",
        model="fixture-model",
        model_version="v1",
        frozen_at=FREEZE_EPOCH,
    )


def test_trusted_replay_binds_external_qualification_into_sct_preparation():
    replay = _replay_input()
    prepared = _prepare(replay)
    assert prepared["schema"] == "sct.trusted_replay_shadow_preparation.v1"
    assert prepared["qualification_sha256"] == replay["qualification_sha256"]
    assert prepared["replay_input_sha256"] == replay["replay_input_sha256"]
    assert prepared["trade_case_sha256"] == replay["case_sha256"]
    assert prepared["trust_created_by_sct"] is False
    assert prepared["store_write_performed"] is False
    assert prepared["live_case_opened"] is False
    assert prepared["live_arm_b_provenance_bypass_allowed"] is False
    assert prepared["execution_authority"] == "NONE"
    assert prepared["can_execute"] is False
    assert prepared["arena_kwargs"] is None


def test_wrong_out_of_band_qualification_hash_fails_closed():
    with pytest.raises(BenchError, match="EXPECTED_QUALIFICATION_MISMATCH"):
        _prepare(expected="f" * 64)


def test_rehashed_tampered_qualification_cannot_replace_expected_external_hash():
    replay = _replay_input()
    original_expected = replay["qualification_sha256"]
    replay["qualification"]["generated_at"] = "2026-08-20T02:11:00+07:00"
    replay["qualification"]["qualification_sha256"] = sha256_obj(
        {k: v for k, v in replay["qualification"].items() if k != "qualification_sha256"}
    )
    replay["qualification_sha256"] = replay["qualification"]["qualification_sha256"]
    replay["replay_input_sha256"] = sha256_obj(
        {k: v for k, v in replay.items() if k != "replay_input_sha256"}
    )
    with pytest.raises(BenchError, match="EXPECTED_QUALIFICATION_MISMATCH"):
        _prepare(replay, expected=original_expected)


def test_qualification_cannot_bind_a_different_case():
    replay = _replay_input()
    replay["qualification"]["case_id"] = "other-case"
    replay["qualification"]["qualification_sha256"] = sha256_obj(
        {k: v for k, v in replay["qualification"].items() if k != "qualification_sha256"}
    )
    replay["qualification_sha256"] = replay["qualification"]["qualification_sha256"]
    replay["replay_input_sha256"] = sha256_obj(
        {k: v for k, v in replay.items() if k != "replay_input_sha256"}
    )
    with pytest.raises(BenchError, match="QUALIFICATION_CASE_BINDING"):
        _prepare(replay, expected=replay["qualification_sha256"])


def test_replay_input_effect_flag_is_rejected_before_sct_preparation():
    replay = _replay_input()
    replay["effects"]["model_call"] = True
    replay["replay_input_sha256"] = sha256_obj(
        {k: v for k, v in replay.items() if k != "replay_input_sha256"}
    )
    with pytest.raises(BenchError, match="INPUT_EFFECT:model_call"):
        _prepare(replay)


def test_sct_cannot_claim_that_it_created_source_authenticity():
    replay = _replay_input()
    replay["source_authenticity_created_here"] = True
    replay["replay_input_sha256"] = sha256_obj(
        {k: v for k, v in replay.items() if k != "replay_input_sha256"}
    )
    with pytest.raises(BenchError, match="AUTHENTICITY_OVERCLAIM"):
        _prepare(replay)
