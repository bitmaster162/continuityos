import pytest

from sct.bench.predict import build_prediction
from sct.canon import sha256_obj
from sct.errors import BenchError
from sct.trading_shadow import OFFLINE_MODE, R13_BASELINE_SHA, export_sct_prediction, prepare_trading_shadow_case

CASE_FREEZE_EPOCH = 1_787_151_600.0
PREDICTION_COMMIT_EPOCH = CASE_FREEZE_EPOCH + 100.0


def _case():
    body = {
        "schema": "tradingos.shadow_trade_case.v1",
        "case_id": "trade-001",
        "frozen_at": "2026-08-19T15:00:00Z",
        "symbol": "BTCUSDT",
        "venue": "Binance",
        "timeframe": "1h",
        "scenario": "BTC tests resistance after an upside sweep.",
        "options": ("LONG", "SHORT", "WAIT"),
        "market_evidence": {
            "snapshot": {"source_id": "snapshot:001", "sha256": "a" * 64, "schema": "tradingos.market_snapshot.v1"},
            "vision": {"source_id": "vision:001", "sha256": "b" * 64, "schema": "tradingos.visual_market_evidence.v1"},
        },
        "human_decision_status": "UNREVEALED",
        "safety": {
            "mode": "SHADOW",
            "execution_authority": "NONE",
            "can_trade": False,
            "capital_permission": "DENY",
            "orders_allowed": False,
            "signals_allowed": False,
        },
    }
    body["case_sha256"] = sha256_obj(body)
    return body


def _prepare(case=None, **extra):
    return prepare_trading_shadow_case(
        case or _case(),
        static_profile="profile context xxxxxxxxxxxxxxxxxxxxxxxxxx",
        sct_state="sct context xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        provider="fixture",
        model="fixture-model",
        model_version="v1",
        frozen_at=CASE_FREEZE_EPOCH,
        **extra,
    )


def _prediction(*, case_id="trade-001", arm="sct"):
    return build_prediction(
        case_id=case_id,
        arm=arm,
        options=("LONG", "SHORT", "WAIT"),
        response={
            "option_probabilities": {"LONG": 0.7, "SHORT": 0.1, "WAIT": 0.2},
            "reasons": ["historical pattern"],
            "change_conditions": ["new evidence"],
            "would_escalate": False,
        },
        committed_at=PREDICTION_COMMIT_EPOCH,
    )


def test_prepare_is_offline_shadow_only_and_r13_bound():
    prepared = _prepare()
    assert prepared["schema"] == "sct.trading_shadow_preparation.v1"
    assert prepared["mode"] == OFFLINE_MODE
    assert prepared["r13_baseline_sha"] == R13_BASELINE_SHA
    assert prepared["store_write_performed"] is False
    assert prepared["live_case_opened"] is False
    assert prepared["live_arm_b_provenance_bypass_allowed"] is False
    assert prepared["execution_authority"] == "NONE"
    assert prepared["can_execute"] is False
    assert prepared["arena_kwargs"] is None
    assert set(prepared["inputs"]) == {"generic", "profile_rag", "sct"}


def test_rejects_any_attempt_to_use_non_offline_mode():
    with pytest.raises(BenchError, match="TRADING_SHADOW_R13_LIVE_BYPASS_FORBIDDEN"):
        _prepare(mode="LIVE")


def test_rejects_trade_case_with_action_authority():
    case = _case()
    case["safety"]["can_trade"] = True
    case["case_sha256"] = sha256_obj({k: v for k, v in case.items() if k != "case_sha256"})
    with pytest.raises(BenchError, match="TRADING_SHADOW_UNSAFE"):
        _prepare(case)


def test_rejects_trade_case_without_wait_option():
    case = _case()
    case["options"] = ("LONG", "SHORT")
    case["case_sha256"] = sha256_obj({k: v for k, v in case.items() if k != "case_sha256"})
    with pytest.raises(BenchError, match="TRADING_SHADOW_WAIT_REQUIRED"):
        _prepare(case)


def test_rejects_mismatched_numeric_freeze_epoch():
    with pytest.raises(BenchError, match="TRADING_SHADOW_FREEZE_MISMATCH"):
        prepare_trading_shadow_case(
            _case(),
            static_profile="profile context xxxxxxxxxxxxxxxxxxxxxxxxxx",
            sct_state="sct context xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
            provider="fixture",
            model="fixture-model",
            model_version="v1",
            frozen_at=1_776_000_000.0,
        )


def test_export_committed_sct_prediction_preserves_full_hash_basis():
    pred = _prediction()
    exported = export_sct_prediction(pred)
    assert exported["case_id"] == "trade-001"
    assert exported["arm"] == "sct"
    assert tuple(exported["options"]) == ("LONG", "SHORT", "WAIT")
    assert exported["predicted_choice"] == "LONG"
    assert exported["option_probabilities"]["LONG"] == 0.7
    assert exported["reasons"] == ("historical pattern",)
    assert exported["change_conditions"] == ("new evidence",)
    assert exported["would_escalate"] is False
    assert exported["committed_at"] == PREDICTION_COMMIT_EPOCH
    assert exported["prediction_id"] == sha256_obj({k: v for k, v in exported.items() if k != "prediction_id"})
    assert exported["execution_authority"] == "NONE"
    assert exported["can_execute"] is False


def test_export_rejects_non_sct_arm():
    pred = _prediction(arm="generic")
    with pytest.raises(BenchError, match="NOT_SCT_ARM"):
        export_sct_prediction(pred)


def test_export_rejects_tampered_probability_with_stale_prediction_id():
    raw = _prediction().to_dict()
    raw["option_probabilities"] = {"LONG": 0.2, "SHORT": 0.1, "WAIT": 0.7}
    raw["predicted_choice"] = "WAIT"
    raw["confidence"] = 0.7
    with pytest.raises(BenchError, match="TRADING_SHADOW_PREDICTION_HASH_MISMATCH"):
        export_sct_prediction(raw)


def test_export_rejects_cross_case_relabel_with_stale_prediction_id():
    raw = _prediction().to_dict()
    raw["case_id"] = "trade-OTHER"
    with pytest.raises(BenchError, match="TRADING_SHADOW_PREDICTION_HASH_MISMATCH"):
        export_sct_prediction(raw)
