import pytest

from sct.bench.predict import build_prediction
from sct.canon import sha256_obj
from sct.errors import BenchError
from sct.trading_shadow import export_sct_prediction, prepare_trading_shadow_case


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
            "snapshot": {
                "source_id": "snapshot:001",
                "sha256": "a" * 64,
                "schema": "tradingos.market_snapshot.v1",
            },
            "vision": {
                "source_id": "vision:001",
                "sha256": "b" * 64,
                "schema": "visionassist.market_observation.v1",
            },
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


def test_prepare_is_pure_and_shadow_only():
    prepared = prepare_trading_shadow_case(
        _case(),
        static_profile="profile context xxxxxxxxxxxxxxxxxxxxxxxxxx",
        sct_state="sct context xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        provider="fixture",
        model="fixture-model",
        model_version="v1",
        frozen_at=1_776_000_000.0,
    )
    assert prepared["schema"] == "sct.trading_shadow_preparation.v1"
    assert prepared["store_write_performed"] is False
    assert prepared["execution_authority"] == "NONE"
    assert prepared["can_execute"] is False
    assert set(prepared["inputs"]) == {"generic", "profile_rag", "sct"}
    assert prepared["arena_kwargs"]["assistant_influence"] == "NONE"
    assert prepared["cluster"]["domain_id"] == "trading"


def test_rejects_trade_case_with_action_authority():
    case = _case()
    case["safety"]["can_trade"] = True
    case["case_sha256"] = sha256_obj({k: v for k, v in case.items() if k != "case_sha256"})
    with pytest.raises(BenchError, match="TRADING_SHADOW_UNSAFE"):
        prepare_trading_shadow_case(
            case,
            static_profile="profile context",
            sct_state="sct context",
            provider="fixture",
            model="fixture-model",
            model_version="v1",
            frozen_at=1_776_000_000.0,
        )


def test_rejects_trade_case_without_wait_option():
    case = _case()
    case["options"] = ("LONG", "SHORT")
    case["case_sha256"] = sha256_obj({k: v for k, v in case.items() if k != "case_sha256"})
    with pytest.raises(BenchError, match="TRADING_SHADOW_WAIT_REQUIRED"):
        prepare_trading_shadow_case(
            case,
            static_profile="profile context",
            sct_state="sct context",
            provider="fixture",
            model="fixture-model",
            model_version="v1",
            frozen_at=1_776_000_000.0,
        )


def test_export_committed_sct_prediction():
    pred = build_prediction(
        case_id="trade-001",
        arm="sct",
        options=("LONG", "SHORT", "WAIT"),
        response={
            "option_probabilities": {"LONG": 0.7, "SHORT": 0.1, "WAIT": 0.2},
            "reasons": ["historical pattern"],
            "change_conditions": ["new evidence"],
            "would_escalate": False,
        },
        committed_at=1_776_000_100.0,
    )
    exported = export_sct_prediction(pred)
    assert exported["predicted_choice"] == "LONG"
    assert exported["option_probabilities"]["LONG"] == 0.7
    assert exported["execution_authority"] == "NONE"
    assert exported["can_execute"] is False


def test_export_rejects_non_sct_arm():
    pred = build_prediction(
        case_id="trade-001",
        arm="generic",
        options=("LONG", "SHORT", "WAIT"),
        response={
            "option_probabilities": {"LONG": 0.3, "SHORT": 0.2, "WAIT": 0.5},
            "reasons": [],
            "change_conditions": [],
            "would_escalate": False,
        },
        committed_at=1_776_000_100.0,
    )
    with pytest.raises(BenchError, match="NOT_SCT_ARM"):
        export_sct_prediction(pred)
