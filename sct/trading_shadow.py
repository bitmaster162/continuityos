from __future__ import annotations

from dataclasses import asdict, is_dataclass
from typing import Any, Mapping

from .bench.envelope import build_standard_inputs
from .bench.predict import PREDICTION_SCHEMA
from .canon import canonical_json, sha256_obj
from .errors import BenchError

TRADING_CASE_SCHEMA = "tradingos.shadow_trade_case.v1"
TRADING_TWIN_PREP_SCHEMA = "sct.trading_shadow_preparation.v1"
SCT_PREDICTION_SCHEMA = PREDICTION_SCHEMA
OFFLINE_MODE = "OFFLINE_FIXTURE_ONLY"
R13_BASELINE_SHA = "944d1711102b7dc12c1be26b17526e87f6b13100"

_REQUIRED_SAFETY = {
    "mode": "SHADOW",
    "execution_authority": "NONE",
    "can_trade": False,
    "capital_permission": "DENY",
    "orders_allowed": False,
    "signals_allowed": False,
}


def _fail(code: str) -> None:
    raise BenchError(code)


def _validate_trade_case(case: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(case, Mapping) or case.get("schema") != TRADING_CASE_SCHEMA:
        _fail("TRADING_SHADOW_WRONG_CASE_SCHEMA")
    safety = case.get("safety")
    if not isinstance(safety, Mapping):
        _fail("TRADING_SHADOW_SAFETY_MISSING")
    for key, expected in _REQUIRED_SAFETY.items():
        if safety.get(key) != expected or type(safety.get(key)) is not type(expected):
            _fail(f"TRADING_SHADOW_UNSAFE:{key}")
    options = case.get("options")
    if not isinstance(options, (list, tuple)) or len(options) < 2:
        _fail("TRADING_SHADOW_OPTIONS_INVALID")
    if any(not isinstance(option, str) or not option.strip() for option in options):
        _fail("TRADING_SHADOW_OPTIONS_INVALID")
    if len(set(options)) != len(options):
        _fail("TRADING_SHADOW_OPTIONS_DUPLICATE")
    if "WAIT" not in options:
        _fail("TRADING_SHADOW_WAIT_REQUIRED")
    if case.get("human_decision_status") != "UNREVEALED":
        _fail("TRADING_SHADOW_DECISION_ALREADY_REVEALED")
    expected = sha256_obj({k: v for k, v in case.items() if k != "case_sha256"})
    if case.get("case_sha256") != expected:
        _fail("TRADING_SHADOW_CASE_HASH_MISMATCH")
    return dict(case)


def _case_situation(case: Mapping[str, Any]) -> str:
    compact = {
        "case_id": case["case_id"],
        "frozen_at": case["frozen_at"],
        "symbol": case["symbol"],
        "venue": case["venue"],
        "timeframe": case["timeframe"],
        "scenario": case["scenario"],
        "market_evidence": case.get("market_evidence", {}),
        "constraint": "Predict the HUMAN trade action only. Do not recommend or execute a trade.",
    }
    return canonical_json(compact)


def prepare_trading_shadow_case(
    trade_case: Mapping[str, Any],
    *,
    static_profile: str,
    sct_state: str,
    provider: str,
    model: str,
    model_version: str,
    permitted_history: str = "",
    token_budget: int = 4096,
    temperature: float | None = 0.0,
    reasoning: str = "default",
    frozen_at: float,
    mode: str = OFFLINE_MODE,
) -> dict[str, Any]:
    """Prepare A/B/C inputs for an OFFLINE TradingOS composition fixture only.

    This adapter deliberately does not open an SCT LIVE case and does not write to the
    EvidenceStore. R13 LIVE Arm B must continue to use the frozen R13 provenance builder and
    qualification/enrollment protocol. Any attempt to use another mode fails closed.
    """
    if mode != OFFLINE_MODE:
        _fail("TRADING_SHADOW_R13_LIVE_BYPASS_FORBIDDEN")
    case = _validate_trade_case(trade_case)
    inputs = build_standard_inputs(
        scenario=_case_situation(case),
        options=case["options"],
        provider=provider,
        model=model,
        model_version=model_version,
        static_profile=static_profile,
        sct_state=sct_state,
        permitted_history=permitted_history,
        token_budget=token_budget,
        temperature=temperature,
        reasoning=reasoning,
        frozen_at=frozen_at,
    )
    cluster = {
        "project_id": "tradingos",
        "domain_id": "trading",
        "time_epoch": str(case["frozen_at"]),
        "decision_family": "trade_action",
    }
    body = {
        "schema": TRADING_TWIN_PREP_SCHEMA,
        "mode": OFFLINE_MODE,
        "r13_baseline_sha": R13_BASELINE_SHA,
        "prediction_schema": SCT_PREDICTION_SCHEMA,
        "case_id": case["case_id"],
        "trade_case_sha256": case["case_sha256"],
        "situation": _case_situation(case),
        "options": tuple(case["options"]),
        "cluster": cluster,
        "assistant_influence": "NONE",
        "input_snapshot_sha256": {arm: value.snapshot_sha256 for arm, value in inputs.items()},
        "execution_authority": "NONE",
        "can_execute": False,
        "store_write_performed": False,
        "live_case_opened": False,
        "live_arm_b_provenance_bypass_allowed": False,
    }
    body["preparation_sha256"] = sha256_obj(body)
    return {
        **body,
        "inputs": inputs,
        "arena_kwargs": None,
    }


def export_sct_prediction(prediction: Any) -> dict[str, Any]:
    """Project one already committed current-schema SCT-arm prediction into a shadow packet."""
    if is_dataclass(prediction):
        raw = asdict(prediction)
    elif isinstance(prediction, Mapping):
        raw = dict(prediction)
    else:
        _fail("TRADING_SHADOW_PREDICTION_INVALID")
    if raw.get("schema") != SCT_PREDICTION_SCHEMA:
        _fail("TRADING_SHADOW_PREDICTION_SCHEMA")
    if raw.get("arm") != "sct":
        _fail("TRADING_SHADOW_PREDICTION_NOT_SCT_ARM")
    if raw.get("execution_authority") != "NONE" or raw.get("can_execute") is not False:
        _fail("TRADING_SHADOW_PREDICTION_UNSAFE")
    probs = raw.get("option_probabilities")
    if not isinstance(probs, Mapping) or not probs:
        _fail("TRADING_SHADOW_PREDICTION_PROBABILITIES")
    return {
        "schema": SCT_PREDICTION_SCHEMA,
        "case_id": raw.get("case_id"),
        "prediction_id": raw.get("prediction_id"),
        "predicted_choice": raw.get("predicted_choice"),
        "confidence": raw.get("confidence"),
        "option_probabilities": dict(probs),
        "committed_at": raw.get("committed_at"),
        "execution_authority": "NONE",
        "can_execute": False,
    }
