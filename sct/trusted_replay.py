from __future__ import annotations

from typing import Any, Mapping

from .canon import sha256_obj
from .errors import BenchError
from .trading_shadow import OFFLINE_MODE, prepare_trading_shadow_case

TRUSTED_REPLAY_INPUT_SCHEMA = "tradingos.trusted_replay_input.v1"
REPLAY_QUALIFICATION_SCHEMA = "tradingos.shadow_temporal_replay_qualification.v1"
TRUSTED_REPLAY_PREP_SCHEMA = "sct.trusted_replay_shadow_preparation.v1"

_REQUIRED_SAFETY = {
    "mode": "SHADOW",
    "execution_authority": "NONE",
    "can_trade": False,
    "capital_permission": "DENY",
    "orders_allowed": False,
    "signals_allowed": False,
}

_REQUIRED_NO_EFFECTS = {
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


def _fail(code: str) -> None:
    raise BenchError(code)


def _sha256(value: Any, field: str) -> str:
    if not isinstance(value, str):
        _fail(f"SCT_TRUSTED_REPLAY_{field}_SHA256")
    text = value.lower()
    if len(text) != 64 or any(ch not in "0123456789abcdef" for ch in text):
        _fail(f"SCT_TRUSTED_REPLAY_{field}_SHA256")
    return text


def _verify_safety(value: Mapping[str, Any], field: str) -> None:
    safety = value.get("safety") if isinstance(value, Mapping) else None
    if not isinstance(safety, Mapping):
        _fail(f"SCT_TRUSTED_REPLAY_{field}_SAFETY_MISSING")
    for key, expected in _REQUIRED_SAFETY.items():
        if safety.get(key) != expected or type(safety.get(key)) is not type(expected):
            _fail(f"SCT_TRUSTED_REPLAY_{field}_UNSAFE:{key}")


def _verify_no_effects(value: Any, field: str) -> None:
    if not isinstance(value, Mapping) or set(value) != set(_REQUIRED_NO_EFFECTS):
        _fail(f"SCT_TRUSTED_REPLAY_{field}_EFFECTS_INVALID")
    for key, expected in _REQUIRED_NO_EFFECTS.items():
        if value.get(key) is not expected:
            _fail(f"SCT_TRUSTED_REPLAY_{field}_EFFECT:{key}")


def _verify_hash(value: Mapping[str, Any], hash_field: str, error_code: str) -> str:
    expected = sha256_obj({k: v for k, v in value.items() if k != hash_field})
    if value.get(hash_field) != expected:
        _fail(error_code)
    return str(value[hash_field])


def _validate_replay_input(
    replay_input: Mapping[str, Any],
    *,
    expected_qualification_sha256: str,
) -> tuple[dict[str, Any], str, str]:
    if not isinstance(replay_input, Mapping) or replay_input.get("schema") != TRUSTED_REPLAY_INPUT_SCHEMA:
        _fail("SCT_TRUSTED_REPLAY_INPUT_SCHEMA")
    _verify_safety(replay_input, "INPUT")
    _verify_no_effects(replay_input.get("effects"), "INPUT")
    if replay_input.get("replay_mode") != "OFFLINE_TRUSTED_REPLAY_ONLY":
        _fail("SCT_TRUSTED_REPLAY_MODE")
    if replay_input.get("external_expected_reference_consumed") is not True:
        _fail("SCT_TRUSTED_REPLAY_EXTERNAL_REFERENCE_MISSING")
    if replay_input.get("source_authenticity_created_here") is not False:
        _fail("SCT_TRUSTED_REPLAY_AUTHENTICITY_OVERCLAIM")
    if replay_input.get("execution_authority") != "NONE" or replay_input.get("can_execute") is not False:
        _fail("SCT_TRUSTED_REPLAY_INPUT_AUTHORITY")

    case = replay_input.get("trade_case")
    if not isinstance(case, Mapping):
        _fail("SCT_TRUSTED_REPLAY_CASE_MISSING")
    case = dict(case)
    case_hash = sha256_obj({k: v for k, v in case.items() if k != "case_sha256"})
    if case.get("case_sha256") != case_hash:
        _fail("SCT_TRUSTED_REPLAY_CASE_HASH")
    if replay_input.get("case_id") != case.get("case_id") or replay_input.get("case_sha256") != case_hash:
        _fail("SCT_TRUSTED_REPLAY_CASE_BINDING")

    qualification = replay_input.get("qualification")
    if not isinstance(qualification, Mapping) or qualification.get("schema") != REPLAY_QUALIFICATION_SCHEMA:
        _fail("SCT_TRUSTED_REPLAY_QUALIFICATION_SCHEMA")
    _verify_safety(qualification, "QUALIFICATION")
    _verify_no_effects(qualification.get("effects"), "QUALIFICATION")
    if qualification.get("case_id") != case.get("case_id") or qualification.get("case_sha256") != case_hash:
        _fail("SCT_TRUSTED_REPLAY_QUALIFICATION_CASE_BINDING")
    if qualification.get("qualification_status") != "QUALIFIED_FOR_OFFLINE_REPLAY_ONLY":
        _fail("SCT_TRUSTED_REPLAY_QUALIFICATION_STATUS")
    if qualification.get("temporal_status") != "QUALIFIED_PRE_FREEZE_AND_FRESH_AT_FREEZE":
        _fail("SCT_TRUSTED_REPLAY_TEMPORAL_STATUS")
    if qualification.get("trust_status") != "MATCHED_EXPECTED_EXTERNAL_ROOT_AND_CASE_BINDING":
        _fail("SCT_TRUSTED_REPLAY_TRUST_STATUS")
    if qualification.get("external_expected_reference_required") is not True:
        _fail("SCT_TRUSTED_REPLAY_EXTERNAL_REFERENCE_FLAG")
    if qualification.get("source_authenticity_created_here") is not False:
        _fail("SCT_TRUSTED_REPLAY_QUALIFICATION_AUTHENTICITY_OVERCLAIM")
    if qualification.get("apply_allowed") is not False or qualification.get("execution_authority") != "NONE":
        _fail("SCT_TRUSTED_REPLAY_QUALIFICATION_AUTHORITY")

    qualification_sha = _verify_hash(
        qualification,
        "qualification_sha256",
        "SCT_TRUSTED_REPLAY_QUALIFICATION_HASH",
    )
    expected_qualification = _sha256(expected_qualification_sha256, "EXPECTED_QUALIFICATION")
    if qualification_sha != expected_qualification:
        _fail("SCT_TRUSTED_REPLAY_EXPECTED_QUALIFICATION_MISMATCH")
    if replay_input.get("qualification_sha256") != qualification_sha:
        _fail("SCT_TRUSTED_REPLAY_INPUT_QUALIFICATION_BINDING")

    replay_input_sha = _verify_hash(
        replay_input,
        "replay_input_sha256",
        "SCT_TRUSTED_REPLAY_INPUT_HASH",
    )
    return case, qualification_sha, replay_input_sha


def prepare_trusted_replay_shadow_case(
    replay_input: Mapping[str, Any],
    *,
    expected_qualification_sha256: str,
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
    """Prepare SCT A/B/C inputs only after an externally anchored replay qualification is bound.

    The upstream TradingOS membrane is responsible for temporal evidence checks and matching the
    expected external authority root/case-binding digest. This SCT adapter does not recreate that
    trust. Instead it requires the exact externally retained qualification SHA-256 and binds it
    into the SCT preparation receipt.
    """
    case, qualification_sha, replay_input_sha = _validate_replay_input(
        replay_input,
        expected_qualification_sha256=expected_qualification_sha256,
    )
    prepared = prepare_trading_shadow_case(
        case,
        static_profile=static_profile,
        sct_state=sct_state,
        provider=provider,
        model=model,
        model_version=model_version,
        permitted_history=permitted_history,
        token_budget=token_budget,
        temperature=temperature,
        reasoning=reasoning,
        frozen_at=frozen_at,
        mode=mode,
    )

    body = {
        "schema": TRUSTED_REPLAY_PREP_SCHEMA,
        "mode": OFFLINE_MODE,
        "case_id": case["case_id"],
        "trade_case_sha256": case["case_sha256"],
        "qualification_sha256": qualification_sha,
        "replay_input_sha256": replay_input_sha,
        "base_preparation_sha256": prepared["preparation_sha256"],
        "input_snapshot_sha256": dict(prepared["input_snapshot_sha256"]),
        "assistant_influence": "NONE",
        "trust_created_by_sct": False,
        "store_write_performed": False,
        "live_case_opened": False,
        "live_arm_b_provenance_bypass_allowed": False,
        "execution_authority": "NONE",
        "can_execute": False,
    }
    body["preparation_sha256"] = sha256_obj(body)
    return {
        **body,
        "inputs": prepared["inputs"],
        "arena_kwargs": None,
    }
