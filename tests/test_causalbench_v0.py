import pytest

try:
    from bench.causalbench import run
except ModuleNotFoundError as exc:
    if exc.name != "bench":
        raise
    pytest.skip(
        "CausalBench is a source-only regression corpus and is intentionally not shipped in the wheel",
        allow_module_level=True,
    )


def test_causalbench_v0_exact_regression_receipt_passes():
    receipt = run()

    assert receipt["status"] == "PASS"
    assert receipt["case_count"] == 17
    assert all(case["ok"] for case in receipt["cases"])
    assert receipt["event_readback_ok"] is True
    assert receipt["tamper_rejected"] is True
    assert receipt["rehashed_effect_forgery_rejected"] is True
    assert receipt["rehashed_authority_forgery_rejected"] is True
    assert receipt["effects"]["can_trade"] is False
    assert receipt["effects"]["capital_permission"] == "DENY"
    assert receipt["effects"]["deployment"] is False