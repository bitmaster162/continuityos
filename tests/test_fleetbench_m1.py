from __future__ import annotations

from continuityos.fleetbench_m1 import EXPECTED, run_fleetbench
from continuityos.gate.fleet_coordination import M1_AUTHORITY


def test_fleetbench_all_mandatory_fixtures_pass():
    result = run_fleetbench()
    assert result["total"] == 15
    assert result["passed"] == 15
    assert result["failed"] == 0
    assert result["terminal"] == "M1_FLEETBENCH_PASS"
    assert {row["fixture_id"] for row in result["cases"]} == set(EXPECTED)
    assert all(row["pass"] for row in result["cases"])
    assert all(row["authority"] == M1_AUTHORITY for row in result["cases"])
    assert result["authority"] == M1_AUTHORITY
