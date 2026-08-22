from __future__ import annotations

import importlib.util
from pathlib import Path

from continuityos.gate.fleet_coordination import M1_AUTHORITY


def _load_bench():
    path = Path(__file__).parents[1] / "bench" / "fleetbench_m1.py"
    spec = importlib.util.spec_from_file_location("continuityos_fleetbench_m1", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_fleetbench_all_mandatory_fixtures_pass():
    bench = _load_bench()
    result = bench.run_fleetbench()
    assert result["total"] == 15
    assert result["passed"] == 15
    assert result["failed"] == 0
    assert result["terminal"] == "M1_FLEETBENCH_PASS"
    assert {row["fixture_id"] for row in result["cases"]} == set(bench.EXPECTED)
    assert all(row["pass"] for row in result["cases"])
    assert all(row["authority"] == M1_AUTHORITY for row in result["cases"])
    assert result["authority"] == M1_AUTHORITY
