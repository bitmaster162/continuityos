from __future__ import annotations

import json
from pathlib import Path

from bench import current_truth_bench


def test_current_truth_frozen_real_project_fixtures_pass():
    result = current_truth_bench.run()
    assert result["status"] == "PASS"
    assert result["fixture_count"] == 5
    assert all(case["ok"] for case in result["cases"])
    by_id = {case["case_id"]: case for case in result["cases"]}
    assert (
        by_id["issue-111-stale-open-vs-pr-115-merged"]["observed"]["selected_kind"]
        == "PROVIDER_READBACK"
    )
    assert (
        by_id["issue-114-stale-sequencing-vs-pr-115-merged"]["observed"]["selected_status"]
        == "PASS"
    )
    assert (
        by_id["fresh-provider-contradiction-blocks-older-human-pass"]["observed"]["reason"]
        == "FRESH_CURRENT_CONTRADICTION"
    )


def test_current_truth_main_writes_result_and_manifest(tmp_path: Path):
    result = tmp_path / "current-truth.json"
    manifest = tmp_path / "current-truth.manifest.json"
    assert (
        current_truth_bench.main(
            [
                "--json-out",
                str(result),
                "--manifest-out",
                str(manifest),
            ]
        )
        == 0
    )
    payload = json.loads(result.read_text(encoding="utf-8"))
    sealed = json.loads(manifest.read_text(encoding="utf-8"))
    assert payload["status"] == "PASS"
    assert sealed["benchmark"]["name"] == "current-truth"
    assert sealed["dataset"]["fixture_count"] == 5
    assert sealed["dataset"]["network_calls"] == 0
    assert sealed["model"]["identity_assurance"] == "NOT_APPLICABLE_DETERMINISTIC_RULES"
    assert sealed["authority"]["provider_effects"] is False
