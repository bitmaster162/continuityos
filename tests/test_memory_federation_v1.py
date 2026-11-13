import base64
import gzip
import json
import random
from importlib import resources

import pytest

from continuityos.memory_federation import (
    FederationContractError,
    MemoryFederation,
    StaticAdapter,
    resolve_candidates,
)

CORPUS_GZIP_B64 = """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"""


def _rows():
    data = gzip.decompress(base64.b64decode(CORPUS_GZIP_B64)).decode("utf-8")
    return [json.loads(line) for line in data.splitlines() if line.strip()]


def _resolve(inp):
    return resolve_candidates(
        inp["query"],
        inp["candidates"],
        sources_unavailable=inp["sources_unavailable"],
        coverage_limits=inp["coverage_limits"],
    )


def test_frozen_24_case_conformance_and_600_order_permutations():
    rows = _rows()
    assert len(rows) == 24
    for row in rows:
        got = _resolve(row["input"])
        expected = row["expected"]
        assert got["decision"] == expected["decision"], row["case_id"]
        assert got["selected_candidate_ids"] == expected["selected_candidate_ids"], row["case_id"]
        assert got["conflict_candidate_ids"] == expected["conflict_candidate_ids"], row["case_id"]
        assert got["coverage_status"] == expected["coverage_status"], row["case_id"]
        baseline = json.dumps(got, sort_keys=True, separators=(",", ":"))
        for seed in range(25):
            clone = json.loads(json.dumps(row["input"]))
            random.Random(seed).shuffle(clone["candidates"])
            again = _resolve(clone)
            assert json.dumps(again, sort_keys=True, separators=(",", ":")) == baseline


def test_effectful_query_is_rejected():
    query = dict(_rows()[0]["input"]["query"])
    query["requested_effect"] = True
    with pytest.raises(FederationContractError):
        resolve_candidates(query, [])


def test_adapter_cannot_escalate_above_registered_authority():
    row = json.loads(json.dumps(_rows()[2]))
    candidate = row["input"]["candidates"][0]
    candidate["adapter_id"] = "GOOGLE_DRIVE_CONNECTOR"
    candidate["result"]["authority_class"] = "CURRENT_TRUTH"
    with pytest.raises(FederationContractError):
        _resolve(row["input"])


def test_gateway_is_read_only_and_conflict_preserving():
    row = _rows()[3]
    adapters = []
    for candidate in row["input"]["candidates"]:
        adapters.append(StaticAdapter(candidate["adapter_id"], (candidate,)))
    gateway = MemoryFederation(adapters)
    result = gateway.read(row["input"]["query"])
    assert result.resolution["decision"] == "CONFLICT"
    assert result.response["gateway_status"] == "PASS_WITH_CONDITIONS"
    assert result.response["authority"] == {
        "read_only": True,
        "grants_current_truth": False,
        "grants_effect_authority": False,
        "can_trade": False,
        "capital_permission": "DENY",
    }
    assert all(item["status"] == "CONFLICT" for item in result.response["results"])


EXPECTED = {
    "universal_artifact_identity_v2.schema.json": "continuityos.universal_artifact_identity/v2",
    "memory_federation_query_v2.schema.json": "continuityos.memory_federation_query/v2",
    "memory_federation_result_v1.schema.json": "continuityos.memory_federation_result/v1",
    "memory_federation_response_v1.schema.json": "continuityos.memory_federation_response/v1",
    "memory_federation_candidate_v1.schema.json": "continuityos.memory_federation_candidate/v1",
    "memory_federation_resolution_v1.schema.json": "continuityos.memory_federation_resolution/v1",
}


def test_memory_federation_schema_package_is_exact_parseable_and_strict():
    root = resources.files("continuityos.memory_federation_schemas")
    observed = {item.name for item in root.iterdir() if item.name.endswith(".schema.json")}
    assert observed == set(EXPECTED)
    for name, expected_id in EXPECTED.items():
        payload = json.loads(root.joinpath(name).read_text(encoding="utf-8"))
        assert payload["$schema"] == "https://json-schema.org/draft/2020-12/schema"
        assert payload["$id"] == expected_id
        assert payload["type"] == "object"
        assert payload["additionalProperties"] is False
