from importlib import resources
import json


EXPECTED = {
    "causal_spine_v1.schema.json": "continuityos.causal_spine/v1",
    "causal_spine_receipt_v1.schema.json": "continuityos.causal_spine.receipt/v1",
    "causal_spine_event_v1.schema.json": "continuityos.causal_spine.event/v1",
}


def test_causal_spine_schema_package_is_exact_parseable_and_strict():
    root = resources.files("continuityos.causal_spine_schemas")
    observed = {
        item.name
        for item in root.iterdir()
        if item.name.endswith(".schema.json")
    }
    assert observed == set(EXPECTED)

    for name, expected_id in EXPECTED.items():
        payload = json.loads(root.joinpath(name).read_text(encoding="utf-8"))
        assert payload["$schema"] == "https://json-schema.org/draft/2020-12/schema"
        assert payload["$id"] == expected_id
        assert payload["type"] == "object"
        assert payload["additionalProperties"] is False


def test_causal_spine_schema_package_does_not_pollute_anti_amnesia_namespace():
    anti = resources.files("continuityos.gate.schemas")
    assert not any(
        item.name.startswith("causal_spine_")
        for item in anti.iterdir()
    )
