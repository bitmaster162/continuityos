from __future__ import annotations

import json
from pathlib import Path

SCHEMA_DIR = Path(__file__).parents[1] / "continuityos" / "fleet_schemas"
DRAFT_2020_12 = "https://json-schema.org/draft/2020-12/schema"


def _schemas():
    files = sorted(SCHEMA_DIR.glob("*.schema.json"))
    assert len(files) == 6
    rows = []
    for path in files:
        schema = json.loads(path.read_text(encoding="utf-8"))
        assert isinstance(schema, dict)
        assert schema.get("$schema") == DRAFT_2020_12
        assert isinstance(schema.get("$id"), str) and schema["$id"]
        assert schema.get("type") == "object"
        assert schema.get("additionalProperties") is False
        assert isinstance(schema.get("properties"), dict) and schema["properties"]
        assert isinstance(schema.get("required"), list)
        assert set(schema["required"]) <= set(schema["properties"])
        rows.append((path, schema))
    assert len({schema["$id"] for _, schema in rows}) == len(rows)
    return rows


def test_all_fleet_schemas_are_parseable_strict_draft_2020_12_documents():
    _schemas()


def test_public_source_schema_ids_are_not_candidate_ids():
    for _, schema in _schemas():
        assert "candidate" not in schema["$id"].lower()
