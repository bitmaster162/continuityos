from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft202012Validator

SCHEMA_DIR = Path(__file__).parents[1] / "continuityos" / "fleet_schemas"


def test_all_fleet_schemas_are_valid_draft_2020_12():
    files = sorted(SCHEMA_DIR.glob("*.schema.json"))
    assert len(files) == 6
    for path in files:
        schema = json.loads(path.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)


def test_public_source_schema_ids_are_not_candidate_ids():
    for path in SCHEMA_DIR.glob("*.schema.json"):
        schema = json.loads(path.read_text(encoding="utf-8"))
        assert "candidate" not in schema["$id"].lower()
