"""Bounded, offline RUAP line-registry evidence comparator (no database access).

Inputs are two *separately authorized* JSON exports. Never fetches sources,
contacts a server, changes a file, or promotes a record to canonical authority.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

SCHEMA = "continuityos.ruap_lines_evidence/v1"
FIELDS = ("line", "executor_chat", "bucket", "current_state", "next_turn", "evidence", "updated_at")
MAX_BYTES = 131_072
EXPECTED_REFERENCE_IDS = frozenset(range(1, 17))


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for name, value in pairs:
        if name in result:
            raise ValueError("DUPLICATE_FIELD")
        result[name] = value
    return result


def load_export(path: str, *, reference: bool) -> dict[str, Any]:
    target = Path(path)
    if target.is_symlink() or not target.is_file():
        raise ValueError("EXPORT_NOT_REGULAR_FILE")
    before = target.stat()
    if before.st_size > MAX_BYTES:
        raise ValueError("EXPORT_TOO_LARGE")
    raw = target.read_bytes()
    after = target.stat()
    if len(raw) > MAX_BYTES or (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
        raise ValueError("EXPORT_CHANGED_OR_TOO_LARGE")
    try:
        obj = json.loads(raw.decode("utf-8-sig"), object_pairs_hook=_unique)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("INVALID_EXPORT_JSON") from exc
    if not isinstance(obj, dict) or obj.get("schema") != SCHEMA:
        raise ValueError("EXPORT_SCHEMA_MISMATCH")
    records = obj.get("records")
    if not isinstance(records, list) or len(records) > 64:
        raise ValueError("EXPORT_RECORDS_INVALID")
    if not isinstance(obj.get("source_version"), str) or not obj["source_version"].strip():
        raise ValueError("SOURCE_VERSION_REQUIRED")
    mapped = {}
    for record in records:
        if not isinstance(record, dict) or set(record) != {"id", *FIELDS}:
            raise ValueError("RECORD_FIELDS_INVALID")
        rid = record["id"]
        if type(rid) is not int or rid < 1 or rid > 64 or rid in mapped:
            raise ValueError("RECORD_ID_INVALID_OR_DUPLICATE")
        if any(not isinstance(record[key], str) for key in FIELDS):
            raise ValueError("RECORD_VALUE_INVALID")
        mapped[rid] = record
    if reference and frozenset(mapped) != EXPECTED_REFERENCE_IDS:
        raise ValueError("REFERENCE_MUST_HAVE_16_LINES")
    return {"source_version": obj["source_version"], "records": mapped}


def compare(reference: dict[str, Any], runtime: dict[str, Any]) -> dict[str, Any]:
    expected, observed = reference["records"], runtime["records"]
    missing = sorted(set(expected) - set(observed))
    unexpected = sorted(set(observed) - set(expected))
    changed = [
        {"id": rid, "fields": [field for field in FIELDS if expected[rid][field] != observed[rid][field]]}
        for rid in sorted(set(expected) & set(observed))
    ]
    changed = [item for item in changed if item["fields"]]
    version_mismatch = reference["source_version"] != runtime["source_version"]
    return {
        "schema": "continuityos.ruap_lines_comparison_receipt/v1",
        "status": "DIFF" if missing or unexpected or changed or version_mismatch else "FIELD_MATCH_UNATTESTED",
        "reference_count": len(expected),
        "runtime_count": len(observed),
        "reference_source_version": reference["source_version"],
        "runtime_source_version": runtime["source_version"],
        "version_mismatch": version_mismatch,
        "missing_runtime_ids": missing,
        "unexpected_runtime_ids": unexpected,
        "changed_fields": changed,
        "canonical_authority_promoted": False,
        "read_only": True,
        "owner_attestation_verified": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Offline RUAP EVIDENCE_ONLY: two JSON exports")
    parser.add_argument("--reference", required=True)
    parser.add_argument("--runtime", required=True)
    args = parser.parse_args()
    report = compare(load_export(args.reference, reference=True), load_export(args.runtime, reference=False))
    print(json.dumps(report, sort_keys=True, ensure_ascii=False, separators=(",", ":")))


if __name__ == "__main__":
    main()
