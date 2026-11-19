"""Bounded, offline RUAP line-registry evidence comparator (no database access).

Inputs are two *separately authorized* JSON exports. Never fetches sources,
contacts a server, changes a file, or promotes a record to canonical authority.
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

from ._offline_path_guard import read_bounded_file

SCHEMA = "continuityos.ruap_lines_evidence/v1"
FIELDS = ("line", "executor_chat", "bucket", "current_state", "next_turn", "evidence", "updated_at")
MAX_BYTES = 131_072
EXPECTED_REFERENCE_IDS = frozenset(range(1, 17))
# Source versions are public identifiers, never arbitrary source-provided text.
_VERSION_RE = re.compile(r"R[0-9]{1,4}(?:\.[0-9]{1,3})?(?:/R[0-9]{1,4}(?:\.[0-9]{1,3})?)?\Z")


def _safe_version(value: Any) -> str:
    if not isinstance(value, str) or not _VERSION_RE.fullmatch(value):
        raise ValueError("SOURCE_VERSION_INVALID")
    return value



def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for name, value in pairs:
        if name in result:
            raise ValueError("DUPLICATE_FIELD")
        result[name] = value
    return result


def load_export(path: str, *, reference: bool) -> dict[str, Any]:
    try:
        raw = read_bounded_file(Path(path), MAX_BYTES)
    except ValueError as exc:
        if str(exc) == "OFFLINE_FILE_TOO_LARGE":
            raise ValueError("EXPORT_TOO_LARGE") from None
        raise ValueError("EXPORT_NOT_REGULAR_FILE") from None
    try:
        obj = json.loads(raw.decode("utf-8-sig"), object_pairs_hook=_unique)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("INVALID_EXPORT_JSON") from exc
    if not isinstance(obj, dict) or obj.get("schema") != SCHEMA:
        raise ValueError("EXPORT_SCHEMA_MISMATCH")
    records = obj.get("records")
    if not isinstance(records, list) or len(records) > 64:
        raise ValueError("EXPORT_RECORDS_INVALID")
    version = _safe_version(obj.get("source_version"))
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
    return {"source_version": version, "records": mapped}


def compare(reference: dict[str, Any], runtime: dict[str, Any]) -> dict[str, Any]:
    # Also enforce the boundary for direct in-process callers.
    ref_version = _safe_version(reference.get("source_version"))
    run_version = _safe_version(runtime.get("source_version"))
    expected, observed = reference["records"], runtime["records"]
    missing = sorted(set(expected) - set(observed))
    unexpected = sorted(set(observed) - set(expected))
    changed = [
        {"id": rid, "fields": [field for field in FIELDS if expected[rid][field] != observed[rid][field]]}
        for rid in sorted(set(expected) & set(observed))
    ]
    changed = [item for item in changed if item["fields"]]
    version_mismatch = ref_version != run_version
    return {
        "schema": "continuityos.ruap_lines_comparison_receipt/v1",
        "status": "DIFF" if missing or unexpected or changed or version_mismatch else "FIELD_MATCH_UNATTESTED",
        "reference_count": len(expected),
        "runtime_count": len(observed),
        "reference_source_version": ref_version,
        "runtime_source_version": run_version,
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
