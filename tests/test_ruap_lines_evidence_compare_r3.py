"""Synthetic EVIDENCE_ONLY reconciliation; no owner DB, provider or client."""
import json
from pathlib import Path

import pytest

from continuityos.ruap_lines_evidence_compare_r3 import SCHEMA, FIELDS, load_export, compare


def _entries():
    return [
        {"id": i, **{field: f"{field}_{i}" for field in FIELDS}}
        for i in range(1, 17)
    ]


def _write(path: Path, records, version="R6.2"):
    path.write_text(json.dumps({"schema": SCHEMA, "source_version": version,
                                "records": records}, ensure_ascii=False),
                    encoding="utf-8")


def test_equal_evidence_is_not_promoted_to_authority(tmp_path):
    reference, runtime = tmp_path / "a.json", tmp_path / "b.json"
    _write(reference, _entries())
    _write(runtime, _entries())
    before = [(p.stat().st_size, p.stat().st_mtime_ns) for p in (reference, runtime)]
    result = compare(load_export(str(reference), reference=True),
                     load_export(str(runtime), reference=False))
    assert result["status"] == "FIELD_MATCH_UNATTESTED"
    assert result["reference_count"] == result["runtime_count"] == 16
    assert result["owner_attestation_verified"] is False
    assert result["canonical_authority_promoted"] is False
    assert before == [(p.stat().st_size, p.stat().st_mtime_ns) for p in (reference, runtime)]


def test_exact_id_and_field_discrepancy(tmp_path):
    reference, runtime = tmp_path / "a.json", tmp_path / "b.json"
    _write(reference, _entries())
    changed = _entries()
    changed.pop(3)
    changed[0]["next_turn"] = "changed"
    changed.append({"id": 17, **{field: "extra" for field in FIELDS}})
    _write(runtime, changed, version="R6.1")
    result = compare(load_export(str(reference), reference=True),
                     load_export(str(runtime), reference=False))
    assert result["status"] == "DIFF"
    assert result["missing_runtime_ids"] == [4]
    assert result["unexpected_runtime_ids"] == [17]
    assert result["changed_fields"] == [{"id": 1, "fields": ["next_turn"]}]
    assert result["version_mismatch"] is True
    assert '"changed"' not in json.dumps(result)
    assert '"extra"' not in json.dumps(result)


def test_reference_requires_all_16(tmp_path):
    path = tmp_path / "a.json"
    _write(path, _entries()[:15])
    with pytest.raises(ValueError, match="16_LINES"):
        load_export(str(path), reference=True)


def test_duplicate_ids_and_keys_fail_closed(tmp_path):
    path = tmp_path / "a.json"
    records = _entries()
    records[1]["id"] = 1
    _write(path, records)
    with pytest.raises(ValueError, match="DUPLICATE"):
        load_export(str(path), reference=False)
    path.write_text('{"schema":"a","schema":"b"}', encoding="utf-8")
    with pytest.raises(ValueError, match="DUPLICATE_FIELD"):
        load_export(str(path), reference=False)


def test_oversized_export_fails_closed(tmp_path):
    path = tmp_path / "a.json"
    path.write_bytes(b"x" * 131_073)
    with pytest.raises(ValueError, match="TOO_LARGE"):
        load_export(str(path), reference=False)


def test_no_runtime_source_does_not_become_complete(tmp_path):
    path = tmp_path / "missing.json"
    with pytest.raises(ValueError, match="NOT_REGULAR"):
        load_export(str(path), reference=False)



@pytest.mark.parametrize("bad_version", [
    "R6.2_SYNTHETIC_PRIVATE_TOKEN",
    "C:/SYNTHETIC_PRIVATE_PATH",
    "R6.2\\nSECRET",
    "R6.2\\r\\nSTATUS=COMPLETE",
    "R6.2" + "A" * 256,
    "",
    "R6.2\\\\windows",
])
def test_ruap_rejects_untrusted_source_version(tmp_path, bad_version):
    from continuityos.ruap_lines_evidence_compare_r3 import load_export
    path = tmp_path / "export.json"
    _write(path, _entries(), version=bad_version)
    with pytest.raises(ValueError, match="SOURCE_VERSION_INVALID"):
        load_export(str(path), reference=True)


def test_direct_compare_cannot_echo_source_version_secret():
    from continuityos.ruap_lines_evidence_compare_r3 import compare
    dirty = {"source_version": "R6.2_SENSITIVE_SECRET", "records": {}}
    clean = {"source_version": "R6.2", "records": {}}
    with pytest.raises(ValueError, match="SOURCE_VERSION_INVALID"):
        compare(dirty, clean)


def test_ruap_parent_junction_export_denied(tmp_path):
    import subprocess
    import sys
    import os
    if sys.platform != "win32":
        pytest.skip("Windows junction test")
    outside = tmp_path / "outside"
    outside.mkdir()
    _write(outside / "data.json", _entries())
    junction = tmp_path / "junction"
    result = subprocess.run(
        ["cmd", "/d", "/c", "mklink", "/J", str(junction), str(outside)],
        capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    try:
        with pytest.raises(ValueError, match="NOT_REGULAR"):
            load_export(str(junction / "data.json"), reference=True)
    finally:
        os.rmdir(junction)



@pytest.mark.parametrize("version", ["R6.2", "R4/R6.2", "R270", "R271"])
def test_ruap_accepts_bounded_public_version_identifiers(tmp_path, version):
    path = tmp_path / "validated.json"
    _write(path, _entries(), version=version)
    assert load_export(str(path), reference=True)["source_version"] == version
