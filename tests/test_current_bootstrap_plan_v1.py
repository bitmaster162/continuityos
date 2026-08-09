from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from continuityos.current_bootstrap_plan import REQUEST_SCHEMA, build_bootstrap_plan
from continuityos.project_memory_bootstrap import MANIFEST_SCHEMA, _validate_manifest

PROJECT = "project:continuityos"


def _write_bytes(path: Path, payload: bytes) -> str:
    path.write_bytes(payload)
    return hashlib.sha256(payload).hexdigest()


def _request(tmp_path: Path):
    evidence = tmp_path / "merge.json"
    evidence_sha = _write_bytes(evidence, b'{"merge":"a0d117","status":"PASS"}\n')
    request = {
        "schema": REQUEST_SCHEMA,
        "project_id": PROJECT,
        "evidence": [{
            "evidence_id": "merge",
            "locator": str(evidence),
            "kind": "GITHUB_PROVIDER_READBACK",
            "scope": PROJECT,
        }],
        "claims": [{
            "predicate": "project.status",
            "scope": "global",
            "value": {"frontier": "a0d117", "state": "ACTIVE"},
            "evidence_state": "VERIFIED",
            "evidence_ids": ["merge"],
            "valid_from": "2026-08-09T18:00:00Z",
            "recorded_at": "2026-08-09T18:00:00Z",
        }],
        "proposed_decisions": [{
            "decision_type": "NEXT_ACTION",
            "value": {"action": "review next bounded step", "priority": 80},
            "rationale": "proposal only",
            "evidence_ids": ["merge"],
            "recorded_at": "2026-08-09T18:01:00Z",
        }],
        "rationale": "compile exact bootstrap bytes without applying them",
    }
    return request, evidence, evidence_sha


def test_compiler_rehashes_exact_evidence_and_emits_r38_valid_manifest(tmp_path):
    request, evidence, evidence_sha = _request(tmp_path)
    before = evidence.read_bytes()

    result = build_bootstrap_plan(request)

    assert result["terminal"] == "CURRENT_BOOTSTRAP_PLAN_PASS"
    assert result["manifest"]["schema"] == MANIFEST_SCHEMA
    assert result["manifest"]["evidence"][0]["sha256"] == evidence_sha
    assert result["evidence"][0]["size_bytes"] == len(before)
    assert evidence.read_bytes() == before
    assert _validate_manifest(result["manifest"])["project_id"] == PROJECT
    assert result["semantic_assertions_accepted"] is False
    assert result["apply_status"] == "NOT_APPLIED"
    assert result["execution_authorized"] is False
    assert result["effects"]["filesystem_write"] is False
    assert result["effects"]["operational_memory_write"] is False


def test_manifest_file_sha_binds_exact_emitted_canonical_bytes(tmp_path):
    request, _, _ = _request(tmp_path)

    first = build_bootstrap_plan(request)
    second = build_bootstrap_plan(request)

    assert first == second
    raw = first["manifest_canonical_json"].encode("utf-8")
    assert hashlib.sha256(raw).hexdigest() == first["manifest_file_sha256"]
    assert len(raw) == first["manifest_file_size_bytes"]
    assert json.loads(raw) == first["manifest"]
    assert first["authorization_requirements"]["must_bind_exact_manifest_file_sha256"] == first["manifest_file_sha256"]


def test_compiler_hashes_actual_bytes_not_text_normalization(tmp_path):
    request, evidence, _ = _request(tmp_path)
    evidence.write_bytes(b"line1\r\nline2\r\n")

    result = build_bootstrap_plan(request)

    assert result["terminal"] == "CURRENT_BOOTSTRAP_PLAN_PASS"
    assert result["manifest"]["evidence"][0]["sha256"] == hashlib.sha256(b"line1\r\nline2\r\n").hexdigest()


def test_duplicate_evidence_id_revises_fail_closed(tmp_path):
    request, _, _ = _request(tmp_path)
    request["evidence"].append(dict(request["evidence"][0]))

    result = build_bootstrap_plan(request)

    assert result["terminal"] == "CURRENT_BOOTSTRAP_PLAN_REVISE"
    assert any("duplicate evidence_id" in item for item in result["errors"])
    assert result["manifest"] is None
    assert result["execution_authorized"] is False


def test_r38_manifest_rules_are_reused_not_weakened(tmp_path):
    request, _, _ = _request(tmp_path)
    request["proposed_decisions"][0]["state"] = "ACCEPTED"

    result = build_bootstrap_plan(request)

    assert result["terminal"] == "CURRENT_BOOTSTRAP_PLAN_REVISE"
    assert any("extra=['state']" in item for item in result["errors"])
    assert result["semantic_assertions_accepted"] is False


@pytest.mark.skipif(not hasattr(Path, "symlink_to"), reason="symlink support unavailable")
def test_symlink_evidence_is_refused(tmp_path):
    request, evidence, _ = _request(tmp_path)
    link = tmp_path / "link.json"
    try:
        link.symlink_to(evidence)
    except OSError:
        pytest.skip("symlink creation unavailable")
    request["evidence"][0]["locator"] = str(link)

    result = build_bootstrap_plan(request)

    assert result["terminal"] == "CURRENT_BOOTSTRAP_PLAN_REVISE"
    assert any("symlink/reparse refused" in item for item in result["errors"])
