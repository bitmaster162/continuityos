from __future__ import annotations

import hashlib
import json

import continuityos.current_effect_boundary as boundary
import continuityos.project_memory_bootstrap as boot


def _write_json(path, value):
    payload = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    path.write_text(payload, encoding="utf-8")
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def test_minimal_valid_bootstrap_is_portable(monkeypatch, tmp_path):
    for name in (
        boundary.ENV_CHALLENGE,
        boundary.ENV_CHALLENGE_SHA,
        boundary.ENV_ACK,
        boundary.ENV_REQUIRED,
    ):
        monkeypatch.delenv(name, raising=False)

    evidence = tmp_path / "evidence.json"
    evidence_sha = _write_json(evidence, {"status": "PASS", "kind": "portable"})
    target = tmp_path / "project.db"
    manifest = {
        "schema": boot.MANIFEST_SCHEMA,
        "project_id": "project:portable",
        "evidence": [{
            "evidence_id": "proof",
            "sha256": evidence_sha,
            "locator": str(evidence),
        }],
        "claims": [{
            "predicate": "project.status",
            "scope": "global",
            "value": {"state": "BOOTSTRAPPED"},
            "evidence_state": "VERIFIED",
            "evidence_ids": ["proof"],
            "valid_from": "2026-08-09T10:00:00Z",
            "recorded_at": "2026-08-09T10:00:00Z",
        }],
        "proposed_decisions": [],
    }
    manifest_path = tmp_path / "manifest.json"
    manifest_sha = _write_json(manifest_path, manifest)
    authorization = {
        "schema": boot.AUTH_SCHEMA,
        "decision": boot.AUTH_DECISION,
        "manifest_file_sha256": manifest_sha,
        "project_id": "project:portable",
        "target_db": str(target.absolute()),
        "claim_count": 1,
        "proposed_decision_count": 0,
        "authority_class": "DETERMINISTIC_CONTROLLER",
        "authority_id": "PORTABILITY_TEST",
        "authority_ref": "test://portable",
        "bootstrap_recorded_at": "2026-08-09T11:00:00Z",
        "rationale": "cross-platform bootstrap smoke test",
    }
    authorization_path = tmp_path / "authorization.json"
    _write_json(authorization_path, authorization)

    result = boot.bootstrap_project_memory(target, manifest_path, authorization_path)

    diagnostic = "DIAG=" + " | ".join(str(item) for item in result.get("errors", []))
    assert result["terminal"] == "PROJECT_MEMORY_BOOTSTRAP_PASS", diagnostic
    assert target.is_file(), diagnostic
