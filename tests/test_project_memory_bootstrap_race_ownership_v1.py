from __future__ import annotations

import hashlib
import json
from pathlib import Path

import continuityos.current_effect_boundary as boundary
import continuityos.project_memory_bootstrap as boot
from continuityos.operational_memory import OperationalMemory


def _write_json(path: Path, value) -> str:
    payload = (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    path.write_bytes(payload)
    return hashlib.sha256(payload).hexdigest()


def test_matching_competitor_that_wins_publish_race_is_never_deleted(monkeypatch, tmp_path):
    for name in (
        boundary.ENV_CHALLENGE,
        boundary.ENV_CHALLENGE_SHA,
        boundary.ENV_ACK,
        boundary.ENV_REQUIRED,
    ):
        monkeypatch.delenv(name, raising=False)

    evidence_path = tmp_path / "evidence.json"
    evidence_sha = _write_json(evidence_path, {"status": "PASS", "kind": "race-ownership"})
    target = tmp_path / "project.db"
    manifest = {
        "schema": boot.MANIFEST_SCHEMA,
        "project_id": "project:race-ownership",
        "evidence": [{
            "evidence_id": "proof",
            "sha256": evidence_sha,
            "locator": str(evidence_path),
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
        "project_id": manifest["project_id"],
        "target_db": str(target.absolute()),
        "claim_count": 1,
        "proposed_decision_count": 0,
        "authority_class": "DETERMINISTIC_CONTROLLER",
        "authority_id": "R38_RACE_TEST",
        "authority_ref": "test://r38/race-ownership",
        "bootstrap_recorded_at": "2026-08-09T11:00:00Z",
        "rationale": "prove no-clobber rollback ownership",
    }
    authorization_path = tmp_path / "authorization.json"
    _write_json(authorization_path, authorization)

    def matching_competitor_wins(src, dst, **kwargs):
        # Simulate another process publishing an independently owned but byte-identical,
        # fully valid bootstrap DB immediately before this call's atomic link attempt.
        Path(dst).write_bytes(Path(src).read_bytes())
        raise FileExistsError("matching competitor won no-clobber race")

    monkeypatch.setattr(boot.os, "link", matching_competitor_wins)
    result = boot.bootstrap_project_memory(target, manifest_path, authorization_path)

    assert result["terminal"] == "PROJECT_MEMORY_BOOTSTRAP_REVISE"
    assert result["reason"] == "BOOTSTRAP_PUBLISH_ROLLED_BACK"
    assert target.is_file(), "failed publisher deleted a competing valid target"
    with OperationalMemory(str(target), read_only=True) as memory:
        assert memory.verify()["ok"] is True
        assert memory.con.execute(
            "SELECT COUNT(*) FROM events WHERE event_type='PROJECT_MEMORY_BOOTSTRAPPED'"
        ).fetchone()[0] == 1
