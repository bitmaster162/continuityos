from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

import continuityos.current_effect_boundary as boundary
import continuityos.project_memory_bootstrap as boot
from continuityos.current_work import compile_project_work
from continuityos.operational_memory import OperationalMemory

PROJECT = "project:continuityos"


def write_json(path: Path, value) -> str:
    payload = (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    path.write_bytes(payload)
    return hashlib.sha256(payload).hexdigest()


def evidence(tmp_path: Path, name="evidence.json"):
    path = tmp_path / name
    sha = write_json(path, {"kind": "provider-readback", "status": "PASS", "commit": "abc123"})
    return path, sha


def manifest(tmp_path: Path, *, duplicate=False, terminal_extra=False):
    ev, sha = evidence(tmp_path)
    claims = [
        {
            "predicate": "project.goal",
            "scope": "global",
            "value": "reconstruct project memory from evidence",
            "evidence_state": "VERIFIED",
            "evidence_ids": ["merge"],
            "valid_from": "2026-08-09T10:00:00Z",
            "recorded_at": "2026-08-09T10:00:00Z",
        },
        {
            "predicate": "project.status",
            "scope": "global",
            "value": {"state": "BOOTSTRAPPED", "frontier": "abc123"},
            "evidence_state": "VERIFIED",
            "evidence_ids": ["merge"],
            "valid_from": "2026-08-09T10:01:00Z",
            "recorded_at": "2026-08-09T10:01:00Z",
        },
        {
            "predicate": "project.open_loop",
            "scope": "next",
            "value": {
                "id": "next",
                "title": "Next product step",
                "status": "OPEN",
                "next_action": "run next bounded step",
                "priority": 80,
                "blocked_by": [],
            },
            "evidence_state": "INFERENCE",
            "evidence_ids": ["merge"],
            "valid_from": "2026-08-09T10:02:00Z",
            "recorded_at": "2026-08-09T10:02:00Z",
        },
    ]
    if duplicate:
        claims.append(dict(claims[0]))
    decision = {
        "decision_type": "NEXT_ACTION",
        "value": {"action": "review bootstrap output", "priority": 90},
        "rationale": "proposal only",
        "evidence_ids": ["merge"],
        "recorded_at": "2026-08-09T10:03:00Z",
    }
    if terminal_extra:
        decision["state"] = "ACCEPTED"
    value = {
        "schema": boot.MANIFEST_SCHEMA,
        "project_id": PROJECT,
        "evidence": [{
            "evidence_id": "merge",
            "sha256": sha,
            "locator": str(ev),
            "kind": "MERGE_EVIDENCE",
            "scope": PROJECT,
        }],
        "claims": claims,
        "proposed_decisions": [decision],
        "rationale": "deterministic fresh project bootstrap",
    }
    path = tmp_path / "manifest.json"
    write_json(path, value)
    return value, path, ev


def authorization(tmp_path: Path, manifest_value, manifest_path: Path, target: Path):
    auth = {
        "schema": boot.AUTH_SCHEMA,
        "decision": boot.AUTH_DECISION,
        "manifest_file_sha256": hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
        "project_id": manifest_value["project_id"],
        "target_db": str(target.absolute()),
        "claim_count": len(manifest_value["claims"]),
        "proposed_decision_count": len(manifest_value["proposed_decisions"]),
        "authority_class": "DETERMINISTIC_CONTROLLER",
        "authority_id": "R38_TEST_CONTROLLER",
        "authority_ref": "ephemeral://r38/bootstrap-test",
        "bootstrap_recorded_at": "2026-08-09T11:00:00Z",
        "rationale": "ephemeral bootstrap test",
    }
    path = tmp_path / "authorization.json"
    write_json(path, auth)
    return auth, path


def set_current(monkeypatch):
    monkeypatch.setenv(boundary.ENV_CHALLENGE, "challenge.json")
    monkeypatch.setenv(boundary.ENV_CHALLENGE_SHA, "a" * 64)
    monkeypatch.setenv(boundary.ENV_ACK, "ack.json")
    monkeypatch.setenv(boundary.ENV_REQUIRED, "1")
    monkeypatch.setattr(
        boundary,
        "verify_current_runtime_binding",
        lambda *args, **kwargs: {
            "terminal": "CURRENT_RUNTIME_BINDING_PASS",
            "binding_verified": True,
            "authority_generation": "R64",
            "challenge_id": "b" * 64,
            "challenge_sha256": "a" * 64,
            "ack_sha256": "c" * 64,
        },
    )


def clear_current(monkeypatch):
    for name in (boundary.ENV_CHALLENGE, boundary.ENV_CHALLENGE_SHA, boundary.ENV_ACK, boundary.ENV_REQUIRED):
        monkeypatch.delenv(name, raising=False)


def snapshot(path: Path):
    with OperationalMemory(str(path), read_only=True) as memory:
        verification = memory.verify()
        assert verification["ok"] is True
        projection = memory.projection()
        counts = {
            "events": memory.con.execute("SELECT COUNT(*) FROM events").fetchone()[0],
            "claims": memory.con.execute("SELECT COUNT(*) FROM claims").fetchone()[0],
            "decisions": memory.con.execute("SELECT COUNT(*) FROM decisions").fetchone()[0],
            "bootstrap_events": memory.con.execute(
                "SELECT COUNT(*) FROM events WHERE event_type='PROJECT_MEMORY_BOOTSTRAPPED'"
            ).fetchone()[0],
        }
    return projection, counts


def test_fresh_bootstrap_rehashes_evidence_and_publishes_verified_project(monkeypatch, tmp_path):
    clear_current(monkeypatch)
    value, mpath, _ = manifest(tmp_path)
    target = tmp_path / "project.db"
    _, apath = authorization(tmp_path, value, mpath, target)

    result = boot.bootstrap_project_memory(target, mpath, apath)

    assert result["terminal"] == "PROJECT_MEMORY_BOOTSTRAP_PASS"
    assert result["shadow_memory_bootstrap"] == "CREATED"
    assert result["claims_created"] == 3
    assert result["proposed_decisions_created"] == 1
    assert result["accepted_truth_modified"] is False
    assert result["effects"]["canonical_mutation"] is False
    assert result["can_trade"] is False
    assert result["capital_permission"] == "DENY"
    assert target.is_file()
    projection, counts = snapshot(target)
    assert counts == {"events": 5, "claims": 3, "decisions": 1, "bootstrap_events": 1}
    assert all(row["state"] == "PROPOSED" for row in projection["decisions"])
    work = compile_project_work(projection, PROJECT)
    assert work["terminal"] == "CURRENT_WORK_PASS"
    assert work["next_action"]["action"] == "review bootstrap output"
    assert work["next_action"]["authority_status"] == "PROPOSED_DECISION"
    assert work["execution_authorized"] is False


def test_current_session_holds_before_target_creation(monkeypatch, tmp_path):
    value, mpath, _ = manifest(tmp_path)
    target = tmp_path / "project.db"
    _, apath = authorization(tmp_path, value, mpath, target)
    set_current(monkeypatch)

    result = boot.bootstrap_project_memory(target, mpath, apath)

    assert result["terminal"] == "PROJECT_MEMORY_BOOTSTRAP_HOLD"
    assert result["reason"] == "CURRENT_SESSION_EFFECT_FORBIDDEN"
    assert not target.exists()
    assert list(tmp_path.glob(f".{target.name}.bootstrap-*")) == []


def test_evidence_sha_mismatch_fails_before_target_creation(monkeypatch, tmp_path):
    clear_current(monkeypatch)
    value, mpath, ev = manifest(tmp_path)
    # Modify evidence after the manifest binds it.
    ev.write_text("changed\n", encoding="utf-8")
    target = tmp_path / "project.db"
    _, apath = authorization(tmp_path, value, mpath, target)

    result = boot.bootstrap_project_memory(target, mpath, apath)

    assert result["terminal"] == "PROJECT_MEMORY_BOOTSTRAP_REVISE"
    assert result["reason"] == "BOOTSTRAP_ARTIFACT_INVALID"
    assert any("evidence SHA mismatch" in item for item in result["errors"])
    assert not target.exists()


def test_duplicate_claim_identity_is_rejected(monkeypatch, tmp_path):
    clear_current(monkeypatch)
    value, mpath, _ = manifest(tmp_path, duplicate=True)
    target = tmp_path / "project.db"
    _, apath = authorization(tmp_path, value, mpath, target)

    result = boot.bootstrap_project_memory(target, mpath, apath)

    assert result["terminal"] == "PROJECT_MEMORY_BOOTSTRAP_REVISE"
    assert any("duplicate bootstrap claim identity" in item for item in result["errors"])
    assert not target.exists()


def test_manifest_cannot_smuggle_terminal_decision_state(monkeypatch, tmp_path):
    clear_current(monkeypatch)
    value, mpath, _ = manifest(tmp_path, terminal_extra=True)
    target = tmp_path / "project.db"
    _, apath = authorization(tmp_path, value, mpath, target)

    result = boot.bootstrap_project_memory(target, mpath, apath)

    assert result["terminal"] == "PROJECT_MEMORY_BOOTSTRAP_REVISE"
    assert any("extra=['state']" in item for item in result["errors"])
    assert not target.exists()


def test_existing_unrelated_target_is_never_overwritten(monkeypatch, tmp_path):
    clear_current(monkeypatch)
    value, mpath, _ = manifest(tmp_path)
    target = tmp_path / "project.db"
    target.write_bytes(b"SENTINEL")
    before = target.read_bytes()
    _, apath = authorization(tmp_path, value, mpath, target)

    result = boot.bootstrap_project_memory(target, mpath, apath)

    assert result["terminal"] == "PROJECT_MEMORY_BOOTSTRAP_REVISE"
    assert result["reason"] == "TARGET_ALREADY_EXISTS"
    assert target.read_bytes() == before


def test_exact_replay_is_idempotent_and_does_not_change_db(monkeypatch, tmp_path):
    clear_current(monkeypatch)
    value, mpath, _ = manifest(tmp_path)
    target = tmp_path / "project.db"
    _, apath = authorization(tmp_path, value, mpath, target)
    first = boot.bootstrap_project_memory(target, mpath, apath)
    assert first["terminal"] == "PROJECT_MEMORY_BOOTSTRAP_PASS"
    before_bytes = target.read_bytes()
    before = snapshot(target)

    second = boot.bootstrap_project_memory(target, mpath, apath)

    assert second["terminal"] == "PROJECT_MEMORY_BOOTSTRAP_ALREADY_CREATED"
    assert target.read_bytes() == before_bytes
    assert snapshot(target) == before


def test_mid_bootstrap_failure_leaves_no_target_or_temp(monkeypatch, tmp_path):
    clear_current(monkeypatch)
    value, mpath, _ = manifest(tmp_path)
    target = tmp_path / "project.db"
    _, apath = authorization(tmp_path, value, mpath, target)
    original = boot.OperationalMemory.record_claim
    calls = {"count": 0}

    def fail_second(self, **kwargs):
        calls["count"] += 1
        if calls["count"] == 2:
            raise RuntimeError("forced bootstrap failure")
        return original(self, **kwargs)

    monkeypatch.setattr(boot.OperationalMemory, "record_claim", fail_second)
    result = boot.bootstrap_project_memory(target, mpath, apath)

    assert result["terminal"] == "PROJECT_MEMORY_BOOTSTRAP_REVISE"
    assert result["reason"] == "BOOTSTRAP_PUBLISH_ROLLED_BACK"
    assert not target.exists()
    assert list(tmp_path.glob(f".{target.name}.bootstrap-*")) == []


def test_publish_race_does_not_clobber_competing_target(monkeypatch, tmp_path):
    clear_current(monkeypatch)
    value, mpath, _ = manifest(tmp_path)
    target = tmp_path / "project.db"
    _, apath = authorization(tmp_path, value, mpath, target)
    real_link = boot.os.link

    def race_link(src, dst, **kwargs):
        Path(dst).write_bytes(b"COMPETITOR")
        raise FileExistsError("forced no-clobber race")

    monkeypatch.setattr(boot.os, "link", race_link)
    result = boot.bootstrap_project_memory(target, mpath, apath)

    assert result["terminal"] == "PROJECT_MEMORY_BOOTSTRAP_REVISE"
    assert result["reason"] == "BOOTSTRAP_PUBLISH_ROLLED_BACK"
    assert target.read_bytes() == b"COMPETITOR"
    assert list(tmp_path.glob(f".{target.name}.bootstrap-*")) == []
