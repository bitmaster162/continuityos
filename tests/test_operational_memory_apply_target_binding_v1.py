from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil

import pytest

from continuityos.current_memory_delta import REQUEST_SCHEMA, build_memory_delta_proposal_from_db
from continuityos.operational_memory import OperationalMemory
import continuityos.current_memory_apply_auth_request as authreq
import continuityos.current_memory_apply_check as checkmod
import continuityos.operational_memory_apply as applymod

PROJECT = "project:r51-target-binding"
REF = {"sha256": "b" * 64, "locator": "evidence://r51/target-binding"}


def write_json(path: Path, value) -> str:
    payload = (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    path.write_bytes(payload)
    return hashlib.sha256(payload).hexdigest()


def seed_db(path: Path):
    with OperationalMemory(str(path)) as memory:
        memory.record_claim(
            subject_id=PROJECT,
            predicate="project.status",
            scope="global",
            value={"state": "OLD"},
            evidence_state="VERIFIED",
            evidence_refs=[REF],
            actor_type="DETERMINISTIC_CONTROLLER",
            actor_id="r51-seed",
            valid_from="2026-08-10T05:00:00Z",
            recorded_at="2026-08-10T05:00:00Z",
        )
        assert memory.verify()["ok"] is True
        projection = memory.projection()
    row = [
        item for item in projection["claims"]
        if item["subject_id"] == PROJECT and item["predicate"] == "project.status"
    ][0]
    return projection, row


def proposal_file(db: Path, tmp_path: Path):
    before, status = seed_db(db)
    proposal = build_memory_delta_proposal_from_db(
        db,
        {
            "schema": REQUEST_SCHEMA,
            "project_id": PROJECT,
            "operations": [{
                "op": "SUPERSEDE_CLAIM",
                "supersedes_id": status["claim_id"],
                "value": {"state": "NEW"},
                "evidence_state": "VERIFIED",
                "evidence_refs": [REF],
                "valid_from": "2026-08-10T08:00:00Z",
            }],
            "rationale": "R51 target-binding regression",
        },
    )
    assert proposal["terminal"] == "CURRENT_MEMORY_DELTA_PROPOSAL_PASS"
    assert proposal["operational_memory"]["path"] == str(db.absolute())
    path = tmp_path / "proposal.json"
    write_json(path, proposal)
    return before, proposal, path


def auth_file(proposal, proposal_path: Path, tmp_path: Path):
    auth = {
        "schema": applymod.AUTH_SCHEMA,
        "decision": applymod.AUTH_DECISION,
        "proposal_id": proposal["proposal_id"],
        "proposal_file_sha256": hashlib.sha256(proposal_path.read_bytes()).hexdigest(),
        "project_id": proposal["project_id"],
        "base_projection_sha256": proposal["base"]["projection_sha256"],
        "base_event_cursor": proposal["base"]["event_cursor"],
        "base_event_chain_head": proposal["base"]["event_chain_head"],
        "operation_count": len(proposal["operations"]),
        "authority_class": "DETERMINISTIC_CONTROLLER",
        "authority_id": "R51_TEST_CONTROLLER",
        "authority_ref": "ephemeral://r51/target-binding",
        "apply_recorded_at": "2026-08-10T08:50:00Z",
        "rationale": "authorize exact target-bound proposal",
    }
    path = tmp_path / "authorization.json"
    write_json(path, auth)
    return auth, path


def current_status(path: Path):
    with OperationalMemory(str(path), read_only=True) as memory:
        assert memory.verify()["ok"] is True
        projection = memory.projection()
    row = [
        item for item in projection["claims"]
        if item["subject_id"] == PROJECT and item["predicate"] == "project.status"
    ][0]
    return row["value"]


def test_same_authorization_cannot_apply_to_byte_identical_clone(tmp_path):
    source = tmp_path / "source.db"
    _, proposal, proposal_path = proposal_file(source, tmp_path)
    clone = tmp_path / "clone.db"
    shutil.copy2(source, clone)
    assert source.read_bytes() == clone.read_bytes()
    _, auth_path = auth_file(proposal, proposal_path, tmp_path)
    clone_before = clone.read_bytes()

    first = applymod.apply_authorized_memory_delta(source, proposal_path, auth_path)
    second = applymod.apply_authorized_memory_delta(clone, proposal_path, auth_path)

    assert first["terminal"] == "CURRENT_MEMORY_APPLY_PASS"
    assert second["terminal"] == "CURRENT_MEMORY_APPLY_REVISE"
    assert second["reason"] == "OPERATIONAL_MEMORY_TARGET_MISMATCH"
    assert source.read_bytes() != clone_before
    assert clone.read_bytes() == clone_before
    assert current_status(source) == {"state": "NEW"}
    assert current_status(clone) == {"state": "OLD"}


def test_r44_preflight_never_reports_ready_for_identical_wrong_clone(tmp_path):
    source = tmp_path / "source.db"
    _, proposal, proposal_path = proposal_file(source, tmp_path)
    clone = tmp_path / "clone.db"
    shutil.copy2(source, clone)
    _, auth_path = auth_file(proposal, proposal_path, tmp_path)
    before = clone.read_bytes()

    result = checkmod.check_authorized_memory_delta(clone, proposal_path, auth_path)

    assert result["terminal"] == "CURRENT_MEMORY_APPLY_CHECK_REVISE"
    assert result["reason"] == "OPERATIONAL_MEMORY_TARGET_MISMATCH"
    assert result["apply_ready"] is False
    assert clone.read_bytes() == before


def test_r45_review_packet_rejects_wrong_clone_target(tmp_path):
    source = tmp_path / "source.db"
    _, proposal, proposal_path = proposal_file(source, tmp_path)
    clone = tmp_path / "clone.db"
    shutil.copy2(source, clone)
    before = clone.read_bytes()

    result = authreq.build_apply_authorization_request(clone, proposal_path)

    assert result["terminal"] == "CURRENT_MEMORY_APPLY_AUTH_REQUEST_REVISE"
    assert result["reason"] == "OPERATIONAL_MEMORY_TARGET_MISMATCH"
    assert result["authorization_granted"] is False
    assert clone.read_bytes() == before


def test_effectful_apply_rejects_proposal_without_db_target_binding(tmp_path):
    db = tmp_path / "memory.db"
    _, proposal, _ = proposal_file(db, tmp_path)
    proposal.pop("operational_memory")
    proposal_path = tmp_path / "unbound-proposal.json"
    write_json(proposal_path, proposal)
    _, auth_path = auth_file(proposal, proposal_path, tmp_path)
    before = db.read_bytes()

    result = applymod.apply_authorized_memory_delta(db, proposal_path, auth_path)

    assert result["terminal"] == "CURRENT_MEMORY_APPLY_REVISE"
    assert result["reason"] == "OPERATIONAL_MEMORY_TARGET_UNBOUND"
    assert db.read_bytes() == before


def test_symlink_alias_to_correct_db_is_not_an_authorized_target(tmp_path):
    db = tmp_path / "memory.db"
    _, proposal, proposal_path = proposal_file(db, tmp_path)
    _, auth_path = auth_file(proposal, proposal_path, tmp_path)
    alias_dir = tmp_path / "alias-dir"
    real_dir = tmp_path / "real-dir"
    real_dir.mkdir()
    real_db = real_dir / "memory.db"
    shutil.copy2(db, real_db)
    try:
        alias_dir.symlink_to(real_dir, target_is_directory=True)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"directory symlink unavailable: {exc}")
    # Build a separate proposal bound to the real DB, then call via the alias.
    with OperationalMemory(str(real_db), read_only=True) as memory:
        projection = memory.projection()
    status = [item for item in projection["claims"] if item["predicate"] == "project.status"][0]
    real_proposal = build_memory_delta_proposal_from_db(
        real_db,
        {
            "schema": REQUEST_SCHEMA,
            "project_id": PROJECT,
            "operations": [{
                "op": "SUPERSEDE_CLAIM",
                "supersedes_id": status["claim_id"],
                "value": {"state": "ALIASED"},
                "evidence_state": "VERIFIED",
                "evidence_refs": [REF],
                "valid_from": "2026-08-10T08:00:00Z",
            }],
        },
    )
    real_proposal_path = tmp_path / "real-proposal.json"
    write_json(real_proposal_path, real_proposal)
    _, real_auth_path = auth_file(real_proposal, real_proposal_path, tmp_path)
    before = real_db.read_bytes()

    result = applymod.apply_authorized_memory_delta(alias_dir / "memory.db", real_proposal_path, real_auth_path)

    assert result["terminal"] == "CURRENT_MEMORY_APPLY_REVISE"
    assert result["reason"] == "OPERATIONAL_MEMORY_TARGET_BINDING_INVALID"
    assert real_db.read_bytes() == before
