from __future__ import annotations

import hashlib
import json
from pathlib import Path

import continuityos.current_claim_sync as sync
from continuityos.operational_memory import OperationalMemory

PROJECT = "project:r51-claim-sync-target"


def write_json(path: Path, value) -> str:
    payload = (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    path.write_bytes(payload)
    return hashlib.sha256(payload).hexdigest()


def test_claim_sync_nested_r36_proposal_binds_verified_db_target(tmp_path):
    evidence = tmp_path / "evidence.json"
    write_json(evidence, {"status": "PASS", "kind": "r51-target-binding"})
    seed_ref = {"sha256": "c" * 64, "locator": "evidence://r51/seed"}
    db = tmp_path / "project.db"
    with OperationalMemory(str(db)) as memory:
        memory.record_claim(
            subject_id=PROJECT,
            predicate="project.status",
            scope="global",
            value={"state": "OLD"},
            evidence_state="VERIFIED",
            evidence_refs=[seed_ref],
            actor_type="DETERMINISTIC_CONTROLLER",
            actor_id="r51-seed",
            valid_from="2026-08-10T05:00:00Z",
            recorded_at="2026-08-10T05:00:00Z",
        )
        assert memory.verify()["ok"] is True
    before = db.read_bytes()
    request = {
        "schema": sync.REQUEST_SCHEMA,
        "project_id": PROJECT,
        "evidence": [{"evidence_id": "new", "locator": str(evidence)}],
        "claims": [{
            "predicate": "project.status",
            "scope": "global",
            "value": {"state": "NEW"},
            "evidence_state": "VERIFIED",
            "evidence_ids": ["new"],
            "valid_from": "2026-08-10T08:00:00Z",
        }],
        "rationale": "R51 target-bound claim sync",
    }

    first = sync.build_claim_sync_plan_from_db(db, request)
    second = sync.build_claim_sync_plan_from_db(db, request)

    assert first["terminal"] == "CURRENT_CLAIM_SYNC_PLAN_PASS"
    assert first == second
    assert first["target_binding"] == "PROPOSAL_FILE_SHA_BINDS_OPERATIONAL_MEMORY_PATH"
    proposal = first["delta_proposal"]
    metadata = proposal["operational_memory"]
    assert metadata == first["operational_memory"]
    assert metadata["path"] == str(db.absolute())
    assert metadata["verified"] is True
    assert metadata["projection_sha256"] == proposal["base"]["projection_sha256"]
    assert metadata["event_cursor"] == proposal["base"]["event_cursor"]
    assert metadata["event_chain_head"] == proposal["base"]["event_chain_head"]
    assert proposal["apply_status"] == "NOT_APPLIED"
    assert proposal["execution_authorized"] is False
    assert db.read_bytes() == before
