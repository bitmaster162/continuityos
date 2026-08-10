from __future__ import annotations

import hashlib
import json
from pathlib import Path

import continuityos.current_project_update_review as review
from continuityos.current_claim_sync import REQUEST_SCHEMA
from continuityos.current_work import build_current_work_from_db
from continuityos.operational_memory import OperationalMemory

PROJECT = "project:r53-target"
OTHER = "project:r53-unrelated"
SEED_REF = {"sha256": "a" * 64, "locator": "evidence://r53/seed"}


def _write_json(path: Path, value) -> str:
    payload = (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    path.write_bytes(payload)
    return hashlib.sha256(payload).hexdigest()


def _seed(path: Path) -> None:
    with OperationalMemory(str(path)) as memory:
        memory.record_claim(
            subject_id=PROJECT,
            predicate="project.status",
            scope="global",
            value={"state": "OLD"},
            evidence_state="VERIFIED",
            evidence_refs=[SEED_REF],
            actor_type="DETERMINISTIC_CONTROLLER",
            actor_id="r53-seed",
            valid_from="2026-08-10T08:00:00Z",
            recorded_at="2026-08-10T08:00:00Z",
        )
        assert memory.verify()["ok"] is True


def _request(evidence: Path):
    return {
        "schema": REQUEST_SCHEMA,
        "project_id": PROJECT,
        "evidence": [{
            "evidence_id": "fresh",
            "locator": str(evidence),
            "kind": "PROVIDER_READBACK",
            "scope": PROJECT,
        }],
        "claims": [{
            "predicate": "project.status",
            "scope": "global",
            "value": {"state": "UPDATED"},
            "evidence_state": "VERIFIED",
            "evidence_ids": ["fresh"],
            "valid_from": "2026-08-10T08:10:00Z",
        }],
        "rationale": "R53 unrelated-memory drift regression",
    }


def test_review_packet_rejects_unrelated_db_drift_even_when_project_work_is_unchanged(monkeypatch, tmp_path):
    db = tmp_path / "project.db"
    _seed(db)
    evidence = tmp_path / "evidence.json"
    _write_json(evidence, {"status": "PASS", "frontier": "r53"})

    before_work = build_current_work_from_db(db, PROJECT)
    assert before_work["terminal"] == "CURRENT_WORK_PASS"
    real_planner = review.claim_sync.build_claim_sync_plan_from_db

    def plan_then_mutate_unrelated(db_path, request):
        plan = real_planner(db_path, request)
        assert plan["terminal"] == "CURRENT_CLAIM_SYNC_PLAN_PASS", plan
        with OperationalMemory(str(db_path)) as memory:
            memory.record_claim(
                subject_id=OTHER,
                predicate="unrelated.noise",
                scope="global",
                value={"changed": True},
                evidence_state="UNKNOWN",
                evidence_refs=[],
                actor_type="DETERMINISTIC_CONTROLLER",
                actor_id="r53-race",
                valid_from="2026-08-10T08:20:00Z",
                recorded_at="2026-08-10T08:20:00Z",
            )
            assert memory.verify()["ok"] is True
        return plan

    monkeypatch.setattr(review.claim_sync, "build_claim_sync_plan_from_db", plan_then_mutate_unrelated)

    result = review.build_project_update_review_packet(db, _request(evidence))
    after_work = build_current_work_from_db(db, PROJECT)

    # The unrelated write changes the global projection/cursor/chain but does not
    # change this project's work capsule. R52 checked only the latter; R53 must also
    # reject the already-stale R36 base before authority review.
    assert after_work["capsule_sha256"] == before_work["capsule_sha256"]
    assert result["terminal"] == "CURRENT_PROJECT_UPDATE_REVIEW_REVISE"
    assert result["reason"] == "REVIEW_PACKET_BINDING_FAILED"
    assert any("operational-memory base changed after claim-sync projection" in item for item in result["errors"])
    assert result["proposal"] is None
    assert result["authorization_review"] is None
    assert result["authorization_granted"] is False
    assert result["execution_authorized"] is False
