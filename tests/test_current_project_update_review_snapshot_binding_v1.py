from __future__ import annotations

import continuityos.current_project_update_review as review


def test_packet_fails_closed_if_current_work_moves_after_claim_sync(monkeypatch, tmp_path):
    proposal = {
        "schema": "continuityos.operational_memory.delta_proposal/v1",
        "terminal": "CURRENT_MEMORY_DELTA_PROPOSAL_PASS",
        "reason": "EXACT_OPERATIONAL_MEMORY_BASE_BOUND",
        "project_id": "project:drift",
        "request_sha256": "a" * 64,
        "base": {
            "projection_sha256": "b" * 64,
            "event_cursor": 1,
            "event_chain_head": "c" * 64,
            "valid_at": "2026-08-10T05:00:00Z",
            "current_work_capsule_sha256": "d" * 64,
        },
        "operations": [{
            "op": "RECORD_CLAIM",
            "subject_id": "project:drift",
            "predicate": "project.status",
            "scope": "global",
            "value": "new",
            "evidence_state": "UNKNOWN",
            "evidence_refs": [],
            "valid_from": None,
            "valid_to": None,
            "supersedes_id": None,
            "superseded_hash": None,
            "required_authority": "DETERMINISTIC_CONTROLLER_OR_HUMAN_REVIEW",
            "note": None,
            "operation_index": 0,
        }],
        "rationale": None,
        "requirements": {
            "base_projection_must_match_at_apply": True,
            "event_chain_head_must_match_at_apply": True,
            "superseded_record_hashes_must_match_at_apply": True,
            "human_or_controller_review_required": True,
            "apply_is_separate_effectful_operation": True,
        },
        "apply_status": "NOT_APPLIED",
        "apply_implemented": False,
        "execution_decision": "HOLD",
        "execution_authorized": False,
        "effects": {"operational_memory_write": False},
        "proposal_id": "placeholder",
        "operational_memory": {
            "path": str((tmp_path / "memory.db").absolute()),
            "verified": True,
            "projection_sha256": "b" * 64,
            "event_cursor": 1,
            "event_chain_head": "c" * 64,
        },
    }
    # This regression tests the post-R43 second-read binding only; proposal shape
    # validation and target binding are isolated so the expected failure is exact.
    monkeypatch.setattr(
        review.claim_sync,
        "build_claim_sync_plan_from_db",
        lambda db, req: {
            "terminal": "CURRENT_CLAIM_SYNC_PLAN_PASS",
            "project_id": "project:drift",
            "delta_proposal": proposal,
        },
    )
    monkeypatch.setattr(review.apply, "_validate_proposal", lambda value: dict(value))
    monkeypatch.setattr(
        review,
        "_validate_bound_target",
        lambda value, db: {"path": str((tmp_path / "memory.db").absolute())},
    )
    monkeypatch.setattr(
        review,
        "build_current_work_from_db",
        lambda db, project: {
            "terminal": "CURRENT_WORK_PASS",
            "project_id": project,
            "capsule_sha256": "e" * 64,
        },
    )

    result = review.build_project_update_review_packet(tmp_path / "memory.db", {"project_id": "project:drift"})

    assert result["terminal"] == "CURRENT_PROJECT_UPDATE_REVIEW_REVISE"
    assert result["reason"] == "REVIEW_PACKET_BINDING_FAILED"
    assert any("current-work changed after claim-sync projection" in item for item in result["errors"])
    assert result["authorization_granted"] is False
    assert result["execution_authorized"] is False
