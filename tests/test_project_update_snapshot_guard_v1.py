from __future__ import annotations

import pytest

import continuityos.current_project_update_review as review
import continuityos.project_update_snapshot_guard as guard
from continuityos.current_work import compile_project_work
from continuityos.operational_memory import OperationalMemory

PROJECT = "project:r53-target"
OTHER = "project:r53-unrelated"


def _packet_from_projection(projection):
    work = compile_project_work(projection, PROJECT)
    assert work["terminal"] == "CURRENT_WORK_PASS"
    return {
        "terminal": "CURRENT_PROJECT_UPDATE_REVIEW_PASS",
        "project_id": PROJECT,
        "claim_sync_plan": {
            "delta_proposal": {
                "base": {
                    "projection_sha256": projection["projection_sha256"],
                    "event_cursor": projection["event_cursor"],
                    "event_chain_head": projection["event_chain_head"],
                    "current_work_capsule_sha256": work["capsule_sha256"],
                }
            }
        },
    }


def test_guard_is_installed_on_public_r52_builder():
    assert getattr(
        review.build_project_update_review_packet,
        "__continuityos_r53_snapshot_rechecked__",
        False,
    ) is True


def test_final_snapshot_recheck_accepts_unchanged_memory(tmp_path):
    db = tmp_path / "memory.db"
    with OperationalMemory(str(db)) as memory:
        projection = memory.projection()
    packet = _packet_from_projection(projection)

    expected, actual = guard._recheck_packet_snapshot(packet, db)

    assert actual == expected


def test_unrelated_event_invalidates_packet_even_when_project_work_is_unchanged(tmp_path):
    db = tmp_path / "memory.db"
    with OperationalMemory(str(db)) as memory:
        before = memory.projection()
    packet = _packet_from_projection(before)
    before_work = compile_project_work(before, PROJECT)

    with OperationalMemory(str(db)) as memory:
        memory.record_claim(
            subject_id=OTHER,
            predicate="project.status",
            value={"state": "CHANGED"},
            scope="global",
            evidence_state="UNKNOWN",
            evidence_refs=[],
            actor_type="DETERMINISTIC_CONTROLLER",
            actor_id="R53_TEST",
            recorded_at="2026-08-10T09:00:00Z",
        )
        after = memory.projection()
    after_work = compile_project_work(after, PROJECT)

    # This is the exact R52 hole: project-specific work is unchanged, while the
    # global immutable OperationalMemory base has moved.
    assert after_work["capsule_sha256"] == before_work["capsule_sha256"]
    assert after["projection_sha256"] != before["projection_sha256"]
    assert after["event_cursor"] != before["event_cursor"]
    assert after["event_chain_head"] != before["event_chain_head"]

    with pytest.raises(guard.ProjectUpdateSnapshotDrift):
        guard._recheck_packet_snapshot(packet, db)
