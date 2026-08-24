from __future__ import annotations

import copy

import pytest

from continuityos.company_twin_ingest import InMemoryIngestStore, replay_ingested
from continuityos.company_twin_lifecycle import (
    LifecycleAuthorizationError,
    LifecycleValidationError,
    build_export_bundle,
    build_tombstone_envelope,
    purge_eligibility,
    request_tombstone,
    retention_state,
    set_hold,
)


OWNER = {"actor_id": "principal_director", "actor_kind": "HUMAN", "authority_class": "OWNER"}
WORKER = {"actor_id": "principal_eng_worker", "actor_kind": "HUMAN", "authority_class": "WORKER"}
ROBOT = {
    "actor_id": "principal_research_robot",
    "actor_kind": "AGENT",
    "authority_class": "PROPOSE",
}


def record(record_id: str = "cti_alpha", *, tenant: str = "tenant_demo", scope: str = "team:engineering",
           deleted: bool = False) -> dict:
    return {
        "id": record_id,
        "tenant_id": tenant,
        "scope": scope,
        "truth_class": "EVIDENCE",
        "source_system": "synthetic",
        "source_object_type": "document_chunk",
        "source_object_id": "doc:chunk:0001",
        "revision_id": "r1",
        "source_envelope_id": "src_demo",
        "effective_at": "2026-01-01T00:00:00Z",
        "observed_at": "2026-01-01T00:00:00Z",
        "content_hash": "a" * 64,
        "deleted": deleted,
        "actor_id": "source_service",
        "actor_kind": "SERVICE",
        "authority_class": "READ_ONLY",
        "payload": {"title": "Synthetic engineering record", "text": "bounded evidence"},
    }


def source_envelope() -> dict:
    return {
        "schema_version": "company-twin-source-envelope/1",
        "tenant_id": "tenant_demo",
        "connector_id": "synthetic_connector",
        "source_system": "synthetic",
        "source_object_type": "document_chunk",
        "source_object_id": "doc:chunk:0001",
        "revision_id": "r1",
        "observed_at": "2026-01-01T00:00:00Z",
        "effective_at": "2026-01-01T00:00:00Z",
        "acl": {"visibility": "TEAM", "scope": "team:engineering"},
        "payload": {"title": "Synthetic engineering record", "text": "bounded evidence"},
        "raw_ref": "synthetic://record/doc:chunk:0001",
        "cursor": "c1",
        "actor": {
            "actor_id": "source_service",
            "actor_kind": "SERVICE",
            "authority_class": "READ_ONLY",
        },
        "deleted": False,
    }


def test_retention_is_deterministic_and_tenant_bound():
    r = record()
    first = retention_state(
        r, retention_class="STANDARD", assigned_at="2026-01-10T00:00:00Z", assigned_by=OWNER
    )
    second = retention_state(
        copy.deepcopy(r), retention_class="STANDARD", assigned_at="2026-01-10T00:00:00Z", assigned_by=OWNER
    )
    assert first == second
    assert first["tenant_id"] == r["tenant_id"]
    assert first["record_id"] == r["id"]
    assert first["retention_until"] == "2027-01-10T00:00:00Z"
    assert len(first["state_hash"]) == 64


def test_indefinite_retention_never_becomes_purge_eligible():
    r = record(deleted=True)
    state = retention_state(
        r, retention_class="INDEFINITE", assigned_at="2026-01-10T00:00:00Z", assigned_by=OWNER
    )
    result = purge_eligibility(r, state, evaluated_at="2036-01-10T00:00:00Z")
    assert result["eligible"] is False
    assert "RETENTION_INDEFINITE" in result["blockers"]
    assert result["physical_delete"] is False


def test_hold_blocks_purge_after_retention_expiry():
    r = record(deleted=True)
    state = retention_state(
        r, retention_class="TRANSIENT", assigned_at="2026-01-01T00:00:00Z", assigned_by=OWNER
    )
    held = set_hold(
        state, hold=True, reason="explicit preservation hold",
        changed_at="2026-01-02T00:00:00Z", changed_by=OWNER,
    )
    result = purge_eligibility(r, held, evaluated_at="2026-03-01T00:00:00Z")
    assert result["eligible"] is False
    assert result["blockers"] == ["HOLD_ACTIVE"]


def test_active_reference_blocks_purge():
    r = record(deleted=True)
    state = retention_state(
        r, retention_class="TRANSIENT", assigned_at="2026-01-01T00:00:00Z", assigned_by=OWNER
    )
    result = purge_eligibility(
        r, state, evaluated_at="2026-03-01T00:00:00Z",
        active_reference_ids=["decision_2", "decision_1", "decision_1"],
    )
    assert result["eligible"] is False
    assert result["blockers"] == ["ACTIVE_REFERENCES"]
    assert result["active_reference_ids"] == ["decision_1", "decision_2"]


def test_purge_eligibility_is_advisory_only():
    r = record(deleted=True)
    state = retention_state(
        r, retention_class="TRANSIENT", assigned_at="2026-01-01T00:00:00Z", assigned_by=OWNER
    )
    result = purge_eligibility(r, state, evaluated_at="2026-03-01T00:00:00Z")
    assert result["eligible"] is True
    assert result["advisory_only"] is True
    assert result["physical_delete"] is False


def test_tombstone_requires_exact_id_not_title_or_similarity():
    records = [record("cti_exact")]
    with pytest.raises(LifecycleValidationError, match="exact tenant-bound record_id"):
        request_tombstone(
            records, tenant_id="tenant_demo", record_id="Synthetic engineering record",
            requested_at="2026-02-01T00:00:00Z", requested_by=OWNER, reason="retire record",
        )


def test_tombstone_request_does_not_mutate_source_records():
    records = [record("cti_exact")]
    before = copy.deepcopy(records)
    event = request_tombstone(
        records, tenant_id="tenant_demo", record_id="cti_exact",
        requested_at="2026-02-01T00:00:00Z", requested_by=OWNER, reason="retire record",
    )
    assert records == before
    assert event["logical_only"] is True
    assert event["physical_delete"] is False


def test_tombstone_envelope_is_new_revision_and_logical_only():
    r = record("cti_exact")
    r.update({
        "connector_id": "synthetic_connector",
        "raw_ref": "synthetic://record/cti_exact",
        "source_acl": {"visibility": "TEAM", "scope": "team:engineering"},
    })
    event = request_tombstone(
        [r], tenant_id="tenant_demo", record_id="cti_exact",
        requested_at="2026-02-01T00:00:00Z", requested_by=OWNER, reason="retire record",
    )
    envelope = build_tombstone_envelope(r, event, requested_by=OWNER)
    assert envelope["tenant_id"] == r["tenant_id"]
    assert envelope["source_object_id"] == r["source_object_id"]
    assert envelope["revision_id"].startswith("tombstone:life_")
    assert envelope["deleted"] is True
    assert envelope["payload"] == {}


def test_tombstone_revision_preserves_historical_replay():
    store = InMemoryIngestStore()
    first = store.apply_batch(
        [source_envelope()], tenant_id="tenant_demo", connector_id="synthetic_connector", cursor_after="c1"
    )
    original = first.records[0]
    event = request_tombstone(
        store.records, tenant_id="tenant_demo", record_id=original["id"],
        requested_at="2026-02-01T00:00:00Z", requested_by=OWNER, reason="retire record",
    )
    tombstone_envelope = build_tombstone_envelope(original, event, requested_by=OWNER)
    store.apply_batch(
        [tombstone_envelope], tenant_id="tenant_demo",
        connector_id="synthetic_connector", cursor_after=tombstone_envelope["cursor"],
    )
    before = replay_ingested(
        store.records, tenant_id="tenant_demo",
        authorized_scopes=["team:engineering"], as_of="2026-01-15T00:00:00Z",
    )
    after = replay_ingested(
        store.records, tenant_id="tenant_demo",
        authorized_scopes=["team:engineering"], as_of="2026-02-02T00:00:00Z",
    )
    assert [item["id"] for item in before["records"]] == [original["id"]]
    assert before["tombstones"] == []
    assert after["records"] == []
    assert len(after["tombstones"]) == 1
    assert after["tombstones"][0]["deleted"] is True


def test_cross_tenant_tombstone_fails_closed():
    with pytest.raises(LifecycleValidationError, match="exact tenant-bound record_id"):
        request_tombstone(
            [record("cti_exact", tenant="tenant_a")],
            tenant_id="tenant_b", record_id="cti_exact",
            requested_at="2026-02-01T00:00:00Z", requested_by=OWNER, reason="retire record",
        )


@pytest.mark.parametrize("operation", ["retention", "hold", "tombstone"])
def test_agent_cannot_manage_lifecycle(operation):
    r = record()
    if operation == "retention":
        call = lambda: retention_state(
            r, retention_class="STANDARD", assigned_at="2026-01-01T00:00:00Z", assigned_by=ROBOT
        )
    elif operation == "hold":
        state = retention_state(
            r, retention_class="STANDARD", assigned_at="2026-01-01T00:00:00Z", assigned_by=OWNER
        )
        call = lambda: set_hold(
            state, hold=True, reason="hold", changed_at="2026-01-02T00:00:00Z", changed_by=ROBOT
        )
    else:
        call = lambda: request_tombstone(
            [r], tenant_id=r["tenant_id"], record_id=r["id"],
            requested_at="2026-01-02T00:00:00Z", requested_by=ROBOT, reason="retire",
        )
    with pytest.raises(LifecycleAuthorizationError):
        call()


def test_worker_cannot_set_retention_or_tombstone():
    r = record()
    with pytest.raises(LifecycleAuthorizationError):
        retention_state(
            r, retention_class="STANDARD", assigned_at="2026-01-01T00:00:00Z", assigned_by=WORKER
        )
    with pytest.raises(LifecycleAuthorizationError):
        request_tombstone(
            [r], tenant_id=r["tenant_id"], record_id=r["id"],
            requested_at="2026-01-02T00:00:00Z", requested_by=WORKER, reason="retire",
        )


def test_export_is_deterministic_tenant_and_scope_filtered():
    records = [
        record("cti_b", tenant="tenant_demo", scope="team:engineering"),
        record("cti_a", tenant="tenant_demo", scope="company"),
        record("cti_hidden", tenant="tenant_demo", scope="team:operations"),
        record("cti_other", tenant="tenant_other", scope="team:engineering"),
    ]
    first = build_export_bundle(
        records, tenant_id="tenant_demo", authorized_scopes=["team:engineering", "company"],
        requested_at="2026-02-01T00:00:00Z", requested_by=WORKER,
    )
    second = build_export_bundle(
        list(reversed(records)), tenant_id="tenant_demo", authorized_scopes=["company", "team:engineering"],
        requested_at="2026-02-01T00:00:00Z", requested_by=WORKER,
    )
    assert first == second
    assert [r["id"] for r in first["records"]] == ["cti_a", "cti_b"]
    assert first["record_count"] == 2
    assert len(first["manifest_hash"]) == 64
    assert len(first["receipt_hash"]) == 64


def test_export_can_exclude_tombstones():
    records = [record("cti_active"), record("cti_dead", deleted=True)]
    bundle = build_export_bundle(
        records, tenant_id="tenant_demo", authorized_scopes=["team:engineering"],
        requested_at="2026-02-01T00:00:00Z", requested_by=OWNER, include_tombstones=False,
    )
    assert [r["id"] for r in bundle["records"]] == ["cti_active"]


def test_export_preserves_truth_and_provenance_fields():
    bundle = build_export_bundle(
        [record("cti_exact")], tenant_id="tenant_demo", authorized_scopes=["team:engineering"],
        requested_at="2026-02-01T00:00:00Z", requested_by=ROBOT,
    )
    exported = bundle["records"][0]
    assert exported["truth_class"] == "EVIDENCE"
    assert exported["source_envelope_id"] == "src_demo"
    assert exported["content_hash"] == "a" * 64
    assert bundle["read_only"] is True


def test_export_requires_nonempty_authorized_scope():
    with pytest.raises(LifecycleValidationError, match="authorized scope"):
        build_export_bundle(
            [record()], tenant_id="tenant_demo", authorized_scopes=[],
            requested_at="2026-02-01T00:00:00Z", requested_by=OWNER,
        )


def test_hold_release_requires_owner():
    r = record()
    state = retention_state(
        r, retention_class="STANDARD", assigned_at="2026-01-01T00:00:00Z", assigned_by=OWNER
    )
    held = set_hold(
        state, hold=True, reason="preserve", changed_at="2026-01-02T00:00:00Z", changed_by=OWNER
    )
    with pytest.raises(LifecycleAuthorizationError):
        set_hold(
            held, hold=False, reason=None, changed_at="2026-01-03T00:00:00Z", changed_by=ROBOT
        )
