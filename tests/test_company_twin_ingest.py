from __future__ import annotations

import copy
import inspect
import json
from pathlib import Path

import pytest

import continuityos.company_twin_ingest as ingest

ROOT = Path(__file__).resolve().parents[1]
SOURCE_FIXTURE = ROOT / "examples" / "company_twin_ingest" / "continuityos_lab_sources.json"


def _actor(kind="HUMAN", actor_id="human:director", authority="OWNER", manager=None):
    value = {
        "actor_id": actor_id,
        "actor_kind": kind,
        "role": "DIRECTOR" if kind == "HUMAN" else "ROBOT",
        "authority_class": authority,
    }
    if manager is not None:
        value["manager_actor_id"] = manager
    return value


def _env(*, connector="drive-synth", source_system="google_drive", object_type="document",
         object_id="doc-1", revision="r1", observed="2026-01-01T10:01:00Z",
         effective="2026-01-01T10:00:00Z", visibility="COMPANY", scope="company",
         payload=None, cursor="c1", actor=None, deleted=False):
    return {
        "schema_version": ingest.ENVELOPE_SCHEMA_VERSION,
        "tenant_id": "tenant:continuityos-lab",
        "connector_id": connector,
        "source_system": source_system,
        "source_object_type": object_type,
        "source_object_id": object_id,
        "revision_id": revision,
        "observed_at": observed,
        "effective_at": effective,
        "acl": {"visibility": visibility, "scope": scope},
        "payload": payload if payload is not None else {"title": "Synthetic source", "text": "evidence"},
        "raw_ref": f"synthetic://{source_system}/{object_id}?rev={revision}",
        "cursor": cursor,
        "actor": actor or _actor(),
        "deleted": deleted,
    }


_PORTABLE_BATCH = [
    _env(object_id="company-plan", revision="r1", cursor="c1"),
    _env(object_type="spreadsheet", object_id="finance", revision="r1",
         visibility="RESTRICTED", scope="restricted:finance",
         payload={"title": "Runway", "months": 12}, cursor="c2"),
]


def _source_fixture():
    if not SOURCE_FIXTURE.exists():
        pytest.skip("source-only ContinuityOS Lab fixture is not packaged in the wheel")
    return json.loads(SOURCE_FIXTURE.read_text(encoding="utf-8"))


def test_schema_contracts_are_exposed_without_source_only_files():
    assert ingest.SOURCE_ENVELOPE_SCHEMA["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert ingest.INGEST_RECEIPT_SCHEMA["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert ingest.PARSER_VERSION == "company-twin-p2b/1"


def test_source_fixture_models_our_company_line_and_three_source_families():
    data = _source_fixture()
    assert data["organization"] == {
        "tenant_id": "tenant:continuityos-lab", "name": "ContinuityOS Lab", "synthetic": True,
    }
    kinds = {actor["actor_kind"] for actor in data["actors"]}
    roles = {actor["role"] for actor in data["actors"]}
    systems = {item["source_system"] for item in data["envelopes"]}
    assert kinds == {"HUMAN", "AGENT"}
    assert {"DIRECTOR", "ENGINEERING_WORKER", "RESEARCH_ROBOT"}.issubset(roles)
    assert {"google_drive", "slack", "github"}.issubset(systems)


def test_same_revision_is_idempotent_and_does_not_duplicate_memory():
    store = ingest.InMemoryIngestStore()
    first = store.apply_batch(_PORTABLE_BATCH, tenant_id="tenant:continuityos-lab",
                              connector_id="drive-synth", cursor_after="c2")
    before = store.records
    second = store.apply_batch(copy.deepcopy(_PORTABLE_BATCH), tenant_id="tenant:continuityos-lab",
                               connector_id="drive-synth", cursor_after="c2")
    assert first.receipt["accepted"] == 2
    assert second.receipt["accepted"] == 0
    assert second.receipt["idempotent"] == 2
    assert store.records == before


def test_reordered_batch_has_same_canonical_records_and_receipt():
    batch = [_env(object_id=f"doc-{i}", cursor=f"c{i}") for i in range(1, 5)]
    a = ingest.InMemoryIngestStore()
    b = ingest.InMemoryIngestStore()
    r1 = a.apply_batch(batch, tenant_id="tenant:continuityos-lab", connector_id="drive-synth", cursor_after="c4")
    r2 = b.apply_batch(list(reversed(batch)), tenant_id="tenant:continuityos-lab", connector_id="drive-synth", cursor_after="c4")
    assert r1.records == r2.records
    assert r1.receipt == r2.receipt


def test_failed_batch_rolls_back_records_and_cursor():
    store = ingest.InMemoryIngestStore()
    store.apply_batch([_env(object_id="seed", cursor="c1")], tenant_id="tenant:continuityos-lab",
                      connector_id="drive-synth", cursor_after="c1")
    before_records = store.records
    before_cursor = store.cursor("tenant:continuityos-lab", "drive-synth")
    with pytest.raises(ingest.IngestionBatchAborted):
        store.apply_batch([_env(object_id="next", cursor="c2")], tenant_id="tenant:continuityos-lab",
                          connector_id="drive-synth", cursor_after="c2", fail_after_normalize=True)
    assert store.records == before_records
    assert store.cursor("tenant:continuityos-lab", "drive-synth") == before_cursor == "c1"


def test_new_revision_preserves_history_and_supersedes_old_revision():
    store = ingest.InMemoryIngestStore()
    r1 = _env(object_id="strategy", revision="r1", observed="2026-01-10T10:01:00Z",
              effective="2026-01-10T10:00:00Z", payload={"title": "Plan", "text": "Director -> workers -> company"}, cursor="c1")
    r2 = _env(object_id="strategy", revision="r2", observed="2026-03-10T10:01:00Z",
              effective="2026-03-10T10:00:00Z", payload={"title": "Plan", "text": "Director -> workers -> company -> governed robots"}, cursor="c2")
    first = store.apply_batch([r1], tenant_id="tenant:continuityos-lab", connector_id="drive-synth", cursor_after="c1")
    second = store.apply_batch([r2], tenant_id="tenant:continuityos-lab", connector_id="drive-synth", cursor_after="c2")
    assert len(store.records) == 2
    assert second.records[0]["supersedes"] == first.records[0]["id"]
    assert {record["revision_id"] for record in store.records} == {"r1", "r2"}


def test_tombstone_has_deterministic_as_of_replay_semantics():
    store = ingest.InMemoryIngestStore()
    worker = _actor(actor_id="human:worker-eng", authority="WORKER")
    original = _env(connector="slack-synth", source_system="slack", object_type="message",
                    object_id="thread-9", revision="r1", observed="2026-02-01T10:01:00Z",
                    effective="2026-02-01T10:00:00Z", visibility="TEAM", scope="team:engineering",
                    payload={"text": "worker update"}, cursor="s1", actor=worker)
    tombstone = _env(connector="slack-synth", source_system="slack", object_type="message",
                     object_id="thread-9", revision="r2", observed="2026-04-01T10:01:00Z",
                     effective="2026-04-01T10:00:00Z", visibility="TEAM", scope="team:engineering",
                     payload={"deleted": True}, cursor="s2", actor=worker, deleted=True)
    store.apply_batch([original, tombstone], tenant_id="tenant:continuityos-lab", connector_id="slack-synth", cursor_after="s2")
    before = ingest.replay_ingested(store.records, tenant_id="tenant:continuityos-lab",
                                    authorized_scopes=["company", "team:engineering"], as_of="2026-03-01T00:00:00Z")
    after = ingest.replay_ingested(store.records, tenant_id="tenant:continuityos-lab",
                                   authorized_scopes=["company", "team:engineering"], as_of="2026-05-01T00:00:00Z")
    assert len(before["records"]) == 1 and before["records"][0]["revision_id"] == "r1"
    assert after["records"] == []
    assert len(after["tombstones"]) == 1 and after["tombstones"][0]["revision_id"] == "r2"


def test_acl_is_preserved_and_restricted_metadata_does_not_leak_to_company_scope():
    store = ingest.InMemoryIngestStore()
    store.apply_batch(_PORTABLE_BATCH, tenant_id="tenant:continuityos-lab", connector_id="drive-synth", cursor_after="c2")
    company_view = ingest.replay_ingested(store.records, tenant_id="tenant:continuityos-lab",
                                          authorized_scopes=["company"], as_of="2026-12-31T00:00:00Z")
    encoded = json.dumps(company_view, sort_keys=True)
    assert "finance" not in encoded
    assert "restricted:finance" not in encoded
    finance = next(r for r in store.records if r["source_object_id"] == "finance")
    assert finance["source_acl"] == {"visibility": "RESTRICTED", "scope": "restricted:finance"}


def test_malformed_and_unmanaged_agent_inputs_are_quarantined_fail_closed():
    malformed = _env(object_id="bad")
    malformed.pop("source_object_id")
    unmanaged_agent = _env(connector="slack-synth", source_system="slack", object_type="message",
                           object_id="robot-unmanaged", actor=_actor(kind="AGENT", actor_id="agent:rogue", authority="PROPOSE"))
    accepted, quarantine, _ = ingest.normalize_batch([malformed, unmanaged_agent])
    assert accepted == []
    assert len(quarantine) == 2


def test_governed_robot_actor_is_preserved_under_human_management():
    robot = _env(connector="slack-synth", source_system="slack", object_type="message",
                 object_id="robot-proposal", actor=_actor(kind="AGENT", actor_id="agent:research-01",
                 authority="PROPOSE", manager="human:director"), payload={"text": "propose provenance receipt"})
    accepted, quarantine, _ = ingest.normalize_batch([robot])
    assert quarantine == []
    assert accepted[0]["actor_kind"] == "AGENT"
    assert accepted[0]["manager_actor_id"] == "human:director"
    assert accepted[0]["authority_class"] == "PROPOSE"
    ingest.validate_agent_management(accepted)


def test_cross_export_exact_duplicate_is_marked_but_not_silently_collapsed():
    payload = {"title": "Same exported evidence", "text": "byte-equivalent"}
    a = _env(object_id="drive-copy", payload=payload)
    b = _env(connector="archive-synth", source_system="email_export", object_type="document",
             object_id="mail-copy", payload=payload)
    accepted, quarantine, _ = ingest.normalize_batch([a, b])
    assert quarantine == [] and len(accepted) == 2
    duplicates = [r for r in accepted if r["duplicate_of"]]
    assert len(duplicates) == 1
    assert duplicates[0]["duplicate_of"] in {r["id"] for r in accepted}


def test_provenance_projection_into_p2a_evidence_is_traceable_and_never_inference():
    record = ingest.normalize_envelope(_env(object_id="decision-note"))
    evidence = ingest.to_company_twin_evidence(record, source_authority_id="auth_company_ingest")
    assert evidence["truth_class"] == "EVIDENCE"
    assert evidence["source_envelope_ids"] == [record["source_envelope_id"]]
    assert evidence["ingest_record_id"] == record["id"]
    assert evidence["content_hash"] == record["content_hash"]


def test_receipt_is_deterministic_and_captures_quarantine_counts():
    good = _env(object_id="good")
    bad = _env(object_id="bad")
    bad["acl"] = {"visibility": "COMPANY", "scope": "restricted:finance"}
    store = ingest.InMemoryIngestStore()
    result = store.apply_batch([good, bad], tenant_id="tenant:continuityos-lab",
                               connector_id="drive-synth", cursor_after="c9")
    assert result.receipt["accepted"] == 1
    assert result.receipt["quarantined"] == 1
    assert len(result.receipt["manifest_hash"]) == 64
    assert len(result.receipt["receipt_hash"]) == 64


def test_p2b_core_has_no_network_connector_calls():
    text = inspect.getsource(ingest)
    forbidden = ("urlopen(", "requests.", "httpx.", "socket.", "subprocess.")
    assert all(token not in text for token in forbidden)
