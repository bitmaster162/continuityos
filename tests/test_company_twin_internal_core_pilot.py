from __future__ import annotations

import ast
import copy
import inspect
import json
import re
from pathlib import Path

import pytest

import continuityos.company_twin_internal_core_pilot as pilot
from continuityos.company_twin import replay, validate_dataset
from continuityos.company_twin_ingest import InMemoryIngestStore

ROOT = Path(__file__).resolve().parents[1]
SOURCE_FIXTURE = ROOT / "examples" / "company_twin" / "continuityos_internal_core_p2e_r3.json"
SCHEMA_FILE = ROOT / "docs" / "schemas" / "company_twin_internal_core_p2e_r3.schema.json"


def _artifact():
    return copy.deepcopy(pilot.REAL_INTERNAL_CORE_ARTIFACT)


def _source_fixture():
    if not SOURCE_FIXTURE.exists():
        pytest.skip("source-only internal core fixture is not packaged in the wheel")
    return pilot.load_source_fixture(SOURCE_FIXTURE)


def _ingested():
    store, result = pilot.ingest_internal_core_artifact(_artifact())
    assert result.receipt["quarantined"] == 0
    assert result.receipt["accepted"] == len(pilot.chunk_sanitized_markdown(_artifact()))
    return store, result


def test_source_fixture_matches_embedded_bounded_internal_copy():
    data = _source_fixture()
    assert data == pilot.source_fixture_document()
    assert data["artifact_count"] == 1
    assert data["source_boundary"] == "SELECTED_INTERNAL_CORE_ONE_FILE_REDACTED_CHUNKED"
    artifact = data["artifact"]
    assert artifact["source_type"] == "google_drive_selected_internal_file"
    assert artifact["file_name"] == "ContinuityOS_Core.md"
    assert artifact["mime_type"] == "text/markdown"
    assert artifact["document_title"] == "ContinuityOS Core & Ecosystem"
    assert artifact["excerpt_kind"] == "sanitized_bounded_internal_excerpt"


def test_fixture_is_bounded_hashed_and_contains_no_raw_drive_locator():
    data = _source_fixture()
    artifact = data["artifact"]
    serialized = json.dumps(data, ensure_ascii=False).lower()
    assert re.fullmatch(r"[0-9a-f]{64}", artifact["source_locator_hash"])
    assert re.fullmatch(r"[0-9a-f]{64}", artifact["sanitized_document_digest"])
    assert len(artifact["sanitized_markdown"].encode("utf-8")) < artifact["size_bytes"]
    assert len(artifact["sanitized_markdown"]) <= pilot.MAX_SANITIZED_CHARS
    assert "https://" not in serialized
    assert "drive.google" not in serialized
    assert "docs.google" not in serialized
    assert {"id", "file_id", "drive_id", "url", "owners", "permissions", "email", "access_token", "refresh_token", "client_secret"}.isdisjoint(artifact)


def test_source_only_schema_is_parseable_and_strict():
    if not SCHEMA_FILE.exists():
        pytest.skip("source-only schema is not packaged in the wheel")
    schema = json.loads(SCHEMA_FILE.read_text(encoding="utf-8"))
    assert schema["properties"]["artifact"]["additionalProperties"] is False
    assert schema["properties"]["artifact_count"]["const"] == 1
    assert schema["properties"]["artifact"]["properties"]["source_locator_hash"]["pattern"] == "^[0-9a-f]{64}$"
    assert schema["properties"]["artifact"]["properties"]["sanitized_document_digest"]["pattern"] == "^[0-9a-f]{64}$"


def test_sanitizer_recomputes_digest_and_discards_unknown_safe_fields():
    artifact = _artifact()
    expected = artifact["sanitized_document_digest"]
    artifact["safe_extra"] = "discard me"
    sanitized = pilot.sanitize_internal_core_artifact(artifact)
    assert sanitized["sanitized_document_digest"] == expected
    assert sanitized["sanitized_markdown"].endswith("\n")
    assert "safe_extra" not in sanitized


@pytest.mark.parametrize("mutator", [
    lambda item: item.update(source_type="google_drive_folder"),
    lambda item: item.update(source_locator_hash="0" * 64),
    lambda item: item.update(file_name="other.md"),
    lambda item: item.update(mime_type="text/plain"),
    lambda item: item.update(size_bytes=0),
    lambda item: item.update(size_bytes=pilot.MAX_SOURCE_BYTES + 1),
    lambda item: item.update(source_observed_at="not-a-time"),
    lambda item: item.update(source_observed_at="2026-07-01T00:00:00Z"),
    lambda item: item.update(sanitized_document_digest="0" * 64),
    lambda item: item.update(sanitized_markdown="too short"),
])
def test_selected_internal_source_boundary_violations_fail_closed(mutator):
    artifact = _artifact()
    mutator(artifact)
    with pytest.raises(pilot.InternalCorePilotError):
        pilot.sanitize_internal_core_artifact(artifact)


@pytest.mark.parametrize("key,value", [
    ("access_token", "redacted-token-shape"),
    ("owner_email", "person-at-example"),
    ("permissions", ["reader"]),
    ("file_id", "opaque-provider-identifier"),
    ("url", "provider-link"),
])
def test_private_provider_metadata_keys_fail_closed(key, value):
    artifact = _artifact()
    artifact[key] = value
    with pytest.raises(pilot.InternalCorePilotError):
        pilot.sanitize_internal_core_artifact(artifact)


def test_sensitive_values_fail_closed_without_tracked_secret_fixture_signatures():
    private_marker = "-" * 5 + "BEGIN " + "PRIVATE" + " KEY" + "-" * 5
    suspicious = [
        "drive" + ".google" + ".com/file/example",
        "person" + "@" + "example.invalid",
        "Bear" + "er abc.def.ghi123",
        "api" + "_key = " + "abcdefghijk",
        private_marker,
    ]
    for value in suspicious:
        artifact = _artifact()
        artifact["sanitized_markdown"] += "\n\n" + value
        artifact.pop("sanitized_document_digest", None)
        with pytest.raises(pilot.InternalCorePilotError):
            pilot.sanitize_internal_core_artifact(artifact)


def test_deterministic_markdown_chunking_has_stable_ids_hashes_ranges_and_heading_lineage():
    first = pilot.chunk_sanitized_markdown(_artifact())
    second = pilot.chunk_sanitized_markdown(_artifact())
    assert first == second
    assert len(first) >= 3
    assert [item["chunk_index"] for item in first] == list(range(len(first)))
    assert all(item["chunk_count"] == len(first) for item in first)
    assert all(0 < len(item["text"]) <= pilot.CHUNK_MAX_CHARS for item in first)
    assert all(re.fullmatch(r"[0-9a-f]{64}", item["chunk_digest"]) for item in first)
    assert all(item["parent_document_digest"] == _artifact()["sanitized_document_digest"] for item in first)
    assert all(item["chunk_id"].startswith("corechunk_") for item in first)
    assert all(first[index]["char_end"] <= first[index + 1]["char_start"] for index in range(len(first) - 1))
    assert any("Source section:" in " > ".join(item["heading_path"]) for item in first)


def test_chunk_text_hashes_and_ranges_point_back_to_normalized_parent():
    artifact = pilot.sanitize_internal_core_artifact(_artifact())
    markdown = artifact["sanitized_markdown"]
    for chunk in pilot.chunk_sanitized_markdown(artifact):
        assert markdown[chunk["char_start"]:chunk["char_end"]] == chunk["text"]
        assert pilot._text_digest(chunk["text"]) == chunk["chunk_digest"]


def test_adapter_produces_read_only_p2b_envelope_per_chunk_with_hashed_locator_only():
    chunks = pilot.chunk_sanitized_markdown(_artifact())
    envelopes = pilot.artifact_to_envelopes(_artifact())
    assert len(envelopes) == len(chunks)
    assert len({item["source_object_id"] for item in envelopes}) == len(chunks)
    assert all(item["source_system"] == pilot.SOURCE_SYSTEM for item in envelopes)
    assert all(item["source_object_type"] == "selected_internal_core_chunk" for item in envelopes)
    assert all(item["raw_ref"].startswith("drive-sha256:") and "http" not in item["raw_ref"].lower() for item in envelopes)
    assert all(item["acl"] == {"visibility": "TEAM", "scope": "team:engineering"} for item in envelopes)
    assert all(item["actor"]["actor_kind"] == "SERVICE" and item["actor"]["authority_class"] == "READ_ONLY" for item in envelopes)
    assert [item["payload"]["chunk_index"] for item in envelopes] == list(range(len(envelopes)))
    assert {item["payload"]["parent_document_digest"] for item in envelopes} == {_artifact()["sanitized_document_digest"]}


def test_reingest_is_idempotent_for_all_chunks():
    store = InMemoryIngestStore()
    _, first = pilot.ingest_internal_core_artifact(_artifact(), store=store)
    before = store.records
    _, second = pilot.ingest_internal_core_artifact(_artifact(), store=store)
    count = len(pilot.chunk_sanitized_markdown(_artifact()))
    assert first.receipt["accepted"] == count
    assert second.receipt["accepted"] == 0
    assert second.receipt["idempotent"] == count
    assert second.receipt["quarantined"] == 0
    assert store.records == before


def test_changed_sanitized_document_creates_superseding_revisions_in_same_chunk_slots():
    store = InMemoryIngestStore()
    original = _artifact()
    _, first = pilot.ingest_internal_core_artifact(original, store=store)
    changed = _artifact()
    changed["sanitized_markdown"] = changed["sanitized_markdown"].replace("still an MVP", "remained an MVP", 1)
    changed["source_observed_at"] = "2026-08-22T01:00:00Z"
    changed.pop("sanitized_document_digest", None)
    assert [item["chunk_id"] for item in pilot.chunk_sanitized_markdown(original)] == [item["chunk_id"] for item in pilot.chunk_sanitized_markdown(changed)]
    _, second = pilot.ingest_internal_core_artifact(changed, store=store)
    assert first.receipt["accepted"] == second.receipt["accepted"] > 0
    assert all(record["supersedes"] for record in second.records)
    assert len(pilot.project_internal_core_to_company_twin(store.records)["evidence"]) == second.receipt["accepted"]


def test_projection_is_valid_real_p2a_memory_with_only_evidence_and_explicit_facts():
    store, _ = _ingested()
    dataset = pilot.project_internal_core_to_company_twin(store.records)
    validate_dataset(dataset)
    assert dataset["organization"]["synthetic"] is False
    assert dataset["organization"]["source_boundary"] == pilot.SOURCE_BOUNDARY
    assert dataset["decisions"] == [] and dataset["outcomes"] == [] and dataset["inferences"] == []
    assert len(dataset["evidence"]) == len(pilot.chunk_sanitized_markdown(_artifact()))
    assert all(item["truth_class"] == "EVIDENCE" and item["source_ref"].startswith("drive-sha256:") for item in dataset["evidence"])
    assert all(item["truth_class"] == "FACT" for item in dataset["events"] + dataset["process_observations"])
    authority = dataset["source_authorities"][0]
    assert authority["source_locator_hash"] == pilot.SELECTED_SOURCE_LOCATOR_HASH
    assert authority["parent_document_digest"] == _artifact()["sanitized_document_digest"]


def test_historical_replay_hides_internal_core_before_source_effective_time():
    store, _ = _ingested()
    dataset = pilot.project_internal_core_to_company_twin(store.records)
    before = replay(dataset, principal_id="principal_director", as_of="2026-07-06T20:00:00Z")
    after = replay(dataset, principal_id="principal_director", as_of="2026-07-07T00:00:00Z")
    assert before["evidence"] == [] and before["events"] == []
    assert len(after["evidence"]) == len(pilot.chunk_sanitized_markdown(_artifact()))
    assert {item["id"] for item in after["events"]} == {"evt_internal_core_selected_snapshot"}


def test_existing_p2c_policy_and_p2d_console_apply_to_internal_core_chunks():
    store, _ = _ingested()
    as_of = "2026-08-22T00:00:00Z"
    director = pilot.build_pilot_console_snapshot(store.records, principal_id="principal_director", as_of=as_of)
    engineer = pilot.build_pilot_console_snapshot(store.records, principal_id="principal_eng_worker", as_of=as_of)
    robot = pilot.build_pilot_console_snapshot(store.records, principal_id="principal_research_robot", as_of=as_of)
    operations = pilot.build_pilot_console_snapshot(store.records, principal_id="principal_ops_worker", as_of=as_of)
    expected = len(pilot.chunk_sanitized_markdown(_artifact()))
    assert director["read_only"] is True and len(director["evidence"]) == expected
    assert len(engineer["evidence"]) == expected and len(robot["evidence"]) == expected
    assert operations["evidence"] == []
    assert robot["capabilities"]["READ"]["allowed"] is True
    assert robot["capabilities"]["PROPOSE"]["allowed"] is True
    assert robot["capabilities"]["APPROVE"]["allowed"] is False
    assert robot["capabilities"]["EXECUTE"]["allowed"] is False
    assert director["governance"] == {"execution_authority": "NONE", "can_execute": False, "can_trade": False, "capital_permission": "DENY"}


def test_core_module_has_no_live_drive_network_oauth_or_subprocess_imports():
    tree = ast.parse(inspect.getsource(pilot))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module)
    forbidden = {"requests", "httpx", "socket", "subprocess", "urllib.request", "googleapiclient", "google.auth", "oauthlib"}
    assert not {name for name in imported if any(name == root or name.startswith(root + ".") for root in forbidden)}
