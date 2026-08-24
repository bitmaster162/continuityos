from __future__ import annotations

import ast
import copy
import inspect
import json
import re
from pathlib import Path

import pytest

import continuityos.company_twin_drive_pilot as pilot
from continuityos.company_twin import replay, validate_dataset
from continuityos.company_twin_ingest import InMemoryIngestStore

ROOT = Path(__file__).resolve().parents[1]
SOURCE_FIXTURE = ROOT / "examples" / "company_twin" / "continuityos_drive_p2e_r2.json"
SCHEMA_FILE = ROOT / "docs" / "schemas" / "company_twin_drive_pilot_p2e_r2.schema.json"


def _artifact():
    return copy.deepcopy(pilot.REAL_SELECTED_DRIVE_ARTIFACT)


def _source_fixture():
    if not SOURCE_FIXTURE.exists():
        pytest.skip("source-only selected Drive fixture is not packaged in the wheel")
    return pilot.load_source_fixture(SOURCE_FIXTURE)


def _ingested():
    store, result = pilot.ingest_selected_drive_artifact(_artifact())
    assert result.receipt["quarantined"] == 0
    assert result.receipt["accepted"] == 1
    return store, result


def test_source_fixture_matches_embedded_sanitized_real_copy():
    data = _source_fixture()
    assert data == pilot.source_fixture_document()
    assert data["artifact_count"] == 1
    assert data["source_boundary"] == "SELECTED_DRIVE_ONE_FOLDER_ONE_FILE_REDACTED"
    artifact = data["artifact"]
    assert artifact["source_type"] == "google_drive_selected_file"
    assert artifact["folder_title"] == "why-continuityos-may-fail-an-adversarial-analysis"
    assert artifact["file_name"] == "index.html"
    assert artifact["mime_type"] == "text/html"
    assert artifact["title"] == "Why ContinuityOS May Fail: An Adversarial Analysis"
    assert artifact["published_date"] == "2026-07-04"


def test_source_fixture_contains_hashes_but_no_raw_drive_locator_or_private_metadata():
    data = _source_fixture()
    serialized = json.dumps(data, ensure_ascii=False).lower()
    assert re.fullmatch(r"[0-9a-f]{64}", data["artifact"]["source_locator_hash"])
    assert re.fullmatch(r"[0-9a-f]{64}", data["artifact"]["content_digest"])
    assert "https://" not in serialized
    assert "drive.google" not in serialized
    assert "docs.google" not in serialized
    forbidden_keys = {
        "id", "file_id", "folder_id", "drive_id", "url", "owners", "permissions",
        "owner_email", "email", "access_token", "refresh_token", "client_secret",
    }
    assert forbidden_keys.isdisjoint(data["artifact"])


def test_source_only_schema_artifact_is_parseable_and_rejects_additional_properties_by_contract():
    if not SCHEMA_FILE.exists():
        pytest.skip("source-only schema is not packaged in the wheel")
    schema = json.loads(SCHEMA_FILE.read_text(encoding="utf-8"))
    assert schema["properties"]["artifact"]["additionalProperties"] is False
    assert schema["properties"]["artifact_count"]["const"] == 1
    assert schema["properties"]["artifact"]["properties"]["source_locator_hash"]["pattern"] == "^[0-9a-f]{64}$"


def test_sanitizer_recomputes_exact_content_digest_and_discards_unknown_safe_fields():
    artifact = _artifact()
    expected = artifact["content_digest"]
    artifact["safe_extra"] = "discard me"
    sanitized = pilot.sanitize_selected_drive_artifact(artifact)
    assert sanitized["content_digest"] == expected
    assert "safe_extra" not in sanitized


@pytest.mark.parametrize(
    "mutator",
    [
        lambda item: item.update(source_type="google_drive_folder"),
        lambda item: item.update(source_locator_hash="0" * 64),
        lambda item: item.update(folder_title="another-folder"),
        lambda item: item.update(file_name="other.html"),
        lambda item: item.update(mime_type="application/pdf"),
        lambda item: item.update(size_bytes=0),
        lambda item: item.update(size_bytes=pilot.MAX_SELECTED_FILE_BYTES + 1),
        lambda item: item.update(source_created_at="not-a-time"),
        lambda item: item.update(source_created_at="2026-07-01T00:00:00Z"),
        lambda item: item.update(published_date="2026-02-30"),
        lambda item: item.update(content_digest="0" * 64),
    ],
)
def test_selected_source_boundary_violations_fail_closed(mutator):
    artifact = _artifact()
    mutator(artifact)
    with pytest.raises(pilot.SelectedDrivePilotError):
        pilot.sanitize_selected_drive_artifact(artifact)


@pytest.mark.parametrize(
    "key,value",
    [
        ("access_token", "redacted-token-shape"),
        ("owner_email", "person@example.invalid"),
        ("permissions", ["reader"]),
        ("file_id", "opaque-provider-identifier"),
        ("url", "provider-link"),
    ],
)
def test_private_drive_metadata_keys_fail_closed_even_when_not_allowlisted(key, value):
    artifact = _artifact()
    artifact[key] = value
    with pytest.raises(pilot.SelectedDrivePilotError):
        pilot.sanitize_selected_drive_artifact(artifact)


def test_drive_host_email_token_and_private_key_values_fail_closed_inside_allowed_text():
    suspicious_values = [
        "drive.google.com/file/example",
        "person@example.invalid",
        "Bearer abc.def.ghi",
        "-----BEGIN PRIVATE KEY-----",
    ]
    for value in suspicious_values:
        artifact = _artifact()
        artifact["description"] = value
        artifact.pop("content_digest", None)
        with pytest.raises(pilot.SelectedDrivePilotError):
            pilot.sanitize_selected_drive_artifact(artifact)


def test_adapter_produces_one_valid_redacted_read_only_p2b_service_envelope():
    envelope = pilot.artifact_to_envelope(_artifact())
    assert envelope["source_system"] == "google_drive_selected_redacted"
    assert envelope["source_object_type"] == "selected_drive_file"
    assert envelope["source_object_id"].startswith("drivefile_")
    assert envelope["raw_ref"].startswith("drive-sha256:")
    assert "http" not in envelope["raw_ref"].lower()
    assert envelope["acl"] == {"visibility": "TEAM", "scope": "team:engineering"}
    assert envelope["actor"]["actor_kind"] == "SERVICE"
    assert envelope["actor"]["authority_class"] == "READ_ONLY"
    assert envelope["payload"]["source_boundary"] == pilot.SOURCE_BOUNDARY
    serialized = json.dumps(envelope, ensure_ascii=False).lower()
    assert "drive.google" not in serialized and "docs.google" not in serialized


def test_reingest_is_idempotent_and_preserves_exact_record():
    store = InMemoryIngestStore()
    _, first = pilot.ingest_selected_drive_artifact(_artifact(), store=store)
    before = store.records
    _, second = pilot.ingest_selected_drive_artifact(_artifact(), store=store)
    assert first.receipt["accepted"] == 1
    assert second.receipt["accepted"] == 0
    assert second.receipt["idempotent"] == 1
    assert second.receipt["quarantined"] == 0
    assert store.records == before


def test_projection_is_valid_p2a_real_memory_and_preserves_evidence_truth_class():
    store, _ = _ingested()
    dataset = pilot.project_selected_drive_to_company_twin(store.records)
    validate_dataset(dataset)
    assert dataset["organization"]["synthetic"] is False
    assert dataset["organization"]["source_boundary"] == pilot.SOURCE_BOUNDARY
    assert dataset["decisions"] == []
    assert dataset["outcomes"] == []
    assert dataset["inferences"] == []
    assert len(dataset["evidence"]) == 1
    evidence = dataset["evidence"][0]
    assert evidence["truth_class"] == "EVIDENCE"
    assert evidence["source_ref"].startswith("drive-sha256:")
    assert evidence["ingest_record_id"] == store.records[0]["id"]


def test_projection_creates_only_explicit_evidence_backed_publication_and_content_facts():
    store, _ = _ingested()
    dataset = pilot.project_selected_drive_to_company_twin(store.records)
    assert {event["id"] for event in dataset["events"]} == {
        "evt_drive_analysis_publication_date",
        "evt_drive_analysis_selected_snapshot",
    }
    assert all(event["truth_class"] == "FACT" for event in dataset["events"])
    assert all(event["evidence_ids"] == [dataset["evidence"][0]["id"]] for event in dataset["events"])
    observation = dataset["process_observations"][0]
    assert observation["truth_class"] == "FACT"
    assert observation["evidence_ids"] == [dataset["evidence"][0]["id"]]


def test_historical_replay_hides_pre_evidence_publication_event_until_source_evidence_exists():
    store, _ = _ingested()
    dataset = pilot.project_selected_drive_to_company_twin(store.records)
    before_evidence = replay(
        dataset,
        principal_id="principal_director",
        as_of="2026-07-05T00:00:00Z",
    )
    after_evidence = replay(
        dataset,
        principal_id="principal_director",
        as_of="2026-07-07T00:00:00Z",
    )
    assert before_evidence["evidence"] == []
    assert before_evidence["events"] == []
    assert {item["id"] for item in after_evidence["events"]} == {
        "evt_drive_analysis_publication_date",
        "evt_drive_analysis_selected_snapshot",
    }
    assert len(after_evidence["evidence"]) == 1


def test_existing_p2c_policy_and_p2d_console_apply_to_selected_drive_memory():
    store, _ = _ingested()
    as_of = "2026-08-22T00:31:03.858Z"
    director = pilot.build_pilot_console_snapshot(store.records, principal_id="principal_director", as_of=as_of)
    engineer = pilot.build_pilot_console_snapshot(store.records, principal_id="principal_eng_worker", as_of=as_of)
    robot = pilot.build_pilot_console_snapshot(store.records, principal_id="principal_research_robot", as_of=as_of)
    operations = pilot.build_pilot_console_snapshot(store.records, principal_id="principal_ops_worker", as_of=as_of)

    assert director["read_only"] is True and director["evidence"]
    assert engineer["evidence"]
    assert robot["evidence"]
    assert operations["evidence"] == []
    assert robot["capabilities"]["READ"]["allowed"] is True
    assert robot["capabilities"]["PROPOSE"]["allowed"] is True
    assert robot["capabilities"]["APPROVE"]["allowed"] is False
    assert robot["capabilities"]["EXECUTE"]["allowed"] is False
    assert director["governance"] == {
        "execution_authority": "NONE",
        "can_execute": False,
        "can_trade": False,
        "capital_permission": "DENY",
    }


def test_core_module_has_no_live_drive_network_oauth_or_subprocess_imports():
    tree = ast.parse(inspect.getsource(pilot))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module)

    forbidden = {"requests", "httpx", "socket", "subprocess", "urllib.request", "googleapiclient", "google.auth", "oauthlib"}
    assert not {
        name
        for name in imported
        if any(name == root or name.startswith(root + ".") for root in forbidden)
    }
