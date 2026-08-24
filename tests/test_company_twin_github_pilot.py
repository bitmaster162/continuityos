from __future__ import annotations

import ast
import copy
import inspect
from pathlib import Path

import pytest

import continuityos.company_twin_github_pilot as pilot
from continuityos.company_twin import replay, validate_dataset
from continuityos.company_twin_ingest import InMemoryIngestStore

ROOT = Path(__file__).resolve().parents[1]
SOURCE_FIXTURE = ROOT / "examples" / "company_twin" / "continuityos_github_p2e_r1.json"


def _artifacts():
    return copy.deepcopy(list(pilot.REAL_PUBLIC_ARTIFACTS))


def _source_fixture():
    if not SOURCE_FIXTURE.exists():
        pytest.skip("source-only real GitHub fixture is not packaged in the wheel")
    return pilot.load_source_fixture(SOURCE_FIXTURE)


def _ingested():
    store, result = pilot.ingest_public_history(_artifacts())
    assert result.receipt["quarantined"] == 0
    return store, result


def test_real_fixture_is_public_continuityos_history_and_matches_embedded_copy():
    data = _source_fixture()
    assert data == pilot.public_fixture_document()
    assert data["repository"] == "bitmaster162/continuityos"
    assert data["source_boundary"] == "PUBLIC_GITHUB_ONLY"
    kinds = {item["artifact_type"] for item in data["artifacts"]}
    assert kinds == {"issue", "pull_request", "commit", "workflow_run"}


def test_real_fixture_pins_p2a_p2c_p2d_merge_lineage():
    artifacts = _artifacts()
    prs = {item["payload"]["number"]: item["payload"] for item in artifacts if item["artifact_type"] == "pull_request"}
    assert prs[124]["merge_commit_sha"] == "72f3811c8bdd9def7b29c79dad4f2172f462af9d"
    assert prs[128]["merge_commit_sha"] == "a3bcc6088a3727d087efa50e9cc0e7e96fcd2b5a"
    assert prs[132]["merge_commit_sha"] == "0429ea2ea836b0fcbcc390ebecb4d7e8fc02ed05"
    assert prs[132]["head_sha"] == "8df3c0d69fbea3cde1e532d0ea77a4407559cdac"


def test_real_fixture_pins_failed_then_fixed_p2d_qualification():
    runs = {item["payload"]["run_id"]: item["payload"] for item in _artifacts() if item["artifact_type"] == "workflow_run"}
    failed = runs[32681056154]
    passed = runs[32681315315]
    assert failed["run_number"] == 895 and failed["conclusion"] == "failure"
    assert failed["head_sha"] == "d85c95d6d3ad964fa66d9d768a17b3677a7b4e60"
    assert len(failed["failing_steps"]) == 2
    assert passed["run_number"] == 897 and passed["conclusion"] == "success"
    assert passed["head_sha"] == "8df3c0d69fbea3cde1e532d0ea77a4407559cdac"


def test_adapter_discards_unknown_safe_fields_instead_of_copying_them():
    artifact = _artifacts()[1]
    artifact["safe_extra"] = "not copied"
    artifact["payload"]["safe_extra"] = "also not copied"
    sanitized = pilot.sanitize_public_artifact(artifact)
    assert "safe_extra" not in sanitized
    assert "safe_extra" not in sanitized["payload"]


@pytest.mark.parametrize(
    "mutator",
    [
        lambda item: item.update(repository="other/repo"),
        lambda item: item.update(public=False),
        lambda item: item.update(artifact_type="release"),
        lambda item: item.update(observed_at="not-a-time"),
        lambda item: item.update(raw_ref="https://example.com/not-github"),
    ],
)
def test_boundary_violations_fail_closed(mutator):
    artifact = _artifacts()[1]
    mutator(artifact)
    with pytest.raises(pilot.PublicGitHubPilotError):
        pilot.sanitize_public_artifact(artifact)


def test_secret_like_fields_fail_closed_even_when_not_allowlisted():
    artifact = _artifacts()[1]
    artifact["payload"]["access_token"] = "should-never-cross-boundary"
    with pytest.raises(pilot.PublicGitHubPilotError):
        pilot.sanitize_public_artifact(artifact)


def test_public_adapter_produces_valid_read_only_p2b_service_envelopes():
    envelopes = pilot.adapt_public_history(_artifacts())
    assert len(envelopes) == len(pilot.REAL_PUBLIC_ARTIFACTS)
    assert all(item["source_system"] == "github_public" for item in envelopes)
    assert all(item["acl"] == {"visibility": "TEAM", "scope": "team:engineering"} for item in envelopes)
    assert all(item["actor"]["actor_kind"] == "SERVICE" for item in envelopes)
    assert all(item["actor"]["authority_class"] == "READ_ONLY" for item in envelopes)
    assert all(item["raw_ref"].startswith("https://github.com/bitmaster162/continuityos/") for item in envelopes)


def test_reingest_is_idempotent_and_preserves_exact_records():
    store = InMemoryIngestStore()
    _, first = pilot.ingest_public_history(_artifacts(), store=store)
    before = store.records
    _, second = pilot.ingest_public_history(list(reversed(_artifacts())), store=store)
    assert first.receipt["accepted"] == len(pilot.REAL_PUBLIC_ARTIFACTS)
    assert second.receipt["accepted"] == 0
    assert second.receipt["idempotent"] == len(pilot.REAL_PUBLIC_ARTIFACTS)
    assert store.records == before


def test_projection_is_valid_p2a_and_keeps_source_records_as_evidence():
    store, _ = _ingested()
    dataset = pilot.project_public_history_to_company_twin(store.records)
    validate_dataset(dataset)
    assert dataset["organization"]["synthetic"] is False
    assert dataset["organization"]["source_boundary"] == "PUBLIC_GITHUB_ONLY"
    assert dataset["inferences"] == []
    assert len(dataset["evidence"]) == len(store.records)
    assert all(item["truth_class"] == "EVIDENCE" for item in dataset["evidence"])
    ingest_ids = {record["id"] for record in store.records}
    assert {item["ingest_record_id"] for item in dataset["evidence"]} == ingest_ids


def test_projection_does_not_invent_merge_rationale():
    store, _ = _ingested()
    dataset = pilot.project_public_history_to_company_twin(store.records)
    decisions = {item["id"]: item for item in dataset["decisions"]}
    assert decisions["dec_merge_pr_124"]["rationale"].endswith("no additional rationale is inferred.")
    assert decisions["dec_merge_pr_128"]["supersedes"] is None
    assert decisions["dec_merge_pr_132"]["supersedes"] is None


def test_historical_replay_changes_as_real_merges_arrive():
    store, _ = _ingested()
    dataset = pilot.project_public_history_to_company_twin(store.records)
    early = replay(dataset, principal_id="principal_director", as_of="2026-08-24T00:30:00Z")
    mid = replay(dataset, principal_id="principal_director", as_of="2026-08-24T01:30:00Z")
    late = replay(dataset, principal_id="principal_director", as_of="2026-08-24T03:00:00Z")
    assert {item["id"] for item in early["decisions"]} == {"dec_merge_pr_124"}
    assert {item["id"] for item in mid["decisions"]} == {"dec_merge_pr_124", "dec_merge_pr_128"}
    assert {item["id"] for item in late["decisions"]} == {
        "dec_merge_pr_124", "dec_merge_pr_128", "dec_merge_pr_132",
    }


def test_real_failure_to_success_becomes_evidence_backed_process_observation():
    store, _ = _ingested()
    dataset = pilot.project_public_history_to_company_twin(store.records)
    observation = next(item for item in dataset["process_observations"] if item["id"] == "proc_p2d_failure_to_success")
    assert observation["truth_class"] == "FACT"
    assert len(observation["evidence_ids"]) == 2
    evidence = {item["id"]: item for item in dataset["evidence"]}
    refs = {evidence[eid]["source_ref"] for eid in observation["evidence_ids"]}
    assert refs == {
        "https://github.com/bitmaster162/continuityos/actions/runs/32681056154",
        "https://github.com/bitmaster162/continuityos/actions/runs/32681315315",
    }


def test_p2d_console_consumes_real_memory_under_existing_policy():
    store, _ = _ingested()
    as_of = "2026-08-24T03:00:00Z"
    director = pilot.build_pilot_console_snapshot(store.records, principal_id="principal_director", as_of=as_of)
    engineer = pilot.build_pilot_console_snapshot(store.records, principal_id="principal_eng_worker", as_of=as_of)
    robot = pilot.build_pilot_console_snapshot(store.records, principal_id="principal_research_robot", as_of=as_of)
    operations = pilot.build_pilot_console_snapshot(store.records, principal_id="principal_ops_worker", as_of=as_of)

    assert director["read_only"] is True and director["decisions"]
    assert engineer["decisions"]
    assert robot["decisions"]
    assert operations["decisions"] == []
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


def test_pilot_core_has_no_live_network_or_subprocess_imports():
    tree = ast.parse(inspect.getsource(pilot))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module)

    forbidden = {"requests", "httpx", "socket", "subprocess", "urllib.request"}
    assert not {
        name
        for name in imported
        if any(name == root or name.startswith(root + ".") for root in forbidden)
    }
