"""Legacy Twin must report bounded evidence, never invented certainty or permission."""
from __future__ import annotations

import json
import socket
import time

import pytest

from continuityos.embed import HashingEmbedder
from continuityos.memory import Memory
from continuityos.twin import Twin


@pytest.fixture
def memory(tmp_path, monkeypatch):
    def no_network(*args, **kwargs):
        raise AssertionError("local Twin regression must not use a network")

    monkeypatch.setattr(socket.socket, "connect", no_network)
    memory = Memory(str(tmp_path / "memory.db"), embedder=HashingEmbedder())
    try:
        yield memory
    finally:
        memory.store.con.close()


def test_empty_memory_does_not_claim_alignment_or_prediction_confidence(memory):
    twin = Twin(memory)
    prediction = twin.predict("ship the release")
    alignment = twin.alignment("ship the release")
    assert "confidence" not in prediction
    assert prediction["evidence_status"] == "NO_EVIDENCE"
    assert prediction["retrieval_signal"]["strongest_score"] is None
    assert prediction["prediction_status"] == "NOT_A_BEHAVIORAL_PREDICTION"
    assert alignment["evidence_status"] == "NO_EVIDENCE"
    assert alignment["verdict_code"] == "INSUFFICIENT_EVIDENCE"
    assert alignment["verdict"].startswith("UNKNOWN")
    assert alignment["authority_granted"] is False


def test_prediction_has_stable_ids_source_metadata_and_uncalibrated_signal(memory):
    record_id = memory.remember("release approval belongs to Robert", namespace="rules",
                                meta={"source_id": "decision:17", "source_version": "R3"})
    prediction = Twin(memory).predict("release approval")
    evidence = prediction["evidence"][0]
    assert evidence["id"] == record_id and evidence["memory_ref"] == f"mem:{record_id}"
    assert evidence["current_status"] == "CURRENT_AT_SNAPSHOT"
    assert evidence["provenance"]["source"] == {"source_id": "decision:17", "source_version": "R3"}
    assert evidence["provenance"]["origin_verified"] is False
    assert evidence["acceptance_status"] == "RECORDED_NOT_VERIFIED"
    assert prediction["retrieval_signal"]["score_is_probability"] is False
    assert prediction["coverage"]["exhaustive"] is False
    assert "confidence" not in prediction


def test_legacy_alignment_uses_current_rules_and_is_only_a_keyword_review(memory):
    old = memory.remember("never ship release", namespace="rules")
    current = memory.supersede(old, "ship release after review", namespace="rules")
    now = time.time()
    memory.remember("never ship release future", namespace="rules", valid_from=now + 3600)
    memory.remember("never ship release expired", namespace="rules", valid_to=now - 1)
    memory.remember("never ship release revoked", namespace="rules", meta={"status": "REVOKED"})
    result = Twin(memory).alignment("ship release", k=10)
    assert [rule["id"] for rule in result["relevant_rules"]] == [current]
    assert result["possible_conflicts"] == []
    assert result["verdict_code"] == "NO_HEURISTIC_CONFLICT_FOUND"
    assert result["semantic_compatibility"] == "UNVERIFIED"
    assert not result["verdict"].startswith("✓")


def test_prohibitive_rule_keeps_evidence_ref_for_existing_gate_callers(memory):
    record_id = memory.remember("Нельзя запускать сервер без решения", namespace="canon")
    result = Twin(memory).alignment("запускать сервер")
    assert result["verdict_code"] == "REVIEW_PROHIBITIVE_RULE"
    assert result["possible_conflicts"][0]["id"] == record_id
    assert result["possible_conflicts"][0]["rule"] == "Нельзя запускать сервер без решения"
    assert result["check_kind"] == "KEYWORD_NEGATION_HEURISTIC"


def test_project_and_subject_filters_happen_before_retrieval_limits(memory):
    for index in range(55):
        memory.remember(f"release deployment foreign restriction {index}", namespace="rules",
                        meta={"project": "foreign", "subject": "Other"})
    global_id = memory.remember("release deployment global constraint", namespace="canon")
    project_id = memory.remember("release deployment Robert decision", namespace="rules",
                                 meta={"project": "COS", "subject": "Robert"})
    other_id = memory.remember("release deployment other subject", namespace="rules",
                               meta={"project": "COS", "subject": "Other"})
    result = Twin(memory, project="COS", subject="Robert").predict("release deployment", k=5)
    ids = {item["id"] for item in result["evidence"]}
    assert ids == {global_id, project_id} and other_id not in ids
    assert all("foreign" not in item["text"] for item in result["evidence"])


def test_unreviewed_candidates_are_visible_but_do_not_become_stance_or_rules(memory):
    candidate_id = memory.remember("never ship release", namespace="rules", meta={
        "accepted": False, "review_status": "UNREVIEWED", "admission_status": "CANDIDATE",
        "source_id": "import:1",
    })
    twin = Twin(memory)
    prediction = twin.predict("ship release")
    alignment = twin.alignment("ship release")
    assert prediction["evidence"] == [] and alignment["relevant_rules"] == []
    assert alignment["possible_conflicts"] == []
    assert prediction["evidence_status"] == "INSUFFICIENT_ACCEPTED_EVIDENCE"
    assert alignment["verdict_code"] == "INSUFFICIENT_ACCEPTED_EVIDENCE"
    assert prediction["candidate_evidence"][0]["id"] == candidate_id
    assert "never ship release" not in prediction["predicted_stance"]
    assert twin.profile()["rules"] == []


def test_many_candidates_cannot_starve_recorded_manual_rule(memory):
    for index in range(55):
        memory.remember(f"ship release candidate {index}", namespace="rules", meta={"accepted": False})
    rule_id = memory.remember("ship release recorded decision", namespace="rules")
    result = Twin(memory).predict("ship release", k=1)
    assert [item["id"] for item in result["evidence"]] == [rule_id]
    assert result["candidate_evidence"]


def test_profile_reports_current_source_ids_and_explicit_omissions(memory):
    old_id = memory.remember("retired identity", namespace="identity")
    current_id = memory.supersede(old_id, "current identity", namespace="identity")
    for index in range(3):
        memory.remember(f"rule {index}", namespace="rules")
    profile = Twin(memory).profile(k=1)
    assert profile["identity"] == ["current identity"]
    assert profile["evidence"]["identity"][0]["id"] == current_id
    assert profile["coverage"]["rules"]["omitted"] == 2
    assert profile["behavior_validated"] is False


def test_alignment_is_one_snapshot_and_next_call_sees_supersession(memory, monkeypatch):
    old_id = memory.remember("never ship release", namespace="rules")
    writer = Memory(memory.store.path, embedder=HashingEmbedder())
    recall = memory.recall
    changed = False

    def race(*args, **kwargs):
        nonlocal changed
        result = recall(*args, **kwargs)
        if kwargs.get("namespace") == "rules" and not changed:
            changed = True
            meta = json.loads(writer.store.get(old_id)["meta"])
            meta["superseded_by"] = 999
            meta["valid_to"] = time.time()
            writer.store.update_meta(old_id, meta)
        return result

    monkeypatch.setattr(memory, "recall", race)
    try:
        first = Twin(memory).alignment("ship release")
        assert [item["id"] for item in first["relevant_rules"]] == [old_id]
        assert first["authority_granted"] is False
        second = Twin(memory).alignment("ship release")
        assert second["relevant_rules"] == [] and second["possible_conflicts"] == []
        assert second["verdict_code"] == "INSUFFICIENT_EVIDENCE"
    finally:
        writer.store.con.close()
