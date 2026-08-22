import hashlib
import json

import pytest

from continuityos.memory_federation import (
    FederationContractError,
    MemoryFederation,
    StaticAdapter,
    resolve_candidates,
)


def _digest(payload):
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _query(*, source_classes=(), project_ids=(), include_conflicts=True):
    return {
        "schema": "continuityos.memory_federation_query/v2",
        "query_id": "scope-q",
        "query": "scope test",
        "resolution_mode": "EVIDENCE",
        "scope": ["RAW_CUSTODY", "FROZEN_EVIDENCE"],
        "as_of_valid_time": None,
        "observed_before_transaction_time": None,
        "source_classes": list(source_classes),
        "project_ids": list(project_ids),
        "include_conflicts": include_conflicts,
        "include_superseded": False,
        "limit": 20,
        "requested_effect": False,
        "created_at": "2026-08-22T15:00:00+00:00",
    }


def _candidate(
    candidate_id,
    *,
    adapter_id="GOOGLE_DRIVE_CONNECTOR",
    surface="RAW_CUSTODY",
    authority="EVIDENCE_ONLY",
    binding="DIRECT_PROVIDER_OBJECT",
    freshness="FRESH_PROVIDER",
    payload=None,
    source_class=None,
    project_ids=None,
):
    payload = payload or {"value": candidate_id}
    row = {
        "candidate_id": candidate_id,
        "adapter_id": adapter_id,
        "semantic_key": "scope.subject",
        "fact_class": "SEMANTIC",
        "subject_ref": "subject:scope",
        "payload_digest": _digest(payload),
        "binding_strength": binding,
        "source_occurrence_id": "occ:" + candidate_id,
        "result": {
            "schema": "continuityos.memory_federation_result/v1",
            "result_id": "result:" + candidate_id,
            "query_id": "scope-q",
            "status": "HIT",
            "surface": surface,
            "stable_source_ref": "source:" + candidate_id,
            "raw_artifact_ref": "artifact:" + candidate_id,
            "provenance_chain": ["prov:" + candidate_id],
            "valid_time": {"start": "2026-01-01T00:00:00+00:00", "end": None},
            "transaction_time": {
                "observed_at": "2026-08-22T14:00:00+00:00",
                "recorded_at": "2026-08-22T14:00:00+00:00",
            },
            "freshness": freshness,
            "confidence": 0.9,
            "contradiction_state": "NONE_KNOWN",
            "supersession_state": "CURRENT",
            "authority_class": authority,
            "payload": payload,
            "abstain_reason": None,
            "effect_authority": "NONE",
        },
    }
    if source_class is not None:
        row["source_class"] = source_class
    if project_ids is not None:
        row["project_ids"] = list(project_ids)
    return row


def test_project_filter_rejects_cross_project_candidate():
    got = resolve_candidates(
        _query(project_ids=["P1"]),
        [_candidate("c1", project_ids=["P2"])],
    )
    assert got["decision"] == "ABSTAIN"
    assert got["discarded"] == [{"candidate_id": "c1", "reason": "PROJECT_SCOPE_FILTERED"}]


def test_project_filter_fails_closed_when_candidate_scope_unproven():
    got = resolve_candidates(_query(project_ids=["P1"]), [_candidate("c1")])
    assert got["decision"] == "ABSTAIN"
    assert got["discarded"] == [{"candidate_id": "c1", "reason": "PROJECT_SCOPE_UNPROVEN"}]


def test_project_filter_accepts_intersection():
    got = resolve_candidates(
        _query(project_ids=["P1"]),
        [_candidate("c1", project_ids=["P0", "P1"])],
    )
    assert got["decision"] == "HIT"
    assert got["selected_candidate_ids"] == ["c1"]


def test_source_class_filter_rejects_mismatch_and_unproven():
    mismatch = resolve_candidates(
        _query(source_classes=["GOOGLE_DRIVE"]),
        [_candidate("c1", source_class="CHATGPT_LIBRARY")],
    )
    assert mismatch["decision"] == "ABSTAIN"
    assert mismatch["discarded"] == [{"candidate_id": "c1", "reason": "SOURCE_CLASS_FILTERED"}]

    unproven = resolve_candidates(
        _query(source_classes=["GOOGLE_DRIVE"]),
        [_candidate("c1")],
    )
    assert unproven["decision"] == "ABSTAIN"
    assert unproven["discarded"] == [{"candidate_id": "c1", "reason": "SOURCE_CLASS_UNPROVEN"}]


def test_adapter_cannot_spoof_surface_capability():
    row = _candidate("c1", surface="R1_4R")
    with pytest.raises(FederationContractError, match="may not emit surface"):
        resolve_candidates(_query(), [row])


def test_adapter_cannot_spoof_direct_binding_capability():
    row = _candidate(
        "c1",
        adapter_id="ROBERT_MEMORY_ROUTER_V11",
        surface="R1_4R_ROUTER",
        binding="DIRECT_PROVIDER_OBJECT",
        freshness="SEALED_HISTORICAL",
    )
    with pytest.raises(FederationContractError, match="may not emit binding_strength"):
        resolve_candidates(_query(), [row])


def test_adapter_cannot_spoof_freshness_capability():
    row = _candidate("c1", freshness="FRESH_LOCAL_RUNTIME")
    with pytest.raises(FederationContractError, match="may not emit freshness"):
        resolve_candidates(_query(), [row])


def test_include_conflicts_false_redacts_payload_but_preserves_conflict_decision():
    a = _candidate("a", payload={"value": 1})
    b = _candidate("b", payload={"value": 2})
    gateway = MemoryFederation([
        StaticAdapter("GOOGLE_DRIVE_CONNECTOR", (a, b)),
    ])
    out = gateway.read(_query(include_conflicts=False))
    assert out.resolution["decision"] == "CONFLICT"
    assert set(out.resolution["conflict_candidate_ids"]) == {"a", "b"}
    assert out.response["results"] == []
    assert out.response["gateway_status"] == "PASS_WITH_CONDITIONS"
