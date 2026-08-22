from continuityos.gate.causal_spine import (
    BoundedSearchReceipt,
    CausalSpine,
    CausalSpineStatus,
    CurrentPhysicalState,
    EvidenceRef,
    Frontier,
    PivotStatus,
    build_evaluation_event,
    evaluate_causal_spine,
    verify_evaluation_event,
)

GOOD_SHA = "a" * 64


def evidence(tag: str = "x", source: str = "github") -> EvidenceRef:
    return EvidenceRef(
        source_system=source,
        object_id=f"object-{tag}",
        revision_id=f"rev-{tag}",
        sha256=GOOD_SHA,
        locator=f"{source}://{tag}",
    )


def complete_origin() -> Frontier:
    return Frontier(event_id="origin-1", evidence=(evidence("origin"),))


def complete_pivot() -> Frontier:
    return Frontier(event_id="pivot-1", evidence=(evidence("pivot"),))


def complete_current() -> CurrentPhysicalState:
    return CurrentPhysicalState(
        provider="github",
        state_id="commit:abc",
        observed_at="2026-08-22T00:52:00Z",
        evidence=(evidence("current"),),
        resolution_artifact_id="github-branch-readback",
        resolution_artifact_sha256=GOOD_SHA,
    )


def state_resolution(
    *,
    terminal: str = "STATE_RESOLUTION_PASS",
    kind: str = "PROVIDER_READBACK",
    artifact_id: str = "github-branch-readback",
    artifact_sha256: str = GOOD_SHA,
    observed_at_utc: str = "2026-08-22T00:52:00Z",
    reason: str | None = None,
):
    out = {
        "terminal": terminal,
        "selected": {
            "kind": kind,
            "status": "PASS",
            "artifact_id": artifact_id,
            "artifact_sha256": artifact_sha256,
            "observed_at_utc": observed_at_utc,
        },
    }
    if reason is not None:
        out["reason"] = reason
    return out


def complete_spine(**overrides) -> CausalSpine:
    values = {
        "spine_id": "s1",
        "subject_type": "project",
        "subject_id": "p1",
        "origin": complete_origin(),
        "pivot_status": PivotStatus.FOUND,
        "pivot": complete_pivot(),
        "current_state": complete_current(),
    }
    values.update(overrides)
    return CausalSpine(**values)


def test_missing_origin_fails_closed():
    result = evaluate_causal_spine(
        complete_spine(origin=None), current_state_resolution=state_resolution()
    )
    assert result.status is CausalSpineStatus.INCOMPLETE_ORIGIN
    assert result.terminal == "CAUSAL_SPINE_INCOMPLETE"
    assert not result.causal_gate_passed


def test_missing_pivot_fails_closed():
    result = evaluate_causal_spine(
        complete_spine(pivot_status=PivotStatus.UNKNOWN, pivot=None),
        current_state_resolution=state_resolution(),
    )
    assert result.status is CausalSpineStatus.INCOMPLETE_PIVOT


def test_missing_current_physical_state_fails_closed():
    result = evaluate_causal_spine(
        complete_spine(current_state=None), current_state_resolution=state_resolution()
    )
    assert result.status is CausalSpineStatus.INCOMPLETE_CURRENT_STATE


def test_complete_requires_state_resolution():
    result = evaluate_causal_spine(complete_spine())
    assert result.status is CausalSpineStatus.INCOMPLETE_CURRENT_STATE
    assert result.reason_code == "CURRENT_STATE_RESOLUTION_REQUIRED"


def test_complete_found_pivot_passes_causal_gate_only():
    result = evaluate_causal_spine(
        complete_spine(), current_state_resolution=state_resolution()
    )
    assert result.status is CausalSpineStatus.COMPLETE
    assert result.causal_gate_passed
    payload = result.to_dict()
    assert payload["terminal"] == "CAUSAL_SPINE_PASS"
    assert payload["grants_source_authority"] is False
    assert payload["grants_canonical_authority"] is False
    assert payload["grants_merge_authority"] is False
    assert payload["grants_deploy_authority"] is False
    assert payload["grants_runtime_authority"] is False
    assert payload["grants_effect_authority"] is False
    assert payload["effects"]["can_trade"] is False
    assert payload["effects"]["capital_permission"] == "DENY"
    assert payload["effects"]["deployment"] is False


def test_no_pivot_requires_bounded_search_receipt():
    result = evaluate_causal_spine(
        complete_spine(
            pivot_status=PivotStatus.NO_MATERIAL_PIVOT_FOUND,
            pivot=None,
            pivot_search=None,
        ),
        current_state_resolution=state_resolution(),
    )
    assert result.status is CausalSpineStatus.SEARCH_INCOMPLETE


def test_no_pivot_with_bounded_completed_search_can_pass():
    result = evaluate_causal_spine(
        complete_spine(
            pivot_status=PivotStatus.NO_MATERIAL_PIVOT_FOUND,
            pivot=None,
            pivot_search=BoundedSearchReceipt(
                search_id="search-1",
                scope="all accepted project events 2025-01-01..2026-08-22",
                sources_checked=(evidence("search"),),
                completed=True,
                completed_at="2026-08-22T00:50:00Z",
            ),
        ),
        current_state_resolution=state_resolution(),
    )
    assert result.status is CausalSpineStatus.COMPLETE
    assert result.causal_gate_passed


def test_weak_provenance_does_not_complete_origin():
    weak = EvidenceRef(source_system="github", object_id="obj")
    result = evaluate_causal_spine(
        complete_spine(origin=Frontier(event_id="origin", evidence=(weak,))),
        current_state_resolution=state_resolution(),
    )
    assert result.status is CausalSpineStatus.INCOMPLETE_ORIGIN


def test_uppercase_sha_is_not_accepted_as_hash_binding():
    weak = EvidenceRef(source_system="github", object_id="obj", sha256="A" * 64)
    result = evaluate_causal_spine(
        complete_spine(origin=Frontier(event_id="origin", evidence=(weak,))),
        current_state_resolution=state_resolution(),
    )
    assert result.status is CausalSpineStatus.INCOMPLETE_ORIGIN


def test_current_state_must_be_provider_readback():
    result = evaluate_causal_spine(
        complete_spine(),
        current_state_resolution=state_resolution(kind="HUMAN_DECISION"),
    )
    assert result.status is CausalSpineStatus.INCOMPLETE_CURRENT_STATE
    assert result.reason_code == "CURRENT_STATE_NOT_PROVIDER_READBACK"


def test_current_state_resolution_sha_mismatch_fails():
    result = evaluate_causal_spine(
        complete_spine(),
        current_state_resolution=state_resolution(artifact_sha256="b" * 64),
    )
    assert result.status is CausalSpineStatus.INCOMPLETE_CURRENT_STATE
    assert result.reason_code == "CURRENT_STATE_ARTIFACT_SHA_MISMATCH"


def test_current_state_observation_time_mismatch_fails():
    result = evaluate_causal_spine(
        complete_spine(),
        current_state_resolution=state_resolution(observed_at_utc="2026-08-22T00:53:00Z"),
    )
    assert result.status is CausalSpineStatus.INCOMPLETE_CURRENT_STATE
    assert result.reason_code == "CURRENT_STATE_OBSERVATION_TIME_MISMATCH"


def test_fresh_current_contradiction_is_not_laundered():
    result = evaluate_causal_spine(
        complete_spine(),
        current_state_resolution={
            "terminal": "STATE_RESOLUTION_HOLD",
            "reason": "FRESH_CURRENT_CONTRADICTION",
            "selected": None,
        },
    )
    assert result.status is CausalSpineStatus.CONTRADICTED
    assert result.terminal == "CAUSAL_SPINE_INCOMPLETE"


def test_naive_current_timestamp_fails_closed():
    current = complete_current()
    bad = CurrentPhysicalState(
        provider=current.provider,
        state_id=current.state_id,
        observed_at="2026-08-22T00:52:00",
        evidence=current.evidence,
        resolution_artifact_id=current.resolution_artifact_id,
        resolution_artifact_sha256=current.resolution_artifact_sha256,
    )
    result = evaluate_causal_spine(
        complete_spine(current_state=bad), current_state_resolution=state_resolution()
    )
    assert result.status is CausalSpineStatus.INCOMPLETE_CURRENT_STATE


def test_current_evidence_provider_must_match_provider():
    current = complete_current()
    bad = CurrentPhysicalState(
        provider="vercel",
        state_id=current.state_id,
        observed_at=current.observed_at,
        evidence=current.evidence,
        resolution_artifact_id=current.resolution_artifact_id,
        resolution_artifact_sha256=current.resolution_artifact_sha256,
    )
    result = evaluate_causal_spine(
        complete_spine(current_state=bad), current_state_resolution=state_resolution()
    )
    assert result.status is CausalSpineStatus.INCOMPLETE_CURRENT_STATE


def test_contradiction_flag_requires_bound_evidence():
    result = evaluate_causal_spine(
        complete_spine(contradicted=True), current_state_resolution=state_resolution()
    )
    assert result.status is CausalSpineStatus.CONTRADICTED
    assert result.reason_code == "CONTRADICTION_EVIDENCE_MISSING"


def test_supersession_requires_bound_evidence():
    result = evaluate_causal_spine(
        complete_spine(superseded=True), current_state_resolution=state_resolution()
    )
    assert result.status is CausalSpineStatus.SUPERSEDED
    assert result.reason_code == "SUPERSESSION_EVIDENCE_MISSING"


def test_event_hash_readback_and_tamper_rejection():
    spine = complete_spine()
    result = evaluate_causal_spine(spine, current_state_resolution=state_resolution())
    event1 = build_evaluation_event(
        spine,
        result,
        sequence=0,
        actor_id="gate",
        recorded_at_utc="2026-08-22T01:00:00Z",
    )
    assert verify_evaluation_event(event1)
    event2 = build_evaluation_event(
        spine,
        result,
        sequence=1,
        actor_id="gate",
        recorded_at_utc="2026-08-22T01:01:00Z",
        prev_event_sha256=event1["event_sha256"],
    )
    assert verify_evaluation_event(
        event2, expected_prev_event_sha256=event1["event_sha256"]
    )
    tampered = dict(event2)
    tampered["subject_id"] = "other"
    assert not verify_evaluation_event(
        tampered, expected_prev_event_sha256=event1["event_sha256"]
    )
