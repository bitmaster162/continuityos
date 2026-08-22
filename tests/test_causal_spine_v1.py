from continuityos.gate.causal_spine import (
    BoundedSearchReceipt,
    CausalSpine,
    CausalSpineStatus,
    CurrentPhysicalState,
    EvidenceRef,
    Frontier,
    PivotStatus,
    evaluate_causal_spine,
)


def evidence(tag: str = "x") -> EvidenceRef:
    return EvidenceRef(
        source_system="github",
        object_id=f"object-{tag}",
        revision_id=f"rev-{tag}",
    )


def complete_origin() -> Frontier:
    return Frontier(event_id="origin-1", evidence=(evidence("origin"),))


def complete_pivot() -> Frontier:
    return Frontier(event_id="pivot-1", evidence=(evidence("pivot"),))


def complete_current() -> CurrentPhysicalState:
    return CurrentPhysicalState(
        provider="github",
        state_id="commit:abc",
        observed_at="2026-08-22T07:52:00+07:00",
        evidence=(evidence("current"),),
    )


def test_missing_origin_fails_closed():
    result = evaluate_causal_spine(CausalSpine(
        spine_id="s1", subject_type="project", subject_id="p1",
        pivot_status=PivotStatus.FOUND, pivot=complete_pivot(),
        current_state=complete_current(),
    ))
    assert result.status is CausalSpineStatus.INCOMPLETE_ORIGIN
    assert not result.causal_gate_passed


def test_missing_pivot_fails_closed():
    result = evaluate_causal_spine(CausalSpine(
        spine_id="s2", subject_type="project", subject_id="p1",
        origin=complete_origin(), current_state=complete_current(),
    ))
    assert result.status is CausalSpineStatus.INCOMPLETE_PIVOT


def test_missing_current_physical_state_fails_closed():
    result = evaluate_causal_spine(CausalSpine(
        spine_id="s3", subject_type="project", subject_id="p1",
        origin=complete_origin(), pivot_status=PivotStatus.FOUND,
        pivot=complete_pivot(),
    ))
    assert result.status is CausalSpineStatus.INCOMPLETE_CURRENT_STATE


def test_complete_found_pivot_passes_causal_gate_only():
    result = evaluate_causal_spine(CausalSpine(
        spine_id="s4", subject_type="project", subject_id="p1",
        origin=complete_origin(), pivot_status=PivotStatus.FOUND,
        pivot=complete_pivot(), current_state=complete_current(),
    ))
    assert result.status is CausalSpineStatus.COMPLETE
    assert result.causal_gate_passed
    assert result.grants_canonical_authority is False
    assert result.grants_effect_authority is False


def test_no_pivot_requires_bounded_search_receipt():
    result = evaluate_causal_spine(CausalSpine(
        spine_id="s5", subject_type="project", subject_id="p1",
        origin=complete_origin(), pivot_status=PivotStatus.NO_MATERIAL_PIVOT_FOUND,
        current_state=complete_current(),
    ))
    assert result.status is CausalSpineStatus.SEARCH_INCOMPLETE


def test_no_pivot_with_bounded_completed_search_can_pass():
    result = evaluate_causal_spine(CausalSpine(
        spine_id="s6", subject_type="project", subject_id="p1",
        origin=complete_origin(),
        pivot_status=PivotStatus.NO_MATERIAL_PIVOT_FOUND,
        pivot_search=BoundedSearchReceipt(
            search_id="search-1",
            scope="all accepted project events 2025-01-01..2026-08-22",
            sources_checked=(evidence("search"),), completed=True,
        ),
        current_state=complete_current(),
    ))
    assert result.status is CausalSpineStatus.COMPLETE
    assert result.causal_gate_passed


def test_weak_provenance_does_not_complete_origin():
    weak = EvidenceRef(source_system="github", object_id="obj")
    result = evaluate_causal_spine(CausalSpine(
        spine_id="s7", subject_type="project", subject_id="p1",
        origin=Frontier(event_id="origin", evidence=(weak,)),
        pivot_status=PivotStatus.FOUND, pivot=complete_pivot(),
        current_state=complete_current(),
    ))
    assert result.status is CausalSpineStatus.INCOMPLETE_ORIGIN


def test_contradiction_has_priority_over_completeness():
    result = evaluate_causal_spine(CausalSpine(
        spine_id="s8", subject_type="project", subject_id="p1",
        origin=complete_origin(), pivot_status=PivotStatus.FOUND,
        pivot=complete_pivot(), current_state=complete_current(),
        contradicted=True,
    ))
    assert result.status is CausalSpineStatus.CONTRADICTED
    assert not result.causal_gate_passed


def test_superseded_has_highest_priority():
    result = evaluate_causal_spine(CausalSpine(
        spine_id="s9", subject_type="project", subject_id="p1",
        contradicted=True, superseded=True,
    ))
    assert result.status is CausalSpineStatus.SUPERSEDED


def test_result_dict_never_launders_authority():
    result = evaluate_causal_spine(CausalSpine(
        spine_id="s10", subject_type="project", subject_id="p1",
        origin=complete_origin(), pivot_status=PivotStatus.FOUND,
        pivot=complete_pivot(), current_state=complete_current(),
    )).to_dict()
    assert result["causal_gate_passed"] is True
    assert result["grants_canonical_authority"] is False
    assert result["grants_effect_authority"] is False
