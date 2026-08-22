from continuityos.gate.causal_spine import (
    CausalSpine,
    CausalSpineStatus,
    CurrentPhysicalState,
    EvidenceRef,
    Frontier,
    PivotStatus,
    evaluate_causal_spine,
)

SHA = "a" * 64


def test_invalid_sha_is_rejected_even_when_revision_is_bound():
    weak = EvidenceRef(
        source_system="github",
        object_id="origin-object",
        revision_id="rev-1",
        sha256="A" * 64,
    )
    good = EvidenceRef(
        source_system="github",
        object_id="current-object",
        revision_id="rev-current",
        sha256=SHA,
    )
    spine = CausalSpine(
        spine_id="strict-1",
        subject_type="project",
        subject_id="p1",
        origin=Frontier(event_id="origin", evidence=(weak,)),
        pivot_status=PivotStatus.FOUND,
        pivot=Frontier(event_id="pivot", evidence=(good,)),
        current_state=CurrentPhysicalState(
            provider="github",
            state_id="commit:abc",
            observed_at="2026-08-22T00:52:00Z",
            evidence=(good,),
            resolution_artifact_id="github-readback",
            resolution_artifact_sha256=SHA,
        ),
    )
    resolution = {
        "terminal": "STATE_RESOLUTION_PASS",
        "selected": {
            "kind": "PROVIDER_READBACK",
            "status": "PASS",
            "artifact_id": "github-readback",
            "artifact_sha256": SHA,
            "observed_at_utc": "2026-08-22T00:52:00Z",
        },
    }
    result = evaluate_causal_spine(spine, current_state_resolution=resolution)
    assert result.status is CausalSpineStatus.INCOMPLETE_ORIGIN
