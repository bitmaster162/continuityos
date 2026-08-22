"""CausalBench v0 — deterministic causal completeness regression corpus."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from continuityos.gate.causal_spine import (
    BoundedSearchReceipt,
    CausalSpine,
    CurrentPhysicalState,
    EvidenceRef,
    Frontier,
    PivotStatus,
    build_evaluation_event,
    evaluate_causal_spine,
    verify_evaluation_event,
)

SHA = "a" * 64


def ev(tag: str, source: str = "github") -> EvidenceRef:
    return EvidenceRef(
        source,
        f"obj-{tag}",
        revision_id=f"rev-{tag}",
        sha256=SHA,
        locator=f"{source}://{tag}",
    )


def origin() -> Frontier:
    return Frontier("origin-1", (ev("origin"),))


def pivot() -> Frontier:
    return Frontier("pivot-1", (ev("pivot"),))


def current() -> CurrentPhysicalState:
    return CurrentPhysicalState(
        provider="github",
        state_id="commit:abc",
        observed_at="2026-08-22T00:52:00Z",
        evidence=(ev("current"),),
        resolution_artifact_id="github-readback",
        resolution_artifact_sha256=SHA,
    )


def resolution(**overrides):
    selected = {
        "kind": "PROVIDER_READBACK",
        "status": "PASS",
        "artifact_id": "github-readback",
        "artifact_sha256": SHA,
        "observed_at_utc": "2026-08-22T00:52:00Z",
    }
    selected.update(overrides.pop("selected", {}))
    out = {"terminal": "STATE_RESOLUTION_PASS", "selected": selected}
    out.update(overrides)
    return out


def spine(**overrides):
    data = dict(
        spine_id="bench",
        subject_type="project",
        subject_id="p1",
        origin=origin(),
        pivot_status=PivotStatus.FOUND,
        pivot=pivot(),
        current_state=current(),
    )
    data.update(overrides)
    return CausalSpine(**data)


def run():
    no_pivot = BoundedSearchReceipt(
        "search-1",
        "all accepted project events",
        (ev("search"),),
        True,
        "2026-08-22T00:50:00Z",
    )
    cases = [
        ("missing-origin", spine(origin=None), resolution(), "INCOMPLETE_ORIGIN"),
        ("missing-pivot", spine(pivot_status=PivotStatus.UNKNOWN, pivot=None), resolution(), "INCOMPLETE_PIVOT"),
        ("missing-current", spine(current_state=None), resolution(), "INCOMPLETE_CURRENT_STATE"),
        ("no-pivot-unproven", spine(pivot_status=PivotStatus.NO_MATERIAL_PIVOT_FOUND, pivot=None, pivot_search=None), resolution(), "SEARCH_INCOMPLETE"),
        ("found-pivot-complete", spine(), resolution(), "COMPLETE"),
        ("bounded-no-pivot-complete", spine(pivot_status=PivotStatus.NO_MATERIAL_PIVOT_FOUND, pivot=None, pivot_search=no_pivot), resolution(), "COMPLETE"),
        ("non-provider-current", spine(), resolution(selected={"kind": "HUMAN_DECISION"}), "INCOMPLETE_CURRENT_STATE"),
        ("fresh-current-contradiction", spine(), {"terminal": "STATE_RESOLUTION_HOLD", "reason": "FRESH_CURRENT_CONTRADICTION", "selected": None}, "CONTRADICTED"),
    ]
    rows = []
    passed = True
    for case_id, candidate, resolved, expected in cases:
        result = evaluate_causal_spine(candidate, current_state_resolution=resolved)
        ok = result.status.value == expected
        rows.append({"case_id": case_id, "expected": expected, "observed": result.status.value, "ok": ok})
        passed &= ok

    good = evaluate_causal_spine(spine(), current_state_resolution=resolution())
    event = build_evaluation_event(
        spine(),
        good,
        sequence=0,
        actor_id="causalbench",
        recorded_at_utc="2026-08-22T01:00:00Z",
    )
    event_ok = verify_evaluation_event(event)
    tampered = dict(event)
    tampered["subject_id"] = "tampered"
    tamper_rejected = not verify_evaluation_event(tampered)
    passed &= event_ok and tamper_rejected
    return {
        "schema": "causalbench-v0-receipt-v1",
        "status": "PASS" if passed else "FAIL",
        "cases": rows,
        "event_readback_ok": event_ok,
        "tamper_rejected": tamper_rejected,
        "effects": good.to_dict()["effects"],
    }


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--json-out")
    args = parser.parse_args(argv)
    receipt = run()
    print(json.dumps(receipt, indent=2, sort_keys=True))
    if args.json_out:
        Path(args.json_out).write_text(
            json.dumps(receipt, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    return 0 if receipt["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
