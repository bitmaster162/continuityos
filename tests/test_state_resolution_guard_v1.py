from continuityos.gate.state_resolution import CANDIDATE_SCHEMA, resolve_state


def c(kind, status, when, artifact_id, **extra):
    row = {
        "schema": CANDIDATE_SCHEMA,
        "subject": "P0_SECURITY",
        "artifact_id": artifact_id,
        "kind": kind,
        "status": status,
        "observed_at_utc": when,
    }
    row.update(extra)
    return row


def test_stale_template_open_cannot_override_later_human_decision():
    out = resolve_state([
        c("TEMPLATE", "OPEN", "2026-07-29T21:22:45Z", "P0_RECEIPTS_TEMPLATE"),
        c("AUDIT", "PARTIAL", "2026-07-31T02:00:00Z", "BYTE_AUDIT", evidence_debt=True),
        c("HUMAN_DECISION", "PASS_WITH_CONDITIONS", "2026-07-31T03:00:00Z", "OPERATIONAL_CLOSURE", evidence_debt=True),
    ])
    assert out["terminal"] == "STATE_RESOLUTION_PASS"
    assert out["selected"]["artifact_id"] == "OPERATIONAL_CLOSURE"
    assert out["operational_state"] == "ACCEPTED_WITH_CONDITIONS"
    assert out["production_qualified"] is False
    assert out["evidence_debt"] is True
    assert out["stale_count"] == 2


def test_even_newer_template_cannot_roll_back_human_decision():
    out = resolve_state([
        c("HUMAN_DECISION", "PASS_WITH_CONDITIONS", "2026-07-31T03:00:00Z", "DECISION", evidence_debt=True),
        c("TEMPLATE", "OPEN", "2026-08-09T04:00:00Z", "STALE_TEMPLATE"),
    ])
    assert out["terminal"] == "STATE_RESOLUTION_PASS"
    assert out["selected"]["artifact_id"] == "DECISION"


def test_newer_current_provider_contradiction_blocks_old_decision_without_stealing_authority():
    out = resolve_state([
        c("HUMAN_DECISION", "PASS_WITH_CONDITIONS", "2026-07-31T03:00:00Z", "DECISION", evidence_debt=True),
        c("PROVIDER_READBACK", "OPEN", "2026-08-09T04:00:00Z", "FRESH_READBACK", current_observation=True),
    ])
    assert out["terminal"] == "STATE_RESOLUTION_HOLD"
    assert out["reason"] == "FRESH_CURRENT_CONTRADICTION"
    assert out["selected"]["artifact_id"] == "DECISION"
    assert out["contradictions"][0]["artifact_id"] == "FRESH_READBACK"


def test_latest_human_decision_supersedes_older_human_decision():
    out = resolve_state([
        c("HUMAN_DECISION", "HOLD", "2026-07-31T03:00:00Z", "OLD"),
        c("HUMAN_DECISION", "PASS", "2026-08-01T03:00:00Z", "NEW", production_qualified=True),
    ])
    assert out["terminal"] == "STATE_RESOLUTION_PASS"
    assert out["selected"]["artifact_id"] == "NEW"
    assert out["production_qualified"] is True


def test_equal_authority_equal_time_conflict_holds():
    out = resolve_state([
        c("HUMAN_DECISION", "PASS", "2026-08-01T03:00:00Z", "A"),
        c("HUMAN_DECISION", "REJECT", "2026-08-01T03:00:00Z", "B"),
    ])
    assert out["terminal"] == "STATE_RESOLUTION_HOLD"
    assert out["reason"] == "EQUAL_AUTHORITY_CONTRADICTION"


def test_audit_beats_raw_return_but_not_human_decision():
    out = resolve_state([
        c("REMEDIATION_RETURN", "PASS", "2026-07-30T22:43:00Z", "RETURN", production_qualified=True),
        c("AUDIT", "PARTIAL", "2026-07-31T02:00:00Z", "AUDIT", evidence_debt=True),
    ])
    assert out["selected"]["artifact_id"] == "AUDIT"
    assert out["current_status"] == "PARTIAL"
    assert out["production_qualified"] is False


def test_malformed_candidate_revises_fail_closed():
    row = c("TEMPLATE", "OPEN", "not-a-time", "BAD")
    out = resolve_state([row])
    assert out["terminal"] == "STATE_RESOLUTION_REVISE"
    assert out["effects"]["can_trade"] is False
    assert out["effects"]["capital_permission"] == "DENY"


def test_multiple_subjects_revise():
    a = c("TEMPLATE", "OPEN", "2026-08-01T00:00:00Z", "A")
    b = c("TEMPLATE", "OPEN", "2026-08-01T00:00:01Z", "B")
    b["subject"] = "OTHER"
    out = resolve_state([a, b])
    assert out["terminal"] == "STATE_RESOLUTION_REVISE"
    assert out["reason"] == "MULTIPLE_SUBJECTS"


def test_no_evidence_holds():
    out = resolve_state([])
    assert out["terminal"] == "STATE_RESOLUTION_HOLD"
    assert out["reason"] == "NO_EVIDENCE"


def test_pass_with_conditions_never_becomes_production_qualified():
    out = resolve_state([
        c("HUMAN_DECISION", "PASS_WITH_CONDITIONS", "2026-08-01T00:00:00Z", "X", production_qualified=True, evidence_debt=False)
    ])
    assert out["terminal"] == "STATE_RESOLUTION_PASS"
    assert out["production_qualified"] is False
