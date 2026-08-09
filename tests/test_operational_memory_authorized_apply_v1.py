from __future__ import annotations

import hashlib
import json
from pathlib import Path

import continuityos.current_effect_boundary as boundary
from continuityos.current_memory_delta import REQUEST_SCHEMA, build_memory_delta_proposal_from_db
from continuityos.operational_memory import OperationalMemory
import continuityos.operational_memory_apply as applymod

PROJECT = "project:continuityos"
REF = {"sha256": "a" * 64, "locator": "evidence://r37"}


def clear_current(monkeypatch):
    for name in (
        boundary.ENV_CHALLENGE,
        boundary.ENV_CHALLENGE_SHA,
        boundary.ENV_ACK,
        boundary.ENV_REQUIRED,
    ):
        monkeypatch.delenv(name, raising=False)


def set_current(monkeypatch):
    monkeypatch.setenv(boundary.ENV_CHALLENGE, "challenge.json")
    monkeypatch.setenv(boundary.ENV_CHALLENGE_SHA, "b" * 64)
    monkeypatch.setenv(boundary.ENV_ACK, "ack.json")
    monkeypatch.setenv(boundary.ENV_REQUIRED, "1")
    monkeypatch.setattr(
        boundary,
        "verify_current_runtime_binding",
        lambda *args, **kwargs: {
            "terminal": "CURRENT_RUNTIME_BINDING_PASS",
            "binding_verified": True,
            "authority_generation": "R64",
            "challenge_id": "c" * 64,
            "challenge_sha256": "b" * 64,
            "ack_sha256": "d" * 64,
        },
    )


def write_json(path: Path, value) -> str:
    payload = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    path.write_text(payload, encoding="utf-8")
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def seed_db(path: Path, *, blocker: bool = False, terminal_decision: bool = False):
    with OperationalMemory(str(path)) as memory:
        memory.record_claim(
            subject_id=PROJECT,
            predicate="project.goal",
            value="make project memory operational",
            scope="global",
            evidence_state="SOURCE_BACKED",
            evidence_refs=[REF],
            actor_type="DETERMINISTIC_CONTROLLER",
            actor_id="seed",
            valid_from="2026-08-09T10:00:00+00:00",
            recorded_at="2026-08-09T10:00:00+00:00",
        )
        memory.record_claim(
            subject_id=PROJECT,
            predicate="project.status",
            value={"state": "BEFORE"},
            scope="global",
            evidence_state="SOURCE_BACKED",
            evidence_refs=[REF],
            actor_type="DETERMINISTIC_CONTROLLER",
            actor_id="seed",
            valid_from="2026-08-09T10:01:00+00:00",
            recorded_at="2026-08-09T10:01:00+00:00",
        )
        if blocker:
            memory.record_claim(
                subject_id=PROJECT,
                predicate="project.blocker",
                value={"id": "existing", "title": "existing blocker", "status": "OPEN"},
                scope="existing",
                evidence_state="SOURCE_BACKED",
                evidence_refs=[REF],
                actor_type="DETERMINISTIC_CONTROLLER",
                actor_id="seed",
                valid_from="2026-08-09T10:02:00+00:00",
                recorded_at="2026-08-09T10:02:00+00:00",
            )
        if terminal_decision:
            memory.record_decision(
                subject_id=PROJECT,
                decision_type="NEXT_ACTION",
                state="HOLD",
                value={"action": "old hold"},
                rationale="old hold",
                authority_class="DETERMINISTIC_CONTROLLER",
                authority_id="seed",
                authority_ref="seed://decision",
                evidence_refs=[REF],
                recorded_at="2026-08-09T10:03:00+00:00",
            )
        assert memory.verify()["ok"] is True
        return memory.projection()


def one_claim(projection, predicate, scope="global"):
    rows = [
        row for row in projection["claims"]
        if row["subject_id"] == PROJECT and row["predicate"] == predicate and row["scope"] == scope
    ]
    assert len(rows) == 1
    return rows[0]


def one_decision(projection, decision_type):
    rows = [
        row for row in projection["decisions"]
        if row["subject_id"] == PROJECT and row["decision_type"] == decision_type
    ]
    assert len(rows) == 1
    return rows[0]


def snapshot(db: Path):
    with OperationalMemory(str(db), read_only=True) as memory:
        assert memory.verify()["ok"] is True
        return memory.projection(), {
            "events": memory.con.execute("SELECT COUNT(*) FROM events").fetchone()[0],
            "claims": memory.con.execute("SELECT COUNT(*) FROM claims").fetchone()[0],
            "decisions": memory.con.execute("SELECT COUNT(*) FROM decisions").fetchone()[0],
            "apply_events": memory.con.execute(
                "SELECT COUNT(*) FROM events WHERE event_type='MEMORY_DELTA_APPLIED'"
            ).fetchone()[0],
        }


def proposal_file(db: Path, tmp_path: Path, operations, name="proposal.json"):
    proposal = build_memory_delta_proposal_from_db(
        db,
        {
            "schema": REQUEST_SCHEMA,
            "project_id": PROJECT,
            "operations": operations,
            "rationale": "R37 test proposal",
        },
    )
    assert proposal["terminal"] == "CURRENT_MEMORY_DELTA_PROPOSAL_PASS", proposal
    path = tmp_path / name
    write_json(path, proposal)
    return proposal, path


def auth_file(proposal, proposal_path: Path, tmp_path: Path, name="authorization.json"):
    auth = {
        "schema": applymod.AUTH_SCHEMA,
        "decision": applymod.AUTH_DECISION,
        "proposal_id": proposal["proposal_id"],
        "proposal_file_sha256": hashlib.sha256(proposal_path.read_bytes()).hexdigest(),
        "project_id": proposal["project_id"],
        "base_projection_sha256": proposal["base"]["projection_sha256"],
        "base_event_cursor": proposal["base"]["event_cursor"],
        "base_event_chain_head": proposal["base"]["event_chain_head"],
        "operation_count": len(proposal["operations"]),
        "authority_class": "DETERMINISTIC_CONTROLLER",
        "authority_id": "R37_TEST_CONTROLLER",
        "authority_ref": "ephemeral://r37/test-controller",
        "apply_recorded_at": "2026-08-09T20:00:00+00:00",
        "rationale": "ephemeral atomic apply test only",
    }
    path = tmp_path / name
    write_json(path, auth)
    return auth, path


def status_supersede(status, value):
    return {
        "op": "SUPERSEDE_CLAIM",
        "supersedes_id": status["claim_id"],
        "value": value,
        "evidence_state": "VERIFIED",
        "evidence_refs": [REF],
    }


def test_two_operation_apply_is_atomic_and_durable(monkeypatch, tmp_path):
    clear_current(monkeypatch)
    db = tmp_path / "memory.db"
    before = seed_db(db)
    status = one_claim(before, "project.status")
    proposal, ppath = proposal_file(
        db,
        tmp_path,
        [
            status_supersede(status, {"state": "AFTER"}),
            {
                "op": "RECORD_CLAIM",
                "predicate": "project.open_loop",
                "scope": "r38",
                "value": {"id": "r38", "title": "next", "status": "OPEN", "next_action": "review"},
                "evidence_state": "INFERENCE",
                "evidence_refs": [REF],
            },
        ],
    )
    _, apath = auth_file(proposal, ppath, tmp_path)

    result = applymod.apply_authorized_memory_delta(db, ppath, apath)

    assert result["terminal"] == "CURRENT_MEMORY_APPLY_PASS"
    assert result["transaction"] == "BEGIN_IMMEDIATE_ATOMIC_COMMIT"
    assert result["accepted_truth_modified"] is False
    assert result["effects"]["canonical_mutation"] is False
    assert result["can_trade"] is False
    assert result["capital_permission"] == "DENY"
    assert result["durable_apply_event"]["sequence"] > result["operation_results"][-1]["event_sequence"]
    after, counts = snapshot(db)
    assert one_claim(after, "project.status")["value"] == {"state": "AFTER"}
    assert one_claim(after, "project.open_loop", "r38")["value"]["status"] == "OPEN"
    assert counts["apply_events"] == 1


def test_verified_current_session_holds_without_memory_change(monkeypatch, tmp_path):
    clear_current(monkeypatch)
    db = tmp_path / "memory.db"
    before = seed_db(db)
    proposal, ppath = proposal_file(
        db,
        tmp_path,
        [status_supersede(one_claim(before, "project.status"), {"state": "NO_WRITE"})],
    )
    _, apath = auth_file(proposal, ppath, tmp_path)
    snap = snapshot(db)

    set_current(monkeypatch)
    result = applymod.apply_authorized_memory_delta(db, ppath, apath)

    assert result["terminal"] == "CURRENT_MEMORY_APPLY_HOLD"
    assert result["reason"] == "CURRENT_SESSION_EFFECT_FORBIDDEN"
    assert result["current_session"]["authority_generation"] == "R64"
    assert snapshot(db) == snap


def test_wrong_authorization_sha_revises_without_write(monkeypatch, tmp_path):
    clear_current(monkeypatch)
    db = tmp_path / "memory.db"
    before = seed_db(db)
    proposal, ppath = proposal_file(
        db, tmp_path, [status_supersede(one_claim(before, "project.status"), {"state": "AFTER"})]
    )
    auth, apath = auth_file(proposal, ppath, tmp_path)
    auth["proposal_file_sha256"] = "0" * 64
    write_json(apath, auth)
    snap = snapshot(db)

    result = applymod.apply_authorized_memory_delta(db, ppath, apath)

    assert result["terminal"] == "CURRENT_MEMORY_APPLY_REVISE"
    assert result["reason"] == "APPLY_ARTIFACT_INVALID"
    assert snapshot(db) == snap


def test_stale_base_revises_without_write(monkeypatch, tmp_path):
    clear_current(monkeypatch)
    db = tmp_path / "memory.db"
    before = seed_db(db)
    proposal, ppath = proposal_file(
        db, tmp_path, [status_supersede(one_claim(before, "project.status"), {"state": "AFTER"})]
    )
    _, apath = auth_file(proposal, ppath, tmp_path)
    with OperationalMemory(str(db)) as memory:
        memory.record_claim(
            subject_id=PROJECT,
            predicate="project.open_loop",
            value={"id": "drift", "title": "drift", "status": "OPEN"},
            scope="drift",
            evidence_state="SOURCE_BACKED",
            evidence_refs=[REF],
            actor_type="DETERMINISTIC_CONTROLLER",
            actor_id="drift",
            valid_from="2026-08-09T11:00:00+00:00",
            recorded_at="2026-08-09T11:00:00+00:00",
        )
    drift = snapshot(db)

    result = applymod.apply_authorized_memory_delta(db, ppath, apath)

    assert result["terminal"] == "CURRENT_MEMORY_APPLY_REVISE"
    assert result["reason"] == "STALE_OPERATIONAL_MEMORY_BASE"
    assert snapshot(db) == drift


def test_second_operation_failure_rolls_back_first_and_receipt(monkeypatch, tmp_path):
    clear_current(monkeypatch)
    db = tmp_path / "memory.db"
    before = seed_db(db, blocker=True)
    proposal, ppath = proposal_file(
        db,
        tmp_path,
        [
            status_supersede(one_claim(before, "project.status"), {"state": "MUST_ROLL_BACK"}),
            {
                "op": "RECORD_CLAIM",
                "predicate": "project.blocker",
                "scope": "existing",
                "value": {"id": "existing", "title": "duplicate", "status": "OPEN"},
                "evidence_state": "VERIFIED",
                "evidence_refs": [REF],
            },
        ],
    )
    _, apath = auth_file(proposal, ppath, tmp_path)
    snap = snapshot(db)

    result = applymod.apply_authorized_memory_delta(db, ppath, apath)

    assert result["terminal"] == "CURRENT_MEMORY_APPLY_REVISE"
    assert result["reason"] == "ATOMIC_SHADOW_MEMORY_APPLY_ROLLED_BACK"
    assert result["transaction"] == "ROLLED_BACK"
    assert snapshot(db) == snap
    assert one_claim(snapshot(db)[0], "project.status")["value"] == {"state": "BEFORE"}
    assert snapshot(db)[1]["apply_events"] == 0


def test_exact_replay_is_idempotent(monkeypatch, tmp_path):
    clear_current(monkeypatch)
    db = tmp_path / "memory.db"
    before = seed_db(db)
    proposal, ppath = proposal_file(
        db, tmp_path, [status_supersede(one_claim(before, "project.status"), {"state": "AFTER"})]
    )
    _, apath = auth_file(proposal, ppath, tmp_path)

    assert applymod.apply_authorized_memory_delta(db, ppath, apath)["terminal"] == "CURRENT_MEMORY_APPLY_PASS"
    snap = snapshot(db)
    second = applymod.apply_authorized_memory_delta(db, ppath, apath)

    assert second["terminal"] == "CURRENT_MEMORY_APPLY_ALREADY_APPLIED"
    assert second["reason"] == "EXACT_PROPOSAL_ALREADY_APPLIED"
    assert snapshot(db) == snap
    assert snap[1]["apply_events"] == 1


def test_terminal_decision_uses_authorization_identity_and_evidence(monkeypatch, tmp_path):
    clear_current(monkeypatch)
    db = tmp_path / "memory.db"
    seed_db(db)
    proposal, ppath = proposal_file(
        db,
        tmp_path,
        [{
            "op": "RECORD_DECISION",
            "decision_type": "NEXT_ACTION",
            "state": "ACCEPTED",
            "value": {"action": "review next stage"},
            "rationale": "bounded test decision",
            "evidence_refs": [REF],
        }],
    )
    _, apath = auth_file(proposal, ppath, tmp_path)

    result = applymod.apply_authorized_memory_delta(db, ppath, apath)

    assert result["terminal"] == "CURRENT_MEMORY_APPLY_PASS"
    row = one_decision(snapshot(db)[0], "NEXT_ACTION")
    assert row["state"] == "ACCEPTED"
    assert row["authority_class"] == "DETERMINISTIC_CONTROLLER"
    assert row["authority_id"] == "R37_TEST_CONTROLLER"
    assert row["authority_ref"] == "ephemeral://r37/test-controller"
    assert row["evidence_refs"] == [{"locator": "evidence://r37", "sha256": "a" * 64}]


def test_competing_terminal_record_decision_rolls_back(monkeypatch, tmp_path):
    clear_current(monkeypatch)
    db = tmp_path / "memory.db"
    seed_db(db, terminal_decision=True)
    proposal, ppath = proposal_file(
        db,
        tmp_path,
        [{
            "op": "RECORD_DECISION",
            "decision_type": "NEXT_ACTION",
            "state": "ACCEPTED",
            "value": {"action": "competing"},
            "rationale": "must not coexist",
            "evidence_refs": [REF],
        }],
    )
    _, apath = auth_file(proposal, ppath, tmp_path)
    snap = snapshot(db)

    result = applymod.apply_authorized_memory_delta(db, ppath, apath)

    assert result["terminal"] == "CURRENT_MEMORY_APPLY_REVISE"
    assert result["reason"] == "ATOMIC_SHADOW_MEMORY_APPLY_ROLLED_BACK"
    assert snapshot(db) == snap
