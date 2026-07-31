from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path

import pytest

from continuityos.operational_memory import (
    IdentityConflict,
    OperationalMemory,
    PolicyViolation,
    resolve_operational_db,
    strict_json_loads,
)

H1 = "1" * 64
H2 = "2" * 64
T1 = "2026-07-30T20:00:00.000000Z"
T2 = "2026-07-31T20:00:00.000000Z"
T3 = "2026-08-01T20:00:00.000000Z"


def ref(sha=H1, locator="evidence://one"):
    return [{"sha256": sha, "locator": locator}]


def make_db(tmp_path: Path) -> OperationalMemory:
    return OperationalMemory(str(tmp_path / "opmem.db"))


def test_default_db_is_local_and_not_drive(monkeypatch, tmp_path):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "Local"))
    path = resolve_operational_db(None)
    assert "My Drive" not in path
    assert path.endswith("common_operational_memory_v1.db")


@pytest.mark.parametrize(
    "path",
    [
        r"C:\Users\coins\My Drive\Control canter\opmem.db",
        r"C:\Users\coins\Google Drive\opmem.db",
        r"C:\Users\coins\AppData\Local\Google\DriveFS\opmem.db",
        r"C:\Users\coins\OneDrive\opmem.db",
        r"C:\safe\00_RETURN_DROP\opmem.db",
        r"\\server\share\opmem.db",
    ],
)
def test_drive_and_network_paths_rejected(path):
    with pytest.raises(PolicyViolation):
        resolve_operational_db(path)


def test_schema_metadata_and_wal(tmp_path):
    with make_db(tmp_path) as db:
        meta = db.metadata()
        assert meta["schema_version"] == "1"
        assert meta["mode"] == "SHADOW_ONLY"
        assert meta["apply_enabled"] == "false"
        assert meta["can_trade"] == "false"
        assert meta["capital_permission"] == "DENY"
        assert meta["deploy_permission"] == "DENY"
        assert meta["self_application"] == "false"
        assert db.con.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"


def test_event_append_is_idempotent(tmp_path):
    with make_db(tmp_path) as db:
        first = db.append_event(
            stream="ops",
            event_type="RUN_REPORTED",
            subject_id="run-1",
            actor_type="AGENT",
            actor_id="FABLE-5",
            payload={"status": "reported"},
            occurred_at=T1,
            recorded_at=T1,
            event_id="evt-fixed",
        )
        second = db.append_event(
            stream="ops",
            event_type="RUN_REPORTED",
            subject_id="run-1",
            actor_type="AGENT",
            actor_id="FABLE-5",
            payload={"status": "reported"},
            occurred_at=T1,
            recorded_at=T2,
            event_id="evt-fixed",
        )
        assert first.inserted is True
        assert second.inserted is False
        assert first.sequence == second.sequence == 1
        assert db.con.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 1


def test_event_identity_conflict_fails(tmp_path):
    with make_db(tmp_path) as db:
        db.append_event(
            stream="ops",
            event_type="RUN_REPORTED",
            subject_id="run-1",
            actor_type="AGENT",
            actor_id="FABLE-5",
            payload={"status": "one"},
            occurred_at=T1,
            event_id="evt-fixed",
        )
        with pytest.raises(IdentityConflict):
            db.append_event(
                stream="ops",
                event_type="RUN_REPORTED",
                subject_id="run-1",
                actor_type="AGENT",
                actor_id="FABLE-5",
                payload={"status": "two"},
                occurred_at=T1,
                event_id="evt-fixed",
            )


def test_event_rows_are_schema_enforced_append_only(tmp_path):
    path = tmp_path / "opmem.db"
    with OperationalMemory(str(path)) as db:
        db.append_event(
            stream="ops", event_type="A", subject_id="x", actor_type="AGENT",
            actor_id="a", payload={"n": 1}, occurred_at=T1, recorded_at=T1,
        )
        db.append_event(
            stream="ops", event_type="B", subject_id="x", actor_type="AGENT",
            actor_id="a", payload={"n": 2}, occurred_at=T2, recorded_at=T2,
        )
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            db.con.execute("UPDATE events SET payload_json='{}' WHERE sequence=1")
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            db.con.execute("DELETE FROM events WHERE sequence=1")
        assert db.verify()["ok"] is True


def test_claim_requires_evidence_except_unknown(tmp_path):
    with make_db(tmp_path) as db:
        with pytest.raises(PolicyViolation):
            db.record_claim(
                subject_id="project", predicate="status", value="PASS",
                evidence_state="VERIFIED", actor_id="gpt", valid_from=T1,
            )
        db.record_claim(
            subject_id="project", predicate="status", value="UNKNOWN",
            evidence_state="UNKNOWN", actor_id="gpt", valid_from=T1,
        )
        assert db.con.execute("SELECT COUNT(*) FROM claims").fetchone()[0] == 1


def test_claim_supersession_is_append_only_and_projection_current(tmp_path):
    with make_db(tmp_path) as db:
        db.record_claim(
            subject_id="project", predicate="status", value="UNKNOWN", scope="runtime",
            evidence_state="UNKNOWN", actor_id="gpt", valid_from=T1,
            claim_id="clm-old", recorded_at=T1,
        )
        db.record_claim(
            subject_id="project", predicate="status", value="TESTED", scope="runtime",
            evidence_state="VERIFIED", evidence_refs=ref(), actor_type="DETERMINISTIC_CONTROLLER",
            actor_id="controller", valid_from=T2, supersedes_id="clm-old",
            claim_id="clm-new", recorded_at=T2,
        )
        assert db.con.execute("SELECT COUNT(*) FROM claims").fetchone()[0] == 2
        projection = db.projection()
        assert [c["claim_id"] for c in projection["claims"]] == ["clm-new"]
        assert projection["claims"][0]["value"] == "TESTED"
        old = db.con.execute("SELECT * FROM claims WHERE claim_id='clm-old'").fetchone()
        assert old["valid_to"] is None  # append-only: no mutation of predecessor


def test_claim_can_only_supersede_same_key(tmp_path):
    with make_db(tmp_path) as db:
        db.record_claim(
            subject_id="a", predicate="status", value="UNKNOWN", evidence_state="UNKNOWN",
            actor_id="gpt", claim_id="clm-a", valid_from=T1,
        )
        with pytest.raises(PolicyViolation):
            db.record_claim(
                subject_id="b", predicate="status", value="UNKNOWN", evidence_state="UNKNOWN",
                actor_id="gpt", supersedes_id="clm-a", valid_from=T2,
            )


def test_agent_cannot_record_accepted_decision(tmp_path):
    with make_db(tmp_path) as db:
        with pytest.raises(PolicyViolation):
            db.record_decision(
                subject_id="project", decision_type="promotion", state="ACCEPTED",
                value={"promote": True}, rationale="agent says so",
                authority_class="AGENT", authority_id="model",
                evidence_refs=ref(), authority_ref="receipt://x",
            )


def test_authority_bound_decision_is_recorded(tmp_path):
    with make_db(tmp_path) as db:
        db.record_decision(
            subject_id="project", decision_type="promotion", state="HOLD",
            value={"promote": False}, rationale="human hold",
            authority_class="HUMAN", authority_id="Robert",
            authority_ref="decision://D1", evidence_refs=ref(), recorded_at=T1,
            decision_id="dec-one",
        )
        p = db.projection()
        assert p["decisions"][0]["state"] == "HOLD"
        assert p["decisions"][0]["authority_class"] == "HUMAN"


def write_registry(path: Path, rows):
    path.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")


def test_broker_import_preserves_epistemic_ceilings(tmp_path):
    registry = tmp_path / "MASTER_RETURN_REGISTRY_R64.jsonl"
    write_registry(
        registry,
        [
            {
                "delivery_id": "d-1", "zip_sha256": H1, "generation": "R64",
                "slot": "CODEX-01", "work_order_id": "WO-1", "status": "PASS",
                "content_status": "ACCEPTED", "apply_status": "APPLIED",
            },
            {
                "delivery_id": "d-2", "zip_sha256": H2, "generation": "R64",
                "slot": "FABLE-5", "work_order_id": "WO-2", "status": "HASH_VERIFIED",
            },
        ],
    )
    with make_db(tmp_path) as db:
        result = db.import_broker_registry(registry)
        assert result["inserted"] == 2
        rows = db.con.execute(
            "SELECT content_status,apply_status FROM broker_custody ORDER BY delivery_id"
        ).fetchall()
        assert [(r[0], r[1]) for r in rows] == [
            ("UNREVIEWED", "NOT_APPLIED"),
            ("UNREVIEWED", "NOT_APPLIED"),
        ]
        p = db.projection()
        assert p["ceilings"]["content_acceptance"] == "NOT_PERFORMED"
        assert p["ceilings"]["state_apply"] == "DISABLED"
        assert p["ceilings"]["can_trade"] is False


def test_broker_import_idempotent(tmp_path):
    registry = tmp_path / "r.jsonl"
    write_registry(registry, [{"delivery_id": "d-1", "zip_sha256": H1}])
    with make_db(tmp_path) as db:
        assert db.import_broker_registry(registry)["inserted"] == 1
        again = db.import_broker_registry(registry)
        assert again["inserted"] == 0
        assert again["duplicates"] == 1
        assert db.con.execute("SELECT COUNT(*) FROM broker_custody").fetchone()[0] == 1
        assert db.con.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 1


def test_broker_delivery_conflict_rolls_back_batch(tmp_path):
    r1 = tmp_path / "r1.jsonl"
    r2 = tmp_path / "r2.jsonl"
    write_registry(r1, [{"delivery_id": "d-1", "zip_sha256": H1}])
    write_registry(
        r2,
        [
            {"delivery_id": "d-2", "zip_sha256": H2},
            {"delivery_id": "d-1", "zip_sha256": H2},
        ],
    )
    with make_db(tmp_path) as db:
        db.import_broker_registry(r1)
        with pytest.raises(IdentityConflict):
            db.import_broker_registry(r2)
        assert db.con.execute("SELECT COUNT(*) FROM broker_custody").fetchone()[0] == 1
        assert db.con.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 1


def test_duplicate_delivery_ids_in_source_fail_before_write(tmp_path):
    registry = tmp_path / "r.jsonl"
    write_registry(
        registry,
        [
            {"delivery_id": "d-1", "zip_sha256": H1},
            {"delivery_id": "d-1", "zip_sha256": H1},
        ],
    )
    with make_db(tmp_path) as db:
        with pytest.raises(IdentityConflict):
            db.import_broker_registry(registry)
        assert db.con.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 0


def test_strict_json_rejects_duplicate_keys():
    with pytest.raises(ValueError):
        strict_json_loads('{"delivery_id":"a","delivery_id":"b"}')


def test_timestamps_use_fixed_utc_precision_for_ordering(tmp_path):
    with make_db(tmp_path) as db:
        db.append_event(
            stream="ops", event_type="A", subject_id="x", actor_type="AGENT",
            actor_id="a", payload={}, occurred_at="2026-08-01T20:00:00Z",
            recorded_at="2026-08-01T20:00:00.12+00:00",
        )
        row = db.con.execute("SELECT occurred_at,recorded_at FROM events").fetchone()
        assert row["occurred_at"] == "2026-08-01T20:00:00.000000Z"
        assert row["recorded_at"] == "2026-08-01T20:00:00.120000Z"


def test_projection_is_byte_deterministic(tmp_path):
    with make_db(tmp_path) as db:
        db.append_event(
            stream="ops", event_type="A", subject_id="x", actor_type="AGENT",
            actor_id="a", payload={"b": 2, "a": 1}, occurred_at=T1, recorded_at=T1,
        )
        one = json.dumps(db.projection(), sort_keys=True, separators=(",", ":"))
        two = json.dumps(db.projection(), sort_keys=True, separators=(",", ":"))
        assert one == two
        assert db.projection()["projection_sha256"] == db.projection()["projection_sha256"]


def test_replay_cursor_excludes_later_state(tmp_path):
    with make_db(tmp_path) as db:
        first = db.record_claim(
            subject_id="project", predicate="status", value="ONE", evidence_state="UNKNOWN",
            actor_id="gpt", claim_id="clm-one", valid_from=T1, recorded_at=T1,
        )
        db.record_claim(
            subject_id="project", predicate="status", value="TWO", evidence_state="UNKNOWN",
            actor_id="gpt", claim_id="clm-two", valid_from=T2, recorded_at=T2,
            supersedes_id="clm-one",
        )
        old = db.projection(event_sequence=first.sequence)
        current = db.projection()
        assert old["claims"][0]["value"] == "ONE"
        assert current["claims"][0]["value"] == "TWO"


def test_projection_supports_independent_valid_time_axis(tmp_path):
    with make_db(tmp_path) as db:
        db.record_claim(
            subject_id="project", predicate="status", value="ONE", evidence_state="UNKNOWN",
            actor_id="gpt", claim_id="clm-one", valid_from=T1, recorded_at=T1,
        )
        db.record_claim(
            subject_id="project", predicate="status", value="TWO", evidence_state="UNKNOWN",
            actor_id="gpt", claim_id="clm-two", valid_from=T2, recorded_at=T3,
            supersedes_id="clm-one",
        )
        known_now_valid_then = db.projection(valid_at="2026-07-30T23:00:00Z")
        known_now_valid_now = db.projection(valid_at=T3)
        assert known_now_valid_then["claims"][0]["value"] == "ONE"
        assert known_now_valid_now["claims"][0]["value"] == "TWO"
        assert known_now_valid_then["event_cursor"] == known_now_valid_now["event_cursor"]


def test_checkpoint_binds_projection_and_is_append_only(tmp_path):
    with make_db(tmp_path) as db:
        db.append_event(
            stream="ops", event_type="A", subject_id="x", actor_type="AGENT",
            actor_id="a", payload={}, occurred_at=T1, recorded_at=T1,
        )
        cp = db.create_checkpoint("after-A", metadata={"reason": "test"})
        assert cp["projection_sha256"] == db.projection()["projection_sha256"]
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            db.con.execute("UPDATE checkpoints SET projection_sha256=?", (H1,))
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            db.con.execute("DELETE FROM checkpoints")
        assert db.verify()["ok"] is True


def test_read_only_open_reads_wal_and_denies_write(tmp_path):
    path = tmp_path / "opmem.db"
    with OperationalMemory(str(path)) as db:
        db.append_event(
            stream="ops", event_type="A", subject_id="x", actor_type="AGENT",
            actor_id="a", payload={}, occurred_at=T1, recorded_at=T1,
        )
    with OperationalMemory(str(path), read_only=True) as ro:
        assert ro.projection()["event_cursor"] == 1
        with pytest.raises(PolicyViolation):
            ro.append_event(
                stream="ops", event_type="B", subject_id="x", actor_type="AGENT",
                actor_id="a", payload={}, occurred_at=T2,
            )


def test_five_concurrent_event_publishers(tmp_path):
    with make_db(tmp_path) as db:
        errors = []

        def worker(i):
            try:
                db.append_event(
                    stream="concurrent", event_type="PUBLISH", subject_id=f"d-{i}",
                    actor_type="AGENT", actor_id=f"a-{i}", payload={"i": i},
                    occurred_at=T1, event_id=f"evt-{i}",
                )
            except Exception as exc:  # pragma: no cover - diagnostic capture
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(5)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        assert errors == []
        assert db.con.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 5
        assert db.verify()["ok"] is True


def test_no_apply_api_or_permission_escalation(tmp_path):
    with make_db(tmp_path) as db:
        assert not hasattr(db, "apply")
        assert not hasattr(db, "apply_delta")
        p = db.projection()
        assert p["ceilings"] == {
            "accepted_truth_owner": "CONTROL_CENTER",
            "content_acceptance": "NOT_PERFORMED",
            "state_apply": "DISABLED",
            "can_trade": False,
            "capital_permission": "DENY",
            "deploy_permission": "DENY",
            "self_application": False,
        }


def test_projection_excludes_expired_claim_at_event_time(tmp_path):
    with make_db(tmp_path) as db:
        db.record_claim(
            subject_id="project", predicate="lease", value="temporary",
            evidence_state="SOURCE_BACKED", evidence_refs=ref(), actor_id="gpt",
            valid_from=T1, valid_to=T2, recorded_at=T1, claim_id="clm-expiring",
        )
        db.append_event(
            stream="clock", event_type="TIME_ADVANCED", subject_id="clock",
            actor_type="DETERMINISTIC_CONTROLLER", actor_id="controller", payload={},
            occurred_at=T3, recorded_at=T3,
        )
        assert db.projection()["valid_at"] == T3
        assert db.projection()["claims"] == []


def test_broker_import_stores_no_arbitrary_source_values(tmp_path):
    registry = tmp_path / "r.jsonl"
    write_registry(
        registry,
        [{
            "delivery_id": "d-1",
            "zip_sha256": H1,
            "api_token": "super-secret",
            "note": "also-sensitive-even-with-generic-key",
            "nested": {"password": "pw"},
        }],
    )
    with make_db(tmp_path) as db:
        db.import_broker_registry(registry)
        raw = db.con.execute("SELECT raw_json FROM broker_custody").fetchone()[0]
        assert "super-secret" not in raw
        assert "also-sensitive-even-with-generic-key" not in raw
        assert '"delivery_id":"d-1"' in raw
        assert '"source_keys"' in raw
        assert db.verify()["ok"] is True


def test_unknown_broker_status_fails_down_to_reported(tmp_path):
    registry = tmp_path / "r.jsonl"
    write_registry(
        registry,
        [{"delivery_id": "d-1", "zip_sha256": H1, "status": "AGENT_SAYS_GREAT"}],
    )
    with make_db(tmp_path) as db:
        db.import_broker_registry(registry)
        row = db.con.execute(
            "SELECT physical_status,record_hash FROM broker_custody"
        ).fetchone()
        assert row["physical_status"] == "REPORTED"
        assert len(row["record_hash"]) == 64
        assert db.verify()["ok"] is True


def test_claim_decision_and_custody_tables_reject_mutation(tmp_path):
    registry = tmp_path / "r.jsonl"
    write_registry(registry, [{"delivery_id": "d-1", "zip_sha256": H1}])
    with make_db(tmp_path) as db:
        db.record_claim(
            subject_id="project", predicate="status", value="UNKNOWN",
            evidence_state="UNKNOWN", actor_id="gpt", claim_id="clm-one", valid_from=T1,
        )
        db.record_decision(
            subject_id="project", decision_type="promotion", state="PROPOSED",
            value={"promote": False}, rationale="proposal", authority_class="AGENT",
            authority_id="model", decision_id="dec-one", recorded_at=T1,
        )
        db.import_broker_registry(registry)
        for statement in (
            "UPDATE claims SET value_json='null'",
            "DELETE FROM decisions",
            "UPDATE broker_custody SET physical_status='REJECTED'",
        ):
            with pytest.raises(sqlite3.IntegrityError, match="append-only"):
                db.con.execute(statement)
        assert db.verify()["ok"] is True


def test_immutable_read_only_creates_no_sidecars_and_denies_write(tmp_path):
    path = tmp_path / "immutable.db"
    with OperationalMemory(str(path)) as db:
        db.append_event(
            stream="ops", event_type="A", subject_id="x", actor_type="AGENT",
            actor_id="a", payload={}, occurred_at=T1, recorded_at=T1,
        )
    before = sorted(p.name for p in tmp_path.glob("immutable.db-*"))
    with OperationalMemory(str(path), read_only=True, immutable=True) as ro:
        assert ro.con.execute("PRAGMA query_only").fetchone()[0] == 1
        assert ro.projection()["event_cursor"] == 1
        with pytest.raises(PolicyViolation):
            ro.append_event(
                stream="ops", event_type="B", subject_id="x", actor_type="AGENT",
                actor_id="a", payload={}, occurred_at=T2,
            )
    after = sorted(p.name for p in tmp_path.glob("immutable.db-*"))
    assert before == after


def test_immutable_requires_read_only(tmp_path):
    with pytest.raises(ValueError, match="requires read_only"):
        OperationalMemory(str(tmp_path / "x.db"), immutable=True)


def test_immutable_rejects_nonempty_wal(tmp_path):
    path = tmp_path / "active.db"
    writer = OperationalMemory(str(path))
    try:
        writer.append_event(
            stream="ops", event_type="ACTIVE", subject_id="x", actor_type="AGENT",
            actor_id="a", payload={}, occurred_at=T1,
        )
        wal = Path(str(path) + "-wal")
        assert wal.exists() and wal.stat().st_size > 0
        with pytest.raises(PolicyViolation, match="quiescent"):
            OperationalMemory(str(path), read_only=True, immutable=True)
    finally:
        writer.close()
