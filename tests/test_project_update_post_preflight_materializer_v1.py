from __future__ import annotations

import hashlib
import json
from pathlib import Path

import continuityos.operational_memory_apply as apply
import continuityos.project_update_post_preflight_materializer as mat
from continuityos.current_claim_sync import REQUEST_SCHEMA
from continuityos.current_project_update_preflight import preflight_project_update_packet
from continuityos.current_project_update_review import build_project_update_review_packet
from continuityos.operational_memory import OperationalMemory

PROJECT = "project:post-preflight-materializer"
SEED_REF = {"sha256": "d" * 64, "locator": "evidence://post-preflight/seed"}


def _json_bytes(value) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def _seed(path: Path) -> None:
    with OperationalMemory(str(path)) as memory:
        memory.record_claim(
            subject_id=PROJECT,
            predicate="project.status",
            scope="global",
            value={"state": "OLD"},
            evidence_state="VERIFIED",
            evidence_refs=[SEED_REF],
            actor_type="DETERMINISTIC_CONTROLLER",
            actor_id="materializer-seed",
            valid_from="2026-08-10T05:00:00Z",
            recorded_at="2026-08-10T05:00:00Z",
        )
        assert memory.verify()["ok"] is True


def _request(evidence: Path):
    return {
        "schema": REQUEST_SCHEMA,
        "project_id": PROJECT,
        "evidence": [{
            "evidence_id": "fresh",
            "locator": str(evidence),
            "kind": "PROVIDER_READBACK",
            "scope": PROJECT,
        }],
        "claims": [{
            "predicate": "project.status",
            "scope": "global",
            "value": {"state": "UPDATED"},
            "evidence_state": "VERIFIED",
            "evidence_ids": ["fresh"],
            "valid_from": "2026-08-10T08:00:00Z",
        }],
        "rationale": "post-preflight materialization regression",
    }


def _case(tmp_path: Path):
    db = tmp_path / "project.db"
    _seed(db)
    evidence = tmp_path / "evidence.json"
    evidence.write_bytes(_json_bytes({"status": "PASS", "frontier": "materializer"}))

    packet = build_project_update_review_packet(db, _request(evidence))
    assert packet["terminal"] == "CURRENT_PROJECT_UPDATE_REVIEW_PASS", packet
    packet_bytes = _json_bytes(packet)
    packet_path = tmp_path / "packet.json"
    packet_path.write_bytes(packet_bytes)

    auth = dict(packet["authorization_review"]["authorization_skeleton"])
    auth.update({
        "decision": apply.AUTH_DECISION,
        "authority_class": "DETERMINISTIC_CONTROLLER",
        "authority_id": "POST_PREFLIGHT_TEST_CONTROLLER",
        "authority_ref": "test://post-preflight/authority",
        "apply_recorded_at": "2026-08-10T09:00:00Z",
        "rationale": "separate authority decision for materializer regression",
    })
    auth_bytes = _json_bytes(auth)
    auth_path = tmp_path / "authorization.json"
    auth_path.write_bytes(auth_bytes)

    preflight = preflight_project_update_packet(db, packet, auth_bytes)
    assert preflight["terminal"] == "CURRENT_PROJECT_UPDATE_PREFLIGHT_READY", preflight
    preflight["current_session"] = {
        "binding_verified": True,
        "authority_generation": "R64",
        "challenge_id": "test-challenge",
        "challenge_sha256": "a" * 64,
        "session_effect_ceiling": "READ_ONLY",
        "authority_ceiling": "NO_FURTHER_AGENT_WORK",
    }
    preflight["inputs"] = {
        "packet_path": str(packet_path),
        "packet_file_sha256": hashlib.sha256(packet_bytes).hexdigest(),
        "packet_file_size_bytes": len(packet_bytes),
        "authorization_path": str(auth_path),
        "authorization_file_sha256": hashlib.sha256(auth_bytes).hexdigest(),
        "authorization_file_size_bytes": len(auth_bytes),
    }
    preflight_bytes = _json_bytes(preflight)
    preflight_path = tmp_path / "preflight.json"
    preflight_path.write_bytes(preflight_bytes)
    return db, packet, packet_path, auth_bytes, auth_path, preflight_bytes, preflight_path


def test_materializer_writes_exact_ready_bound_artifacts_without_memory_apply(monkeypatch, tmp_path):
    db, packet, packet_path, auth_bytes, auth_path, preflight_bytes, preflight_path = _case(tmp_path)
    before_db = hashlib.sha256(db.read_bytes()).hexdigest()
    monkeypatch.setattr(mat, "inspect_current_session", lambda: {"mode": mat.MODE_LEGACY})
    out = tmp_path / "review"

    result = mat.materialize_project_update_after_preflight(packet_path, auth_path, preflight_path, out)

    assert result["terminal"] == "PROJECT_UPDATE_POST_PREFLIGHT_MATERIALIZATION_PASS", result
    assert result["apply_status"] == "NOT_APPLIED"
    assert result["execution_authorized"] is False
    assert result["effects"]["filesystem_write"] is True
    assert result["effects"]["operational_memory_write"] is False
    assert (out / mat.PROPOSAL_NAME).read_bytes() == packet["proposal"]["proposal_canonical_json"].encode("utf-8")
    assert (out / mat.AUTHORIZATION_NAME).read_bytes() == auth_bytes
    assert (out / mat.PREFLIGHT_NAME).read_bytes() == preflight_bytes
    assert (out / mat.RECEIPT_NAME).is_file()
    assert (out / mat.SUMS_NAME).is_file()
    assert result["r37_revalidation_required"] is True
    assert result["current_session_must_not_run_r37"] is True
    assert hashlib.sha256(db.read_bytes()).hexdigest() == before_db


def test_current_session_holds_before_any_input_io(monkeypatch, tmp_path):
    out = tmp_path / "never-created"
    monkeypatch.setattr(
        mat,
        "inspect_current_session",
        lambda: {"mode": "CURRENT", "binding_verified": True, "reason": "verified"},
    )
    monkeypatch.setattr(mat, "_stable_read", lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not read")))

    result = mat.materialize_project_update_after_preflight(
        tmp_path / "missing-packet.json",
        tmp_path / "missing-auth.json",
        tmp_path / "missing-preflight.json",
        out,
    )

    assert result["terminal"] == "PROJECT_UPDATE_POST_PREFLIGHT_MATERIALIZATION_HOLD"
    assert not out.exists()


def test_authorization_byte_drift_after_preflight_is_rejected(monkeypatch, tmp_path):
    _, _, packet_path, auth_bytes, auth_path, _, preflight_path = _case(tmp_path)
    monkeypatch.setattr(mat, "inspect_current_session", lambda: {"mode": mat.MODE_LEGACY})
    auth_path.write_bytes(auth_bytes + b" ")
    out = tmp_path / "review"

    result = mat.materialize_project_update_after_preflight(packet_path, auth_path, preflight_path, out)

    assert result["terminal"] == "PROJECT_UPDATE_POST_PREFLIGHT_MATERIALIZATION_REVISE"
    assert any("authorization SHA mismatch" in item for item in result["errors"])
    assert not out.exists()


def test_tampered_ready_receipt_is_rejected(monkeypatch, tmp_path):
    _, _, packet_path, _, auth_path, preflight_bytes, preflight_path = _case(tmp_path)
    monkeypatch.setattr(mat, "inspect_current_session", lambda: {"mode": mat.MODE_LEGACY})
    preflight = json.loads(preflight_bytes)
    preflight["proposal_file_sha256"] = "0" * 64
    preflight_path.write_bytes(_json_bytes(preflight))
    out = tmp_path / "review"

    result = mat.materialize_project_update_after_preflight(packet_path, auth_path, preflight_path, out)

    assert result["terminal"] == "PROJECT_UPDATE_POST_PREFLIGHT_MATERIALIZATION_REVISE"
    assert any("preflight proposal SHA mismatch" in item for item in result["errors"])
    assert not out.exists()


def test_existing_output_is_never_overwritten(monkeypatch, tmp_path):
    _, _, packet_path, _, auth_path, _, preflight_path = _case(tmp_path)
    monkeypatch.setattr(mat, "inspect_current_session", lambda: {"mode": mat.MODE_LEGACY})
    out = tmp_path / "review"
    out.mkdir()
    marker = out / "KEEP"
    marker.write_bytes(b"sentinel")

    result = mat.materialize_project_update_after_preflight(packet_path, auth_path, preflight_path, out)

    assert result["terminal"] == "PROJECT_UPDATE_POST_PREFLIGHT_MATERIALIZATION_REVISE"
    assert marker.read_bytes() == b"sentinel"


def test_mid_materialization_failure_removes_owned_output(monkeypatch, tmp_path):
    _, _, packet_path, _, auth_path, _, preflight_path = _case(tmp_path)
    monkeypatch.setattr(mat, "inspect_current_session", lambda: {"mode": mat.MODE_LEGACY})
    original = mat._write_exclusive
    calls = {"n": 0}

    def fail_second(path, payload):
        calls["n"] += 1
        if calls["n"] == 2:
            raise RuntimeError("forced second write failure")
        return original(path, payload)

    monkeypatch.setattr(mat, "_write_exclusive", fail_second)
    out = tmp_path / "review"
    result = mat.materialize_project_update_after_preflight(packet_path, auth_path, preflight_path, out)

    assert result["terminal"] == "PROJECT_UPDATE_POST_PREFLIGHT_MATERIALIZATION_REVISE"
    assert result["reason"] == "MATERIALIZATION_ROLLED_BACK"
    assert not out.exists()
