from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

import continuityos.project_update_review_materializer as mat
import continuityos.operational_memory_apply as apply
from continuityos.current_claim_sync import REQUEST_SCHEMA
from continuityos.current_project_update_review import build_project_update_review_packet
from continuityos.operational_memory import OperationalMemory, strict_json_loads

PROJECT = "project:r54"
SEED_REF = {"sha256": "d" * 64, "locator": "evidence://r54/seed"}


def _write_json(path: Path, value) -> bytes:
    payload = (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    path.write_bytes(payload)
    return payload


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
            actor_id="r54-seed",
            valid_from="2026-08-10T08:00:00Z",
            recorded_at="2026-08-10T08:00:00Z",
        )


def _request(evidence: Path):
    return {
        "schema": REQUEST_SCHEMA,
        "project_id": PROJECT,
        "evidence": [{"evidence_id": "fresh", "locator": str(evidence)}],
        "claims": [{
            "predicate": "project.status",
            "scope": "global",
            "value": {"state": "UPDATED"},
            "evidence_state": "VERIFIED",
            "evidence_ids": ["fresh"],
            "valid_from": "2026-08-10T08:10:00Z",
        }],
        "rationale": "materialize review artifacts only",
    }


def _packet_file(tmp_path: Path):
    db = tmp_path / "memory.db"
    _seed(db)
    evidence = tmp_path / "evidence.json"
    _write_json(evidence, {"status": "PASS", "release": "R54"})
    packet = build_project_update_review_packet(db, _request(evidence))
    assert packet["terminal"] == "CURRENT_PROJECT_UPDATE_REVIEW_PASS", packet
    path = tmp_path / "packet.json"
    _write_json(path, packet)
    return db, packet, path


def test_materializer_writes_exact_proposal_and_still_invalid_skeleton(monkeypatch, tmp_path):
    db, packet, packet_path = _packet_file(tmp_path)
    before_db = hashlib.sha256(db.read_bytes()).hexdigest()
    monkeypatch.setattr(mat, "inspect_current_session", lambda: {"mode": mat.MODE_LEGACY})
    out = tmp_path / "review"

    result = mat.materialize_project_update_review(packet_path, out)

    assert result["terminal"] == "PROJECT_UPDATE_MATERIALIZATION_PASS", result
    assert result["authorization_granted"] is False
    assert result["authorization_identity_authenticated"] is False
    assert result["execution_authorized"] is False
    proposal_bytes = (out / mat.PROPOSAL_NAME).read_bytes()
    assert proposal_bytes == packet["proposal"]["proposal_canonical_json"].encode("utf-8")
    assert hashlib.sha256(proposal_bytes).hexdigest() == packet["proposal"]["proposal_file_sha256"]
    skeleton = strict_json_loads((out / mat.SKELETON_NAME).read_text(encoding="utf-8"))
    assert skeleton["decision"] is None
    assert skeleton["authority_class"] is None
    assert skeleton["authority_id"] is None
    with pytest.raises(Exception):
        apply._validate_authorization(
            skeleton,
            proposal=strict_json_loads(proposal_bytes.decode("utf-8")),
            proposal_file_sha256=hashlib.sha256(proposal_bytes).hexdigest(),
        )
    assert (out / mat.RECEIPT_NAME).is_file()
    assert (out / mat.SUMS_NAME).is_file()
    assert hashlib.sha256(db.read_bytes()).hexdigest() == before_db


def test_current_session_holds_before_packet_or_output_io(monkeypatch, tmp_path):
    out = tmp_path / "never-created"
    monkeypatch.setattr(
        mat,
        "inspect_current_session",
        lambda: {"mode": "CURRENT", "binding_verified": True, "reason": "verified"},
    )
    monkeypatch.setattr(mat, "_stable_read", lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not read")))

    result = mat.materialize_project_update_review(tmp_path / "missing.json", out)

    assert result["terminal"] == "PROJECT_UPDATE_MATERIALIZATION_HOLD"
    assert not out.exists()


def test_existing_output_is_never_overwritten(monkeypatch, tmp_path):
    _, _, packet_path = _packet_file(tmp_path)
    monkeypatch.setattr(mat, "inspect_current_session", lambda: {"mode": mat.MODE_LEGACY})
    out = tmp_path / "review"
    out.mkdir()
    marker = out / "KEEP"
    marker.write_bytes(b"sentinel")

    result = mat.materialize_project_update_review(packet_path, out)

    assert result["terminal"] == "PROJECT_UPDATE_MATERIALIZATION_REVISE"
    assert marker.read_bytes() == b"sentinel"


def test_tampered_packet_id_is_rejected_without_output(monkeypatch, tmp_path):
    _, packet, packet_path = _packet_file(tmp_path)
    packet["packet_id"] = "purp-" + "0" * 40
    _write_json(packet_path, packet)
    monkeypatch.setattr(mat, "inspect_current_session", lambda: {"mode": mat.MODE_LEGACY})
    out = tmp_path / "review"

    result = mat.materialize_project_update_review(packet_path, out)

    assert result["terminal"] == "PROJECT_UPDATE_MATERIALIZATION_REVISE"
    assert any("packet_id integrity mismatch" in item for item in result["errors"])
    assert not out.exists()


def test_mid_materialization_failure_removes_owned_output(monkeypatch, tmp_path):
    _, _, packet_path = _packet_file(tmp_path)
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
    result = mat.materialize_project_update_review(packet_path, out)

    assert result["terminal"] == "PROJECT_UPDATE_MATERIALIZATION_REVISE"
    assert result["reason"] == "MATERIALIZATION_ROLLED_BACK"
    assert not out.exists()
