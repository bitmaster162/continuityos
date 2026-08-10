from __future__ import annotations

import hashlib

from continuityos.current_memory_apply_check import check_authorized_memory_delta
from continuityos.current_memory_delta import REQUEST_SCHEMA, build_memory_delta_proposal_from_db
from continuityos.operational_memory import OperationalMemory, _canonical_json
import continuityos.operational_memory_apply as apply

PROJECT = "project:r44-time-parity"


def _write(path, value):
    payload = _canonical_json(value).encode("utf-8")
    path.write_bytes(payload)
    return hashlib.sha256(payload).hexdigest()


def test_omitted_valid_from_uses_apply_time_exactly_like_r37(tmp_path):
    db = tmp_path / "memory.db"
    with OperationalMemory(str(db)) as memory:
        assert memory.verify()["ok"] is True

    request = {
        "schema": REQUEST_SCHEMA,
        "project_id": PROJECT,
        "operations": [{
            "op": "RECORD_CLAIM",
            "predicate": "project.window",
            "scope": "global",
            "value": "future-window",
            "evidence_state": "UNKNOWN",
            "evidence_refs": [],
            "valid_to": "2026-08-10T03:59:59Z",
        }],
        "rationale": "valid_to is earlier than apply time while valid_from is omitted",
    }
    proposal = build_memory_delta_proposal_from_db(db, request)
    assert proposal["terminal"] == "CURRENT_MEMORY_DELTA_PROPOSAL_PASS"
    proposal_path = tmp_path / "proposal.json"
    proposal_sha = _write(proposal_path, proposal)
    base = proposal["base"]
    authorization = {
        "schema": apply.AUTH_SCHEMA,
        "decision": apply.AUTH_DECISION,
        "proposal_id": proposal["proposal_id"],
        "proposal_file_sha256": proposal_sha,
        "project_id": PROJECT,
        "base_projection_sha256": base["projection_sha256"],
        "base_event_cursor": base["event_cursor"],
        "base_event_chain_head": base["event_chain_head"],
        "operation_count": 1,
        "authority_class": "DETERMINISTIC_CONTROLLER",
        "authority_id": "R44_TIME_PARITY",
        "authority_ref": "test://r44/time-parity",
        "apply_recorded_at": "2026-08-10T04:00:00Z",
        "rationale": "mirror R37 effective valid_from",
    }
    auth_path = tmp_path / "authorization.json"
    _write(auth_path, authorization)

    checked = check_authorized_memory_delta(db, proposal_path, auth_path)
    applied = apply.apply_authorized_memory_delta(db, proposal_path, auth_path)

    assert checked["terminal"] == "CURRENT_MEMORY_APPLY_CHECK_REVISE"
    assert checked["reason"] == "OPERATIONAL_MEMORY_PREFLIGHT_FAILED"
    assert any("valid_to must be later than valid_from" in item for item in checked["errors"])
    assert applied["terminal"] == "CURRENT_MEMORY_APPLY_REVISE"
    assert applied["reason"] == "ATOMIC_SHADOW_MEMORY_APPLY_ROLLED_BACK"
    assert any("valid_to must be later than valid_from" in item for item in applied["errors"])
