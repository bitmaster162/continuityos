from __future__ import annotations

import json

import continuityos.current_effect_boundary as boundary
import continuityos.current_memory_delta_cli as cli


def clear_binding(monkeypatch):
    for name in (boundary.ENV_CHALLENGE, boundary.ENV_CHALLENGE_SHA, boundary.ENV_ACK, boundary.ENV_REQUIRED):
        monkeypatch.delenv(name, raising=False)


def set_current(monkeypatch):
    monkeypatch.setenv(boundary.ENV_CHALLENGE, "challenge.json")
    monkeypatch.setenv(boundary.ENV_CHALLENGE_SHA, "a" * 64)
    monkeypatch.setenv(boundary.ENV_ACK, "ack.json")
    monkeypatch.setenv(boundary.ENV_REQUIRED, "1")
    monkeypatch.setattr(
        boundary,
        "verify_current_runtime_binding",
        lambda *args, **kwargs: {
            "terminal": "CURRENT_RUNTIME_BINDING_PASS",
            "binding_verified": True,
            "authority_generation": "R64",
            "challenge_id": "b" * 64,
            "challenge_sha256": "a" * 64,
            "ack_sha256": "c" * 64,
        },
    )


def write_request(tmp_path):
    path = tmp_path / "request.json"
    path.write_text(json.dumps({
        "schema": "continuityos.operational_memory.delta_request/v1",
        "project_id": "project:x",
        "operations": [{
            "op": "RECORD_CLAIM",
            "predicate": "project.status",
            "scope": "global",
            "value": {"state": "new"},
            "evidence_state": "UNKNOWN",
            "evidence_refs": [],
        }],
    }), encoding="utf-8")
    return path


def test_cli_requires_verified_current_session(monkeypatch, tmp_path, capsys):
    clear_binding(monkeypatch)
    request = write_request(tmp_path)
    called = []
    monkeypatch.setattr(cli, "build_memory_delta_proposal_from_db", lambda *args: called.append(args))

    code = cli.main(["--operational-db", "memory.db", "--request", str(request)])

    assert code == 2
    assert called == []
    payload = json.loads(capsys.readouterr().out)
    assert payload["reason"] == "VERIFIED_CURRENT_SESSION_REQUIRED"
    assert payload["apply_status"] == "NOT_APPLIED"
    assert payload["execution_authorized"] is False


def test_cli_missing_request_fails_without_calling_builder(monkeypatch, tmp_path, capsys):
    set_current(monkeypatch)
    called = []
    monkeypatch.setattr(cli, "build_memory_delta_proposal_from_db", lambda *args: called.append(args))
    missing = tmp_path / "missing.json"

    code = cli.main(["--operational-db", "memory.db", "--request", str(missing)])

    assert code == 2
    assert called == []
    payload = json.loads(capsys.readouterr().out)
    assert payload["reason"] == "DELTA_REQUEST_MISSING"
    assert not missing.exists()


def test_cli_pass_emits_current_session_identity(monkeypatch, tmp_path, capsys):
    set_current(monkeypatch)
    request = write_request(tmp_path)
    monkeypatch.setattr(
        cli,
        "build_memory_delta_proposal_from_db",
        lambda db, req: {
            "schema": "continuityos.operational_memory.delta_proposal/v1",
            "terminal": "CURRENT_MEMORY_DELTA_PROPOSAL_PASS",
            "reason": "EXACT_OPERATIONAL_MEMORY_BASE_BOUND",
            "project_id": req["project_id"],
            "proposal_id": "omdp-test",
            "apply_status": "NOT_APPLIED",
            "apply_implemented": False,
            "execution_decision": "HOLD",
            "execution_authorized": False,
            "effects": {"can_trade": False, "capital_permission": "DENY"},
        },
    )

    code = cli.main(["--operational-db", "memory.db", "--request", str(request)])

    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["terminal"] == "CURRENT_MEMORY_DELTA_PROPOSAL_PASS"
    assert payload["current_session"]["authority_generation"] == "R64"
    assert payload["current_session"]["session_effect_ceiling"] == "READ_ONLY"
    assert payload["apply_status"] == "NOT_APPLIED"
    assert payload["execution_authorized"] is False


def test_cli_revise_returns_two(monkeypatch, tmp_path, capsys):
    set_current(monkeypatch)
    request = write_request(tmp_path)
    monkeypatch.setattr(
        cli,
        "build_memory_delta_proposal_from_db",
        lambda *args: {
            "schema": "continuityos.operational_memory.delta_proposal/v1",
            "terminal": "CURRENT_MEMORY_DELTA_PROPOSAL_REVISE",
            "reason": "OPERATIONAL_MEMORY_MISSING",
            "project_id": "project:x",
            "proposal_id": None,
            "apply_status": "NOT_APPLIED",
            "apply_implemented": False,
            "execution_decision": "HOLD",
            "execution_authorized": False,
            "effects": {"can_trade": False, "capital_permission": "DENY"},
        },
    )
    assert cli.main(["--operational-db", "memory.db", "--request", str(request)]) == 2
    assert json.loads(capsys.readouterr().out)["reason"] == "OPERATIONAL_MEMORY_MISSING"
