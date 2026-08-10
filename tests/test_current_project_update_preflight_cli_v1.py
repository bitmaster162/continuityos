from __future__ import annotations

import json

import continuityos.current_project_update_preflight_cli as cli


def test_cli_requires_verified_current_session_before_reading_inputs(monkeypatch, capsys):
    monkeypatch.setattr(cli, "inspect_current_session", lambda: {"mode": "LEGACY", "binding_verified": False})
    called = {"read": False}

    def forbidden(*args, **kwargs):
        called["read"] = True
        raise AssertionError("input read must not occur")

    monkeypatch.setattr(cli, "_stable_read", forbidden)
    rc = cli.main(["--db", "missing.db", "--packet", "missing.json", "--authorization", "missing-auth.json"])
    out = json.loads(capsys.readouterr().out)

    assert rc == 2
    assert out["terminal"] == "CURRENT_PROJECT_UPDATE_PREFLIGHT_REVISE"
    assert out["reason"] == "VERIFIED_CURRENT_SESSION_REQUIRED"
    assert called["read"] is False


def test_cli_ready_is_read_only_and_binds_exact_input_hashes(monkeypatch, tmp_path, capsys):
    packet = tmp_path / "packet.json"
    auth = tmp_path / "auth.json"
    packet.write_bytes(b'{"schema":"packet"}\n')
    auth.write_bytes(b'{"schema":"auth"}\n')
    monkeypatch.setattr(cli, "inspect_current_session", lambda: {
        "mode": cli.MODE_CURRENT,
        "binding_verified": True,
        "authority_generation": "R64",
        "challenge_id": "c" * 64,
        "challenge_sha256": "d" * 64,
        "session_effect_ceiling": "READ_ONLY",
        "authority_ceiling": "NO_FURTHER_AGENT_WORK",
    })
    monkeypatch.setattr(cli, "strict_json_loads", lambda text: {"schema": "packet"})
    seen = {}

    def fake(db, packet_value, auth_bytes):
        seen["db"] = db
        seen["packet"] = packet_value
        seen["auth_bytes"] = auth_bytes
        return {
            "schema": cli.PREFLIGHT_SCHEMA,
            "terminal": "CURRENT_PROJECT_UPDATE_PREFLIGHT_READY",
            "reason": "READY",
            "apply_status": "NOT_APPLIED",
            "apply_ready": True,
            "execution_authorized": False,
            "effects": {"filesystem_write": False, "operational_memory_write": False},
        }

    monkeypatch.setattr(cli, "preflight_project_update_packet", fake)
    rc = cli.main(["--db", "project.db", "--packet", str(packet), "--authorization", str(auth)])
    out = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert seen["db"] == "project.db"
    assert seen["packet"] == {"schema": "packet"}
    assert seen["auth_bytes"] == auth.read_bytes()
    assert out["current_session"]["binding_verified"] is True
    assert out["current_session"]["authority_generation"] == "R64"
    assert out["inputs"]["authorization_file_sha256"]
    assert out["execution_authorized"] is False
