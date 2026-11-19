from __future__ import annotations

import json
import os
import shlex
import socket
import subprocess
import threading
import urllib.error
import urllib.request

import pytest

from continuityos import Memory
from continuityos.api import make_handler
from continuityos.gate import ActionSpec, Ledger, preflight
from continuityos.gate.broker import GateBroker
from continuityos.gate.effects import classify_effects


def _command(argv: list[str]) -> str:
    return subprocess.list2cmdline(argv) if os.name == "nt" else shlex.join(argv)


def _spec(argv: list[str], cwd: str) -> ActionSpec:
    return ActionSpec(tool="exec", command=_command(argv), args=argv, paths=[], cwd=cwd)


def _outside_home_cwd() -> str:
    return r"C:\continuityos-p0-effect-test" if os.name == "nt" else "/workspace/continuityos-p0-effect-test"


@pytest.mark.parametrize(
    ("argv", "decision", "effect"),
    [
        (["gh", "pr", "merge", "999", "--merge"], "REQUIRE_CONFIRMATION", "GIT_REMOTE_MUTATION"),
        (["python", "-m", "pip", "install", "example-package"], "REQUIRE_CONFIRMATION", "PACKAGE_MUTATION"),
        (["curl", "-X", "POST", "https://example.invalid/hook"], "REQUIRE_CONFIRMATION", "NETWORK_WRITE"),
        (["terraform", "apply", "-auto-approve"], "HOLD", "INFRA_MUTATION"),
        (["kubectl", "apply", "-f", "deployment.yaml"], "HOLD", "INFRA_MUTATION"),
        (["docker", "push", "example.invalid/image:tag"], "REQUIRE_CONFIRMATION", "REMOTE_ARTIFACT_MUTATION"),
        (["ssh", "example.invalid", "true"], "HOLD", "REMOTE_SHELL"),
        (["python", "-c", "print(1)"], "REQUIRE_CONFIRMATION", "DYNAMIC_CODE"),
        (["mystery-deployer", "go"], "REQUIRE_CONFIRMATION", "UNKNOWN_EXEC"),
        (["python", "script.py"], "REQUIRE_CONFIRMATION", "DYNAMIC_CODE"),
    ],
)
def test_effect_ceiling_blocks_or_confirms_external_effects(tmp_path, argv, decision, effect):
    result = preflight(_spec(argv, _outside_home_cwd()))
    assert result["decision"] == decision
    assert effect in result["effect"]["classes"]
    assert result["effect"]["schema"] == "continuityos.gate.effect-classification/v1"


def test_known_local_read_stays_allow(tmp_path):
    result = preflight(_spec(["python", "--version"], _outside_home_cwd()))
    assert result["decision"] == "ALLOW"
    assert result["effect"]["classes"] == ["LOCAL_READ"]


def test_effect_classification_is_durable_in_preflight_receipt(tmp_path):
    ledger_path = tmp_path / "ledger.db"
    with Ledger(str(ledger_path)) as ledger:
        result = preflight(_spec(["terraform", "apply", "-auto-approve"], _outside_home_cwd()), ledger=ledger)
        event = ledger.event(result["ledger_hash"])
    assert event is not None
    assert event["payload"]["effect"] == result["effect"]
    assert event["payload"]["decision"] == "HOLD"


def _memory_db(path):
    memory = Memory(str(path))
    memory.remember("audit fixture", namespace="facts")
    memory.store.con.close()


def test_r14_broker_requires_confirmation_for_remote_merge_before_execution(tmp_path, monkeypatch):
    db = tmp_path / "memory.db"
    _memory_db(db)
    broker = GateBroker(
        registry_path=str(tmp_path / "registry.db"),
        ledger_path=str(tmp_path / "ledger.db"),
        witness_path=str(tmp_path / "witness.json"),
        db=str(db),
    )
    result = broker.preflight_exec(
        "remote-merge",
        ["gh", "pr", "merge", "999", "--merge"],
        str(tmp_path),
    )
    assert result["decision"] == "REQUIRE_CONFIRMATION"
    import continuityos.gate.cli as cli
    monkeypatch.setattr(cli.subprocess, "call", lambda *a, **k: pytest.fail("subprocess must not run"))
    executed = broker.execute_preflight("remote-merge")
    assert executed["state"] == "HELD"
    assert executed["decision"] == "HELD"


def test_r14_broker_holds_infrastructure_apply_at_preflight(tmp_path):
    db = tmp_path / "memory.db"
    _memory_db(db)
    broker = GateBroker(
        registry_path=str(tmp_path / "registry.db"),
        ledger_path=str(tmp_path / "ledger.db"),
        witness_path=str(tmp_path / "witness.json"),
        db=str(db),
    )
    result = broker.preflight_exec(
        "infra-apply", ["terraform", "apply", "-auto-approve"], str(tmp_path)
    )
    assert result["decision"] == "HOLD"


def _http_server(tmp_path, *, token=None, allowed_origins=None):
    memory = Memory(str(tmp_path / "api.db"))
    from http.server import ThreadingHTTPServer
    server = ThreadingHTTPServer(
        ("127.0.0.1", 0),
        make_handler(memory, token=token, allowed_origins=allowed_origins),
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, f"http://127.0.0.1:{server.server_port}"


def _http(url, *, data=None, headers=None, method=None):
    request = urllib.request.Request(url, data=data, headers=headers or {}, method=method)
    try:
        response = urllib.request.urlopen(request, timeout=3)
        return response.status, dict(response.headers), json.loads(response.read().decode()) if response.status != 204 else None
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers), json.loads(exc.read().decode())


def test_browser_origin_is_denied_by_default_before_memory_access(tmp_path):
    server, base = _http_server(tmp_path)
    try:
        status, headers, body = _http(base + "/health", headers={"Origin": "https://evil.example"})
        assert status == 403
        assert body["error"] == "origin not allowed"
        assert headers.get("Access-Control-Allow-Origin") is None
    finally:
        server.shutdown()


def test_disallowed_browser_post_cannot_poison_memory(tmp_path):
    server, base = _http_server(tmp_path)
    try:
        payload = json.dumps({"text": "poison", "namespace": "facts"}).encode()
        status, _, body = _http(
            base + "/remember",
            data=payload,
            headers={"Content-Type": "application/json", "Origin": "https://evil.example"},
        )
        assert status == 403
        assert body["error"] == "origin not allowed"
        status, _, body = _http(base + "/recall?q=poison&k=5")
        assert status == 200
        assert body["hits"] == []
    finally:
        server.shutdown()


def test_explicit_origin_is_echoed_never_wildcard(tmp_path):
    origin = "https://trusted.example"
    server, base = _http_server(tmp_path, token="secret", allowed_origins={origin})
    try:
        status, headers, body = _http(
            base + "/health",
            headers={"Origin": origin, "Authorization": "Bearer secret"},
        )
        assert status == 200 and body["ok"] is True
        assert headers.get("Access-Control-Allow-Origin") == origin
        assert headers.get("Access-Control-Allow-Origin") != "*"
    finally:
        server.shutdown()


def test_cors_allowlist_rejects_header_control_chars(tmp_path):
    memory = Memory(str(tmp_path / "invalid-origin.db"))
    try:
        with pytest.raises(RuntimeError, match="invalid CORS origin"):
            make_handler(
                memory,
                token="secret",
                allowed_origins={"https://trusted.example\r\nX-Injected: yes"},
            )
    finally:
        memory.store.con.close()


def test_folded_origin_is_rejected_and_never_reflected(tmp_path):
    server, _ = _http_server(
        tmp_path,
        token="secret",
        allowed_origins={"https://trusted.example"},
    )
    try:
        request = (
            b"GET /health HTTP/1.1\r\n"
            b"Host: 127.0.0.1\r\n"
            b"Origin: https://trusted.example\r\n"
            b" X-Injected: yes\r\n"
            b"Authorization: Bearer secret\r\n"
            b"Connection: close\r\n\r\n"
        )
        with socket.create_connection(("127.0.0.1", server.server_port), timeout=3) as conn:
            conn.sendall(request)
            chunks = []
            while True:
                chunk = conn.recv(65536)
                if not chunk:
                    break
                chunks.append(chunk)
        response = b"".join(chunks)
        header_block = response.partition(b"\r\n\r\n")[0]
        assert response.startswith(b"HTTP/1.0 403")
        assert b"Access-Control-Allow-Origin:" not in header_block
        assert b"X-Injected:" not in header_block
    finally:
        server.shutdown()


def test_disallowed_cors_preflight_is_rejected(tmp_path):
    server, base = _http_server(tmp_path, token="secret", allowed_origins={"https://trusted.example"})
    try:
        status, headers, body = _http(
            base + "/remember",
            method="OPTIONS",
            headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "POST"},
        )
        assert status == 403
        assert body["error"] == "origin not allowed"
        assert headers.get("Access-Control-Allow-Origin") is None
    finally:
        server.shutdown()



def _broker_event_for_validation(tmp_path, *, effect_marker=True):
    spec = _spec(["python", "--version"], str(tmp_path))
    request_key = GateBroker._key("validated-effect")
    digest = GateBroker._base_digest(spec)
    spec.meta = {
        "broker_request_key": request_key,
        "broker_action_sha256": digest,
    }
    action = spec.to_dict()
    payload = {
        "action": action,
        "decision": "ALLOW",
        "rollback_plan": {},
    }
    if effect_marker:
        payload["effect"] = classify_effects(spec)
    return {
        "kind": "preflight",
        "hash": "a" * 64,
        "payload": payload,
    }, request_key, digest


def test_broker_validates_new_effect_receipt_shape_but_keeps_historical_compatibility(tmp_path):
    event, request_key, digest = _broker_event_for_validation(tmp_path)
    assert GateBroker._validated_event(event, request_key, digest) == ("ALLOW", None)
    event["payload"]["effect"]["classes"] = ["NOT_A_REAL_EFFECT"]
    assert GateBroker._validated_event(event, request_key, digest)[1] == "effect classification invalid"

    historical, request_key, digest = _broker_event_for_validation(tmp_path, effect_marker=False)
    assert GateBroker._validated_event(historical, request_key, digest) == ("ALLOW", None)


def test_browser_origin_configuration_requires_token_even_for_direct_handler(tmp_path):
    memory = Memory(str(tmp_path / "direct-handler.db"))
    try:
        with pytest.raises(RuntimeError, match="requires a bearer token"):
            make_handler(memory, allowed_origins={"https://trusted.example"})
    finally:
        memory.store.con.close()



@pytest.mark.parametrize(
    ("argv", "effect"),
    [
        (["gh", "api", "repos/o/r/issues/1", "-f", "state=closed"], "GIT_REMOTE_MUTATION"),
        (["curl", "-F", "file=@payload.bin", "https://example.invalid/upload"], "NETWORK_WRITE"),
        (["wget", "--post-data", "x=1", "https://example.invalid/hook"], "NETWORK_WRITE"),
        (["git", "remote", "add", "backup", "https://example.invalid/repo.git"], "LOCAL_MUTATION"),
        (["gh", "release", "download", "v1.0.0"], "LOCAL_MUTATION"),
        (["terraform", "init"], "LOCAL_MUTATION"),
        (["docker", "run", "example/image:latest"], "DYNAMIC_CODE"),
    ],
)
def test_effect_edge_cases_do_not_fall_through_to_allow(tmp_path, argv, effect):
    result = preflight(_spec(argv, _outside_home_cwd()))
    assert result["decision"] != "ALLOW"
    assert effect in result["effect"]["classes"]


def test_broker_rejects_well_shaped_but_forged_effect_receipt(tmp_path):
    event, request_key, digest = _broker_event_for_validation(tmp_path)
    event["payload"]["effect"] = {
        "schema": "continuityos.gate.effect-classification/v1",
        "classes": ["NETWORK_READ"],
        "remote_or_irreversible": False,
        "basis": ["forged but well shaped"],
    }
    assert GateBroker._validated_event(event, request_key, digest)[1] == "effect classification mismatch"


def test_effectless_historical_preflight_cannot_start_a_new_execution(tmp_path, monkeypatch):
    import continuityos.gate.cli as cli

    argv = ["python", "--version"]
    action = _spec(argv, str(tmp_path)).to_dict()
    ledger_path = tmp_path / "legacy-effectless.db"
    with Ledger(str(ledger_path)) as ledger:
        preflight_hash = ledger.append("preflight", {
            "action": action,
            "decision": "ALLOW",
            "rollback_plan": {},
        })
    result = {
        "action": action,
        "decision": "ALLOW",
        "ledger_hash": preflight_hash,
        "rollback_plan": {},
    }
    calls = []
    monkeypatch.setattr(cli.subprocess, "call", lambda *a, **k: calls.append((a, k)) or 0)
    assert cli._execute_approved(
        action["command"], "exec", result, argv=argv,
        ledger_path=str(ledger_path), execution_cwd=str(tmp_path),
    ) == 1
    assert calls == []

@pytest.mark.parametrize(
    ("command", "decision", "effect"),
    [
        ("terraform apply -auto-approve", "HOLD", "INFRA_MUTATION"),
        ("gh pr merge 999 --merge", "REQUIRE_CONFIRMATION", "GIT_REMOTE_MUTATION"),
        ("python -m pip install example-package", "REQUIRE_CONFIRMATION", "PACKAGE_MUTATION"),
        ("curl -X POST https://example.invalid/hook", "REQUIRE_CONFIRMATION", "NETWORK_WRITE"),
        ("python build.py", "REQUIRE_CONFIRMATION", "DYNAMIC_CODE"),
        ("npm test", "REQUIRE_CONFIRMATION", "DYNAMIC_CODE"),
        ("npm run build", "REQUIRE_CONFIRMATION", "DYNAMIC_CODE"),
        ("pytest -q", "REQUIRE_CONFIRMATION", "DYNAMIC_CODE"),
        ("git commit -m fix", "REQUIRE_CONFIRMATION", "UNKNOWN_EXEC"),
        ("mystery-deployer go", "REQUIRE_CONFIRMATION", "UNKNOWN_EXEC"),
    ],
)
def test_shell_effect_ceiling_matches_exec_boundary(tmp_path, command, decision, effect):
    result = preflight(ActionSpec(tool="shell", command=command, cwd=_outside_home_cwd()))
    assert result["decision"] == decision
    assert effect in result["effect"]["classes"]


def test_compound_shell_syntax_is_never_silent_allow(tmp_path):
    result = preflight(ActionSpec(tool="shell", command="echo ok && mystery-deployer go", cwd=_outside_home_cwd()))
    assert result["decision"] == "REQUIRE_CONFIRMATION"
    assert "DYNAMIC_CODE" in result["effect"]["classes"]


def test_typed_local_file_write_remains_policy_allow_outside_protected_paths():
    result = preflight(ActionSpec(
        tool="file.write", command="", paths=["artifact.txt"], cwd=_outside_home_cwd()
    ))
    assert result["decision"] == "ALLOW"
    assert result["effect"]["classes"] == ["TYPED_LOCAL_MUTATION"]


def test_cli_local_mutation_without_typed_targets_requires_confirmation():
    result = preflight(ActionSpec(
        tool="shell", command="gh release download v1.0.0", cwd=_outside_home_cwd()
    ))
    assert result["decision"] == "REQUIRE_CONFIRMATION"
    assert "LOCAL_MUTATION" in result["effect"]["classes"]
    assert "local mutation has no typed rollback target paths" in result["reasons"]
